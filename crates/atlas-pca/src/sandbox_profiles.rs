//! Sandbox OS policy compilation and the confinement profile generators: the policy an authorized operation set needs (paths and
//! hosts validated strictly, refused rather than escaped, merged and sorted so the same grant gives the same bytes), the Docker /
//! OCI seccomp profile, the Landlock ruleset, the macOS sandbox profile, and the flags of the reference confinement helper.
//! JSON-valued: needs and policies are the reference's objects.
use crate::authorize::{AuthorizedOperation, Operation};
use crate::oauth::js_str;
use crate::sandbox_egress::is_bound_for;
use serde_json::{json, Value};
use std::collections::BTreeSet;

fn check_path(p: &Value) -> Result<&str, String> {
    let bad = || format!("bad_path: {}", crate::js_stringify(p).chars().take(80).collect::<String>());
    let s = p.as_str().ok_or_else(bad)?;
    let chars_ok = s.starts_with('/') && s.bytes().all(|c| c.is_ascii_alphanumeric() || b"._+@=,:~ /-".contains(&c));
    if !chars_ok || s.contains("//") || (s.len() > 1 && s.ends_with('/')) || s.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(bad());
    }
    Ok(s)
}

/// `/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/` of `String(host)`.
fn host_ok(h: &str) -> bool {
    let b = h.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    !b.is_empty() && edge(b[0]) && edge(b[b.len() - 1]) && b.iter().all(|c| edge(*c) || *c == b'.' || *c == b'-')
}

fn port_ok(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Number(n)) => n.as_f64().filter(|f| *f == f.floor() && (1.0..=65535.0).contains(f)).map(|f| f as i64),
        _ => None,
    }
}

/// An iterable member (`x ?? []`): absent or null is empty, an array its items; anything else is not iterable here.
fn items<'a>(v: Option<&'a Value>, what: &str) -> Result<&'a [Value], String> {
    match v {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(a)) => Ok(a),
        Some(_) => Err(format!("{what} is not iterable")),
    }
}

/// The pure core of [`compile_policy`]: validate, merge, sort. `needs` is a list of `{fs?: [{path, mode}], net?: [{host, port}]}`;
/// `proxy_port` absent or null means no proxy.
pub fn policy_from_needs(needs: &Value, proxy_port: Option<&Value>) -> Result<Value, String> {
    let list = needs.as_array().ok_or("needs is not iterable")?;
    let (mut read, mut write, mut exec, mut hosts) = (BTreeSet::new(), BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for n in list {
        if n.is_null() {
            return Err("Cannot read properties of null (reading 'fs')".into());
        }
        for f in items(n.get("fs"), "needs.fs")? {
            let path = check_path(f.get("path").unwrap_or(&Value::Null))?.to_string();
            match f.get("mode").and_then(Value::as_str) {
                Some("x") => {
                    exec.insert(path);
                }
                Some(m @ ("r" | "rw")) => {
                    read.insert(path.clone());
                    if m == "rw" {
                        write.insert(path);
                    }
                }
                _ => return Err("bad_mode".into()),
            }
        }
        for h in items(n.get("net"), "needs.net")? {
            let host = h.get("host").map(js_str).unwrap_or_else(|| "undefined".into());
            let port = port_ok(h.get("port")).filter(|_| host_ok(&host)).ok_or("bad_net_need")?;
            hosts.insert(format!("{host}:{port}"));
        }
    }
    let proxy = proxy_port.filter(|p| !p.is_null());
    if !hosts.is_empty() && proxy.is_none() {
        return Err("net_needs_proxy: network access exists only through the egress proxy; pass its port".into());
    }
    let proxy = match proxy {
        None => Value::Null,
        Some(p) => json!({"host": "127.0.0.1", "port": port_ok(Some(p)).ok_or("bad_proxy_port")?}),
    };
    let v = |s: BTreeSet<String>| s.into_iter().collect::<Vec<_>>();
    Ok(json!({"v": 1, "fs": {"read": v(read), "write": v(write), "exec": v(exec)}, "net": {"proxy": proxy, "hosts": v(hosts)}}))
}

/// Compile the OS policy from what was actually authorized: only operations an allowing result is bound to contribute, so a denied
/// or unrelated operation widens nothing. Each item is `(the bound operation of an ALLOWING result or None, the operation)`.
pub fn compile_policy(
    items: &[(Option<&AuthorizedOperation>, &Operation)],
    needs_of: impl Fn(&Operation) -> Option<Value>,
    proxy_port: Option<&Value>,
) -> Result<Value, String> {
    let mut needs = vec![];
    for (bound, op) in items {
        if !is_bound_for(*bound, op) {
            return Err("not_authorized: result does not allow exactly this operation".into());
        }
        if let Some(n) = needs_of(op).filter(|n| !n.is_null()) {
            needs.push(n);
        }
    }
    policy_from_needs(&Value::Array(needs), proxy_port)
}

/// Syscalls for a statically linked tool that reads, computes and exits. A starting point: confirm with your tool under strace.
const BASE: &[&str] = &[
    "read",
    "write",
    "close",
    "fstat",
    "newfstatat",
    "statx",
    "lseek",
    "mmap",
    "mprotect",
    "munmap",
    "mremap",
    "brk",
    "madvise",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "pread64",
    "pwrite64",
    "readv",
    "writev",
    "openat",
    "getdents64",
    "fcntl",
    "getcwd",
    "readlink",
    "readlinkat",
    "dup",
    "dup3",
    "pipe2",
    "poll",
    "ppoll",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "eventfd2",
    "futex",
    "set_tid_address",
    "set_robust_list",
    "rseq",
    "arch_prctl",
    "prlimit64",
    "sched_yield",
    "nanosleep",
    "clock_nanosleep",
    "clock_gettime",
    "gettimeofday",
    "getrandom",
    "getpid",
    "gettid",
    "getuid",
    "geteuid",
    "getgid",
    "getegid",
    "uname",
    "tgkill",
    "exit",
    "exit_group",
];
const NET: &[&str] = &["connect", "getsockopt", "setsockopt", "getsockname", "getpeername", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown"];
const EXEC: &[&str] = &["execve", "execveat"];

fn sorted(names: &[&str]) -> Vec<Value> {
    let mut v: Vec<&str> = names.to_vec();
    v.sort();
    v.into_iter().map(|s| json!(s)).collect()
}

fn strs<'a>(p: &'a Value, a: &str, b: &str) -> Vec<&'a str> {
    p.get(a).and_then(|x| x.get(b)).and_then(Value::as_array).map(|l| l.iter().filter_map(Value::as_str).collect()).unwrap_or_default()
}

fn proxy_of(p: &Value) -> Option<&Value> {
    p.get("net").and_then(|n| n.get("proxy")).filter(|x| !x.is_null())
}

/// Docker/OCI-format seccomp profile: deny by default; network syscalls only when the policy has a proxy; `socket` only for
/// AF_INET / AF_INET6; exec only when the grant names a binary. seccomp cannot see paths or addresses: pair it with the Landlock
/// rules or a network namespace.
pub fn seccomp_profile(p: &Value) -> Value {
    let mut syscalls = vec![json!({"names": sorted(BASE), "action": "SCMP_ACT_ALLOW"})];
    if proxy_of(p).is_some() {
        syscalls.push(json!({"names": sorted(NET), "action": "SCMP_ACT_ALLOW"}));
        for d in [2, 10] {
            syscalls.push(json!({"names": ["socket"], "action": "SCMP_ACT_ALLOW", "args": [{"index": 0, "value": d, "op": "SCMP_CMP_EQ"}]}));
        }
    }
    if !strs(p, "fs", "exec").is_empty() {
        syscalls.push(json!({"names": EXEC, "action": "SCMP_ACT_ALLOW"}));
    }
    json!({
        "defaultAction": "SCMP_ACT_ERRNO",
        "defaultErrnoRet": 1,
        "archMap": [{"architecture": "SCMP_ARCH_X86_64", "subArchitectures": []}, {"architecture": "SCMP_ARCH_AARCH64", "subArchitectures": []}],
        "syscalls": syscalls,
    })
}

/// Landlock ruleset (access-right names from the kernel UAPI; network rules need ABI 4). Handle every right, allow only what the
/// grant names.
pub fn landlock_ruleset(p: &Value) -> Value {
    let fs_name = |x: &str| format!("LANDLOCK_ACCESS_FS_{x}");
    let handled: Vec<String> = [
        "EXECUTE",
        "WRITE_FILE",
        "READ_FILE",
        "READ_DIR",
        "REMOVE_DIR",
        "REMOVE_FILE",
        "MAKE_CHAR",
        "MAKE_DIR",
        "MAKE_REG",
        "MAKE_SOCK",
        "MAKE_FIFO",
        "MAKE_BLOCK",
        "MAKE_SYM",
        "REFER",
        "TRUNCATE",
    ]
    .iter()
    .map(|x| fs_name(x))
    .collect();
    let (read, write, exec) = (strs(p, "fs", "read"), strs(p, "fs", "write"), strs(p, "fs", "exec"));
    let paths: BTreeSet<&str> = read.iter().chain(&write).chain(&exec).copied().collect();
    let fs: Vec<Value> = paths
        .into_iter()
        .map(|path| {
            let mut access: Vec<&str> = vec![];
            let mut add = |xs: &[&'static str]| {
                for &x in xs {
                    if !access.contains(&x) {
                        access.push(x);
                    }
                }
            };
            if exec.contains(&path) {
                add(&["EXECUTE", "READ_FILE"]);
            }
            if read.contains(&path) {
                add(&["READ_FILE", "READ_DIR"]);
            }
            if write.contains(&path) {
                add(&["WRITE_FILE", "TRUNCATE", "MAKE_REG", "MAKE_DIR", "REMOVE_FILE", "REMOVE_DIR"]);
            }
            json!({"path": path, "access": access.iter().map(|x| fs_name(x)).collect::<Vec<_>>()})
        })
        .collect();
    let net = match proxy_of(p) {
        Some(px) => vec![json!({"port": px.get("port").cloned().unwrap_or(Value::Null), "access": ["LANDLOCK_ACCESS_NET_CONNECT_TCP"]})],
        None => vec![],
    };
    json!({
        "v": 1,
        "abi_min": 4,
        "handled_access_fs": handled,
        "handled_access_net": ["LANDLOCK_ACCESS_NET_BIND_TCP", "LANDLOCK_ACCESS_NET_CONNECT_TCP"],
        "rules": {"fs": fs, "net": net},
    })
}

/// macOS sandbox profile (SBPL for sandbox-exec(1), deprecated but present): deny by default; the base lines are what a
/// dynamically linked binary needs to start.
pub fn macos_profile(p: &Value) -> String {
    let q = |s: &str| format!("\"{s}\""); // paths were validated to need no escaping
    let mut lines: Vec<String> = [
        "(version 1)",
        "(deny default)",
        "(allow sysctl-read)",
        "(allow process-fork)",
        "(allow mach-lookup)",
        "(allow file-read-metadata)",
        "(allow file-read* (literal \"/\") (literal \"/dev/null\") (literal \"/dev/urandom\") (subpath \"/usr/lib\") (subpath \"/System/Library\") (subpath \"/private/var/db/dyld\") (subpath \"/System/Volumes/Preboot/Cryptexes\"))",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for x in strs(p, "fs", "exec") {
        lines.push(format!("(allow process-exec (literal {}))", q(x)));
        lines.push(format!("(allow file-read* (literal {}))", q(x)));
    }
    for r in strs(p, "fs", "read") {
        lines.push(format!("(allow file-read* (subpath {}))", q(r)));
    }
    for w in strs(p, "fs", "write") {
        lines.push(format!("(allow file-write* (subpath {}))", q(w)));
    }
    if let Some(px) = proxy_of(p) {
        let port = px.get("port").map(js_str).unwrap_or_default();
        lines.push(format!("(allow network-outbound (remote tcp {}))", q(&format!("localhost:{port}"))));
    }
    format!("{}\n", lines.join("\n"))
}

/// Flatten the GENERATED seccomp and Landlock profiles into the flags of the reference confinement helper, so what the helper
/// enforces is exactly what the generators produced. Run it as `pca-confine <flags> -- <command>`.
pub fn confine_args(policy: &Value) -> Vec<String> {
    let ll = landlock_ruleset(policy);
    let sc = seccomp_profile(policy);
    let short = |v: &Value| v.as_str().unwrap_or("").trim_start_matches("LANDLOCK_ACCESS_").to_string();
    let join = |v: &Value| v.as_array().map(|a| a.iter().map(short).collect::<Vec<_>>().join(",")).unwrap_or_default();
    let mut args = vec!["--fs-handled".to_string(), join(&ll["handled_access_fs"])];
    let net_rules = ll["rules"]["net"].as_array().cloned().unwrap_or_default();
    if !net_rules.is_empty() || proxy_of(policy).is_some() {
        args.push("--net-handled".into());
        args.push(join(&ll["handled_access_net"]));
    }
    for r in ll["rules"]["fs"].as_array().into_iter().flatten() {
        args.push("--fs".into());
        args.push(format!("{}:{}", r["path"].as_str().unwrap_or(""), join(&r["access"])));
    }
    for r in &net_rules {
        args.push("--net".into());
        args.push(format!("{}:{}", js_str(&r["port"]), join(&r["access"])));
    }
    for s in sc["syscalls"].as_array().into_iter().flatten() {
        let names: Vec<&str> = s["names"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        match s.get("args").and_then(Value::as_array) {
            Some(al) => {
                for a in al {
                    for n in &names {
                        args.push("--allow-arg".into());
                        args.push(format!("{n}:{}:{}", js_str(&a["index"]), js_str(&a["value"])));
                    }
                }
            }
            None => {
                for n in &names {
                    args.push("--allow".into());
                    args.push(n.to_string());
                }
            }
        }
    }
    args
}

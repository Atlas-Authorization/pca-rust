//! The durable state store: the shared scenario corpus (every lane replays the same directory scenarios), plus the parts a corpus
//! cannot carry: real concurrent writers, real SIGKILL crash safety, file modes, and the in-memory store.
#![cfg(unix)]

mod common;

use atlas_pca::durable_state::*;
use atlas_pca::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::Arc;

static N: AtomicUsize = AtomicUsize::new(0);

fn tmp() -> PathBuf {
    let d = std::env::temp_dir().join(format!("pca-ds-test-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

extern "C" {
    fn gethostname(name: *mut std::ffi::c_char, len: usize) -> std::ffi::c_int;
}

fn hostname() -> String {
    let mut buf = [0 as std::ffi::c_char; 256];
    // SAFETY: 256-byte buffer, length 256.
    assert_eq!(unsafe { gethostname(buf.as_mut_ptr(), buf.len()) }, 0);
    let b: Vec<u8> = buf.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    String::from_utf8_lossy(&b).into_owned()
}

// ---- the corpus replay ----

const DEAD: i64 = 999_999_999;

fn subst(s: &str, host: &str) -> String {
    s.replace("$HOST", host).replace("$PID", &std::process::id().to_string()).replace("$DEAD", &DEAD.to_string())
}

fn so(v: &Value, host: &str) -> Value {
    match v {
        Value::String(s) if s == "$HOST" => json!(host),
        Value::String(s) if s == "$PID" => json!(std::process::id()),
        Value::Array(a) => Value::Array(a.iter().map(|x| so(x, host)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), so(x, host))).collect()),
        other => other.clone(),
    }
}

fn norm_name(f: &str) -> String {
    let mut s = f.to_string();
    if let Some(rest) = s.strip_prefix("state.fence.") {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        let after = &rest[digits.len()..];
        if !digits.is_empty() && after.starts_with('-') {
            let hexlen = after[1..].chars().take_while(|c| c.is_ascii_digit() || ('a'..='f').contains(c)).count();
            if hexlen > 0 {
                s = format!("state.fence.{digits}-*{}", &after[1 + hexlen..]);
            }
        }
    }
    if let Some(i) = s.find(".quarantine-") {
        s = format!("{}.quarantine-*", &s[..i]);
    }
    if s.starts_with("state.lock.legacy-recovered-") {
        s = "state.lock.legacy-recovered-*".into();
    }
    s
}

fn read_opt(dir: &Path, f: &str) -> Value {
    match fs::read(dir.join(f)) {
        Ok(b) => json!(String::from_utf8_lossy(&b).into_owned()),
        Err(_) => Value::Null,
    }
}

fn snapshot(dir: &Path) -> Value {
    let mut names: Vec<String> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    let strip = |mut v: Value| {
        if let Some(o) = v.as_object_mut() {
            o.remove("t");
        }
        v
    };
    let parse = |f: &str| -> Option<Value> { atlas_pca::serde_json::from_str(&String::from_utf8_lossy(&fs::read(dir.join(f)).ok()?)).ok() };
    let mut fences: Vec<Value> = Vec::new();
    if names.iter().any(|n| n == "state.fence") {
        match parse("state.fence").and_then(|o| o.get("fences").and_then(|f| f.as_array().cloned())) {
            Some(a) => fences.extend(a.into_iter().map(strip)),
            None => fences.push(json!({"unreadable": norm_name("state.fence")})),
        }
    }
    let mut entries: Vec<(f64, String)> = names
        .iter()
        .filter_map(|n| {
            let rest = n.strip_prefix("state.fence.")?;
            let (g, tag) = rest.split_once('-')?;
            (!g.is_empty() && g.bytes().all(|c| c.is_ascii_digit()) && !tag.is_empty() && tag.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
                .then(|| (g.parse::<f64>().unwrap(), n.clone()))
        })
        .collect();
    entries.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap().then_with(|| a.1.cmp(&b.1)));
    for (_, n) in entries {
        match parse(&n).and_then(|o| o.get("fence").cloned()).filter(|f| !f.is_null()) {
            Some(f) => fences.push(strip(f)),
            None => fences.push(json!({"unreadable": norm_name(&n)})),
        }
    }
    let g = names
        .iter()
        .filter_map(|f| f.strip_prefix("state.lock."))
        .filter(|d| !d.is_empty() && d.bytes().all(|c| c.is_ascii_digit()))
        .filter_map(|d| d.parse::<u64>().ok())
        .max()
        .unwrap_or(0);
    let top = if g > 0 {
        match parse(&format!("state.lock.{g}")) {
            None | Some(Value::Null) => json!({"g": g, "st": "unreadable"}),
            Some(b) => {
                let mut m = Map::new();
                m.insert("g".into(), json!(g));
                for k in ["st", "recovering", "recoveredFrom"] {
                    if let Some(v) = b.get(k) {
                        m.insert(k.into(), v.clone());
                    }
                }
                Value::Object(m)
            }
        }
    } else {
        Value::Null
    };
    let files: Vec<Value> = names
        .iter()
        .filter(|f| !f.starts_with("state.lock.tmp-") && !f.starts_with("state.probe-") && !f.contains(".tmp-"))
        .map(|f| json!(norm_name(f)))
        .collect();
    json!({"t": "dir", "files": files, "journal": read_opt(dir, "state.journal"), "head": read_opt(dir, "state.head"), "fences": fences, "top": top})
}

fn run_scenario(sc: &Value) -> Value {
    let dir = tmp();
    let host = hostname();
    let pid = std::process::id().to_string();
    let norm = |s: &str| {
        s.replace(dir.to_str().unwrap(), "$DIR").replace(&host, "$HOST").replace(&format!("pid={pid}"), "pid=$PID").replace(&format!("pid {pid}"), "pid $PID")
    };
    let err = |e: &DurableStateError| json!({"err": {"code": e.code.as_str(), "msg": norm(&e.message)}});
    let mut out: Vec<Value> = Vec::new();
    if let Some(files) = sc["files"].as_object() {
        for (f, t) in files {
            fs::write(dir.join(f), subst(t.as_str().unwrap(), &host)).unwrap();
        }
    }
    for st in sc["steps"].as_array().unwrap() {
        match st["t"].as_str().unwrap() {
            "write" => {
                match st["text"].as_str() {
                    Some(t) => fs::write(dir.join(st["file"].as_str().unwrap()), subst(t, &host)).unwrap(),
                    None => {
                        let _ = fs::remove_file(dir.join(st["file"].as_str().unwrap()));
                    }
                }
                out.push(Value::Null);
            }
            "dir" => out.push(snapshot(&dir)),
            "recover" => {
                let mut opts = Map::new();
                opts.insert("force".into(), json!(true));
                if let Some(o) = so(&st["opts"], &host).as_object() {
                    for (k, v) in o {
                        opts.insert(k.clone(), v.clone());
                    }
                }
                out.push(match recover_durable_state_value(&dir, &Value::Object(opts)) {
                    Ok(r) => {
                        let mut m = Map::new();
                        m.insert("released".into(), json!(r.released));
                        m.insert("reason".into(), json!(r.reason));
                        if let Some(f) = r.lock_file {
                            m.insert("lockFile".into(), json!(norm(f.to_str().unwrap())));
                        }
                        json!({ "ok": m })
                    }
                    Err(e) => err(&e),
                });
            }
            "open" => {
                let op = &st["opts"];
                let counter = Arc::new(AtomicI64::new(1000));
                let c2 = counter.clone();
                let mut o = DurableStateOptions::new(if op.get("dir").and_then(|d| d.as_str()) == Some("") { PathBuf::new() } else { dir.clone() });
                o.now = Some(Box::new(move || c2.fetch_add(1, Ordering::SeqCst)));
                if let Some(l) = op.get("hmacKey").and_then(|l| l.as_str()) {
                    o.hmac_key = Some(Sha256::digest(l.as_bytes()).to_vec());
                }
                if let Some(n) = op.get("hmacKeyBytes").and_then(|n| n.as_u64()) {
                    o.hmac_key = Some(vec![0u8; n as usize]);
                }
                o.recover_from_corruption = op.get("recoverFromCorruption") == Some(&json!(true));
                o.lock_timeout_ms = op.get("lockTimeoutMs").and_then(|v| v.as_i64());
                o.compact_every = op.get("compactEvery").and_then(|v| v.as_i64());
                o.max_value_bytes = op.get("maxValueBytes").and_then(|v| v.as_u64()).map(|v| v as usize);
                let h = match open_durable_state(o) {
                    Ok(h) => h,
                    Err(e) => {
                        out.push(err(&e));
                        continue;
                    }
                };
                let mut res: Vec<Value> = Vec::new();
                let mut saved: std::collections::HashMap<String, (Value, Value)> = Default::default();
                for x in st["ops"].as_array().unwrap() {
                    let key = x["key"].as_str().unwrap_or("");
                    let r: Result<Value, DurableStateError> = match x["op"].as_str().unwrap() {
                        "set" => h.set(key, &x["value"]).map(|_| Value::Null),
                        "get" => h.get(key).map(|v| v.unwrap_or_else(|| json!({"$undef": true}))),
                        "keys" => h.keys().map(|k| json!(k)),
                        "verify" => h.verify().map(|p| json!({"seq": p.seq, "hash": p.hash})),
                        "position" => {
                            let p = h.position();
                            Ok(json!({"seq": p.seq, "hash": p.hash}))
                        }
                        "update" => {
                            let arg = x.get("arg").cloned();
                            let kind = x["kind"].as_str().unwrap().to_string();
                            h.update(key, &mut |p: Option<Value>| match kind.as_str() {
                                "append" => {
                                    let mut a = p.and_then(|v| v.as_array().cloned()).unwrap_or_default();
                                    a.push(arg.clone().unwrap());
                                    Some(Value::Array(a))
                                }
                                "max" => {
                                    let a = arg.clone().unwrap();
                                    match p {
                                        None => Some(a),
                                        Some(p) if a.as_f64() > p.as_f64() => Some(a),
                                        _ => None,
                                    }
                                }
                                "noop" => None,
                                "same" => p,
                                "set" => arg.clone(),
                                other => panic!("unknown update kind {other}"),
                            })
                            .map(|v| v.unwrap_or_else(|| json!({"$undef": true})))
                        }
                        "fs" => {
                            match x["text"].as_str() {
                                Some(t) => fs::write(dir.join(x["file"].as_str().unwrap()), subst(t, &host)).unwrap(),
                                None => {
                                    let _ = fs::remove_file(dir.join(x["file"].as_str().unwrap()));
                                }
                            }
                            Ok(Value::Null)
                        }
                        "save" => {
                            saved.insert(x["name"].as_str().unwrap().into(), (read_opt(&dir, "state.journal"), read_opt(&dir, "state.head")));
                            Ok(Value::Null)
                        }
                        "restore" => {
                            let (j, hd) = saved.get(x["name"].as_str().unwrap()).unwrap();
                            for (f, v) in [("state.journal", j), ("state.head", hd)] {
                                match v.as_str() {
                                    Some(t) => fs::write(dir.join(f), t).unwrap(),
                                    None => {
                                        let _ = fs::remove_file(dir.join(f));
                                    }
                                }
                            }
                            Ok(Value::Null)
                        }
                        other => panic!("unknown op {other}"),
                    };
                    res.push(match r {
                        Ok(v) => json!({ "ok": v }),
                        Err(e) => err(&e),
                    });
                }
                out.push(json!({"ok": {"recovered": h.recovered(), "ops": res}}));
            }
            other => panic!("unknown step {other}"),
        }
    }
    out.push(snapshot(&dir));
    let _ = fs::remove_dir_all(&dir);
    Value::Array(out)
}

#[test]
fn every_scenario_of_the_reference_corpus_replays_identically() {
    let cases = common::ref_cases("durable-state");
    assert!(cases.len() >= 200, "corpus too small: {}", cases.len());
    let mut bad = Vec::new();
    for c in &cases {
        assert_eq!(c["fn"], "scenario");
        let got = run_scenario(&c["args"][0]);
        if got != c["out"] {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} scenarios differ:\n{}", bad.len(), cases.len(), bad.iter().take(3).cloned().collect::<Vec<_>>().join("\n"));
}

// ---- what the corpus cannot carry ----

fn open_at(d: &Path) -> DurableState {
    open_durable_state(DurableStateOptions::new(d)).unwrap()
}

#[test]
fn the_directory_is_0700_and_the_files_0600() {
    let d = tmp().join("state");
    let s = open_at(&d);
    s.set("a", &json!(1)).unwrap();
    let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&d), 0o700);
    assert_eq!(mode(&d.join("state.journal")), 0o600);
    assert_eq!(mode(&d.join("state.head")), 0o600);
}

#[test]
fn racing_writers_lose_no_update_and_the_chain_stays_intact() {
    let d = tmp();
    let threads = 4;
    let each = 12;
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let d = d.clone();
            std::thread::spawn(move || {
                let s = open_durable_state(DurableStateOptions { lock_timeout_ms: Some(60_000), ..DurableStateOptions::new(&d) }).unwrap();
                for _ in 0..each {
                    s.update("n", &mut |p| Some(json!(p.and_then(|v| v.as_i64()).unwrap_or(0) + 1))).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let s = open_at(&d);
    assert_eq!(s.get("n").unwrap(), Some(json!(threads * each)));
    assert!(s.verify().unwrap().seq >= (threads * each) as i64);
}

#[test]
fn one_handle_shared_between_threads_is_serialised() {
    let d = tmp();
    let s = Arc::new(open_at(&d));
    let hs: Vec<_> = (0..4)
        .map(|_| {
            let s = s.clone();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    s.update("n", &mut |p| Some(json!(p.and_then(|v| v.as_i64()).unwrap_or(0) + 1))).unwrap();
                }
            })
        })
        .collect();
    for h in hs {
        h.join().unwrap();
    }
    assert_eq!(s.get("n").unwrap(), Some(json!(40)));
}

#[test]
fn a_live_holder_is_never_robbed_the_waiter_times_out() {
    let d = tmp();
    let s = open_at(&d);
    s.set("a", &json!(1)).unwrap();
    // a second handle cannot take the lock while a live process holds the top generation
    let top = fs::read_dir(&d).unwrap().filter_map(|e| e.unwrap().file_name().to_str()?.strip_prefix("state.lock.")?.parse::<u64>().ok()).max().unwrap();
    fs::write(
        d.join(format!("state.lock.{}", top + 1)),
        format!("{{\"st\":\"held\",\"pid\":{},\"host\":\"{}\",\"nonce\":\"n\"}}", std::process::id(), hostname()),
    )
    .unwrap();
    let e = open_durable_state(DurableStateOptions { lock_timeout_ms: Some(150), ..DurableStateOptions::new(&d) }).err().unwrap();
    assert_eq!(e.code, DurableStateErrorCode::LockTimeout);
}

#[test]
fn the_in_memory_store_has_the_same_update_semantics() {
    let m = create_memory_durable_kv();
    assert_eq!(m.update("hw", &mut |p| if p.is_none() { Some(json!(5)) } else { None }).unwrap(), Some(json!(5)));
    assert_eq!(m.update("hw", &mut |p| if p.is_none() { Some(json!(9)) } else { None }).unwrap(), Some(json!(5)));
    m.set("b", &json!({"x": [1, null]})).unwrap();
    assert_eq!(m.keys().unwrap(), vec!["b", "hw"]);
    assert_eq!(m.snapshot().get("b"), Some(&json!({"x": [1, null]})));
    assert_eq!(m.update("nope", &mut |_| None).unwrap(), None);
}

// ---- real SIGKILL crash safety: the test binary re-runs itself and the child kills itself at the crash point ----

#[test]
fn crash_child() {
    let (Ok(dir), Ok(point)) = (std::env::var("PCA_DS_CRASH_DIR"), std::env::var("PCA_DS_CRASH_AT")) else { return };
    let at = if point == "after-temp-write" { CrashAt::AfterTempWrite } else { CrashAt::AfterJournalRename };
    let s = open_durable_state(DurableStateOptions { test_crash_at: Some(at), ..DurableStateOptions::new(&dir) }).unwrap();
    s.set("k", &json!("new")).unwrap();
    unreachable!("the process must have been killed");
}

fn crash_at(point: &str) -> PathBuf {
    let d = tmp();
    open_at(&d).set("k", &json!("old")).unwrap();
    let st = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture", "--test-threads=1"])
        .env("PCA_DS_CRASH_DIR", &d)
        .env("PCA_DS_CRASH_AT", point)
        .status()
        .unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(st.signal(), Some(9), "the child must die by SIGKILL");
    d
}

#[test]
fn killed_between_temp_write_and_rename_the_old_state_is_intact_and_the_dead_lock_is_taken_over() {
    let d = crash_at("after-temp-write");
    let s = open_durable_state(DurableStateOptions { lock_timeout_ms: Some(5_000), ..DurableStateOptions::new(&d) }).unwrap();
    assert_eq!(s.get("k").unwrap(), Some(json!("old")));
    s.set("k", &json!("later")).unwrap();
    s.verify().unwrap();
}

#[test]
fn killed_after_the_journal_rename_the_new_value_is_durable_and_the_head_is_repaired() {
    let d = crash_at("after-journal-rename");
    let s = open_durable_state(DurableStateOptions { lock_timeout_ms: Some(5_000), ..DurableStateOptions::new(&d) }).unwrap();
    assert_eq!(s.get("k").unwrap(), Some(json!("new")));
    let head: Value = atlas_pca::serde_json::from_str(&fs::read_to_string(d.join("state.head")).unwrap()).unwrap();
    assert_eq!(head["seq"], json!(s.verify().unwrap().seq), "the open repaired the head");
}

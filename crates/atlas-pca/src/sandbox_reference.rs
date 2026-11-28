//! The reference tool and component: hand-assembled core-WebAssembly modules (bytes) and a component in the WebAssembly text
//! format, so the sandbox can be shown working with no toolchain. Byte-for-byte the reference's output. Specs are the reference's
//! JSON objects; a missing integer member reads as 0 (as `undefined & 0x7f` does) and integers wrap to i32.

fn u(mut n: u64) -> Vec<u8> {
    let mut o = vec![];
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n > 0 {
            b |= 0x80;
        }
        o.push(b);
        if n == 0 {
            return o;
        }
    }
}
fn s(x: &str) -> Vec<u8> {
    // the length is the UTF-16 length, the content UTF-8 (as the reference writes it)
    [u(x.encode_utf16().count() as u64), x.as_bytes().to_vec()].concat()
}
fn section(id: u8, body: Vec<u8>) -> Vec<u8> {
    [vec![id], u(body.len() as u64), body].concat()
}
fn vec_of(items: Vec<Vec<u8>>) -> Vec<u8> {
    [u(items.len() as u64), items.concat()].concat()
}
fn sleb(mut n: i32) -> Vec<u8> {
    let mut o = vec![];
    loop {
        let b = (n & 0x7f) as u8;
        n >>= 7;
        if (n == 0 && b & 0x40 == 0) || (n == -1 && b & 0x40 != 0) {
            o.push(b);
            return o;
        }
        o.push(b | 0x80);
    }
}
fn i32c(n: i32) -> Vec<u8> {
    [vec![0x41], sleb(n)].concat()
}
fn int(v: &serde_json::Value, k: &str) -> i32 {
    v.get(k).and_then(serde_json::Value::as_f64).filter(|f| f.is_finite()).map(|f| f as i64 as i32).unwrap_or(0)
}
const HEAD: [u8; 8] = [0, 0x61, 0x73, 0x6d, 1, 0, 0, 0];

/// A module that calls `pca:act.invoke(handle, ptr, cap)` for each of `spec.calls` and returns the last call's code (`returns`
/// "last", the default) or the first byte of linear memory ("byte0"). Other members: `extraImports` `[{module, name}]` (ambient
/// authority the host must refuse), `memory` `{min, max}` (`max: null` declares none), `spin` (loop forever after the calls).
pub fn build_tool(spec: &serde_json::Value) -> Result<Vec<u8>, String> {
    let calls = spec.get("calls").and_then(|c| c.as_array()).ok_or("spec.calls is not an array")?;
    let extra: Vec<&serde_json::Value> = spec.get("extraImports").and_then(|c| c.as_array()).map(|a| a.iter().collect()).unwrap_or_default();
    let types = vec_of(vec![vec![0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f], vec![0x60, 0, 1, 0x7f], vec![0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]]);
    let mut imps = vec![[s("pca:act"), s("invoke"), vec![0, 0]].concat()];
    for e in &extra {
        let g = |k: &str| e.get(k).and_then(|x| x.as_str()).ok_or(format!("extraImports.{k} is not a string"));
        imps.push([s(g("module")?), s(g("name")?), vec![0, 2]].concat());
    }
    let imports = vec_of(imps);
    let (min, max) = match spec.get("memory") {
        Some(m) => (m.get("min").and_then(|x| x.as_u64()).unwrap_or(1), m.get("max").and_then(|x| x.as_u64())),
        None => (1, Some(1)),
    };
    let memory = vec_of(vec![match max {
        None => [vec![0], u(min)].concat(),
        Some(mx) => [vec![1], u(min), u(mx)].concat(),
    }]);
    let run_index = 1 + extra.len() as u64;
    let returns = spec.get("returns").and_then(|x| x.as_str());
    let mut body: Vec<u8> = vec![0]; // no locals
    for (i, c) in calls.iter().enumerate() {
        body.extend([i32c(int(c, "handle")), i32c(int(c, "ptr")), i32c(int(c, "cap")), vec![0x10, 0]].concat());
        if !(i == calls.len() - 1 && returns.unwrap_or("last") == "last") {
            body.push(0x1a);
        }
    }
    if spec.get("spin").is_some_and(|x| !matches!(x, serde_json::Value::Null | serde_json::Value::Bool(false))) {
        body.extend([0x03, 0x40, 0x0c, 0x00, 0x0b]);
    }
    if returns == Some("byte0") {
        body.extend([i32c(0), vec![0x2d, 0, 0]].concat());
    }
    if calls.is_empty() {
        body.extend(i32c(0));
    }
    body.push(0x0b);
    let exports = vec_of(vec![[s("memory"), vec![2, 0]].concat(), [s("run"), vec![0], u(run_index)].concat()]);
    Ok([
        HEAD.to_vec(),
        section(1, types),
        section(2, imports),
        section(3, vec_of(vec![vec![1]])),
        section(5, memory),
        section(7, exports),
        section(10, vec_of(vec![[u(body.len() as u64), body].concat()])),
    ]
    .concat())
}

/// A tool that asks the table what it holds: returns `handle_count() * 256 + first byte of handle 1's verb` (the verb window is
/// `cap` bytes; the reference's default is 64).
pub fn build_probe_tool(cap: Option<i32>) -> Vec<u8> {
    let cap = cap.unwrap_or(64);
    let types = vec_of(vec![vec![0x60, 3, 0x7f, 0x7f, 0x7f, 1, 0x7f], vec![0x60, 0, 1, 0x7f]]);
    let imports = vec_of(vec![
        [s("pca:act"), s("invoke"), vec![0, 0]].concat(),
        [s("pca:act"), s("handle_count"), vec![0, 1]].concat(),
        [s("pca:act"), s("handle_verb"), vec![0, 0]].concat(),
    ]);
    let body = [vec![0], i32c(1), i32c(0), i32c(cap), vec![0x10, 2, 0x1a, 0x10, 1], i32c(256), vec![0x6c], i32c(0), vec![0x2d, 0, 0, 0x6a, 0x0b]].concat();
    [
        HEAD.to_vec(),
        section(1, types),
        section(2, imports),
        section(3, vec_of(vec![vec![1]])),
        section(5, vec_of(vec![vec![1, 1, 1]])),
        section(7, vec_of(vec![[s("memory"), vec![2, 0]].concat(), [s("run"), vec![0, 3]].concat()])),
        section(10, vec_of(vec![[u(body.len() as u64), body].concat()])),
    ]
    .concat()
}

/// The reference tool as a component in the WebAssembly text format: imports only `pca:act/invoke@0.1.0`, exports
/// `run: func() -> s32`. Options (`o`, may be absent): `handle` (default 1), `spin` (loop forever), `extraImport` (an extra
/// import the host must refuse; empty = none).
pub fn reference_component_wat(o: Option<&serde_json::Value>) -> String {
    let get = |k: &str| o.and_then(|v| v.get(k));
    let extra = match get("extraImport").and_then(|x| x.as_str()).filter(|x| !x.is_empty()) {
        Some(e) => format!("(import \"{e}\" (instance (export \"get-arguments\" (func (result (list string))))))"),
        None => String::new(),
    };
    let spin = get("spin")
        .is_some_and(|x| !matches!(x, serde_json::Value::Null | serde_json::Value::Bool(false)) && x.as_f64() != Some(0.0) && x.as_str() != Some(""));
    let handle = match get("handle") {
        Some(h) if !h.is_null() => h.as_i64().map(|i| i.to_string()).unwrap_or_else(|| crate::js_stringify(h)),
        _ => "1".into(),
    };
    let body = if spin {
        "(loop $l (br $l)) (i32.const 0)".to_string()
    } else {
        format!("(call $invoke (i32.const {handle}) (i32.const 16))\n       (if (result i32) (i32.load8_u (i32.const 16))\n         (then (i32.load (i32.const 20)))\n         (else (i32.load8_u (i32.load (i32.const 20)))))")
    };
    let extra_line = format!("  {extra}");
    let body_line = format!("      {body}))");
    [
        "(component",
        "  (import \"pca:act/invoke@0.1.0\" (instance $inv",
        "    (export \"handle-count\" (func (result u32)))",
        "    (export \"invoke\" (func (param \"handle\" u32) (result (result (list u8) (error s32)))))))",
        extra_line.as_str(),
        "  (core module $libc",
        "    (memory (export \"memory\") 1 1)",
        "    (global $bump (mut i32) (i32.const 1024))",
        "    (func (export \"realloc\") (param $old i32) (param $oldsz i32) (param $align i32) (param $new i32) (result i32)",
        "      (local $p i32)",
        "      (local.set $p (global.get $bump))",
        "      (global.set $bump (i32.add (local.get $p) (local.get $new)))",
        "      (local.get $p)))",
        "  (core instance $libc (instantiate $libc))",
        "  (alias core export $libc \"memory\" (core memory $mem))",
        "  (alias core export $libc \"realloc\" (core func $realloc))",
        "  (core func $count (canon lower (func $inv \"handle-count\")))",
        "  (core func $invoke (canon lower (func $inv \"invoke\") (memory $mem) (realloc $realloc)))",
        "  (core module $main",
        "    (import \"libc\" \"memory\" (memory 1))",
        "    (import \"host\" \"count\" (func $count (result i32)))",
        "    (import \"host\" \"invoke\" (func $invoke (param i32 i32)))",
        "    (func (export \"run\") (result i32)",
        body_line.as_str(),
        "  (core instance $host (export \"count\" (func $count)) (export \"invoke\" (func $invoke)))",
        "  (core instance $main (instantiate $main (with \"libc\" (instance $libc)) (with \"host\" (instance $host))))",
        "  (alias core export $main \"run\" (core func $run))",
        "  (func $lifted (result s32) (canon lift (core func $run)))",
        "  (export \"run\" (func $lifted)))",
        "",
    ]
    .join("\n")
}

//! Differential replay of the pure parts of the MPC networked runner (wire frame codec and splitter, canonical field hex, NetAbort,
//! pairwise-authenticated shares, forensic disclosures and their audit, the OT-over-network codecs including the Ed25519 point
//! codec, the gadget seed commitments) against the TypeScript reference (test-data/ref-mpc-net.json.gz). Bytes cross as
//! {"$bytes": base64url}; big integers as decimal strings. A reference throw only requires a refusal.
//! Skipped: nothing (sockets / TLS / the distributed driver are not in the corpus).
mod common;
use atlas_pca::mpc::mod_dec;
use atlas_pca::mpc_net::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use std::collections::BTreeMap;

static NULL: Value = Value::Null;
type R = Result<Value, String>;

fn arg(a: &[Value], i: usize) -> &Value {
    a.get(i).unwrap_or(&NULL)
}

fn err<E: ToString>(e: E) -> String {
    e.to_string()
}

fn text(v: &Value) -> Result<&str, String> {
    v.as_str().ok_or_else(|| "string expected".to_string())
}

fn int(v: &Value) -> Result<i64, String> {
    let f = v.as_f64().ok_or_else(|| "not a number".to_string())?;
    if !f.is_finite() || f != f.trunc() {
        return Err("not an integer".into());
    }
    Ok(f.clamp(-1e12, 1e12) as i64)
}

fn list(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "not a list".to_string())
}

fn bytes_arg(v: &Value) -> Result<Vec<u8>, String> {
    Ok(common::b64d(v.get("$bytes").and_then(Value::as_str).ok_or("bytes expected")?))
}

fn bytes_out(b: &[u8]) -> Value {
    json!({"$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)})
}

fn raw(v: &Value) -> Result<u64, String> {
    text(v)?.parse::<u64>().map_err(err)
}

fn dec(v: &Value) -> Result<u64, String> {
    mod_dec(text(v)?).map_err(err)
}

fn s(x: u64) -> Value {
    Value::String(x.to_string())
}

fn ls(x: &[u64]) -> Value {
    Value::Array(x.iter().map(|v| s(*v)).collect())
}

fn veq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| veq(p, q)),
        (Value::Object(x), Value::Object(y)) => x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| veq(v, w))),
        _ => a == b,
    }
}

fn opt_int(v: Option<i64>) -> Value {
    v.map_or(Value::Null, |x| json!(x))
}

// ---- pairwise-authenticated shares

fn pa_in(v: &Value) -> Result<Pa, String> {
    let m = v.as_object().ok_or_else(|| "not an object".to_string())?;
    let words = |k: &str| -> Result<Vec<u64>, String> { list(m.get(k).unwrap_or(&NULL))?.iter().map(raw).collect() };
    Ok(Pa { x: raw(m.get("x").unwrap_or(&NULL))?, tag: words("tag")?, key: words("key")? })
}

fn pa_out(p: &Pa) -> Value {
    json!({"x": s(p.x), "tag": ls(&p.tag), "key": ls(&p.key)})
}

fn aw_in(v: &Value) -> Result<Aw, String> {
    Ok(Aw { v: pa_in(v.get("v").unwrap_or(&NULL))?, m: list(v.get("m").unwrap_or(&NULL))?.iter().map(pa_in).collect::<Result<_, _>>()? })
}

fn aw_out(a: &Aw) -> Value {
    json!({"v": pa_out(&a.v), "m": Value::Array(a.m.iter().map(pa_out).collect())})
}

fn pa_op(a: &[Value]) -> R {
    let op = text(arg(a, 0))?;
    let x = pa_in(arg(a, 1))?;
    let n = x.tag.len();
    match op {
        "add" | "sub" => {
            let y = pa_in(arg(a, 2))?;
            Ok(pa_out(&if op == "add" { pa_add(&x, &y)? } else { pa_sub(&x, &y)? }))
        }
        "neg" => Ok(pa_out(&pa_neg(&x))),
        "scale" => Ok(pa_out(&pa_scale(&x, raw(arg(a, 2))?))),
        "addPublic0" => {
            let env = PaEnv { id: int(arg(a, 2))? as usize, n, delta: raw(arg(a, 3))?, tagged: arg(a, 4) == &Value::Bool(true) };
            Ok(pa_out(&pa_add_public0(&env, &x, raw(arg(a, 5))?)?))
        }
        "verify" => {
            let env = PaEnv { id: int(arg(a, 2))? as usize, n, delta: raw(arg(a, 3))?, tagged: true };
            Ok(Value::Bool(pa_verify(&env, &x, int(arg(a, 4))? as usize, raw(arg(a, 5))?, raw(arg(a, 6))?)?))
        }
        "flat" => {
            let (id, tagged) = (int(arg(a, 2))? as usize, arg(a, 3) == &Value::Bool(true));
            let f = pa_flat(&x, id, n, tagged)?;
            let back = pa_parse(&f, 0, id, n, tagged)?;
            Ok(json!({"f": ls(&f), "w": pa_width(n, tagged), "back": pa_out(&back)}))
        }
        o => Err(format!("unknown op {o}")),
    }
}

fn aw_op(name: &str, a: &[Value]) -> R {
    if name.starts_with("aw/sharingsPerTriple") {
        return Ok(json!(sharings_per_triple(int(arg(a, 0))? as usize)));
    }
    let x = aw_in(arg(a, 0))?;
    let n = x.v.tag.len();
    if name.starts_with("aw/ops") {
        let y = aw_in(arg(a, 1))?;
        let alpha: Vec<Pa> = list(arg(a, 2))?.iter().map(pa_in).collect::<Result<_, _>>()?;
        let tagged = arg(a, 3) == &Value::Bool(true);
        let c = raw(arg(a, 4))?;
        let env = |id| PaEnv { id, n, delta: 7, tagged };
        return Ok(json!({
            "add": aw_out(&w_add(&x, &y)?), "sub": aw_out(&w_sub(&x, &y)?), "neg": aw_out(&w_neg(&x)), "scale": aw_out(&w_scale(&x, c)),
            "addPublic": aw_out(&w_add_public(&env(1), &x, c, &alpha)?), "addPublic0": aw_out(&w_add_public(&env(0), &x, c, &alpha)?),
        }));
    }
    if name.starts_with("aw/flat") {
        let (id, tagged) = (int(arg(a, 1))? as usize, arg(a, 2) == &Value::Bool(true));
        let keys = x.m.len();
        let f = aw_flat(&x, id, n, tagged)?;
        let back = aw_parse(&f, 0, id, n, keys, tagged)?;
        return Ok(json!({"f": ls(&f), "w": aw_width(n, keys, tagged), "back": aw_out(&back)}));
    }
    Err(format!("unknown aw case {name}"))
}

// ---- forensics

fn side_dec(e: &[(i64, Vec<u64>)]) -> Value {
    Value::Array(e.iter().map(|(p, r)| json!([*p, ls(r)])).collect())
}

fn dis_dec(d: &[SlotDisclosure]) -> Value {
    Value::Array(d.iter().map(|x| json!({"bits": x.bits.clone(), "y": s(x.y), "z": s(x.z), "recv": side_dec(&x.recv), "rho": side_dec(&x.rho)})).collect())
}

fn side_in(v: &Value) -> Result<Vec<(i64, Vec<u64>)>, String> {
    list(v)?
        .iter()
        .map(|e| {
            let e = list(e)?;
            Ok((int(arg(e, 0))?, list(arg(e, 1))?.iter().map(dec).collect::<Result<_, _>>()?))
        })
        .collect()
}

fn dis_in(v: &Value) -> Result<Vec<SlotDisclosure>, String> {
    list(v)?
        .iter()
        .map(|x| {
            let bits = list(x.get("bits").unwrap_or(&NULL))?.iter().map(|b| int(b).map(|i| i as u8)).collect::<Result<_, _>>()?;
            Ok(SlotDisclosure {
                bits,
                y: dec(x.get("y").unwrap_or(&NULL))?,
                z: dec(x.get("z").unwrap_or(&NULL))?,
                recv: side_in(x.get("recv").unwrap_or(&NULL))?,
                rho: side_in(x.get("rho").unwrap_or(&NULL))?,
            })
        })
        .collect()
}

fn forensics(name: &str, a: &[Value]) -> R {
    let part = name.split('/').nth(1).unwrap_or("");
    match part {
        "parse" => {
            let peers: Vec<i64> = list(arg(a, 3))?.iter().map(int).collect::<Result<_, _>>()?;
            let dd = parse_disclosure(arg(a, 0), int(arg(a, 1))? as usize, int(arg(a, 2))? as usize, &peers)?;
            Ok(json!({"dd": dis_dec(&dd), "back": wire_disclosure(&dd)}))
        }
        "audit" => {
            let obj = arg(a, 0).as_object().ok_or("not an object")?;
            let mut all: BTreeMap<i64, Vec<SlotDisclosure>> = BTreeMap::new();
            for (k, v) in obj {
                all.insert(k.parse::<i64>().map_err(err)?, dis_in(v)?);
            }
            if !arg(a, 2).is_null() {
                all.remove(&int(arg(a, 2))?);
            }
            let gadget: Vec<u64> = list(arg(a, 1))?.iter().map(dec).collect::<Result<_, _>>()?;
            let res = audit_disclosures(&all, &gadget)?;
            let blame: Vec<Value> = (0..3).map(|me| opt_int(blame_from(me, &res))).collect();
            let pairs: Vec<Value> = res.pair_bad.iter().map(|(x, y)| json!([*x, *y])).collect();
            let self_bad: Vec<i64> = res.self_bad.iter().copied().collect();
            Ok(json!({"selfBad": self_bad, "pairBad": pairs, "blame": blame}))
        }
        "blame" => {
            let mut r = AuditResult::default();
            for p in list(arg(a, 1))? {
                r.self_bad.insert(int(p)?);
            }
            for p in list(arg(a, 2))? {
                let p = list(p)?;
                r.pair_bad.push((int(arg(p, 0))?, int(arg(p, 1))?));
            }
            Ok(opt_int(blame_from(int(arg(a, 0))?, &r)))
        }
        "commit" | "commit-scalar" => {
            Ok(Value::String(disclosure_commit(text(arg(a, 0))?, int(arg(a, 1))?, int(arg(a, 2))?, int(arg(a, 3))?, text(arg(a, 4))?, arg(a, 5))))
        }
        "slotsFor" => Ok(json!(slots_for(int(arg(a, 0))? as usize))),
        o => Err(format!("unknown forensics case {o}")),
    }
}

fn codec(a: &[Value]) -> R {
    match text(arg(a, 0))? {
        "unb64" => {
            let len = if arg(a, 2).is_null() { None } else { Some(int(arg(a, 2))? as usize) };
            Ok(bytes_out(&unb64(arg(a, 1), len)?))
        }
        "b64" => Ok(Value::String(b64(&bytes_arg(arg(a, 1))?))),
        "hexBig" => Ok(Value::String(hex_big(arg(a, 1))?.to_str_radix(10))),
        "jPt" => {
            let (x, y) = j_pt(arg(a, 1))?;
            Ok(pt_j(&x, &y))
        }
        "ptJ" => {
            let k = atlas_pca_biguint(text(arg(a, 1))?)?;
            let (x, y) = mul_base_affine(&k)?;
            Ok(pt_j(&x, &y))
        }
        "gadgetCommit" => Ok(Value::String(gadget_commit(text(arg(a, 1))?, int(arg(a, 2))?, &bytes_arg(arg(a, 3))?))),
        "gadgetStatement" => Ok(bytes_out(&gadget_statement(text(arg(a, 1))?, text(arg(a, 2))?, int(arg(a, 3))?, text(arg(a, 4))?))),
        o => Err(format!("unknown codec op {o}")),
    }
}

/// A non-negative decimal integer as the big integer type of the codec API.
fn atlas_pca_biguint(t: &str) -> Result<rsa::BigUint, String> {
    rsa::BigUint::parse_bytes(t.as_bytes(), 10).ok_or_else(|| "bigint arg".to_string())
}

fn abort_out(a: &NetAbort) -> Value {
    json!({
        "message": a.message, "name": "NetAbort", "kind": a.kind, "blamed": opt_int(a.blamed), "reporter": a.reporter, "reason": a.reason,
        "claimedKind": a.claimed_kind, "claimedBlame": opt_int(a.claimed_blame), "evidence": a.evidence.clone().unwrap_or(Value::Null), "deadlineMs": opt_int(a.deadline_ms),
    })
}

fn run(f: &str, name: &str, a: &[Value]) -> R {
    match f {
        "encodeFrame" => Ok(bytes_out(&encode_frame(arg(a, 0))?)),
        "split" => {
            let mut sp = FrameSplitter::new();
            let mut frames = vec![];
            for c in list(arg(a, 0))? {
                for fr in sp.push(&bytes_arg(c)?)? {
                    frames.push(bytes_out(&fr));
                }
            }
            Ok(json!({"frames": frames}))
        }
        "peekVersion" => Ok(opt_int(peek_version(&bytes_arg(arg(a, 0))?))),
        "parseFrame" => Ok(parse_frame(&bytes_arg(arg(a, 0))?).unwrap_or(Value::Null)),
        "versionMismatch" => Ok(opt_int(version_mismatch(&bytes_arg(arg(a, 0))?))),
        "hx" => Ok(Value::String(hx(text(arg(a, 0))?.parse::<i128>().map_err(err)?))),
        "unhx" => Ok(unhx_value(arg(a, 0)).map_or(Value::Null, s)),
        "unhxArray" => Ok(unhx_array(arg(a, 0), int(arg(a, 1))? as usize).map_or(Value::Null, |v| ls(&v))),
        "netAbort" => {
            let opts_v = arg(a, 6);
            let opts = NetAbortOpts {
                reason: opts_v.get("reason").and_then(Value::as_str).map(String::from),
                evidence: opts_v.get("evidence").cloned(),
                deadline_ms: opts_v.get("deadlineMs").and_then(Value::as_i64),
            };
            let blamed = if arg(a, 1).is_null() { None } else { Some(int(arg(a, 1))?) };
            let claimed_blame = arg(a, 5).as_f64().map(|f| f as i64);
            let ab = NetAbort::new(text(arg(a, 0))?, blamed, int(arg(a, 2))?, text(arg(a, 3))?, arg(a, 4).as_str(), claimed_blame, opts);
            Ok(abort_out(&ab))
        }
        "abortKinds" => {
            let mut k = ABORT_KINDS.to_vec();
            k.sort();
            Ok(json!(k))
        }
        "pa" => pa_op(a),
        "aw" => aw_op(name, a),
        "forensics" => forensics(name, a),
        "codec" => codec(a),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn replays_the_mpc_net_pure_parts() {
    let cases = common::ref_cases("mpc-net");
    assert!(cases.len() > 300, "corpus shrank: {}", cases.len());
    let mut failures = vec![];
    for c in &cases {
        let f = c["fn"].as_str().expect("fn");
        let name = c["name"].as_str().expect("name");
        let args = c["args"].as_array().expect("args");
        let want = &c["out"];
        let got = run(f, name, args);
        if want.get("$throws").is_some() {
            if let Ok(v) = got {
                failures.push(format!("{name}: the reference refuses but the native returned {v}"));
            }
        } else {
            match got {
                Ok(v) if veq(&v, want) => {}
                Ok(v) => failures.push(format!("{name}: got {v}, want {want}")),
                Err(e) => failures.push(format!("{name}: refused ({e}), want {want}")),
            }
        }
    }
    let shown: Vec<&String> = failures.iter().take(10).collect();
    assert!(failures.is_empty(), "{} of {} cases differ; first: {:#?}", failures.len(), cases.len(), shown);
}

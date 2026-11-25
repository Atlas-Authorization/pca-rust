//! Differential replay of the SCITT package (deterministic CBOR codec, RFC 9162 Merkle tree, COSE Signed Statements and Receipts,
//! the in-memory and durable transparency services) against the TypeScript reference (test-data/ref-scitt.json.gz). Ed25519 is
//! deterministic, so signed bytes compare exactly; ES256 material is verify-only in the corpus (JS-signed bytes), the sign-side
//! ES256 cases compare verification outcomes. A reference throw only requires a refusal (checkStatement's `malformed:` reasons
//! compare by prefix). Skipped: cases whose arguments hold a lone surrogate (no Rust string), and checkScittLogStore (the reference's
//! generic store contract checker; the file store has its own byte-level replay below: fileStoreBytes, fileStoreOpen).
mod common;
use atlas_pca::scitt::*;
use atlas_pca::scitt_file::FileScittLogStore;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;

const HALF_N: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC,
    0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn by(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn bytes_v(b: &[u8]) -> Value {
    json!({ "$bytes": b64u(b) })
}

fn list(v: &Value) -> Vec<Vec<u8>> {
    v.as_array().expect("array").iter().map(by).collect()
}

fn list_v(l: &[Vec<u8>]) -> Value {
    Value::Array(l.iter().map(|h| bytes_v(h)).collect())
}

fn num(v: &Value) -> f64 {
    v.as_f64().expect("number")
}

fn from_cj(v: &Value) -> Result<Cbor, String> {
    match v {
        Value::Null => Ok(Cbor::Null),
        Value::Bool(b) => Ok(Cbor::Bool(*b)),
        Value::Number(n) => cbor_int_from_number(n),
        Value::String(s) => Ok(Cbor::Text(s.clone())),
        Value::Array(a) => Ok(Cbor::Array(a.iter().map(from_cj).collect::<Result<Vec<_>, _>>()?)),
        Value::Object(o) => {
            if o.contains_key("$bytes") {
                Ok(Cbor::Bytes(by(v)))
            } else if let Some(m) = o.get("$map") {
                // a JavaScript Map holds one entry per key: a repeated key keeps its first slot and takes the last value
                let mut es: Vec<(Cbor, Cbor)> = Vec::new();
                for e in m.as_array().ok_or("$map")? {
                    // a Map key is normalised by SameValueZero: -0 is 0 (a bare -0 value is still refused)
                    let key = if e[0].as_f64().is_some_and(|f| f == 0.0) { json!(0) } else { e[0].clone() };
                    let (k, v) = (from_cj(&key)?, from_cj(&e[1])?);
                    match es.iter_mut().find(|(k0, _)| *k0 == k) {
                        Some(slot) => slot.1 = v,
                        None => es.push((k, v)),
                    }
                }
                Ok(Cbor::Map(es))
            } else if let Some(t) = o.get("$tag") {
                let tag = t.as_u64().ok_or("cbor: bad tag")?;
                Ok(Cbor::Tag(tag, Box::new(from_cj(&o["v"])?)))
            } else {
                Err("bad cj".into())
            }
        }
    }
}

fn to_cj(c: &Cbor) -> Value {
    match c {
        Cbor::Int(i) => json!(i),
        Cbor::Text(s) => json!(s),
        Cbor::Bytes(b) => bytes_v(b),
        Cbor::Bool(b) => json!(b),
        Cbor::Null => Value::Null,
        Cbor::Array(a) => Value::Array(a.iter().map(to_cj).collect()),
        Cbor::Map(m) => json!({ "$map": m.iter().map(|(k, v)| json!([to_cj(k), to_cj(v)])).collect::<Vec<_>>() }),
        Cbor::Tag(t, v) => json!({ "$tag": t, "v": to_cj(v) }),
    }
}

fn reg_v(r: &Registration) -> Value {
    json!({ "index": r.index, "receipt": bytes_v(&r.receipt), "root": r.root })
}

fn app_v(r: &AppendResult) -> Value {
    let mut v = reg_v(&r.registration);
    v["statement"] = bytes_v(&r.statement);
    v
}

fn cp_v(c: &ConsistencyProofResult) -> Value {
    json!({ "oldSize": c.old_size, "newSize": c.new_size, "oldRoot": c.old_root, "newRoot": c.new_root, "proof": bytes_v(&c.proof) })
}

/// A durable store with the oracle's injected faults.
struct Faulty {
    inner: MemoryScittLogStore,
    drop: Option<(u32, u64)>,
    short: Option<(u32, u64)>,
    neg: bool,
    stale: bool,
}

impl ScittLogStore for Faulty {
    fn size(&self) -> i64 {
        if self.neg {
            -1
        } else {
            self.inner.size()
        }
    }
    fn get_entry(&self, index: u64) -> Option<Vec<u8>> {
        self.inner.get_entry(index)
    }
    fn get_node(&self, level: u32, index: u64) -> Option<Vec<u8>> {
        if self.drop == Some((level, index)) {
            return None;
        }
        if self.short == Some((level, index)) {
            return Some(vec![0; 31]);
        }
        self.inner.get_node(level, index)
    }
    fn append(&mut self, expected_size: u64, entry: &[u8], nodes: &[StoredNode]) -> bool {
        !self.stale && self.inner.append(expected_size, entry, nodes)
    }
}

enum Svc {
    Mem(TransparencyService),
    Dur(DurableTransparencyService<Faulty>),
}

fn me(_e: String) -> Value {
    json!(true)
}

fn de(e: ScittLogError) -> Value {
    if e.code.is_empty() {
        json!(true)
    } else {
        json!(e.code)
    }
}

fn pair(v: &Value) -> Option<(u32, u64)> {
    let a = v.as_array()?;
    Some((a.first()?.as_u64()? as u32, a.get(1)?.as_u64()?))
}

fn service_op(svc: &mut Svc, spec: &Value, op: &Value) -> Result<Value, Value> {
    let name = op["op"].as_str().expect("op");
    let append_opts = || {
        let mut o = json!({ "alg": "EdDSA", "key": spec["stmtKey"], "issuer": "https://issuer.example" });
        for k in ["subject", "contentType"] {
            if let Some(x) = op.get(k) {
                o[k] = x.clone();
            }
        }
        o
    };
    let (i, m) = (op.get("i").map(num).unwrap_or(f64::NAN), op.get("m").map(num).unwrap_or(f64::NAN));
    match svc {
        Svc::Mem(s) => match name {
            "append" => s.append_and_receipt(&op["payload"], &append_opts()).map(|r| app_v(&r)).map_err(me),
            "register" => s.register(&by(&op["statement"])).map(|r| reg_v(&r)).map_err(me),
            "receipt" => s.get_receipt(i).map(|r| reg_v(&r)).map_err(me),
            "consistency" => s.consistency_proof(m).map(|c| cp_v(&c)).map_err(me),
            "snapshot" => Ok(json!(s.snapshot())),
            "root" => Ok(json!(s.root())),
            "size" => Ok(json!(s.size())),
            _ => Err(json!(true)), // the in-memory service has no getEntry
        },
        Svc::Dur(s) => match name {
            "append" => s.append_and_receipt(&op["payload"], &append_opts()).map(|r| app_v(&r)).map_err(de),
            "register" => s.register(&by(&op["statement"])).map(|r| reg_v(&r)).map_err(de),
            "receipt" => s.get_receipt(i).map(|r| reg_v(&r)).map_err(de),
            "consistency" => s.consistency_proof(m).map(|c| cp_v(&c)).map_err(de),
            "entry" => s.get_entry(i).map(|e| bytes_v(&e)).map_err(de),
            "root" => s.root().map(|r| json!(r)).map_err(de),
            "size" => s.size().map(|n| json!(n)).map_err(de),
            _ => Err(json!(true)), // the durable service has no snapshot
        },
    }
}

fn service(spec: &Value) -> Result<Value, String> {
    let key = &spec["key"];
    let mut signer = json!({ "alg": key["alg"], "key": key });
    if let Some(i) = spec.get("issuer") {
        signer["issuer"] = i.clone();
    }
    let mut svc = if spec["kind"] == "durable" {
        let f = spec.get("storeFault");
        let fault = |k: &str| f.and_then(|f| f.get(k)).and_then(pair);
        Svc::Dur(DurableTransparencyService::new(
            Faulty {
                inner: MemoryScittLogStore::new(),
                drop: fault("dropNode"),
                short: fault("shortNode"),
                neg: f.and_then(|f| f.get("negSize")).is_some(),
                stale: f.and_then(|f| f.get("stale")).is_some(),
            },
            signer,
        ))
    } else {
        Svc::Mem(TransparencyService::new(signer))
    };
    let res: Vec<Value> = spec["ops"]
        .as_array()
        .ok_or("ops")?
        .iter()
        .map(|op| match service_op(&mut svc, spec, op) {
            Ok(v) => json!({ "ok": v }),
            Err(e) => json!({ "err": e }),
        })
        .collect();
    Ok(Value::Array(res))
}

fn es256_sign_verify(a: &[Value]) -> Result<Value, String> {
    let st = sign_statement(&a[1], &json!({ "alg": "ES256", "key": a[0], "issuer": a[2] }))?;
    let c = decode_cose_sign1(&st)?;
    let pubk = json!({ "alg": "ES256", "x": a[0]["x"], "y": a[0]["y"] });
    Ok(json!({
        "check": check_statement(&st, &pubk, false),
        "payload": bytes_v(&statement_payload(&st)?),
        "lowS": c.signature[32..] <= HALF_N[..],
        "protectedBytes": bytes_v(&c.protected_bytes),
    }))
}

fn es256_receipt(a: &[Value]) -> Result<Value, String> {
    let n = a[1].as_u64().ok_or("n")? as usize;
    let index = a[2].as_u64().ok_or("index")? as usize;
    let mut ts = TransparencyService::new(json!({ "alg": "ES256", "key": a[0], "issuer": "ts" }));
    let ed_opts = json!({ "alg": "EdDSA", "key": a[3], "issuer": "iss" });
    let mut sts = Vec::new();
    for i in 0..n {
        sts.push(ts.append_and_receipt(&json!({ "i": i }), &ed_opts)?.statement);
    }
    let pubk = json!({ "alg": "ES256", "x": a[0]["x"], "y": a[0]["y"] });
    let seed: [u8; 32] = common::b64d(a[3]["seed"].as_str().ok_or("seed")?).try_into().map_err(|_| "seed length")?;
    let ed_pub = json!({ "alg": "EdDSA", "pub": b64u(&ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key().to_bytes()) });
    let r = ts.get_receipt(index as f64)?;
    let st = &sts[index];
    Ok(json!({
        "key": verify_receipt(&r.receipt, st, &json!({ "verificationKey": pubk })),
        "root": verify_receipt(&r.receipt, st, &json!({ "treeRoot": r.root })),
        "both": verify_receipt(&r.receipt, st, &json!({ "verificationKey": pubk, "treeRoot": r.root, "statementKey": ed_pub })),
        "wrongKey": verify_receipt(&r.receipt, st, &json!({ "verificationKey": a[4] })),
        "otherStatement": verify_receipt(&r.receipt, &sts[(index + 1) % n], &json!({ "verificationKey": pubk })),
        "none": verify_receipt(&r.receipt, st, &json!({})),
    }))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    let s = |i: usize| a[i].as_str().ok_or_else(|| "string expected".to_string());
    match f {
        "cborEncode" => encode(&from_cj(&a[0])?).map(|b| bytes_v(&b)),
        "cborDecode" => decode(&by(&a[0])).map(|c| to_cj(&c)),
        "emptyRoot" => Ok(bytes_v(&empty_root())),
        "leafHash" => Ok(bytes_v(&leaf_hash(&by(&a[0])))),
        "nodeHash" => Ok(bytes_v(&node_hash(&by(&a[0]), &by(&a[1])))),
        "treeHash" => Ok(bytes_v(&tree_hash(&list(&a[0])))),
        "inclusionPath" => inclusion_path(&list(&a[0]), num(&a[1])).map(|p| list_v(&p)),
        "rootFromInclusionPath" => Ok(root_from_inclusion_path(&by(&a[0]), num(&a[1]), num(&a[2]), &list(&a[3])).map_or(Value::Null, |r| bytes_v(&r))),
        "verifyInclusionPath" => Ok(json!(verify_inclusion_path(&by(&a[0]), num(&a[1]), num(&a[2]), &list(&a[3]), &by(&a[4])))),
        "consistencyPath" => consistency_path(&list(&a[0]), num(&a[1])).map(|p| list_v(&p)),
        "verifyConsistencyPath" => Ok(json!(verify_consistency_path(num(&a[0]), num(&a[1]), &by(&a[2]), &by(&a[3]), &list(&a[4])))),
        "siblingSides" => Ok(json!(sibling_sides(a[0].as_i64().ok_or("index")?, a[1].as_i64().ok_or("size")?))),
        "encodeInclusionProof" => encode_inclusion_proof(&a[0]).map(|b| bytes_v(&b)),
        "decodeInclusionProof" => decode_inclusion_proof(&by(&a[0])),
        "signStatement" => sign_statement(&a[0], &a[1]).map(|b| bytes_v(&b)),
        "decodeCoseSign1" => decode_cose_sign1(&by(&a[0])).map(|c| {
            json!({
                "protectedBytes": bytes_v(&c.protected_bytes),
                "protectedMap": to_cj(&c.protected_map),
                "unprotected": to_cj(&c.unprotected),
                "payload": c.payload.as_ref().map_or(Value::Null, |p| bytes_v(p)),
                "signature": bytes_v(&c.signature),
            })
        }),
        "checkStatement" | "verifyStatement" => {
            let high = a.get(2).and_then(|o| o.get("allowHighS")) == Some(&Value::Bool(true));
            let r = check_statement(&by(&a[0]), &a[1], high);
            Ok(if f == "checkStatement" { r } else { json!(r["ok"] == Value::Bool(true)) })
        }
        "statementPayload" => statement_payload(&by(&a[0])).map(|b| bytes_v(&b)),
        "statementLeaf" => Ok(json!(statement_leaf(&by(&a[0])))),
        "buildReceipt" => build_receipt(s(0)?, &a[1], &a[2]).map(|b| bytes_v(&b)),
        "verifyReceipt" => Ok(json!(verify_receipt(&by(&a[0]), &by(&a[1]), &a[2]))),
        "verifyConsistencyProof" => Ok(json!(verify_consistency_proof(&by(&a[0]), s(1)?, s(2)?))),
        "es256SignVerify" => es256_sign_verify(a),
        "es256Receipt" => es256_receipt(a),
        "service" => service(&a[0]),
        "constants" => Ok(json!({
            "COSE_SIGN1_TAG": COSE_SIGN1_TAG, "HDR_ALG": HDR_ALG, "HDR_CONTENT_TYPE": HDR_CONTENT_TYPE, "HDR_CWT_CLAIMS": HDR_CWT_CLAIMS,
            "CWT_ISS": CWT_ISS, "CWT_SUB": CWT_SUB, "HDR_VDS": HDR_VDS, "HDR_VDS_PROOFS": HDR_VDS_PROOFS, "VDS_RFC9162_SHA256": VDS_RFC9162_SHA256,
            "PROOF_TYPE_INCLUSION": PROOF_TYPE_INCLUSION, "DEFAULT_CONTENT_TYPE": DEFAULT_CONTENT_TYPE,
        })),
        f => panic!("unknown fn {f}"),
    }
}

fn same(f: &str, want: &Value, got: &Value) -> bool {
    if f == "checkStatement" {
        let (wr, gr) = (want.get("reason").and_then(Value::as_str), got.get("reason").and_then(Value::as_str));
        if let (Some(w), Some(g)) = (wr, gr) {
            if w.starts_with("malformed:") {
                return g.starts_with("malformed:") && want["ok"] == got["ok"];
            }
        }
    }
    atlas_pca::canonicalize(want) == atlas_pca::canonicalize(got)
}

#[test]
fn scitt_vectors() {
    let cases = common::ref_cases_seeded("scitt");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) || matches!(f, "fileStoreBytes" | "fileStoreOpen" | "checkScittLogStore") {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, c["args"].as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => same(f, &c["out"], v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

fn tmp_path(tag: &str) -> std::path::PathBuf {
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    std::env::temp_dir().join(format!("atlas-scitt-{}-{}-{tag}.log", std::process::id(), N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)))
}

#[test]
fn scitt_file_store_vectors() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in common::ref_cases_seeded("scitt") {
        let f = c["fn"].as_str().unwrap();
        let a = c["args"].as_array().unwrap();
        let path = tmp_path(f);
        let want = &c["out"];
        match f {
            "fileStoreBytes" => {
                n += 1;
                let mut s = FileScittLogStore::open(&path).expect("open");
                for op in a[0].as_array().unwrap() {
                    let nodes: Option<Vec<StoredNode>> = op["nodes"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|t| {
                            Some(StoredNode {
                                level: u32::try_from(t[0].as_i64()?).ok()?,
                                index: u64::try_from(t[1].as_i64()?).ok()?,
                                hash: common::b64d(t[2].as_str()?),
                            })
                        })
                        .collect();
                    // a negative level / index is a refused append in the reference (nothing written)
                    let Some(nodes) = nodes else { continue };
                    let _ = s.try_append(op["expected"].as_u64().unwrap_or(u64::MAX), &by(&op["entry"]), &nodes);
                }
                drop(s);
                let got = bytes_v(&std::fs::read(&path).unwrap());
                if &got != want {
                    bad.push(format!("{}: file bytes differ", c["name"]));
                }
            }
            "fileStoreOpen" => {
                n += 1;
                std::fs::write(&path, by(&a[0])).unwrap();
                let opened = FileScittLogStore::open(&path);
                match (want.get("$throws"), opened) {
                    (Some(_), Err(e)) => {
                        if let Some(code) = want.get("code").and_then(Value::as_str) {
                            if e.code != code {
                                bad.push(format!("{}: code {} want {code}", c["name"], e.code));
                            }
                        }
                    }
                    (None, Ok(s)) => {
                        let size = s.size();
                        let entries: Vec<Value> = (0..size as u64).map(|i| bytes_v(&s.get_entry(i).unwrap())).collect();
                        let nodes0: Vec<Value> = (0..size as u64).map(|i| s.get_node(0, i).map_or(Value::Null, |h| bytes_v(&h))).collect();
                        drop(s);
                        let got = json!({ "size": size, "entries": entries, "nodes0": nodes0, "after": bytes_v(&std::fs::read(&path).unwrap()) });
                        if atlas_pca::canonicalize(&got) != atlas_pca::canonicalize(want) {
                            bad.push(format!("{}: state differs", c["name"]));
                        }
                    }
                    _ => bad.push(format!("{}: throw/ok mismatch", c["name"])),
                }
            }
            _ => {}
        }
        let _ = std::fs::remove_file(&path);
    }
    assert!(n >= 100, "only {n} file-store cases");
    assert!(bad.is_empty(), "{} file-store cases differ:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn scitt_log_store_contract_checker() {
    let mut n = 0;
    for c in common::ref_cases_seeded("scitt") {
        if c["fn"] != "checkScittLogStore" {
            continue;
        }
        n += 1;
        let got: Vec<String> = match c["args"][0].as_str().unwrap() {
            "memory" => check_scitt_log_store(|| Ok(MemoryScittLogStore::new())),
            _ => check_scitt_log_store(|| FileScittLogStore::open(tmp_path("check")).map_err(|e| e.message)),
        };
        let want: Vec<String> = c["out"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
        assert_eq!(got, want, "{}", c["name"]);
    }
    assert_eq!(n, 2);
}

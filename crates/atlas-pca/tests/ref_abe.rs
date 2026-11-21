//! Differential replay of the FAME attribute-based encryption package (scheme arithmetic with fixed scalars, GT and pairing
//! helpers, policy normalisation, ciphertext parsing, decrypt of reference-made keys and ciphertexts, capability attributes)
//! against the TypeScript reference (test-data/ref-abe-go.json.gz). A reference throw only requires a refusal.
//! The corpus carries no key bytes: master and user keys are recipes ({"$abeMsk": label}, {"$abeKey": {msk, attrs, id}}, edited by
//! "$patch"/"$edits" or merged by "$pool") re-derived here from sha512("abe-oracle/" + label) mod r, exactly as the generator does.
//! Skipped (counted, must stay under 10%): cases whose arguments hold a lone surrogate, which a Rust string cannot represent
//! (the reference refuses those attribute names; here they are unrepresentable by construction).
mod common;
use atlas_pca::abe::*;
use atlas_pca::bbs::Fr;
use atlas_pca::serde_json::{json, Value};
use sha2::{Digest, Sha512};
use std::collections::HashMap;

fn bytes(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn b(x: &[u8]) -> Value {
    use base64::Engine;
    json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x) })
}

fn fr(v: &Value) -> Fr {
    Fr::from_hex(v.as_str().expect("hex scalar")).expect("scalar")
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().expect("list").iter().map(|x| x.as_str().unwrap_or_default().to_string()).collect()
}

fn opts(v: &Value) -> CapabilityOpts {
    CapabilityOpts {
        chain: v.get("chain").and_then(Value::as_array).cloned(),
        principal: v.get("principal").and_then(Value::as_str).map(String::from),
        pq_pins: v
            .get("pqPins")
            .and_then(Value::as_object)
            .map(|m| m.iter().filter_map(|(k, x)| Some((k.clone(), x.as_str()?.to_string()))).collect::<HashMap<_, _>>()),
    }
}

fn g1l(x: &[atlas_pca::bbs::ec::G1; 3]) -> Value {
    Value::Array(x.iter().map(|p| b(&p.to_bytes())).collect())
}

fn g2l(x: &[atlas_pca::bbs::ec::G2; 3]) -> Value {
    Value::Array(x.iter().map(|p| b(&p.to_bytes())).collect())
}

/// A fixed non-zero scalar from a label: sha512("abe-oracle/" + label) mod r (1 for 0).
fn sc(label: &str) -> Fr {
    let f = Fr::from_be_reduce(&Sha512::digest(format!("abe-oracle/{label}").as_bytes()));
    if f.is_zero() {
        Fr::from_u64(1)
    } else {
        f
    }
}

fn b64u(x: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x)
}

fn tri1(x: &[atlas_pca::bbs::ec::G1; 3]) -> Value {
    json!(x.iter().map(|p| b64u(&p.to_bytes())).collect::<Vec<_>>())
}

fn seeded_msk_raw(label: &str) -> FameMsk {
    let s = |n: &str| sc(&format!("{label}/{n}"));
    fame_setup([s("a1"), s("a2")], [s("b1"), s("b2")], [s("d1"), s("d2"), s("d3")]).expect("seeded setup").1
}

fn seeded_msk(label: &str) -> Value {
    let msk = seeded_msk_raw(label);
    json!({"v": 2, "curve": "bls12-381",
        "a": [b64u(&msk.a[0].to_be_bytes()), b64u(&msk.a[1].to_be_bytes())],
        "b": [b64u(&msk.b[0].to_be_bytes()), b64u(&msk.b[1].to_be_bytes())],
        "g": tri1(&msk.g)})
}

fn seeded_key(spec: &Value) -> Value {
    let id = spec["id"].as_str().expect("id");
    let mut names: Vec<String> = Vec::new();
    for a in strs(&spec["attrs"]) {
        if !a.is_empty() && !names.contains(&a) {
            names.push(a);
        }
    }
    let msk = seeded_msk_raw(spec["msk"].as_str().expect("msk"));
    let sigmas: Vec<Fr> = (0..names.len()).map(|i| sc(&format!("{id}/sg{i}"))).collect();
    let key = fame_keygen(&msk, &names, [sc(&format!("{id}/r1")), sc(&format!("{id}/r2"))], &sigmas, &sc(&format!("{id}/sgp"))).expect("seeded keygen");
    let attrs: atlas_pca::serde_json::Map<String, Value> = names.iter().map(|n| (n.clone(), json!({"k": tri1(&key.attrs[n])}))).collect();
    json!({"v": 2, "curve": "bls12-381",
        "k0": key.k0.iter().map(|p| b64u(&p.to_bytes())).collect::<Vec<_>>(),
        "kp": tri1(&key.kp), "attrs": Value::Object(attrs)})
}

fn at<'a>(v: &'a Value, path: &[Value]) -> &'a Value {
    path.iter().fold(v, |x, k| match k {
        Value::String(n) => &x[n.as_str()],
        _ => &x[k.as_u64().expect("index") as usize],
    })
}

/// Applies one edit: set (or delete, for `undefined`) the position `path` of `root`.
fn set_at(root: &mut Value, path: &[Value], val: Value, delete: bool) {
    let (last, parent) = path.split_last().expect("path");
    let mut p = root;
    for k in parent {
        p = match k {
            Value::String(n) => &mut p[n.as_str()],
            _ => &mut p[k.as_u64().expect("index") as usize],
        };
    }
    match last {
        Value::String(n) if delete => {
            p.as_object_mut().expect("object").remove(n);
        }
        Value::String(n) => p[n.as_str()] = val,
        _ => p[last.as_u64().expect("index") as usize] = val,
    }
}

/// Replaces every key recipe inside `v` by the key it derives.
fn resolve(v: &Value) -> Value {
    match v {
        Value::Array(l) => Value::Array(l.iter().map(resolve).collect()),
        Value::Object(m) => {
            if let Some(label) = m.get("$abeMsk").and_then(Value::as_str) {
                return seeded_msk(label);
            }
            if let Some(spec) = m.get("$abeKey").filter(|s| s.is_object()) {
                return seeded_key(spec);
            }
            if let Some(pool) = m.get("$pool").and_then(Value::as_array) {
                let mut base = resolve(&pool[0]);
                for o in &pool[1..] {
                    let extra = resolve(o)["attrs"].as_object().cloned().unwrap_or_default();
                    let attrs = base["attrs"].as_object_mut().expect("attrs");
                    for (n, c) in extra {
                        attrs.insert(n, c);
                    }
                }
                return base;
            }
            if let Some(patch) = m.get("$patch") {
                let mut base = resolve(patch);
                let edits = m["$edits"].as_array().expect("edits");
                // a $ref reads the base as it was before any edit
                let vals: Vec<Value> = edits
                    .iter()
                    .map(|e| match e["value"].get("$ref").and_then(Value::as_array) {
                        Some(r) => at(&base, r).clone(),
                        None => e["value"].clone(),
                    })
                    .collect();
                for (e, val) in edits.iter().zip(vals) {
                    let del = val.get("$undefined").is_some();
                    set_at(&mut base, e["path"].as_array().expect("path"), val, del);
                }
                return base;
            }
            Value::Object(m.iter().map(|(k, x)| (k.clone(), resolve(x))).collect())
        }
        _ => v.clone(),
    }
}

/// setup, keygen, encrypt and decrypt with the scalars derived from a seed label.
fn fame(a: &[Value]) -> Result<Value, String> {
    let tree = normalize_policy_tree(&a[0])?;
    let attrs = strs(&a[1]);
    let label = a[2]["$seed"].as_str().expect("$seed");
    let n = |x: &str| sc(&format!("{label}{x}"));
    let (aa, bb, dd, rr, ss) = ([n("a1"), n("a2")], [n("b1"), n("b2")], [n("d1"), n("d2"), n("d3")], [n("r1"), n("r2")], [n("s1"), n("s2")]);
    let (mpk, msk) = fame_setup(aa, bb, dd)?;
    let sigmas: Vec<Fr> = (0..attrs.len()).map(|i| n(&format!("sg{i}"))).collect();
    let key = fame_keygen(&msk, &attrs, rr, &sigmas, &n("sgp"))?;
    let (ct, k) = fame_encrypt(&mpk, &tree, ss);
    let dec = fame_decrypt(&key, &tree, &ct);
    let key_attrs: atlas_pca::serde_json::Map<String, Value> = key.attrs.iter().map(|(n, c)| (n.clone(), g1l(c))).collect();
    Ok(json!({
        "h": [b(&mpk.h1.to_bytes()), b(&mpk.h2.to_bytes())],
        "t": [b(&mpk.t1.to_bytes()), b(&mpk.t2.to_bytes())],
        "mskg": g1l(&msk.g),
        "k0": g2l(&key.k0),
        "kp": g1l(&key.kp),
        "key": Value::Object(key_attrs),
        "ct0": g2l(&ct.ct0),
        "rows": Value::Array(ct.rows.iter().map(g1l).collect()),
        "k": b(&k.to_bytes()),
        "dec": dec.map_or(Value::Null, |d| b(&d.to_bytes())),
    }))
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    match f {
        "fame" => fame(a),
        "gtIsElement" => Ok(json!(gt_is_element(&bytes(&a[0])))),
        "gtPow" => gt_pow(&bytes(&a[0]), &fr(&a[1]).to_be_bytes()).map(|x| b(&x)).ok_or_else(|| "gtPow refused".to_string()),
        "gtMul" => gt_mul(&bytes(&a[0]), &bytes(&a[1])).map(|x| b(&x)).ok_or_else(|| "gtMul refused".to_string()),
        "pairingProduct" => {
            let list = |v: &Value| v.as_array().unwrap().iter().map(bytes).collect::<Vec<_>>();
            pairing_product(&list(&a[0]), &list(&a[1])).map(|x| b(&x)).ok_or_else(|| "pairingProduct refused".to_string())
        }
        "normalizePolicy" => Ok(match normalize_policy(&a[0]) {
            Ok(t) => json!({"ok": true, "tree": t}),
            Err(r) => json!({"ok": false, "reason": r}),
        }),
        "satisfies" => Ok(json!(satisfies(&a[0], &strs(&a[1])))),
        "policyAttributes" => Ok(json!(policy_attributes(&a[0]))),
        "parseCiphertext" => Ok(parse_ciphertext(&a[0]).unwrap_or(Value::Null)),
        "decrypt" => Ok(decrypt(&a[0], &a[1]).map_or(Value::Null, |p| b(&p))),
        "decryptText" => Ok(decrypt_text(&a[0], &a[1]).map_or(Value::Null, Value::String)),
        "decryptWithCapability" => Ok(match decrypt_with_capability(&a[0], &a[1]) {
            Ok(p) => json!({"ok": true, "payload": p}),
            Err(r) => json!({"ok": false, "reason": r}),
        }),
        "encryptAccepts" => encrypt_for_policy(&a[0], &a[1], b"x").map(|_| json!(true)),
        "keygenForAttributes" => keygen_for_attributes_named(&a[0], &strs(&a[1])).map(|k| json!(k.1)),
        "keygenForCapability" => keygen_for_capability_named(&a[0], &a[1], &strs(&a[2]), &opts(&a[3]))
            .map(|(k, names)| json!({"holder": k.get("holder").cloned().unwrap_or(Value::Null), "attrs": names})),
        "capabilityAttributes" => Ok(json!(capability_attributes(&a[0], &opts(&a[1])))),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn matches_reference() {
    let mut cases = common::ref_cases("abe-go");
    cases.extend(common::ref_gen_cases("abe-go", false));
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = std::panic::catch_unwind(|| run(f, resolve(&c["args"]).as_array().unwrap())).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn round_trip_and_collusion() {
    let (mpk, msk) = setup().unwrap();
    let policy = json!({"allOf": [{"attr": "a"}, {"attr": "b"}]});
    let ct = encrypt_for_policy(&mpk, &policy, b"hello").unwrap();
    let both = keygen_for_attributes(&msk, &["a".into(), "b".into()]).unwrap();
    let one = keygen_for_attributes(&msk, &["a".into()]).unwrap();
    assert_eq!(decrypt(&both, &ct).as_deref(), Some(&b"hello"[..]));
    assert!(decrypt(&one, &ct).is_none());
    assert!(encrypt_for_policy(&mpk, &json!({"anyOf": [{"attr": "a"}, {"attr": "a"}]}), b"x").is_err());
}

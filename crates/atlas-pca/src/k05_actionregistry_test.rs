//! k05 differential oracle for the action-kit registry layer: tests/data/k05-actionregistry.json.gz, written by the TypeScript
//! reference (tools/pca-audit/k05-oracles/actionregistry-oracle.mts; every native replays the same file): evolution records,
//! registry signatures, re-approvals, the grant pin, signed packs + shards, the rollback tracker, rule 22 and pack proofs.
//! A case with `textPrefix` carries an engine-specific message tail: the decision must match and the message must start with it.
use super::*;
use crate::k042_support::{k05_cases, k05_run, k05_same, K05};
use std::sync::OnceLock;

/// `v` with every string that starts with `p` cut down to `p`.
fn cut(v: &Value, p: &str) -> Value {
    match v {
        Value::String(x) if !p.is_empty() && x.starts_with(p) => Value::String(p.into()),
        Value::Array(a) => Value::Array(a.iter().map(|x| cut(x, p)).collect()),
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), cut(x, p))).collect()),
        _ => v.clone(),
    }
}

/// A value (or a refusal message) against the case's `out`, honouring `textPrefix`.
fn cmp(c: &Value, got: Result<Value, String>) -> K05 {
    let (p, want) = (c["textPrefix"].as_str().unwrap_or(""), &c["out"]);
    match (&got, want.get("$throws")) {
        (Ok(v), _) if p.is_empty() => return K05::Val(v.clone()), // the harness compares and shows it
        (Err(m), None) => return K05::Val(json!({ "refused": m })),
        _ => {}
    }
    K05::Match(match (got, want.get("$throws")) {
        (Ok(v), None) => k05_same(&cut(want, p), &cut(&v, p)),
        (Err(m), Some(Value::String(w))) => cut(&json!(w), p) == cut(&json!(m), p),
        (Err(_), Some(_)) => true,
        _ => false,
    })
}

fn opt(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

/// The registry keys the reference's PackTracker is built with (ALLKEYS: Ed25519, ML-DSA-65, hybrid).
fn all_keys() -> &'static Value {
    static K: OnceLock<Value> = OnceLock::new();
    K.get_or_init(|| {
        let c = k05_cases("actionregistry").into_iter().find(|c| c["name"] == "verifyEvolutionRecord/seed narrow").expect("ALLKEYS seed case");
        c["args"][1].clone()
    })
}

fn verbs(defs: &[Value]) -> Value {
    Value::Array(defs.iter().map(|d| d["verb"].clone()).collect())
}

#[test]
fn k05_actionregistry_matches_the_reference() {
    k05_run("actionregistry", 19000, |c, f, a| match f {
        "compareVersions" => match (a[0].as_str(), a[1].as_str()) {
            (Some(x), Some(y)) => cmp(c, compare_versions(x, y).map(|n| json!(n.signum()))),
            _ => K05::Skip("non-string version (typed port)"),
        },
        "packDefs" => cmp(c, pack_defs(&a[0], opt(a.get(1))).map(|d| verbs(&d))),
        "evolutionRecordError" => cmp(c, Ok(json!(evolution_record_error(&a[0], a[1].as_bool().unwrap_or(true))))),
        "evolutionDiffDigest" => cmp(c, evolution_diff_digest(&a[0]).map(Value::String).ok_or_else(|| "out of profile".to_string())),
        "verifyRegistrySig" => match (a[0].as_str(), a[2].as_object()) {
            (Some(d), Some(sig)) => cmp(c, Ok(json!(verify_registry_sig(d, &a[1], sig, &a[3]).err()))),
            _ => K05::Skip("non-string domain / non-object sig (typed port)"),
        },
        "verifyEvolutionRecord" => cmp(c, Ok(json!(verify_evolution_record(&a[0], &a[1]).err()))),
        "reapprovalValid" => match (a[1].as_str(), a[2].as_str(), a[3].as_str(), a[4].as_str()) {
            (Some(g), Some(i), Some(v), Some(d)) => cmp(c, Ok(json!(reapproval_valid(&a[0], g, i, v, d)))),
            _ => K05::Skip("non-string grant id / issuer / verb / diff (typed port)"),
        },
        "actionPinError" => cmp(c, Ok(json!(action_pin_error(&a[0])))),
        "decidePin" => cmp(c, Ok(decide_pin(&a[0]))),
        "packShapeError" => match a[1].as_bool() {
            Some(true) => cmp(c, Ok(json!(pack_shape_error(&a[0])))),
            _ => K05::Skip("unsigned-mode pack shape: the Rust port only verifies signed packs"),
        },
        "verifyPack" => cmp(
            c,
            Ok(match verify_pack(&a[0], &a[1], opt(a.get(2))) {
                Ok((d, defs)) => json!({"ok": true, "digest": d, "verbs": verbs(&defs)}),
                Err(r) => json!({"ok": false, "reason": r}),
            }),
        ),
        "packTracker" => {
            // ok/status/code; the reason only for bad_pack (the reference's other reasons are its own wording)
            let mut t = PackTracker::new(all_keys().clone());
            let mut got = Vec::new();
            for st in a[0].as_array().into_iter().flatten() {
                let (p, sh) = (&st[0], opt(st.get(1)));
                got.push(match t.accept(p, sh) {
                    Ok(s) => json!({"ok": true, "status": s}),
                    Err("bad_pack") => json!({"ok": false, "code": "bad_pack", "reason": verify_pack(p, all_keys(), sh).err()}),
                    Err(code) => json!({"ok": false, "code": code}),
                });
            }
            let mut want = c["out"].clone();
            for w in want.as_array_mut().into_iter().flatten() {
                if w["code"].is_string() && w["code"] != "bad_pack" {
                    w.as_object_mut().unwrap().remove("reason");
                }
            }
            K05::Match(k05_same(&want, &Value::Array(got)))
        }
        "rule22Decide" => match a[1].as_str() {
            Some(v) => cmp(c, Ok(json!(rule22_decide(&a[0], v, &a[2], &a[3])))),
            None => K05::Skip("non-string verb (typed port)"),
        },
        "verifyPackProof" => match (a[0].as_str(), a[2].as_str()) {
            (Some(root), Some(d)) => cmp(c, Ok(json!(crate::actions::pack_verify(root, &a[1], d)))),
            _ => K05::Skip("non-string root / digest (typed port)"),
        },
        _ => K05::Skip("fn not mapped"),
    });
}

/// A reapproval signed by `k` over exactly `body` (whatever it says), so only the field rules can refuse it.
fn signed_reapproval(k: &crate::agent::KeyPair, body: Value) -> Value {
    use base64::Engine;
    let sig = k.sign(&message(REAPPROVAL_DOMAIN, &body).unwrap());
    let mut o = body.as_object().unwrap().clone();
    o.insert("sig".into(), json!({"alg": "ed25519", "value": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)}));
    Value::Object(o)
}

#[test]
fn reapproval_fields_are_checked_under_a_valid_signature() {
    let k = crate::agent::KeyPair::from_seed(&[5u8; 32]);
    let body = json!({"v": 1, "kind": REAPPROVAL_KIND, "grant": "g1", "verb": "acme.pay", "diff": "D"});
    let ok = |b: Value| reapproval_valid(&signed_reapproval(&k, b), "g1", &k.public, "acme.pay", "D");
    assert!(ok(body.clone()), "the baseline reapproval verifies");
    let with = |key: &str, v: Value| {
        let mut b = body.clone();
        b[key] = v;
        b
    };
    for (key, v) in [("v", json!(2)), ("kind", json!("pca-other")), ("grant", json!("g2")), ("verb", json!("acme.refund")), ("diff", json!("E")), ("extra", json!(1))] {
        assert!(!ok(with(key, v.clone())), "{key} = {v} must refuse");
    }
    // the right body under another issuer's key
    assert!(!reapproval_valid(&signed_reapproval(&crate::agent::KeyPair::from_seed(&[6u8; 32]), body.clone()), "g1", &k.public, "acme.pay", "D"));
}

#[test]
fn pack_size_bounds() {
    assert!(!pack_size_ok(0));
    assert!(pack_size_ok(1) && pack_size_ok(MAX_PACK_DEFS));
    assert!(!pack_size_ok(MAX_PACK_DEFS + 1));
}

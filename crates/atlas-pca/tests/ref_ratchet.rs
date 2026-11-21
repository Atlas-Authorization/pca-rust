//! Differential replay of the capability ratchet (GGM puncturable tree, leaf signatures, spent-leaf store, counter and risk
//! adapters, Pedersen risk accumulator with range and budget proofs, attested budgets) against the TypeScript reference
//! (test-data/ref-ratchet.json.gz), plus independent ristretto255 known answers (test-data/ref-ratchet-kat.json.gz).
//! Deterministic functions compare exactly. The provers draw fresh randomness, so recorded proofs (valid, out of range, over
//! budget, tampered) must reach the reference verdict and prover refusals must refuse (with the reference's code when it has one).
//! A reference throw only requires a refusal; the `ratchet` scenario compares the recorded `{"$err": code|true}`. Cases with a lone
//! surrogate are skipped (capped below 10%).
mod common;
use atlas_pca::ratchet::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use rsa::BigUint;

fn b64d(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap_or_default()
}

/// `{"$bytes": b64url}` as bytes; anything else is an empty byte string (a non-bytes seed is refused by length).
fn bytes_of(v: Option<&Value>) -> Vec<u8> {
    v.and_then(|v| v.get("$bytes")).and_then(Value::as_str).map(b64d).unwrap_or_default()
}

struct ThrowingStore;
impl SpentLeafStore for ThrowingStore {
    fn claim(&self, _: &str, _: &str) -> Result<(bool, Option<String>), String> {
        Err("boom".into())
    }
}

/// The corpus clonePath: a deep copy with `path` set to `value` ("__DEL__" deletes); an empty path names the member "undefined".
fn set_path(v: &Value, path: &[Value], value: &Value) -> Value {
    let mut c = v.clone();
    let key = |k: &Value| match k {
        Value::String(s) => s.clone(),
        o => o.to_string(),
    };
    let last = path.last().cloned().unwrap_or_else(|| json!("undefined"));
    let mut t = Some(&mut c);
    for k in path.iter().take(path.len().saturating_sub(1)) {
        t = match t {
            Some(Value::Object(m)) => m.get_mut(&key(k)),
            Some(Value::Array(a)) => k.as_u64().and_then(|i| a.get_mut(i as usize)),
            _ => None,
        };
    }
    let del = value == "__DEL__";
    match t {
        Some(Value::Object(m)) => {
            if del {
                m.remove(&key(&last));
            } else {
                m.insert(key(&last), value.clone());
            }
        }
        Some(Value::Array(a)) => {
            if let (Some(i), false) = (last.as_u64(), del) {
                if let Some(slot) = a.get_mut(i as usize) {
                    *slot = value.clone();
                }
            }
        }
        _ => {}
    }
    c
}

fn err_out(e: &RatchetError) -> Value {
    match e.code {
        Some(c) => json!({ "$err": c }),
        None => json!({ "$err": true }),
    }
}

fn scenario(spec: &Value) -> Value {
    let mut state: Option<RatchetState> = None;
    let mut root = String::new();
    let mut sigs: Vec<Value> = Vec::new();
    let mem = MemorySpentLeafStore::default();
    let throwing = ThrowingStore;
    let store: &dyn SpentLeafStore = if spec["store"] == "throws" { &throwing } else { &mem };
    let mut out = Vec::new();
    for s in spec["ops"].as_array().unwrap() {
        let msg = bytes_of(s.get("msg"));
        let leaf = s.get("leaf").unwrap_or(&Value::Null);
        let res: Result<Value, RatchetError> = (|| match s["op"].as_str().unwrap_or("") {
            "derive" => {
                let d = derive_ratchet_root(&bytes_of(s.get("seed")), s.get("depth").unwrap_or(&Value::Null))?;
                root = d.root_commitment.clone();
                let r = json!({ "root": d.root_commitment, "leafPubKeys": d.leaf_pub_keys, "available": available_leaves(&d) });
                state = Some(d);
                Ok(r)
            }
            "sign" => {
                let st = state.as_ref().ok_or("signAtLeaf needs a ratchet state")?;
                let (sig, next) = sign_at_leaf(st, leaf, &msg)?;
                state = Some(next);
                sigs.push(sig.clone());
                Ok(json!({ "signature": sig }))
            }
            "avail" => Ok(json!(available_leaves(state.as_ref().ok_or("no state")?))),
            "isAvail" => Ok(json!(is_leaf_available(state.as_ref().ok_or("no state")?, leaf))),
            op @ ("verify" | "once") => {
                let mut sig = s["sigRef"].as_u64().and_then(|i| sigs.get(i as usize)).cloned();
                for p in s.get("set").and_then(Value::as_array).into_iter().flatten() {
                    let base = sig.as_ref().ok_or("JSON.parse: unexpected end")?;
                    let path = p[0].as_array().cloned().unwrap_or_default();
                    sig = Some(set_path(base, &path, &p[1]));
                }
                let sig = sig.unwrap_or(Value::Null);
                let rc = if s["root"] == "other" { "other-root" } else { root.as_str() };
                if op == "verify" {
                    Ok(json!(verify_leaf_signature(rc, leaf, &msg, &sig)))
                } else {
                    Ok(verify_leaf_signature_once(rc, leaf, &msg, &sig, Some(store)))
                }
            }
            _ => Err("bad op".into()),
        })();
        out.push(res.unwrap_or_else(|e| err_out(&e)));
    }
    Value::Array(out)
}

fn run(f: &str, a: &[Value]) -> Result<Value, RatchetError> {
    let arg = |i: usize| a.get(i).unwrap_or(&Value::Null);
    let text = |i: usize| arg(i).as_str().map(str::to_string).ok_or_else(|| RatchetError::from("not a string"));
    match f {
        "leafNullifier" => Ok(json!(leaf_nullifier(&text(0)?, arg(1))?)),
        "counterToLeafIndex" => counter_to_leaf_index(arg(0), arg(1)),
        "leafIndexToCounter" => leaf_index_to_counter(arg(0)),
        "leafIndexForAction" => leaf_index_for_action(arg(0), arg(1)),
        "riskToUnits" => risk_to_units(arg(0)),
        "budgetCeilingUnits" => budget_ceiling_units(arg(0)),
        "quantizer" => {
            let mut q = RiskQuantizer::new();
            let mut out: Vec<Value> = arg(0).as_array().ok_or("not a list")?.iter().map(|r| q.next(r).unwrap_or_else(|_| json!({ "$err": true }))).collect();
            out.push(q.total_units());
            Ok(Value::Array(out))
        }
        "ratchet" => {
            // the generator's adapter reads a seed with Buffer.from: a number is refused there, before the library is called
            if arg(0)["ops"].as_array().is_some_and(|ops| ops.iter().any(|o| o["op"] == "derive" && o.get("seed").is_some_and(Value::is_number))) {
                return Err(RatchetError { code: Some("ERR_INVALID_ARG_TYPE"), message: "The first argument must be of type string or an instance of Buffer".into() });
            }
            Ok(scenario(arg(0)))
        }
        "commitRisk" => commit_risk(arg(0), a.get(1)),
        "addCommitments" => Ok(json!(add_commitments(arg(0))?)),
        "openCommitment" => Ok(json!(open_commitment(arg(0), arg(1), arg(2)))),
        "verifyRiskRange" => Ok(json!(verify_risk_range(arg(0), arg(1)))),
        "verifyBudget" => Ok(json!(verify_budget(arg(0), arg(1), arg(2)))),
        "verifyBoundedBudget" => Ok(json!(verify_bounded_budget(arg(0), arg(1), arg(2), arg(3)))),
        "proveBudget" => prove_budget(arg(0), arg(1), arg(2)),
        "proveRiskRange" => prove_risk_range(arg(0), arg(1)),
        "issueRiskCommitment" => {
            // the recorded cases are refusals: any 32-byte key reaches them; "short" is a 3-byte key
            let key = if arg(2) == "short" { vec![0u8; 3] } else { vec![0u8; 32] };
            issue_risk_commitment(arg(0), &text(1)?, &key)
        }
        "verifyRiskAttestation" => Ok(json!(verify_risk_attestation(arg(0), arg(1), arg(2)))),
        "verifyAttestedBudget" => Ok(json!(verify_attested_budget(arg(0), arg(1), arg(2), arg(3), arg(4)))),
        f => panic!("unknown fn {f}"),
    }
}

#[test]
fn ratchet_vectors() {
    let cases = common::ref_cases_seeded("ratchet");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(e)) => c["out"].get("code").and_then(Value::as_str).map_or(true, |code| e.code == Some(code)),
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

fn kat() -> Value {
    let path = format!("{}/test-data/ref-ratchet-kat.json.gz", env!("CARGO_MANIFEST_DIR"));
    let o = std::process::Command::new("gzip").arg("-dc").arg(&path).output().expect("gzip");
    assert!(o.status.success(), "{path}: gzip failed");
    atlas_pca::serde_json::from_slice(&o.stdout).expect("parse")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

#[test]
fn ristretto_known_answers() {
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
    use curve25519_dalek::scalar::Scalar;
    let k = kat();
    let rs = &k["ristretto"];
    for (i, want) in rs["baseMultiples"].as_array().unwrap().iter().enumerate() {
        assert_eq!(hex((G * Scalar::from(i as u64)).compress().as_bytes()), want.as_str().unwrap(), "{i}*G");
    }
    assert_eq!(hex(&generator_h_bytes()), rs["H"].as_str().unwrap());
    for p in rs["pedersen"].as_array().unwrap() {
        let b = BigUint::from_bytes_le(&unhex(p["b"].as_str().unwrap())).to_str_radix(10);
        let risk = json!({ "$bigint": p["v"] });
        let got = commit_risk(&risk, Some(&json!({ "$bigint": b }))).unwrap();
        assert_eq!(hex(&b64d(got["commitment"].as_str().unwrap())), p["C"].as_str().unwrap());
    }
    for b in rs["budget"].as_array().unwrap() {
        let bmax = json!({ "$bigint": b["bMax"] });
        assert_eq!(verify_budget(&b["sum"], &bmax, &b["proof"]), b["oracle"] == "1", "{}", b["name"]);
    }
}

#[test]
fn recorded_transcript_verifies_and_is_bound_to_its_statement() {
    let k = kat();
    let r2 = &k["r2"];
    let (cs, rps, bp, total) = (&r2["commitments"], &r2["rangeProofs"], &r2["budgetProof"], &r2["sum"]);
    let b_max = r2["bMax"].as_u64().unwrap();
    assert!(verify_risk_range(&cs[0], &rps[0]) && verify_risk_range(&cs[1], &rps[1]));
    assert!(verify_budget(total, &json!(b_max), bp));
    assert!(verify_bounded_budget(cs, rps, &json!(b_max), bp));
    assert!(!verify_risk_range(&cs[1], &rps[0]));
    assert!(!verify_budget(total, &json!(b_max + 1), bp));
    let mut more = rps.as_array().unwrap().clone();
    more.push(rps[0].clone());
    assert!(!verify_bounded_budget(cs, &Value::Array(more), &json!(b_max), bp));
}

#[test]
fn provers_round_trip() {
    let (risks, blinds) = (json!([30, 12]), json!([{ "$bigint": "11" }, { "$bigint": "22" }]));
    let cs: Vec<Value> =
        [(30, "11"), (12, "22")].iter().map(|(r, b)| commit_risk(&json!(r), Some(&json!({ "$bigint": b }))).unwrap()["commitment"].clone()).collect();
    let total = json!(add_commitments(&Value::Array(cs)).unwrap());
    assert!(verify_budget(&total, &json!(42), &prove_budget(&risks, &blinds, &json!(42)).unwrap()));
    assert!(!verify_budget(&total, &json!(41), &prove_budget(&risks, &blinds, &json!(41)).unwrap()));
    let iss = issue_risk_commitment(&json!(9), "only", &[7u8; 32]).unwrap();
    let pubk = atlas_pca::agent::KeyPair::from_seed(&[7u8; 32]).public;
    let items = json!([{ "commitment": iss["commitment"], "rangeProof": iss["rangeProof"], "attestation": iss["attestation"] }]);
    let proof = prove_budget(&json!([9]), &json!([iss["blinding"]]), &json!(9)).unwrap();
    assert!(verify_attested_budget(&items, &json!(["only"]), &json!(pubk), &json!(9), &proof));
    assert!(!verify_attested_budget(&items, &json!(["other"]), &json!(pubk), &json!(9), &proof));
}

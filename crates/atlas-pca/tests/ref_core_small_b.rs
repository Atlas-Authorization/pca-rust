//! Differential replay of the protocol helpers of test-data/ref-core-small-surface.json.gz (written by the TypeScript reference): the detector
//! receipt shape, reference and policy checks and the detector fold, the replay guard over one fresh in-memory store (options, counters,
//! every refusal code), obligation rules, the cheap chain verifier, the holder post-quantum key, the discovery document (parse, build, fetch,
//! suite acceptance) and the revocation-staleness policy. A reference throw requires a refusal; per-function totals are asserted.
mod common;
use std::cell::RefCell;
use std::collections::BTreeMap;

use atlas_pca::dataflow_detectors::*;
use atlas_pca::discovery::*;
use atlas_pca::replay_guard::{guard_pcactn_replay, GuardOptions, InMemoryReplayStore};
use atlas_pca::serde_json::{json, Value};

const FNS: [(&str, usize); 16] = [
    ("detectorReceiptShapeError", 25),
    ("detectorReceiptRef", 25),
    ("detectorPolicyError", 18),
    ("detectorSignal", 24),
    ("guardSeq", 19),
    ("collectObligations", 18),
    ("verifyChainCheap", 23),
    ("holderPqKey", 9),
    ("parseDiscoveryDocument", 32),
    ("parseDiscoveryIntent", 15),
    ("acceptsSuite", 3),
    ("buildDiscoveryDocument", 5),
    ("fetchDiscovery", 6),
    ("catalogReversibilityScore", 1),
    ("catalogRisk", 110),
    ("limits", 1),
];

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

fn strings(v: &Value) -> Option<Vec<String>> {
    v.as_array().map(|a| a.iter().map(|s| text(s).to_string()).collect())
}

/// The fixed document the fetch transport serves.
fn base_doc() -> Value {
    json!({"audience": "https://rs.example", "pca_versions": [2], "signature_suites": ["ed25519", "ml-dsa-65"], "action_header": "PCA-Action"})
}

fn fetch_case(base: &str, mode: &str) -> Value {
    let urls: RefCell<Vec<String>> = RefCell::new(Vec::new());
    let get = |url: &str, accept: &str| -> Result<(u16, Value), String> {
        urls.borrow_mut().push(format!("{url}|{accept}"));
        match mode {
            "throw" => Err("boom".into()),
            "500" => Ok((500, Value::Null)),
            "bad" => Ok((200, json!({"nope": 1}))),
            _ => Ok((200, base_doc())),
        }
    };
    match fetch_discovery(base, &get) {
        Ok(doc) => json!({"doc": doc, "urls": urls.borrow().clone()}),
        Err(_) => json!({"error": true, "urls": urls.borrow().clone()}),
    }
}

fn guard_seq(opts: &Value, steps: &Value) -> Value {
    let store = InMemoryReplayStore::default();
    let out: Vec<Value> = steps
        .as_array()
        .unwrap()
        .iter()
        .map(|st| {
            let o = GuardOptions {
                aud: text(&opts["aud"]),
                now: st["now"].as_f64().unwrap(),
                clock_skew_ms: opts.get("clockSkewMs").and_then(Value::as_f64),
                require_nonce: opts.get("requireNonce").and_then(Value::as_bool),
                counters: if opts.get("counters") == Some(&json!(true)) { Some(&store) } else { None },
            };
            guard_pcactn_replay(&store, &st["p"], &o).to_json()
        })
        .collect();
    Value::Array(out)
}

fn detector_signal_case(i: &Value) -> Value {
    let digests: Vec<String> = strings(&i["input_digests"]).unwrap_or_default();
    let input = DetectorInput {
        receipts: i.get("receipts"),
        policy: &i["policy"],
        input_digests: &digests,
        session: i.get("session").and_then(Value::as_str),
        now: &i["now"],
    };
    let o = detector_signal(&input);
    json!({
        "signal": o.signal, "env": o.env, "flagged": o.flagged,
        "rejected": o.rejected.iter().map(|(i, r)| json!({"index": i, "reason": r})).collect::<Vec<_>>(),
    })
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    Ok(match f {
        "detectorReceiptShapeError" => detector_receipt_shape_error(&a[0]).map_or(Value::Null, Value::String),
        "detectorReceiptRef" => json!(detector_receipt_ref(&a[0])?),
        "detectorPolicyError" => detector_policy_error(&a[0]).map_or(Value::Null, Value::String),
        "detectorSignal" => detector_signal_case(&a[0]),
        "guardSeq" => guard_seq(&a[0], &a[1]),
        "collectObligations" => match atlas_pca::obligations::collect_obligations(Some(&a[0]).filter(|r| !r.is_null()), &a[1]) {
            Ok(v) => json!({"ok": true, "obligations": v}),
            Err(r) => json!({"ok": false, "reason": r}),
        },
        "verifyChainCheap" => {
            let chain = a[0].as_array().map_or(&[][..], |v| v.as_slice());
            let policy = strings(&a[2]);
            match atlas_pca::chain_cheap::verify_chain_cheap(chain, a[1].as_str(), policy.as_deref()) {
                Ok(n) => json!({"ok": true, "pqHops": n}),
                Err(r) => json!({"ok": false, "reason": r}),
            }
        }
        "holderPqKey" => {
            atlas_pca::pq::holder_pq_key(a[0].as_str(), text(&a[1]), a[2].as_str(), a[3].as_str()).map_or(Value::Null, |k| json!(k.key()))
        }
        "parseDiscoveryDocument" => parse_discovery_document(&a[0])?,
        "parseDiscoveryIntent" => parse_discovery_intent(&a[0])?,
        "acceptsSuite" => json!(accepts_suite(&a[0], text(&a[1]))),
        "buildDiscoveryDocument" => {
            let o = &a[0];
            let opts = BuildDiscoveryOptions {
                signature_suites: strings(&o["signatureSuites"]),
                pca_versions: o["pcaVersions"].as_array().map(|v| v.iter().filter_map(Value::as_i64).collect()),
                action_header: o["actionHeader"].as_str().map(String::from),
                required_checks: strings(&o["requiredChecks"]),
                endpoints: o.get("endpoints").cloned(),
                trusted_roots: strings(&o["trustedRoots"]),
                metadata: o.get("metadata").cloned(),
                intent: o.get("intent").cloned(),
                obligations_supported: strings(&o["obligationsSupported"]),
            };
            build_discovery_document(text(&o["audience"]), &opts)?
        }
        "fetchDiscovery" => fetch_case(text(&a[0]), text(&a[1])),
        "catalogReversibilityScore" => {
            let m: atlas_pca::serde_json::Map<String, Value> =
                atlas_pca::consts::CATALOG_REVERSIBILITY_SCORE.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
            Value::Object(m)
        }
        "catalogRisk" => {
            let taint = if a[3].is_null() { None } else { a[3].as_f64() };
            let params = if a[1].is_null() { Value::Null } else { a[1].clone() };
            Value::Object(atlas_pca::catalog_risk::catalog_risk(text(&a[0]), &params, &a[2], taint))
        }
        "limits" => json!({
            "MAX_SLOTS": atlas_pca::MAX_SLOTS, "MAX_SLOT_STRING": atlas_pca::MAX_SLOT_STRING, "MAX_SLOT_SET": atlas_pca::MAX_SLOT_SET,
            "TEMPLATE_KIND": atlas_pca::TEMPLATE_KIND, "TIGHTEN_KIND": atlas_pca::TIGHTEN_KIND,
        }),
        other => panic!("unhandled corpus function {other}"),
    })
}

#[test]
fn core_small_surface_protocol_helpers_replay() {
    let all = common::ref_cases_seeded("core-small-surface");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    let mut bad = Vec::new();
    for c in &all {
        let f = text(&c["fn"]);
        if !FNS.iter().any(|(n, _)| *n == f) {
            continue;
        }
        *per_fn.entry(f.to_string()).or_default() += 1;
        let args = c["args"].as_array().unwrap();
        let got = std::panic::catch_unwind(|| run(f, args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    let want: BTreeMap<String, usize> = FNS.iter().map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}

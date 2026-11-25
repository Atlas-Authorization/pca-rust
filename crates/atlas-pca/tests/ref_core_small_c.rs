//! Differential replay of the policy and approval helpers of test-data/ref-core-small-surface.json.gz (written by the TypeScript reference):
//! the role templates and the fluent policy builder, policy template links (slots digest, link digest, link creation), the undo ledger
//! (the pure transitions with signed receipts, and the store contract over the memory and the key/value stores) and the payment approval
//! profiles (the Secure Payment Confirmation expectation and the CIBA authorization details). Keys come from the corpus's seed labels. A
//! reference throw requires a refusal; per-function totals are asserted.
mod common;
use std::collections::BTreeMap;
use std::sync::Arc;

use atlas_pca::actions_surface::{ciba_approval_details, spc_expectation};
use atlas_pca::agent::KeyPair;
use atlas_pca::kv::MemoryAtomicKv;
use atlas_pca::policy_templates::{from_template, list_templates, FromTemplateOptions, PolicyBuilder};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::undo::{undo_receipt_chain_error, undo_transition, UndoTransition};
use atlas_pca::undo_store::{with_receipt, KvUndoStore, MemoryUndoStore, UndoCreate, UndoQuery, UndoStore};
use atlas_pca::{create_link, link_digest, slots_digest};
use sha2::{Digest, Sha256};

const FNS: [(&str, usize); 10] = [
    ("listTemplates", 1),
    ("fromTemplate", 11),
    ("policyBuilder", 9),
    ("createLink", 16),
    ("slotsDigest", 8),
    ("linkDigest", 2),
    ("undoLifecycle", 8),
    ("undoStore", 6),
    ("spcExpectation", 22),
    ("cibaApprovalDetails", 4),
];

fn text(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// The key of a seed label: SHA-256("atlas-pca-conformance/" + label), as the corpus derives every seed.
fn key(label: &str) -> KeyPair {
    KeyPair::from_seed(&<[u8; 32]>::try_from(Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).as_slice()).unwrap())
}

fn list_json() -> Value {
    Value::Array(
        list_templates()
            .into_iter()
            .map(|t| {
                let mut o = json!({"name": t.name, "description": t.description, "permissions": t.permissions});
                if let Some(l) = t.limits {
                    o["limits"] = l;
                }
                if let Some(r) = t.risk_policy {
                    o["riskPolicy"] = r;
                }
                o
            })
            .collect(),
    )
}

fn from_template_case(name: &str, ov: &Value) -> Value {
    let principal = key("small/tpl/p");
    let mut o = FromTemplateOptions::new(&principal, "g");
    o.holder = Some(key("small/tpl/h"));
    o.now = Some(1_700_000_000_000);
    o.overrides_limits = ov.get("limits");
    o.overrides_permissions = ov.get("permissions");
    o.overrides_risk_policy = ov.get("riskPolicy");
    o.budget_model = ov.get("budgetModel").and_then(Value::as_str);
    match from_template(name, o) {
        Ok(a) => {
            json!({"ok": true, "predicates": a.policy.predicates, "caveats": a.policy.caveats, "riskPolicy": a.policy.risk_policy, "budgetModel": a.policy.budget_model})
        }
        Err(_) => json!({"ok": false}),
    }
}

fn builder_case(ops: &Value) -> Value {
    let mut b = PolicyBuilder::new();
    for op in ops.as_array().unwrap() {
        let op = op.as_array().unwrap();
        match text(&op[0]) {
            "allow" => {
                let acts: Vec<&str> = op[2].as_array().unwrap().iter().map(text).collect();
                b = b.allow(text(&op[1]), &acts);
            }
            "limit" => b = b.limit(text(&op[1]), text(&op[2])),
            "risk" => b = b.risk(&op[1]),
            "from" => match PolicyBuilder::from(text(&op[1])) {
                Ok(f) => b = f,
                Err(_) => return json!({"ok": false}),
            },
            other => panic!("bad op {other}"),
        }
    }
    match b.build() {
        Ok(p) => {
            let mut built = json!({"permissions": p.permissions, "limits": p.limits});
            if let Some(r) = p.risk_policy {
                built["riskPolicy"] = r;
            }
            json!({"ok": true, "built": built})
        }
        Err(_) => json!({"ok": false}),
    }
}

fn undo_lifecycle(rec: &Value, steps: &Value) -> Value {
    let svc = key("small/undo/service");
    let mut cur = with_receipt(rec, "opened", "", rec["opened_at"].as_i64().unwrap(), &svc).unwrap();
    let mut out = vec![cur.clone()];
    for st in steps.as_array().unwrap() {
        let (ev, now) = (&st[0], st[1].as_f64().unwrap());
        match undo_transition(&cur, ev, now) {
            UndoTransition::Applied { record, event, note } => {
                cur = with_receipt(&record, event, &note, now as i64, &svc).unwrap();
                out.push(json!({"applied": ev["kind"], "record": cur}));
            }
            UndoTransition::Replayed => out.push(json!({"replayed": null})),
            UndoTransition::Refused { code, .. } => out.push(json!({"refused": code})),
        }
    }
    out.push(json!({"chain": undo_receipt_chain_error(&cur, &svc.public)}));
    Value::Array(out)
}

fn undo_store(kind: &str, ops: &Value) -> Value {
    let st: Box<dyn UndoStore> =
        if kind == "memory" { Box::new(MemoryUndoStore::new()) } else { Box::new(KvUndoStore::new(Arc::new(MemoryAtomicKv::new()), true)) };
    let err = |e: atlas_pca::undo_store::UndoError| json!({"error": e.code.as_str()});
    let out: Vec<Value> = ops
        .as_array()
        .unwrap()
        .iter()
        .map(|op| {
            let op = op.as_array().unwrap();
            match text(&op[0]) {
                "create" => match st.create(&op[1]) {
                    Ok(UndoCreate::Created) => json!({"created": true}),
                    Ok(UndoCreate::Exists(r)) => json!({"created": false, "record": r}),
                    Err(e) => err(e),
                },
                "get" => st.get(text(&op[1])).map_or_else(err, |r| r.unwrap_or(Value::Null)),
                "replace" => st.replace(text(&op[1]), op[2].as_i64().unwrap(), &op[3]).map_or_else(err, |b| json!(b)),
                _ => {
                    let q = &op[1];
                    let query = UndoQuery {
                        state: text(&q["state"]).to_string(),
                        window_ended_by: q.get("windowEndedBy").and_then(Value::as_i64),
                        grant_ref: q.get("grantRef").and_then(Value::as_str).map(String::from),
                        bond_ref: q.get("bondRef").and_then(Value::as_str).map(String::from),
                        limit: q.get("limit").and_then(Value::as_u64).map(|l| l as usize),
                    };
                    st.list(&query).map_or_else(err, Value::Array)
                }
            }
        })
        .collect();
    Value::Array(out)
}

fn wrap(r: Result<Value, String>) -> Value {
    match r {
        Ok(v) => json!({"ok": true, "v": v}),
        Err(_) => json!({"ok": false}),
    }
}

fn run(f: &str, a: &[Value]) -> Result<Value, String> {
    Ok(match f {
        "listTemplates" => list_json(),
        "fromTemplate" => from_template_case(text(&a[0]), &a[1]),
        "policyBuilder" => builder_case(&a[0]),
        "createLink" => match create_link(&a[0], &a[1], a[2] == json!(true)) {
            Ok(r) => json!({"ok": true, "ref": r}),
            Err(_) => json!({"ok": false}),
        },
        "slotsDigest" => slots_digest(&a[0]).map_or(Value::Null, Value::String),
        "linkDigest" => link_digest(&a[0]).map_or(Value::Null, Value::String),
        "undoLifecycle" => undo_lifecycle(&a[0], &a[1]),
        "undoStore" => undo_store(text(&a[0]), &a[1]),
        "spcExpectation" => wrap(spc_expectation(&a[0], "https://shop.example", text(&a[1]) == "origin")),
        "cibaApprovalDetails" => wrap(ciba_approval_details(&a[0])),
        other => panic!("unhandled corpus function {other}"),
    })
}

#[test]
fn core_small_surface_policy_and_approval_replay() {
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

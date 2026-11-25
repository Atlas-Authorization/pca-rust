//! The policy-as-code test runner: boundary-test generation, running a test document, and signed test documents.

use super::coverage::{permit_id, witness_of};
use super::enumerate::*;
use super::exposure::thresholds_of;
use super::js::*;
use super::query::{always_denies, probes_for};
use super::residual::policy_digest_of;
use crate::agent::KeyPair;
use serde_json::{Map, Value};
use std::collections::HashSet;

const POLICY_TESTS_KIND: &str = "pca-policy-tests";
const POLICY_TESTS_SIG_DOMAIN: &str = "atlas-pca/policy-tests/v1\u{0}";

pub(crate) fn policy_tests_doc(policy: &Value, cases: &Value) -> Value {
    u(vec![("v", num(1.0)), ("kind", s(POLICY_TESTS_KIND)), ("policy_digest", s(&policy_digest_of(&to_model(policy)))), ("cases", cases.clone())])
}

/// Runs a test document against a policy: `{total, passed, failures, digestMatch, ok}`. With `requireDigest` a changed policy fails even
/// if every case still passes.
pub(crate) fn run_policy_tests(policy: &Value, doc: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let opts = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let model = to_model(policy);
    let mut failures: Vec<Value> = vec![];
    let cases = req_list(get(doc, "cases"));
    for c in cases {
        let w = witness_of(&model, get(c, "action"));
        let decided_by = get(get(&w, "winner"), "id");
        let exp_by = get(c, "decidedBy");
        if !strict_eq(get(&w, "decision"), get(c, "expect")) || (!is_undef(exp_by) && !strict_eq(exp_by, decided_by)) {
            let mut f = u_map(vec![
                ("name", get(c, "name").clone()),
                ("expected", get(c, "expect").clone()),
                ("got", get(&w, "decision").clone()),
                ("decidedBy", decided_by.clone()),
            ]);
            if !is_undef(exp_by) {
                f.insert("expectedDecidedBy".into(), exp_by.clone());
            }
            failures.push(Value::Object(f));
        }
    }
    let digest_match = strict_eq(get(doc, "policy_digest"), &s(&policy_digest_of(&model)));
    u(vec![
        ("total", num(cases.len() as f64)),
        ("passed", num((cases.len() - failures.len()) as f64)),
        ("ok", Value::Bool(failures.is_empty() && (get(opts, "requireDigest").as_bool() != Some(true) || digest_match))),
        ("failures", Value::Array(failures)),
        ("digestMatch", Value::Bool(digest_match)),
    ])
}

fn tests_message(doc: &Value) -> Vec<u8> {
    let h = match crate::hash_canonical_strict(doc) {
        Some(h) => h,
        None => fail("document hash: not canonicalisable"),
    };
    let mut m = POLICY_TESTS_SIG_DOMAIN.as_bytes().to_vec();
    m.extend(crate::sha(h.as_bytes()));
    m
}

/// The principal signs the confirmed examples.
pub(crate) fn sign_policy_tests(doc: &Value, kp: &KeyPair) -> Value {
    u(vec![("doc", doc.clone()), ("signer", s(&kp.public)), ("sig", s(&crate::b64_encode(&kp.sign(&tests_message(doc)))))])
}

pub(crate) fn verify_policy_tests(sv: &Value, expected: &Value) -> bool {
    try_js(|| {
        if !strict_eq(get(sv, "signer"), expected) {
            return false;
        }
        let d = get(sv, "doc");
        if is_undef(d) || d.is_null() || get(d, "kind").as_str() != Some(POLICY_TESTS_KIND) {
            return false;
        }
        let sig = match get(sv, "sig").as_str() {
            Some(t) => t,
            None => return false,
        };
        let signer = get(sv, "signer").as_str().unwrap_or("");
        let pk = crate::decode_b64u_strict(signer, Some(32)).and_then(|b| <[u8; 32]>::try_from(b).ok());
        let msg = tests_message(d);
        let sg = crate::decode_b64u_strict(sig, Some(64)).and_then(|b| <[u8; 64]>::try_from(b).ok());
        match (pk, sg) {
            (Some(pk), Some(sg)) => crate::verify_ed25519_strict(&pk, &msg, &sg),
            _ => false,
        }
    })
    .unwrap_or(false)
}

fn param_paths(p: &Value) -> Vec<String> {
    let mut set = OrdSet::default();
    fn walk(c: &Value, set: &mut OrdSet) {
        let m = match obj(c) {
            Some(m) => m,
            None => return,
        };
        if let Some(f) = m.get("field").and_then(Value::as_str) {
            if f.starts_with("action.params.") {
                set.add(f);
            }
        }
        for k in ["all_of", "any_of"] {
            if let Some(l) = m.get(k).and_then(Value::as_array) {
                for x in l {
                    walk(x, set);
                }
            }
        }
        if let Some(n) = m.get("not") {
            if truthy(n) {
                walk(n, set);
            }
        }
    }
    if let Some(w) = get(p, "where").as_array() {
        for c in w {
            walk(c, &mut set);
        }
    }
    set.keys
}

/// Boundary examples for every clause and numeric threshold. Expectations are the policy's CURRENT behaviour, to be confirmed.
pub(crate) fn generate_boundary_tests(policy: &Value, opts_in: &Value) -> Value {
    let empty = empty_obj();
    let o = if opts_in.is_null() || is_undef(opts_in) { &empty } else { opts_in };
    let one = num(1.0);
    let eps = to_number(nn(get(o, "epsilon"), &one));
    let model = to_model(policy);
    let mut cases: Vec<Value> = vec![];
    let mut seen: HashSet<String> = HashSet::new();
    let mut add = |name: String, action: Value, cases: &mut Vec<Value>| {
        let key = json_str(&action);
        if !seen.insert(key) {
            return;
        }
        let w = witness_of(&model, &action);
        let mut c = u_map(vec![("name", s(&name)), ("action", action), ("expect", get(&w, "decision").clone())]);
        let id = get(get(&w, "winner"), "id");
        if !id.is_null() {
            c.insert("decidedBy".into(), id.clone());
        }
        cases.push(Value::Object(c));
    };
    for (i, p) in req_list(get(&model, "predicates")).iter().enumerate() {
        let full = u(vec![
            ("predicates", Value::Array(vec![p.clone()])),
            ("caveats", get(&model, "caveats").clone()),
            ("vetoes", get(&model, "vetoes").clone()),
            ("tighten", get(&model, "tighten").clone()),
        ]);
        let r = always_denies(&full, &Value::Null, &Value::Null);
        let mut base: Option<Value> = Some(own(&r, "witness").clone()).filter(is_obj);
        if base.is_none() {
            let r2 =
                always_denies(&u(vec![("predicates", Value::Array(vec![p.clone()])), ("caveats", get(&model, "caveats").clone())]), &Value::Null, &Value::Null);
            base = Some(own(&r2, "witness").clone()).filter(is_obj);
        }
        let base = match base {
            Some(b) => b,
            None => continue,
        };
        add(format!("{}: minimal admitted action", permit_id(i)), base.clone(), &mut cases);
        for path in param_paths(p) {
            let name = path["action.params.".len()..].to_string();
            let sub = to_model(&u(vec![("predicates", Value::Array(vec![p.clone()]))]));
            for t in thresholds_of(&sub, &path) {
                let tf = to_number(&t);
                for (tag, v) in [("below", num(tf - eps)), ("at", t.clone()), ("above", num(tf + eps))] {
                    let mut a = copy_map(&base);
                    let mut np = copy_map(own(&base, "params"));
                    np.insert(name.clone(), v);
                    a.insert("params".into(), Value::Object(np));
                    add(format!("{}: {name} {tag} {}", permit_id(i), num_str(tf)), Value::Object(a), &mut cases);
                }
            }
        }
        let mut other = copy_map(&base);
        other.insert("resource".into(), s(&format!("{}/__other__", js(own(&base, "resource")))));
        add(format!("{}: unmentioned resource", permit_id(i)), Value::Object(other), &mut cases);
    }
    // a trigger per prohibition: an action some permit would allow and this prohibition stops
    let mut permit_only: Map<String, Value> = copy_map(&model);
    permit_only.insert("vetoes".into(), empty_arr());
    permit_only.insert("tighten".into(), empty_arr());
    let permit_only = Value::Object(permit_only);
    let pr = probes_for(std::slice::from_ref(&model), &Value::Null);
    for v in req_list(get(&model, "vetoes")) {
        let (hits, _) = collect(
            &pr,
            &mut |rep: &Rep| decide(&permit_only, rep) != "deny" && veto_applies(v, &context_of_action(&rep_to_action(rep))),
            DEFAULT_MAX_COMBINATIONS,
            1,
        );
        if !hits.is_empty() {
            add(format!("{}: trigger", js(get(v, "id"))), rep_to_action(&hits[0]), &mut cases);
        }
    }
    policy_tests_doc(policy, &Value::Array(cases))
}

/// The decision of every case of a test document under `policy`.
pub(crate) fn decide_all(policy: &Value, doc: &Value) -> Value {
    let model = to_model(policy);
    Value::Array(req_list(get(doc, "cases")).iter().map(|c| s(decide_action(&model, get(c, "action")))).collect())
}

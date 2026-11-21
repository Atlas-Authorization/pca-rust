//! The full verdict of the stateless resource-server verifier against the TypeScript reference: every case of
//! test-data/ref-verify-verdict.json.gz (allow, r, requiredThreshold, every check with its status, the reasons in order, budget, assurance).
//! Hooks are constant data in the corpus: {enforced:false} | {enforced:true, ok, reason?, t?} | {throws} | {raw}; a `replay` hook is not a
//! hook of the verifier and is ignored. Counted deviations (asserted, never skipped silently):
//!  - a verifier error of the reference carries a JavaScript engine message; this crate fails closed in the same shape (`malformed: fail`,
//!    r 1, the worst threshold) with its own message (the prefix `verifier error (fail closed): ` is compared);
//!  - a wire text that does not parse is described by the strict parser in its own words (the prefix `undecodable PCActn: ` is compared);
//!  - allowUnboundPq is never ported: a case the reference admits only through it must be refused here;
//!  - a malformed budget (`hostile/budget ...`): the reference coerces it in JavaScript; the policy VM here fails closed on it.
mod common;
use std::collections::BTreeMap;

use atlas_pca::serde_json::Value;
use atlas_pca::{verify_pcactn_verdict, AttestationGate, VerdictHook, VerdictHooks};

type Hook<'a> = Box<dyn Fn(&Value, &Value, i64) -> Result<Value, String> + 'a>;

fn hook(h: &Value) -> Hook<'_> {
    Box::new(move |_, _, _| {
        if let Some(t) = h.get("throws") {
            Err(t.as_str().unwrap_or("").to_string())
        } else if let Some(r) = h.get("raw") {
            Ok(r.clone())
        } else {
            Ok(h.clone())
        }
    })
}

fn as_dyn<'a>(h: &'a Option<Hook<'a>>) -> Option<VerdictHook<'a>> {
    h.as_deref()
}

fn close(a: f64, b: f64) -> bool {
    a == b || (a - b).abs() <= 1e-12 * a.abs().max(b.abs())
}

fn f(v: &Value) -> f64 {
    v.as_f64().unwrap_or(f64::NAN)
}

/// The differences between this crate's verdict and the reference's.
fn diff(have: &Value, want: &Value) -> Vec<String> {
    let mut bad = Vec::new();
    if have["allow"] != want["allow"] {
        bad.push(format!("allow {} want {}", have["allow"], want["allow"]));
    }
    if !close(f(&have["r"]), f(&want["r"])) {
        bad.push(format!("r {} want {}", have["r"], want["r"]));
    }
    if atlas_pca::canonicalize(&have["requiredThreshold"]) != atlas_pca::canonicalize(&want["requiredThreshold"]) {
        bad.push(format!("requiredThreshold {} want {}", have["requiredThreshold"], want["requiredThreshold"]));
    }
    if have["checks"] != want["checks"] {
        bad.push(format!("checks {} want {}", have["checks"], want["checks"]));
    }
    if have["reasons"] != want["reasons"] {
        bad.push(format!("reasons {} want {}", have["reasons"], want["reasons"]));
    }
    match (have.get("budget"), want.get("budget")) {
        (None, None) => {}
        (Some(h), Some(w)) => {
            for k in w.as_object().map(|m| m.keys().cloned().collect::<Vec<_>>()).unwrap_or_default() {
                if !close(f(&h[&k]), f(&w[&k])) {
                    bad.push(format!("budget.{k} {} want {}", h[&k], w[&k]));
                }
            }
        }
        (h, w) => bad.push(format!("budget {h:?} want {w:?}")),
    }
    if have.get("assurance").map(atlas_pca::canonicalize) != want.get("assurance").map(atlas_pca::canonicalize) {
        bad.push(format!("assurance {:?} want {:?}", have.get("assurance"), want.get("assurance")));
    }
    bad
}

fn starts(v: &Value, prefix: &str) -> bool {
    v.as_str().is_some_and(|s| s.starts_with(prefix))
}

#[test]
fn verify_verdict_replays_the_reference() {
    let cases = common::ref_cases("verify-verdict");
    assert_eq!(cases.len(), 1022, "case total");
    let (mut bad, mut dev, mut skipped) = (Vec::<String>::new(), BTreeMap::<&str, usize>::new(), 0usize);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let name = c["name"].as_str().unwrap_or("");
        let (pcactn, j) = (&c["args"][0], &c["args"][1]);
        let want = &c["out"];
        // the hooks: constant data, built per case
        let hj = |n: &str| j.get("hooks").and_then(|h| h.get(n));
        let (att, thr, rev, zk) = (hj("attestation").map(hook), hj("threshold").map(hook), hj("revocation").map(hook), hj("zk").map(hook));
        let gate_j = j.get("enforce").and_then(|e| e.get("attestation"));
        let gate_v = gate_j.and_then(|g| g.get("verifier")).map(hook);
        let hooks = VerdictHooks {
            attestation: as_dyn(&att),
            threshold: as_dyn(&thr),
            revocation: as_dyn(&rev),
            zk: as_dyn(&zk),
            attestation_gate: gate_j.map(|g| AttestationGate { verifier: as_dyn(&gate_v), required: g.get("required").and_then(Value::as_bool) }),
            taint: None,
            labels: None,
        };
        let mut opts = j.clone();
        if let Some(m) = opts.as_object_mut() {
            m.remove("hooks");
        }
        let have = verify_pcactn_verdict(pcactn, &opts, &hooks);
        let d = diff(&have, want);
        if d.is_empty() {
            continue;
        }
        let w0 = &want["reasons"][0];
        let only_malformed = have["checks"].as_object().is_some_and(|m| m.len() == 1 && m.get("malformed") == Some(&Value::from("fail")));
        if starts(w0, "verifier error (fail closed)") {
            if have["allow"] == false && only_malformed && have["reasons"].as_array().is_some_and(|r| r.len() == 1) && starts(&have["reasons"][0], "verifier error (fail closed)") && f(&have["r"]) == 1.0 {
                *dev.entry("verifier error: engine message").or_default() += 1;
                continue;
            }
        } else if starts(w0, "undecodable PCActn: strict JSON") {
            if have["allow"] == false && starts(&have["reasons"][0], "undecodable PCActn:") && only_malformed {
                *dev.entry("undecodable: parser wording").or_default() += 1;
                continue;
            }
        } else if j.get("allowUnboundPq") == Some(&Value::Bool(true)) {
            if have["allow"] == false {
                *dev.entry("allowUnboundPq refused (never ported)").or_default() += 1;
                continue;
            }
        } else if name.contains("/hostile/budget") && have["allow"] == false {
            *dev.entry("malformed budget: fails closed").or_default() += 1;
            continue;
        }
        bad.push(format!("{name}\n   {}", d.join("\n   ")));
    }
    assert_eq!(skipped, 0, "cases not run (a lone surrogate in the arguments)");
    assert!(bad.is_empty(), "{} of {} cases differ (deviations {dev:?}):\n{}", bad.len(), cases.len(), bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
    eprintln!("ref-verify-verdict: 1022 cases, counted deviations {dev:?}");
}

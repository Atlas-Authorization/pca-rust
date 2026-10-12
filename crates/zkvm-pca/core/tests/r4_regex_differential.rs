//! R4-02: the guest's `re:` matcher must give the SAME verdict as the TypeScript reference (predicates.ts
//! `isSafeRegexSource` + the R3-02 linear-time NFA, JavaScript semantics over UTF-16).
//! Golden file: fixtures/ts_regex_cases.json, produced by `tests/gen_ts_regex_cases.ts` from the TS reference
//! (17 round-4 PoC cases, a hand-written corpus, ~7000 generated pattern x subject pairs).
//! `PCA_REGEX_CASES=<file>` replaces the golden file (used for the 100k run on the cloud box).
use pca_zkvm_core::caveats::{evaluate_caveats, CaveatCtx};
use pca_zkvm_core::predicates::{evaluate_predicates, Ctx};
use pca_zkvm_core::safe_regex;
use serde_json::{json, Value};

fn guest_allows(pattern: &str, resource: &str) -> bool {
    let preds = json!([{ "verb": "*", "resource": format!("re:{pattern}") }]);
    let root = json!({ "action": { "verb": "read", "resource": resource } });
    evaluate_predicates(preds.as_array().unwrap(), &Ctx::new(&root)).allowed
}

/// The verdict of the golden case's document through the guest's own evaluators.
fn guest_verdict(c: &Value) -> bool {
    let resource = c["resource"].as_str().unwrap();
    let root = json!({ "action": { "verb": "read", "resource": resource } });
    if let Some(p) = c.get("predicates") {
        return evaluate_predicates(p.as_array().unwrap(), &Ctx::new(&root)).allowed;
    }
    if let Some(cv) = c.get("caveats") {
        let cx = CaveatCtx {
            now: 1.0e12, blast_radius: None, reversibility_class: None, delegation_depth: None, recent_action_times: None,
            action_root: &root, tool: None, tool_args: None, tool_signature_digest: None,
        };
        return evaluate_caveats(cv.as_array().unwrap(), &cx).ok;
    }
    guest_allows(c["pattern"].as_str().unwrap(), resource)
}

fn load() -> Vec<Value> {
    let text = match std::env::var("PCA_REGEX_CASES") {
        Ok(p) => std::fs::read_to_string(p).expect("PCA_REGEX_CASES readable"),
        Err(_) => include_str!("../../fixtures/ts_regex_cases.json").to_string(),
    };
    serde_json::from_str(&text).unwrap()
}

#[test]
fn guest_agrees_with_the_ts_reference_on_every_golden_case() {
    let cases = load();
    assert!(cases.len() >= 7000 || std::env::var("PCA_REGEX_CASES").is_ok());
    if std::env::var("PCA_REGEX_CASES").is_err() {
        let docs = cases.iter().filter(|c| c["id"].as_str().unwrap().starts_with("doc:") || c["id"].as_str().unwrap().starts_with("cdoc:")).count();
        assert!(docs >= 25, "the R4-05 document-budget cases are part of the golden file ({docs})");
    }
    let mut bad = Vec::new();
    let (mut allow, mut deny) = (0usize, 0usize);
    for c in &cases {
        let want = c["allow"].as_bool().unwrap();
        if want { allow += 1 } else { deny += 1 }
        let got = guest_verdict(c);
        if got != want {
            bad.push(format!("{}: pattern {:?} resource {:?} TS {} guest {}", c["id"], c.get("pattern"), c["resource"], want, got));
        }
    }
    assert!(allow > 500 && deny > 500, "corpus must exercise both verdicts (allow {allow}, deny {deny})");
    assert!(bad.is_empty(), "{} divergences from the TS reference, first 20:\n{}", bad.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn the_17_round4_poc_cases_agree() {
    let cases: Vec<Value> = load().into_iter().filter(|c| c["id"].as_str().unwrap().starts_with("poc:")).collect();
    if std::env::var("PCA_REGEX_CASES").is_ok() {
        return;
    }
    assert_eq!(cases.len(), 17);
    for c in cases {
        assert_eq!(guest_allows(c["pattern"].as_str().unwrap(), c["resource"].as_str().unwrap()), c["allow"].as_bool().unwrap(), "{}", c["id"]);
    }
}

#[test]
fn named_divergences_are_closed() {
    // each of these was ALLOWED by the regex-crate guest and DENIED by the TS reference
    for (p, r) in [
        ("/acct/\\d+", "/acct/١٢٣"), ("/files/.*", "/files/a\rb"), ("/files/.*", "/files/a\u{2028}b"), ("/files/.*", "/files/a\u{2029}b"),
        ("/u/\\w+", "/u/é中"), ("a\\sb", "a\u{85}b"), ("x[^a]y", "x😀y"), ("x.y", "x😀y"), ("\\bfoo\\b", "foo"), ("(?i)ABC", "abc"),
        ("(a+)+b", "aaab"), ("\\p{L}+", "abc"), ("[[:alpha:]]+", "abc"), ("(?s)a.b", "a\nb"),
    ] {
        assert!(!guest_allows(p, r), "{p:?} must not match {r:?}");
    }
    // ... and the one the old guest DENIED while TS ALLOWS: `.` is one UTF-16 code unit
    assert!(guest_allows("x.{2}y", "x😀y"));
    assert!(guest_allows("/acct/[0-9]+", "/acct/123"));
    assert!(!guest_allows("/acct/[0-9]+", "/acct/12x"));
}

#[test]
fn subset_guard_and_budgets_match_the_ts_constants() {
    let u = |s: &str| -> Vec<u16> { s.encode_utf16().collect() };
    assert!(safe_regex::is_safe_regex_source(&u("/acct/[^/]+/items/\\d+")));
    assert!(!safe_regex::is_safe_regex_source(&u("(a+)+b")), "nested quantifier");
    assert!(!safe_regex::is_safe_regex_source(&u("a*b*c*d*")), "4 unbounded quantifiers");
    assert!(!safe_regex::is_safe_regex_source(&u("\\1")), "backreference");
    assert!(!safe_regex::is_safe_regex_source(&u("(?=a)")), "lookahead");
    assert!(!safe_regex::is_safe_regex_source(&u("a{65}")), "repeat bound");
    // the matcher budget: 4096-instruction ceiling and 2M step cap
    let big = safe_regex::compile(&u(&"[^]{64}".repeat(63))).expect("4033 instructions compile");
    assert_eq!(safe_regex::run(&big, &vec![b'a' as u16; 512]), None, "over the 2,000,000-step budget");
    assert_eq!(safe_regex::run(&big, &vec![b'a' as u16; 10]), Some(false));
    assert!(safe_regex::compile(&u(&"[^]{64}".repeat(70))).is_none(), "over 4096 instructions");
    // lengths are UTF-16 code units, like JS `.length`
    assert!(guest_allows(&"😀".repeat(100), &"😀".repeat(100)));
    assert!(!guest_allows(&"😀".repeat(101), &"😀".repeat(101)), "202 code units > 200");
}

#[test]
fn document_regex_budget_mirrors_the_ts_reference() {
    // 64 evaluations per document: 63 misses + the hit is the 64th (allowed), 64 misses + the hit is the 65th (refused)
    let miss = |i: usize| json!({ "verb": "*", "resource": format!("re:/nomatch/{i}/[a-z]+") });
    let hit = json!({ "verb": "*", "resource": "re:/acct/[0-9]+" });
    let root = json!({ "action": { "verb": "read", "resource": "/acct/7" } });
    let run = |n: usize| {
        let mut preds: Vec<Value> = (0..n).map(miss).collect();
        preds.push(hit.clone());
        evaluate_predicates(&preds, &Ctx::new(&root)).allowed
    };
    assert!(run(63));
    assert!(!run(64));
    assert!(!run(100));
    // the budget does not leak between documents: a fresh call starts at zero
    assert!(run(0) && run(63));
}

#[test]
fn deeply_nested_groups_are_refused_not_crashed() {
    let p = format!("{}a{}", "(".repeat(150), ")".repeat(150));
    let _ = guest_allows(&p, "a"); // must return, whichever verdict
    let q = format!("{}a{}", "(".repeat(1000), ")".repeat(1000));
    assert!(!guest_allows(&q, "a"));
}

//! `explain_refusal`: every entry of the table, the fallbacks, and inputs that must not panic.
use atlas_pca::{explain_refusal, refusal_help::PCA_DOCS};

#[test]
fn known_checks_map_to_their_entries() {
    let r = explain_refusal("replay: 1 is not greater than last seen 1");
    assert_eq!(r.check, "replay");
    assert_eq!(r.meaning, "This proof (or an older counter) was already used.");
    assert_eq!(r.fix, "Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.");
    assert_eq!(r.docs, format!("{PCA_DOCS}/reference/refusals.md#replay"));

    let t = explain_refusal("threshold: needs co-sign");
    assert_eq!((t.check.as_str(), t.docs.as_str()), ("threshold", "https://github.com/Atlas-Authorization/pca/blob/main/docs/concepts/threshold-and-step-up.md"));
    // the longer name wins over its prefix
    assert_eq!(explain_refusal("authorize_config: audience is missing").check, "authorize_config");
    assert_eq!(explain_refusal("grant_ref_bound: x").check, "grant_ref_bound");
    assert_eq!(explain_refusal("wire: PCActn could not be decoded").docs, format!("{PCA_DOCS}/reference/wire-formats.md"));
}

#[test]
fn a_check_named_later_in_the_reason_is_found() {
    assert_eq!(explain_refusal("2 checks failed. policy: amount <= 100 not satisfied").check, "policy");
}

#[test]
fn unknown_and_hostile_reasons_get_the_generic_entry_and_never_panic() {
    for s in ["", "no PCA-Action header or body supplied", "\u{0}", "é: ünïcode", "_", "::::", &"a".repeat(100_000), "replay", "workflow: edge_relation (step pay)"] {
        let r = explain_refusal(s);
        assert!(!r.check.is_empty() && !r.meaning.is_empty() && !r.fix.is_empty() && r.docs.starts_with(PCA_DOCS), "{s:?}");
    }
    let u = explain_refusal("no PCA-Action header or body supplied");
    assert_eq!(u.check, "unknown");
    assert_eq!(u.docs, format!("{PCA_DOCS}/reference/refusals.md"));
    // a bare check name (no colon) is still its entry
    assert_eq!(explain_refusal("replay").check, "replay");
}

#[test]
fn provenance_and_undo_rows() {
    let p = explain_refusal("provenance_flow: escalate: the choice of payments.send derives from untrusted content");
    assert_eq!(p.check, "provenance_flow");
    assert_eq!(p.docs, format!("{PCA_DOCS}/guides/prompt-injection-provenance.md"));
    assert!(p.fix.contains("PCA-Provenance"));
    let u = explain_refusal("undo_window: runs now under a veto window until 1 (compensation payments.refund)");
    assert_eq!(u.check, "undo_window");
    assert_eq!(u.docs, format!("{PCA_DOCS}/guides/undo-windows.md"));
    assert!(u.fix.contains("undo coordinator"));
}

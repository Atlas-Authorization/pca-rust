//! O5: the literal SafeRegex guard cases the other ports pin: a quantified group that holds an alternation (however nested) is refused,
//! and the cost budget of 22 bits counts `a*b*a{0,64}` as 8 + 8 + 7 = 23 and `a{0,1}` as one bit each (predicates.ts `isSafeRegexSource`).
use super::*;

fn safe(src: &str) -> bool {
    is_safe_regex_source(&src.encode_utf16().collect::<Vec<u16>>())
}

#[test]
fn a_quantified_group_with_a_nested_alternation_is_refused() {
    assert!(!safe("(a|(b))*"));
    assert!(!safe("((a|b))*"));
    assert!(!safe("(a|b)*"));
}

#[test]
fn the_cost_budget_is_22_bits() {
    assert!(!safe("a*b*a{0,64}"), "8 + 8 + 7 = 23 bits");
    assert!(!safe(&"a{0,1}".repeat(23)), "23 one-bit options");
    assert!(safe(&"a{0,1}".repeat(22)), "22 one-bit options");
}

#[test]
fn the_document_budget_counts_each_refused_evaluation() {
    assert_eq!(regex_refusals(), 0, "outside a scope nothing is refused");
    with_regex_budget(|| {
        assert_eq!(regex_refusals(), 0);
        for _ in 0..MAX_REGEX_EVALUATIONS_PER_DOCUMENT {
            assert_eq!(full_match_tri("a", "a"), Some(true));
        }
        assert_eq!(regex_refusals(), 0);
        assert_eq!(full_match_tri("a", "a"), None);
        assert_eq!(regex_refusals(), 1);
        assert_eq!(full_match_tri("a", "a"), None, "the scope is poisoned");
        assert_eq!(regex_refusals(), 2);
    });
    assert_eq!(regex_refusals(), 0, "the scope closed");
}

/// Deadline: the structural guard advances past an escape (backslash plus its character).
#[test]
fn an_escape_is_scanned_to_its_end() {
    let (a, b) = crate::k042_support::within("structural_guard", || (safe("\\d"), safe("a\\.b\\d+")));
    assert!(a && b);
}

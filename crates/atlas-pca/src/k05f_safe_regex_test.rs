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

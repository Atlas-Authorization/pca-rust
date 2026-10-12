//! cargo-mutants kills for core/src/safe_regex.rs (batch Z2b): char-class normalisation, hex escapes, brace
//! quantifier digit limits, the repeat-bound refusal, atom refusals and the group-depth counter.
//! Expected verdicts follow packages/pca/src/safe-regex.ts (the TS reference the guest ports line by line).
use pca_zkvm_core::safe_regex::{self, compile, full_match, run};

fn u(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// compile + run with no structural guard in front (the parser is what these tests target).
fn m(pat: &str, subj: &str) -> Option<bool> {
    let re = compile(&u(pat))?;
    run(&re, &u(subj))
}

fn compiles(pat: &str) -> bool {
    compile(&u(pat)).is_some()
}

// ---- normalize (line 92) --------------------------------------------------------------------------------------------

#[test]
fn class_with_ranges_contained_in_an_earlier_range_is_merged() {
    // [a-zbc]: sorted by start -> (a,z),(b,b),(c,c). Unmerged, the binary search misses 'y' (TS normalize merges).
    assert!(full_match("[a-zbc]", "y"));
    assert!(full_match("[a-zbc]", "a"));
    assert!(full_match("[a-zbc]", "z"));
    assert!(!full_match("[a-zbc]", "A"));
    assert_eq!(m("[a-zbcdx]", "w"), Some(true));
    assert_eq!(m("[^a-zbc]", "y"), Some(false));
}

#[test]
fn class_starting_at_nul_is_not_merged_with_a_later_range() {
    // (0,0),(z,z): `last.1 + 1` with last.1 == 0 is 1; a `last.1 - 1` would underflow (wrap -> merge everything).
    assert!(!full_match("[\\0z]", "a"));
    assert!(!full_match("[\\0z]", "y"));
    assert!(full_match("[\\0z]", "z"));
    assert!(full_match("[\\0z]", "\u{0}"));
    assert!(full_match("[\\0\\0z]", "\u{0}"));
    assert!(!full_match("[\\x00\\x00z]", "m"));
}

// ---- is_ascii_alnum (line 134) --------------------------------------------------------------------------------------

#[test]
fn identity_escape_of_a_digit_or_uppercase_letter_is_refused() {
    // TS: /^[A-Za-z0-9]$/.test(c) || c === '_' -> refuse.
    for p in ["\\A", "\\Z", "\\M", "\\8", "\\9", "[\\A]", "[\\8]", "\\_", "\\a", "\\z"] {
        assert!(!compiles(p), "{p} must be refused");
    }
    assert!(!full_match("\\A", "A"));
    assert!(!full_match("\\Q", "Q"));
    // punctuation identity escapes are the character itself
    assert_eq!(m("\\@", "@"), Some(true));
    assert_eq!(m("\\.", "."), Some(true));
    assert_eq!(m("\\.", "x"), Some(false));
}

// ---- hexval (line 145) ----------------------------------------------------------------------------------------------

#[test]
fn uppercase_hex_digits_decode_to_10_through_15() {
    // \x4A = 'J' (0x4a), \x4B = 'K', \x4F = 'O'; uppercase and lowercase agree.
    let cases = [("\\x4A", "J"), ("\\x4B", "K"), ("\\x4C", "L"), ("\\x4D", "M"), ("\\x4E", "N"), ("\\x4F", "O")];
    for (p, s) in cases {
        assert_eq!(m(p, s), Some(true), "{p} vs {s}");
        assert_eq!(m(&p.to_lowercase(), s), Some(true), "{p} lowercase");
    }
    assert_eq!(m("\\x4A", "@"), Some(false));
    assert_eq!(m("\\xAA", "\u{aa}"), Some(true));
    assert_eq!(m("\\xFF", "\u{ff}"), Some(true));
    assert_eq!(m("\\xFF", "\u{b}"), Some(false));
    assert_eq!(m("\\u00C9", "\u{c9}"), Some(true));
    assert_eq!(m("\\uABCD", "\u{abcd}"), Some(true));
    assert_eq!(m("\\uFFFE", "\u{fffe}"), Some(true));
    assert_eq!(m("[\\x41-\\x46]", "F"), Some(true));
    assert_eq!(m("[\\x41-\\x46]", "G"), Some(false));
    assert!(full_match("\\x4A", "J"));
}

// ---- parse (line 157) -----------------------------------------------------------------------------------------------

#[test]
fn unbalanced_close_paren_is_refused_by_the_parser() {
    for p in ["a)", ")", "a)b", "(a))", "a|b)"] {
        assert!(!compiles(p), "{p} must be refused (unbalanced ))");
    }
    assert!(compiles("(a)"));
}

// ---- brace_quantifier (lines 191, 203) ------------------------------------------------------------------------------

#[test]
fn unterminated_brace_at_end_of_source_is_refused_without_panicking() {
    // the digit loop reaches the end of the source; it must stop there, not index past it
    for p in ["a{1", "a{12", "a{123", "a{1,", "a{1,2", "a{1,23", "a{1,234"] {
        assert!(!compiles(p), "{p}");
    }
}

#[test]
fn brace_bounds_take_at_most_four_digits() {
    // TS: /^\{(\d{1,4})(?:(,)(\d{0,4}))?\}/ — five digits is not a quantifier -> refuse.
    for p in ["a{00001}", "a{00001,}", "a{00001,2}", "a{1,00002}", "a{0,000001}", "xxxxxxxxa{00001}", "a{0000000001}"] {
        assert!(!compiles(p), "{p} must be refused");
    }
    assert!(!full_match("a{00001}", "a"));
    assert!(!full_match("a{1,00002}", "a"));
    // four digits is fine
    assert_eq!(m("a{0001}", "a"), Some(true));
    assert_eq!(m("a{0001,0002}", "aa"), Some(true));
    assert_eq!(m("a{0001,0002}", "aaa"), Some(false));
    assert_eq!(m("a{0001,}", "aaaa"), Some(true));
}

// ---- quantified repeat bound (line 251) -----------------------------------------------------------------------------

#[test]
fn either_bound_over_64_is_refused() {
    assert!(!compiles("a{0,65}"), "max over the bound, min under it");
    assert!(!compiles("a{65,}"), "min over the bound, unbounded max");
    assert!(!compiles("a{65}"));
    assert!(!full_match("a{65,}", &"a".repeat(65)));
    assert!(compiles("a{0,64}"));
    assert!(compiles("a{64,}"));
}

// ---- atom refusals (line 301) ---------------------------------------------------------------------------------------

#[test]
fn leading_quantifier_chars_are_refused_as_atoms() {
    for p in ["*", "+", "?", "{", "*a", "a**", "a+?+", "a{2}{3}", "(?:*)", "a|*", "{1}"] {
        assert!(!compiles(p), "{p} must be refused (nothing to repeat)");
    }
    assert!(compiles("a+?"));
}

// ---- group depth (lines 273, 277) -----------------------------------------------------------------------------------

#[test]
fn exactly_max_parse_depth_nested_groups_compile_and_one_more_is_refused() {
    let d = safe_regex::MAX_PARSE_DEPTH;
    assert_eq!(d, 256);
    let nest = |n: usize| format!("{}a{}", "(".repeat(n), ")".repeat(n));
    assert_eq!(m(&nest(d), "a"), Some(true), "depth 256 is within the limit (TS has no limit at all)");
    assert_eq!(m(&nest(d - 1), "a"), Some(true));
    assert!(!compiles(&nest(d + 1)), "depth 257 fails closed");
}

#[test]
fn sequential_groups_do_not_accumulate_depth() {
    // leaving a group restores the depth: 600 sibling groups are depth 1 each
    let p = "(a)".repeat(600);
    assert_eq!(m(&p, &"a".repeat(600)), Some(true));
    let q = "(?:b)".repeat(300);
    assert_eq!(m(&q, &"b".repeat(300)), Some(true));
    // nested-then-siblings: a depth-200 group followed by 100 siblings
    let r = format!("{}c{}{}", "(".repeat(200), ")".repeat(200), "(c)".repeat(100));
    assert_eq!(m(&r, &"c".repeat(101)), Some(true));
}

// ======== batch Z3: is_safe_regex_source structural scan, charge (the per-document regex budget) ======================

use pca_zkvm_core::safe_regex::{is_safe_regex_source, with_regex_budget, MAX_REGEX_EVALUATIONS_PER_DOCUMENT};

fn safe(p: &str) -> bool {
    is_safe_regex_source(&u(p))
}

#[test]
fn guard_class_scan_skips_the_whole_class_including_quantifier_chars() {
    // predicates.ts: the class ends at the FIRST unescaped `]`; its contents are one atom (line 631, 640).
    assert!(safe("[(a+)+]"), "quantifier chars inside a class are literals");
    assert!(safe("x[(a+)+]y"));
    assert!(safe("[^(a+)+]"));
    // an escaped `]` does not end the class (line 633)
    assert!(safe("[\\](a+)+]"));
    assert!(full_match("[\\](a+)+]", "]"));
    // unterminated class at the very end of the source: refused, never indexes past it
    for p in ["[", "a[", "[^", "a[\\", "[a"] {
        assert!(!safe(p), "{p}");
    }
}

#[test]
fn guard_unterminated_max_digits_at_end_of_source_is_refused_without_panicking() {
    // line 701: the `{n,` digit loop must stop at the end of the source
    for p in ["a{1,2", "a{1,23", "a{0,"] {
        assert!(!safe(p), "{p}");
    }
}

#[test]
fn guard_lazy_brace_quantifier_is_not_charged_as_a_second_quantifier() {
    // a* (8) + b* (8) + c{0,63} (ceil(log2 64) = 6) = 22 = MAX_REGEX_COST_BITS: allowed; the trailing `?` is the lazy
    // modifier (consumed with the quantifier, no cost). Line 716: the quantifier length must cover `{...}` exactly.
    assert!(safe("a*b*c{0,63}?"));
    assert!(full_match("a*b*c{0,63}?", "abc"));
    assert!(safe("a*b*c{0,63}"));
    assert!(safe("a*b*c{1,64}?"), "64 options = 6 bits");
    assert!(!safe("a*b*c{0,64}?"), "65 options = 7 bits: 23 > 22");
}

#[test]
fn guard_requires_both_a_balanced_stack_and_a_compiling_source() {
    // line 759: `stack.len() == 1 && compile(src).is_some()` — a structurally clean source that does not compile is unsafe
    for p in ["\\A", "a{00001}", "[z-a]", "\\xZZ", "\\c1", "a{2}{3}"] {
        assert!(!safe(p), "{p}");
    }
    assert!(!full_match("\\A", "A"));
    assert!(safe("a{0001}"));
}

#[test]
fn budget_allows_exactly_64_evaluations_per_document() {
    // regex-budget.ts: ev > MAX_REGEX_EVALUATIONS_PER_DOCUMENT refuses, so the 64th is allowed and the 65th refused.
    assert_eq!(MAX_REGEX_EVALUATIONS_PER_DOCUMENT, 64);
    with_regex_budget(|| {
        for k in 1..=64 {
            assert!(full_match("a", "a"), "evaluation {k} is within budget");
        }
        assert!(!full_match("a", "a"), "the 65th is over budget");
    });
}

#[test]
fn budget_steps_are_prog_len_times_subject_plus_one_and_exactly_5m_is_allowed() {
    // `a*` compiles to 4 instructions (split, set, jmp, match); steps = 4 * (n + 1).
    // 4*500000 + 4*500000 + 4*250000 = 5,000,000 = MAX_REGEX_STEPS_PER_DOCUMENT: allowed (refusal is steps > max).
    with_regex_budget(|| {
        assert!(full_match("a*", &"a".repeat(499_999)));
        assert!(full_match("a*", &"a".repeat(499_999)));
        assert!(full_match("a*", &"a".repeat(249_999)), "reaching exactly 5,000,000 steps is allowed");
        // one more evaluation of even the empty subject costs 4 * (0 + 1) = 4 > 0 remaining
        assert!(!full_match("a*", ""), "the (n + 1) term is charged");
    });
    // without the +1 the same three would cost 4,999,988 and leave room: check the +1 at a second boundary
    with_regex_budget(|| {
        assert!(full_match("a*", &"a".repeat(499_999)));
        assert!(full_match("a*", &"a".repeat(499_999)));
        assert!(!full_match("a*", &"a".repeat(250_000)), "4 * 250001 overflows the budget by 4");
        assert!(!full_match("a", "a"), "the scope is poisoned after a refusal");
    });
}


#[test]
fn budget_allows_exactly_8192_source_chars_per_document() {
    // line 822 (chars > MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT): "(?:)" x 512 is 2048 code units and compiles to a lone
    // Match, so four evaluations are exactly 8192 chars (allowed, the refusal is chars > max) and a fifth is refused.
    assert_eq!(safe_regex::MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT, 8192);
    let p = "(?:)".repeat(512);
    assert_eq!(p.len(), 2048);
    with_regex_budget(|| {
        for k in 1..=4 {
            assert!(full_match(&p, ""), "evaluation {k}: {} chars", 2048 * k);
        }
        assert!(!full_match("a", "a"), "8193 chars is over budget");
    });
}

#[test]
fn run_step_cap_counts_subject_length_plus_one() {
    // line 527: prog.len() * (n + 1) > MAX_MATCH_STEPS -> None. `a*` is 4 instructions:
    // 4 * (499_999 + 1) = 2,000,000 runs, 4 * (500_000 + 1) = 2,000,004 does not.
    let re = compile(&u("a*")).unwrap();
    assert_eq!(run(&re, &vec![b'a' as u16; 499_999]), Some(true));
    assert_eq!(run(&re, &vec![b'a' as u16; 500_000]), None);
}

// ======== batch Z4: class range order, emit depth/size limits, compile size limit =====================================

#[test]
fn class_range_with_equal_endpoints_is_valid_and_reversed_is_refused() {
    // line 414 (TS cls: x > y refuses): [a-a] is the single char a
    assert_eq!(m("[a-a]", "a"), Some(true));
    assert_eq!(m("[a-a]", "b"), Some(false));
    assert_eq!(m("[\\x41-\\x41]", "A"), Some(true));
    assert!(full_match("x[0-0]", "x0"));
    assert!(!compiles("[b-a]"));
    assert!(!compiles("[z-a]"));
}

/// `(` + 255 nested alternation groups + `)`: emit depth = 2 * 255 + 2 at the innermost leaf; `leaf` is the innermost
/// atom. `first` puts the nesting chain through the FIRST alternative (line 456), else through the last (line 462).
fn deep(leaf: &str, first: bool) -> String {
    if first {
        format!("({}{}|a{})", "(".repeat(255), leaf, "|a)".repeat(255))
    } else {
        format!("({}{}{})", "(a|".repeat(255), leaf, ")".repeat(255))
    }
}

#[test]
fn emit_depth_limit_is_exactly_twice_max_parse_depth() {
    // line 438: depth > MAX_PARSE_DEPTH * 2 (512) refuses. The innermost leaf of deep("a") sits at depth 512 (allowed);
    // a quantified leaf adds one Rep level, putting its body at 513 (refused, fail closed). Parse depth is 256 (allowed).
    for first in [false, true] {
        assert!(compiles(&deep("a", first)), "depth 512 compiles (first={first})");
        assert_eq!(m(&deep("a", first), "a"), Some(true));
        // body at 513 through each Rep emission path: min copies (472), unbounded (478), optional copies (489)
        for leaf in ["a{1}", "a*", "a?", "a{0,2}", "a+"] {
            assert!(!compiles(&deep(leaf, first)), "{leaf} at depth 513 is refused (first={first})");
        }
    }
    // a bare quantified leaf one level up is fine
    let shallow = format!("{}a?{}", "(a|".repeat(255), ")".repeat(255));
    assert!(compiles(&shallow));
}

#[test]
fn compile_allows_exactly_4096_instructions_including_match() {
    // line 517: prog.len() > MAX_NFA_INSTRUCTIONS refuses. 63 x [^]{64} + [^]{63} = 4095 sets, + Match = 4096.
    let p = format!("{}[^]{{63}}", "[^]{64}".repeat(63));
    let re = compile(&u(&p)).expect("exactly 4096 instructions compile");
    assert_eq!(run(&re, &[b'a' as u16; 10]), Some(false));
    assert_eq!(run(&re, &[b'a' as u16; 400]), Some(false), "within the step cap (4096 * 401), too short to match");
    let p2 = format!("{}[^]{{63}}a", "[^]{64}".repeat(63));
    assert!(compile(&u(&p2)).is_none(), "4097 instructions are refused");
}

#[test]
fn negated_class_caret_is_consumed_not_a_member() {
    // line 381: after `[^` the `^` is the negation marker, not a class member; `[` is never a member either
    assert_eq!(m("[^a]", "^"), Some(true));
    assert_eq!(m("[^a]", "["), Some(true));
    assert_eq!(m("[^a]", "a"), Some(false));
    assert_eq!(m("[^^]", "^"), Some(false), "a second ^ is a member");
}

/// `\uXXXX` takes exactly four HEX digits: any non-hex character in the four positions refuses the pattern
/// (the TS reference compiles with the `u` flag, where an incomplete `\u` escape is a SyntaxError). Pins the
/// `is_hex(h)` guard in escape_inner (a `g` would otherwise decode as digit value 16).
#[test]
fn unicode_escape_requires_four_hex_digits() {
    for bad in ["\\u00g0", "\\u00G0", "\\uZZZZ", "\\u12 4", "\\u123"] {
        assert!(!compiles(bad), "{bad:?} must be refused");
    }
    assert_eq!(m("\\u0041", "A"), Some(true));
    assert_eq!(m("\\u00e9", "\u{e9}"), Some(true));
}

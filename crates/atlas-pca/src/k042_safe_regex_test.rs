//! Differential kill test for the 0.4.2 safe_regex.rs mutation survivors: every pattern of a TS-generated corpus
//! (tools/pca-audit/java-mutate/k042-saferegex-oracle.mjs over packages/pca/src/safe-regex.ts + predicates.ts) must
//! compile to the EXACT same NFA program (op, x, y, set ranges, negation, instruction for instruction) or be refused
//! alike, get the same is_safe_regex_source verdict, and full-match every recorded subject with the same true / false / None.
use super::*;
use sha2::{Digest, Sha256};

fn dump(c: &Compiled) -> String {
    let mut parts = Vec::new();
    for ins in &c.prog {
        parts.push(match ins {
            Inst::Set(cs) => {
                let r = if cs.ranges.is_empty() { "E".to_string() } else { cs.ranges.iter().map(|(a, b)| format!("{a}-{b}")).collect::<Vec<_>>().join(":") };
                format!("0,0,0,{},{}", if cs.negated { 1 } else { 0 }, r)
            }
            Inst::Split(x, y) => format!("1,{x},{y},-,-"),
            Inst::Jmp(x) => format!("2,{x},0,-,-"),
            Inst::Bol => "3,0,0,-,-".into(),
            Inst::Eol => "4,0,0,-,-".into(),
            Inst::Match => "5,0,0,-,-".into(),
        });
    }
    let s = parts.join(";");
    if s.len() > 1000 {
        let d = Sha256::digest(s.as_bytes());
        return format!("H{}", d.iter().map(|b| format!("{b:02x}")).collect::<String>());
    }
    s
}

fn unhex(h: &str) -> Vec<u16> {
    if h == "-" {
        return Vec::new();
    }
    (0..h.len()).step_by(4).map(|k| u16::from_str_radix(&h[k..k + 4], 16).unwrap()).collect()
}

fn show(s: &[u16]) -> String {
    let t: String = s.iter().map(|&c| if (0x20..0x7f).contains(&c) { (c as u8 as char).to_string() } else { format!("\\u{c:04x}") }).collect();
    if t.len() > 80 { format!("{}...({})", &t[..80], s.len()) } else { t }
}

#[test]
fn corpus_matches_the_ts_reference() {
    let o = std::process::Command::new("gzip")
        .arg("-dc")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/k042-saferegex.txt.gz"))
        .output()
        .expect("gzip");
    assert!(o.status.success());
    let text = String::from_utf8(o.stdout).unwrap();
    let mut fails: Vec<String> = Vec::new();
    let (mut patterns, mut compiled, mut safe, mut matches) = (0, 0, 0, 0);
    let mut pat: Vec<u16> = Vec::new();
    let mut cur: Option<Compiled> = None;
    for line in text.lines() {
        let f: Vec<&str> = line.split(' ').collect();
        if f[0] == "P" {
            patterns += 1;
            pat = unhex(f[1]);
            let want_safe = f[2] == "1";
            let got = compile(&pat);
            let dumped = got.as_ref().map_or("N".to_string(), dump);
            if got.is_some() {
                compiled += 1;
            }
            if dumped != f[3] {
                fails.push(format!("compile /{}/: want {} got {}", show(&pat), f[3], dumped));
            }
            let got_safe = is_safe_regex_source(&pat);
            if got_safe {
                safe += 1;
            }
            if got_safe != want_safe {
                fails.push(format!("is_safe_regex_source /{}/: want {want_safe} got {got_safe}", show(&pat)));
            }
            cur = got;
        } else {
            matches += 1;
            let subj = unhex(f[1]);
            let want = match f[2] {
                "N" => None,
                t => Some(t == "T"),
            };
            match &cur {
                None => fails.push(format!("subject for a refused pattern /{}/", show(&pat))),
                Some(c) => {
                    let got = run(c, &subj);
                    if got != want {
                        fails.push(format!("run /{}/ on \"{}\": want {want:?} got {got:?}", show(&pat), show(&subj)));
                    }
                }
            }
        }
        if fails.len() >= 3 {
            break;
        }
    }
    assert!(fails.is_empty(), "{} differences:\n{}", fails.len(), fails.join("\n"));
    assert_eq!(patterns, 8648);
    assert_eq!(compiled, 5267);
    assert_eq!(safe, 3206);
    assert_eq!(matches, 572525);
}

// ---- killRegex: the Kotlin kill corpus (tools/pca-audit/kotlin-mutate/killRegex-oracle-gen.mjs): full-match results over a
// pattern corpus crossed with boundary-probing subjects, compiled sizes, the step boundary, the safe-source guard and the
// per-document budget. A pattern or subject with a lone surrogate (not a Rust string) is skipped. -------------------------

fn kill() -> serde_json::Value {
    crate::k042_support::parse(&crate::k042_support::gunzip("killRegex.json.gz")).expect("killRegex")
}

/// Skipped patterns: a lone surrogate (not a Rust string), or groups nested deeper than 100 (this verifier refuses at a
/// recursion limit of its own, MAX_PARSE_DEPTH, where the reference runs out of stack at another depth: both refuse a
/// source of at most 200 code units that nests that deep, so the pair is not comparable beyond it).
fn lone(s: &str) -> bool {
    let mut depth = 0usize;
    let mut max = 0usize;
    for c in s.chars() {
        match c {
            '(' => {
                depth += 1;
                max = max.max(depth);
            }
            ')' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    s.contains(crate::k042_support::LONE) || max > 100
}

#[test]
fn kill_full_match_corpus() {
    let d = kill();
    let mut n = 0;
    let mut bad = Vec::new();
    for e in d["fm"].as_array().unwrap() {
        let p = e[0].as_str().unwrap();
        let subs = e[1].as_array().unwrap();
        let rs = e[2].as_str().unwrap().as_bytes();
        assert_eq!(subs.len(), rs.len(), "{p}");
        if lone(p) {
            continue;
        }
        for (i, s) in subs.iter().enumerate() {
            let s = s.as_str().unwrap();
            if lone(s) {
                continue;
            }
            let want = match rs[i] {
                b'1' => Some(true),
                b'0' => Some(false),
                _ => None,
            };
            let units: Vec<u16> = p.encode_utf16().collect();
            let subj: Vec<u16> = s.encode_utf16().collect();
            let got = compile(&units).and_then(|c| run(&c, &subj));
            if got != want {
                bad.push(format!("/{p}/ on {:?}: want {want:?} got {got:?}", s.encode_utf16().collect::<Vec<_>>()));
            }
            n += 1;
        }
        if bad.len() > 5 {
            break;
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(n > 100000, "ran {n}");
}

#[test]
fn kill_compiled_sizes_steps_and_safe_guard() {
    let d = kill();
    for e in d["size"].as_array().unwrap() {
        let p = e[0].as_str().unwrap();
        if lone(p) {
            continue;
        }
        let units: Vec<u16> = p.encode_utf16().collect();
        match (e[1].as_i64().unwrap(), compile(&units)) {
            (w, None) => assert!(w < 0, "/{p}/ refused, want size {w}"),
            (w, Some(c)) => assert_eq!(c.prog.len() as i64, w, "/{p}/"),
        }
    }
    for e in d["steps"].as_array().unwrap() {
        let p = e[0].as_str().unwrap();
        let n = e[1].as_u64().unwrap() as usize;
        let want = match e[2].as_i64().unwrap() {
            1 => Some(true),
            0 => Some(false),
            _ => None,
        };
        let units: Vec<u16> = p.encode_utf16().collect();
        let got = compile(&units).and_then(|c| run(&c, &vec![b'a' as u16; n]));
        assert_eq!(got, want, "/{}/ n={n}", &p[..p.len().min(20)]);
    }
    let mut n = 0;
    for e in d["safe"].as_array().unwrap() {
        let p = e[0].as_str().unwrap();
        if lone(p) {
            continue;
        }
        let units: Vec<u16> = p.encode_utf16().collect();
        assert_eq!(is_safe_regex_source(&units), e[1].as_bool().unwrap(), "/{p}/");
        n += 1;
    }
    assert!(n > 3800);
}

#[test]
fn kill_budget_sequences() {
    let d = kill();
    for (k, b) in d["budgets"].as_array().unwrap().iter().enumerate() {
        let ops = b["ops"].as_array().unwrap();
        let res = b["res"].as_array().unwrap();
        let fin = b["fin"].as_array().unwrap();
        with_regex_budget(|| {
            for (i, op) in ops.iter().enumerate() {
                let src: Vec<u16> = op[0].as_str().unwrap().encode_utf16().collect();
                let n = op[1].as_u64().unwrap();
                // the reference refuses a source that does not compile BEFORE charging (a refusal, no state change)
                let got = match compile(&src) {
                    None => false,
                    Some(c) => charge(src.len() as u64, c.prog.len() as u64, n),
                };
                assert_eq!(got, res[i].as_bool().unwrap(), "budget #{k} op {i}");
            }
            let (ev, ch, st) = BUDGET.with(|b| {
                let b = b.borrow();
                let b = b.as_ref().unwrap();
                (b.evaluations, b.chars, b.steps)
            });
            // an over-budget scope is poisoned (evaluations = cap + 1), as in the reference
            assert_eq!(ev, fin[0].as_u64().unwrap(), "budget #{k} evaluations");
            assert_eq!(ch, fin[1].as_u64().unwrap(), "budget #{k} chars");
            assert_eq!(st, fin[2].as_u64().unwrap(), "budget #{k} steps");
        });
    }
}

#[test]
fn budget_constants_and_scopes() {
    assert_eq!(MAX_NFA_INSTRUCTIONS, 4096);
    assert_eq!(MAX_REPEAT, 64);
    assert_eq!(MAX_MATCH_STEPS, 2_000_000);
    assert_eq!(MAX_REGEX_EVALUATIONS_PER_DOCUMENT, 64);
    assert_eq!(MAX_REGEX_SOURCE_CHARS_PER_DOCUMENT, 8192);
    assert_eq!(MAX_REGEX_STEPS_PER_DOCUMENT, 5_000_000);
    // outside any scope a charge is unbudgeted
    for _ in 0..100 {
        assert!(charge(1, 2, 1));
    }
    // a scope joins an enclosing scope and a fresh one starts from zero again
    let r = with_regex_budget(|| {
        let ok = (0..40).filter(|_| charge(1, 2, 0)).count();
        let inner = with_regex_budget(|| (0..40).filter(|_| charge(1, 2, 0)).count());
        (ok, inner, charge(1, 2, 0))
    });
    assert_eq!(r, (40, 24, false));
    assert_eq!(with_regex_budget(|| (0..70).filter(|_| charge(1, 2, 0)).count()), 64);
    // the scope is cleared when the closure unwinds
    let _ = std::panic::catch_unwind(|| with_regex_budget(|| -> () { panic!("boom") }));
    assert!(BUDGET.with(|b| b.borrow().is_none()));
}

fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

#[test]
fn complement_covers_exactly_the_gaps() {
    assert_eq!(complement(&[]), vec![(0, 0xffff)]);
    assert_eq!(complement(&[(0, 0xffff)]), vec![]);
    assert_eq!(complement(&[(0, 0)]), vec![(1, 0xffff)]);
    assert_eq!(complement(&[(0xffff, 0xffff)]), vec![(0, 0xfffe)]);
    assert_eq!(complement(&[(5, 9)]), vec![(0, 4), (10, 0xffff)]);
    assert_eq!(complement(&[(0, 4), (10, 20)]), vec![(5, 9), (21, 0xffff)]);
    assert_eq!(complement(&[(10, 20), (0, 4)]), vec![(5, 9), (21, 0xffff)]);
    assert_eq!(complement(&[(0, 4), (5, 9)]), vec![(10, 0xffff)]); // adjacent ranges merge
    assert_eq!(complement(&[(1, 1)]), vec![(0, 0), (2, 0xffff)]);
}

#[test]
fn brace_quantifier_digit_caps() {
    let q = |src: &str| {
        let s = units(src);
        let p = Parser { s: &s, i: 1, depth: 0 };
        p.brace_quantifier()
    };
    assert_eq!(q("a{3}"), Some((3, Some(3), 3)));
    assert_eq!(q("a{3,}"), Some((3, None, 4)));
    assert_eq!(q("a{3,5}"), Some((3, Some(5), 5)));
    assert_eq!(q("a{1234}"), Some((1234, Some(1234), 6)));
    assert_eq!(q("a{12345}"), None); // a fifth digit is not part of the quantifier
    assert_eq!(q("a{1,1234}"), Some((1, Some(1234), 8)));
    assert_eq!(q("a{1,12345}"), None);
    assert_eq!(q("a{1234,}"), Some((1234, None, 7)));
    assert_eq!(q("a{12345,}"), None);
    assert_eq!(q("a{0064}"), Some((64, Some(64), 6)));
    assert_eq!(q("a{00064}"), None);
    assert_eq!(q("a{1,0064}"), Some((1, Some(64), 8)));
    assert_eq!(q("a{1,00064}"), None);
    assert_eq!(q("a{}"), None);
    assert_eq!(q("a{,3}"), None);
    assert_eq!(q("a{3"), None);
    assert_eq!(q("a{3,"), None);
    assert_eq!(q("a{3,4"), None);
    assert_eq!(q("a{x}"), None);
    // and through the whole pipeline
    assert!(full_match_tri("a{0064}", &"a".repeat(64)).is_some());
    assert_eq!(full_match_tri("a{00064}", "a"), None);
    assert_eq!(full_match_tri("a{1,00064}", "a"), None);
    assert_eq!(full_match_tri("a{0,0064}", "a"), Some(true));
}

#[test]
fn nesting_limits_are_exact() {
    let mk = |n: usize, open: &str, close: &str| units(&format!("{}a{}", open.repeat(n), close.repeat(n)));
    // (open, close, deepest nesting that still compiles): the parser caps groups at 256, the emitter caps its own recursion
    // (two levels for a quantified or alternated group) at 512
    for (open, close, last_ok) in [
        ("(?:", ")", 256),
        ("(", ")", 256),
        ("(?:", ")?", 255),
        ("(?:", "|b)", 255),
        ("(?:b|", ")", 255),
        ("(?:b|", "|c)", 255),
        ("(?:", "){1}", 255),
        ("(?:", ")*", 255),
        ("(?:", "){0,1}", 255),
    ] {
        assert!(compile(&mk(last_ok, open, close)).is_some(), "{open}..{close} x{last_ok}");
        assert!(compile(&mk(last_ok + 1, open, close)).is_none(), "{open}..{close} x{}", last_ok + 1);
    }
    // the group depth is released when a group closes: many sequential groups are fine
    assert!(compile(&units(&"(?:a)".repeat(600))).is_some());
    assert!(compile(&units(&"(a)".repeat(300))).is_some());
    assert!(compile(&units(&format!("{}{}", "(?:a)".repeat(200), "(?:(?:b))".repeat(200)))).is_some());
}

#[test]
fn the_guard_agrees_with_the_parser_on_what_it_does_not_check_itself() {
    // backreferences and a quantifier with nothing to repeat are refused by the guard AND by the parser
    for p in ["\\1", "\\9", "\\k", "a\\1", "*", "+a", "?", "{2}", "a|*", "(*)", "(?:+)", "a{65}", "a{0,65}", "a{65,}"] {
        assert!(compile(&units(p)).is_none(), "{p}");
        assert!(!is_safe_regex_source(&units(p)), "{p}");
    }
    // an escaped bracket does not close a class: what follows still belongs to the class
    assert!(is_safe_regex_source(&units("[\\](a+)+]")));
    assert!(is_safe_regex_source(&units("[^\\](a+)+]")));
    assert!(!is_safe_regex_source(&units("[](a+)+]")));
    assert!(is_safe_regex_source(&units("[^]]")));
    assert!(is_safe_regex_source(&units("[]]")));
    assert!(!is_safe_regex_source(&units("[a")));
    assert!(!is_safe_regex_source(&units("[a\\")));
    // the cost bits: ceil(log2(options)) of a bounded quantifier
    assert!(is_safe_regex_source(&units("a?".repeat(22).as_str())));
    assert!(!is_safe_regex_source(&units("a?".repeat(23).as_str())));
    assert!(is_safe_regex_source(&units(&"a{0,3}".repeat(11)))); // 4 options = 2 bits each
    assert!(!is_safe_regex_source(&units(&"a{0,3}".repeat(12))));
    assert!(is_safe_regex_source(&units(&"a{0,2}".repeat(11)))); // 3 options = 2 bits each
    assert!(!is_safe_regex_source(&units(&"a{0,2}".repeat(12))));

    assert!(is_safe_regex_source(&units(&"a{1}".repeat(100)))); // one option: no cost
    assert!(is_safe_regex_source(&units(&"a{0}".repeat(100))));
    assert!(is_safe_regex_source(&units("a{64}a{64}")));
    assert!(is_safe_regex_source(&units("a{0,64}")));
    assert!(!is_safe_regex_source(&units("a{0,65}")));
}

/// emit's depth cap (`depth > MAX_PARSE_DEPTH * 2`). A group nest `(?:a(?:a...)*)*` costs two emit levels per group
/// below a one-level root, so 255 groups around `aa*` put the deepest Set at exactly emit depth 512 (compiles), and
/// 256 groups put it at 513 (refused). Kills `>` -> `>=` and `>` -> `==` on the depth half of the check.
#[test]
fn emit_depth_cap_is_exactly_twice_the_parse_depth() {
    let nest = |n: usize, inner: &str| -> String { format!("{}(?:{inner})*{}", "(?:a".repeat(n - 1), ")*".repeat(n - 1)) };
    let at_cap: Vec<u16> = nest(MAX_PARSE_DEPTH - 1, "aa*").encode_utf16().collect();
    let over: Vec<u16> = nest(MAX_PARSE_DEPTH, "a").encode_utf16().collect();
    let ok = compile(&at_cap).expect("depth 512 compiles");
    assert_eq!(run(&ok, &[]), Some(true));
    assert_eq!(run(&ok, &"a".encode_utf16().collect::<Vec<_>>()), Some(true));
    assert!(compile(&over).is_none(), "depth 513 is refused");
}

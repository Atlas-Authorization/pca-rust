//! Kill tests for the safe_regex.rs mutants that never produced a plain FAIL (timeouts, 5-10 GiB allocations, aborts).
//! Each group runs in a CHILD process (this test binary, one probe test, 4 GiB address-space cap, 10 s deadline): a mutant
//! that spins, recurses or allocates without bound makes the child die or get killed, so the PARENT assertion fails
//! with an ordinary message. Every case also pins the exact `re:` verdict (the TS `safeRegexFullMatch` result).
use atlas_pca::evaluate_agent_caveats;
use atlas_pca::serde_json::json;
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ENV: &str = "K05B_RE1_GROUP";

/// (pattern, subject, expected full match)
fn table(group: &str) -> Vec<(&'static str, &'static str, bool)> {
    match group {
        // Parser::at, alt, atom (every `self.i += 1` site), CharSet::has (break, hi = mid - 1, lo = mid + 1), structural_guard (i += 1/3, j, `[` scan)
        "basic" => vec![
            ("a", "a", true),
            ("b", "a", false),
            ("a", "b", false),
            (".", "x", true),
            (".", "\n", false),
            ("^a$", "a", true),
            ("(a)", "a", true),
            ("(?:a)", "a", true),
            ("a|b", "b", true),
            ("a|b", "a", true),
        ],
        // Parser::quantified (`*` `+` `?` and the lazy `?`), structural_guard's quantifier tail
        "quant" => vec![("a*", "aa", true), ("a+", "a", true), ("a?", "", true), ("a*?", "aa", true), ("a+?", "aaa", true), ("a??", "", true)],
        // Parser::brace_quantifier, structural_guard's brace scan
        "brace" => vec![("a{2}", "aa", true), ("a{2}", "a", false), ("a{1,2}", "aa", true), ("a{1,}", "aaa", true), ("a{1,2}", "aaa", false)],
        // Parser::cls / read_atom, structural_guard's `[` scan (an escaped `]` is skipped)
        "class" => vec![("[a]", "a", true), ("[a]", "b", false), ("[^a]", "b", true), ("[\\](a+)+]", "(", true), ("[a-c]", "b", true)],
        // Parser::escape_inner
        "escape" => vec![("\\d", "5", true), ("\\x41", "A", true), ("\\u0041", "A", true), ("\\cJ", "\n", true), ("\\.", ".", true), ("\\.", "x", false)],
        // run: an epsilon cycle only terminates through the `mark[pc] == epoch` skip
        "empty" => vec![("(?:)*", "", true), ("(?:)*a", "a", true), ("(?:)*a", "b", false)],
        _ => Vec::new(),
    }
}

fn re_match(pat: &str, subject: &str) -> bool {
    let caveats = json!([{"type": "predicates", "allow": [{"verb": "v", "resource": format!("re:{pat}")}]}]);
    let action_ctx = json!({"action": {"verb": "v", "resource": subject}});
    evaluate_agent_caveats(&caveats, &json!({}), Some(&action_ctx), None).0
}

/// Child side: a no-op unless the parent set the group variable.
#[test]
fn k05b_re1_probe() {
    let group = match std::env::var(ENV) {
        Ok(g) => g,
        Err(_) => return,
    };
    let t = table(&group);
    assert!(!t.is_empty(), "unknown group {group}");
    for (pat, subject, want) in t {
        assert_eq!(re_match(pat, subject), want, "/{pat}/ on {subject:?}");
    }
    println!("K05B_RE1_RAN {group}");
}

/// Parent side: the child must exit successfully inside the deadline.
fn child_ok(group: &str) -> bool {
    let exe = std::env::current_exe().expect("current_exe");
    let mut child = Command::new("sh")
        .arg("-c")
        .arg(r#"ulimit -v 4194304 2>/dev/null; exec "$0" "$@""#)
        .arg(exe)
        .args(["--exact", "k05b_re1_probe", "--nocapture", "--test-threads=1"])
        .env(ENV, group)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn child");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(st) => {
                // the marker proves the probe really ran (a name that matched no test would exit 0 having run nothing)
                let mut out = String::new();
                let _ = child.stdout.take().unwrap().read_to_string(&mut out);
                return st.success() && out.contains(&format!("K05B_RE1_RAN {group}"));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

#[test]
fn safe_regex_basic_atoms_terminate_with_the_reference_verdicts() {
    assert!(child_ok("basic"), "a basic-atom pattern looped, aborted or gave a wrong verdict");
}

#[test]
fn safe_regex_quantifiers_terminate_with_the_reference_verdicts() {
    assert!(child_ok("quant"), "a quantifier pattern looped, aborted or gave a wrong verdict");
}

#[test]
fn safe_regex_brace_quantifiers_terminate_with_the_reference_verdicts() {
    assert!(child_ok("brace"), "a {{n,m}} pattern looped, aborted or gave a wrong verdict");
}

#[test]
fn safe_regex_classes_terminate_with_the_reference_verdicts() {
    assert!(child_ok("class"), "a class pattern looped, aborted or gave a wrong verdict");
}

#[test]
fn safe_regex_escapes_terminate_with_the_reference_verdicts() {
    assert!(child_ok("escape"), "an escape pattern looped, aborted or gave a wrong verdict");
}

#[test]
fn safe_regex_empty_group_cycle_terminates() {
    assert!(child_ok("empty"), "an epsilon-cycle pattern looped, aborted or gave a wrong verdict");
}

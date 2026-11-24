//! k05b re2: kill tests for mutants whose run ended without a plain FAIL (hang, runaway allocation, stack overflow).
//! Each parent test re-runs a probe of this very binary in a CHILD process (ulimit -v caps its memory, a deadline kills a
//! spinner) and asserts the child printed its marker and exited success: a mutant that loops, allocates without bound or
//! recurses without end turns into an ordinary assertion FAIL here. The probes are no-ops unless the marker env var is set.
use atlas_pca::actions::{core_registry, schema_verb_floor_error};
use atlas_pca::attest::rim::{parse_xml, Child, Doc};
use atlas_pca::attest::x509::pem_blocks;
use atlas_pca::{decide_tighten, merkle_root, strict_parse, verify_inclusion};
use serde_json::{json, Value};
use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const ENV: &str = "K05B_RE2_CHILD";

fn child_mode() -> bool {
    std::env::var(ENV).is_ok()
}

/// Run `probe` in a child of this test binary; true only if it printed its marker and exited successfully within `secs`.
fn child_ok(probe: &str, secs: u64) -> bool {
    let exe = std::env::current_exe().unwrap();
    // 4 GiB of address space: an unbounded allocation aborts the child instead of the machine (a failed ulimit is ignored)
    let mut c = Command::new("sh")
        .args(["-c", "ulimit -v 4194304 2>/dev/null; exec \"$0\" \"$@\"", exe.to_str().unwrap(), "--exact", probe, "--nocapture", "--test-threads=1"])
        .env(ENV, "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t0 = Instant::now();
    let status = loop {
        if let Some(s) = c.try_wait().unwrap() {
            break Some(s);
        }
        if t0.elapsed() > Duration::from_secs(secs) {
            let _ = c.kill();
            let _ = c.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut out = String::new();
    let _ = c.stdout.take().unwrap().read_to_string(&mut out);
    matches!(status, Some(s) if s.success()) && out.contains(&format!("K05B_RE2_RAN {probe}"))
}

fn ran(probe: &str) {
    println!("K05B_RE2_RAN {probe}");
}

// ---------------------------------------------------------------- Merkle: split, path_shape

#[test]
fn probe_merkle() {
    if !child_mode() {
        return;
    }
    let (a, b, c) = (json!({"n": 1}), json!({"n": 2}), json!({"n": 3}));
    let h = |l: &Value| merkle_root(std::slice::from_ref(l)).unwrap();
    let proof = |index: u64, size: u64, path: Vec<(&str, String)>| {
        json!({"index": index, "size": size, "path": path.into_iter().map(|(s, h)| json!({"side": s, "hash": h})).collect::<Vec<_>>()})
    };
    let check = |root: &str, p: Value, leaf: &Value| verify_inclusion(root, p.as_object(), leaf);
    // size 1: no path (path_shape stops at a single leaf)
    assert!(check(&h(&a), proof(0, 1, vec![]), &a));
    // size 2, index 0 and 1
    let r2 = merkle_root(&[a.clone(), b.clone()]).unwrap();
    assert!(check(&r2, proof(0, 2, vec![("R", h(&b))]), &a));
    assert!(check(&r2, proof(1, 2, vec![("L", h(&a))]), &b));
    // size 3: split(3) = 2 (k doubles from 1)
    let r3 = merkle_root(&[a.clone(), b.clone(), c.clone()]).unwrap();
    assert!(check(&r3, proof(2, 3, vec![("L", r2.clone())]), &c));
    assert!(check(&r3, proof(0, 3, vec![("R", h(&b)), ("R", h(&c))]), &a));
    ran("probe_merkle");
}

#[test]
fn merkle_split_and_path_shape_terminate_and_agree() {
    assert!(child_ok("probe_merkle", 5), "merkle_root / verify_inclusion hung, ran away or answered wrongly");
}

// ---------------------------------------------------------------- strict JSON parser

#[test]
fn probe_strict_json() {
    if !child_mode() {
        return;
    }
    let v = strict_parse(r#" {"a\n\"b":[-12, 0, 3.25, "xé\\"], "c": {}} "#).unwrap();
    assert_eq!(v, json!({"a\n\"b": [-12, 0, 3.25, "x\u{e9}\\"], "c": {}}));
    ran("probe_strict_json");
}

#[test]
fn the_strict_json_parser_terminates_and_reads_every_token() {
    assert!(child_ok("probe_strict_json", 5), "strict_parse hung, ran away or misread a token");
}

// ---------------------------------------------------------------- RIM XML parser

fn dump(d: &Doc, i: usize) -> String {
    let e = &d.els[i];
    let mut s = format!("<{}", e.qname);
    for a in &e.attrs {
        s += &format!(" {}={:?}", a.qname, a.value);
    }
    s.push('>');
    for c in &e.children {
        match c {
            Child::El(j) => s += &dump(d, *j),
            Child::Text(t) => s += &format!("{t:?}"),
        }
    }
    s + &format!("</{}>", e.qname)
}

#[test]
fn probe_rim() {
    if !child_mode() {
        return;
    }
    // leading and trailing whitespace, a prolog comment, attributes in both quotes, text, a nested element, an empty
    // element, tail text and a comment inside the element
    let d = parse_xml("  <!-- p -->\n <r a=\"1\" b='2'>t<c d=\"3\">x&amp;y</c><e/>tail<!-- k --></r>  ").ok().unwrap();
    assert_eq!(dump(&d, d.root), r#"<r a="1" b="2">"t"<c d="3">"x&y"</c><e></e>"tail"</r>"#);
    assert_eq!(d.violation.as_deref(), Some("XML comments are not permitted"));
    // an unterminated comment inside an element is an error, not a spin
    assert!(parse_xml("<r><!-- never closed</r>").is_err());
    assert!(parse_xml("<r><?pi never closed</r>").is_err());
    ran("probe_rim");
}

#[test]
fn the_rim_xml_parser_terminates_and_reads_every_token() {
    assert!(child_ok("probe_rim", 5), "parse_xml hung, ran away or misread a token");
}

// ---------------------------------------------------------------- PEM blocks

#[test]
fn probe_pem() {
    if !child_mode() {
        return;
    }
    const B1: &str = "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----";
    const B2: &str = "-----BEGIN CERTIFICATE-----\nAQ==\n-----END CERTIFICATE-----";
    // two blocks, then an unterminated BEGIN: the scan returns both and stops
    let text = format!("xx{B1}\n{B2}\n-----BEGIN CERTIFICATE-----\nzz");
    assert_eq!(pem_blocks(&text), vec![B1, B2]);
    assert!(pem_blocks("-----BEGIN CERTIFICATE-----\nAA==").is_empty());
    ran("probe_pem");
}

#[test]
fn pem_blocks_terminates_and_advances_past_each_block() {
    assert!(child_ok("probe_pem", 5), "pem_blocks hung or ran away");
}

// ---------------------------------------------------------------- `like` glob (predicates::glob_match)

#[test]
fn probe_glob() {
    if !child_mode() {
        return;
    }
    let run = |s: &str| {
        let input = json!({
            "tighten": [{"id": "g", "when": {"field": "action.params.s", "op": "like", "value": "*a"}, "signal": "deny"}],
            "context": {"action": {"verb": "v", "resource": "r", "params": {"s": s}}}
        });
        decide_tighten(&input).outcome
    };
    // the star must backtrack one unit at a time: "bba" matches "*a", "bbb" does not
    assert_eq!(run("bba"), "deny");
    assert_eq!(run("bbb"), "ok");
    ran("probe_glob");
}

#[test]
fn glob_match_backtracking_terminates() {
    assert!(child_ok("probe_glob", 5), "like / glob_match hung or answered wrongly");
}

// ---------------------------------------------------------------- js_number_string (stack overflow when mutated)

#[test]
fn probe_js_number() {
    if !child_mode() {
        return;
    }
    // a numeric trait is named by its ECMAScript String() form (js_number_string(5)) before anything else is checked;
    // a mutant that recurses on every positive number overflows the stack here
    let verb = json!({"effects": [], "traits": [5, -1.5], "floors": {}});
    assert!(schema_verb_floor_error(&verb, &core_registry(), None).is_some());
    ran("probe_js_number");
}

#[test]
fn js_number_string_recursion_is_bounded() {
    assert!(child_ok("probe_js_number", 5), "js_number_string overflowed the stack or the verb check did not refuse");
}

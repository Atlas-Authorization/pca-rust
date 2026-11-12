//! Shared helpers of the k042 differential unit tests (serde_json cannot hold a lone surrogate: see tests/common/mod.rs).
use serde_json::Value;

/// A Rust `String` cannot hold a lone surrogate, but `vectors.json` carries one in an OBJECT-form vector
/// (`"aud": "rs-\ud800"`), which `serde_json` refuses to load. Replace every lone surrogate escape inside a
/// JSON string with this sentinel; the harness then reports `wire` failure for any vector containing it
/// (exactly what a UTF-16 language reaches via the strict canonical encoder).
pub const LONE: char = '\u{10FFFF}';

pub fn sanitize_lone_surrogates(text: &str) -> String {
    let cs: Vec<char> = text.chars().collect();
    let hex = |at: usize| -> Option<u32> {
        let s: String = cs.get(at..at + 4)?.iter().collect();
        if s.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&s, 16).ok()
        } else {
            None
        }
    };
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0, false);
    while i < cs.len() {
        let c = cs[i];
        if !in_str {
            in_str = c == '"';
            out.push(c);
            i += 1;
        } else if c == '"' {
            in_str = false;
            out.push(c);
            i += 1;
        } else if c == '\\' {
            if cs.get(i + 1) == Some(&'u') {
                match hex(i + 2) {
                    Some(hi) if (0xD800..=0xDBFF).contains(&hi) => {
                        let paired = cs.get(i + 6) == Some(&'\\')
                            && cs.get(i + 7) == Some(&'u')
                            && hex(i + 8).is_some_and(|lo| (0xDC00..=0xDFFF).contains(&lo));
                        if paired {
                            out.extend(&cs[i..i + 12]);
                            i += 12;
                        } else {
                            out.push(LONE);
                            i += 6;
                        }
                    }
                    Some(lo) if (0xDC00..=0xDFFF).contains(&lo) => {
                        out.push(LONE);
                        i += 6;
                    }
                    _ => {
                        out.extend(&cs[i..(i + 2).min(cs.len())]);
                        i += 2;
                    }
                }
            } else {
                out.extend(&cs[i..(i + 2).min(cs.len())]);
                i += 2;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

#[allow(dead_code)]
pub fn has_lone(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(LONE),
        Value::Array(a) => a.iter().any(has_lone),
        Value::Object(m) => m.iter().any(|(k, x)| k.contains(LONE) || has_lone(x)),
        _ => false,
    }
}

/// Run `gzip -dc` over a file under tests/data and return the text.
#[allow(dead_code)]
pub fn gunzip(name: &str) -> String {
    let o = std::process::Command::new("gzip").arg("-dc").arg(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).output().expect("gzip");
    assert!(o.status.success());
    String::from_utf8(o.stdout).expect("utf8")
}

pub fn read(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).expect("read")
}

/// Parse JSON text with lone surrogates replaced by [`LONE`]; None when serde_json cannot hold the text (1e400).
pub fn parse(t: &str) -> Option<Value> {
    use serde::Deserialize;
    let text = sanitize_lone_surrogates(t);
    let mut de = serde_json::Deserializer::from_str(&text);
    de.disable_recursion_limit();
    let v = Value::deserialize(&mut de).ok()?;
    de.end().ok()?;
    Some(v)
}


/// The cases `fn_name` of a gzipped k042 corpus (`[{fn, name, args, out}]`), parsed with lone surrogates sanitized.
pub fn corpus_cases(file: &str, fn_name: &str) -> Vec<Value> {
    let text = if file.ends_with(".gz") { gunzip(file) } else { read(file) };
    let all = parse(&text).expect("corpus");
    let out: Vec<Value> = all.as_array().expect("array").iter().filter(|c| c["fn"] == fn_name).cloned().collect();
    assert!(!out.is_empty(), "no oracle cases for {fn_name}");
    out
}

/// The `cases` member of a gzipped k042 corpus document `{about, cases}`.
pub fn doc_cases(file: &str) -> Vec<Value> {
    let text = if file.ends_with(".gz") { gunzip(file) } else { read(file) };
    parse(&text).expect("corpus")["cases"].as_array().expect("cases").clone()
}

/// A refusal reason must be the TS reference's, character for character. A thrown internal error is compared up to its
/// prefix "<check> error (fail closed): ". `PCA_TEXTDIFF_DUMP=<file>` appends each differing pair to the file and accepts
/// it instead of failing (a porting aid for finding what still differs).
pub fn same_text(key: &str, want: Option<&str>, got: Option<&str>) -> bool {
    match (want, got) {
        (None, None) => true,
        (Some(w), Some(g)) => {
            if w == g || (w.ends_with("(fail closed): ") && g.starts_with(w)) {
                return true;
            }
            if let Ok(p) = std::env::var("PCA_TEXTDIFF_DUMP") {
                use std::io::Write;
                if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(p) {
                    let _ = writeln!(f, "{key}\n  want {w:?}\n  got  {g:?}");
                }
                return true;
            }
            false
        }
        _ => false,
    }
}

/// Run `f` on a thread with a 512 MiB stack (the kill corpora nest values thousands of levels deep).
pub fn on_big_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new().stack_size(512 << 20).spawn(f).expect("spawn").join().unwrap_or_else(|e| std::panic::resume_unwind(e));
}

// ---- k05 differential oracles (tools/pca-audit/k05-oracles; tests/data/k05-<module>.json.gz = {about, cases: [{fn, name, args, out}]})

/// What the native returned for one k05 case.
#[allow(dead_code)]
pub enum K05 {
    /// a value, compared with [`k05_same`] against `out`
    Val(Value),
    /// a refusal (throw / Err); `Some(code)` must equal the case's `out.code` when the case has one
    Throw(Option<String>),
    /// the module compared the case itself
    Match(bool),
    /// not comparable here (the reason is counted and printed)
    Skip(&'static str),
}

/// The cases of tests/data/k05-<module>.json.gz, streamed one per line (the oracle writes `{about, ..., "count":N,"cases":[`,
/// then one case per line, then `]}`): a 170 MB corpus parsed whole is several GiB, past the mutation runner's 6 GiB cap per
/// test process. A truncated / malformed stream or a case count other than the header's fails the test.
#[allow(dead_code)]
pub fn k05_cases(module: &str) -> impl Iterator<Item = Value> {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    let path = format!("{}/tests/data/k05-{module}.json.gz", env!("CARGO_MANIFEST_DIR"));
    let mut child = Command::new("gzip").arg("-dc").arg(&path).stdout(Stdio::piped()).spawn().expect("gzip");
    let mut lines = BufReader::new(child.stdout.take().expect("stdout")).lines().map(|l| l.expect("utf8 corpus line"));
    let head = lines.next().expect("corpus header");
    assert!(head.ends_with("\"cases\":["), "{path}: header must end with \"cases\":[");
    let head = parse(&format!("{head}]}}")).expect("header");
    let count = head["count"].as_u64().expect("header count") as usize;
    let (mut seen, mut done) = (0usize, false);
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let line = lines.next().expect("corpus truncated before ]}");
        if line == "]}" {
            assert!(lines.next().is_none(), "{path}: text after ]}}");
            assert!(child.wait().expect("gzip").success(), "{path}: gzip failed");
            assert_eq!(seen, count, "{path}: case count");
            done = true;
            return None;
        }
        seen += 1;
        let case = parse(line.strip_suffix(',').unwrap_or(&line)).expect("corpus case line");
        assert!(case.is_object(), "{path}: case {seen} is not an object");
        Some(case)
    })
}

/// The bytes of a `{"$bytes": b64url}` value.
#[allow(dead_code)]
pub fn k05_bytes(v: &Value) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(v.get("$bytes")?.as_str()?).ok()
}

/// `{"$bytes": b64url}` of `b` (how the oracle writes a Uint8Array).
#[allow(dead_code)]
pub fn k05_b64(b: &[u8]) -> Value {
    use base64::Engine;
    serde_json::json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b) })
}

/// JSON equality as the reference sees it: numbers by value (-0 = 0, 1 = 1.0), objects regardless of member order, and an
/// absent member = a null one (the oracle drops `undefined` members; a typed port writes them as null).
#[allow(dead_code)]
pub fn k05_same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => match (x.as_i64(), y.as_i64()) {
            (Some(p), Some(q)) => p == q,
            _ => x.as_f64() == y.as_f64(),
        },
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| k05_same(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            let null = Value::Null;
            x.iter().all(|(k, v)| k05_same(v, y.get(k).unwrap_or(&null))) && y.iter().all(|(k, v)| x.contains_key(k) || v.is_null())
        }
        _ => a == b,
    }
}

/// Replay every case of k05-<module> through `f(case, fn, args)` and fail on any difference. A case whose args or out carry a
/// lone surrogate (serde_json cannot hold one) is skipped; an `@suspect` fn (behaviour the oracle flags as questionable) is run
/// and reported, never failed. At least `min` cases must be compared.
#[allow(dead_code)]
pub fn k05_run(module: &'static str, min: usize, f: impl Fn(&Value, &str, &[Value]) -> K05 + Send + 'static) {
    on_big_stack(move || {
        use std::collections::BTreeMap;
        let (mut bad, mut suspect, mut ran) = (Vec::new(), Vec::new(), 0usize);
        // failures per fn; at most 6 shown per fn so one CI round shows every kind of difference
        let mut bad_by: BTreeMap<String, usize> = BTreeMap::new();
        let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
        let mut skipped: BTreeMap<String, usize> = BTreeMap::new();
        for c in k05_cases(module) {
            let name = c["name"].as_str().unwrap_or("?").to_string();
            let full = c["fn"].as_str().expect("fn");
            let (fname, is_suspect) = match full.strip_suffix("@suspect") {
                Some(b) => (b, true),
                None => (full, false),
            };
            let args = c["args"].as_array().cloned().unwrap_or_default();
            let want = &c["out"];
            if args.iter().any(has_lone) || has_lone(want) {
                *skipped.entry(format!("{fname}: lone surrogate")).or_default() += 1;
                continue;
            }
            let got = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(&c, fname, &args)));
            let got = match got {
                Ok(g) => g,
                Err(_) => {
                    *bad_by.entry(fname.to_string()).or_default() += 1;
                    let n = kinds.entry(format!("{fname} PANIC")).or_default();
                    *n += 1;
                    if *n <= 2 {
                        bad.push(format!("{name}: PANIC (args {})", short(&Value::Array(args.clone()))));
                    }
                    continue;
                }
            };
            let thrown = want.get("$throws").is_some();
            let (ok, shown) = match &got {
                K05::Skip(why) => {
                    *skipped.entry(format!("{fname}: {why}")).or_default() += 1;
                    continue;
                }
                K05::Match(m) => (*m, "(module compare)".to_string()),
                K05::Throw(code) => {
                    let ok = thrown && match (want.get("code").and_then(Value::as_str), code) {
                        (Some(w), Some(g)) => w == g,
                        (Some(_), None) => false,
                        (None, _) => true,
                    };
                    (ok, format!("throw {code:?}"))
                }
                K05::Val(v) => (!thrown && k05_same(want, v), v.to_string()),
            };
            ran += 1;
            if !ok {
                let (at, key) = diff_at(&want.to_string(), &shown);
                let line = format!("{name}:\n  args {}\n  want {}\n  got  {}\n  first diff {at}", short(&Value::Array(args.clone())), short(want), short_str(&shown));
                if is_suspect {
                    suspect.push(line)
                } else {
                    *bad_by.entry(fname.to_string()).or_default() += 1;
                    // at most 2 shown per kind of difference (fn + the masked text around the first differing char)
                    let n = {
                        let n = kinds.entry(format!("{fname} {key}")).or_default();
                        *n += 1;
                        *n
                    };
                    if n <= 2 && kinds.len() <= 400 {
                        bad.push(line)
                    }
                }
            }
        }
        eprintln!("k05-{module}: {ran} compared; skipped {skipped:?}");
        if !suspect.is_empty() {
            eprintln!("k05-{module}: {} @suspect cases differ (reported, not failed):\n{}", suspect.len(), suspect.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
        }
        assert!(ran >= min, "k05-{module}: only {ran} cases compared (want >= {min})");
        let kinds: Vec<String> = kinds.iter().take(300).map(|(k, n)| format!("  {n:>5}  {k}")).collect();
        assert!(bad.is_empty(), "k05-{module}: {} of {ran} cases differ {bad_by:?}; kinds:\n{}\n{}", bad_by.values().sum::<usize>(), kinds.join("\n"), bad.join("\n"));
    });
}

/// The first char where `want` and `got` differ, as "…want-context ⟂ got-context" (shown) and the same with digits masked
/// (the grouping key of the divergence report).
#[allow(dead_code)]
fn diff_at(want: &str, got: &str) -> (String, String) {
    let (w, g): (Vec<char>, Vec<char>) = (want.chars().collect(), got.chars().collect());
    let i = w.iter().zip(&g).take_while(|(a, b)| a == b).count();
    let cut = |v: &[char], a: usize, b: usize| v[a.min(v.len())..b.min(v.len())].iter().collect::<String>();
    let at = format!("…{}⟂ want {:?} got {:?}", cut(&w, i.saturating_sub(40), i), cut(&w, i, i + 50), cut(&g, i, i + 50));
    let key = format!("{} | {} | {}", cut(&w, i.saturating_sub(24), i), cut(&w, i, i + 24), cut(&g, i, i + 24)).chars().map(|c| if c.is_ascii_digit() { '#' } else { c }).collect();
    (at, key)
}

#[allow(dead_code)]
fn short_str(s: &str) -> String {
    if s.len() > 600 { format!("{}...({} chars)", &s[..s.char_indices().take_while(|(i, _)| *i < 600).last().map_or(0, |(i, c)| i + c.len_utf8())], s.len()) } else { s.to_string() }
}

#[allow(dead_code)]
fn short(v: &Value) -> String {
    let s = v.to_string();
    if s.len() > 600 { format!("{}...({} chars)", &s[..s.char_indices().take_while(|(i, _)| *i < 600).last().map_or(0, |(i, c)| i + c.len_utf8())], s.len()) } else { s }
}

/// k05 deadline (BRIEF "Timeouts are not kills"): run `f` on its own thread and fail unless it answers within 2 s. A mutant
/// that stops a loop advancing then FAILS the test that calls this instead of timing out the run (the mutation run's nextest
/// config terminates the tests still spinning). Every call site's real work takes well under a millisecond.
pub fn within<T: Send + 'static>(what: &str, f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(2)) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("{what}: no answer within 2 s (a loop that stopped advancing)"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("{what}: panicked"),
    }
}

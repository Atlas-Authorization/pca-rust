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

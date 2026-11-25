//! Differential replay of the action pack YAML text: the writer (`defsToYaml`, byte-identical output including the anchors and aliases
//! written for repeated containers) and the authoring-file text loader (`loadActionsText`, YAML 1.2 core and JSON, with source
//! positions). The loader is compared by value; a syntax error is compared by class (the parser's wording is its own), and a text that
//! uses a construct this loader refuses on purpose (see the loader's module note) may answer one "not YAML" refusal instead.
mod common;
use atlas_pca::actions_kit_ops::yaml::{defs_to_yaml_units, load_actions_text, Y};
use atlas_pca::serde_json::{Map, Value};
use std::collections::HashMap;

/// Lone surrogates of the corpus text become characters of plane 16 (U+10D800 + offset) so that serde_json can read the text; `units`
/// turns them back into the lone code unit.
fn load_units(name: &str) -> Vec<Value> {
    let path = format!("{}/test-data/ref-{name}.json.gz", env!("CARGO_MANIFEST_DIR"));
    let o = std::process::Command::new("gzip").arg("-dc").arg(&path).output().expect("gzip");
    assert!(o.status.success(), "{path}");
    let text: Vec<char> = String::from_utf8(o.stdout).expect("utf8").chars().collect();
    let hex = |at: usize| -> Option<u32> { u32::from_str_radix(&text.get(at..at + 4)?.iter().collect::<String>(), 16).ok() };
    let mut out = String::new();
    let mut i = 0;
    while i < text.len() {
        if text[i] == '\\' && text.get(i + 1) == Some(&'u') {
            match hex(i + 2) {
                Some(hi)
                    if (0xD800..=0xDBFF).contains(&hi)
                        && text.get(i + 6) == Some(&'\\')
                        && text.get(i + 7) == Some(&'u')
                        && hex(i + 8).is_some_and(|lo| (0xDC00..=0xDFFF).contains(&lo)) =>
                {
                    out.extend(&text[i..i + 12]);
                    i += 12;
                }
                Some(u) if (0xD800..=0xDFFF).contains(&u) => {
                    out.push(char::from_u32(0x10_0000 + u).expect("plane 16"));
                    i += 6;
                }
                _ => {
                    out.extend(&text[i..i + 2]);
                    i += 2;
                }
            }
        } else if text[i] == '\\' {
            out.extend(&text[i..(i + 2).min(text.len())]);
            i += 2;
        } else {
            out.push(text[i]);
            i += 1;
        }
    }
    let doc: Value = atlas_pca::serde_json::from_str(&out).expect("parse");
    let cases = doc["cases"].as_array().expect("cases").clone();
    assert_eq!(cases.len() as u64, doc["count"].as_u64().expect("count"));
    cases
}

fn units(s: &str) -> Vec<u16> {
    let mut out = Vec::new();
    for c in s.chars() {
        let n = c as u32;
        if (0x10_D800..=0x10_DFFF).contains(&n) {
            out.push((n - 0x10_0000) as u16);
        } else {
            let mut b = [0u16; 2];
            out.extend_from_slice(c.encode_utf16(&mut b));
        }
    }
    out
}

fn conv(v: &Value, boxes: &HashMap<String, Y>) -> Y {
    match v {
        Value::Null => Y::Null,
        Value::Bool(b) => Y::Bool(*b),
        Value::Number(n) => Y::Num(n.as_f64().expect("number")),
        Value::String(s) => Y::Str(units(s)),
        Value::Array(a) => Y::seq(a.iter().map(|x| conv(x, boxes)).collect()),
        Value::Object(o) if o.len() == 1 && o.contains_key("$ref") => boxes[o["$ref"].as_str().expect("ref id")].clone(),
        Value::Object(o) => Y::map(o.iter().map(|(k, x)| (units(k), conv(x, boxes))).collect()),
    }
}

/// ONE container per id of `shared`, filled (cycles allowed); every `{"$ref": id}` of the arguments is that container.
fn replay(corpus: &str, anchored: bool) {
    let cases = load_units(corpus);
    let mut bad = Vec::new();
    for c in &cases {
        let a = c["args"].as_array().expect("args");
        let mut boxes: HashMap<String, Y> = HashMap::new();
        let shared: Map<String, Value> = if anchored { a[3].as_object().cloned().unwrap_or_default() } else { Map::new() };
        for (id, v) in &shared {
            boxes.insert(id.clone(), if v.is_array() { Y::seq(vec![]) } else { Y::map(vec![]) });
        }
        for (id, v) in &shared {
            match (&boxes[id], conv(v, &boxes)) {
                (Y::Seq(rc), Y::Seq(f)) => *rc.borrow_mut() = f.borrow().clone(),
                (Y::Map(rc), Y::Map(f)) => *rc.borrow_mut() = f.borrow().clone(),
                _ => panic!("shared container kind"),
            }
        }
        let ns = units(a[0].as_str().expect("ns"));
        let defs: Vec<Y> = a[1].as_array().expect("defs").iter().map(|d| conv(d, &boxes)).collect();
        let rules = a[2].is_object().then(|| conv(&a[2], &boxes));
        let want = units(c["out"].as_str().expect("out"));
        match defs_to_yaml_units(&ns, &defs, rules.as_ref()) {
            Ok(got) if got == want => {}
            got => bad.push(format!("{}: got {:?}\nwant {:?}", c["name"], got.map(|g| String::from_utf16_lossy(&g)), String::from_utf16_lossy(&want))),
        }
    }
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), cases.len(), bad.iter().take(8).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn defs_to_yaml_plain_corpus() {
    replay("core-yaml-java", false);
}

#[test]
fn defs_to_yaml_anchor_corpus() {
    replay("core-yaml-anchors-java", true);
}

#[test]
fn load_actions_text_corpus() {
    let cases = common::ref_cases("actions-yaml-load-py");
    let syntax = ["not YAML", "YAML warning", "not JSON"];
    let stricter = |t: &str| {
        t.contains("!!binary")
            || t.contains("? [")
            || t.contains("\r")
            || t.split_whitespace().any(|w| w.starts_with('!') && !["!!str", "!!map", "!!seq"].contains(&w))
    };
    let (mut bad, mut tolerated) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(c) {
            continue;
        }
        let (text, fmt) = (c["args"][0].as_str().expect("text"), c["args"][1].as_str().expect("fmt"));
        let got = load_actions_text(text, fmt);
        let exp = &c["out"];
        let e0 = exp["errors"][0]["message"].as_str().unwrap_or("");
        let single = |g: &Value, prefix: &str| {
            g["errors"].as_array().is_some_and(|e| e.len() == 1 && e[0]["message"].as_str().unwrap_or("").starts_with(prefix))
                && g["defs"] == serde_json_empty()
        };
        let ok = if syntax.iter().any(|p| e0.starts_with(p)) {
            single(&got, if fmt == "yaml" { "not YAML" } else { "not JSON" }) || (fmt == "yaml" && single(&got, "YAML warning"))
        } else if ["defs", "notes", "errors", "locs", "rules", "ns"].iter().all(|k| got.get(k) == exp.get(k)) {
            true
        } else {
            let t = stricter(text) && single(&got, "not YAML");
            tolerated += t as usize;
            t
        };
        if !ok {
            bad.push(format!("{}: {:.80}\n got {:.300}\nwant {:.300}", c["name"], text, got, exp));
        }
    }
    assert!(bad.is_empty(), "{} of {} differ:\n{}", bad.len(), cases.len(), bad.iter().take(10).cloned().collect::<Vec<_>>().join("\n"));
    assert!(tolerated * 10 < cases.len(), "too many stricter refusals: {tolerated}");
}

fn serde_json_empty() -> Value {
    Value::Array(vec![])
}

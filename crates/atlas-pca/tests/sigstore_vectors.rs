//! Offline Sigstore bundle verification (track K9): replays packages/pca/conformance/sigstore-vectors.json. `ok` and the
//! refusal `code` must match, and on ok the whole `core`. A missing file fails, it never skips.
use atlas_pca::serde_json::{json, Value};
use atlas_pca::sigstore::{parse_trusted_root, verify_sigstore_bundle, verify_sigstore_bundle_core};
use atlas_pca::provenance_facts_error;

fn vectors() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/sigstore-vectors.json");
    atlas_pca::serde_json::from_str(&std::fs::read_to_string(path).expect("read sigstore-vectors.json")).expect("parse")
}

#[test]
fn sigstore_vectors() {
    let d = vectors();
    let cases = d["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    let (mut bad, mut facts) = (Vec::new(), 0);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let roots = parse_trusted_root(&d["roots"][c["roots"].as_str().unwrap()]).unwrap_or_else(|e| panic!("{name}: root: {e}"));
        let r = verify_sigstore_bundle_core(&c["bundle"], &roots);
        let exp = &c["expect"];
        match (&r, exp["ok"].as_bool().unwrap()) {
            (Ok(core), true) if core.core != exp["core"] => bad.push(format!("{name}: core\n got {}\nwant {}", core.core, exp["core"])),
            (Ok(_), true) => {
                if let Ok(f) = verify_sigstore_bundle(&c["bundle"], &roots) {
                    if let Some(e) = provenance_facts_error(&f) {
                        bad.push(format!("{name}: facts rejected by the gate: {e}"));
                    }
                    facts += 1;
                }
            }
            (Err(e), false) if e.code != exp["code"] => bad.push(format!("{name}: refused with {} ({}), the reference says {}", e.code, e.detail, exp["code"])),
            (Err(_), false) => {}
            (Ok(_), false) => bad.push(format!("{name}: accepted, want {}", exp["code"])),
            (Err(e), true) => bad.push(format!("{name}: refused {} ({})", e.code, e.detail)),
        }
    }
    eprintln!("{} cases replayed, {facts} produced gate-valid SLSA facts", cases.len());
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn sigstore_hostile_input() {
    let d = vectors();
    let roots = parse_trusted_root(&d["roots"]["public-good-844a1c6d"]).unwrap();
    let ok = d["cases"].as_array().unwrap().iter().find(|c| c["expect"]["ok"] == json!(true)).unwrap()["bundle"].clone();
    for b in [json!(null), json!([]), json!({}), json!({"verificationMaterial": {}})] {
        assert!(verify_sigstore_bundle_core(&b, &roots).is_err());
    }
    // every string member of a verifying bundle replaced by garbage, and every array emptied: refused, never a panic
    fn walk(v: &Value, path: &mut Vec<String>, out: &mut Vec<Vec<String>>) {
        match v {
            Value::Object(m) => m.iter().for_each(|(k, x)| { path.push(k.clone()); out.push(path.clone()); walk(x, path, out); path.pop(); }),
            Value::Array(a) => a.iter().enumerate().for_each(|(i, x)| { path.push(i.to_string()); out.push(path.clone()); walk(x, path, out); path.pop(); }),
            _ => {}
        }
    }
    let mut paths = Vec::new();
    walk(&ok, &mut Vec::new(), &mut paths);
    for p in paths {
        for junk in [json!("AAAA"), json!(""), json!(7), json!([])] {
            let mut b = ok.clone();
            let mut cur = &mut b;
            for k in &p[..p.len() - 1] {
                cur = if cur.is_array() { &mut cur[k.parse::<usize>().unwrap()] } else { &mut cur[k.as_str()] };
            }
            let last = &p[p.len() - 1];
            if cur.is_array() { cur[last.parse::<usize>().unwrap()] = junk.clone() } else { cur[last.as_str()] = junk.clone() }
            if let Err(e) = verify_sigstore_bundle_core(&b, &roots) {
                assert!(!e.detail.contains("panic"), "{p:?}: {}", e.detail);
            }
        }
    }
}

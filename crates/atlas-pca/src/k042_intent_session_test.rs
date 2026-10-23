//! 0.4.2 mutation kills for intent_session.rs (rule 13: the `intent_session` wire member, the grant caveat, the signed session
//! root) and intent_revocation.rs (rule 13 step 7). Differential against the TypeScript reference: the cases and their exact
//! reasons come from tools/pca-audit/java-mutate/k042-sessrevoc-oracle.mts (tests/data/k042-sessrevoc-cases.json, the same
//! file the Java suite runs). Verdicts compare exactly; a reason text is the reference's, character for character
//! (same_text). Not compared: the `prim` cases (the conformance-driver wrapper over the epoch check, not a function of
//! this crate) and the rev cases whose authority / ids are not a string / list (this API is typed).
use super::*;
use crate::k042_support::{has_lone, parse, read, same_text};

fn cases(kind: &str) -> Vec<Value> {
    parse(&read("k042-sessrevoc-cases.json")).expect("corpus")[kind].as_array().expect(kind).clone()
}

fn j(text: &Value) -> Option<Value> {
    parse(text.as_str()?).filter(|v| !has_lone(v))
}

fn report(bad: Vec<String>, n: usize) {
    assert!(n > 0);
    assert!(bad.is_empty(), "{}/{n} divergent:\n{}", bad.len(), bad.iter().take(400).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn wire() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for (i, c) in cases("wire").iter().enumerate() {
        let Some(v) = j(&c["v"]) else { continue };
        n += 1;
        let got = validate_intent_session_wire(&v).err();
        if !same_text(&format!("wire/{}#{i}", c["name"]), c["reason"].as_str(), got.as_deref()) {
            bad.push(format!("{}: want {} got {got:?}", c["name"], c["reason"]));
        }
    }
    assert!(n >= 60);
    report(bad, n);
}

#[test]
fn caveat() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for (i, c) in cases("caveat").iter().enumerate() {
        let Some(v) = j(&c["c"]) else { continue };
        n += 1;
        let got = intent_session_caveat_error(Some(&v));
        if !same_text(&format!("caveat/{}#{i}", c["name"]), c["reason"].as_str(), got.as_deref()) {
            bad.push(format!("{}: want {} got {got:?}", c["name"], c["reason"]));
        }
    }
    assert!(n >= 17);
    report(bad, n);
}

#[test]
fn root() {
    let (mut bad, mut n) = (Vec::new(), 0);
    for (i, c) in cases("root").iter().enumerate() {
        let Some(s) = j(&c["s"]) else { continue };
        n += 1;
        let name = c["name"].as_str().unwrap();
        let pins = c.get("pq_pins").filter(|p| !p.is_null()).and_then(j);
        let shape = session_root_shape_error(&s);
        if !same_text(&format!("shape/{name}#{i}"), c["shape"].as_str(), shape.as_deref()) {
            bad.push(format!("shape {name}: want {} got {shape:?}", c["shape"]));
        }
        let verify = verify_session_root_pinned(&s, pins.as_ref()).err();
        if !same_text(&format!("verify/{name}#{i}"), c["verify"].as_str(), verify.as_deref()) {
            bad.push(format!("verify {name}: want {} got {verify:?}", c["verify"]));
        }
    }
    assert!(n >= 150);
    report(bad, n);
}

#[test]
fn revocation() {
    use crate::intent_revocation::check_session_revocation;
    let (mut bad, mut n) = (Vec::new(), 0);
    for (i, c) in cases("rev").iter().enumerate() {
        let ev = if c["ev"].is_null() { None } else { j(&c["ev"]) };
        let (Some(authority), Some(ids)) = (j(&c["authority"]), j(&c["ids"])) else { continue };
        let (Some(authority), Some(ids)) = (authority.as_str(), ids.as_array()) else { continue };
        let Some(ids) = ids.iter().map(|x| x.as_str().map(String::from)).collect::<Option<Vec<String>>>() else { continue };
        if !c["ev"].is_null() && ev.is_none() {
            continue;
        }
        let last = if c["last"].is_null() { None } else { j(&c["last"]) };
        n += 1;
        let got = check_session_revocation(ev.as_ref(), c["session"].as_str().unwrap(), authority, &ids, c["now"].as_f64().unwrap(), c["maxAge"].as_f64().unwrap(), c["scope"].as_str(), None, last.as_ref()).err();
        if !same_text(&format!("rev/{}#{i}", c["name"]), c["reason"].as_str(), got.as_deref()) {
            bad.push(format!("{}: want {} got {got:?}", c["name"], c["reason"]));
        }
    }
    assert!(n >= 80, "ran only {n}");
    report(bad, n);
}

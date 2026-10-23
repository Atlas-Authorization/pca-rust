//! Differential kill test for the 0.4.2 predicates.rs mutation survivors against the TypeScript reference
//! (packages/pca/src/predicates.ts): tests/data/k042-predjs.json is written by tools/pca-audit/java-mutate/k042-predjs-oracle.mjs
//! (the Java suite runs the same file). serde_json cannot hold a lone surrogate or a non-finite number, so a case that
//! needs one (the context members `lone`, `lone2`, `inf`, `ninf`, or a lexeme such as 1e400) is skipped and counted.
use super::*;
use crate::k042_support::{has_lone, parse, read};
use std::collections::BTreeMap;

fn tri_of(s: &str) -> Tri {
    match s {
        "true" => T,
        "false" => F,
        _ => U,
    }
}

fn golden() -> Value {
    parse(&read("k042-predjs.json")).expect("golden")
}

/// The golden context with the two non-finite members dropped (serde_json cannot hold them).
fn contexts(g: &Value) -> BTreeMap<String, Value> {
    g["ctx"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(k, v)| {
            let t = v.as_str().unwrap().replace("\"ninf\":-1e400", "\"ninf\":null").replace("\"inf\":1e400", "\"inf\":null");
            (k.clone(), parse(&t).expect("ctx"))
        })
        .collect()
}

/// Cases that read a member serde_json cannot represent.
fn unrepresentable(text: &str) -> bool {
    ["params.inf", "params.ninf", "params.lone"].iter().any(|m| text.contains(m))
}

#[test]
fn conditions_match_the_reference() {
    let g = golden();
    let ctxs = contexts(&g);
    let (mut bad, mut n, mut skipped) = (Vec::new(), 0, 0);
    for c in g["tri"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let ct = c["cond"].as_str().unwrap();
        let cond = match parse(ct) {
            Some(v) if !has_lone(&v) && !unrepresentable(ct) => v,
            _ => {
                skipped += 1;
                continue;
            }
        };
        let cx = &ctxs[c["ctx"].as_str().unwrap()];
        let want = tri_of(c["tri"].as_str().unwrap());
        let ctx = Ctx::new(cx);
        let got = evaluate_condition_tri(&cond, &ctx);
        let got_b = evaluate_condition(&cond, &ctx);
        if got != want || got_b != (want == T) {
            bad.push(format!("{name}: {ct} want {want:?} got {got:?}/{got_b}"));
        }
        n += 1;
    }
    eprintln!("conditions: {n} compared, {skipped} skipped");
    assert!(n > 400, "golden too small: {n}");
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.iter().take(30).cloned().collect::<Vec<_>>().join("\n"));
}

#[test]
fn predicates_match_the_reference() {
    let g = golden();
    let ctxs = contexts(&g);
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in g["preds"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let pt = c["preds"].as_str().unwrap();
        let preds = match parse(pt) {
            Some(v) if !has_lone(&v) => v,
            _ => continue,
        };
        let cx = &ctxs[c["ctx"].as_str().unwrap()];
        let ctx = Ctx::new(cx);
        let want = c["allowed"].as_bool().unwrap();
        let got = match &preds {
            Value::Array(a) => evaluate_predicates(a, &ctx),
            _ => false, // the typed API takes a list: a non-list is not allowed, as the reference says
        };
        if got != want {
            bad.push(format!("{name}: allowed want {want} got {got}"));
        }
        let each = c["each"].as_array().unwrap();
        if let Value::Array(ps) = &preds {
            assert_eq!(each.len(), ps.len(), "{name}");
            for (i, p) in ps.iter().enumerate() {
                let m = predicate_matches(p, &ctx);
                if Some(m) != each[i].as_bool() {
                    bad.push(format!("{name}[{i}]: want {} got {m}", each[i]));
                }
            }
        }
        n += 1;
    }
    assert!(n > 40);
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn json_equality_is_the_lenient_canonical_text_equality() {
    let g = golden();
    let (mut bad, mut n) = (Vec::new(), 0);
    for c in g["eq"].as_array().unwrap() {
        let (at, bt) = (c["a"].as_str().unwrap(), c["b"].as_str().unwrap());
        let (a, b) = match (parse(at), parse(bt)) {
            (Some(a), Some(b)) if !has_lone(&a) && !has_lone(&b) => (a, b),
            _ => continue,
        };
        let want = c["eq"].as_bool().unwrap();
        if js_canonical_eq(&a, &b) != want {
            bad.push(format!("{at} == {bt}: want {want}"));
        }
        n += 1;
    }
    assert!(n > 40);
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

fn mo(v: &str) -> Value {
    serde_json::json!({"field": "subject.id", "op": "member_of", "collection": "subject.g", "value": v})
}

fn chain_ctx(n: usize) -> Value {
    let mut g = Map::new();
    for i in 0..n {
        g.insert(format!("n{i}"), Value::String(format!("n{}", i + 1)));
    }
    serde_json::json!({"action": {"verb": "v", "resource": "r"}, "subject": {"id": "n0", "g": g}})
}

fn fan_ctx() -> Value {
    let cs: Vec<Value> = (0..100).map(|j| Value::String(format!("c{j}"))).collect();
    let mut g = Map::new();
    let mut s = Vec::new();
    for i in 0..100 {
        s.push(Value::String(format!("a{i}")));
        g.insert(format!("a{i}"), Value::Array(cs.clone()));
    }
    g.insert("s".into(), Value::Array(s));
    g.insert("c0".into(), "e".into());
    g.insert("e".into(), "t".into());
    serde_json::json!({"action": {"verb": "v", "resource": "r"}, "subject": {"id": "s", "g": g}})
}

#[test]
fn member_closure_is_capped_like_the_reference() {
    let g = golden();
    let cc = chain_ctx(10005);
    for (k, v) in g["chain"].as_object().unwrap() {
        assert_eq!(evaluate_condition_tri(&mo(k), &Ctx::new(&cc)), tri_of(v.as_str().unwrap()), "{k}");
    }
    let fc = fan_ctx();
    for (k, v) in g["fan"].as_object().unwrap() {
        assert_eq!(evaluate_condition_tri(&mo(k), &Ctx::new(&fc)), tri_of(v.as_str().unwrap()), "{k}");
    }
}

// ---- killPred: the Kotlin kill corpus (tools/pca-audit/kotlin-mutate/killPred-oracle-gen.mjs): path resolution over many
// contexts, every leaf operator over fields x operands (value and ref forms), `like` globs, `matches`, `member_of`
// closures, groupings, predicates and predicate lists. A case that carries a lone surrogate (not representable) is skipped. --

fn kill() -> (Value, Vec<bool>) {
    let d = parse(&crate::k042_support::gunzip("killPred.json.gz")).expect("killPred");
    let lone: Vec<bool> = d["ctxs"].as_array().unwrap().iter().map(has_lone).collect();
    (d, lone)
}

fn label(e: &Value) -> String {
    format!("{} @ctx{}", e[0].to_string().chars().take(160).collect::<String>(), e[1])
}

#[test]
fn kill_resolve_path() {
    crate::k042_support::on_big_stack(|| {
    let (d, lone) = kill();
    let ctxs = d["ctxs"].as_array().unwrap();
    let mut bad = Vec::new();
    for e in d["rp"].as_array().unwrap() {
        let i = e[1].as_u64().unwrap() as usize;
        if lone[i] || has_lone(&e[3]) || has_lone(&e[0]) {
            continue;
        }
        let ctx = Ctx::new(&ctxs[i]);
        // the typed API takes a string: a non-string path is never found, as the reference says
        let got = e[0].as_str().and_then(|p| ctx.resolve(p));
        let found = e[2].as_bool().unwrap();
        if got.is_some() != found || (found && got.map(|v| js_canonical_eq(v, &e[3])) != Some(true)) {
            bad.push(format!("{}: want {found} {} got {got:?}", label(e), e[3]));
        }
    }
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
    });
}

#[test]
fn kill_conditions() {
    crate::k042_support::on_big_stack(|| {
    let (d, lone) = kill();
    let ctxs = d["ctxs"].as_array().unwrap();
    let (mut bad, mut n) = (Vec::new(), 0);
    for e in d["cond"].as_array().unwrap() {
        let i = e[1].as_u64().unwrap() as usize;
        if lone[i] || has_lone(&e[0]) {
            continue;
        }
        let ctx = Ctx::new(&ctxs[i]);
        let want = tri_of(match e[2].as_str().unwrap() {
            "T" => "true",
            "F" => "false",
            _ => "unknown",
        });
        let got = evaluate_condition_tri(&e[0], &ctx);
        if got != want || evaluate_condition(&e[0], &ctx) != (want == T) {
            bad.push(format!("{}: want {want:?} got {got:?}", label(e)));
        }
        n += 1;
    }
    assert!(n > 100000, "ran {n}");
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
    });
}

#[test]
fn kill_predicates_and_lists() {
    crate::k042_support::on_big_stack(|| {
    let (d, lone) = kill();
    let ctxs = d["ctxs"].as_array().unwrap();
    let mut bad = Vec::new();
    for e in d["pred"].as_array().unwrap() {
        let i = e[1].as_u64().unwrap() as usize;
        if lone[i] || has_lone(&e[0]) {
            continue;
        }
        let got = predicate_matches(&e[0], &Ctx::new(&ctxs[i]));
        if got != e[2].as_bool().unwrap() {
            bad.push(format!("pred {}: want {} got {got}", label(e), e[2]));
        }
    }
    for e in d["preds"].as_array().unwrap() {
        let i = e[1].as_u64().unwrap() as usize;
        if lone[i] || has_lone(&e[0]) {
            continue;
        }
        let got = match &e[0] {
            Value::Array(a) => evaluate_predicates(a, &Ctx::new(&ctxs[i])),
            _ => false,
        };
        if got != e[2].as_bool().unwrap() {
            bad.push(format!("preds {}: want {} got {got}", label(e), e[2]));
        }
    }
    assert!(bad.is_empty(), "{} differ:\n{}", bad.len(), bad.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
    });
}

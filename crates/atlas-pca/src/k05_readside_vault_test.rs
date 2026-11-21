//! k05 differential oracle for read-side authorization (this file: aggregate grants and reads, the tokenisation vault and the
//! discrete Laplace sampler; the read grant, redaction, receipts and sinks are replayed by k05_readside_test.rs):
//! tests/data/k05-readside.json.gz, written by the TypeScript reference (tools/pca-audit/k05-oracles/readside-oracle.mts; the Java
//! suite replays the same file). Every result compares by JSON value with the reference's whole result; a reference throw requires
//! a refusal.
use super::*;
use crate::agent::{sign_aggregate_grant, sign_read_grant, KeyPair};
use crate::k042_support::{k05_run, K05};
use serde_json::json;

/// A flat input object: `members[i]` = `a[i]` (a missing arg is null), after `head`.
fn flat(head: (&str, &Value), members: &[&str], a: &[Value]) -> Value {
    let mut m = Map::new();
    m.insert(head.0.to_string(), head.1.clone());
    for (i, k) in members.iter().enumerate() {
        m.insert(k.to_string(), a.get(i).cloned().unwrap_or(Value::Null));
    }
    Value::Object(m)
}

static NUL: Value = Value::Null;
const REDACT: [&str; 10] = ["principal", "now", "verb", "resource", "purpose", "schema", "record", "tighten", "salt", "counts"];
const AGGREGATE: [&str; 10] = ["principal", "now", "verb", "resource", "purpose", "fn", "values", "salt", "noise", "state"];

/// `seededDraws(seed)` then `draw` `count` times (any refusal = the reference's throw).
fn draws(seed: &Value, count: usize, mut draw: impl FnMut(&mut Draws, usize) -> Result<i64, SamplerError>) -> K05 {
    let Some(seed) = seed.as_str() else { return K05::Skip("non-string seed (typed port)") };
    let mut d = seeded_draws(seed);
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        match draw(&mut d, i) {
            Ok(x) => out.push(x),
            Err(_) => return K05::Throw(None),
        }
    }
    K05::Val(json!(out))
}

#[test]
fn k05_readside_vault_matches_the_reference() {
    k05_run("readside", 3100, |_, f, a| match f {
        "validAggregateGrantBody" => K05::Val(json!(parse_agrant(&a[0]).is_some())),
        "aggregateRead" => K05::Val(aggregate_read(&flat(("grant", &a[0]), &AGGREGATE, &a[1..])).to_json()),
        "vault" => {
            let (Some(ra), Some(da), Some(field)) = (a[1].as_array(), a[3].as_array(), a[5].as_str()) else {
                return K05::Skip("non-list redact / detokenize args or non-string field (typed port)");
            };
            let store = MemoryVault::new();
            let red = redact_read_with_vault(&flat(("grant", &a[0]), &REDACT, ra), &store);
            let token = if a[4].is_null() { red.view.get(field).cloned().unwrap_or(Value::Null) } else { a[4].clone() };
            let arg = |i: usize| da.get(i).unwrap_or(&NUL);
            let det = detokenize(&a[2], arg(0), arg(1), arg(2), &token, &store);
            K05::Val(json!({"redact": red.to_json(), "detok": det.to_json()}))
        }
        "uniform" => {
            let Some(bounds) = a[1].as_array() else { return K05::Skip("non-list bounds (typed port)") };
            let Some(bounds) = bounds.iter().map(Value::as_i64).collect::<Option<Vec<i64>>>() else { return K05::Skip("non-integer bound (typed port)") };
            draws(&a[0], bounds.len(), |d, i| d.uniform(bounds[i]))
        }
        "laplace" => match (a[1].as_i64(), a[2].as_i64(), a[3].as_u64()) {
            (Some(rate), Some(scale), Some(n)) => draws(&a[0], n as usize, |d, _| d.discrete_laplace(rate, scale)),
            _ => K05::Skip("non-integer rate / scale / count (typed port)"),
        },
        "validReadGrantBody" | "redactRead" | "readChainLabels" | "checkSink" | "readGrantDigest" | "readReceiptRef" => K05::Skip("other module (k05_readside_test.rs)"),
        _ => K05::Skip("fn not in this module"),
    });
}

fn pk() -> KeyPair {
    KeyPair::from_seed(&[1u8; 32])
}
const SALT: &str = "0123456789abcdef";

#[test]
fn the_vault_records_tokens_and_nothing_else() {
    let k = pk();
    let entry = json!({"verb": "read", "resource_prefix": "r/", "purposes": ["audit"], "modes": {"fin": "hash", "pii": "token", "pub": "show"}, "default_mode": "drop"});
    let body = json!({"v": 1, "id": "g1", "principal": k.public, "issued_at": 100, "expires_at": 200, "reads": [entry], "caps": {}, "sinks": {}});
    let inp = json!({"grant": sign_read_grant(&k, &body).unwrap(), "principal": k.public, "now": 150, "verb": "read", "resource": "r/1", "purpose": "audit",
        "schema": {"fields": {"a": "pii", "b": "fin", "c": "pub"}, "required": []}, "record": {"a": "alice", "b": "bob", "c": "carol", "d": "dave"},
        "tighten": {}, "salt": SALT, "counts": {}});
    let store = MemoryVault::new();
    let r = redact_read_with_vault(&inp, &store);
    assert_eq!(r.decision, Decision::Allow);
    let view = |f: &str| r.view[f].as_str().unwrap().to_string();
    let tok = view("a");
    assert!(tok.starts_with("tok_"), "{tok}");
    let e = store.get(&tok).unwrap();
    assert_eq!((e.cls.as_str(), e.value.clone(), e.exp), ("pii", json!("alice"), 200));
    assert_eq!(store.get(&view("b")), None, "a hash is masked but is not a token");
    assert_eq!(store.get("carol"), None, "a shown value is not a token");
}

/// A draw source that yields exactly `buf` (the block stream is only reached after it).
fn scripted(buf: Vec<u64>) -> Draws {
    Draws { seed: "s".into(), block: 0, buf, pos: 0 }
}

#[test]
fn uniform_rejects_a_draw_at_the_limit_and_keeps_the_one_below() {
    // reference read-vault.ts: limit = 2^48 - (2^48 % n), accept r < limit. 2^48 % 3 = 1
    let limit = (1u64 << 48) - 1;
    assert_eq!(scripted(vec![limit, 5]).uniform(3), Ok(2));
    assert_eq!(scripted(vec![limit - 1]).uniform(3), Ok(((limit - 1) % 3) as i64));
}

#[test]
fn laplace_tail_counter_stops_only_past_the_bound() {
    // s = t = 1: u = uniform(1) = 0; bern_exp_small(0, 1) accepts on one draw. One `true` from bern_exp_small(1, 1) takes three
    // draws: uniform(1), uniform(2) = 0 (below 1/2), uniform(3) = 1 (not below 1/3, k = 3 is odd). A `false` takes two: uniform(1),
    // uniform(2) = 1 (k = 2 is even). The last draw is the sign. Reference: `++v > MAX_STEPS` with MAX_STEPS = 100000.
    let script = |trues: usize| {
        let mut b: Vec<u64> = vec![0, 0];
        for _ in 0..trues {
            b.extend([0, 0, 1]);
        }
        b.extend([0, 1, 0]);
        scripted(b)
    };
    assert_eq!(script(100_000).discrete_laplace(1, 1), Ok(100_000));
    assert_eq!(script(100_001).discrete_laplace(1, 1), Err(SamplerError));
}

fn rule_body() -> Value {
    json!({"verb": "read", "resource_prefix": "r/", "purposes": ["audit"], "fns": ["count", "sum"], "min_group": 1, "clamp": 10, "epsilon_micro": 0, "dp": false})
}
fn agrant_body() -> Value {
    json!({"v": 1, "id": "g1", "principal": pk().public, "issued_at": 100, "expires_at": 200, "rules": [rule_body()], "epsilon_budget_micro": 0, "max_queries": 5})
}

#[test]
fn aggregate_rule_limits_are_the_references_each_alone() {
    let ok = |pairs: &[(&str, Value)]| {
        let mut r = rule_body();
        for (k, v) in pairs {
            r[*k] = v.clone();
        }
        parse_rule(&r).is_some()
    };
    assert!(ok(&[]));
    assert!(!ok(&[("verb", json!(""))]));
    assert!(!ok(&[("resource_prefix", json!(""))]));
    assert!(ok(&[("fns", json!(["count"]))]));
    assert!(!ok(&[("fns", json!(["avg"]))]));
    assert!(!ok(&[("min_group", json!(0))]));
    assert!(ok(&[("min_group", json!(2))]));
    assert!(ok(&[("clamp", json!(1_000_000))]));
    assert!(!ok(&[("clamp", json!(1_000_001))]));
    assert!(ok(&[("epsilon_micro", json!(1_073_741_824))]));
    assert!(!ok(&[("epsilon_micro", json!(1_073_741_825))]));
    assert!(!ok(&[("dp", json!(true))]), "dp with epsilon 0");
    assert!(ok(&[("dp", json!(true)), ("epsilon_micro", json!(1))]));
}

#[test]
fn aggregate_grant_refuses_each_clause_alone() {
    let ok = |k: &str, v: Value| {
        let mut b = agrant_body();
        b[k] = v;
        parse_agrant(&b).is_some()
    };
    assert!(parse_agrant(&agrant_body()).is_some());
    assert!(!ok("v", json!(2)));
    assert!(!ok("id", json!("bad id")));
    assert!(!ok("principal", json!("x")));
    assert!(!ok("issued_at", json!(-1)));
    assert!(!ok("expires_at", json!(-1)));
    assert!(!ok("rules", json!([])));
    assert!(ok("rules", json!(vec![rule_body(); 16])));
    assert!(!ok("rules", json!(vec![rule_body(); 17])));
}

#[test]
fn aggregate_read_refuses_each_request_clause_alone_and_opens_at_issued_at() {
    let k = pk();
    let grant = sign_aggregate_grant(&k, &agrant_body()).unwrap();
    let state = empty_aggregate_state();
    let read = |key: &str, v: Value| {
        let mut inp = json!({"grant": grant, "principal": k.public, "now": 150, "verb": "read", "resource": "r/1", "purpose": "audit", "fn": "count",
            "values": [1, 2, 3], "salt": SALT, "noise": "seeded", "state": state});
        inp[key] = v;
        aggregate_read(&inp)
    };
    let good = read("now", json!(150));
    assert_eq!((good.decision, good.code, good.value), (Decision::Allow, None, Some(3)));
    assert_eq!(read("now", json!(100)).code, None, "valid from issued_at itself");
    assert_eq!(read("now", json!(99)).code, Some("not_yet"));
    assert_eq!(read("salt", json!("0123456789abcde")).code, Some("bad_request"), "15 characters");
    for (key, v) in [("verb", json!("")), ("resource", json!("")), ("purpose", json!("bad id")), ("fn", json!("avg")), ("noise", json!("loud"))] {
        let r = read(key, v);
        assert_eq!((r.code, &r.state), (Some("bad_request"), &state), "{key}");
    }
}

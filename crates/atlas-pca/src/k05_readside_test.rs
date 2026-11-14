//! k05 differential oracle for read-side authorization (this file: the read grant, redaction, read receipts and sinks; the vault,
//! aggregates and sampler are replayed by k05_readside_vault_test.rs): tests/data/k05-readside.json.gz, written by the TypeScript
//! reference (tools/pca-audit/k05-oracles/readside-oracle.mts; the Java suite replays the same file). Every result compares by
//! JSON value with the reference's whole result (decision, code, view, every field digest, labels, counts); a reference throw
//! requires a refusal.
use super::*;
use crate::agent::{sign_artifact, KeyPair, Suite};
use crate::k042_support::{k05_run, K05};
use serde_json::json;

/// The flat `redactRead` input from the oracle's positional args (grant, then the ten members in this order).
fn redact_input(grant: &Value, a: &[Value]) -> Value {
    let mut m = Map::new();
    m.insert("grant".into(), grant.clone());
    for (i, k) in ["principal", "now", "verb", "resource", "purpose", "schema", "record", "tighten", "salt", "counts"].iter().enumerate() {
        m.insert((*k).into(), a.get(i).cloned().unwrap_or(Value::Null));
    }
    Value::Object(m)
}

fn digest(d: Option<String>) -> K05 {
    d.map_or(K05::Throw(None), |d| K05::Val(json!(d)))
}

#[test]
fn k05_readside_matches_the_reference() {
    k05_run("readside", 6800, |_, f, a| match f {
        "validReadGrantBody" => K05::Val(json!(parse_grant(&a[0]).is_some())),
        "redactRead" => K05::Val(redact_read(&redact_input(&a[0], &a[1..])).to_json()),
        "readChainLabels" => match (a[1].as_str(), a[2].as_str(), a[3].as_i64()) {
            (Some(signer), Some(gd), Some(now)) => K05::Val(match read_chain_labels(&a[0], signer, gd, now) {
                Ok(labels) => json!({"labels": labels}),
                Err((code, at)) => json!({"code": code, "at": at}),
            }),
            _ => K05::Skip("non-string signer / digest or non-integer clock (typed port)"),
        },
        "checkSink" => K05::Val(check_sink(&a[0], &a[1], &a[2], &a[3], &a[4], &a[5]).to_json()),
        "readGrantDigest" => digest(read_grant_digest(&a[0])),
        "readReceiptRef" => digest(read_receipt_ref(&a[0])),
        "validAggregateGrantBody" | "aggregateRead" | "vault" | "uniform" | "laplace" => K05::Skip("other module (k05_readside_vault_test.rs)"),
        _ => K05::Skip("fn not in this module"),
    });
}

fn pk(seed: u8) -> KeyPair {
    KeyPair::from_seed(&[seed; 32])
}
fn grant_body() -> Value {
    let entry = json!({"verb": "read", "resource_prefix": "r/", "purposes": ["audit"], "modes": {"pii": "hash"}, "default_mode": "drop"});
    json!({"v": 1, "id": "g1", "principal": pk(1).public, "issued_at": 100, "expires_at": 200, "reads": [entry], "caps": {}, "sinks": {}})
}
fn grant_with(k: &str, v: Value) -> bool {
    let mut b = grant_body();
    b[k] = v;
    parse_grant(&b).is_some()
}
fn entry_modes(modes: Value) -> bool {
    let mut b = grant_body();
    b["reads"][0]["modes"] = modes;
    parse_grant(&b).is_some()
}

#[test]
fn mode_strings_are_the_reference_regex() {
    // ^(show|last4|hash|token|drop|bucket:[1-9][0-9]{0,8})$
    for ok in ["show", "last4", "hash", "token", "drop", "bucket:1", "bucket:10", "bucket:999999999"] {
        assert!(is_mode_str(ok), "{ok}");
    }
    for bad in ["bucket:", "bucket:0", "bucket:01", "bucket:1a", "bucket:a1", "bucket:1234567890", "bucket", "Show", ""] {
        assert!(!is_mode_str(bad), "{bad}");
    }
}

#[test]
fn mode_ranks_are_the_reference_table() {
    for (mode, want) in [("show", 0), ("last4", 1), ("bucket:7", 2), ("token", 3), ("hash", 4), ("drop", 5)] {
        assert_eq!(rank(mode), want, "{mode}");
    }
}

#[test]
fn read_grant_refuses_each_clause_alone() {
    assert!(parse_grant(&grant_body()).is_some());
    assert!(!grant_with("v", json!(2)));
    assert!(!grant_with("id", json!("bad id")));
    assert!(!grant_with("principal", json!("x")));
    assert!(!grant_with("issued_at", json!(-1)));
    assert!(!grant_with("expires_at", json!(-1)));
    let e = grant_body()["reads"][0].clone();
    assert!(!grant_with("reads", json!([])));
    assert!(grant_with("reads", json!(vec![e.clone(); 32])));
    assert!(!grant_with("reads", json!(vec![e; 33])));
    assert!(entry_modes(json!({"pii": "show"})));
    assert!(!entry_modes(json!({"PII": "show"})));
    assert!(!entry_modes(json!({"pii": "reveal"})));
}

fn receipt_body(rs: &KeyPair, gd: &str, seq: i64, prev: Value, issued_at: i64) -> Value {
    json!({"v": 1, "grant": gd, "verb": "read", "resource": "r/1", "purpose": "audit", "seq": seq, "prev": prev,
        "fields": {"a": {"class": "pii", "action": "shown", "kind": null, "vd": gd}}, "labels": ["pii"], "issued_at": issued_at, "signer": rs.public})
}
fn signed_receipt(rs: &KeyPair, gd: &str, seq: i64, prev: Value, issued_at: i64) -> Value {
    sign_artifact(READ_RECEIPT_DOMAIN, &receipt_body(rs, gd, seq, prev, issued_at), rs, &Suite::default()).unwrap()
}

#[test]
fn read_receipt_shape_refuses_each_field_clause_alone() {
    let (rs, gd) = (pk(2), pk(3).public);
    let parses = |f: Value| {
        let mut r = receipt_body(&rs, &gd, 0, Value::Null, 100);
        r["sig"] = json!("x");
        r["fields"] = f;
        parse_read_receipt(&r).is_some()
    };
    let field = |class: &str, kind: Value, vd: &str| json!({"class": class, "action": "masked", "kind": kind, "vd": vd});
    assert!(parses(json!({"a": field("pii", json!("hash"), &gd)})));
    assert!(parses(json!({"a": field("pii", Value::Null, &gd)})));
    assert!(parses(json!({"a": field("unclassified", Value::Null, &gd)})));
    assert!(!parses(json!({"a": field("PII", Value::Null, &gd)})));
    assert!(!parses(json!({"a b": field("pii", Value::Null, &gd)})));
    assert!(!parses(json!({"a": field("pii", json!(5), &gd)})));
    assert!(!parses(json!({"a": field("pii", Value::Null, "x")})));
}

#[test]
fn read_chain_accepts_issued_now_and_refuses_each_link_clause_alone() {
    let (rs, gd) = (pk(2), pk(3).public);
    let r0 = signed_receipt(&rs, &gd, 0, Value::Null, 100);
    let labels = || vec!["pii".to_string()];
    assert_eq!(read_chain_labels(&json!([r0]), &rs.public, &gd, 100), Ok(labels()));
    assert_eq!(read_chain_labels(&json!([r0]), &rs.public, &gd, 99), Err(("bad_receipt", 0)));
    let good = read_receipt_ref(&r0).unwrap();
    let r1 = signed_receipt(&rs, &gd, 1, json!(good), 100);
    assert_eq!(read_chain_labels(&json!([r0, r1]), &rs.public, &gd, 100), Ok(labels()));
    // only the previous reference is wrong: the receipt is correctly signed
    let wrong_prev = signed_receipt(&rs, &gd, 1, json!(pk(4).public), 100);
    assert_eq!(read_chain_labels(&json!([r0, wrong_prev]), &rs.public, &gd, 100), Err(("bad_receipt", 1)));
    // only the signature is wrong: a well-formed signature over another receipt
    let mut forged = r0.clone();
    forged["sig"] = signed_receipt(&rs, &gd, 0, Value::Null, 99)["sig"].clone();
    assert_eq!(read_chain_labels(&json!([forged]), &rs.public, &gd, 100), Err(("bad_receipt", 0)));
}

#[test]
fn read_receipt_shape_refuses_each_top_level_clause_alone() {
    let (rs, gd) = (pk(2), pk(3).public);
    let first = {
        let mut r = receipt_body(&rs, &gd, 0, Value::Null, 100);
        r["sig"] = json!("x");
        r
    };
    let later = {
        let mut r = first.clone();
        r["seq"] = json!(1);
        r["prev"] = json!(gd);
        r
    };
    assert!(parse_read_receipt(&first).is_some());
    assert!(parse_read_receipt(&later).is_some());
    let cases = [
        (&first, "v", json!(2)),
        (&first, "grant", json!("x")),
        (&first, "verb", json!("")),
        (&first, "verb", json!("v".repeat(129))),
        (&first, "resource", json!("")),
        (&first, "resource", json!("r".repeat(513))),
        (&first, "purpose", json!("a b")),
        (&first, "prev", json!(gd)), // seq 0 must not name a previous receipt
        (&later, "prev", Value::Null), // a later one must
        (&later, "prev", json!("x")),
        (&first, "issued_at", json!(-1)),
        (&first, "signer", json!("x")),
        (&first, "sig", json!(5)),
    ];
    for (base, k, x) in cases {
        let mut r = base.clone();
        r[k] = x.clone();
        assert!(parse_read_receipt(&r).is_none(), "{k} {x}");
    }
}

#[test]
fn mask_last4_is_bmp_only_and_a_zero_bucket_drops() {
    // readside.ts BMP: every code point < 0x10000; MODE_RE keeps bucket:0 out of a grant, the Rust port stays total on it
    assert_eq!(mask("last4", &json!("\u{FFFF}abcd"), "c", "s"), Ok(Some(json!("****abcd"))));
    assert_eq!(mask("last4", &json!("\u{10000}abcd"), "c", "s"), Ok(None));
    assert_eq!(mask("bucket:0", &json!(5), "c", "s"), Ok(None));
    assert_eq!(mask("bucket:10", &json!(25), "c", "s"), Ok(Some(json!(20))));
}

fn signed_grant(body: &Value) -> Value {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let sig = pk(1).sign(&crate::fresh_at::domain_bytes(READ_GRANT_DOMAIN, body).unwrap());
    json!({"body": body, "sig": URL_SAFE_NO_PAD.encode(sig)})
}

/// A valid redact input (allowed: the grant runs 100..200, `a` is class pii) with `patch` applied.
fn redact_in(patch: Value) -> Value {
    let mut inp = json!({"grant": signed_grant(&grant_body()), "principal": pk(1).public, "now": 150, "verb": "read", "resource": "r/1", "purpose": "audit",
        "schema": {"fields": {"a": "pii"}, "required": []}, "record": {"a": "v"}, "tighten": {}, "salt": "s".repeat(16), "counts": {}});
    for (k, x) in patch.as_object().unwrap() {
        inp[k.as_str()] = x.clone();
    }
    inp
}

#[test]
fn redact_runs_from_issue_time_and_refuses_each_request_clause_alone() {
    let run = |patch: Value| redact_read(&redact_in(patch));
    assert_eq!(run(json!({})).decision, Decision::Allow);
    assert_eq!(run(json!({"now": 100})).decision, Decision::Allow);
    assert_eq!(run(json!({"now": 99})).code, Some("not_yet"));
    assert_eq!(run(json!({"salt": "s".repeat(16)})).decision, Decision::Allow);
    assert_eq!(run(json!({"schema": {"fields": {"a": "pii"}, "required": ["a"]}})).decision, Decision::Allow);
    for patch in [
        json!({"verb": ""}),
        json!({"verb": "v".repeat(129)}),
        json!({"resource": ""}),
        json!({"resource": "r".repeat(513)}),
        json!({"purpose": "a b"}),
        json!({"salt": "s".repeat(15)}),
        json!({"schema": {"fields": {"a b": "pii"}, "required": []}}),
        json!({"schema": {"fields": {"a": "PII"}, "required": []}}),
        json!({"schema": {"fields": {"a": "pii"}, "required": ["z"]}}),
    ] {
        assert_eq!(run(patch.clone()).code, Some("bad_request"), "{patch}");
    }
}

#[test]
fn a_tighten_of_equal_rank_does_not_replace_the_granted_mode() {
    // readside.ts: rank(t) > rank(mode); every bucket has rank 2, so bucket:7 leaves bucket:10 in place
    let mut body = grant_body();
    body["reads"][0]["modes"] = json!({"pii": "bucket:10"});
    let r = redact_read(&redact_in(json!({"grant": signed_grant(&body), "record": {"a": 25}, "tighten": {"pii": "bucket:7"}})));
    assert_eq!(r.decision, Decision::Allow);
    assert_eq!(r.view["a"], json!(20));
}

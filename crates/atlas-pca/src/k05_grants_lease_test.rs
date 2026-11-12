//! k05 differential oracle for leases: tests/data/k05-grants.json.gz, written by the TypeScript reference
//! (tools/pca-audit/k05-oracles/grants-oracle.mts; the Java, Kotlin, Python, Go, ... suites replay the same file): record shapes
//! (unsigned and re-signed), separation of duties, and registry walks replayed step by step on a fresh registry. The break-glass
//! fns of the same corpus are replayed by break_glass.rs's k05 test.
use super::*;
use crate::k042_support::{k05_run, K05};
use serde_json::json;

fn strs(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

/// `{authorities, minApprovals?, eligibleApprovers?, freshJustification?}`
fn policy(p: &Value) -> LeasePolicy {
    let mut out = LeasePolicy::new(strs(p.get("authorities")));
    out.min_approvals = p.get("minApprovals").and_then(Value::as_i64);
    out.eligible = p.get("eligibleApprovers").filter(|e| e.is_array()).map(|e| strs(Some(e)));
    if let Some(f) = p.get("freshJustification").and_then(Value::as_bool) {
        out.fresh_justification = f;
    }
    out
}

fn lease_walk(pol: &Value, steps: &Value) -> Value {
    let reg = LeaseRegistry::new(policy(pol), std::sync::Arc::new(crate::kv::MemoryAtomicKv::new()));
    let mut out = Vec::new();
    for s in steps.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        out.push(match s["op"].as_str().unwrap_or("") {
            "accept" => match reg.accept(&s["rec"], &strs(s.get("chain"))) {
                Ok((replaced, seq)) => json!({"ok": true, "replaced": replaced, "seq": seq}),
                Err(code) => json!({"ok": false, "code": code}),
            },
            "revoke" => match reg.revoke(&s["rec"]) {
                Ok(n) => json!({"ok": true, "revoked": n}),
                Err(code) => json!({"ok": false, "code": code}),
            },
            _ => {
                let d = check_lease(&s["rec"], &reg, &s["now"]);
                json!({"decision": d.decision, "code": d.code, "lease_id": d.lease_id, "expires_at": d.expires_at})
            }
        });
    }
    Value::Array(out)
}

#[test]
fn k05_grants_lease_matches_the_reference() {
    // 3268 lease cases (verifyLease, verifyLeaseRevocation, sodError, leaseWalk), ~57 skipped for lone surrogates
    k05_run("grants", 2900, |_, f, a| match f {
        "verifyLease" => K05::Val(json!(verify_lease(&a[0]))),
        "verifyLeaseRevocation" => K05::Val(json!(verify_lease_revocation(&a[0]))),
        "sodError" => K05::Val(json!(sod_error(&a[0], &policy(&a[1]), &strs(Some(&a[2]))))),
        "leaseWalk" => K05::Val(lease_walk(&a[0], &a[1])),
        _ => K05::Skip("other module (break_glass.rs)"),
    });
}

// ---- separation of duties and renewal, under valid signatures; every code and order per packages/pca-grants/src/lease.ts ----

use crate::agent::KeyPair;

fn signed_with(k: &KeyPair, domain: &str, mut body: Value) -> Value {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let sig = k.sign(&crate::fresh_at::domain_bytes(domain, &body).unwrap());
    body["sig"] = json!(URL_SAFE_NO_PAD.encode(sig));
    body
}

/// A valid first record (seq 1, window 1000..2000, ttl cap 10000) with `patch` applied before signing.
fn rec(k: &KeyPair, patch: Value) -> Value {
    let mut body = json!({"v": 1, "lease_id": "l1", "path": "a/b", "grant_ref": "g", "holder": "h", "requester": "q", "approvers": ["ap"], "justification_digest": "j1", "seq": 1, "issued_at": 1000, "renewed_at": 1000, "expires_at": 2000, "max_ttl": 10000, "authority": k.public});
    for (key, x) in patch.as_object().unwrap() {
        body[key.as_str()] = x.clone();
    }
    signed_with(k, LEASE_DOMAIN, body)
}

fn revocation(k: &KeyPair, value: &str) -> Value {
    signed_with(k, LEASE_REVOKE_DOMAIN, json!({"v": 1, "target": "lease", "value": value, "revoked_at": 5000, "authority": k.public}))
}

#[test]
fn min_approvals_must_be_a_safe_positive_integer() {
    let l = json!({"requester": "q", "holder": "h", "approvers": []});
    let sod = |k: i64| {
        let mut p = LeasePolicy::new(vec![]);
        p.min_approvals = Some(k);
        sod_error(&l, &p, &[])
    };
    const BAD: &str = "minApprovals must be a positive integer";
    for k in [-1, 0, 1i64 << 53, (1i64 << 53) + 1] {
        assert_eq!(sod(k).as_deref(), Some(BAD), "{k}");
    }
    assert_eq!(sod(1).as_deref(), Some("0 approver(s), need 1"));
    assert_eq!(sod((1i64 << 53) - 1).as_deref(), Some("0 approver(s), need 9007199254740991"));
}

#[test]
fn a_renewal_may_not_change_any_pinned_member_alone() {
    let (k, other) = (KeyPair::from_seed(&[1u8; 32]), KeyPair::from_seed(&[2u8; 32]));
    let reg = LeaseRegistry::new(LeasePolicy::new(vec![k.public.clone(), other.public.clone()]), std::sync::Arc::new(crate::kv::MemoryAtomicKv::new()));
    assert_eq!(reg.accept(&rec(&k, json!({})), &[]), Ok((true, 1)));
    let renew = || json!({"seq": 2, "renewed_at": 1500, "expires_at": 3000, "justification_digest": "j2"});
    let with = |key: &str, x: Value| {
        let mut p = renew();
        p[key] = x;
        p
    };
    for patch in [with("path", json!("a/c")), with("grant_ref", json!("g2")), with("holder", json!("h2")), with("requester", json!("q2")), with("max_ttl", json!(20000)), with("issued_at", json!(1001))] {
        assert_eq!(reg.accept(&rec(&k, patch.clone()), &[]), Err("renewal_mismatch"), "{patch}");
    }
    assert_eq!(reg.accept(&rec(&other, renew()), &[]), Err("renewal_mismatch"));
    assert_eq!(reg.accept(&rec(&k, renew()), &[]), Ok((true, 2)));
}

#[test]
fn a_renewal_keeps_or_advances_renewed_at_and_extends_expiry() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let reg = LeaseRegistry::new(LeasePolicy::new(vec![k.public.clone()]), std::sync::Arc::new(crate::kv::MemoryAtomicKv::new()));
    assert_eq!(reg.accept(&rec(&k, json!({})), &[]), Ok((true, 1)));
    assert_eq!(reg.accept(&rec(&k, json!({"seq": 2, "renewed_at": 1500, "expires_at": 3000, "justification_digest": "j2"})), &[]), Ok((true, 2)));
    let third = |renewed: i64, expires: i64| rec(&k, json!({"seq": 3, "renewed_at": renewed, "expires_at": expires, "justification_digest": "j3"}));
    assert_eq!(reg.accept(&third(1499, 4000), &[]), Err("not_extending"));
    assert_eq!(reg.accept(&third(1500, 3000), &[]), Err("not_extending"));
    assert_eq!(reg.accept(&third(1500, 4000), &[]), Ok((true, 3)));
}

fn total_revocations(reg: &LeaseRegistry) -> usize {
    (0..reg.shard_count()).map(|i| reg.shard_revocations(i).unwrap().len()).sum()
}

#[test]
fn revocations_are_deduplicated_by_signature_and_each_distinct_one_holds() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let reg = LeaseRegistry::new(LeasePolicy::new(vec![k.public.clone()]), std::sync::Arc::new(crate::kv::MemoryAtomicKv::new()));
    let (r1, r2) = (revocation(&k, "l1"), revocation(&k, "l2"));
    assert_eq!(reg.revoke(&r1), Ok(0));
    assert_eq!(reg.revoke(&r1), Ok(0));
    assert_eq!(total_revocations(&reg), 1);
    assert_eq!(reg.revoke(&r2), Ok(0));
    assert_eq!(total_revocations(&reg), 2);
    assert_eq!(reg.accept(&rec(&k, json!({})), &[]), Err("revoked"));
    assert_eq!(reg.accept(&rec(&k, json!({"lease_id": "l2"})), &[]), Err("revoked"));
}

// ---- record and revocation shapes: each clause alone, every other member valid (lease.ts wellFormed, revWellFormed, PATH_RE) ----

#[test]
fn path_is_one_to_eight_segments_of_one_to_64_allowed_bytes() {
    let eight = vec!["a"; 8].join("/");
    let nine = vec!["a"; 9].join("/");
    let (seg64, seg65) = ("a".repeat(64), "a".repeat(65));
    for p in ["a", "z9_.-", "0", eight.as_str(), seg64.as_str()] {
        assert!(path_ok(p), "{p}");
    }
    for p in ["", "A", "a/", "/a", "a//b", "a b", "\u{e9}", nine.as_str(), seg65.as_str()] {
        assert!(!path_ok(p), "{p}");
    }
}

#[test]
fn lease_shape_refuses_each_clause_alone() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let sixteen: Vec<String> = (0..16).map(|i| format!("a{i}")).collect();
    let seventeen: Vec<String> = (0..17).map(|i| format!("a{i}")).collect();
    for patch in [json!({}), json!({"approvers": []}), json!({"approvers": sixteen}), json!({"max_ttl": 1}), json!({"seq": 2, "renewed_at": 1000}), json!({"seq": 2, "renewed_at": 1500}), json!({"lease_id": "l".repeat(128), "grant_ref": "g".repeat(256), "holder": "h".repeat(128), "requester": "q".repeat(128), "justification_digest": "j".repeat(128)})] {
        let r = rec(&k, patch.clone());
        assert!(well_formed(&r), "{patch}");
        assert!(verify_lease(&r), "{patch}");
    }
    assert!(!well_formed(&json!("x")));
    for patch in [
        json!({"v": 2}),
        json!({"lease_id": ""}),
        json!({"lease_id": "l".repeat(129)}),
        json!({"grant_ref": ""}),
        json!({"grant_ref": "g".repeat(257)}),
        json!({"holder": ""}),
        json!({"holder": "h".repeat(129)}),
        json!({"requester": ""}),
        json!({"requester": "q".repeat(129)}),
        json!({"authority": ""}),
        json!({"authority": "a".repeat(129)}),
        json!({"justification_digest": ""}),
        json!({"justification_digest": "j".repeat(129)}),
        json!({"path": "A"}),
        json!({"path": 1}),
        json!({"seq": 0}),
        json!({"seq": -1}),
        json!({"max_ttl": 0}),
        json!({"seq": 2, "renewed_at": 999}),
        json!({"expires_at": 1000}),
        json!({"expires_at": 999}),
        json!({"seq": 1, "renewed_at": 1001, "expires_at": 2000}),
        json!({"approvers": seventeen}),
        json!({"approvers": ["ok", ""]}),
        json!({"approvers": ["a".repeat(129)]}),
        json!({"approvers": "ap"}),
    ] {
        let r = rec(&k, patch.clone());
        // well_formed itself: the authority clause would otherwise be hidden by the signature check that follows it
        assert!(!well_formed(&r), "{patch}");
        assert!(!verify_lease(&r), "{patch}");
    }
}

#[test]
fn revocation_shape_refuses_each_clause_alone() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let rv = |patch: Value| {
        let mut body = json!({"v": 1, "target": "lease", "value": "l1", "revoked_at": 5000, "authority": k.public});
        for (key, x) in patch.as_object().unwrap() {
            body[key.as_str()] = x.clone();
        }
        signed_with(&k, LEASE_REVOKE_DOMAIN, body)
    };
    for patch in [json!({}), json!({"target": "grant", "value": "G!"}), json!({"target": "prefix", "value": "a/b"}), json!({"value": "v".repeat(256)}), json!({"revoked_at": 0})] {
        let r = rv(patch.clone());
        assert!(rev_well_formed(&r), "{patch}");
        assert!(verify_lease_revocation(&r), "{patch}");
    }
    assert!(!rev_well_formed(&json!("x")));
    for patch in [
        json!({"v": 2}),
        json!({"value": ""}),
        json!({"value": "v".repeat(257)}),
        json!({"authority": ""}),
        json!({"authority": "a".repeat(129)}),
        json!({"revoked_at": -1}),
        json!({"revoked_at": "5000"}),
        json!({"target": "other"}),
        json!({"target": "prefix", "value": "A"}),
    ] {
        let r = rv(patch.clone());
        assert!(!rev_well_formed(&r), "{patch}");
        assert!(!verify_lease_revocation(&r), "{patch}");
    }
}

#[test]
fn a_revocation_covers_a_lease_issued_at_or_before_it() {
    let k = KeyPair::from_seed(&[1u8; 32]);
    let at = |t: i64| signed_with(&k, LEASE_REVOKE_DOMAIN, json!({"v": 1, "target": "lease", "value": "l1", "revoked_at": t, "authority": k.public}));
    let l = rec(&k, json!({}));
    assert!(covers(&at(1000), &l));
    assert!(covers(&at(1001), &l));
    assert!(!covers(&at(999), &l));
}

//! base differential oracle for the prohibition engine: tests/data/base-prohibitions.json.gz, written by the TypeScript reference
//! (every native replays the same file): constitution and state validation, the canonical state and its digest, the monitor, the
//! strict advance, safety evidence (plain and signed), the atomic check-and-advance, the constitution id and its signature check.
use super::*;
use crate::k042_support::{base_run_seeded, Base};
use serde_json::json;

/// `{ok: true, state}` or `{ok: false, reason}`.
fn stepped(r: Result<Value, String>) -> Base {
    Base::Val(match r {
        Ok(state) => json!({"ok": true, "state": state}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    })
}

/// `{ok: true}` (verified) or `{ok: false, reason}`.
fn verdict(r: Result<(), String>) -> Base {
    Base::Val(match r {
        Ok(()) => json!({"ok": true}),
        Err(reason) => json!({"ok": false, "reason": reason}),
    })
}

/// An optional clock argument: absent is the default, a present value that is not a number is a clock regression (NaN).
fn clock(v: Option<&Value>) -> Option<f64> {
    v.map(|n| fin(Some(n)).unwrap_or(f64::NAN))
}

fn digest(d: Option<String>) -> Base {
    d.map_or(Base::Throw(None), |d| Base::Val(json!(d)))
}

#[test]
fn base_prohibitions_matches_the_reference() {
    base_run_seeded("prohibitions", 21_300, |_, f, a| match f {
        "validateInvariant" => Base::Val(json!(validate_invariant(&a[0]))),
        "validateConstitution" => Base::Val(json!(validate_constitution(&a[0]))),
        "stateProblem" => Base::Val(json!(state_problem(&a[0]))),
        "canonicalState" => canonical_state(&a[0]).map_or(Base::Throw(None), Base::Val),
        "stateDigest" => digest(state_digest(&a[0])),
        "tickState" => stepped(tick_state(&a[0], fin(a.get(1)).unwrap_or(f64::NAN))),
        "emptyState" => match fin(a.first()) {
            Some(now) => Base::Val(empty_state(now)),
            None => Base::Skip("a clock that is not a number (typed port)"),
        },
        "checkProhibitions" => Base::Val(check_prohibitions(&a[0], &a[1], &a[2]).to_json()),
        "advanceStateStrict" => stepped(advance_state_strict(&a[0], &a[1], &a[2], clock(a.get(3)))),
        "proveSafety" => Base::Val(prove_safety(&a[0], &a[1], &a[2])),
        "verifySafetyEvidence" => verdict(verify_safety_evidence(&a[0], &a[1], &a[2], &a[3])),
        "safetyBindingId" => match a[1].as_str() {
            Some(signer) => digest(safety_binding_id(&a[0], signer)),
            None => Base::Skip("a signer that is not a string (typed port)"),
        },
        "signSafetyEvidence" => match a[1].as_str().map(crate::agent::KeyPair::from_seed_b64u) {
            // the port signs under the key pair's own public key: a case naming another signer is not expressible
            Some(Ok(k)) if a[2].as_str() == Some(k.public.as_str()) => {
                crate::signers_more::sign_safety_evidence(&k, &a[0]).map_or(Base::Throw(None), Base::Val)
            }
            Some(Ok(_)) => Base::Skip("a signer public key other than the key pair's (typed port)"),
            _ => Base::Throw(None),
        },
        "verifySignedSafetyEvidence" => verdict(verify_signed_safety_evidence(&a[0], &a[1])),
        "checkAndAdvance" => {
            let opts = a.get(4);
            let seq = opts.and_then(|o| o.get("expectedSeq")).map(|s| fin(Some(s)).unwrap_or(f64::NAN));
            let head = opts.and_then(|o| o.get("expectedStateDigest"));
            if head.is_some_and(|h| !h.is_string()) {
                return Base::Skip("an expected digest that is not a string (typed port)");
            }
            let r = check_and_advance(a[0] == true, &a[1], &a[2], &a[3], seq, head.and_then(Value::as_str));
            let mut o = json!({"allow": r.allow, "decidedBy": r.decided_by, "evidence": r.evidence, "prohibition": r.prohibition.to_json(), "next": r.next});
            if let Some(why) = r.reason {
                o["reason"] = json!(why);
            }
            Base::Val(o)
        }
        "constitutionId" => digest(constitution_id(&a[0])),
        "verifyConstitution" => verdict(verify_constitution(&a[0], a.get(1).and_then(Value::as_str))),
        "whenAffirmative" => Base::Val(json!(when_affirmative(&a[0], &a[1]))),
        other => panic!("unhandled corpus function {other}"),
    });
}

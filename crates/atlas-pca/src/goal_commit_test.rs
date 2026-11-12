//! Goal binding v3 (`approved_goal`): replays goal-commit-vectors.json (`commit`, `invalid`, `binding`) against the real
//! functions and the intent check. A missing vector file fails the test.
use super::*;
use serde_json::json;

fn doc() -> Value {
    let p = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/goal-commit-vectors.json");
    serde_json::from_str(&std::fs::read_to_string(p).expect("goal-commit-vectors.json must exist")).expect("json")
}

fn gref(g: &str, p: &str) -> ApprovedGoalRef {
    ApprovedGoalRef { goal_digest: g.into(), policy_digest: p.into() }
}

#[test]
fn v3_commit_vectors() {
    let d = doc();
    let rows = d["commit"].as_array().unwrap();
    assert_eq!(rows.len(), 7);
    for v in rows {
        let r = gref(v["goal_digest"].as_str().unwrap(), v["policy_digest"].as_str().unwrap());
        let n = v["name"].as_str().unwrap();
        assert_eq!(intent_goal_v3(&r).as_deref(), v["goal"].as_str(), "{n}");
        assert_eq!(intent_goal_commit_v3(&r, v["salt"].as_str().unwrap()).as_deref(), v["commit"].as_str(), "{n}");
    }
}

#[test]
fn v3_invalid_digests_are_refused() {
    let d = doc();
    let rows = d["invalid"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for v in rows {
        let r = gref(v["goal_digest"].as_str().unwrap(), v["policy_digest"].as_str().unwrap());
        let n = v["name"].as_str().unwrap();
        assert!(!r.is_valid(), "{n}");
        assert_eq!(intent_goal_v3(&r), None, "{n}");
        assert_eq!(intent_goal_commit_v3(&r, "s"), None, "{n}");
    }
}

#[test]
fn v3_binding_vectors() {
    let d = doc();
    let rows = d["binding"].as_array().unwrap();
    assert_eq!(rows.len(), 16);
    for v in rows {
        let n = v["name"].as_str().unwrap();
        let grant = match v["grant_commit"].as_str() {
            Some(c) => json!({"caveats": [{"type": "envelope", "goal_commit": c}]}),
            None => json!({"caveats": []}),
        };
        let intent = (!v["intent"].is_null()).then(|| v["intent"].clone());
        let pol = IntentPolicy::from_json(&v["policy"]).unwrap();
        let session = v["session"].as_str().map(|s| (s, false));
        let got = decide_intent(intent.as_ref(), &grant, Some(&pol), session).expect(n);
        match v["expect"].as_str().unwrap() {
            "pass" => assert_eq!(got, Ok(()), "{n}"),
            _ => assert!(got.is_err(), "{n}"),
        }
    }
}

#[test]
fn from_json_keeps_a_malformed_approved_goal_failing_closed() {
    let a = "B5JcJLcCoUyZ2P4kdlU8dI9ukFkzuspDbELVR295azw";
    for bad in [json!({"goal_digest": a}), json!({"goal_digest": a, "policy_digest": a, "extra": 1}), json!("x"), json!(null), json!({"goal_digest": 1, "policy_digest": a})] {
        let pol = IntentPolicy::from_json(&json!({"approved_goal": bad})).unwrap();
        assert!(pol.is_active());
        let grant = json!({"caveats": [{"type": "envelope", "goal_commit": "x"}]});
        let e = decide_intent(None, &grant, Some(&pol), None).unwrap().unwrap_err();
        assert!(e.contains("approved_goal digests must be canonical"), "{e}");
    }
}

//! Action-kit conformance: every vector of the shared action vector directory must reproduce its `expect` exactly through
//! `atlas_pca::actions` (and the v2 conform path of `conform_action`). No skips, no vector left unread.
mod common;
use atlas_pca::actions::*;
use atlas_pca::actions_registry::*;
use atlas_pca::{
    action_schema_shape_error_unsigned, approval_batch, approval_challenge, approval_render_digest, approval_render_shape_error, binding_words, conform_action, psd2_linking, render_approval,
    verify_escalation_answer, EscalationBinding, EscalationVerdict, PinnedSigner,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn vector_dir() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for rel in ["../../packages/pca-conformance/vectors/actions", "../../conformance/actions", "conformance/actions"] {
        let d = root.join(rel);
        if d.is_dir() {
            return d;
        }
    }
    panic!("the action-kit vectors are missing (a vector directory is never skipped)");
}

fn cases() -> Vec<Value> {
    let mut files: Vec<_> = std::fs::read_dir(vector_dir()).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    files.sort();
    files
        .iter()
        .map(|f| serde_json::from_str(&common::sanitize_lone_surrogates(&std::fs::read_to_string(f).unwrap())).unwrap_or_else(|e| panic!("{f:?}: {e}")))
        .collect()
}

fn code_of(e: Option<String>) -> Value {
    match e {
        None => json!({"ok": true}),
        Some(e) => json!({"ok": false, "code": e.split(':').next().unwrap().split(' ').next().unwrap()}),
    }
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

fn replay(c: &Value) -> Value {
    let i = &c["input"];
    match c["kind"].as_str().unwrap() {
        "parse" => json!({"ok": validate_def(&i["def"]).is_none()}),
        "digest" => json!({"digest": def_digest(&i["def"]).unwrap(), "normalized": normalize(&i["def"])}),
        "effective" => {
            let e = effective(&i["def"], &core_registry(), i.get("pins")).unwrap();
            json!({"confirmed": e.confirmed, "traits": e.traits, "closure": e.closure, "eff": e.eff.to_value()})
        }
        k @ ("expand" | "schema_verb") => {
            let reg = match i.get("custom_traits").and_then(Value::as_array) {
                Some(t) if !t.is_empty() => extend_registry(&core_registry(), t),
                _ => Ok(core_registry()),
            };
            let reg = match reg {
                Ok(r) => r,
                Err(_) => return json!({"error": true}),
            };
            if k == "schema_verb" {
                return code_of(schema_verb_floor_error(&i["verb"], &reg, i.get("pins")));
            }
            let ids = strs(&i["traits"]);
            match (closure(&reg, &ids), floor_of(&reg, &ids)) {
                (Ok(cl), Ok(f)) => json!({"closure": cl, "floor": f.to_value()}),
                _ => json!({"error": true}),
            }
        }
        "floor" => {
            let g = GrantFacts { caveats: strs(&i["grant"]["caveats"]), max_esc: i["grant"]["max_esc"].as_i64().unwrap(), preauth_esc: i["grant"]["preauth_esc"].as_i64().unwrap() };
            json!({"decision": floor_decision(&g, &strs(&i["call"]["context"]), &Profile::from_value(&i["profile"]).unwrap())})
        }
        "conform" => {
            let r = conform_action(&i["schema"], i["verb"].as_str().unwrap(), &i["params"]);
            if r.ok { json!({"ok": true}) } else { json!({"ok": false, "code": r.code}) }
        }
        "pack" => {
            let ds = strs(&i["digests"]);
            let d = &ds[i["index"].as_u64().unwrap() as usize];
            json!({"root": pack_root(&ds).unwrap(), "proof": pack_proof(&ds, d).unwrap()})
        }
        "rule22_schema" => match rule22_integrity(i.get("doc").unwrap(), i.get("pins")) {
            Ok(()) => json!({"ok": true}),
            Err(c) => json!({"ok": false, "code": c}),
        },
        "rule22" => match rule22_integrity(&i["doc"], i.get("pins")) {
            Err(c) => json!({"integrity": c, "decision": "deny"}),
            Ok(()) => json!({"integrity": "ok", "decision": rule22_decide(&i["doc"], i["verb"].as_str().unwrap(), &i["grant"], &i["context"])}),
        },
        "schema_shape" => json!({"ok": action_schema_shape_error_unsigned(&i["doc"]).is_none()}),
        "pack_verify" => match verify_pack(&i["pack"], &i["keys"], i.get("shards")) {
            Ok((d, defs)) => json!({"ok": true, "digest": d, "defs": defs.len()}),
            Err(_) => json!({"ok": false}),
        },
        "evolution_verify" => json!({"ok": verify_evolution_record(&i["record"], &i["keys"]).is_ok(), "diff": evolution_diff_digest(&i["record"])}),
        "reapproval_verify" => json!({"ok": reapproval_valid(&i["reapproval"], i["grant"]["id"].as_str().unwrap(), i["grant"]["issuer"].as_str().unwrap(), i["verb"].as_str().unwrap(), i["diff"].as_str().unwrap())}),
        "pin" => {
            let d = decide_pin(i);
            if d["ok"] == json!(true) {
                json!({"ok": true, "via": d["via"]})
            } else {
                let mut o = json!({"ok": false, "code": d["code"], "escalate": d["escalate"]});
                if d.get("needs_reapproval").is_some() {
                    o["needs_reapproval"] = d["needs_reapproval"].clone();
                }
                o
            }
        }
        "pack_proof_verify" => json!({"ok": pack_verify(i["root"].as_str().unwrap(), &i["proof"], i["digest"].as_str().unwrap())}),
        "tracker" => {
            let mut t = PackTracker::new(i["keys"].clone());
            Value::Array(i["steps"].as_array().unwrap().iter().map(|st| match t.accept(&st["pack"], st.get("shards")) {
                Ok(status) => json!({"ok": true, "status": status}),
                Err(code) => json!({"ok": false, "code": code}),
            }).collect())
        }
        "approval_render" => match render_approval(&i["def"], &i["params"], i["confirmed"] == json!(true)) {
            Ok(r) => {
                let d = approval_render_digest(&r).unwrap();
                json!({"ok": true, "words": binding_words(&d).unwrap(), "render": r, "digest": d})
            }
            Err(e) => json!({"ok": false, "code": e.code}),
        },
        "approval_digest" => match approval_render_shape_error(&i["render"]) {
            Some(_) => json!({"ok": false}),
            None => json!({"ok": true, "digest": approval_render_digest(&i["render"]).unwrap()}),
        },
        "approval_challenge" => match approval_challenge(i["action_digest"].as_str().unwrap_or(""), i["render_digest"].as_str().unwrap_or("")) {
            Ok(c) if i["action_digest"].is_string() && i["render_digest"].is_string() => json!({"ok": true, "challenge": c}),
            _ => json!({"ok": false}),
        },
        "approval_escalation" => {
            let b = &i["bind"];
            let bind = EscalationBinding {
                policy_digest: b["policy_digest"].as_str().unwrap().into(),
                action_digest: b["action_digest"].as_str().unwrap().into(),
                history_head: b["history_head"].as_str().unwrap().into(),
                render_digest: b["render_digest"].as_str().map(String::from),
            };
            let pins: Vec<PinnedSigner> = i["principals"].as_array().unwrap().iter().map(|p| PinnedSigner::ed25519(p.as_str().unwrap())).collect();
            match verify_escalation_answer(&i["answer"], &pins, &bind, i["now"].as_i64().unwrap()) {
                EscalationVerdict::Ok { decision, .. } => json!({"ok": true, "decision": decision}),
                EscalationVerdict::Refused(reason) => json!({"ok": false, "reason": reason}),
            }
        }
        k => panic!("unknown vector kind {k}"),
    }
}

fn replay_profile(c: &Value) -> Value {
    let i = &c["input"];
    match c["kind"].as_str().unwrap() {
        "approval_psd2" => match psd2_linking(&i["render"]) {
            Ok(l) => json!({"ok": true, "linking": l}),
            Err(e) => json!({"ok": false, "code": e.code}),
        },
        "approval_batch" => match approval_batch(i["items"].as_array().unwrap()) {
            Ok(b) => json!({"ok": true, "batch": b["batch"], "action_digest": b["action_digest"], "render_digest": b["render_digest"], "challenge": b["challenge"], "words": b["words"]}),
            Err(e) => json!({"ok": false, "code": e.code}),
        },
        k => panic!("unknown approval profile vector kind {k}"),
    }
}

#[test]
fn approval_profile_vectors_replay() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let dir = ["../../packages/pca-conformance/vectors/approval-profiles", "../../conformance/approval-profiles", "conformance/approval-profiles"]
        .iter()
        .map(|r| root.join(r))
        .find(|d| d.is_dir())
        .expect("the approval profile vectors are missing (a vector directory is never skipped)");
    let mut files: Vec<_> = std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|x| x == "json")).collect();
    files.sort();
    assert!(files.len() >= 12, "only {} approval profile vectors", files.len());
    for f in files {
        let c: Value = serde_json::from_str(&common::sanitize_lone_surrogates(&std::fs::read_to_string(&f).unwrap())).unwrap();
        assert_eq!(replay_profile(&c), c["expect"], "{}", c["id"]);
    }
}

#[test]
fn every_vector_replays() {
    let cs = cases();
    assert!(cs.len() >= 781, "only {} vectors", cs.len());
    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cs {
        *kinds.entry(c["kind"].as_str().unwrap().into()).or_default() += 1;
        assert_eq!(replay(c), c["expect"], "{}", c["id"]);
    }
    for k in ["parse", "digest", "effective", "expand", "floor", "conform", "pack", "schema_verb", "rule22", "rule22_schema", "schema_shape", "pack_verify", "evolution_verify", "reapproval_verify", "pin", "pack_proof_verify", "tracker", "approval_render", "approval_digest", "approval_challenge", "approval_escalation"] {
        assert!(kinds.get(k).copied().unwrap_or(0) >= 8, "{k}");
    }
}

#[test]
fn pinned_digests() {
    assert_eq!(traits_digest(&core_registry()), "W2xe4TXZKavAeEpzGVYC8pp-ZhOxDv-_3TF76MveweM");
    assert_eq!(tables_digest(), "I7nxRoiVhU18WNY_EaUqegG7KeBYtfP8gMmibsfXJtU");
}

#[test]
fn pack_proof_verifies_and_tamper_fails() {
    let c = cases().into_iter().find(|c| c["id"] == "pack-builtin").unwrap();
    let ds = strs(&c["input"]["digests"]);
    let root = c["expect"]["root"].as_str().unwrap();
    for d in &ds {
        assert!(pack_verify(root, &pack_proof(&ds, d).unwrap(), d));
    }
    assert!(!pack_verify(root, &pack_proof(&ds, &ds[0]).unwrap(), &ds[1]));
    assert!(pack_root(&[ds[0].clone(), ds[0].clone()]).is_err());
}

#[test]
fn whole_document_rule_22() {
    let c = cases().into_iter().find(|c| c["id"] == "schema-verb-adv-honest").unwrap();
    let mut doc = json!({"verbs": [c["input"]["verb"].clone()]});
    assert_eq!(schema_floor_error(&doc, None), None);
    doc["traits_digest"] = json!("A".repeat(43));
    assert!(schema_floor_error(&doc, None).unwrap().starts_with("traits_digest_mismatch"));
}

/// Differential oracle for expand/floor: the closure equals eight rounds of one-step implication, and the floor of a set is the
/// join of the floors of its closure, on every subset of a small window of the core traits.
#[test]
fn expand_oracle_matches_one_step_rounds() {
    let reg = core_registry();
    let ids: Vec<String> = reg.traits.keys().cloned().collect();
    for mask in 0u32..(1 << 10) {
        let pick: Vec<String> = ids.iter().enumerate().filter(|(n, _)| mask & (1 << (n % 10)) != 0 && n % 3 != 2).map(|(_, s)| s.clone()).collect();
        let mut set: std::collections::BTreeSet<String> = pick.iter().cloned().collect();
        for _ in 0..8 {
            let add: Vec<String> = set.iter().flat_map(|t| reg.traits[t].implies.clone()).collect();
            set.extend(add);
        }
        let cl = closure(&reg, &pick).unwrap();
        assert_eq!(cl, set.iter().cloned().collect::<Vec<_>>());
        let want = cl.iter().fold(Profile::bottom(), |a, t| join(&a, &reg.traits[t].floor));
        assert_eq!(floor_of(&reg, &pick).unwrap(), want);
    }
}

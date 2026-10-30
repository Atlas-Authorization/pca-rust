//! Undo windows (pure layer): the shared vectors `undo-vectors.json` (made by the TypeScript reference; every section), the
//! signers byte for byte, and mutation-kill units for the token check order, receipts, chains, transitions, the window clamp and
//! the `undo_window` obligation.

mod common;

use atlas_pca::agent::KeyPair;
use atlas_pca::obligations::obligation_error;
use atlas_pca::undo::{
    compensation_digest, decode_undo_token, encode_undo_token, resolve_undo_window, sign_undo_receipt, sign_undo_token, undo_receipt_chain_error,
    undo_receipt_digest, undo_token_check, undo_token_digest, undo_transition, verify_undo_receipt, UndoAdmission, UndoCompensationRef,
    UndoTransition, UndoWindowPolicy, UNDO_DEFAULT_WINDOW_MS, UNDO_MAX_WINDOW_MS, UNDO_MIN_WINDOW_MS,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn vectors() -> Value {
    // a missing vector file fails (never skips)
    common::load("undo-vectors.json")
}

fn signer() -> KeyPair {
    KeyPair::from_seed(&Sha256::digest(b"atlas-pca/undo-vectors/signer").into())
}

fn other() -> KeyPair {
    KeyPair::from_seed(&[9u8; 32])
}

fn outcome(t: &UndoTransition) -> Value {
    match t {
        UndoTransition::Applied { record, .. } => {
            let mut o = json!({"outcome": "applied", "state": record["state"], "ver": record["ver"]});
            o["attempt"] = record["attempt"].clone();
            o
        }
        UndoTransition::Replayed => json!({"outcome": "replayed"}),
        UndoTransition::Refused { code, .. } => json!({"outcome": "refused", "code": code}),
    }
}

#[test]
fn undo_vectors_signer() {
    let d = vectors();
    assert_eq!(d["format"], "pca-undo-vectors");
    assert_eq!(signer().public, d["signer"]["public"].as_str().unwrap());
}

#[test]
fn undo_vectors_compensation() {
    let d = vectors();
    let cases = d["compensation"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        assert_eq!(compensation_digest(&c["compensation"]).as_deref(), c["digest"].as_str(), "{}", c["name"]);
    }
}

#[test]
fn undo_vectors_token() {
    let d = vectors();
    let t = &d["token"];
    // Ed25519 is deterministic: the same record and key sign the same token
    assert_eq!(sign_undo_token(&t["record"], &signer()).unwrap(), t["token"]);
    assert_eq!(encode_undo_token(&t["token"]).unwrap(), t["encoded"].as_str().unwrap());
    assert_eq!(decode_undo_token(t["encoded"].as_str().unwrap()), Some(t["token"].clone()));
    assert_eq!(undo_token_digest(&t["token"]).as_deref(), t["digest"].as_str());
    let checks = t["checks"].as_array().unwrap();
    assert_eq!(checks.len(), 12);
    for c in checks {
        let now = c["now"].as_f64().unwrap();
        let got = undo_token_check(&c["token"], c["signer"].as_str().unwrap(), &c["record"], now);
        assert_eq!(got, c["expect"].as_str().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn undo_vectors_receipts() {
    let d = vectors();
    let pk = d["signer"]["public"].as_str().unwrap();
    let list = d["receipts"]["list"].as_array().unwrap();
    assert!(!list.is_empty());
    for r in list {
        let rc = &r["receipt"];
        assert!(verify_undo_receipt(rc, pk));
        assert!(!verify_undo_receipt(rc, d["signer"]["other_public"].as_str().unwrap()));
        assert_eq!(undo_receipt_digest(rc).as_deref(), r["digest"].as_str());
        // the signer reproduces the receipt byte for byte
        let body = json!({"record": rc["record"], "event": rc["event"], "state": rc["state"], "at": rc["at"],
            "compensation_digest": rc["compensation_digest"], "prev": rc["prev"], "note": rc["note"]});
        assert_eq!(sign_undo_receipt(&body, &signer()).unwrap(), *rc);
    }
    let chains = d["receipts"]["chains"].as_array().unwrap();
    assert!(chains.len() >= 12);
    for c in chains {
        let mut rec = c["record"].clone();
        rec["receipts"] = c["receipts"].clone();
        let err = undo_receipt_chain_error(&rec, c["signer"].as_str().unwrap());
        assert_eq!(err.is_none(), c["expect"]["ok"].as_bool().unwrap(), "{}: {err:?}", c["name"]);
    }
}

#[test]
fn undo_vectors_transitions() {
    let d = vectors();
    let cases = d["transitions"].as_array().unwrap();
    assert_eq!(cases.len(), 33);
    for c in cases {
        let got = outcome(&undo_transition(&c["record"], &c["event"], c["now"].as_f64().unwrap()));
        let e = &c["expect"];
        for (k, v) in e.as_object().unwrap() {
            assert_eq!(&got[k], v, "{}: {k} in {got}", c["name"]);
        }
        if e["outcome"] == "applied" && e.get("attempt").is_none() {
            assert_eq!(got["attempt"], c["record"]["attempt"], "{}: attempt changes only on retry", c["name"]);
        }
    }
}

fn policy(p: &Value) -> UndoWindowPolicy {
    UndoWindowPolicy { min_ms: p["minMs"].as_f64(), max_ms: p["maxMs"].as_f64(), default_ms: p["defaultMs"].as_f64() }
}

#[test]
fn undo_vectors_window() {
    let d = vectors();
    let cases = d["window"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        assert_eq!(resolve_undo_window(c["requested"].as_f64(), &policy(&c["policy"])), c["expect"].as_i64().unwrap(), "{}", c["name"]);
    }
}

#[test]
fn undo_vectors_obligation() {
    let d = vectors();
    let cases = d["obligation"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        assert_eq!(obligation_error(&c["obligation"]).is_none(), c["expect"]["ok"].as_bool().unwrap(), "{}", c["name"]);
    }
}

// ---- mutation kills -------------------------------------------------------------------------------------------------------

fn record() -> Value {
    json!({"id": "op_1", "aud": "drafts-rs", "principal": "P", "compensation_digest": "C", "render_digest": "R", "window_end": 1000})
}

#[test]
fn undo_kill_token_check_order() {
    let (k, o) = (signer(), other());
    let tok = sign_undo_token(&record(), &k).unwrap();
    assert_eq!(undo_token_check(&tok, &k.public, &record(), 0.0), "ok");
    // exp is inclusive; a non-integral or unsafe clock is expired
    assert_eq!(undo_token_check(&tok, &k.public, &record(), 1000.0), "ok");
    assert_eq!(undo_token_check(&tok, &k.public, &record(), 1001.0), "expired");
    for bad_now in [999.5, f64::NAN, f64::INFINITY, 9_007_199_254_740_992.0] {
        assert_eq!(undo_token_check(&tok, &k.public, &record(), bad_now), "expired", "{bad_now}");
    }
    // malformed: member count, version, kind, record id, string members, exp, signature encoding
    let mut extra = tok.clone();
    extra["x"] = json!(1);
    let mut missing = tok.clone();
    missing.as_object_mut().unwrap().remove("aud");
    let mut v2 = tok.clone();
    v2["v"] = json!(2);
    let mut kind = tok.clone();
    kind["kind"] = json!("pca-undo-receipt");
    let mut ctl = tok.clone();
    ctl["record"] = json!("op\u{1}");
    let mut long = tok.clone();
    long["record"] = json!("r".repeat(257));
    let mut num_aud = tok.clone();
    num_aud["aud"] = json!(1);
    let mut exp = tok.clone();
    exp["exp"] = json!(1.5);
    let mut sig = tok.clone();
    sig["sig"] = json!("AAAA");
    for (name, t) in [("extra", extra), ("missing", missing), ("v", v2), ("kind", kind), ("ctl", ctl), ("long", long), ("aud", num_aud), ("exp", exp), ("sig", sig), ("str", json!("x"))] {
        assert_eq!(undo_token_check(&t, &k.public, &record(), 0.0), "malformed", "{name}");
    }
    // a 256-unit id is well formed (it then names another record)
    let mut at_cap = record();
    at_cap["id"] = json!("r".repeat(256));
    let capped = sign_undo_token(&at_cap, &k).unwrap();
    assert_eq!(undo_token_check(&capped, &k.public, &at_cap, 0.0), "ok");
    // signer before signature: another key's token, also tampered
    let mut theirs = sign_undo_token(&record(), &o).unwrap();
    theirs["exp"] = json!(999);
    assert_eq!(undo_token_check(&theirs, &k.public, &record(), 0.0), "signer");
    // signature before record: a tampered token for another record
    let mut tampered = tok.clone();
    tampered["record"] = json!("op_2");
    assert_eq!(undo_token_check(&tampered, &k.public, &record(), 0.0), "signature");
    // record before binding: a sound token for another record whose binding also differs
    let mut r2 = record();
    r2["id"] = json!("op_2");
    r2["aud"] = json!("elsewhere");
    assert_eq!(undo_token_check(&tok, &k.public, &r2, 0.0), "record");
    // every binding member, and binding before expiry
    for (k2, v) in [("aud", json!("x")), ("principal", json!("x")), ("compensation_digest", json!("x")), ("render_digest", json!("x")), ("window_end", json!(1001))] {
        let mut r = record();
        r[k2] = v;
        assert_eq!(undo_token_check(&tok, &k.public, &r, 5000.0), "binding", "{k2}");
    }
    // a record without a render binds the empty string
    let mut bare = record();
    bare.as_object_mut().unwrap().remove("render_digest");
    let t = sign_undo_token(&bare, &k).unwrap();
    assert_eq!(t["render_digest"], "");
    assert_eq!(undo_token_check(&t, &k.public, &bare, 0.0), "ok");
    assert_eq!(undo_token_check(&t, &k.public, &record(), 0.0), "binding");
}

#[test]
fn undo_kill_token_codec() {
    let tok = sign_undo_token(&record(), &signer()).unwrap();
    let s = encode_undo_token(&tok).unwrap();
    assert_eq!(decode_undo_token(&s), Some(tok));
    assert_eq!(decode_undo_token(""), None);
    assert_eq!(decode_undo_token(&"A".repeat(4097)), None);
    assert_eq!(decode_undo_token(&format!("{s}=")), None, "padding is not canonical");
    let b64 = |x: &[u8]| {
        use base64::Engine;
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x)
    };
    assert_eq!(decode_undo_token(&b64(b"[1]")), None, "an array is not a token");
    assert_eq!(decode_undo_token(&b64(b"{bad")), None);
    assert_eq!(decode_undo_token(&b64(&[0xff, 0xfe])), None);
}

fn chain(states: &[(&str, &str, i64)], key: &KeyPair) -> Value {
    let mut rs: Vec<Value> = Vec::new();
    for (event, state, at) in states {
        let prev = rs.last().map_or(String::new(), |r| undo_receipt_digest(r).unwrap());
        let body = json!({"record": "op_1", "event": event, "state": state, "at": at, "compensation_digest": "C", "prev": prev, "note": ""});
        rs.push(sign_undo_receipt(&body, key).unwrap());
    }
    let last = states.last().map_or("open", |s| s.1);
    json!({"id": "op_1", "compensation_digest": "C", "state": last, "receipts": rs})
}

#[test]
fn undo_kill_receipts_and_chains() {
    let k = signer();
    let rec = chain(&[("opened", "open", 5), ("effect", "open", 5), ("vetoed", "vetoed", 6)], &k);
    // equal timestamps are fine (never decreasing)
    assert_eq!(undo_receipt_chain_error(&rec, &k.public), None);
    // exactly 11 members
    let r0 = rec["receipts"][0].clone();
    assert!(verify_undo_receipt(&r0, &k.public));
    let mut extra = r0.clone();
    extra["x"] = json!(1);
    assert!(!verify_undo_receipt(&extra, &k.public));
    let mut fewer = r0.clone();
    fewer.as_object_mut().unwrap().remove("note");
    assert!(!verify_undo_receipt(&fewer, &k.public));
    let mut bad_event = r0.clone();
    bad_event["event"] = json!("exploded");
    assert!(!verify_undo_receipt(&bad_event, &k.public));
    assert!(!verify_undo_receipt(&json!("x"), &k.public));
    // the first receipt links to "" and nothing else
    let mut first = rec.clone();
    first["receipts"][0]["prev"] = json!("x");
    assert!(undo_receipt_chain_error(&first, &k.public).is_some());
    let resigned = {
        let r = &rec["receipts"][0];
        let body = json!({"record": r["record"], "event": r["event"], "state": r["state"], "at": r["at"], "compensation_digest": r["compensation_digest"], "prev": "x", "note": r["note"]});
        sign_undo_receipt(&body, &k).unwrap()
    };
    let mut first = rec.clone();
    first["receipts"][0] = resigned;
    assert_eq!(undo_receipt_chain_error(&first, &k.public).as_deref(), Some("receipt 0 does not link to the previous one"));
    // time goes back
    let back = chain(&[("opened", "open", 6), ("vetoed", "vetoed", 5)], &k);
    assert_eq!(undo_receipt_chain_error(&back, &k.public).as_deref(), Some("receipt 1 goes back in time"));
    // the last receipt states the record's state
    let mut stale = rec.clone();
    stale["state"] = json!("open");
    assert_eq!(undo_receipt_chain_error(&stale, &k.public).as_deref(), Some("the last receipt does not state the record state"));
    // the first event is opened
    let late = chain(&[("effect", "open", 5)], &k);
    assert_eq!(undo_receipt_chain_error(&late, &k.public).as_deref(), Some("the first receipt is not opened"));
    // empty, and another signer
    assert_eq!(undo_receipt_chain_error(&json!({"id": "op_1", "state": "open", "receipts": []}), &k.public).as_deref(), Some("no receipts"));
    assert!(undo_receipt_chain_error(&rec, &other().public).is_some());
}

fn rec_in(state: &str) -> Value {
    json!({"state": state, "window_end": 1000, "ver": 3, "attempt": 0})
}

fn veto() -> Value {
    json!({"kind": "veto", "veto": {"at": 1, "via": "token", "by": "P"}})
}

#[test]
fn undo_kill_every_transition_row() {
    let o = |r: Value, e: Value, now: f64| outcome(&undo_transition(&r, &e, now));
    let applied = |state: &str| json!({"outcome": "applied", "state": state, "ver": 4, "attempt": 0});
    let refused = |code: &str| json!({"outcome": "refused", "code": code});
    let replayed = json!({"outcome": "replayed"});
    // veto
    assert_eq!(o(rec_in("open"), veto(), 1000.0), applied("vetoed"));
    assert_eq!(o(rec_in("open"), veto(), 1001.0), refused("window_closed"));
    for s in ["vetoed", "compensated", "compensation_failed"] {
        assert_eq!(o(rec_in(s), veto(), 5000.0), replayed, "{s}");
    }
    assert_eq!(o(rec_in("finalized"), veto(), 0.0), refused("finalized"));
    for bad in [json!({"kind": "veto"}), json!({"kind": "veto", "veto": {"at": 1.5, "via": "token", "by": "P"}}), json!({"kind": "veto", "veto": {"at": 1, "via": "token", "by": 3}})] {
        assert_eq!(o(rec_in("open"), bad.clone(), 0.0), refused("invalid"), "{bad}");
    }
    // finalize
    assert_eq!(o(rec_in("open"), json!({"kind": "finalize"}), 1000.0), refused("window_open"));
    assert_eq!(o(rec_in("open"), json!({"kind": "finalize"}), 1001.0), applied("finalized"));
    assert_eq!(o(rec_in("finalized"), json!({"kind": "finalize"}), 1001.0), replayed);
    for s in ["vetoed", "compensated", "compensation_failed"] {
        assert_eq!(o(rec_in(s), json!({"kind": "finalize"}), 5000.0), refused("vetoed"), "{s}");
    }
    // abort
    let abort = json!({"kind": "abort", "reason": "effect_failed"});
    assert_eq!(o(rec_in("open"), abort.clone(), 0.0), applied("finalized"));
    assert_eq!(o(rec_in("vetoed"), abort.clone(), 0.0), applied("finalized"));
    let mut ran = rec_in("open");
    ran["effect"] = json!({"at": 1});
    assert_eq!(o(ran, abort.clone(), 0.0), refused("effect_recorded"));
    let mut aborted = rec_in("finalized");
    aborted["outcome"] = json!({"status": "aborted"});
    assert_eq!(o(aborted, abort.clone(), 0.0), replayed);
    for s in ["finalized", "compensated", "compensation_failed"] {
        assert_eq!(o(rec_in(s), abort.clone(), 0.0), refused("finalized"), "{s}");
    }
    // effect
    assert_eq!(o(rec_in("open"), json!({"kind": "effect"}), 0.0), applied("open"));
    assert_eq!(o(rec_in("vetoed"), json!({"kind": "effect"}), 0.0), applied("vetoed"));
    let mut had = rec_in("finalized");
    had["effect"] = json!({"at": 1});
    assert_eq!(o(had, json!({"kind": "effect"}), 0.0), replayed, "an effect already recorded replays in any state");
    for s in ["finalized", "compensated", "compensation_failed"] {
        assert_eq!(o(rec_in(s), json!({"kind": "effect"}), 0.0), refused("finalized"), "{s}");
    }
    // compensated
    assert_eq!(o(rec_in("vetoed"), json!({"kind": "compensated"}), 0.0), applied("compensated"));
    assert_eq!(o(rec_in("compensation_failed"), json!({"kind": "compensated"}), 0.0), applied("compensated"));
    assert_eq!(o(rec_in("compensated"), json!({"kind": "compensated"}), 0.0), replayed);
    for s in ["open", "finalized"] {
        assert_eq!(o(rec_in(s), json!({"kind": "compensated"}), 0.0), refused("not_vetoed"), "{s}");
    }
    // compensation_failed
    let failed = json!({"kind": "compensation_failed", "reason": "x"});
    assert_eq!(o(rec_in("vetoed"), failed.clone(), 0.0), applied("compensation_failed"));
    assert_eq!(o(rec_in("compensation_failed"), failed.clone(), 0.0), replayed);
    for s in ["open", "compensated", "finalized"] {
        assert_eq!(o(rec_in(s), failed.clone(), 0.0), refused("not_vetoed"), "{s}");
    }
    // retry bumps attempt and ver
    let r = undo_transition(&rec_in("compensation_failed"), &json!({"kind": "retry"}), 0.0);
    assert_eq!(outcome(&r), json!({"outcome": "applied", "state": "vetoed", "ver": 4, "attempt": 1}));
    for s in ["open", "vetoed", "compensated", "finalized"] {
        assert_eq!(o(rec_in(s), json!({"kind": "retry"}), 0.0), refused("not_failed"), "{s}");
    }
    // malformed records, clocks and events
    assert_eq!(o(rec_in("weird"), veto(), 0.0), refused("invalid"));
    assert_eq!(o(json!({"state": "open", "window_end": 1.5, "ver": 3}), veto(), 0.0), refused("invalid"));
    assert_eq!(o(json!({"state": "open", "window_end": 1000, "ver": "3"}), veto(), 0.0), refused("invalid"));
    assert_eq!(o(json!("open"), veto(), 0.0), refused("invalid"));
    assert_eq!(o(rec_in("open"), veto(), 0.5), refused("invalid"));
    assert_eq!(o(rec_in("open"), veto(), f64::NAN), refused("invalid"));
    assert_eq!(o(rec_in("open"), json!({"kind": "explode"}), 0.0), refused("invalid"));
    assert_eq!(o(rec_in("open"), json!({}), 0.0), refused("invalid"));
}

#[test]
fn undo_kill_transition_payloads() {
    // the veto is kept, the receipt note is its via; the abort reason is clipped (512 in the outcome, 128 in the note)
    match undo_transition(&rec_in("open"), &veto(), 0.0) {
        UndoTransition::Applied { record, event, note } => {
            assert_eq!((event, note.as_str()), ("vetoed", "token"));
            assert_eq!(record["veto"], veto()["veto"]);
        }
        other => panic!("{other:?}"),
    }
    let long = "r".repeat(600);
    match undo_transition(&rec_in("open"), &json!({"kind": "abort", "reason": long}), 7.0) {
        UndoTransition::Applied { record, event, note } => {
            assert_eq!((event, note.len()), ("aborted", 128));
            assert_eq!(record["outcome"]["reason"].as_str().unwrap().len(), 512);
            assert_eq!((record["outcome"]["status"].clone(), record["outcome"]["at"].clone()), (json!("aborted"), json!(7)));
        }
        other => panic!("{other:?}"),
    }
    match undo_transition(&rec_in("open"), &json!({"kind": "effect", "result": {"id": "d_1"}}), 7.0) {
        UndoTransition::Applied { record, .. } => assert_eq!(record["effect"], json!({"at": 7, "result": {"id": "d_1"}})),
        other => panic!("{other:?}"),
    }
    // the input record is never modified
    let r = rec_in("open");
    let _ = undo_transition(&r, &veto(), 0.0);
    assert_eq!(r, rec_in("open"));
}

#[test]
fn undo_kill_window_clamp_edges() {
    let none = UndoWindowPolicy::default();
    assert_eq!(resolve_undo_window(None, &none), UNDO_DEFAULT_WINDOW_MS);
    assert_eq!(resolve_undo_window(Some(f64::NAN), &none), UNDO_DEFAULT_WINDOW_MS);
    assert_eq!(resolve_undo_window(Some(f64::INFINITY), &none), UNDO_DEFAULT_WINDOW_MS);
    assert_eq!(resolve_undo_window(Some(29_999.0), &none), UNDO_MIN_WINDOW_MS);
    assert_eq!(resolve_undo_window(Some(30_000.0), &none), 30_000);
    assert_eq!(resolve_undo_window(Some(30_001.0), &none), 30_001);
    assert_eq!(resolve_undo_window(Some(120_000.9), &none), 120_000);
    assert_eq!(resolve_undo_window(Some(86_400_000.0), &none), UNDO_MAX_WINDOW_MS);
    assert_eq!(resolve_undo_window(Some(86_400_001.0), &none), UNDO_MAX_WINDOW_MS);
    assert_eq!(resolve_undo_window(Some(-5.0), &none), UNDO_MIN_WINDOW_MS);
    // a host maximum above the protocol maximum is the protocol maximum; below the minimum it is the minimum
    let wide = UndoWindowPolicy { max_ms: Some(1e12), ..Default::default() };
    assert_eq!(resolve_undo_window(Some(1e11), &wide), UNDO_MAX_WINDOW_MS);
    let narrow = UndoWindowPolicy { min_ms: Some(60_000.0), max_ms: Some(10.0), ..Default::default() };
    assert_eq!(resolve_undo_window(Some(1e9), &narrow), 60_000);
    // a host default outside the bounds is clamped too
    let dflt = UndoWindowPolicy { default_ms: Some(1.0), ..Default::default() };
    assert_eq!(resolve_undo_window(None, &dflt), UNDO_MIN_WINDOW_MS);
}

#[test]
fn undo_kill_obligation_params() {
    let ok = json!({"kind": "undo_window", "params": {"id": "a".repeat(128), "window_end": 0}, "due": 0});
    assert_eq!(obligation_error(&ok), None);
    let long = json!({"kind": "undo_window", "params": {"id": "a".repeat(129), "window_end": 1}});
    assert!(obligation_error(&long).is_some(), "a 129-character id");
    let empty = json!({"kind": "undo_window", "params": {"id": "", "window_end": 1}});
    assert!(obligation_error(&empty).is_some());
    let extra = json!({"kind": "undo_window", "params": {"id": "a", "window_end": 1, "by": "x"}});
    assert!(obligation_error(&extra).is_some(), "an extra member");
    let negative = json!({"kind": "undo_window", "params": {"id": "a", "window_end": -1}});
    assert!(obligation_error(&negative).is_some(), "a negative window_end");
    let frac = json!({"kind": "undo_window", "params": {"id": "a", "window_end": 1.5}});
    assert!(obligation_error(&frac).is_some());
    // the admission's own obligation is well formed and due at the window end
    let a = UndoAdmission { id: "op_1".into(), window_end: 1_800_000_900_000, compensation: UndoCompensationRef { verb: "drafts.delete".into(), resource: "drafts:box1".into() } };
    let ob = a.obligation();
    assert_eq!(ob, json!({"kind": "undo_window", "params": {"id": "op_1", "window_end": 1_800_000_900_000i64}, "due": 1_800_000_900_000i64}));
    assert_eq!(obligation_error(&ob), None);
}

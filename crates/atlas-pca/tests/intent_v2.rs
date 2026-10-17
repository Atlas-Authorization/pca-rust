//! Intent Layer v2 (rules 13-18): mutation kills for every boundary and for the check order, on natively built and
//! natively signed fixtures (action schema, session root, session grants G_0 / D_1, sequencer key sets and reservation
//! receipts, revocation epochs, oracle facts, offer sets, label receipts, classifier verdicts). The shapes follow
//! `packages/pca/scripts/gen-conformance-intent-v2.mjs` / `gen-conformance-intent-wb.mjs`.
use atlas_pca::*;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const CAP_DOMAIN: &[u8] = b"atlas-pca/cap/v1\x00";
const AUD: &str = "skyair.example";
const NOW: i64 = 1_800_000_000_000;
const MAX_SAFE: i64 = 9_007_199_254_740_991;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}
fn key(label: &str) -> SigningKey {
    let seed: [u8; 32] = Sha256::digest(format!("v2/{label}").as_bytes()).into();
    SigningKey::from_bytes(&seed)
}
fn pk(label: &str) -> String {
    b64(key(label).verifying_key().as_bytes())
}
fn d32(label: &str) -> String {
    b64(&Sha256::digest(label.as_bytes()))
}
fn canon(v: &Value) -> String {
    canonicalize_strict(v).unwrap()
}
/// Ed25519 over `domain || strictCanonical(body)`.
fn sign_domain(signer: &str, domain: &str, body: &Value) -> String {
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(canon(body).as_bytes());
    b64(&key(signer).sign(&m).to_bytes())
}
/// An artifact signed over `domain || strictCanonical(artifact without sig)`, `sig` added.
fn signed(signer: &str, domain: &str, mut body: Value) -> Value {
    let sig = sign_domain(signer, domain, &body);
    body["sig"] = json!(sig);
    body
}
fn ref_of(domain: &str, slot: &str, artifact: &Value) -> String {
    hash_canonical_strict(&json!({"d": domain, slot: artifact})).unwrap()
}

// ---- the site schema ----------------------------------------------------------------------------------------------

fn unsigned_schema() -> Value {
    json!({
        "v": 1, "kind": "pca-action-schema", "site": "https://skyair.example", "aud": AUD, "version": "2026-10-01",
        "units": {"usd_cents": {"kind": "money", "currency": "USD", "exponent": 2}},
        "verbs": [
            {"verb": "air.book", "kind": "write", "params": {
                "action.params.offer_id": {"type": "string", "semantic": "product.ref", "sensitivity": "material"},
                "action.params.total": {"type": "integer", "unit": "usd_cents", "min": 0, "max": 5_000_000, "semantic": "money.amount", "sensitivity": "critical", "accumulates_into": ["spend.usd_cents"]},
                "action.params.add_ons": {"type": "set", "values": ["none", "tripshield", "seat_plus"], "default": ["none"], "principal_neutral_default": true, "semantic": "product.addon", "sensitivity": "material"},
                "action.params.refundable": {"type": "boolean", "semantic": "flag", "sensitivity": "material"},
                "action.params.passengers": {"type": "array", "max_items": 9, "max_len": 64, "semantic": "person.identity", "sensitivity": "critical", "required": false},
                "action.params.note": {"type": "string", "semantic": "text.note", "sensitivity": "free", "required": false, "max_len": 16}
            }, "reversibility_by": {"param": "action.params.refundable", "map": {"true": "reversible", "false": "irreversible"}}},
            {"verb": "air.search", "kind": "read", "params": {
                "action.params.from": {"type": "string", "values": ["SFO", "JFK"], "semantic": "place.airport", "sensitivity": "material"},
                "action.params.date": {"type": "date", "semantic": "schedule.date", "sensitivity": "material"},
                "action.params.pax": {"type": "integer", "min": 1, "max": 9, "semantic": "quantity", "sensitivity": "material"}
            }, "reversibility": "reversible"}
        ]
    })
}
fn sign_schema(doc: Value, signer: &str) -> Value {
    let value = sign_domain(signer, "atlas-pca/action-schema/v1\0", &doc);
    let mut d = doc;
    d["sig"] = json!({"alg": "ed25519", "kid": "skyair-2026", "value": value});
    d
}
fn schema() -> Value {
    sign_schema(unsigned_schema(), "site")
}
fn schema_keys() -> Value {
    json!([{"kid": "skyair-2026", "alg": "ed25519", "pk": pk("site")}])
}
fn schema_digest() -> String {
    action_schema_digest(&schema()).unwrap()
}

// ---- session root, grants, PCActn ----------------------------------------------------------------------------------

fn session() -> String {
    d32("session")
}
fn ref_() -> String {
    d32("ref")
}
fn map0() -> String {
    d32("map0")
}
fn map1() -> String {
    d32("map1")
}
fn trip() -> Value {
    json!({"id": "trip_spend", "agg": "sum", "unit": "usd_cents", "sel": {"accumulates_into": "spend.usd_cents"}, "win": {"kind": "task"}, "key": null, "domain_max": 500_000, "holder": {"kind": "site_local"}})
}
fn questions() -> Value {
    json!({"id": "questions", "agg": "count", "sel": {"event": "intent_required"}, "win": {"kind": "task"}, "key": null, "cap": 6, "holder": {"kind": "wallet"}})
}
fn root_body() -> Value {
    json!({
        "v": 1, "kind": "pca-intent-session", "session": session(), "principals": [{"key": pk("principal")}], "intent_ref": ref_(),
        "schema": {"aud": AUD, "digest": schema_digest()}, "layers": {"task": {"map_digest": map0()}},
        "accumulators": [trip(), questions()], "monitors": [], "question_uri": "https://atlas.example/q", "expires_at": NOW + 86_400_000
    })
}
/// Sign S (body + signer) as `signer`; returns (S, digest(S)).
fn sign_root(body: Value, signer: &str) -> (Value, String) {
    let mut b = body;
    b["signer"] = json!(pk(signer));
    let sig = sign_domain(signer, "atlas-pca/intent-session/v1\0", &b);
    b["sig"] = json!(sig);
    let d = session_root_digest(&b).unwrap();
    (b, d)
}
fn root_with(f: impl FnOnce(&mut Value)) -> (Value, String) {
    let mut b = root_body();
    f(&mut b);
    sign_root(b, "principal")
}
fn base_root() -> (Value, String) {
    sign_root(root_body(), "principal")
}
/// A ROOT capability signed by `issuer` (a principal for a real session grant).
fn cap(issuer: &str, caveats: Value) -> Value {
    let holder = pk("agent");
    let body = json!({"issuer": pk(issuer), "holder": holder, "caveats": caveats.clone(), "parent": null});
    let d = hash_canonical_strict(&body).unwrap();
    let mut msg = CAP_DOMAIN.to_vec();
    msg.extend_from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&d).unwrap());
    json!({"id": d, "issuer": pk(issuer), "holder": holder, "caveats": caveats, "body_digest": d, "sig": b64(&key(issuer).sign(&msg).to_bytes())})
}
/// G_0 (seq 0) or D_k: envelope with the v2 goal, then the `intent_session` caveat.
fn grant(issuer: &str, seq: i64, prev: Option<&str>, root: &str, map: &str, salt: &str) -> Value {
    let goal = intent_goal_commit_v2(&session(), map, salt).unwrap();
    let mut sc = json!({"type": "intent_session", "session": session(), "seq": seq, "root": root});
    if let Some(p) = prev {
        sc["prev"] = json!(p);
    }
    cap(issuer, json!([{"type": "envelope", "goal_commit": goal}, sc]))
}
fn params() -> Value {
    json!({"offer_id": "OF-1", "total": 38_900, "add_ons": ["none"], "refundable": false})
}
fn is0(root: &str) -> Value {
    json!({"session": session(), "root": root, "seq": 0, "schema": schema_digest(), "acc": [{"id": "trip_spend", "post": 38_900}]})
}
/// The unsigned PCActn body (no `sig`) over `grant`.
fn body(grant: &Value, params: &Value, map: &str, salt: &str, is: Option<Value>) -> Value {
    let pd = hash_canonical_strict(params).unwrap();
    let cond = d32("cond");
    let leaf = json!({"node_id": "book", "verb": "air.book", "resource": "skyair.example/bookings", "params_digest": pd, "reversibility_class": "irreversible", "conditions": cond});
    let mut lb = vec![0u8];
    lb.extend_from_slice(canon(&leaf).as_bytes());
    let plan_root = b64(&Sha256::digest(&lb));
    let mut p = json!({
        "ver": 2, "action": {"verb": "air.book", "resource": "skyair.example/bookings", "params_digest": pd, "reversibility_class": "irreversible"},
        "grant_ref": grant["id"], "cap_chain": [grant],
        "plan": {"root": plan_root, "node_id": "book", "conditions_digest": cond, "inclusion_proof": {"index": 0, "size": 1, "path": []}},
        "attestation": {"epoch": 1, "quote_digest": "q", "model_id": "m", "measurement": "x", "operator": "o"},
        "provenance": {"causal_hash": "h", "taint_level": 0, "trusted_refs": []},
        "freshness": {"beacon_ref": "b", "accumulator_witness": "w", "epoch": 1},
        "counter": 1, "risk_claim": {"r": 0.1, "inputs": {}}, "aud": AUD, "iat": NOW, "exp": NOW + 600_000,
        "intent": {"ref": ref_(), "map_digest": map, "goal_salt": salt, "fidelity_ppm": 1_000_000, "residual_risk_ppm": 0}
    });
    if let Some(is) = is {
        p["intent_session"] = is;
    }
    p
}
fn sign_p(mut p: Value) -> Value {
    p.as_object_mut().unwrap().remove("sig");
    let msg = threshold_message(p.as_object().unwrap()).unwrap();
    p["sig"] = json!(b64(&key("agent").sign(&msg).to_bytes()));
    p
}
fn ctx_json(root: &Value) -> Value {
    json!({
        "params": params(), "schema": {"docs": [schema()], "keys": schema_keys()},
        "session": {"root": root, "grants": []}, "acc": {"state": {"trip_spend": {"sum": 0}}, "monitors": {}}
    })
}

struct Fx {
    g0: Value,
    p0: Value,
    ctx: Value,
}
fn fx() -> Fx {
    let (s, r) = base_root();
    let g0 = grant("principal", 0, None, &r, &map0(), "salt0");
    let p0 = sign_p(body(&g0, &params(), &map0(), "salt0", Some(is0(&r))));
    Fx { g0, p0, ctx: ctx_json(&s) }
}

/// The checks a malformed top-level context fails (with the member present).
const TOP: &[&str] = &["accumulators", "intent_session", "schema"];

fn run(p: &Value, g: &Value, ctx: &Value) -> Verdict {
    let c = IntentV2Context::from_json(ctx).unwrap();
    verify_pcactn_core_with(p, g, NOW, AUD, &VerifyOptions { allowed: None, intent: None, intent_v2: Some(&c) })
}
fn failed(v: &Verdict) -> Vec<String> {
    v.checks.iter().filter(|(_, ok)| !**ok).map(|(k, _)| k.clone()).collect()
}
fn assert_allow(v: &Verdict) {
    assert!(v.allow, "{} {:?}", v.reason, v.checks);
}
fn assert_only(v: &Verdict, names: &[&str]) {
    let mut want: Vec<String> = names.iter().map(|x| x.to_string()).collect();
    want.sort();
    assert_eq!(failed(v), want, "{}", v.reason);
}

// ---- the pipeline -------------------------------------------------------------------------------------------------

#[test]
fn g0_admits_and_reports_the_v2_checks_in_order() {
    let f = fx();
    let v = run(&f.p0, &f.g0, &f.ctx);
    assert_allow(&v);
    for k in ["intent", "schema", "intent_session", "accumulators"] {
        assert_eq!(v.checks.get(k), Some(&true), "{k}");
    }
    for k in ["layers", "facts", "provenance", "classes"] {
        assert!(!v.checks.contains_key(k), "{k} must not be reported");
    }
    let d = decide_intent_v2(&f.p0, &f.g0, Some(&IntentV2Context::from_json(&f.ctx).unwrap()), NOW);
    let names: Vec<&str> = d.checks.iter().map(|c| c.name).collect();
    assert_eq!(names, ["schema", "intent_session", "accumulators"]);
    assert_eq!(d.env["acc"]["trip_spend"]["post"], json!(38_900));
    assert_eq!(d.env["canon"]["add_ons"], json!("[\"none\"]"));
    assert_eq!(d.env["canon"]["refundable"], json!("false"));
}

#[test]
fn back_compat_without_member_or_policy_reports_no_v2_check() {
    let f = fx();
    let (s, _) = base_root();
    let g = cap("principal", json!([{"type": "envelope", "goal_commit": intent_goal_commit(&ref_(), &map0(), "salt0").unwrap()}]));
    let p = sign_p(body(&g, &params(), &map0(), "salt0", None));
    let v = run(&p, &g, &ctx_json(&s));
    assert_allow(&v);
    assert_eq!(v.checks.len(), 10, "{:?}", v.checks);
    // the inactive policy changes nothing either
    let v = run(&p, &g, &json!({"policy": {"session": {"require": false}, "schema": {"closed_world": false}}}));
    assert_eq!(v.checks.len(), 10);
    let _ = f;
}

#[test]
fn policies_activate_their_checks_without_the_member() {
    let (s, _) = base_root();
    let g = cap("principal", json!([{"type": "envelope", "goal_commit": intent_goal_commit(&ref_(), &map0(), "salt0").unwrap()}]));
    let p = sign_p(body(&g, &params(), &map0(), "salt0", None));
    let mut c = ctx_json(&s);
    c["policy"] = json!({"schema": {"closed_world": true}});
    let v = run(&p, &g, &c);
    assert_allow(&v);
    assert_eq!(v.checks.get("schema"), Some(&true));
    assert!(!v.checks.contains_key("intent_session") && !v.checks.contains_key("accumulators"));
    c["policy"] = json!({"session": {"require": true}});
    let v = run(&p, &g, &c);
    assert_only(&v, &["intent_session"]);
    assert!(!v.checks.contains_key("schema"));
}

#[test]
fn v2_goal_amends_rule_12() {
    let f = fx();
    // the v1 goal does not open a v2 grant once the member is present
    let (_, r) = base_root();
    let v1 = cap("principal", json!([{"type": "envelope", "goal_commit": intent_goal_commit(&ref_(), &map0(), "salt0").unwrap()},
        {"type": "intent_session", "session": session(), "seq": 0, "root": r}]));
    let p = sign_p(body(&v1, &params(), &map0(), "salt0", Some(is0(&r))));
    assert!(run(&p, &v1, &f.ctx).checks["intent"] == false);
    // and the v2 goal does not open without the member (back-compat path)
    let p = sign_p(body(&f.g0, &params(), &map0(), "salt0", None));
    assert_only(&run(&p, &f.g0, &f.ctx), &["intent"]);
    assert_ne!(intent_goal_commit_v2(&session(), &map0(), "salt0"), intent_goal_commit_v2(&session(), &map1(), "salt0"));
}

#[test]
fn checks_one_to_four_are_independent() {
    let f = fx();
    // schema and accumulators both fail on params that do not open the digest; intent_session still passes
    let mut c = f.ctx.clone();
    c["params"]["total"] = json!(1);
    let v = run(&f.p0, &f.g0, &c);
    assert_only(&v, &["accumulators", "schema"]);
    assert_eq!(v.checks.get("intent_session"), Some(&true));
    // no root: intent_session and accumulators fail, schema still passes
    let mut c = f.ctx.clone();
    c["session"] = json!({"grants": []});
    assert_only(&run(&f.p0, &f.g0, &c), &["accumulators", "intent_session"]);
    // a failing org ceiling does not stop the accumulators check
    let mut c = f.ctx.clone();
    c["layers"] = json!({"org": {"predicates": [{"verb": "air.book", "where": [{"field": "action.params.total", "op": "lte", "value": 10_000}]}]}});
    let v = run(&f.p0, &f.g0, &c);
    assert_only(&v, &["layers"]);
    assert_eq!(v.checks.get("accumulators"), Some(&true));
}

// ---- rule 13: intent_session wire boundaries ------------------------------------------------------------------

fn wire_ok(is: Value) -> bool {
    let f = fx();
    let mut p = f.p0.clone();
    p["intent_session"] = is;
    let v = run(&sign_p(p), &f.g0, &f.ctx);
    v.checks.get("wire") == Some(&true)
}
fn digests(n: usize, tag: &str) -> Value {
    Value::Array((0..n).map(|i| json!(d32(&format!("{tag}{i}")))).collect())
}

#[test]
fn intent_session_wire_boundaries() {
    let (_, r) = base_root();
    let base = || is0(&r);
    let with = |k: &str, v: Value| {
        let mut x = base();
        x[k] = v;
        x
    };
    assert!(wire_ok(base()));
    assert!(wire_ok(with("seq", json!(2_147_483_647))));
    assert!(!wire_ok(with("seq", json!(2_147_483_648i64))));
    assert!(!wire_ok(with("seq", json!(-1))));
    assert!(!wire_ok(with("seq", json!(1.5))));
    assert!(!wire_ok(json!([base()])));
    assert!(!wire_ok(with("note", json!("x"))));
    let mut no_schema = base();
    no_schema.as_object_mut().unwrap().remove("schema");
    assert!(!wire_ok(no_schema));
    assert!(!wire_ok(with("root", json!(b64(&[7u8; 31])))));
    // acc: 16 / 17 entries, id 64 / 65 bytes and charset, distinct, post integral
    let accs = |n: usize| Value::Array((0..n).map(|i| json!({"id": format!("a{i}"), "post": 0})).collect());
    assert!(wire_ok(with("acc", accs(16))));
    assert!(!wire_ok(with("acc", accs(17))));
    assert!(wire_ok(with("acc", json!([{"id": "a".repeat(64), "post": 0}]))));
    assert!(!wire_ok(with("acc", json!([{"id": "a".repeat(65), "post": 0}]))));
    assert!(!wire_ok(with("acc", json!([{"id": "a-b", "post": 0}]))));
    assert!(!wire_ok(with("acc", json!([{"id": "a", "post": 1}, {"id": "a", "post": 2}]))));
    assert!(!wire_ok(with("acc", json!([{"id": "a", "post": -1}]))));
    assert!(!wire_ok(with("acc", json!([{"id": "a", "post": 0, "extra": 1}]))));
    assert!(!wire_ok(with("acc", json!([{"id": "a", "post": 0, "receipt": "x"}]))));
    // digest lists: facts 16 / labels 16 / classes 8, distinct, offer_set a digest
    assert!(wire_ok(with("facts", digests(16, "f"))));
    assert!(!wire_ok(with("facts", digests(17, "f"))));
    assert!(!wire_ok(with("facts", json!([d32("x"), d32("x")]))));
    assert!(wire_ok(with("labels", digests(16, "l"))));
    assert!(!wire_ok(with("labels", digests(17, "l"))));
    assert!(wire_ok(with("classes", digests(8, "c"))));
    assert!(!wire_ok(with("classes", digests(9, "c"))));
    assert!(wire_ok(with("offer_set", json!(d32("o")))));
    assert!(!wire_ok(with("offer_set", json!("o"))));
    // prov: 32 / 33 paths, 1..8 refs, 256 / 257 byte refs, the key shape
    let paths = |n: usize| Value::Object((0..n).map(|i| (format!("action.params.p{i}"), json!(["r"]))).collect::<Map<String, Value>>());
    assert!(wire_ok(with("prov", paths(32))));
    assert!(!wire_ok(with("prov", paths(33))));
    let refs = |n: usize| json!({"action.params.total": (0..n).map(|i| format!("r{i}")).collect::<Vec<_>>()});
    assert!(wire_ok(with("prov", refs(8))));
    assert!(!wire_ok(with("prov", refs(9))));
    assert!(!wire_ok(with("prov", refs(0))));
    assert!(wire_ok(with("prov", json!({"action.params.total": ["é".repeat(128)]}))));
    assert!(!wire_ok(with("prov", json!({"action.params.total": [format!("{}x", "é".repeat(128))]}))));
    assert!(!wire_ok(with("prov", json!({"action.params.total": [""]}))));
    assert!(!wire_ok(with("prov", json!({"env.x": ["r"]}))));
    assert!(!wire_ok(with("prov", json!({"action.params.a.b": ["r"]}))));
}

// ---- rule 13: the intent_session check --------------------------------------------------------------------------

#[test]
fn session_delta_chain() {
    let (s, r) = base_root();
    let g0 = grant("principal", 0, None, &r, &map0(), "salt0");
    let d1 = grant("principal", 1, Some(g0["id"].as_str().unwrap()), &r, &map1(), "salt1");
    let mut is1 = is0(&r);
    is1["seq"] = json!(1);
    is1["acc"] = json!([{"id": "trip_spend", "post": 77_800}]);
    let p1 = sign_p(body(&d1, &params(), &map1(), "salt1", Some(is1.clone())));
    let mut c = ctx_json(&s);
    c["acc"]["state"]["trip_spend"]["sum"] = json!(38_900);
    c["session"]["grants"] = json!([g0.clone()]);
    assert_allow(&run(&p1, &d1, &c));
    // the verifier does not hold G_0
    let mut c2 = c.clone();
    c2["session"]["grants"] = json!([]);
    assert_only(&run(&p1, &d1, &c2), &["intent_session"]);
    // an agent-signed delta (T15)
    let forged = grant("agent", 1, Some(g0["id"].as_str().unwrap()), &r, &map1(), "salt1");
    assert_only(&run(&sign_p(body(&forged, &params(), &map1(), "salt1", Some(is1.clone()))), &forged, &c), &["intent_session"]);
    // a broken prev
    let loose = grant("principal", 1, Some(&d32("nope")), &r, &map1(), "salt1");
    assert_only(&run(&sign_p(body(&loose, &params(), &map1(), "salt1", Some(is1.clone()))), &loose, &c), &["intent_session"]);
    // a held grant 0 that is not at seq 0 / not principal-signed
    let mut c3 = c.clone();
    c3["session"]["grants"] = json!([grant("agent", 0, None, &r, &map0(), "salt0")]);
    assert_only(&run(&p1, &d1, &c3), &["intent_session"]);
    // seq 1 under G_0 (caveat seq 0)
    let f = fx();
    let mut is = is0(&r);
    is["seq"] = json!(1);
    let p = sign_p(body(&f.g0, &params(), &map0(), "salt0", Some(is)));
    let mut c4 = f.ctx.clone();
    c4["session"]["grants"] = json!([f.g0.clone()]);
    assert_only(&run(&p, &f.g0, &c4), &["intent_session"]);
    // a seq-0 action must use the session task map
    let gm = grant("principal", 0, None, &r, &map1(), "salt0");
    assert_only(&run(&sign_p(body(&gm, &params(), &map1(), "salt0", Some(is0(&r)))), &gm, &f.ctx), &["intent_session"]);
}

#[test]
fn session_root_binding_and_expiry_boundary() {
    let f = fx();
    // expires_at == now: expired (strict now < expires_at); intent_session and accumulators both fail
    for (exp, ok) in [(NOW, false), (NOW + 1, true)] {
        let (s, r) = root_with(|b| b["expires_at"] = json!(exp));
        let g = grant("principal", 0, None, &r, &map0(), "salt0");
        let p = sign_p(body(&g, &params(), &map0(), "salt0", Some(is0(&r))));
        let v = run(&p, &g, &ctx_json(&s));
        if ok {
            assert_allow(&v);
        } else {
            assert_only(&v, &["accumulators", "intent_session"]);
        }
    }
    // a root signed by a non-principal, a tampered root, a root for another statement / audience
    let (bad, _) = sign_root(root_body(), "stranger");
    let mut c = f.ctx.clone();
    c["session"]["root"] = bad;
    assert_only(&run(&f.p0, &f.g0, &c), &["accumulators", "intent_session"]);
    let (mut s, _) = base_root();
    s["question_uri"] = json!("https://evil.example/q");
    let mut c = f.ctx.clone();
    c["session"]["root"] = s;
    assert_only(&run(&f.p0, &f.g0, &c), &["accumulators", "intent_session"]);
    let (s, r) = root_with(|b| b["intent_ref"] = json!(d32("other")));
    let g = grant("principal", 0, None, &r, &map0(), "salt0");
    let p = sign_p(body(&g, &params(), &map0(), "salt0", Some(is0(&r))));
    assert_only(&run(&p, &g, &ctx_json(&s)), &["intent_session"]);
    let (s, r) = root_with(|b| b["schema"]["aud"] = json!("other.example"));
    let g = grant("principal", 0, None, &r, &map0(), "salt0");
    let p = sign_p(body(&g, &params(), &map0(), "salt0", Some(is0(&r))));
    assert_only(&run(&p, &g, &ctx_json(&s)), &["intent_session"]);
}

#[test]
fn session_caveat_shape() {
    let r = d32("root");
    let ok = |c: Value| intent_session_caveat_error(Some(&c)).is_none();
    assert!(ok(json!({"type": "intent_session", "session": session(), "seq": 0, "root": r})));
    assert!(ok(json!({"type": "intent_session", "session": session(), "seq": 2_147_483_647, "root": r, "prev": r})));
    assert!(!ok(json!({"type": "intent_session", "session": session(), "seq": 2_147_483_648i64, "root": r, "prev": r})));
    assert!(!ok(json!({"type": "intent_session", "session": session(), "seq": 0, "root": r, "prev": r})));
    assert!(!ok(json!({"type": "intent_session", "session": session(), "seq": 1, "root": r})));
    assert!(!ok(json!({"type": "intent_session", "session": session(), "seq": 0, "root": r, "x": 1})));
    // rule 10: a well-formed caveat is satisfied, a malformed one is not
    let ctx = json!({"now": NOW});
    assert!(evaluate_caveats(&json!([{"type": "intent_session", "session": session(), "seq": 0, "root": r}]), &ctx).0);
    assert!(!evaluate_caveats(&json!([{"type": "intent_session", "session": session(), "seq": 1, "root": r}]), &ctx).0);
    assert!(!evaluate_caveats(&json!([{"type": "intent_session", "session": session(), "seq": 0, "root": r}]), &json!({})).0);
}

// ---- rule 13 step 7: revocation ---------------------------------------------------------------------------------

const REVOKED: &str = "pca-intent:zzzz";

/// The revocation authority's epoch over the FULL revoked `list` (sorted here; `epoch == set_size == |list|`).
fn epoch_over(signer: &str, list: &[String], issued: i64, not_after: i64, scope: &str) -> Value {
    let mut l = list.to_vec();
    l.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    let root = revset_root(&l).unwrap();
    let body = json!({"instance_id": "ana", "grant_ref": scope, "epoch": l.len(), "set_size": l.len(), "root": root, "issued_at": issued, "not_after": not_after});
    let sig = sign_domain(signer, "atlas-pca/revepoch/v1\0", &body);
    let mut e = body;
    e["guardian"] = json!(pk(signer));
    e["sig"] = json!(sig);
    e
}
/// Evidence `{epoch, revoked}` over `list`.
fn evidence(signer: &str, list: &[&str], issued: i64, not_after: i64, scope: &str) -> Value {
    let mut l: Vec<String> = list.iter().map(|x| x.to_string()).collect();
    l.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    json!({"epoch": epoch_over(signer, &l, issued, not_after, scope), "revoked": l})
}
fn rev(ev: &Value, ids: &[String], max_age_ms: f64, last: Option<&Value>) -> Result<(), String> {
    check_session_revocation(Some(ev), &session(), &pk("revauth"), ids, NOW as f64, max_age_ms, None, None, last)
}

#[test]
fn revocation_epoch_boundaries() {
    let scope = session_revocation_scope(&session());
    let ids = vec![session_revocation_id(&session()), map_revocation_id(&map0())];
    let ev = |issued: i64, not_after: i64| evidence("revauth", &[REVOKED], issued, not_after, &scope);
    assert!(rev(&ev(NOW - 10_000, NOW + 1), &ids, 60_000.0, None).is_ok());
    // max age inclusive
    assert!(rev(&ev(NOW - 60_000, NOW + 1), &ids, 60_000.0, None).is_ok());
    assert!(rev(&ev(NOW - 60_001, NOW + 1), &ids, 60_000.0, None).is_err());
    // not_after inclusive
    assert!(rev(&ev(NOW - 1, NOW), &ids, 60_000.0, None).is_ok());
    assert!(rev(&ev(NOW - 1, NOW - 1), &ids, 60_000.0, None).is_err());
    // issued_at future skew inclusive (60 s)
    assert!(rev(&ev(NOW + 60_000, NOW + 120_000), &ids, 60_000.0, None).is_ok());
    assert!(rev(&ev(NOW + 60_001, NOW + 120_000), &ids, 60_000.0, None).is_err());
    // misconfigured max age (negative, -0, fractional, above 2^53-1); 0 is a valid (strictest) bound
    for bad in [-1.0, -0.0, 0.5, 9_007_199_254_740_992.0] {
        assert!(rev(&ev(NOW, NOW + 1), &ids, bad, None).is_err(), "{bad}");
    }
    assert!(rev(&ev(NOW, NOW + 1), &ids, 0.0, None).is_ok());
    // an empty set (epoch 0)
    assert!(rev(&evidence("revauth", &[], NOW, NOW + 1, &scope), &ids, 60_000.0, None).is_ok());
    // ONLY the dedicated authority: a principal's or a stranger's epoch is refused; another scope; a revoked id
    assert!(rev(&evidence("principal", &[REVOKED], NOW, NOW + 1, &scope), &ids, 60_000.0, None).is_err());
    assert!(rev(&evidence("stranger", &[REVOKED], NOW, NOW + 1, &scope), &ids, 60_000.0, None).is_err());
    assert!(rev(&evidence("revauth", &[REVOKED], NOW, NOW + 1, &session_revocation_scope(&d32("s2"))), &ids, 60_000.0, None).is_err());
    assert!(rev(&evidence("revauth", &[REVOKED, &ids[1]], NOW, NOW + 1, &scope), &ids, 60_000.0, None).unwrap_err().contains("revoked"));
    assert!(check_session_revocation(None, &session(), &pk("revauth"), &ids, NOW as f64, 60_000.0, None, None, None).is_err());
    assert!(check_session_revocation(Some(&ev(NOW, NOW + 1)), &session(), &pk("revauth"), &ids, 1.5, 60_000.0, None, None, None).is_err());
}

#[test]
fn revoked_list_is_the_full_signed_set() {
    let scope = session_revocation_scope(&session());
    let ids = vec![session_revocation_id(&session())];
    let good = evidence("revauth", &["pca-intent:a", "pca-intent:b", REVOKED], NOW, NOW + 1, &scope);
    assert!(rev(&good, &ids, 60_000.0, None).is_ok());
    let with = |v: Value| {
        let mut e = good.clone();
        e["revoked"] = v;
        rev(&e, &ids, 60_000.0, None).is_err()
    };
    assert!(with(json!(null)));
    assert!(with(json!("pca-intent:a")));
    assert!(with(json!(["pca-intent:a", "pca-intent:b"]))); // short (set_size 3)
    assert!(with(json!(["pca-intent:b", "pca-intent:a", REVOKED]))); // unsorted
    assert!(with(json!(["pca-intent:a", "pca-intent:a", REVOKED]))); // repeating
    assert!(with(json!(["pca-intent:a", "pca-intent:c", REVOKED]))); // swapped: root mismatch
    assert!(with(json!(["pca-intent:a", 5, REVOKED])));
    // epoch must equal set_size: re-sign with epoch 4 over 3 ids
    let l: Vec<String> = ["pca-intent:a", "pca-intent:b", REVOKED].iter().map(|x| x.to_string()).collect();
    let mut body = json!({"instance_id": "ana", "grant_ref": scope, "epoch": 4, "set_size": 3, "root": revset_root(&l).unwrap(), "issued_at": NOW, "not_after": NOW + 1});
    let sig = sign_domain("revauth", "atlas-pca/revepoch/v1\0", &body);
    body["guardian"] = json!(pk("revauth"));
    body["sig"] = json!(sig);
    assert!(rev(&json!({"epoch": body, "revoked": l}), &ids, 60_000.0, None).is_err());
}

#[test]
fn revocation_is_append_only_against_the_last_epoch() {
    let scope = session_revocation_scope(&session());
    let ids = vec![session_revocation_id(&session())];
    let last = evidence("revauth", &["pca-intent:a"], NOW - 5_000, NOW + 1, &scope);
    // an extension and a re-presentation of the same epoch are fine
    assert!(rev(&evidence("revauth", &["pca-intent:a", "pca-intent:b"], NOW, NOW + 1, &scope), &ids, 60_000.0, Some(&last)).is_ok());
    assert!(rev(&last, &ids, 60_000.0, Some(&last)).is_ok());
    // DROP (same size and larger), rollback, equivocation
    assert!(rev(&evidence("revauth", &["pca-intent:b"], NOW, NOW + 1, &scope), &ids, 60_000.0, Some(&last)).unwrap_err().contains("drops"));
    assert!(rev(&evidence("revauth", &["pca-intent:b", "pca-intent:c"], NOW, NOW + 1, &scope), &ids, 60_000.0, Some(&last)).unwrap_err().contains("drops"));
    assert!(rev(&evidence("revauth", &[], NOW, NOW + 1, &scope), &ids, 60_000.0, Some(&last)).unwrap_err().contains("rollback"));
    let last2 = evidence("revauth", &["pca-intent:a", "pca-intent:b"], NOW - 5_000, NOW + 1, &scope);
    let eq = evidence("revauth", &["pca-intent:a", "pca-intent:c"], NOW, NOW + 1, &scope);
    assert!(rev(&eq, &ids, 60_000.0, Some(&last2)).is_err());
    // a malformed tracked epoch fails closed
    let mut bad = last.clone();
    bad["revoked"] = json!(["pca-intent:z"]);
    assert!(rev(&evidence("revauth", &["pca-intent:a"], NOW, NOW + 1, &scope), &ids, 60_000.0, Some(&bad)).unwrap_err().contains("malformed"));
    assert!(rev(&last, &ids, 60_000.0, Some(&json!(null))).is_err());
}

#[test]
fn session_revocation_in_the_pipeline() {
    let rv = json!({"epoch_uri": "https://atlas.example/rev", "max_age_s": 60, "key": pk("revauth")});
    let (s, r) = root_with(|b| b["revocation"] = rv.clone());
    let g = grant("principal", 0, None, &r, &map0(), "salt0");
    let p = sign_p(body(&g, &params(), &map0(), "salt0", Some(is0(&r))));
    let scope = session_revocation_scope(&session());
    let with_ev = |issued: i64, policy: Option<Value>| {
        let mut c = ctx_json(&s);
        c["session"]["revocation"] = evidence("revauth", &[REVOKED], issued, issued + 300_000, &scope);
        if let Some(p) = policy {
            c["policy"] = p;
        }
        c
    };
    assert_allow(&run(&p, &g, &with_ev(NOW - 60_000, None)));
    assert_only(&run(&p, &g, &with_ev(NOW - 60_001, None)), &["intent_session"]);
    assert_only(&run(&p, &g, &ctx_json(&s)), &["intent_session"]);
    // the stricter policy bound applies; a malformed policy age is a malformed context
    let pol = |x: Value| Some(json!({"session": {"max_revocation_age_s": x}}));
    assert_allow(&run(&p, &g, &with_ev(NOW - 10_000, pol(json!(10)))));
    assert_only(&run(&p, &g, &with_ev(NOW - 10_001, pol(json!(10)))), &["intent_session"]);
    for bad in [json!(-1), json!(1.5), json!("10"), json!(-0.0), json!(null)] {
        assert_only(&run(&p, &g, &with_ev(NOW, pol(bad))), TOP);
    }
    // the admitting grant's delta id revoked; a tracked last epoch the evidence drops
    let mut c = with_ev(NOW, None);
    c["session"]["revocation"] = evidence("revauth", &[REVOKED, &delta_revocation_id(g["id"].as_str().unwrap())], NOW, NOW + 1, &scope);
    assert_only(&run(&p, &g, &c), &["intent_session"]);
    let mut c = with_ev(NOW, None);
    c["session"]["revocation_last"] = evidence("revauth", &["pca-intent:a", REVOKED], NOW - 1_000, NOW + 1, &scope);
    assert_only(&run(&p, &g, &c), &["intent_session"]);
    let mut c = with_ev(NOW, None);
    c["session"]["revocation_last"] = evidence("revauth", &[REVOKED], NOW - 1_000, NOW + 1, &scope);
    assert_allow(&run(&p, &g, &c));
    c["session"]["revocation_last"] = json!(null);
    assert_only(&run(&p, &g, &c), &["intent_session"]);
    // a policy age with no authority in S fails
    let (s2, r2) = base_root();
    let _ = r2;
    let mut c = ctx_json(&s2);
    c["policy"] = json!({"session": {"max_revocation_age_s": 60}});
    assert_only(&run(&f_p0(), &fx().g0, &c), &["intent_session"]);
}

/// The base fixture's PCActn.
fn f_p0() -> Value {
    fx().p0
}

// ---- rule 14: schema ----------------------------------------------------------------------------------------------

fn conform(verb: &str, p: Value) -> ConformResult {
    conform_action(&schema(), verb, &p)
}
fn with_param(k: &str, v: Value) -> Value {
    let mut p = params();
    p[k] = v;
    p
}

#[test]
fn schema_signature_and_digest() {
    assert!(verify_action_schema(&schema(), &schema_keys()).is_ok());
    assert!(verify_action_schema(&sign_schema(unsigned_schema(), "stranger"), &schema_keys()).is_err());
    assert!(verify_action_schema(&schema(), &json!([{"kid": "other", "alg": "ed25519", "pk": pk("site")}])).is_err());
    let mut alg = schema();
    alg["sig"]["alg"] = json!("ml-dsa-65");
    assert!(verify_action_schema(&alg, &schema_keys()).is_err());
    let mut tampered = schema();
    tampered["version"] = json!("x");
    assert!(verify_action_schema(&tampered, &schema_keys()).is_err());
    let mut extra = schema();
    extra["extra"] = json!(1);
    assert!(verify_action_schema(&extra, &schema_keys()).is_err());
    // a key entry without `alg` is ed25519
    assert!(verify_action_schema(&schema(), &json!([{"kid": "skyair-2026", "pk": pk("site")}])).is_ok());
    assert_ne!(action_schema_digest(&schema()), action_schema_digest(&tampered));
}

#[test]
fn conformance_order_and_codes() {
    let code = |r: ConformResult| (r.code.unwrap_or_default(), r.path.unwrap_or_default());
    assert!(conform("air.book", params()).ok);
    assert_eq!(code(conform("air.book", json!([]))).0, "params_not_object");
    assert_eq!(code(conform("air.cancel", params())).0, "unknown_verb");
    // undeclared keys in UTF-8 byte order, before missing
    let mut p = params();
    p["zz"] = json!(1);
    p["aa"] = json!(1);
    assert_eq!(code(conform("air.book", p)), ("undeclared_param".into(), "action.params.aa".into()));
    assert_eq!(code(conform("air.book", json!({"offer_id": "x", "extra": 1}))).0, "undeclared_param");
    assert_eq!(code(conform("air.book", json!({}))), ("missing_param".into(), "action.params.add_ons".into()));
    // integer domain (inclusive bounds), -0 and fractions are not safe integers
    assert!(conform("air.book", with_param("total", json!(0))).ok);
    assert!(conform("air.book", with_param("total", json!(5_000_000))).ok);
    assert_eq!(code(conform("air.book", with_param("total", json!(5_000_001)))).0, "out_of_domain");
    assert_eq!(code(conform("air.book", with_param("total", json!(-1)))).0, "out_of_domain");
    assert_eq!(code(conform("air.book", with_param("total", json!(1.5)))).0, "bad_type");
    assert_eq!(code(conform("air.book", with_param("total", json!(-0.0)))).0, "bad_type");
    assert_eq!(code(conform("air.book", with_param("total", json!("38900")))).0, "bad_type");
    assert_eq!(code(conform("air.book", with_param("refundable", json!("false")))).0, "bad_type");
    // strings: max_len in UTF-8 bytes (16), inclusive
    assert!(conform("air.book", with_param("note", json!("é".repeat(8)))).ok);
    assert_eq!(code(conform("air.book", with_param("note", json!(format!("{}a", "é".repeat(8)))))).0, "out_of_domain");
    // sets
    assert!(conform("air.book", with_param("add_ons", json!([]))).ok);
    assert!(conform("air.book", with_param("add_ons", json!(["none", "tripshield", "seat_plus"]))).ok);
    assert_eq!(code(conform("air.book", with_param("add_ons", json!(["none", "none"])))).0, "out_of_domain");
    assert_eq!(code(conform("air.book", with_param("add_ons", json!(["bag"])))).0, "out_of_domain");
    assert_eq!(code(conform("air.book", with_param("add_ons", json!([1])))).0, "bad_type");
    // arrays: max_items 9, item max_len 64
    let pax = |n: usize| json!((0..n).map(|i| format!("p{i}")).collect::<Vec<_>>());
    assert!(conform("air.book", with_param("passengers", pax(9))).ok);
    assert_eq!(code(conform("air.book", with_param("passengers", pax(10)))).0, "out_of_domain");
    assert!(conform("air.book", with_param("passengers", json!(["x".repeat(64)]))).ok);
    assert_eq!(code(conform("air.book", with_param("passengers", json!(["x".repeat(65)])))).0, "bad_type");
    // enum strings and dates (leap rules)
    let search = |from: &str, date: &str| conform("air.search", json!({"from": from, "date": date, "pax": 2}));
    assert_eq!(code(search("LAX", "2026-11-20")).0, "out_of_domain");
    assert!(search("SFO", "2028-02-29").ok);
    assert!(search("SFO", "2000-02-29").ok);
    assert_eq!(code(search("SFO", "2026-02-29")).0, "out_of_domain");
    assert_eq!(code(search("SFO", "1900-02-29")).0, "out_of_domain");
    assert_eq!(code(search("SFO", "2026-1-05")).0, "out_of_domain");
    assert_eq!(code(search("SFO", "0000-01-01")).0, "out_of_domain");
    assert!(search("SFO", "0001-01-01").ok);
    assert!(search("SFO", "2026-12-31").ok);
    assert_eq!(code(search("SFO", "2026-13-01")).0, "out_of_domain");
    assert_eq!(code(search("SFO", "2026-04-31")).0, "out_of_domain");
}

#[test]
fn schema_check_in_the_pipeline() {
    let f = fx();
    let bad = |p: Value| {
        let (_, r) = base_root();
        let pc = sign_p(body(&f.g0, &p, &map0(), "salt0", Some(is0(&r))));
        let mut c = f.ctx.clone();
        c["params"] = p;
        run(&pc, &f.g0, &c)
    };
    assert_only(&bad(with_param("reseller", json!("x"))), &["schema"]);
    assert_only(&bad(with_param("add_ons", json!(["bag"]))), &["schema"]);
    // unknown digest: schema and accumulators (accumulates_into needs the session schema)
    let mut c = f.ctx.clone();
    let mut other = unsigned_schema();
    other["version"] = json!("v2");
    c["schema"]["docs"] = json!([sign_schema(other, "site")]);
    assert_only(&run(&f.p0, &f.g0, &c), &["accumulators", "schema"]);
    // forged schema, no schema, no params
    let mut c = f.ctx.clone();
    c["schema"]["keys"] = json!([{"kid": "skyair-2026", "alg": "ed25519", "pk": pk("stranger")}]);
    assert_only(&run(&f.p0, &f.g0, &c), &["schema"]);
    let mut c = f.ctx.clone();
    c["schema"]["docs"] = json!([]);
    assert_only(&run(&f.p0, &f.g0, &c), &["accumulators", "schema"]);
    let mut c = f.ctx.clone();
    c.as_object_mut().unwrap().remove("params");
    assert_only(&run(&f.p0, &f.g0, &c), &["accumulators", "schema"]);
}

// ---- layers (V5) ---------------------------------------------------------------------------------------------------

#[test]
fn layer_ceilings() {
    let f = fx();
    let with = |layers: Value| {
        let mut c = f.ctx.clone();
        c["layers"] = layers;
        run(&f.p0, &f.g0, &c)
    };
    let site = json!({"site": {"predicates": [{"verb": "air.book", "where": [{"field": "env.canon.add_ons", "op": "eq", "value": "[\"none\"]"}]}]}});
    let v = with(site);
    assert_allow(&v);
    assert_eq!(v.checks.get("layers"), Some(&true));
    assert_allow(&with(json!({})));
    // a malformed ceiling (null, no predicate list, not an object) or layers member is a malformed context
    for bad in [json!({"org": null}), json!(null), json!({"std": {}}), json!({"org": 5}), json!({"other": {"predicates": []}}), json!([])] {
        assert_only(&with(bad.clone()), TOP);
    }
    assert_only(&with(json!({"site": {"predicates": []}})), &["layers"]);
    // inclusive comparison at the boundary
    let cap = |op: &str, x: i64| json!({"org": {"predicates": [{"verb": "*", "where": [{"field": "action.params.total", "op": op, "value": x}]}]}});
    assert_allow(&with(cap("lte", 38_900)));
    assert_only(&with(cap("lte", 38_899)), &["layers"]);
    assert_only(&with(cap("lt", 38_900)), &["layers"]);
    // env.canon is absent when the schema check failed
    let mut c = f.ctx.clone();
    c["schema"]["docs"] = json!([]);
    c["layers"] = json!({"site": {"predicates": [{"verb": "air.book", "where": [{"field": "env.canon.add_ons", "op": "exists"}]}]}});
    assert!(failed(&run(&f.p0, &f.g0, &c)).contains(&"layers".to_string()));
}

// ---- rule 15: accumulators --------------------------------------------------------------------------------------

fn with_acc(f: &Fx, claim_post: i64, pre_sum: Value) -> Verdict {
    let (_, r) = base_root();
    let mut is = is0(&r);
    is["acc"] = json!([{"id": "trip_spend", "post": claim_post}]);
    let p = sign_p(body(&f.g0, &params(), &map0(), "salt0", Some(is)));
    let mut c = f.ctx.clone();
    c["acc"]["state"]["trip_spend"] = pre_sum;
    run(&p, &f.g0, &c)
}

#[test]
fn site_local_arithmetic_and_domain_boundary() {
    let f = fx();
    assert_allow(&with_acc(&f, 38_900, json!({"sum": 0})));
    assert_only(&with_acc(&f, 38_899, json!({"sum": 0})), &["accumulators"]);
    assert_allow(&with_acc(&f, 500_000, json!({"sum": 461_100})));
    assert_only(&with_acc(&f, 500_001, json!({"sum": 461_101})), &["accumulators"]);
    assert_only(&with_acc(&f, 38_900, json!({"count": 0})), &["accumulators"]);
    assert_only(&with_acc(&f, 38_900, json!({"sum": -1})), &["accumulators"]);
    assert_only(&with_acc(&f, 38_900, json!({"sum": 0, "x": 1})), &["accumulators"]);
    // overflow past 2^53-1 fails closed
    let (s, r) = root_with(|b| b["accumulators"][0].as_object_mut().unwrap().remove("domain_max").map(|_| ()).unwrap_or(()));
    let g = grant("principal", 0, None, &r, &map0(), "salt0");
    let mut is = is0(&r);
    is["acc"] = json!([{"id": "trip_spend", "post": MAX_SAFE}]);
    let p = sign_p(body(&g, &params(), &map0(), "salt0", Some(is)));
    let mut c = ctx_json(&s);
    c["acc"]["state"]["trip_spend"] = json!({"sum": MAX_SAFE - 38_900});
    assert_allow(&run(&p, &g, &c));
    c["acc"]["state"]["trip_spend"] = json!({"sum": MAX_SAFE - 38_899});
    assert_only(&run(&p, &g, &c), &["accumulators"]);
}

#[test]
fn claims_and_monitors() {
    let f = fx();
    let (_, r) = base_root();
    let claims = |acc: Value| {
        let mut is = is0(&r);
        is["acc"] = acc;
        run(&sign_p(body(&f.g0, &params(), &map0(), "salt0", Some(is))), &f.g0, &f.ctx)
    };
    assert_only(&claims(json!([])), &["accumulators"]);
    assert_only(&claims(json!([{"id": "trip_spend", "post": 38_900}, {"id": "nope", "post": 0}])), &["accumulators"]);
    assert_only(&claims(json!([{"id": "trip_spend", "post": 38_900}, {"id": "questions", "post": 1}])), &["accumulators"]);
    let mut c = f.ctx.clone();
    c["acc"]["state"] = json!({});
    assert_only(&run(&f.p0, &f.g0, &c), &["accumulators"]);
    // monitors: every state of Q, nothing else
    let mon = json!({"id": "w", "kind": "responds_within", "p": {"verb": "a"}, "q": {"verb": "b"}, "within": 3});
    let (s, rm) = root_with(|b| b["monitors"] = json!([mon]));
    let g = grant("principal", 0, None, &rm, &map0(), "salt0");
    let p = sign_p(body(&g, &params(), &map0(), "salt0", Some(is0(&rm))));
    for (state, ok) in [("idle", true), ("pending:1", true), ("pending:3", true), ("missed", true), ("pending:0", false), ("pending:4", false), ("met", false)] {
        let mut c = ctx_json(&s);
        c["acc"]["monitors"] = json!({"w": state});
        assert_eq!(run(&p, &g, &c).allow, ok, "{state}");
    }
    let c = ctx_json(&s);
    assert_only(&run(&p, &g, &c), &["accumulators"]);
    // within 1..64
    for (w, ok) in [(1, true), (64, true), (0, false), (65, false)] {
        let m = json!({"id": "w", "kind": "responds_within", "p": {"verb": "a"}, "q": {"verb": "b"}, "within": w});
        let (sv, _) = root_with(|b| b["monitors"] = json!([m]));
        assert_eq!(verify_session_root(&sv).is_ok(), ok, "within {w}");
    }
}

#[test]
fn distinct_max_and_keyed_count() {
    let dist = json!({"id": "payees", "agg": "distinct", "val": "action.params.offer_id", "sel": {"verbs": ["air.book"]}, "win": {"kind": "task"}, "key": null, "domain_max": 3, "holder": {"kind": "site_local"}});
    let max = json!({"id": "largest", "agg": "max", "val": "action.params.total", "sel": {"verbs": ["air.book"]}, "win": {"kind": "task"}, "key": null, "holder": {"kind": "site_local"}});
    let cnt = json!({"id": "per_offer", "agg": "count", "sel": {"verbs": ["air.book"]}, "win": {"kind": "sliding", "ms": 60_000}, "key": "action.params.offer_id", "domain_max": 1, "holder": {"kind": "site_local"}});
    let (s, r) = root_with(|b| b["accumulators"] = json!([dist, max, cnt]));
    let g = grant("principal", 0, None, &r, &map0(), "salt0");
    let go = |acc: Value, state: Value| {
        let mut is = is0(&r);
        is["acc"] = acc;
        let p = sign_p(body(&g, &params(), &map0(), "salt0", Some(is)));
        let mut c = ctx_json(&s);
        c["acc"]["state"] = state;
        run(&p, &g, &c)
    };
    let good = json!([{"id": "payees", "post": 2}, {"id": "largest", "post": 40_000}, {"id": "per_offer", "post": 1}]);
    let st = json!({"payees": {"values": ["\"OF-1\"", "\"OF-9\""]}, "largest": {"max": 40_000}, "per_offer": {"count": 0}});
    assert_allow(&go(good.clone(), st.clone()));
    let mut st2 = st.clone();
    st2["payees"] = json!({"values": ["\"OF-7\"", "\"OF-9\""]});
    assert_only(&go(good.clone(), st2), &["accumulators"]);
    let mut st3 = st.clone();
    st3["per_offer"] = json!({"count": 1});
    assert_only(&go(json!([{"id": "payees", "post": 2}, {"id": "largest", "post": 40_000}, {"id": "per_offer", "post": 2}]), st3), &["accumulators"]);
    let mut st4 = st.clone();
    st4["payees"] = json!({"values": ["\"OF-1\"", "\"OF-1\""]});
    assert_only(&go(good.clone(), st4), &["accumulators"]);
    // max takes the larger of pre and val
    let mut st5 = st.clone();
    st5["largest"] = json!({"max": 1});
    assert_only(&go(good, st5), &["accumulators"]);
}

// ---- rule 15: sequenced holders, root-signed key sets, receipts ---------------------------------------------------

fn seq_holder() -> Value {
    json!({"kind": "sequenced", "uri": "https://atlas.example/seq", "root": pk("seqroot")})
}
fn key_set(signer: &str, entries: Value) -> Value {
    key_set_at(signer, entries, 1, NOW - 1_000_000)
}
fn key_set_at(signer: &str, entries: Value, version: i64, issued_at: i64) -> Value {
    let body = json!({"v": 1, "kind": "pca-sequencer-keys", "sequencer": pk(signer), "version": version, "issued_at": issued_at, "keys": entries});
    signed(signer, "atlas-pca/sequencer-keys/v1\0", body)
}
fn entry(kid: &str, signer: &str, not_before: i64, not_after: Option<i64>) -> Value {
    let mut e = json!({"kid": kid, "pk": pk(signer), "not_before": not_before});
    if let Some(na) = not_after {
        e["not_after"] = json!(na);
    }
    e
}

struct SeqFx {
    s: Value,
    g: Value,
    r: String,
}
fn seq_fx() -> SeqFx {
    let mut t = trip();
    t["holder"] = seq_holder();
    let (s, r) = root_with(|b| b["accumulators"] = json!([t]));
    let g = grant("principal", 0, None, &r, &map0(), "salt0");
    SeqFx { s, g, r }
}
fn receipt(fx: &SeqFx, signer: &str, kid: &str, edit: impl FnOnce(&mut Value)) -> Value {
    let draft = body(&fx.g, &params(), &map0(), "salt0", None);
    let mut b = json!({
        "v": 1, "kind": "pca-acc-receipt", "session": session(), "acc": "trip_spend", "seq": 3, "pre": 10_000, "delta": 38_900, "post": 48_900,
        "pcactn_digest": pcactn_reservation_digest(&draft).unwrap(), "aud": AUD, "issued_at": NOW - 1_000, "expires_at": NOW + 60_000,
        "kid": kid, "ledger": {"index": 7, "head": d32("head")}, "signer": pk(signer)
    });
    edit(&mut b);
    signed(signer, "atlas-pca/acc-receipt/v1\0", b)
}
fn run_seq(fx: &SeqFx, rc: &Value, sets: Value, last: Option<Value>) -> Verdict {
    let mut is = is0(&fx.r);
    is["acc"] = json!([{"id": "trip_spend", "post": rc["post"], "receipt": acc_receipt_digest(rc).unwrap()}]);
    let p = sign_p(body(&fx.g, &params(), &map0(), "salt0", Some(is)));
    let mut c = ctx_json(&fx.s);
    c["acc"] = json!({"receipts": [rc], "monitors": {}, "sequencer_keys": sets});
    if let Some(l) = last {
        c["acc"]["last_seq"] = json!({"trip_spend": l});
    }
    run(&p, &fx.g, &c)
}

#[test]
fn sequenced_receipt_admits() {
    let fx = seq_fx();
    let rc = receipt(&fx, "seq1", "k1", |_| {});
    assert_allow(&run_seq(&fx, &rc, json!([key_set("seqroot", json!([entry("k1", "seq1", 0, None)]))]), None));
}

#[test]
fn key_window_and_skew_boundaries() {
    let fx = seq_fx();
    let issued = NOW - 1_000;
    let rc = receipt(&fx, "seq1", "k1", |_| {});
    let one = |e: Value| json!([key_set("seqroot", json!([e]))]);
    // not_before <= issued_at (inclusive)
    assert_allow(&run_seq(&fx, &rc, one(entry("k1", "seq1", issued, None)), None));
    assert_only(&run_seq(&fx, &rc, one(entry("k1", "seq1", issued + 1, None)), None), &["accumulators"]);
    // issued_at <= not_after (inclusive): a retired key signs nothing after its not_after
    assert_allow(&run_seq(&fx, &rc, one(entry("k1", "seq1", 0, Some(issued))), None));
    assert_only(&run_seq(&fx, &rc, one(entry("k1", "seq1", 0, Some(issued - 1))), None), &["accumulators"]);
    // a rotated set: the retired key verifies receipts it issued in its window, the new key the later ones
    let rotated = json!([key_set("seqroot", json!([entry("k1", "seq1", 0, Some(issued)), entry("k2", "seq2", issued + 1, None)]))]);
    assert_allow(&run_seq(&fx, &rc, rotated.clone(), None));
    let late = receipt(&fx, "seq1", "k1", |b| b["issued_at"] = json!(issued + 1));
    assert_only(&run_seq(&fx, &late, rotated.clone(), None), &["accumulators"]);
    let k2 = receipt(&fx, "seq2", "k2", |b| b["issued_at"] = json!(issued + 1));
    assert_allow(&run_seq(&fx, &k2, rotated, None));
    // issued_at <= now + 60000 (inclusive)
    let open = one(entry("k1", "seq1", 0, None));
    let at = receipt(&fx, "seq1", "k1", |b| b["issued_at"] = json!(NOW + 60_000));
    assert_allow(&run_seq(&fx, &at, open.clone(), None));
    let past = receipt(&fx, "seq1", "k1", |b| b["issued_at"] = json!(NOW + 60_001));
    assert_only(&run_seq(&fx, &past, open, None), &["accumulators"]);
}

#[test]
fn key_set_refusals() {
    let fx = seq_fx();
    let rc = receipt(&fx, "seq1", "k1", |_| {});
    let good = || key_set("seqroot", json!([entry("k1", "seq1", 0, None)]));
    // a missing set, a foreign set (signed by another root), a set signed by the signing key itself
    assert_only(&run_seq(&fx, &rc, json!([]), None), &["accumulators"]);
    assert_only(&run_seq(&fx, &rc, json!(null), None), &["accumulators"]);
    assert_only(&run_seq(&fx, &rc, json!([key_set("stranger", json!([entry("k1", "seq1", 0, None)]))]), None), &["accumulators"]);
    assert_only(&run_seq(&fx, &rc, json!([key_set("seq1", json!([entry("k1", "seq1", 0, None)]))]), None), &["accumulators"]);
    // a foreign set first, then the root's: SOME presented set verifies
    assert_allow(&run_seq(&fx, &rc, json!([key_set("stranger", json!([entry("k1", "seq1", 0, None)])), good()]), None));
    // the kid names another key, the kid is unknown, a tampered set
    assert_only(&run_seq(&fx, &rc, json!([key_set("seqroot", json!([entry("k1", "seq2", 0, None)]))]), None), &["accumulators"]);
    assert_only(&run_seq(&fx, &rc, json!([key_set("seqroot", json!([entry("k9", "seq1", 0, None)]))]), None), &["accumulators"]);
    let mut t = good();
    t["issued_at"] = json!(1);
    assert_only(&run_seq(&fx, &rc, json!([t]), None), &["accumulators"]);
    // the entry suite must equal the receipt's
    let mut e = entry("k1", "seq1", 0, None);
    e["alg"] = json!("ml-dsa-65");
    assert_only(&run_seq(&fx, &rc, json!([key_set("seqroot", json!([e]))]), None), &["accumulators"]);
    // a receipt signed by another key under the listed kid
    let forged = receipt(&fx, "stranger", "k1", |_| {});
    assert_only(&run_seq(&fx, &forged, json!([good()]), None), &["accumulators"]);
    // key-set shape: duplicate kids, not_after < not_before, 256 / 257 entries
    assert!(!run_seq(&fx, &rc, json!([key_set("seqroot", json!([entry("k1", "seq1", 0, None), entry("k1", "seq1", 0, None)]))]), None).allow);
    assert!(!run_seq(&fx, &rc, json!([key_set("seqroot", json!([entry("k1", "seq1", 10, Some(9))]))]), None).allow);
    let many = |n: usize| {
        let mut es: Vec<Value> = (0..n - 1).map(|i| entry(&format!("x{i}"), "stranger", 0, None)).collect();
        es.push(entry("k1", "seq1", 0, None));
        json!([key_set("seqroot", Value::Array(es))])
    };
    assert_allow(&run_seq(&fx, &rc, many(256), None));
    assert_only(&run_seq(&fx, &rc, many(257), None), &["accumulators"]);
}

#[test]
fn receipt_binding_replay_and_arithmetic() {
    let fx = seq_fx();
    let set = || json!([key_set("seqroot", json!([entry("k1", "seq1", 0, None)]))]);
    let rc = receipt(&fx, "seq1", "k1", |_| {});
    // replay: seq must be ABOVE the last accepted one
    assert_allow(&run_seq(&fx, &rc, set(), Some(json!(2))));
    assert_only(&run_seq(&fx, &rc, set(), Some(json!(3))), &["accumulators"]);
    // a last accepted seq that is not a non-negative safe integer (null included) is malformed: fail closed
    for bad in [json!(null), json!("2"), json!(2.5), json!(-1)] {
        assert_only(&run_seq(&fx, &rc, set(), Some(bad)), &["accumulators"]);
    }
    // expiry inclusive
    let at = receipt(&fx, "seq1", "k1", |b| b["expires_at"] = json!(NOW));
    assert_allow(&run_seq(&fx, &at, set(), None));
    let late = receipt(&fx, "seq1", "k1", |b| b["expires_at"] = json!(NOW - 1));
    assert_only(&run_seq(&fx, &late, set(), None), &["accumulators"]);
    // bound to the audience, the session, the accumulator and this action
    for edit in [
        |b: &mut Value| b["aud"] = json!("hotel.example"),
        |b: &mut Value| b["session"] = json!(d32("other")),
        |b: &mut Value| b["acc"] = json!("other_acc"),
        |b: &mut Value| b["pcactn_digest"] = json!(d32("other-action")),
        |b: &mut Value| b["post"] = json!(48_901),
        |b: &mut Value| b["delta"] = json!(38_901),
    ] {
        let bad = receipt(&fx, "seq1", "k1", edit);
        assert_only(&run_seq(&fx, &bad, set(), None), &["accumulators"]);
    }
    // a site-local style claim (no receipt) on a sequenced accumulator, and a receipt nobody presented
    let mut is = is0(&fx.r);
    is["acc"] = json!([{"id": "trip_spend", "post": 48_900}]);
    let p = sign_p(body(&fx.g, &params(), &map0(), "salt0", Some(is)));
    let mut c = ctx_json(&fx.s);
    c["acc"] = json!({"receipts": [rc.clone()], "monitors": {}, "sequencer_keys": set()});
    assert_only(&run(&p, &fx.g, &c), &["accumulators"]);
    let mut c = ctx_json(&fx.s);
    c["acc"] = json!({"receipts": [], "monitors": {}, "sequencer_keys": set()});
    let mut is = is0(&fx.r);
    is["acc"] = json!([{"id": "trip_spend", "post": 48_900, "receipt": acc_receipt_digest(&rc).unwrap()}]);
    assert_only(&run(&sign_p(body(&fx.g, &params(), &map0(), "salt0", Some(is))), &fx.g, &c), &["accumulators"]);
}

#[test]
fn unsigned_tamper_fails_signature_and_claim() {
    let f = fx();
    let mut p = f.p0.clone();
    p["intent_session"]["acc"] = json!([{"id": "trip_spend", "post": 1}]);
    assert_only(&run(&p, &f.g0, &f.ctx), &["accumulators", "leaf_signature"]);
}

// ---- W-B in the pipeline: one unit, first failure ends it; a question fails provenance -------------------------

#[test]
fn wb_unit_order_and_question() {
    let f = fx();
    let (_, r) = base_root();
    // a committed fact that is not supplied: facts fails, and provenance / classes are not reported
    let mut is = is0(&r);
    is["facts"] = json!([d32("missing")]);
    is["prov"] = json!({"action.params.offer_id": ["agent:planner"]});
    let p = sign_p(body(&f.g0, &params(), &map0(), "salt0", Some(is)));
    let mut c = f.ctx.clone();
    c["wb"] = json!({"policy": {"classifiers": [{"id": "tone", "param": "action.params.offer_id", "labels": ["x"], "keys": [pk("judge")], "k": 1}]}});
    let v = run(&p, &f.g0, &c);
    assert_only(&v, &["facts"]);
    assert!(!v.checks.contains_key("provenance") && !v.checks.contains_key("classes"));
    // a tainted material value: a question, reported as a FAILED provenance check, and the unit goes on to classes
    let mut is = is0(&r);
    is["prov"] = json!({"action.params.offer_id": ["agent:planner"]});
    let p = sign_p(body(&f.g0, &params(), &map0(), "salt0", Some(is)));
    let mut c = f.ctx.clone();
    c["wb"] = json!({"policy": {"provenance": {"params": {"action.params.offer_id": "material"}}}});
    let v = run(&p, &f.g0, &c);
    assert_only(&v, &["provenance"]);
    assert!(v.reason.contains("intent_required"), "{}", v.reason);
    c["wb"]["policy"]["provenance"]["material_tainted"] = json!("allow");
    assert_allow(&run(&p, &f.g0, &c));
    // no member and no W-B policy: none of the three is reported
    let v = run(&f.p0, &f.g0, &f.ctx);
    assert!(!v.checks.contains_key("facts") && !v.checks.contains_key("provenance") && !v.checks.contains_key("classes"));
    // a policy alone activates its check (provenance with an empty params map passes); a null one does not
    let mut c = f.ctx.clone();
    c["wb"] = json!({"policy": {"provenance": {"params": {}}}});
    assert_eq!(run(&f.p0, &f.g0, &c).checks.get("provenance"), Some(&true));
    c["wb"] = json!({"policy": {"provenance": null}});
    assert_only(&run(&f.p0, &f.g0, &c), TOP);
}

// ---- rule 16 -------------------------------------------------------------------------------------------------------

fn fact(oracle: &str, value: Value, t_obs: i64) -> Value {
    let body = json!({"v": 1, "kind": "pca-fact", "name": "fare", "subject": "OF-2", "value": value, "t_obs": t_obs, "oracle": oracle});
    signed(&format!("oracle-{oracle}"), "atlas-pca/fact/v1\0", body)
}
fn world_policy(min: i64, faulty: i64, n: usize, fresh: i64) -> Value {
    let oracles: Vec<Value> = (0..n).map(|i| json!({"kid": format!("o{i}"), "pk": pk(&format!("oracle-o{i}"))})).collect();
    json!({"worlds": [{"name": "fare", "subject_path": "action.params.offer_id", "oracles": oracles, "freshness_ms": fresh, "min_oracles": min, "max_faulty": faulty}]})
}
fn world(facts: &[Value], policy: Value) -> IntentWorldDecision {
    let refs: Vec<Value> = facts.iter().map(|f| json!(ref_of("atlas-pca/fact-ref/v1", "f", f))).collect();
    decide_intent_world(&json!({
        "now": NOW, "aud": AUD, "session": session(),
        "action": {"verb": "air.book", "resource": "r", "params": {"offer_id": "OF-2", "total": 77_800, "quote": 38_900}},
        "committed": {"facts": refs}, "facts": facts, "policy": policy
    }))
}

#[test]
fn world_median_freshness_and_skew() {
    let three = |a: i64, b: i64, c: i64| vec![fact("o0", json!(a), NOW), fact("o1", json!(b), NOW), fact("o2", json!(c), NOW)];
    let d = world(&three(39_800, 1, 99_999), world_policy(3, 1, 3, 60_000));
    assert!(d.ok, "{}", d.reason);
    assert_eq!(d.world["fare"], json!(39_800));
    // even count: the LOWER median
    let four = vec![fact("o0", json!(10), NOW), fact("o1", json!(20), NOW), fact("o2", json!(30), NOW), fact("o3", json!(40), NOW)];
    assert_eq!(world(&four, world_policy(3, 1, 4, 60_000)).world["fare"], json!(20));
    // freshness inclusive; a stale fact is not counted
    let fr = |t: i64| world(&[fact("o0", json!(5), t)], world_policy(1, 0, 1, 60_000));
    assert!(fr(NOW - 60_000).ok);
    assert!(!fr(NOW - 60_001).ok);
    // future skew inclusive (default 60 s, and a policy skew)
    assert!(fr(NOW + 60_000).ok);
    assert!(!fr(NOW + 60_001).ok);
    let mut p = world_policy(1, 0, 1, 60_000);
    p["skew_ms"] = json!(0);
    assert!(world(&[fact("o0", json!(5), NOW)], p.clone()).ok);
    assert!(!world(&[fact("o0", json!(5), NOW + 1)], p).ok);
    assert_eq!(world(&[fact("o0", json!(5), NOW)], world_policy(1, 0, 1, 60_000)).single_source, vec!["fare".to_string()]);
    // min_oracles >= 2*max_faulty+1 and at least min_oracles pins
    assert!(!world(&three(1, 2, 3), world_policy(2, 1, 3, 60_000)).ok);
    assert!(!world(&three(1, 2, 3), world_policy(3, 1, 2, 60_000)).ok);
    // too few fresh facts; strings must agree; a mix fails
    assert!(!world(&three(1, 2, 3)[..2], world_policy(3, 1, 3, 60_000)).ok);
    let s = |a: &str, b: &str| world(&[fact("o0", json!(a), NOW), fact("o1", json!(b), NOW), fact("o2", json!(a), NOW)], world_policy(3, 1, 3, 60_000));
    assert_eq!(s("gold", "gold").world["fare"], json!("gold"));
    assert!(!s("gold", "silver").ok);
    assert!(!world(&[fact("o0", json!(1), NOW), fact("o1", json!("1"), NOW), fact("o2", json!(1), NOW)], world_policy(3, 1, 3, 60_000)).ok);
    // a duplicate oracle and an unpinned one
    assert!(!world(&[fact("o0", json!(1), NOW), fact("o0", json!(2), NOW - 1)], world_policy(1, 0, 1, 60_000)).ok);
    assert!(!world(&[fact("o9", json!(1), NOW)], world_policy(1, 0, 1, 60_000)).ok);
    // 16 / 17 commitments
    let many = |n: usize| {
        let refs: Vec<Value> = (0..n).map(|i| json!(d32(&format!("c{i}")))).collect();
        decide_intent_world(&json!({"now": NOW, "action": {}, "committed": {"facts": refs}, "policy": {}}))
    };
    assert!(many(16).reason.contains("not supplied"), "{}", many(16).reason);
    assert!(many(17).reason.contains("at most 16"), "{}", many(17).reason);
}

#[test]
fn relational_arithmetic() {
    let rel = |a: i64, b: i64, f: &str| {
        decide_intent_world(&json!({
            "now": NOW, "action": {"params": {"a": a, "b": b}}, "committed": {},
            "policy": {"relational": [{"name": "x", "fn": f, "a": "action.params.a", "b": "action.params.b"}]}
        }))
    };
    assert_eq!(rel(1, 3, "ratio_ppm").world["x"], json!(333_333));
    assert_eq!(rel(0, 7, "ratio_ppm").world["x"], json!(0));
    assert!(!rel(1, 0, "ratio_ppm").ok);
    assert!(!rel(-1, 3, "ratio_ppm").ok);
    // floor(a * 1e6 / b) in exact integer arithmetic, up to 2^53-1 inclusive
    assert_eq!(rel(MAX_SAFE, 1_000_000, "ratio_ppm").world["x"], json!(MAX_SAFE));
    assert!(!rel(MAX_SAFE, 999_999, "ratio_ppm").ok);
    assert_eq!(rel(5, 9, "sub").world["x"], json!(-4));
    assert_eq!(rel(MAX_SAFE, 0, "sub").world["x"], json!(MAX_SAFE));
    assert!(!rel(-MAX_SAFE, 1, "sub").ok);
    assert_eq!(rel(-MAX_SAFE + 1, 1, "sub").world["x"], json!(-MAX_SAFE));
    // operands: a string or a missing parameter fails; a forward reference is a misconfigured policy
    let d = decide_intent_world(&json!({"now": NOW, "action": {"params": {"a": "1", "b": 1}}, "committed": {},
        "policy": {"relational": [{"name": "x", "fn": "sub", "a": "action.params.a", "b": "action.params.b"}]}}));
    assert!(!d.ok);
    let d = decide_intent_world(&json!({"now": NOW, "action": {"params": {"a": 1}}, "committed": {},
        "policy": {"relational": [{"name": "x", "fn": "sub", "a": "env.world.y", "b": "action.params.a"}, {"name": "y", "fn": "sub", "a": "action.params.a", "b": "action.params.a"}]}}));
    assert!(!d.ok && d.reason.contains("misconfigured"));
}

fn offer_set(site: &str, issued: i64, complete: bool, query: Value) -> Value {
    let body = json!({"v": 1, "kind": "pca-offer-set", "site": site, "session": session(), "query": query, "rank": "price_asc", "complete": complete,
        "offers": [{"offer_id": "OF-1", "price": 38_900, "cabin": "economy"}, {"offer_id": "OF-2", "price": 39_800, "cabin": "economy"}, {"offer_id": "OF-3", "price": 10, "cabin": "basic"}],
        "issued_at": issued, "kid": "s1"});
    signed("site", "atlas-pca/offer-set/v1\0", body)
}
fn offers(os: &Value, chosen: &str, max_age: i64) -> IntentWorldDecision {
    decide_intent_world(&json!({
        "now": NOW, "aud": AUD, "session": session(), "action": {"params": {"offer_id": chosen}},
        "committed": {"offer_set": ref_of("atlas-pca/offer-set-ref/v1", "o", os)}, "offer_set": os,
        "policy": {"offers": {"name": "excess", "site_keys": [{"kid": "s1", "pk": pk("site")}], "max_age_ms": max_age, "offer_param": "action.params.offer_id",
            "filter": {"query": {"from": "SFO"}, "offer": {"cabin": "economy"}}}}
    }))
}

#[test]
fn offer_set_coverage_age_and_excess() {
    let os = offer_set(AUD, NOW - 1_000, true, json!({"from": "SFO"}));
    assert_eq!(offers(&os, "OF-2", 60_000).world["excess"], json!(900));
    assert_eq!(offers(&os, "OF-1", 60_000).world["excess"], json!(0));
    assert!(!offers(&os, "OF-3", 60_000).ok); // filtered out by the intent filter
    assert!(!offers(&os, "OF-9", 60_000).ok);
    // age inclusive, future skew inclusive
    assert!(offers(&os, "OF-1", 1_000).ok);
    assert!(!offers(&os, "OF-1", 999).ok);
    assert!(offers(&offer_set(AUD, NOW + 60_000, true, json!({"from": "SFO"})), "OF-1", 60_000).ok);
    assert!(!offers(&offer_set(AUD, NOW + 60_001, true, json!({"from": "SFO"})), "OF-1", 60_000).ok);
    // coverage: the query may not narrow the search; it may be broader / empty
    assert!(offers(&offer_set(AUD, NOW, true, json!({})), "OF-1", 60_000).ok);
    assert!(!offers(&offer_set(AUD, NOW, true, json!({"from": "SFO", "cabin": "economy"})), "OF-1", 60_000).ok);
    assert!(!offers(&offer_set(AUD, NOW, true, json!({"from": "JFK"})), "OF-1", 60_000).ok);
    assert!(!offers(&offer_set(AUD, NOW, true, json!({"from": true})), "OF-1", 60_000).ok);
    // complete, site
    assert!(!offers(&offer_set(AUD, NOW, false, json!({})), "OF-1", 60_000).ok);
    assert!(!offers(&offer_set("other.example", NOW, true, json!({})), "OF-1", 60_000).ok);
}

// ---- rule 17 -------------------------------------------------------------------------------------------------------

fn prov(p: Value, policy: Value) -> ProvenanceDecision {
    decide_param_provenance(&json!({"aud": AUD, "session": session(), "action": {"params": {"offer_id": "OF-1", "payment_ref": "pm", "note": "hi"}}, "prov": p, "policy": policy}))
}

#[test]
fn provenance_modes_and_critical_max() {
    let reg = json!({"vouched": "trusted", "fp": "first_party", "t": "tool", "w": "web"});
    let pol = |extra: Value| {
        let mut p = json!({"params": {"action.params.offer_id": "material", "action.params.payment_ref": "critical"}, "registry": reg});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    };
    let both = |o: &str, c: &str| json!({"action.params.offer_id": [o], "action.params.payment_ref": [c]});
    assert_eq!(prov(both("fp", "vouched"), pol(json!({}))).outcome, "pass");
    // tool is the first TAINTED rank: material -> question (tap), critical -> question (typed)
    let d = prov(both("t", "vouched"), pol(json!({})));
    assert_eq!((d.outcome.as_str(), d.friction.as_deref()), ("question", Some("tap")));
    let d = prov(both("fp", "t"), pol(json!({})));
    assert_eq!((d.outcome.as_str(), d.friction.as_deref()), ("question", Some("typed")));
    assert_eq!(prov(both("t", "vouched"), pol(json!({"material_tainted": "allow"}))).outcome, "pass");
    assert_eq!(prov(both("t", "vouched"), pol(json!({"material_tainted": "deny"}))).outcome, "deny");
    assert_eq!(prov(both("fp", "t"), pol(json!({"critical_tainted": "deny"}))).outcome, "deny");
    assert_eq!(prov(both("fp", "t"), pol(json!({"critical_tainted": "allow"}))).outcome, "deny"); // misconfigured
    // critical_max inclusive
    assert_eq!(prov(both("fp", "fp"), pol(json!({"critical_max": "first_party"}))).outcome, "pass");
    assert_eq!(prov(both("fp", "t"), pol(json!({"critical_max": "first_party"}))).outcome, "deny");
    // the join is the least trusted ref; an unknown or prototype-named ref is agent
    let d = prov(json!({"action.params.offer_id": ["fp", "w"]}), pol(json!({"material_tainted": "allow"})));
    assert_eq!(d.labels["action.params.offer_id"], json!("web"));
    for r in ["nope", "__proto__", "constructor", "toString"] {
        let d = prov(json!({"action.params.offer_id": [r]}), pol(json!({"material_tainted": "allow"})));
        assert_eq!(d.labels["action.params.offer_id"], json!("agent"), "{r}");
    }
    // an undeclared material / critical parameter the action carries is agent
    let d = prov(json!({}), pol(json!({"material_tainted": "allow", "critical_tainted": "question"})));
    assert_eq!(d.labels["action.params.payment_ref"], json!("agent"));
    assert_eq!(d.outcome, "question");
    // prov shape: 32 / 33 paths, 8 / 9 refs, a parameter the action does not carry
    let paths = |n: usize| Value::Object((0..n).map(|i| (format!("action.params.p{i}"), json!(["fp"]))).collect::<Map<String, Value>>());
    assert!(prov(paths(32), pol(json!({}))).reason.contains("does not carry"));
    assert!(prov(paths(33), pol(json!({}))).reason.contains("more than 32"));
    // (payment_ref, critical, is carried by the action: undeclared it would be agent and ask)
    let refs = |n: usize| json!({"action.params.offer_id": vec!["fp"; n], "action.params.payment_ref": ["fp"]});
    assert_eq!(prov(refs(8), pol(json!({}))).outcome, "pass");
    assert_eq!(prov(refs(9), pol(json!({}))).outcome, "deny");
}

fn labels_receipt(site: &str, fields: Value) -> Value {
    let body = json!({"v": 1, "kind": "pca-labels", "site": site, "session": session(), "response_digest": d32("resp"), "fields": fields, "issued_at": NOW, "kid": "k1"});
    signed(&format!("labels-{site}"), "atlas-pca/labels/v1\0", body)
}

#[test]
fn label_receipts_and_flows() {
    let value_digest = hash_canonical_strict(&json!("OF-1")).unwrap();
    let go = |site: &str, digest: &str, class: &str, flows: Value| {
        let rc = labels_receipt(site, json!({"offer": {"class": class, "value_digest": digest}}));
        let r = ref_of("atlas-pca/labels-ref/v1", "l", &rc);
        decide_param_provenance(&json!({
            "aud": AUD, "session": session(), "action": {"params": {"offer_id": "OF-1"}},
            "prov": {"action.params.offer_id": [format!("pca-labels:{r}#offer")]}, "committed_labels": [r], "labels": [rc],
            "policy": {"params": {"action.params.offer_id": "material"}, "material_tainted": "allow",
                "label_keys": [{"site": AUD, "kid": "k1", "pk": pk(&format!("labels-{AUD}"))}, {"site": "gov.example", "kid": "k1", "pk": pk("labels-gov.example")}],
                "flows": flows}
        }))
    };
    let d = go(AUD, &value_digest, "product.ref", json!({}));
    assert_eq!((d.outcome.as_str(), d.labels["action.params.offer_id"].clone()), ("pass", json!("first_party")));
    assert_eq!(d.classes["action.params.offer_id"], json!(["product.ref"]));
    // a foreign receipt is tool, and its class must be allowed to flow to the audience (most specific pattern)
    assert_eq!(go("gov.example", &value_digest, "pii.contact", json!({})).outcome, "deny");
    assert_eq!(go("gov.example", &value_digest, "public", json!({})).outcome, "pass");
    assert_eq!(go("gov.example", &value_digest, "pii.contact", json!({"pii.*": [AUD]})).labels["action.params.offer_id"], json!("tool"));
    assert_eq!(go("gov.example", &value_digest, "pii.contact", json!({"*": [AUD], "pii.*": ["x.example"]})).outcome, "deny");
    assert_eq!(go("gov.example", &value_digest, "pii.contact", json!({"pii.contact": [AUD], "pii.*": ["x.example"]})).outcome, "pass");
    // a value mismatch is agent
    assert_eq!(go(AUD, &d32("other"), "product.ref", json!({})).labels["action.params.offer_id"], json!("agent"));
}

// ---- rule 18 -------------------------------------------------------------------------------------------------------

fn verdict(judge: &str, label: &str) -> Value {
    let body = json!({"v": 1, "kind": "pca-intent-classification", "classifier": "tone", "session": session(),
        "content_digest": hash_canonical_strict(&json!("We are sorry.")).unwrap(), "label": label, "measurement": "m1", "judge": pk(judge)});
    signed(judge, "atlas-pca/intent-classifier/v1\0", body)
}
fn classify(vs: &[Value], k: i64, labels: Value) -> ClassifierDecision {
    let refs: Vec<Value> = vs.iter().map(|v| json!(ref_of("atlas-pca/intent-classifier-ref/v1", "c", v))).collect();
    decide_classifier_dimensions(&json!({
        "session": session(), "action": {"params": {"body": "We are sorry."}}, "committed": refs, "verdicts": vs,
        "policy": {"classifiers": [{"id": "tone", "param": "action.params.body", "labels": labels, "keys": [pk("j1"), pk("j2"), pk("j3")], "k": k, "measurements": ["m1"]}]}
    }))
}

#[test]
fn classifier_quorum_boundaries() {
    let labels = json!(["neutral", "apologetic", "toString"]);
    let two = [verdict("j1", "apologetic"), verdict("j2", "apologetic"), verdict("j3", "neutral")];
    assert_eq!(classify(&two, 2, labels.clone()).classes["tone"], json!("apologetic"));
    assert!(!classify(&two, 3, labels.clone()).ok);
    assert!(!classify(&two, 1, labels.clone()).ok); // two labels reach k = 1: ambiguous
    assert!(!classify(&two, 4, labels.clone()).ok); // k above |keys|: misconfigured
    assert!(!classify(&two, 0, labels.clone()).ok);
    // a label named like an Object.prototype member is an ordinary key of a prototype-free tally
    let proto = [verdict("j1", "toString"), verdict("j2", "toString")];
    assert_eq!(classify(&proto, 2, labels.clone()).classes["tone"], json!("toString"));
    assert!(!classify(&proto, 3, labels.clone()).ok);
    // a double vote, a judge off the allowlist, 8 / 9 commitments
    assert!(!classify(&[verdict("j1", "neutral"), verdict("j1", "apologetic")], 1, labels.clone()).ok);
    assert!(!classify(&[verdict("j9", "neutral")], 1, labels.clone()).ok);
    let commit = |n: usize| {
        let refs: Vec<Value> = (0..n).map(|i| json!(d32(&format!("v{i}")))).collect();
        decide_classifier_dimensions(&json!({"session": session(), "action": {"params": {}}, "committed": refs, "policy": {"classifiers": []}}))
    };
    assert!(commit(8).reason.contains("not supplied"), "{}", commit(8).reason);
    assert!(commit(9).reason.contains("at most 8"), "{}", commit(9).reason);
}

// ---- clock and activity (rules 16-18) -----------------------------------------------------------------------------

#[test]
fn a_clock_that_is_not_a_safe_integer_makes_facts_and_offers_stale() {
    let f = fact("o0", json!(5), NOW);
    let refs = json!([ref_of("atlas-pca/fact-ref/v1", "f", &f)]);
    let w = |now: Value| {
        decide_intent_world(&json!({"now": now, "action": {"params": {"offer_id": "OF-2", "a": 3, "b": 1}}, "committed": {"facts": refs}, "facts": [f],
            "policy": world_policy(1, 0, 1, 60_000)}))
    };
    assert!(w(json!(NOW)).ok);
    for bad in [json!("1800000000000"), json!(1_800_000_000_000.5), json!(null), json!(9_007_199_254_740_992u64), json!(-0.0)] {
        assert!(!w(bad.clone()).ok, "{bad}");
    }
    // relational dimensions need no clock
    let r = decide_intent_world(&json!({"now": "x", "action": {"params": {"a": 3, "b": 1}}, "committed": {},
        "policy": {"relational": [{"name": "d", "fn": "sub", "a": "action.params.a", "b": "action.params.b"}]}}));
    assert_eq!(r.world["d"], json!(2));
    // offers: stale without a clock
    let os = offer_set(AUD, NOW - 1_000, true, json!({"from": "SFO"}));
    let mut i = json!({
        "now": NOW, "aud": AUD, "session": session(), "action": {"params": {"offer_id": "OF-1"}},
        "committed": {"offer_set": ref_of("atlas-pca/offer-set-ref/v1", "o", &os)}, "offer_set": os,
        "policy": {"offers": {"name": "excess", "site_keys": [{"kid": "s1", "pk": pk("site")}], "max_age_ms": 60_000, "offer_param": "action.params.offer_id",
            "filter": {"query": {"from": "SFO"}, "offer": {"cabin": "economy"}}}}
    });
    assert!(decide_intent_world(&i).ok);
    i["now"] = json!("1800000000000");
    assert!(!decide_intent_world(&i).ok);
}

#[test]
fn activity_typing_is_strict() {
    let act = |is: Value, policy: Value| intent_wb_active(&json!({"intent_session": is, "policy": policy}));
    assert_eq!(act(json!({}), json!({})), (false, false, false));
    assert_eq!(act(json!({"facts": [d32("f")]}), json!({})), (true, false, false));
    assert_eq!(act(json!({"facts": []}), json!({})), (false, false, false));
    assert_eq!(act(json!({"facts": {"length": 1}}), json!({})), (false, false, false));
    assert_eq!(act(json!({"offer_set": d32("o")}), json!({})), (true, false, false));
    assert_eq!(act(json!({"offer_set": 5}), json!({})), (false, false, false));
    assert_eq!(act(json!({}), json!({"world": {"worlds": [{}]}})), (true, false, false));
    assert_eq!(act(json!({}), json!({"world": {"relational": {"length": 2}}})), (false, false, false));
    assert_eq!(act(json!({}), json!({"world": {"offers": {}}})), (true, false, false));
    assert_eq!(act(json!({}), json!({"world": {"offers": []}})), (false, false, false));
    assert_eq!(act(json!({"prov": null}), json!({})), (false, true, false));
    assert_eq!(act(json!({"labels": [d32("l")]}), json!({})), (false, true, false));
    assert_eq!(act(json!({"labels": []}), json!({})), (false, false, false));
    assert_eq!(act(json!({}), json!({"provenance": {}})), (false, true, false));
    assert_eq!(act(json!({}), json!({"provenance": []})), (false, false, false));
    assert_eq!(act(json!({}), json!({"provenance": null})), (false, false, false));
    assert_eq!(act(json!({"classes": [d32("c")]}), json!({})), (false, false, true));
    assert_eq!(act(json!({}), json!({"classifiers": {"length": 1}})), (false, false, false));
    assert_eq!(act(json!({}), json!({"classifiers": [{}]})), (false, false, true));
}

// ---- suites: every v2 signature goes through the suite dispatch ------------------------------------------------

#[test]
fn an_alg_the_dispatch_refuses_is_unsupported_suite() {
    let f = fx();
    // session root
    let (mut s, _) = base_root();
    s["alg"] = json!("x-unknown-suite");
    let mut c = f.ctx.clone();
    c["session"]["root"] = s.clone();
    let v = run(&f.p0, &f.g0, &c);
    assert_only(&v, &["accumulators", "intent_session"]);
    assert!(v.reason.contains("unsupported_suite"), "{}", v.reason);
    assert!(verify_session_root(&s).unwrap_err().contains("unsupported_suite"));
    // action schema (the document's sig.alg, and the pinned key's alg)
    let mut doc = schema();
    doc["sig"]["alg"] = json!("x-unknown-suite");
    assert!(verify_action_schema(&doc, &schema_keys()).unwrap_err().contains("unsupported_suite"));
    let keys = json!([{"kid": "skyair-2026", "alg": "x-unknown-suite", "pk": pk("site")}]);
    assert!(verify_action_schema(&schema(), &keys).unwrap_err().contains("unsupported_suite"));
    // reservation receipt and sequencer key set
    let fx = seq_fx();
    let rc = receipt(&fx, "seq1", "k1", |b| b["alg"] = json!("x-unknown-suite"));
    let v = run_seq(&fx, &rc, json!([key_set("seqroot", json!([entry("k1", "seq1", 0, None)]))]), None);
    assert_only(&v, &["accumulators"]);
    assert!(v.reason.contains("unsupported_suite"), "{}", v.reason);
    let rc = receipt(&fx, "seq1", "k1", |_| {});
    let mut ks = key_set("seqroot", json!([entry("k1", "seq1", 0, None)]));
    ks["alg"] = json!("x-unknown-suite");
    let v = run_seq(&fx, &rc, json!([ks]), None);
    assert!(v.reason.contains("unsupported_suite"), "{}", v.reason);
    // revocation epoch
    let scope = session_revocation_scope(&session());
    let ids = vec![session_revocation_id(&session())];
    let mut ev = evidence("revauth", &[REVOKED], NOW, NOW + 1, &scope);
    ev["epoch"]["alg"] = json!("x-unknown-suite");
    let e = rev(&ev, &ids, 60_000.0, None).unwrap_err();
    assert!(e.contains("unsupported_suite"), "{e}");
}

// ---- null is malformed, absent is empty ----------------------------------------------------------------------

#[test]
fn null_verifier_state_fails_closed_absent_is_empty() {
    let f = fx();
    let set = |c: &mut Value, path: &[&str], v: Option<Value>| {
        let mut cur = c;
        for k in &path[..path.len() - 1] {
            if cur.get(*k).is_none() {
                cur[*k] = json!({});
            }
            cur = &mut cur[*k];
        }
        match v {
            Some(v) => cur[path[path.len() - 1]] = v,
            None => {
                cur.as_object_mut().map(|o| o.remove(path[path.len() - 1]));
            }
        }
    };
    // a malformed TOP-LEVEL member fails every check that could be reported (no layers / W-B check is reported)
    let top: Vec<(&[&str], Value)> = vec![
        (&["policy"], json!(null)),
        (&["policy"], json!([])),
        (&["policy", "session"], json!(null)),
        (&["policy", "schema"], json!(null)),
        (&["params"], json!(null)),
        (&["params"], json!([])),
        (&["schema"], json!(null)),
        (&["session"], json!(null)),
        (&["acc"], json!(null)),
        (&["layers"], json!(null)),
        (&["layers", "org"], json!(null)),
        (&["wb"], json!(null)),
        (&["wb"], json!(5)),
        (&["wb", "artifacts"], json!(null)),
        (&["wb", "artifacts"], json!("x")),
        (&["wb", "artifacts", "facts"], json!(null)),
        (&["wb", "artifacts", "labels"], json!({})),
        (&["wb", "artifacts", "verdicts"], json!(null)),
        (&["wb", "artifacts", "offer_set"], json!(null)),
        (&["wb", "policy"], json!(null)),
        (&["wb", "policy"], json!([])),
        (&["wb", "policy", "world"], json!(null)),
        (&["wb", "policy", "provenance"], json!(null)),
        (&["wb", "policy", "classifiers"], json!(null)),
    ];
    for (path, v) in top {
        let mut c = f.ctx.clone();
        set(&mut c, path, Some(v.clone()));
        let r = run(&f.p0, &f.g0, &c);
        assert_only(&r, TOP);
        assert_eq!(r.checks.keys().filter(|k| ["layers", "facts", "provenance", "classes"].contains(&k.as_str())).count(), 0, "{path:?}");
    }
    // a malformed member BELOW the top level fails the check that owns it
    let owned: Vec<(&[&str], Value, &[&str])> = vec![
        (&["session", "grants"], json!(null), &["intent_session"]),
        (&["session", "grants"], json!({}), &["intent_session"]),
        (&["session", "revocation"], json!(null), &["intent_session"]),
        (&["session", "root"], json!(null), &["accumulators", "intent_session"]),
        (&["schema", "docs"], json!(null), &["accumulators", "schema"]),
        (&["schema", "keys"], json!(null), &["accumulators", "schema"]),
        (&["schema", "keys"], json!("k"), &["accumulators", "schema"]),
        (&["acc", "state"], json!(null), &["accumulators"]),
        (&["acc", "state"], json!([]), &["accumulators"]),
        (&["acc", "monitors"], json!(null), &["accumulators"]),
        (&["acc", "receipts"], json!(null), &["accumulators"]),
        (&["acc", "receipts"], json!({}), &["accumulators"]),
        (&["acc", "last_seq"], json!(null), &["accumulators"]),
        (&["acc", "last_seq"], json!({"x": null}), &["accumulators"]),
        (&["acc", "last_seq"], json!({"x": "3"}), &["accumulators"]),
        (&["acc", "sequencer_keys"], json!(null), &["accumulators"]),
        (&["acc", "sequencer_keys"], json!({}), &["accumulators"]),
    ];
    for (path, v, want) in owned {
        let mut c = f.ctx.clone();
        set(&mut c, path, Some(v.clone()));
        assert_only(&run(&f.p0, &f.g0, &c), want);
    }
    // absent = empty / default (only a missing root, docs, keys, params or pre-state can fail)
    for path in [
        &["policy"][..], &["session", "grants"], &["session", "revocation"], &["session", "root"], &["schema", "docs"], &["schema", "keys"],
        &["params"], &["acc", "state"], &["acc", "monitors"], &["acc", "receipts"], &["acc", "last_seq"], &["acc", "sequencer_keys"],
        &["acc"], &["layers"], &["wb"], &["wb", "artifacts"], &["wb", "policy"],
    ] {
        let mut c = f.ctx.clone();
        set(&mut c, path, None);
        let v = run(&f.p0, &f.g0, &c);
        let essential = matches!(path, ["session", "root"] | ["schema", "docs"] | ["schema", "keys"] | ["params"] | ["acc", "state"] | ["acc"]);
        assert_eq!(v.allow, !essential, "absent {path:?}: {}", v.reason);
    }
    // a policy flag is on only as `true`; `false` leaves it off, and since the policy is closed and typed (ca361968) a
    // null / 1 / "true" flag is a malformed context: it reports schema and intent_session even without the member (no
    // accumulators then)
    let (s, _) = base_root();
    let g = cap("principal", json!([{"type": "envelope", "goal_commit": intent_goal_commit(&ref_(), &map0(), "salt0").unwrap()}]));
    let p = sign_p(body(&g, &params(), &map0(), "salt0", None));
    for off in [json!(null), json!(1), json!("true"), json!(false)] {
        let mut c = ctx_json(&s);
        c["policy"] = json!({"schema": {"closed_world": off.clone()}, "session": {"require": off.clone()}});
        let v = run(&p, &g, &c);
        if off == json!(false) {
            assert_allow(&v);
            assert_eq!(v.checks.len(), 10, "{off}");
        } else {
            assert_only(&v, &["intent_session", "schema"]);
        }
    }
    let mut c = ctx_json(&s);
    c["policy"] = json!({"schema": null});
    assert_only(&run(&p, &g, &c), &["intent_session", "schema"]);
    assert!(intent_v2_context_error(&c).is_some());
    assert!(intent_v2_context_error(&ctx_json(&s)).is_none());
    // a clock that is not a safe integer fails every reported v2 check
    let ctxv = IntentV2Context::from_json(&f.ctx).unwrap();
    let d = decide_intent_v2(&f.p0, &f.g0, Some(&ctxv), MAX_SAFE + 1);
    assert!(!d.checks.is_empty() && d.checks.iter().all(|c| !c.ok), "{:?}", d.checks);
    assert!(decide_intent_v2(&f.p0, &f.g0, Some(&ctxv), NOW).checks.iter().all(|c| c.ok));
}

#[test]
fn null_wb_inputs_fail_closed_absent_is_empty() {
    // rule 16
    let base = json!({"now": NOW, "action": {"params": {"a": 3, "b": 1}}, "committed": {}, "policy": {}});
    assert!(decide_intent_world(&base).ok);
    for (k, v) in [("committed", json!(null)), ("facts", json!(null)), ("policy", json!(null)), ("offer_set", json!(null))] {
        let mut i = base.clone();
        i[k] = v;
        let d = decide_intent_world(&i);
        // a present null is refused for every member, offer_set included (oracle-facts.ts: offer_set must be an object)
        assert!(!d.ok, "{k}: {}", d.reason);
    }
    for (k, v) in [("facts", json!(null)), ("offer_set", json!(null))] {
        let mut i = base.clone();
        i["committed"][k] = v;
        assert!(!decide_intent_world(&i).ok, "committed.{k}");
    }
    for k in ["worlds", "relational", "skew_ms", "offers"] {
        let mut i = base.clone();
        i["policy"][k] = json!(null);
        assert!(!decide_intent_world(&i).ok, "policy.{k}");
    }
    let mut i = base.clone();
    i["policy"] = json!({"relational": [{"name": "d", "fn": "sub", "a": "action.params.a", "b": "action.params.b"}]});
    assert!(decide_intent_world(&i).ok);
    i["action"]["params"] = json!(null);
    assert!(!decide_intent_world(&i).ok);
    // rule 17
    let pbase = json!({"aud": AUD, "session": session(), "action": {"params": {"x": 1}}, "policy": {"params": {}}});
    assert_eq!(decide_param_provenance(&pbase).outcome, "pass");
    for k in ["prov", "committed_labels", "labels", "policy", "action"] {
        let mut i = pbase.clone();
        i[k] = json!(null);
        assert_eq!(decide_param_provenance(&i).outcome, "deny", "{k}");
    }
    for k in ["params", "registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"] {
        let mut i = pbase.clone();
        i["policy"][k] = json!(null);
        assert_eq!(decide_param_provenance(&i).outcome, "deny", "policy.{k}");
    }
    let mut i = pbase.clone();
    i["action"]["params"] = json!(null);
    assert_eq!(decide_param_provenance(&i).outcome, "deny");
    // rule 18
    let cbase = json!({"session": session(), "action": {"params": {}}, "policy": {"classifiers": []}});
    assert!(decide_classifier_dimensions(&cbase).ok);
    for k in ["committed", "verdicts", "policy", "action"] {
        let mut i = cbase.clone();
        i[k] = json!(null);
        assert!(!decide_classifier_dimensions(&i).ok, "{k}");
    }
    let mut i = cbase.clone();
    i["policy"]["classifiers"] = json!(null);
    assert!(!decide_classifier_dimensions(&i).ok);
    let mut i = cbase.clone();
    i["policy"]["classifiers"] = json!([{"id": "t", "param": "action.params.b", "labels": ["x"], "keys": [pk("j1")], "k": 1, "measurements": null}]);
    assert!(!decide_classifier_dimensions(&i).ok);
    // the W-B unit: a null member of any input container fails `facts`, the first check
    let wb = |policy: Value| decide_intent_wb(&json!({"now": NOW, "aud": AUD, "session": session(), "action": {"params": {}}, "intent_session": {}, "policy": policy}));
    assert!(wb(json!({})).checks.is_empty());
    for k in ["world", "provenance", "classifiers"] {
        let r = wb(json!({ k: null }));
        assert_eq!(r.checks, vec![("facts", WbCheck::Fail)], "{k}");
    }
}

// ---- strict artifacts (rules 13-15) -------------------------------------------------------------------------------

#[test]
fn revocation_epoch_is_strictly_typed() {
    let scope = session_revocation_scope(&session());
    let ids = vec![session_revocation_id(&session())];
    let ok = |ev: &Value| rev(ev, &ids, 60_000.0, None);
    let good = evidence("revauth", &[REVOKED], NOW, NOW + 1, &scope);
    assert!(ok(&good).is_ok());
    // null optional members of the epoch are refused (before the signature)
    for k in ["alg", "pq_pk", "pq_sig", "guardian_epoch"] {
        let mut ev = good.clone();
        ev["epoch"][k] = json!(null);
        assert!(ok(&ev).is_err(), "{k}");
    }
    // a non-string alg is malformed, not an unsupported suite
    let mut ev = good.clone();
    ev["epoch"]["alg"] = json!(7);
    let e = ok(&ev).unwrap_err();
    assert!(!e.contains("unsupported_suite"), "{e}");
    // numbers are safe integers, strings are strings
    for (k, v) in [("issued_at", json!("1800000000000")), ("not_after", json!(1.5)), ("epoch", json!(-1)), ("set_size", json!(null)), ("root", json!(5)), ("guardian_epoch", json!("1"))] {
        let mut ev = good.clone();
        ev["epoch"][k] = v;
        assert!(ok(&ev).is_err(), "{k}");
    }
    assert!(revocation_epoch_shape_error(&good["epoch"]).is_none());
}

#[test]
fn session_root_strictness() {
    let bad = |f: &dyn Fn(&mut Value)| {
        let (s, _) = root_with(|b| f(b));
        verify_session_root(&s).is_err()
    };
    assert!(bad(&|b| b["layers"]["org"] = json!(null)));
    assert!(bad(&|b| b["layers"]["std"] = json!(null)));
    // the dedicated revocation authority is required and is not a principal
    assert!(bad(&|b| b["revocation"] = json!({"epoch_uri": "u", "max_age_s": 60, "pq_pk": "AAAA"})));
    assert!(bad(&|b| b["revocation"] = json!({"epoch_uri": "u", "max_age_s": 60})));
    assert!(bad(&|b| b["revocation"] = json!({"epoch_uri": "u", "max_age_s": 60, "key": pk("principal")})));
    assert!(!bad(&|b| b["revocation"] = json!({"epoch_uri": "u", "max_age_s": 60, "key": pk("rk"), "pq_pk": "AAAA"})));
    assert!(bad(&|b| b["principals"][0]["alg"] = json!(null)));
    assert!(bad(&|b| b["accumulators"][0]["id"] = json!("constructor")));
    assert!(bad(&|b| b["monitors"] = json!([{"id": "__proto__", "kind": "never", "p": {"verb": "x"}}])));
    let mut s = base_root().0;
    s["alg"] = json!(5);
    assert!(!verify_session_root(&s).unwrap_err().contains("unsupported_suite"));
}

#[test]
fn held_grants_and_schema_strictness() {
    let (s, r) = base_root();
    let g0 = grant("principal", 0, None, &r, &map0(), "salt0");
    let d1 = grant("principal", 1, Some(g0["id"].as_str().unwrap()), &r, &map1(), "salt1");
    let mut is1 = is0(&r);
    is1["seq"] = json!(1);
    is1["acc"] = json!([{"id": "trip_spend", "post": 77_800}]);
    let p1 = sign_p(body(&d1, &params(), &map1(), "salt1", Some(is1)));
    let mut c = ctx_json(&s);
    c["acc"]["state"]["trip_spend"]["sum"] = json!(38_900);
    for (held, needle) in [(json!("g0"), "not a capability"), (json!({"id": 5, "issuer": pk("principal")}), "not a capability"), ({
        let mut g = g0.clone();
        g["alg"] = json!("x-unknown-suite");
        g
    }, "unsupported_suite")] {
        c["session"]["grants"] = json!([held]);
        let v = run(&p1, &d1, &c);
        assert_only(&v, &["intent_session"]);
        assert!(v.reason.contains(needle), "{}", v.reason);
    }
    // schema: reserved parameter names, a null default, a non-string key pq_pk, keys not an array
    let with_param = |name: &str, decl: Value| {
        let mut u = unsigned_schema();
        u["verbs"][0]["params"][name] = decl;
        sign_schema(u, "site")
    };
    let decl = json!({"type": "string", "semantic": "x", "sensitivity": "free", "required": false});
    assert!(verify_action_schema(&with_param("action.params.ok_name", decl.clone()), &schema_keys()).is_ok());
    for n in ["action.params.__proto__", "action.params.constructor", "action.params.prototype"] {
        assert!(verify_action_schema(&with_param(n, decl.clone()), &schema_keys()).is_err(), "{n}");
    }
    let mut nd = decl.clone();
    nd["default"] = json!(null);
    assert!(verify_action_schema(&with_param("action.params.x", nd), &schema_keys()).is_err());
    assert!(verify_action_schema(&schema(), &json!([{"kid": "skyair-2026", "alg": "ed25519", "pk": pk("site"), "pq_pk": 5}])).is_err());
    assert!(verify_action_schema(&schema(), &json!({"kid": "skyair-2026"})).is_err());
}

// ---- W-B suite agility, pinned PQ keys, closed and typed policies (d63b36e6, 0cc44911, ca361968, ab9766e0) ---------

/// A fact signed as `signed` does, with extra (signed) suite members.
fn fact_with(oracle: &str, extra: Value) -> Value {
    let mut body = json!({"v": 1, "kind": "pca-fact", "name": "fare", "subject": "OF-2", "value": 5, "t_obs": NOW, "oracle": oracle});
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    signed(&format!("oracle-{oracle}"), "atlas-pca/fact/v1\0", body)
}

#[test]
fn wb_artifact_suite_members() {
    let one = |f: Value, policy: Value| world(&[f], policy);
    let pol = world_policy(1, 0, 1, 60_000);
    // explicit ed25519 is the default suite (signed, accepted)
    assert!(one(fact_with("o0", json!({"alg": "ed25519"})), pol.clone()).ok);
    // an alg the dispatch refuses: unsupported_suite, before the world / pin / signature
    let d = one(fact_with("o0", json!({"alg": "no-such-suite"})), pol.clone());
    assert!(!d.ok && d.reason.contains("unsupported_suite"), "{}", d.reason);
    let d = one(fact_with("o9", json!({"alg": "no-such-suite"})), pol.clone());
    assert!(d.reason.contains("unsupported_suite"), "{}", d.reason); // even with an unpinned oracle
    // a non-string alg is malformed, never unsupported_suite
    for a in [json!(7), json!(null), json!(true)] {
        let d = one(fact_with("o0", json!({"alg": a})), pol.clone());
        assert!(!d.ok && !d.reason.contains("unsupported_suite"), "{}", d.reason);
    }
    // an ed25519 artifact carries neither pq_pk nor pq_sig
    assert!(!one(fact_with("o0", json!({"pq_pk": "AAAA"})), pol.clone()).ok);
    let mut f = fact("o0", json!(5), NOW);
    f["pq_sig"] = json!("AAAA"); // unsigned member: the wire allows it, the suite rule refuses it
    assert!(!one(f, pol.clone()).ok);
    // a PQ suite verifies only under the pinned PQ key: no pin, no admission
    assert!(!one(fact_with("o0", json!({"alg": "ml-dsa-65", "pq_pk": d32("pq")})), pol.clone()).ok);
    // pins: pq_pk absent or a non-empty string
    let mut p2 = pol.clone();
    p2["worlds"][0]["oracles"][0]["pq_pk"] = json!(null);
    assert!(one(fact("o0", json!(5), NOW), p2.clone()).reason.contains("misconfigured"));
    p2["worlds"][0]["oracles"][0]["pq_pk"] = json!("");
    assert!(one(fact("o0", json!(5), NOW), p2.clone()).reason.contains("misconfigured"));
    p2["worlds"][0]["oracles"][0]["pq_pk"] = json!(d32("pq"));
    assert!(one(fact("o0", json!(5), NOW), p2).ok);
    // offer sets, label receipts and verdicts follow the same rule
    let mut os = offer_set(AUD, NOW, true, json!({}));
    os.as_object_mut().unwrap().remove("sig");
    os["alg"] = json!("no-such-suite");
    let os = signed("site", "atlas-pca/offer-set/v1\0", os);
    let d = offers(&os, "OF-1", 60_000);
    assert!(!d.ok && d.reason.contains("unsupported_suite"), "{}", d.reason);
    let mut v = verdict("j1", "apologetic");
    v.as_object_mut().unwrap().remove("sig");
    v["alg"] = json!("no-such-suite");
    let v = signed("j1", "atlas-pca/intent-classifier/v1\0", v);
    let d = classify(&[v], 1, json!(["apologetic"]));
    assert!(!d.ok && d.reason.contains("unsupported_suite"), "{}", d.reason);
    let mut rc = labels_receipt(AUD, json!({"offer": {"class": "product.ref", "value_digest": d32("x")}}));
    rc.as_object_mut().unwrap().remove("sig");
    rc["alg"] = json!("no-such-suite");
    let rc = signed(&format!("labels-{AUD}"), "atlas-pca/labels/v1\0", rc);
    let r = ref_of("atlas-pca/labels-ref/v1", "l", &rc);
    let d = decide_param_provenance(&json!({"aud": AUD, "session": session(), "action": {"params": {"offer_id": "OF-1"}},
        "prov": {"action.params.offer_id": [format!("pca-labels:{r}#offer")]}, "committed_labels": [r], "labels": [rc],
        "policy": {"params": {}, "label_keys": [{"site": AUD, "kid": "k1", "pk": pk(&format!("labels-{AUD}"))}]}}));
    assert!(d.outcome == "deny" && d.reason.contains("unsupported_suite"), "{}", d.reason);
    // classifier pq_keys: a map from allowlisted keys to non-empty PQ keys
    let cl = |pq: Value| {
        decide_classifier_dimensions(&json!({"session": session(), "action": {"params": {}}, "policy": {"classifiers": [
            {"id": "t", "param": "action.params.b", "labels": ["x"], "keys": [pk("j1")], "k": 1, "pq_keys": pq}]}}))
    };
    assert!(cl(json!({})).reason.contains("quorum"));
    assert!(cl(json!({ pk("j1"): d32("pq") })).reason.contains("quorum"));
    for bad in [json!({ pk("j2"): d32("pq") }), json!({ pk("j1"): "" }), json!({ pk("j1"): 1 }), json!(null), json!([])] {
        assert!(cl(bad.clone()).reason.contains("misconfigured"), "{bad}");
    }
}

#[test]
fn wb_policies_are_closed_and_typed() {
    let base = || json!({"now": NOW, "aud": AUD, "session": session(), "action": {"params": {"a": 3, "b": 1}}, "committed": {}, "policy": {}});
    let wpol = |f: &dyn Fn(&mut Value)| {
        let mut i = base();
        i["policy"] = world_policy(1, 0, 1, 60_000);
        i["policy"]["relational"] = json!([{"name": "d", "fn": "sub", "a": "action.params.a", "b": "action.params.b"}]);
        f(&mut i["policy"]);
        decide_intent_world(&i)
    };
    // the well-formed policy is not misconfigured (it then needs its facts: none are supplied here)
    assert!(!wpol(&|_| {}).reason.contains("misconfigured"));
    let bad: Vec<Box<dyn Fn(&mut Value)>> = vec![
        Box::new(|p| p["extra"] = json!(1)),
        Box::new(|p| p["worlds"][0]["extra"] = json!(1)),
        Box::new(|p| p["worlds"][0]["oracles"][0]["extra"] = json!(1)),
        Box::new(|p| p["relational"][0]["extra"] = json!(1)),
        Box::new(|p| p["skew_ms"] = json!("60000")),
        Box::new(|p| p["skew_ms"] = json!(1.5)),
        Box::new(|p| p["worlds"][0]["freshness_ms"] = json!("1")),
        Box::new(|p| p["worlds"][0]["min_oracles"] = json!(true)),
        Box::new(|p| p["relational"][0]["fn"] = json!(1)),
    ];
    for (i, f) in bad.iter().enumerate() {
        let d = wpol(f.as_ref());
        assert!(!d.ok && d.reason.contains("misconfigured"), "{i}: {}", d.reason);
    }
    // offers policy, site key and filter are closed
    let os = offer_set(AUD, NOW, true, json!({}));
    let opol = |f: &dyn Fn(&mut Value)| {
        let mut p = json!({"name": "excess", "site_keys": [{"kid": "s1", "pk": pk("site")}], "max_age_ms": 60_000, "offer_param": "action.params.offer_id",
            "filter": {"query": {}, "offer": {}}});
        f(&mut p);
        decide_intent_world(&json!({"now": NOW, "aud": AUD, "session": session(), "action": {"params": {"offer_id": "OF-1"}},
            "committed": {"offer_set": ref_of("atlas-pca/offer-set-ref/v1", "o", &os)}, "offer_set": os.clone(), "policy": {"offers": p}}))
    };
    assert!(opol(&|_| {}).ok);
    for f in [
        Box::new(|p: &mut Value| p["extra"] = json!(1)) as Box<dyn Fn(&mut Value)>,
        Box::new(|p: &mut Value| p["site_keys"][0]["extra"] = json!(1)),
        Box::new(|p: &mut Value| p["filter"]["extra"] = json!({})),
        Box::new(|p: &mut Value| p["max_age_ms"] = json!("60000")),
    ] {
        assert!(!opol(f.as_ref()).ok);
    }
    // provenance policy and label keys
    let ppol = |p: Value| decide_param_provenance(&json!({"aud": AUD, "session": session(), "action": {"params": {}}, "policy": p})).outcome;
    assert_eq!(ppol(json!({"params": {}})), "pass");
    assert_eq!(ppol(json!({"params": {}, "extra": 1})), "deny");
    assert_eq!(ppol(json!({"params": {}, "label_keys": [{"site": AUD, "kid": "k1", "pk": pk("x"), "extra": 1}]})), "deny");
    assert_eq!(ppol(json!({"params": {}, "critical_max": 0})), "deny");
    assert_eq!(ppol(json!({"params": {}, "material_tainted": true})), "deny");
    // classifier policy and classifier entries
    let cpol = |p: Value| decide_classifier_dimensions(&json!({"session": session(), "action": {"params": {}}, "policy": p}));
    assert!(cpol(json!({"classifiers": []})).ok);
    assert!(!cpol(json!({"classifiers": [], "extra": 1})).ok);
    assert!(!cpol(json!({"classifiers": [{"id": "t", "param": "action.params.b", "labels": ["x"], "keys": [pk("j1")], "k": 1, "extra": 1}]})).ok);
    assert!(!cpol(json!({"classifiers": [{"id": "t", "param": "action.params.b", "labels": ["x"], "keys": [pk("j1")], "k": "1"}]})).ok);
    // the W-B context: artifacts and policy are closed, intent_session must be an object
    let wb = |i: Value| decide_intent_wb(&i).checks;
    let ctx = |extra: Value| {
        let mut i = json!({"now": NOW, "aud": AUD, "session": session(), "action": {"params": {}}, "intent_session": {}});
        for (k, v) in extra.as_object().unwrap() {
            i[k] = v.clone();
        }
        i
    };
    assert!(wb(ctx(json!({"artifacts": {}, "policy": {}}))).is_empty());
    for bad in [json!({"artifacts": {"extra": []}}), json!({"policy": {"extra": {}}}), json!({"intent_session": null}), json!({"artifacts": {"offer_set": []}})] {
        assert_eq!(wb(ctx(bad.clone())), vec![("facts", WbCheck::Fail)], "{bad}");
    }
    assert_eq!(wb(json!({"now": NOW, "action": {"params": {}}})), vec![("facts", WbCheck::Fail)]);
    // a null member INSIDE intent_session is not a context error: it is read by its rule (prov: null is active and denies)
    assert_eq!(wb(ctx(json!({"intent_session": {"prov": null}}))), vec![("provenance", WbCheck::Fail)]);
    // rules 16-18 need an action object
    assert!(!decide_intent_world(&json!({"now": NOW, "committed": {}, "policy": {}})).ok);
    assert_eq!(decide_param_provenance(&json!({"aud": AUD, "session": session(), "action": [], "policy": {"params": {}}})).outcome, "deny");
    assert!(!decide_classifier_dimensions(&json!({"session": session(), "action": "x", "policy": {"classifiers": []}})).ok);
}

#[test]
fn v2_policy_is_closed_and_typed() {
    let f = fx();
    let with = |policy: Value, p: &Value| {
        let mut c = f.ctx.clone();
        c["policy"] = policy;
        run(p, &f.g0, &c)
    };
    let plain = sign_p(body(&f.g0, &params(), &map0(), "salt0", None));
    // explicit false / absent = inactive; the ages 0 and 2^53-1 are well-formed
    for ok in [json!({}), json!({"session": {"require": false}}), json!({"schema": {"closed_world": false}}), json!({"session": {}, "schema": {}}),
        json!({"session": {"max_revocation_age_s": 0}}), json!({"session": {"max_revocation_age_s": MAX_SAFE}})] {
        let v = with(ok.clone(), &plain);
        assert!(!v.checks.contains_key("schema") && !v.checks.contains_key("intent_session"), "{ok}: {:?}", v.checks);
    }
    // anything else is a malformed context: schema and intent_session fail even without the member, and
    // accumulators too when the PCActn carries intent_session
    for bad in [
        json!(null), json!([]), json!({"extra": {}}), json!({"session": null}), json!({"schema": 1}),
        json!({"session": {"require": null}}), json!({"session": {"require": 1}}), json!({"session": {"require": "true"}}),
        json!({"session": {"extra": true}}), json!({"session": {"max_revocation_age_s": null}}), json!({"session": {"max_revocation_age_s": -1}}),
        json!({"session": {"max_revocation_age_s": 1.5}}), json!({"session": {"max_revocation_age_s": "60"}}),
        json!({"session": {"max_revocation_age_s": MAX_SAFE + 1}}), json!({"schema": {"closed_world": 0}}), json!({"schema": {"extra": false}}),
    ] {
        assert_only(&with(bad.clone(), &plain), &["intent", "intent_session", "schema"]);
        assert_only(&with(bad.clone(), &f.p0), TOP);
    }
}

#[test]
fn a_ceiling_is_exactly_predicates() {
    let f = fx();
    let with = |layers: Value| {
        let mut c = f.ctx.clone();
        c["layers"] = layers;
        run(&f.p0, &f.g0, &c)
    };
    let any = json!([{"verb": "*"}]);
    assert_allow(&with(json!({"org": {"predicates": any}})));
    // an extra member on a ceiling passes the context rule and fails `layers` as that ceiling
    let v = with(json!({"site": {"predicates": any, "note": "x"}}));
    assert_only(&v, &["layers"]);
    assert!(v.reason.contains("site"), "{}", v.reason);
    // an unknown member of the layers object is a malformed context
    assert_only(&with(json!({"org": {"predicates": any}, "extra": {"predicates": any}})), TOP);
}

#[test]
fn read_purpose() {
    let rp = |i: Value| {
        let d = decide_read_purpose(&i);
        (d.outcome, d.minimise, d.uncovered)
    };
    let fields = json!([{"path": "name", "class": "pii.identity"}, {"path": "email", "class": "pii.contact", "optional": true},
        {"path": "loyalty", "class": "internal", "optional": true}, {"path": "fares", "class": "public"}]);
    let cov = json!({"booking": ["pii.identity"], "support": ["pii.*", "internal"], "all": ["*"], "none": []});
    let r = |purpose: &str| rp(json!({"fields": fields, "purpose": purpose, "coverage": cov}));
    assert_eq!(r("booking"), ("allow".into(), vec!["email".into(), "loyalty".into()], vec![]));
    assert_eq!(r("support"), ("allow".into(), vec![], vec![]));
    assert_eq!(r("all"), ("allow".into(), vec![], vec![]));
    assert_eq!(r("none"), ("question".into(), vec!["email".into(), "loyalty".into()], vec!["name".into()]));
    // an unknown or prototype-named purpose covers nothing but public
    assert_eq!(r("toString").2, vec!["name".to_string()]);
    assert_eq!(r("__proto__").0, "question");
    let d = rp(json!({"fields": fields, "purpose": "none", "coverage": cov, "on_uncovered": "deny"}));
    assert_eq!(d.0, "deny");
    assert_eq!(d.1.len(), 2); // deny still reports the lists (not malformed)
    // UTF-8 byte order (U+FFFD before U+1F600) and de-duplication
    let d = rp(json!({"fields": [{"path": "\u{1F600}", "class": "x"}, {"path": "\u{FFFD}", "class": "x"}, {"path": "a", "class": "x"}, {"path": "a", "class": "x"}],
        "purpose": "p", "coverage": {}}));
    assert_eq!(d.2, vec!["a".to_string(), "\u{FFFD}".into(), "\u{1F600}".into()]);
    // malformed: deny with empty lists
    for bad in [
        json!({"fields": null, "purpose": "p", "coverage": {}}),
        json!({"fields": [], "purpose": 1, "coverage": {}}),
        json!({"fields": [], "purpose": "p", "coverage": {"p": "x"}}),
        json!({"fields": [], "purpose": "p", "coverage": {"p": [1]}}),
        json!({"fields": [], "purpose": "p", "coverage": {}, "on_uncovered": "allow"}),
        json!({"fields": [], "purpose": "p", "coverage": {}, "on_uncovered": null}),
        json!({"fields": [{"path": "a"}], "purpose": "p", "coverage": {}}),
        json!({"fields": [{"path": "a", "class": "x", "optional": "yes"}], "purpose": "p", "coverage": {}}),
        json!({"fields": [5], "purpose": "p", "coverage": {}}),
    ] {
        assert_eq!(rp(bad.clone()), ("deny".into(), vec![], vec![]), "{bad}");
    }
}

#[test]
fn provenance_classes_sort_in_utf8_byte_order() {
    let value_digest = hash_canonical_strict(&json!("OF-1")).unwrap();
    let rc = labels_receipt(AUD, json!({"a": {"class": "zeta", "value_digest": value_digest}, "b": {"class": "alpha", "value_digest": value_digest}}));
    let r = ref_of("atlas-pca/labels-ref/v1", "l", &rc);
    let d = decide_param_provenance(&json!({"aud": AUD, "session": session(), "action": {"params": {"offer_id": "OF-1"}},
        "prov": {"action.params.offer_id": [format!("pca-labels:{r}#a"), format!("pca-labels:{r}#b"), format!("pca-labels:{r}#a")]},
        "committed_labels": [r], "labels": [rc], "policy": {"params": {}, "label_keys": [{"site": AUD, "kid": "k1", "pk": pk(&format!("labels-{AUD}"))}]}}));
    assert_eq!(d.classes["action.params.offer_id"], json!(["alpha", "zeta"]));
}

// ---- rule 15: receipt and key-set freshness ----------------------------------------------------------------------

/// `run_seq` with extra `policy` / `acc` members merged into the context.
fn run_seq_with(fx: &SeqFx, rc: &Value, sets: Value, edit: impl FnOnce(&mut Value)) -> Verdict {
    let mut is = is0(&fx.r);
    is["acc"] = json!([{"id": "trip_spend", "post": rc["post"], "receipt": acc_receipt_digest(rc).unwrap()}]);
    let p = sign_p(body(&fx.g, &params(), &map0(), "salt0", Some(is)));
    let mut c = ctx_json(&fx.s);
    c["acc"] = json!({"receipts": [rc], "monitors": {}, "sequencer_keys": sets});
    edit(&mut c);
    run(&p, &fx.g, &c)
}

#[test]
fn receipt_lifetime_and_age() {
    let fx = seq_fx();
    let set = || json!([key_set("seqroot", json!([entry("k1", "seq1", 0, None)]))]);
    // lifetime: issued_at <= expires_at <= issued_at + 900000 (inclusive)
    let at = receipt(&fx, "seq1", "k1", |b| b["expires_at"] = json!(NOW - 1_000 + 900_000));
    assert_allow(&run_seq(&fx, &at, set(), None));
    let over = receipt(&fx, "seq1", "k1", |b| b["expires_at"] = json!(NOW - 1_000 + 900_001));
    assert_only(&run_seq(&fx, &over, set(), None), &["accumulators"]);
    let back = receipt(&fx, "seq1", "k1", |b| b["expires_at"] = json!(NOW - 1_001));
    assert_only(&run_seq(&fx, &back, set(), None), &["accumulators"]);
    // age: now - issued_at <= A_r (policy.acc.max_receipt_age_s, inclusive; default 900 s)
    let old = |age: i64| receipt(&fx, "seq1", "k1", |b| {
        b["issued_at"] = json!(NOW - age);
        b["expires_at"] = json!(NOW + 1);
    });
    let pol = |s: i64| move |c: &mut Value| c["policy"] = json!({"acc": {"max_receipt_age_s": s}});
    assert_allow(&run_seq_with(&fx, &old(10_000), set(), pol(10)));
    assert_only(&run_seq_with(&fx, &old(10_001), set(), pol(10)), &["accumulators"]);
    assert_allow(&run_seq_with(&fx, &old(899_999), set(), |_| {}));
    assert_allow(&run_seq_with(&fx, &old(0), set(), pol(0)));
    assert_only(&run_seq_with(&fx, &old(1), set(), pol(0)), &["accumulators"]);
}

#[test]
fn key_set_version_age_and_retirement() {
    let fx = seq_fx();
    let rc = receipt(&fx, "seq1", "k1", |_| {});
    let e = || json!([entry("k1", "seq1", 0, None)]);
    let root = pk("seqroot");
    let set3 = key_set_at("seqroot", e(), 3, NOW - 1_000);
    let tracked = |v: i64, set: &Value| json!({"version": v, "digest": sequencer_key_set_digest(set).unwrap()});
    let kv = |root: String, entry: Value| move |c: &mut Value| c["acc"]["keyset_versions"] = json!({ root: entry });
    // tracked {version, digest}: the same set at the tracked version is accepted, a newer one too
    assert_allow(&run_seq_with(&fx, &rc, json!([set3.clone()]), kv(root.clone(), tracked(3, &set3))));
    assert_allow(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 4, NOW - 1_000)]), kv(root.clone(), tracked(3, &set3))));
    // rollback (an older version) and equivocation (another set under the tracked version) are SKIPPED: with no other set
    // the receipt has no key set, so accumulators fails
    assert_only(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 2, NOW - 1_000)]), kv(root.clone(), tracked(3, &set3))), &["accumulators"]);
    let other3 = key_set_at("seqroot", e(), 3, NOW - 2_000);
    assert_only(&run_seq_with(&fx, &rc, json!([other3.clone()]), kv(root.clone(), tracked(3, &set3))), &["accumulators"]);
    // skipped, not failed: a later good set in the list still admits
    assert_allow(&run_seq_with(&fx, &rc, json!([other3, set3.clone()]), kv(root.clone(), tracked(3, &set3))));
    // version 0 is a malformed set; another root's tracked entry does not apply
    assert_only(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 0, NOW - 1_000)]), |_| {}), &["accumulators"]);
    assert_allow(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 2, NOW - 1_000)]), kv(pk("other"), tracked(9, &set3))));
    // a malformed tracked entry (bare number, null, version 0 or a string, no / bad digest, an unknown member) is a
    // malformed acc context
    let d = sequencer_key_set_digest(&set3).unwrap();
    for bad in [
        json!(3),
        json!(null),
        json!({"version": 0, "digest": d}),
        json!({"version": "3", "digest": d}),
        json!({"version": 3}),
        json!({"version": 3, "digest": "x"}),
        json!({"version": 3, "digest": d, "extra": 1}),
    ] {
        assert_only(&run_seq_with(&fx, &rc, json!([set3.clone()]), kv(root.clone(), bad.clone())), &["accumulators"]);
    }
    assert_only(&run_seq_with(&fx, &rc, json!([set3.clone()]), |c| c["acc"]["keyset_versions"] = json!(null)), &["accumulators"]);
    // key-set age: issued_at <= now + 60 s and now - issued_at <= A_k (default 3600 s; inclusive)
    assert_allow(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 1, NOW - 3_600_000)]), |_| {}));
    assert_only(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 1, NOW - 3_600_001)]), |_| {}), &["accumulators"]);
    assert_allow(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 1, NOW + 60_000)]), |_| {}));
    assert_only(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 1, NOW + 60_001)]), |_| {}), &["accumulators"]);
    let ka = |s: i64| move |c: &mut Value| c["policy"] = json!({"acc": {"max_keyset_age_s": s}});
    assert_allow(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 1, NOW - 5_000)]), ka(5)));
    assert_only(&run_seq_with(&fx, &rc, json!([key_set_at("seqroot", e(), 1, NOW - 5_001)]), ka(5)), &["accumulators"]);
    // a RETIRED key stops verifying 60 s after its retirement, even for a receipt back-dated into its window
    let back = |ret: i64| {
        let r = receipt(&fx, "seq1", "k1", |b| {
            b["issued_at"] = json!(ret - 10);
            b["expires_at"] = json!(NOW + 1);
        });
        run_seq_with(&fx, &r, json!([key_set_at("seqroot", json!([entry("k1", "seq1", 0, Some(ret))]), 1, NOW - 1_000)]), |_| {})
    };
    assert_allow(&back(NOW - 60_000));
    assert_only(&back(NOW - 60_001), &["accumulators"]);
}

#[test]
fn v2_policy_and_map_context_are_closed_and_typed() {
    let f = fx();
    for pol in [
        json!({"acc": {"max_receipt_age_s": null}}),
        json!({"acc": {"max_receipt_age_s": "900"}}),
        json!({"acc": {"max_keyset_age_s": -1}}),
        json!({"acc": {"other": 1}}),
        json!({"acc": null}),
        json!({"map": {"require": 1}}),
        json!({"map": {"require": null}}),
        json!({"map": {"max_residual_risk_ppm": 1.5}}),
        json!({"map": {"x": true}}),
        json!({"map": null}),
        json!({"other": {}}),
    ] {
        let mut c = f.ctx.clone();
        c["policy"] = pol.clone();
        assert_only(&run(&f.p0, &f.g0, &c), TOP);
    }
    for m in [json!(null), json!([]), json!({"other": 1})] {
        let mut c = f.ctx.clone();
        c["map"] = m.clone();
        assert_only(&run(&f.p0, &f.g0, &c), TOP);
    }
    // well-typed members are fine; policy.map.require reports `map` (and fails without a committed map)
    let mut c = f.ctx.clone();
    c["policy"] = json!({"acc": {"max_receipt_age_s": 900, "max_keyset_age_s": 3600}, "map": {"max_residual_risk_ppm": 5}});
    c["map"] = json!({});
    assert_allow(&run(&f.p0, &f.g0, &c));
    c["policy"]["map"]["require"] = json!(true);
    assert_only(&run(&f.p0, &f.g0, &c), &["map"]);
}

// ---- rule 19: the committed map --------------------------------------------------------------------------------

/// A tiny committed map for `air.book`: one numeric dimension `total` with the cut 40000 (cells [0, 39999], {40000},
/// [40001, 5000000]); cell 0 in the grant. Leaves: header, 3 cells, metrics, learner (n = 6).
struct MapFx {
    commit: String,
    leaves: Vec<(String, Vec<u8>, Value)>,
}
fn map_node(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut m = b"atlas-pca/intent-map/node/v1\0".to_vec();
    m.extend_from_slice(l);
    m.extend_from_slice(r);
    Sha256::digest(&m).to_vec()
}
fn map_leaf(kind: &str, salt: &[u8], leaf: &Value) -> Vec<u8> {
    let mut m = format!("atlas-pca/intent-map/{kind}/v1\0").into_bytes();
    m.extend_from_slice(salt);
    m.extend_from_slice(canon(leaf).as_bytes());
    Sha256::digest(&m).to_vec()
}
fn map_split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}
fn map_root(hs: &[Vec<u8>]) -> Vec<u8> {
    if hs.len() == 1 {
        return hs[0].clone();
    }
    let k = map_split(hs.len());
    map_node(&map_root(&hs[..k]), &map_root(&hs[k..]))
}
fn map_path(hs: &[Vec<u8>], idx: usize, out: &mut Vec<String>) {
    if hs.len() == 1 {
        return;
    }
    let k = map_split(hs.len());
    if idx < k {
        map_path(&hs[..k], idx, out);
        out.push(b64(&map_root(&hs[k..])));
    } else {
        map_path(&hs[k..], idx - k, out);
        out.push(b64(&map_root(&hs[..k])));
    }
}
fn metrics_leaf(rr: i64) -> Value {
    json!({"residual_risk_ppm": rr, "burden_ppm": 1, "uncertainty_ppm": 2, "disagreement_ppm": 0, "mean_harm_ppm": 3, "fidelity_est_ppm": 990_000, "entropy_mbits": 5, "questions": 1, "conflicts": 0})
}
fn map_fx(in_grant0: bool, rr: i64) -> MapFx {
    let header = json!({"verb": "air.book", "first": 1, "cells": 3, "dims": [{"kind": "num", "path": "action.params.total", "lo": 0, "hi": 5_000_000, "cuts": [40_000]}]});
    let mut leaves = vec![("header".to_string(), header)];
    for (i, g) in [in_grant0, false, false].iter().enumerate() {
        leaves.push(("cell".into(), json!({"verb": "air.book", "cell": [i], "p_ppm": 900_000 - i as i64, "in_grant": g})));
    }
    leaves.push(("metrics".into(), metrics_leaf(rr)));
    leaves.push(("learner".into(), json!({"learner_digest": d32("learner")})));
    let leaves: Vec<(String, Vec<u8>, Value)> = leaves.into_iter().enumerate().map(|(i, (k, l))| (k, Sha256::digest(format!("salt{i}").as_bytes()).to_vec(), l)).collect();
    let hs: Vec<Vec<u8>> = leaves.iter().map(|(k, s, l)| map_leaf(k, s, l)).collect();
    let mut m = b"atlas-pca/intent-map/commit/v1\0".to_vec();
    m.extend_from_slice(&(hs.len() as u64).to_be_bytes());
    m.extend_from_slice(&map_root(&hs));
    MapFx { commit: b64(&Sha256::digest(&m)), leaves }
}
impl MapFx {
    fn entry(&self, i: usize) -> Value {
        let hs: Vec<Vec<u8>> = self.leaves.iter().map(|(k, s, l)| map_leaf(k, s, l)).collect();
        let mut path = Vec::new();
        map_path(&hs, i, &mut path);
        json!({"index": i, "salt": b64(&self.leaves[i].1), "leaf": self.leaves[i].2, "path": path})
    }
    fn disclosure(&self, cell: usize) -> Value {
        json!({"size": self.leaves.len(), "header": self.entry(0), "cell": self.entry(1 + cell), "metrics": self.entry(self.leaves.len() - 2)})
    }
    fn leaves_json(&self) -> Value {
        Value::Array(self.leaves.iter().map(|(k, s, l)| json!({"kind": k, "salt": b64(s), "leaf": l})).collect())
    }
}
fn map_action(total: i64) -> (Value, Value) {
    let p = json!({"total": total});
    (json!({"verb": "air.book", "resource": "skyair.example/bookings", "params_digest": hash_canonical_strict(&p).unwrap()}), p)
}

#[test]
fn map_commitment_and_disclosure() {
    let m = map_fx(true, 1_200);
    assert_eq!(map_commit_of_leaves(&m.leaves_json()).as_deref(), Some(m.commit.as_str()));
    let (a, p) = map_action(38_900);
    let commit = json!(m.commit);
    let d = |disc: &Value, eps: Option<i64>| decide_map_disclosure(Some(&commit), &a, Some(&p), Some(disc), eps);
    let ok = d(&m.disclosure(0), None);
    assert!(ok.ok, "{}", ok.reason);
    assert_eq!((ok.cell.clone(), ok.p_ppm), (vec![0], 900_000));
    // ε inclusive
    assert!(d(&m.disclosure(0), Some(1_200)).ok);
    assert!(!d(&m.disclosure(0), Some(1_199)).ok);
    // another cell: the action's value is in cell 0, not cell 1
    assert!(!d(&m.disclosure(1), None).ok);
    // numeric cut cell boundaries: 39999 -> 0, 40000 -> 1, 40001 -> 2
    for (v, c) in [(39_999, 0usize), (40_000, 1), (40_001, 2)] {
        let (a2, p2) = map_action(v);
        let r = decide_map_disclosure(Some(&commit), &a2, Some(&p2), Some(&m.disclosure(c)), None);
        assert_eq!(r.ok, c == 0, "{v}");
        assert_eq!(r.reason.contains("outside the committed grant"), c != 0, "{v}: {}", r.reason);
    }
    // values outside the dimension: out of range, string, fraction, null, absent
    for bad in [json!({"total": 5_000_001}), json!({"total": "1"}), json!({"total": 1.5}), json!({"total": null}), json!({})] {
        let a2 = json!({"verb": "air.book", "resource": "r", "params_digest": hash_canonical_strict(&bad).unwrap()});
        assert!(!decide_map_disclosure(Some(&commit), &a2, Some(&bad), Some(&m.disclosure(0)), None).ok, "{bad}");
    }
    // params digest mismatch, a foreign commitment, a non-digest commitment
    assert!(!decide_map_disclosure(Some(&commit), &a, Some(&json!({"total": 1})), Some(&m.disclosure(0)), None).ok);
    assert!(!decide_map_disclosure(Some(&json!(d32("other"))), &a, Some(&p), Some(&m.disclosure(0)), None).ok);
    assert!(!decide_map_disclosure(Some(&json!("x")), &a, Some(&p), Some(&m.disclosure(0)), None).ok);
    // altered salt / path / leaf / size; kind confusion; the metrics position
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut x = m.disclosure(0);
        f(&mut x);
        d(&x, None).ok
    };
    assert!(!edit(&|x| x["cell"]["salt"] = json!(d32("s"))));
    assert!(!edit(&|x| x["cell"]["path"][0] = json!(d32("h"))));
    assert!(!edit(&|x| x["cell"]["path"].as_array_mut().unwrap().push(json!(d32("h")))));
    assert!(!edit(&|x| x["cell"]["leaf"]["p_ppm"] = json!(1)));
    assert!(!edit(&|x| x["size"] = json!(7)));
    assert!(!edit(&|x| x["size"] = json!(3)));
    assert!(!edit(&|x| x["metrics"] = m.entry(5)));
    assert!(!edit(&|x| x["header"]["index"] = json!(1)));
    // closed / typed shapes
    assert!(!edit(&|x| x["extra"] = json!(1)));
    assert!(!edit(&|x| x["cell"]["leaf"]["in_grant"] = json!("true")));
    assert!(!edit(&|x| x["metrics"]["leaf"]["log2_vs_mbits"] = json!(null)));
    assert!(!edit(&|x| x["header"]["leaf"]["dims"][0]["cuts"] = json!([40_000, 40_000])));
    // a cell outside the committed grant
    let m2 = map_fx(false, 1_200);
    let r = decide_map_disclosure(Some(&json!(m2.commit)), &a, Some(&p), Some(&m2.disclosure(0)), None);
    assert!(!r.ok && r.reason.contains("outside the committed grant"));
}

#[test]
fn committed_map_in_the_pipeline() {
    let m = map_fx(true, 1_200);
    // a session over the committed map: S.layers.task.map_digest is the commitment; the grant opens the v2c goal
    let (s, r) = root_with(|b| b["layers"]["task"]["map_digest"] = json!(m.commit));
    let goal = intent_goal_commit_v2c(&session(), &m.commit, "salt0").unwrap();
    let sc = json!({"type": "intent_session", "session": session(), "seq": 0, "root": r});
    let g = cap("principal", json!([{"type": "envelope", "goal_commit": goal}, sc]));
    let mut is = is0(&r);
    is["map_form"] = json!("commit");
    let p = sign_p(body(&g, &params(), &m.commit, "salt0", Some(is.clone())));
    let (_, _) = map_action(38_900);
    let mut c = ctx_json(&s);
    c["map"] = json!({"disclosure": m.disclosure(0)});
    let v = run(&p, &g, &c);
    assert_allow(&v);
    assert_eq!(v.checks.get("map"), Some(&true));
    let d = decide_intent_v2(&p, &g, Some(&IntentV2Context::from_json(&c).unwrap()), NOW);
    let names: Vec<&str> = d.checks.iter().map(|x| x.name).collect();
    assert_eq!(names, ["schema", "intent_session", "accumulators", "map"]);
    // no disclosure, a null one, ε over the committed residual risk
    let mut c2 = c.clone();
    c2["map"] = json!({});
    assert_only(&run(&p, &g, &c2), &["map"]);
    c2["map"] = json!({"disclosure": null});
    assert_only(&run(&p, &g, &c2), &["map"]);
    let mut c3 = c.clone();
    c3["policy"] = json!({"map": {"max_residual_risk_ppm": 1_199}});
    assert_only(&run(&p, &g, &c3), &["map"]);
    // the v2 goal does not open a v2c grant and vice versa
    let mut is_plain = is.clone();
    is_plain.as_object_mut().unwrap().remove("map_form");
    let p_plain = sign_p(body(&g, &params(), &m.commit, "salt0", Some(is_plain)));
    assert!(failed(&run(&p_plain, &g, &c)).contains(&"intent".to_string()));
    // map_form other than "commit" is a wire refusal
    for bad in [json!("plain"), json!(null), json!(1)] {
        let mut is_bad = is.clone();
        is_bad["map_form"] = bad.clone();
        let v = run(&sign_p(body(&g, &params(), &m.commit, "salt0", Some(is_bad))), &g, &c);
        assert_eq!(v.checks.get("wire"), Some(&false), "{bad}");
    }
    // a malformed context reports `map` too when the PCActn commits its map
    let mut c4 = c.clone();
    c4["params"] = json!(null);
    assert_only(&run(&p, &g, &c4), &["accumulators", "intent_session", "map", "schema"]);
    // policy.map.require without the member: map reported and failed
    let f = fx();
    let gp = cap("principal", json!([{"type": "envelope", "goal_commit": intent_goal_commit(&ref_(), &map0(), "salt0").unwrap()}]));
    let pp = sign_p(body(&gp, &params(), &map0(), "salt0", None));
    let mut c5 = f.ctx.clone();
    c5["policy"] = json!({"map": {"require": true}});
    assert_only(&run(&pp, &gp, &c5), &["map"]);
}

#[test]
fn revocation_evidence_and_map_leaves_are_closed() {
    let scope = session_revocation_scope(&session());
    let ids = vec![session_revocation_id(&session())];
    let mut ev = evidence("revauth", &[REVOKED], NOW, NOW + 1, &scope);
    assert!(rev(&ev, &ids, 60_000.0, None).is_ok());
    ev["proofs"] = json!({});
    assert!(rev(&ev, &ids, 60_000.0, None).is_err());
    let good = evidence("revauth", &[REVOKED], NOW, NOW + 1, &scope);
    let mut last = good.clone();
    last["x"] = json!(1);
    assert!(rev(&good, &ids, 60_000.0, Some(&last)).is_err());
    let m = map_fx(true, 1);
    let mut l = m.leaves_json();
    l[0]["extra"] = json!(1);
    assert!(map_commit_of_leaves(&l).is_none());
    let mut l = m.leaves_json();
    l[1]["kind"] = json!("bogus");
    assert!(map_commit_of_leaves(&l).is_none());
    assert!(map_commit_of_leaves(&json!([])).is_none());
}

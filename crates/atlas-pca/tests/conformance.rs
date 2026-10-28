use atlas_pca::*;
use ed25519_dalek::SigningKey;
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../conformance/");

/// A Rust `String` cannot hold a lone surrogate, but `vectors.json` carries one in an OBJECT-form vector
/// (`"aud": "rs-\ud800"`), which `serde_json` refuses to load. Replace every lone surrogate escape inside a
/// JSON string with this sentinel; the harness then reports `wire` failure for any vector containing it
/// (exactly what a UTF-16 language reaches via the strict canonical encoder).
const LONE: char = '\u{10FFFF}';

fn sanitize_lone_surrogates(text: &str) -> String {
    let cs: Vec<char> = text.chars().collect();
    let hex = |at: usize| -> Option<u32> {
        let s: String = cs.get(at..at + 4)?.iter().collect();
        if s.chars().all(|c| c.is_ascii_hexdigit()) {
            u32::from_str_radix(&s, 16).ok()
        } else {
            None
        }
    };
    let mut out = String::with_capacity(text.len());
    let (mut i, mut in_str) = (0, false);
    while i < cs.len() {
        let c = cs[i];
        if !in_str {
            in_str = c == '"';
            out.push(c);
            i += 1;
        } else if c == '"' {
            in_str = false;
            out.push(c);
            i += 1;
        } else if c == '\\' {
            if cs.get(i + 1) == Some(&'u') {
                match hex(i + 2) {
                    Some(hi) if (0xD800..=0xDBFF).contains(&hi) => {
                        let paired = cs.get(i + 6) == Some(&'\\')
                            && cs.get(i + 7) == Some(&'u')
                            && hex(i + 8).is_some_and(|lo| (0xDC00..=0xDFFF).contains(&lo));
                        if paired {
                            out.extend(&cs[i..i + 12]);
                            i += 12;
                        } else {
                            out.push(LONE);
                            i += 6;
                        }
                    }
                    Some(lo) if (0xDC00..=0xDFFF).contains(&lo) => {
                        out.push(LONE);
                        i += 6;
                    }
                    _ => {
                        out.extend(&cs[i..(i + 2).min(cs.len())]);
                        i += 2;
                    }
                }
            } else {
                out.extend(&cs[i..(i + 2).min(cs.len())]);
                i += 2;
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn load(name: &str) -> Value {
    let b = std::fs::read_to_string(format!("{DIR}{name}")).expect("read file");
    serde_json::from_str(&sanitize_lone_surrogates(&b)).expect("parse json")
}

fn has_lone(v: &Value) -> bool {
    match v {
        Value::String(s) => s.contains(LONE),
        Value::Array(a) => a.iter().any(has_lone),
        Value::Object(m) => m.iter().any(|(k, x)| k.contains(LONE) || has_lone(x)),
        _ => false,
    }
}

fn b64d(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// The signature suites this Rust verifier implements — for the LEAF signature (`requires:"pq"`), for
/// non-leaf capability-chain hops (`requires:"pq-nonleaf"`), and for the threshold-share binding. The three
/// CROSS-IMPL suites every conformant impl is required to agree on (GAP 1): classical Ed25519, the pure
/// lattice ML-DSA-65 (FIPS-204, via the `fips204` crate), and the hybrid Ed25519 + ML-DSA-65. The remaining
/// registered suites (ml-dsa-87, slh-dsa-sha2-128f/256s, their hybrids, and the SUF-CMA nested hybrid) are
/// NOT yet wired in Rust, so vectors that need a real signature verdict under them are skipped explicitly.
static SUPPORTED_SUITES: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(atlas_pca::supported_suites);

/// Which concrete signature suite a vector exercises that this verifier does NOT implement, if any:
/// the leaf `alg` for `requires:"pq"`, or any capability-hop `alg` for `requires:"pq-nonleaf"`.
/// `None` for core vectors and for vectors that stay entirely within [`SUPPORTED_SUITES`].
fn unsupported_suite(v: &Value) -> Option<String> {
    let p = match v.get("pcactn") {
        Some(p) => p,
        None => return unsupported_required_suite(v),
    };
    let alg = |o: &Value| o.get("alg").and_then(Value::as_str).unwrap_or("ed25519").to_string();
    match v.get("requires").and_then(Value::as_str) {
        Some("pq") => {
            let a = alg(p);
            (!SUPPORTED_SUITES.contains(&a.as_str())).then_some(a)
        }
        Some("pq-nonleaf") => p
            .get("cap_chain")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(alg)
            .find(|a| !SUPPORTED_SUITES.contains(&a.as_str())),
        // 0.4.1: a vector may name the one suite it needs directly (e.g. a threshold share under `ml-dsa-87`).
        Some(r) => (!SUPPORTED_SUITES.contains(&r)).then(|| r.to_string()),
        None => None,
    }
    .or_else(|| unsupported_required_suite(v))
}

/// Intent Layer v2: a vector whose v2 artifacts are signed under a suite names it in `requires_suite` (a string or a
/// list); a verifier without the suite fails such a vector closed (`unsupported_suite`), so the runner skips it.
fn unsupported_required_suite(v: &Value) -> Option<String> {
    match v.get("requires_suite") {
        Some(Value::String(s)) => (!SUPPORTED_SUITES.contains(&s.as_str())).then(|| s.clone()),
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).find(|s| !SUPPORTED_SUITES.contains(s)).map(String::from),
        _ => None,
    }
}

#[test]
fn vectors() {
    let doc = load("vectors.json");
    assert_eq!(doc["format"].as_i64(), Some(2));
    let vs = doc["vectors"].as_array().expect("vectors");
    assert!(!vs.is_empty());
    let mut bad = Vec::new();
    let mut skipped = 0usize;
    let mut skipped_suites: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for v in vs {
        let name = v["name"].as_str().unwrap();
        let want = v["expect"]["checks"].as_object().unwrap();
        // A terminal `wire` failure ({wire:false}) is suite-agnostic: this verifier rejects an unknown /
        // unimplemented suite at the wire stage (unknown `alg`, or a `pq_sig` the suite requires but we
        // cannot size), which IS the correct contract verdict for those negatives, so we still run them.
        // A vector whose expected verdict needs a genuine signature outcome under an unsupported suite
        // (every positive, and every `*-corrupt-sig`/`*-corrupt-pqsig` that expects `wire:true`) is skipped
        // with an explicit count — never silently passed.
        let terminal_wire_false = want.len() == 1 && want.get("wire") == Some(&Value::Bool(false));
        // Intent Layer v2: a vector whose artifacts need a suite this build lacks must FAIL closed with unsupported_suite
        if let Some(suite) = unsupported_required_suite(v) {
            let got = run_vector(v);
            if got.allow || !got.reason.contains("unsupported_suite") {
                bad.push(format!("{name}: requires_suite {suite} not implemented, so it must fail with unsupported_suite (allow {}, {})", got.allow, got.reason));
            }
            continue;
        }
        if let Some(suite) = unsupported_suite(v) {
            if !terminal_wire_false {
                // Suite capability rule: a suite outside the manifest is refused with unsupported_suite (counted).
                let got = run_vector(v);
                if got.allow || !got.reason.contains(atlas_pca::UNSUPPORTED_SUITE_REASON) {
                    bad.push(format!("{name}: suite {suite} is not implemented, so it must fail with unsupported_suite (allow {}, {})", got.allow, got.reason));
                }
                skipped += 1;
                skipped_suites.insert(suite);
                continue;
            }
        }
        let got = run_vector(v);
        let exp = &v["expect"];
        if got.allow != exp["allow"].as_bool().unwrap() {
            bad.push(format!("{name}: allow = {}, want {} ({})", got.allow, exp["allow"], got.reason));
        }
        if got.checks.len() != want.len() {
            bad.push(format!("{name}: checks {:?}, want {:?}", got.checks, want));
        }
        for (k, w) in want {
            if got.checks.get(k) != w.as_bool().as_ref() {
                bad.push(format!("{name}: check {k} = {:?}, want {w} ({})", got.checks.get(k), got.reason));
            }
        }
        if let Some(rc) = exp.get("reason_contains").and_then(Value::as_str) {
            if !got.reason.contains(rc) {
                bad.push(format!("{name}: reason {:?} does not contain {rc:?}", got.reason));
            }
        }
    }
    assert!(bad.is_empty(), "{} of {} vectors failed:\n{}", bad.len(), vs.len() - skipped, bad.join("\n"));
    eprintln!(
        "{} of {} vectors passed; {skipped} skipped (suites not yet in Rust: {})",
        vs.len() - skipped,
        vs.len(),
        skipped_suites.iter().cloned().collect::<Vec<_>>().join(", ")
    );
}

/// v2.1 agent-leaf share binding (GAP 2). Every `primitives.threshold_share[]` entry must verify over the
/// `signerSetHash‖t`-bound share message iff `valid`; in particular the PRE-v2.1 bare agent share and a
/// cross-signer-set replay MUST be rejected. An entry whose `requires` suite this build lacks must be refused.
#[test]
fn threshold_shares() {
    let doc = load("vectors.json");
    let shares = doc["primitives"]["threshold_share"].as_array().expect("threshold_share");
    assert!(!shares.is_empty());
    let mut bad = Vec::new();
    let (mut accepted, mut rejected) = (0usize, 0usize);
    let (mut bare_rejected, mut wrong_set_rejected) = (false, false);
    for s in shares {
        let name = s.get("name").and_then(Value::as_str).unwrap_or_else(|| s["role"].as_str().unwrap());
        let want = s.get("valid").and_then(Value::as_bool).unwrap_or(true);
        let got = verify_threshold_share(s);
        // Suite capability: an entry whose `requires` suite this build lacks is not compared; it must be refused.
        if let Some(req) = s.get("requires").and_then(Value::as_str) {
            if !SUPPORTED_SUITES.contains(&req) {
                if got {
                    bad.push(format!("{name}: share under unsupported suite {req} verified (want fail closed)"));
                }
                continue;
            }
        }
        if got != want {
            bad.push(format!("{name}: share verified = {got}, want valid = {want}"));
        }
        if want {
            accepted += 1;
        } else {
            rejected += 1;
        }
        bare_rejected |= name == "agent-bare-rejected" && !got;
        wrong_set_rejected |= name == "agent-bound-wrong-set" && !got;
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert!(bare_rejected, "v2.1 binding: the pre-v2.1 bare agent share MUST be rejected");
    assert!(wrong_set_rejected, "v2.1 binding: a cross-signer-set agent share replay MUST be rejected");
    eprintln!(
        "threshold shares: {accepted} valid accepted, {rejected} invalid rejected \
         (incl. v2.1 bare-agent-share + cross-signer-set replay)"
    );
}

/// R4-01: the standalone chain verifier needs a verifier-side PQ pin (`pq_pins`) or the stored grant (`trusted_root`) for a
/// non-ed25519 root. Rust implements every suite these vectors use, so none are skipped; a vector that would need an
/// unsupported suite is counted and skipped, never passed. Hop-0-pin refusals are asserted on the exact reason.
#[test]
fn chain_pin() {
    let doc = load("vectors.json");
    let vecs = doc["primitives"]["chain_pin"].as_array().expect("chain_pin");
    assert!(vecs.len() >= 25, "expected >= 25 chain_pin vectors, got {}", vecs.len());
    let (mut ran, mut skipped) = (0usize, 0usize);
    let mut bad = Vec::new();
    for v in vecs {
        let name = v["name"].as_str().unwrap();
        let chain = v["chain"].as_array().expect("chain");
        let want_ok = v["expect"]["ok"].as_bool().unwrap();
        let want_reason = v["expect"].get("reason").and_then(Value::as_str).unwrap_or("");
        let pin_refusal = want_reason.starts_with("hop 0: root suite");
        let unsupported = chain.iter().any(|c| {
            let a = c.get("alg").and_then(Value::as_str).unwrap_or("ed25519");
            !SUPPORTED_SUITES.contains(&a)
        });
        if unsupported && !pin_refusal {
            skipped += 1;
            continue;
        }
        let allowed: Option<Vec<String>> = v
            .get("allowed_suites")
            .and_then(Value::as_array)
            .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
        let pins: Option<std::collections::HashMap<String, String>> = v.get("pq_pins").and_then(Value::as_object).map(|m| {
            m.iter().map(|(k, x)| (k.clone(), x.as_str().unwrap_or("").to_string())).collect()
        });
        let got = verify_chain_policy(
            chain,
            v.get("expected_root_issuer").and_then(Value::as_str),
            allowed.as_deref(),
            pins.as_ref(),
            v.get("trusted_root"),
        );
        if got.is_ok() != want_ok {
            bad.push(format!("{name}: ok = {}, want {want_ok} ({got:?})", got.is_ok()));
        }
        if pin_refusal && got != Err(want_reason.to_string()) {
            bad.push(format!("{name}: reason {got:?}, want {want_reason:?}"));
        }
        ran += 1;
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
    assert_eq!(ran + skipped, vecs.len());
    assert!(ran >= 25, "only {ran} chain_pin vectors ran");
    eprintln!("[chain_pin] {ran} checked, {skipped} skipped");
}

#[test]
fn primitives() {
    let doc = load("vectors.json");
    let prim = &doc["primitives"];
    for c in prim["canonical"].as_array().unwrap() {
        assert_eq!(canonicalize_strict(&c["value"]).unwrap(), c["expect"].as_str().unwrap());
        assert_eq!(hash_canonical(&c["value"]), c["hash"].as_str().unwrap());
    }
    for m in prim["merkle"].as_array().unwrap() {
        let leaves = m["leaves"].as_array().unwrap();
        let root = merkle_root(leaves).unwrap();
        assert_eq!(root, m["root"].as_str().unwrap());
        for (i, p) in m["proofs"].as_array().unwrap().iter().enumerate() {
            assert!(verify_inclusion(&root, p.as_object(), &leaves[i]), "proof {i}");
        }
    }
    assert_eq!(params_digest(None), prim["params_digest_empty"].as_str().unwrap());
}

#[test]
fn json_parse_table() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for t in doc["primitives"]["json_parse"].as_array().unwrap() {
        let input = t["input"].as_str().unwrap();
        let accept = t["accept"].as_bool().unwrap();
        match (strict_parse(input), accept) {
            (Ok(v), true) => {
                if let Some(c) = t["canonical"].as_str() {
                    if canonicalize_strict(&v).ok().as_deref() != Some(c) {
                        bad.push(format!("{input:?}: canonical {:?}, want {c:?}", canonicalize_strict(&v)));
                    }
                }
            }
            (Err(_), false) => {}
            (Ok(_), false) => bad.push(format!("{input:?}: accepted, want reject")),
            (Err(e), true) => bad.push(format!("{input:?}: rejected ({e}), want accept")),
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn b64u_table() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for t in doc["primitives"]["b64u"].as_array().unwrap() {
        let input = t["input"].as_str().unwrap();
        let valid = t["valid"].as_bool().unwrap();
        let len = t.get("len").and_then(Value::as_u64).map(|n| n as usize);
        if decode_b64u_strict(input, len).is_some() != valid {
            bad.push(format!("{input:?} (len {len:?}): want valid={valid}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn keys_consistent() {
    let keys = load("keys.json");
    for (label, k) in keys.as_object().unwrap() {
        let seed: [u8; 32] = b64d(k["seed"].as_str().unwrap()).try_into().unwrap();
        let sk = SigningKey::from_bytes(&seed);
        assert_eq!(sk.verifying_key().to_bytes().to_vec(), b64d(k["public"].as_str().unwrap()), "{label}");
    }
}

/// Regression: `len = Some(n)` with n > usize::MAX/4 used to hit an unchecked `n * 4` (panic under overflow checks).
#[test]
fn b64u_huge_len_fails_closed() {
    for n in [usize::MAX, usize::MAX / 4 + 1, usize::MAX / 2] {
        assert!(decode_b64u_strict("AAAA", Some(n)).is_none());
        assert!(decode_b64u_strict("", Some(n)).is_none());
    }
    assert!(decode_b64u_strict("AAAA", Some(3)).is_some());
}

/// Run one `vectors[]` entry through the verifier with every context member it carries.
fn run_vector(v: &Value) -> Verdict {
        // the Rust API clock is an i64: a vector whose clock is not an integer is reported as a failed verdict, never a panic
        let now = match v["context"]["now"].as_i64() {
            Some(n) => n,
            None => return Verdict { allow: false, checks: std::collections::BTreeMap::new(), reason: "runner: context.now is not an integer".into(), reasons: Vec::new(), legacy_model_polarity: false },
        };
        let aud = v["context"]["aud"].as_str().unwrap();
        let allowed: Option<Vec<String>> = v["context"]["allowed_suites"]
            .as_array()
            .map(|a| a.iter().map(|x| x.as_str().unwrap().to_string()).collect());
        // Intent Layer M2: `intent-*` vectors may carry context.intent_policy (lenient; misconfig fails closed).
        // context.intent_policy_json (raw JSON text, keeps 950000.0 / 1e6 / -0.0) wins over context.intent_policy.
        let intent = match v["context"].get("intent_policy_json").and_then(Value::as_str) {
            Some(text) => Some(IntentPolicy::from_json_text(text).unwrap_or_else(|e| panic!("{}: {e}", v["name"]))),
            None => v["context"].get("intent_policy").and_then(IntentPolicy::from_json),
        };
        // Intent Layer v2: `schema-*` / `session-*` / `acc-*` / `layers-*` vectors carry the verifier state in context.intent_v2.
        let intent_v2 = v["context"].get("intent_v2").and_then(IntentV2Context::from_json);
        let opts = VerifyOptions { allowed: allowed.as_deref(), intent: intent.as_ref(), intent_v2: intent_v2.as_ref() };
        if let Some(raw) = v.get("pcactn_json").and_then(Value::as_str) {
            verify_pcactn_json_with(raw, &v["grant"], now, aud, &opts)
        } else if has_lone(&v["pcactn"]) {
            // not representable as a Rust String: a lone surrogate is a wire failure
            let mut checks = std::collections::BTreeMap::new();
            checks.insert("wire".to_string(), false);
            Verdict { allow: false, checks, reason: "wire: lone surrogate".into(), reasons: Vec::new(), legacy_model_polarity: false }
        } else {
            verify_pcactn_core_with(&v["pcactn"], &v["grant"], now, aud, &opts)
        }
}

/// A primitive's input: `input_json` (raw JSON text, for values plain JSON erases such as `-0`) parsed with the crate's
/// lenient JSON reader (serde_json keeps `-0` as negative zero), else `input`.
fn input_of(e: &Value) -> Value {
    match e.get("input_json").and_then(Value::as_str) {
        Some(text) => serde_json::from_str(text).unwrap_or_else(|err| panic!("{}: input_json: {err}", e["name"])),
        None => e["input"].clone(),
    }
}

/// The entries of `primitives.<name>`; empty when the corpus does not carry the table yet (the W-A tables are written by
/// the freeze job's generator run).
fn prim(doc: &Value, name: &str) -> Vec<Value> {
    doc["primitives"].get(name).and_then(Value::as_array).cloned().unwrap_or_default()
}

/// Rule 14 alone (`primitives.intent_schema`): `sig` (verifyActionSchema), `digest` when the signature is valid, and
/// `conform` (`{ok, code?, path?}`).
#[test]
fn intent_schema_primitives() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for e in prim(&doc, "intent_schema") {
        let name = e["name"].as_str().unwrap_or("?");
        let input = input_of(&e);
        let i = &input;
        let sig = verify_action_schema(&i["schema"], &i["keys"]).is_ok();
        if Some(sig) != e["expect"]["sig"].as_bool() {
            bad.push(format!("{name}: sig = {sig}"));
        }
        if let Some(d) = e["expect"].get("digest").and_then(Value::as_str) {
            if action_schema_digest(&i["schema"]).as_deref() != Some(d) {
                bad.push(format!("{name}: digest differs"));
            }
        }
        let c = conform_action(&i["schema"], i["verb"].as_str().unwrap_or(""), &i["params"]);
        let want = &e["expect"]["conform"];
        if Some(c.ok) != want["ok"].as_bool() || c.code.as_deref() != want.get("code").and_then(Value::as_str) || c.path.as_deref() != want.get("path").and_then(Value::as_str) {
            bad.push(format!("{name}: conform = {c:?}, want {want}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Rule 13 step 7 alone (`primitives.intent_revocation`): `checkSessionRevocation` on `{epoch, proofs}`.
#[test]
fn intent_revocation_primitives() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for e in prim(&doc, "intent_revocation") {
        let name = e["name"].as_str().unwrap_or("?");
        let input = input_of(&e);
        let i = &input;
        let ok = run_intent_revocation(i);
        if Some(ok) != e["expect"]["ok"].as_bool() {
            bad.push(format!("{name}: ok = {ok}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// `primitives.intent_revocation` (rule 13 step 7 alone): `{epoch, revoked, session, authority, ids, now, max_age_ms,
/// scope?, last?}` through `check_session_revocation` (no PQ pin; an `ids` list with a non-string is refused).
fn run_intent_revocation(i: &Value) -> bool {
    let ids: Option<Vec<String>> = i["ids"].as_array().and_then(|a| a.iter().map(|x| x.as_str().map(String::from)).collect());
    let (Some(ids), Some(authority)) = (ids, i["authority"].as_str()) else { return false };
    let ev = revocation_evidence_of(i);
    check_session_revocation(
        Some(&ev),
        i["session"].as_str().unwrap_or(""),
        authority,
        &ids,
        i["now"].as_f64().unwrap_or(f64::NAN),
        i["max_age_ms"].as_f64().unwrap_or(f64::NAN),
        i.get("scope").and_then(Value::as_str),
        None,
        i.get("last"),
    )
    .is_ok()
}

/// The evidence of an `intent_revocation` input: the input without the parameters `session`, `scope`, `authority`, `ids`,
/// `now`, `max_age_ms`, `last` (README rule 13: it is closed, so any other member makes it malformed).
fn revocation_evidence_of(i: &Value) -> Value {
    let mut ev = i.as_object().cloned().unwrap_or_default();
    for k in ["session", "scope", "authority", "ids", "now", "max_age_ms", "last"] {
        ev.remove(k);
    }
    Value::Object(ev)
}

/// Rule 19 (`primitives.intent_map_commit`): the commitment of a full leaf list.
#[test]
fn intent_map_commit_primitives() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for e in prim(&doc, "intent_map_commit") {
        let got = map_commit_of_leaves(&input_of(&e)["leaves"]);
        if got.as_deref() != e["expect"]["map_commit"].as_str() {
            bad.push(format!("{}: map_commit {got:?}", e["name"]));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Rule 19 (`primitives.intent_map`): the Z0 decision; `ok` and, when ok, `cell` and `p_ppm` exactly.
#[test]
fn intent_map_primitives() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for e in prim(&doc, "intent_map") {
        let input = input_of(&e);
        let i = &input;
        let eps = i.get("max_residual_risk_ppm").and_then(Value::as_i64);
        let d = decide_map_disclosure(i.get("map_commit"), &i["action"], i.get("params"), i.get("disclosure"), eps);
        let want = &e["expect"];
        if Some(d.ok) != want["ok"].as_bool() {
            bad.push(format!("{}: ok = {} ({})", e["name"], d.ok, d.reason));
            continue;
        }
        if d.ok && (serde_json::json!(d.cell) != want["cell"] || Some(d.p_ppm) != want["p_ppm"].as_i64()) {
            bad.push(format!("{}: cell {:?} p_ppm {}", e["name"], d.cell, d.p_ppm));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The suite rule of the W-B primitives: an entry whose `requires_suite` this build lacks must be refused with a reason
/// containing `unsupported_suite`; an `expect.reason_contains` must appear in the reason. `Some(Err)` = a mismatch,
/// `Some(Ok)` = the entry is settled by this rule, `None` = compare it normally.
fn wb_suite_rule(e: &Value, refused: bool, reason: &str) -> Option<Result<(), String>> {
    let name = e["name"].as_str().unwrap_or("?");
    if let Some(suite) = unsupported_required_suite(e) {
        return Some(if refused && reason.contains("unsupported_suite") {
            Ok(())
        } else {
            Err(format!("{name}: requires_suite {suite} not implemented, so it must be refused with unsupported_suite ({reason})"))
        });
    }
    match e["expect"].get("reason_contains").and_then(Value::as_str) {
        Some(rc) if !reason.contains(rc) => Some(Err(format!("{name}: reason {reason:?} does not contain {rc:?}"))),
        _ => None,
    }
}

/// Rule 16 (`primitives.intent_world`): `ok` and, when true, `world` and `single_source` exactly.
#[test]
fn intent_world_primitives() {
    let doc = load("vectors.json");
    let es = prim(&doc, "intent_world");
    assert!(!es.is_empty());
    let mut bad = Vec::new();
    for e in es {
        let name = e["name"].as_str().unwrap_or("?");
        let d = decide_intent_world(&input_of(&e));
        match wb_suite_rule(&e, !d.ok, &d.reason) {
            Some(Err(m)) => {
                bad.push(m);
                continue;
            }
            Some(Ok(())) => continue,
            None => {}
        }
        let want = &e["expect"];
        if Some(d.ok) != want["ok"].as_bool() {
            bad.push(format!("{name}: ok = {} ({})", d.ok, d.reason));
            continue;
        }
        if d.ok {
            let ss: Vec<Value> = d.single_source.iter().cloned().map(Value::String).collect();
            if Value::Object(d.world.clone()) != want["world"] || Value::Array(ss) != want["single_source"] {
                bad.push(format!("{name}: world {:?} / single_source {:?}", d.world, d.single_source));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Rule 17 (`primitives.intent_provenance`): `outcome` and, unless `deny`, `labels`, `classes` and (question) `friction`.
#[test]
fn intent_provenance_primitives() {
    let doc = load("vectors.json");
    let es = prim(&doc, "intent_provenance");
    assert!(!es.is_empty());
    let mut bad = Vec::new();
    for e in es {
        let name = e["name"].as_str().unwrap_or("?");
        let d = decide_param_provenance(&input_of(&e));
        match wb_suite_rule(&e, d.outcome == "deny", &d.reason) {
            Some(Err(m)) => {
                bad.push(m);
                continue;
            }
            Some(Ok(())) => continue,
            None => {}
        }
        let want = &e["expect"];
        if Some(d.outcome.as_str()) != want["outcome"].as_str() {
            bad.push(format!("{name}: outcome = {} ({})", d.outcome, d.reason));
            continue;
        }
        if d.outcome != "deny" {
            if Value::Object(d.labels.clone()) != want["labels"] || Value::Object(d.classes.clone()) != want["classes"] {
                bad.push(format!("{name}: labels {:?} / classes {:?}", d.labels, d.classes));
            }
            if d.outcome == "question" && d.friction.as_deref() != want["friction"].as_str() {
                bad.push(format!("{name}: friction {:?}", d.friction));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Rule 18 (`primitives.intent_classifier`): `ok` and, when true, `classes` exactly.
#[test]
fn intent_classifier_primitives() {
    let doc = load("vectors.json");
    let es = prim(&doc, "intent_classifier");
    assert!(!es.is_empty());
    let mut bad = Vec::new();
    for e in es {
        let name = e["name"].as_str().unwrap_or("?");
        let d = decide_classifier_dimensions(&input_of(&e));
        match wb_suite_rule(&e, !d.ok, &d.reason) {
            Some(Err(m)) => {
                bad.push(m);
                continue;
            }
            Some(Ok(())) => continue,
            None => {}
        }
        let want = &e["expect"];
        if Some(d.ok) != want["ok"].as_bool() {
            bad.push(format!("{name}: ok = {} ({})", d.ok, d.reason));
            continue;
        }
        if d.ok && Value::Object(d.classes.clone()) != want["classes"] {
            bad.push(format!("{name}: classes {:?}", d.classes));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// The W-B activity rule (`primitives.intent_wb_active`): which of `facts`, `provenance`, `classes` are reported.
#[test]
fn intent_wb_active_primitives() {
    let doc = load("vectors.json");
    let mut bad = Vec::new();
    for e in prim(&doc, "intent_wb_active") {
        let name = e["name"].as_str().unwrap_or("?");
        let (f, p, c) = intent_wb_active(&input_of(&e));
        let want = &e["expect"];
        if Some(f) != want["facts"].as_bool() || Some(p) != want["provenance"].as_bool() || Some(c) != want["classes"].as_bool() {
            bad.push(format!("{name}: ({f}, {p}, {c})"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

/// Read purpose (`primitives.intent_read_purpose`, V14): `{outcome, minimise, uncovered}` exactly.
#[test]
fn intent_read_purpose_primitives() {
    let doc = load("vectors.json");
    let es = prim(&doc, "intent_read_purpose");
    assert!(!es.is_empty());
    let mut bad = Vec::new();
    for e in es {
        let name = e["name"].as_str().unwrap_or("?");
        let d = decide_read_purpose(&input_of(&e));
        let got = serde_json::json!({ "outcome": d.outcome, "minimise": d.minimise, "uncovered": d.uncovered });
        if got != e["expect"] {
            bad.push(format!("{name}: {got}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

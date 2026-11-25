//! Differential replay of the zero-knowledge compliance module against the TypeScript reference: every case of
//! test-data/ref-zk.json.gz (1429: commitments, binding tag, struct and risk hashes, quantizers, signal decoders, context pins,
//! the canonical envelope gate, verifyPolicyVmProof, the four SNARK backends, the verifier hook, the attested prover, circuit
//! versions, trusted-setup provenance, constants, the prover contract). An unknown function fails the test.
//!
//! The pairing check: with cargo feature `zk` it is the real engine (the pca-zk crate). Without it, a case that reaches the
//! pairing gets the reference's recorded verdict of that case, so every gate in front of it is still compared; the cases the
//! gates alone decide may not ask the engine at all.
mod common;
use atlas_pca::assurance::AssuranceLabel;
use atlas_pca::attest::{AttResult, Binding};
use atlas_pca::serde_json::{json, Map, Number, Value};
use atlas_pca::zk::*;
use atlas_pca::zk_ceremony::*;
use atlas_pca::HookResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

static NULL: Value = Value::Null;
const FAIL_CLOSED: &str = "zk verification error (fail closed)";
/// verifyPolicyVmProof cases (after the curve prefix) that a gate in front of the pairing refuses on a proof the pairing accepts.
const GATE_ONLY: [&str; 7] = ["expect-now-wrong", "expect-thunk-throws", "expectRiskHash", "circuit-", "system-", "extra-key", "proof-extra-key"];

enum Got {
    Value(Value),
    Refused(String),
}

fn res<T: Into<Value>>(r: Result<T, String>) -> Got {
    match r {
        Ok(v) => Got::Value(v.into()),
        Err(e) => Got::Refused(e),
    }
}

/// The corpus conventions: `{"$bigint": "<decimal>"}` is that integer (a JSON number here), `{"$num": ...}` a NaN or an
/// infinity, which JSON cannot carry (`None`).
fn revive(v: &Value) -> Option<Value> {
    Some(match v {
        Value::Array(a) => Value::Array(a.iter().map(revive).collect::<Option<Vec<_>>>()?),
        Value::Object(m) if m.len() == 1 && m.contains_key("$num") => return None,
        Value::Object(m) if m.len() == 1 && m.contains_key("$bigint") => {
            let s = m["$bigint"].as_str()?;
            match (s.parse::<u64>(), s.parse::<i64>()) {
                (Ok(u), _) => json!(u),
                (_, Ok(i)) => json!(i),
                _ => Value::Number(Number::from_f64(s.parse::<f64>().ok()?)?),
            }
        }
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m {
                out.insert(k.clone(), revive(x)?);
            }
            Value::Object(out)
        }
        other => other.clone(),
    })
}

fn big(xs: &[u64]) -> Value {
    Value::Array(xs.iter().map(|x| json!({ "$bigint": x.to_string() })).collect())
}

fn halves_json(h: DigestHalves) -> Value {
    json!({ "hi": h.hi, "lo": h.lo })
}

fn halves(v: Option<&Value>) -> Option<DigestHalves> {
    let v = v?;
    Some(DigestHalves { hi: v["hi"].as_str()?.to_string(), lo: v["lo"].as_str()?.to_string() })
}

fn label_json(l: &AssuranceLabel) -> Value {
    let mut m = Map::new();
    m.insert("level".into(), json!(l.level));
    if let Some(v) = &l.vendor {
        m.insert("vendor".into(), json!(v));
    }
    if let Some(c) = &l.ceremony {
        m.insert("ceremony".into(), json!(c));
    }
    Value::Object(m)
}

fn layout_json(l: &PolicyVmSignalLayout) -> Value {
    let mut m = json!({
        "actionHi": l.action_hi, "actionLo": l.action_lo, "policyHi": l.policy_hi, "policyLo": l.policy_lo, "planHi": l.plan_hi, "planLo": l.plan_lo,
        "r": l.r, "t": l.t, "admit": l.admit, "allow": l.allow, "now": l.now, "blast": l.blast, "delegationDepth": l.delegation_depth,
        "recentCount": l.recent_count, "allocChild": l.alloc_child,
    });
    if let (Some(hi), Some(lo)) = (l.risk_hi, l.risk_lo) {
        m["riskHi"] = json!(hi);
        m["riskLo"] = json!(lo);
    }
    m
}

fn constants() -> Value {
    json!({
        "ZK_PROVER_BINDING_REF": ZK_PROVER_BINDING_REF,
        "POLICYVM_PUBLIC_SIGNAL": layout_json(&POLICYVM_PUBLIC_SIGNAL), "POLICYVM_PUBLIC_SIGNAL_COUNT": POLICYVM_PUBLIC_SIGNAL_COUNT,
        "POLICYVM_BOUND_PUBLIC_SIGNAL": layout_json(&POLICYVM_BOUND_PUBLIC_SIGNAL), "POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT": POLICYVM_BOUND_PUBLIC_SIGNAL_COUNT,
        "POLICYVM_BOUND_RISK_FIELDS": POLICYVM_BOUND_RISK_FIELDS, "POLICYVM_REVERSIBILITY_ORDER": POLICYVM_REVERSIBILITY_ORDER,
        "paths": {
            "DEFAULT_VKEY_PATH": DEFAULT_VKEY_PATH, "DEFAULT_WASM_PATH": DEFAULT_WASM_PATH, "DEFAULT_ZKEY_PATH": DEFAULT_ZKEY_PATH,
            "POLICYVM_VKEY_PATH": POLICYVM_VKEY_PATH, "POLICYVM_SAMPLE_PROOF_PATH": POLICYVM_SAMPLE_PROOF_PATH, "POLICYVM_WASM_PATH": POLICYVM_WASM_PATH,
            "POLICYVM_ZKEY_PATH": POLICYVM_ZKEY_PATH, "POLICYVM_BLS12381_VKEY_PATH": POLICYVM_BLS12381_VKEY_PATH,
            "POLICYVM_BLS12381_SAMPLE_PROOF_PATH": POLICYVM_BLS12381_SAMPLE_PROOF_PATH, "POLICYVM_BOUND_VKEY_PATH": POLICYVM_BOUND_VKEY_PATH,
            "POLICYVM_BOUND_SAMPLE_PROOF_PATH": POLICYVM_BOUND_SAMPLE_PROOF_PATH, "POLICYVM_BOUND_WASM_PATH": POLICYVM_BOUND_WASM_PATH,
            "POLICYVM_BOUND_ZKEY_PATH": POLICYVM_BOUND_ZKEY_PATH,
        },
    })
}

/// Answers the reference's recorded verdict and remembers that it was asked.
struct Recorded {
    verdict: bool,
    asked: AtomicBool,
}

impl Groth16Engine for Recorded {
    fn verify(&self, _vkey: &Value, _public_signals: &Value, _proof: &Value) -> Result<bool, String> {
        self.asked.store(true, Ordering::SeqCst);
        Ok(self.verdict)
    }
}

/// The engine of one case: the built-in one (`None`) with cargo feature `zk`, else the recorded verdict.
fn engine_for(verdict: bool) -> (Option<Arc<dyn Groth16Engine>>, Arc<Recorded>) {
    let rec = Arc::new(Recorded { verdict, asked: AtomicBool::new(false) });
    let engine: Arc<dyn Groth16Engine> = rec.clone();
    (if cfg!(feature = "zk") { None } else { Some(engine) }, rec)
}

/// A corpus expectation: `"$absent"` = none, `{"$expectThunk": X}` = computed at verification (`"throw"` fails), else fixed.
fn expect_source(e: &Value) -> Option<PolicyVmExpectSource> {
    if *e == "$absent" {
        return None;
    }
    if let Some(t) = e.get("$expectThunk").cloned() {
        return Some(PolicyVmExpectSource::Dynamic(Arc::new(move || if t == "throw" { Err("thunk".to_string()) } else { Ok(t.clone()) })));
    }
    Some(PolicyVmExpectSource::Fixed(e.clone())) // as written: the reference is given these expectations unrevived
}

fn proof_opts(o: &Value, engine: Option<Arc<dyn Groth16Engine>>) -> ZkProofOpts {
    ZkProofOpts {
        verification_key: o.get("verificationKey").filter(|k| !k.is_null()).cloned(),
        verification_key_path: None,
        expect: o.get("expect").and_then(expect_source),
        expect_action_hash: halves(o.get("expectActionHash")),
        expect_policy_hash: halves(o.get("expectPolicyHash")),
        expect_plan_hash: halves(o.get("expectPlanHash")),
        expect_risk_hash: halves(o.get("expectRiskHash")),
        ceremony: o.get("ceremony").cloned(),
        engine,
    }
}

fn make_backend(kind: &str, opts: ZkProofOpts) -> ZkSnarkBackend {
    match kind {
        "createGroth16SnarkBackend" | "groth16" => create_groth16_snark_backend(opts),
        "createPolicyVmSnarkBackend" | "policyvm" => create_policy_vm_snark_backend(opts),
        "createPolicyVmSnarkBackendBls12381" | "policyvm-bls" => create_policy_vm_snark_backend_bls12381(opts),
        "createPolicyVmBoundSnarkBackend" | "policyvm-bound" => create_policy_vm_bound_snark_backend(opts),
        other => panic!("unknown backend kind {other}"),
    }
}

fn hook_json(r: HookResult) -> Value {
    match r {
        HookResult::NotEnforced => json!({ "enforced": false }),
        HookResult::Enforced { ok: true, .. } => json!({ "enforced": true, "ok": true }),
        // the reference corpus cuts the engine text after the fail-closed prefix
        HookResult::Enforced { reason, .. } => {
            let r = reason.unwrap_or_default();
            json!({ "enforced": true, "ok": false, "reason": if r.starts_with(FAIL_CLOSED) { FAIL_CLOSED.to_string() } else { r } })
        }
    }
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    Some(v?.as_array()?.iter().filter_map(|x| x.as_str().map(str::to_string)).collect())
}

fn zk_verifier(spec: &Value, ctx: &Value, want_ok: bool) -> Value {
    let (engine, _) = engine_for(want_ok);
    let now = spec["nowMs"].as_i64().expect("nowMs");
    let opts = ZkVerifierOpts {
        trusted_prover_keys: strings(spec.get("trustedProverKeys")).unwrap_or_default(),
        policy_commitments: strings(spec.get("policyCommitments")),
        snark_backend: spec.get("snark").map(|s| Arc::new(make_backend(s["kind"].as_str().expect("kind"), proof_opts(&s["opts"], engine.clone()))) as Arc<dyn SnarkBackend>),
        revoked_prover_keys: strings(spec.get("revokedProverKeys")).unwrap_or_default(),
        prover_attestation: None,
        now: Some(Arc::new(move || now)),
        clock_skew_ms: match spec.get("clockSkewMs") {
            None => 0.0,
            Some(v) => v.as_f64().unwrap_or(f64::NAN), // {"$num": "NaN"} is the only non-number in the corpus
        },
    };
    let hook = create_zk_verifier(opts).expect("a verifier without prover attestation is always built");
    json!({ "result": hook_json(hook.verify(ctx)), "label": label_json(hook.label()) })
}

/// The prover contract: proving the committed sample witness gives exactly the recorded public signals (the three struct
/// commitments are recomputed here), and the proof verifies under the bundled key. The proof itself needs the proving key and
/// the witness calculator, which are build artifacts: PCA_ZK_POLICYVM_WASM / PCA_ZK_POLICYVM_ZKEY name them.
fn prover_contract(w: &Value, want: &Value) -> Value {
    let ps = &want["publicSignals"];
    let fields = |keys: &[&str]| keys.iter().map(|k| w[*k].clone()).collect::<Vec<Value>>();
    let commit = |keys: &[&str], hi: usize| {
        let h = policy_vm_struct_hash(&fields(keys)).expect("sample struct");
        assert_eq!((json!(h.hi), json!(h.lo)), (ps[hi].clone(), ps[hi + 1].clone()), "struct commitment at signal {hi}");
    };
    commit(&["verb", "resource", "reversibility", "paramScalar"], 0);
    commit(&["wAlpha", "wBeta", "wGamma", "wDelta", "wEpsilon", "wZeta", "theta1", "theta2", "kappa", "budgetB", "policyVerb", "policyResource", "policyParamBound", "expiresAt", "notBefore", "maxBlast", "maxDepth", "revMax", "rateMax", "allocParent"], 2);
    commit(&["planVerb", "planResource", "semanticDist", "planSalt"], 4);
    assert!(prove_policy_vm_compliance(w, &ZkProverOpts::default()).is_err(), "a prover without artifacts refuses");
    assert!(prove_policy_vm_compliance(&json!([1]), &ZkProverOpts { wasm_path: Some("w".into()), zkey_path: Some("z".into()) }).is_err(), "a witness that is not an object is refused");
    if let (true, Ok(wasm), Ok(zkey)) = (cfg!(feature = "zk"), std::env::var("PCA_ZK_POLICYVM_WASM"), std::env::var("PCA_ZK_POLICYVM_ZKEY")) {
        let env = prove_policy_vm_compliance(w, &ZkProverOpts { wasm_path: Some(wasm), zkey_path: Some(zkey) }).expect("prove the sample witness");
        assert_eq!(&env["publicSignals"], ps, "public signals of the sample witness");
        assert_eq!((&env["system"], &env["circuit"]), (&json!("groth16-bn254"), &want["sampleProofCircuit"]));
        assert_eq!(verify_policy_vm_proof(&env, &ZkProofOpts::default()), Ok(true), "the fresh proof verifies under the bundled key");
    }
    want.clone()
}

fn run(f: &str, name: &str, a: &[Value], want: &Value) -> Got {
    let arg = |i: usize| a.get(i).unwrap_or(&NULL);
    // options argument: absent = none given, anything else as it is (a null is refused, as in the reference)
    let opts = |i: usize| a.get(i).cloned().unwrap_or_else(|| json!({}));
    let unrepresentable = || Got::Refused("NaN and the infinities are not JSON".into());
    let by_type = || Got::Refused("refused by the argument type".into());
    let reason = |r: Option<String>| Got::Value(r.map_or(Value::Null, Value::String));
    match f {
        "constants" => Got::Value(constants()),
        "policyCommitment" => res(policy_commitment(arg(0))),
        "pinnedPolicyCommitment" => res(pinned_policy_commitment(arg(0))),
        "actionCommitment" => res(action_commitment(arg(0))),
        "proverKeyBinding" => {
            let b = prover_key_binding(arg(0).as_str().expect("key"), arg(1).as_f64().expect("epoch"), arg(2).as_str().expect("nonce"));
            let epoch = if b.epoch.fract() == 0.0 { json!(b.epoch as i64) } else { json!(b.epoch) };
            Got::Value(json!({ "holderPub": b.holder_pub, "grantRef": b.grant_ref, "epoch": epoch, "nonce": b.nonce }))
        }
        "commitmentField" => match arg(0).as_str() {
            Some(s) => res(commitment_field(s)),
            None => by_type(),
        },
        "isCanonicalGroth16Envelope" => Got::Value(json!(is_canonical_groth16_envelope(arg(0), arg(1).as_str().unwrap_or("")))),
        "policyVmStructHash" | "policyVmRiskHash" => {
            let Some(fields) = arg(0).as_array() else { return by_type() };
            let Some(fields) = fields.iter().map(revive).collect::<Option<Vec<Value>>>() else { return unrepresentable() };
            res(if f == "policyVmStructHash" { policy_vm_struct_hash(&fields) } else { policy_vm_risk_hash(&fields) }.map(halves_json))
        }
        "quantizeActionStruct" | "policyVmCommitmentFromAction" | "quantizePlanStruct" | "quantizePolicyStruct" | "quantizePolicyVmInputs" => {
            let (Some(x), Some(o)) = (revive(arg(0)), revive(&opts(1))) else { return unrepresentable() };
            match f {
                "quantizeActionStruct" => res(quantize_action_struct(&x, &o).map(|s| big(&s))),
                "policyVmCommitmentFromAction" => res(policy_vm_commitment_from_action(&x, &o).map(halves_json)),
                "quantizePlanStruct" => res(quantize_plan_struct(&x, &o).map(|s| big(&s))),
                "quantizePolicyStruct" => res(quantize_policy_struct(&x, &o).map(|s| big(&s))),
                _ => res(quantize_policy_vm_inputs(&x, &o).map(|q| {
                    let mut m = Map::new();
                    m.insert("action".into(), big(&q.action));
                    if let Some(p) = q.plan {
                        m.insert("plan".into(), big(&p));
                    }
                    if let Some(p) = q.policy {
                        m.insert("policy".into(), big(&p));
                    }
                    Value::Object(m)
                })),
            }
        }
        "decodePolicyVmPublic" => res(decode_policy_vm_public(arg(0))),
        "decodePolicyVmBoundPublic" => res(decode_policy_vm_bound_public(arg(0))),
        "policyVmContextMatches" => {
            let layout = if *arg(2) == "bound" { &POLICYVM_BOUND_PUBLIC_SIGNAL } else { &POLICYVM_PUBLIC_SIGNAL };
            res(policy_vm_context_matches(arg(0), expect_source(arg(1)).as_ref(), layout))
        }
        "verifyPolicyVmProof" => {
            let (engine, rec) = engine_for(want == true);
            let got = verify_policy_vm_proof(arg(0), &proof_opts(arg(1), engine));
            let stem = name.splitn(3, '/').nth(2).unwrap_or("");
            if !cfg!(feature = "zk") && GATE_ONLY.iter().any(|g| stem.starts_with(g)) {
                assert!(!rec.asked.load(Ordering::SeqCst), "{name}: a gate must refuse this proof before the pairing check");
            }
            res(got)
        }
        "createGroth16SnarkBackend" | "createPolicyVmSnarkBackend" | "createPolicyVmSnarkBackendBls12381" | "createPolicyVmBoundSnarkBackend" => {
            let (engine, _) = engine_for(want["verified"] == true);
            let b = make_backend(f, proof_opts(arg(0), engine));
            let input = arg(1);
            let label = label_json(b.label());
            assert_eq!(SnarkBackend::assurance_label(&b).as_ref(), Some(b.label()), "{name}: the backend declares its label");
            res(b.verify(input.get("proof").unwrap_or(&NULL), input.get("publicInputs").unwrap_or(&NULL), input.get("ctx").unwrap_or(&NULL)).map(|verified| json!({ "verified": verified, "label": label })))
        }
        "createZkVerifier" => Got::Value(zk_verifier(arg(0), arg(1), want["result"]["ok"] == true)),
        "createAttestedComplianceProver" => {
            use sha2::{Digest, Sha256};
            let label = arg(0)["$bytes"]["$seed"].as_str().expect("seed label");
            let secret: [u8; 32] = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into();
            let p = create_attested_compliance_prover(&secret);
            let o = arg(1);
            res(p.prove(&o["pcactn"], &o["decideInput"], o["issued_at"].as_i64().expect("issued_at"), o["expires_at"].as_i64().expect("expires_at")).map(|st| json!({ "publicKey": p.public_key(), "statement": st })))
        }
        "circuitVersion" => match arg(0).as_str() {
            Some(id) => res(circuit_version(id).map(|v| json!({ "circuit": v.circuit, "sourceSha256": v.source_sha256, "circom": v.circom, "circomlib": v.circomlib }))),
            None => by_type(),
        },
        "provePolicyVmCompliance" => Got::Value(prover_contract(arg(0), want)),
        // trusted-setup provenance (src/zk_ceremony.rs)
        "vkId" => res(vk_id(arg(0))),
        "circuitProvenance" => res(circuit_provenance(arg(0))),
        "checkCircuitProvenance" => reason(check_circuit_provenance(arg(0), arg(1))),
        "transcriptSha256" => res(transcript_sha256(arg(0))),
        "checkTranscript" => reason(check_transcript(arg(0), &a.get(1).filter(|o| o.is_object()).cloned().unwrap_or_else(|| json!({})))),
        "ceremonyOf" => Got::Value(json!(ceremony_of(a.first(), a.get(1)))),
        other => panic!("{name}: the corpus has a function this test does not replay: {other}"),
    }
}

#[test]
fn every_zk_case_matches_the_reference() {
    let (mut ran, mut bad) = (0usize, Vec::new());
    for c in common::ref_cases("zk") {
        let (f, name, want) = (c["fn"].as_str().expect("fn"), c["name"].as_str().expect("name"), &c["out"]);
        let args = c["args"].as_array().cloned().unwrap_or_default();
        let got = run(f, name, &args, want);
        ran += 1;
        let ok = match (&got, want.get("$throws").is_some()) {
            (Got::Refused(_), threw) => threw,
            (Got::Value(_), true) => false,
            (Got::Value(v), false) => {
                // a Rust string cannot hold the lone surrogate the reference fails closed on: any denial of that case is right
                let lone = f == "createZkVerifier" && common::has_lone(&c["args"]) && want["result"]["reason"] == FAIL_CLOSED && v["result"]["ok"] == false;
                lone || atlas_pca::canonicalize(v) == atlas_pca::canonicalize(want)
            }
        };
        if !ok {
            let got = match got {
                Got::Value(v) => v.to_string(),
                Got::Refused(e) => format!("refused: {e}"),
            };
            bad.push(format!("{name}\n  want {want}\n  got  {got}"));
        }
    }
    assert_eq!(ran, 1429, "zk cases replayed");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.iter().take(40).cloned().collect::<Vec<_>>().join("\n"));
}

/// The first case named `name`.
fn case(name: &str) -> Value {
    common::ref_cases("zk").into_iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("no case {name}"))
}

/// Hands the verifying key it was asked about to the test.
struct Capture(Mutex<Option<Value>>);

impl Groth16Engine for Capture {
    fn verify(&self, vkey: &Value, _public_signals: &Value, _proof: &Value) -> Result<bool, String> {
        *self.0.lock().expect("lock") = Some(vkey.clone());
        Ok(true)
    }
}

#[test]
fn the_bundled_keys_are_the_reference_keys() {
    for curve in ["bn", "bls"] {
        let c = case(&format!("verifyPolicyVmProof/{curve}/valid"));
        let capture = Arc::new(Capture(Mutex::new(None)));
        let engine: Arc<dyn Groth16Engine> = capture.clone();
        let opts = ZkProofOpts { engine: Some(engine), ..Default::default() };
        assert_eq!(verify_policy_vm_proof(&c["args"][0], &opts), Ok(true), "{curve}: the sample proof reaches the pairing check");
        let used = capture.0.lock().expect("lock").clone().expect("the engine was asked");
        assert_eq!(atlas_pca::canonicalize(&used), atlas_pca::canonicalize(&c["args"][1]["verificationKey"]), "{curve}: bundled verifying key");
    }
}

#[test]
fn the_built_in_engine() {
    let c = case("verifyPolicyVmProof/bn/valid");
    let (env, key) = (&c["args"][0], &c["args"][1]["verificationKey"]);
    let answer = DefaultGroth16Engine::default().verify(key, &env["publicSignals"], &env["proof"]);
    if cfg!(feature = "zk") {
        assert_eq!(answer, Ok(true), "the sample proof verifies");
        let mut renamed = key.clone();
        renamed["curve"] = json!("ALT_BN128");
        assert_eq!(DefaultGroth16Engine::default().verify(&renamed, &env["publicSignals"], &env["proof"]), Ok(true), "the curve name is read as snarkjs reads it");
        assert_eq!(DefaultGroth16Engine { strict: true }.verify(&renamed, &env["publicSignals"], &env["proof"]), Ok(false), "strict takes the exact curve name only");
        assert_eq!(DefaultGroth16Engine { strict: true }.verify(key, &env["publicSignals"], &env["proof"]), Ok(true), "strict verifies the sample proof");
        // snarkjs ignores the key's protocol, nPublic and extra IC entries; the strict engine does not
        for quirk in ["quirk-vkey-ic-long", "quirk-vkey-nPublic-14", "quirk-vkey-protocol-plonk"] {
            let q = case(&format!("verifyPolicyVmProof/bn/{quirk}"));
            let (env, key) = (&q["args"][0], &q["args"][1]["verificationKey"]);
            assert_eq!(DefaultGroth16Engine { strict: false }.verify(key, &env["publicSignals"], &env["proof"]), Ok(true), "{quirk}: snarkjs rules");
            assert_eq!(DefaultGroth16Engine { strict: true }.verify(key, &env["publicSignals"], &env["proof"]), Ok(false), "{quirk}: strict");
        }
    } else {
        // no pairing engine: nothing verifies, and nothing is reported as verified
        assert!(answer.is_err());
        assert_eq!(verify_policy_vm_proof(env, &ZkProofOpts::default()), Ok(false));
        let unverified = create_policy_vm_snark_backend(ZkProofOpts::default()).verify(env, &NULL, &NULL);
        assert_eq!(unverified, Ok(false));
    }
}

#[test]
fn a_statement_from_the_prover_passes_the_hook_of_authorize() {
    let c = case("createAttestedComplianceProver/compliant");
    let o = &c["args"][1];
    let prover = create_attested_compliance_prover(&[7u8; 32]);
    let (issued, expires) = (o["issued_at"].as_i64().expect("issued_at"), o["expires_at"].as_i64().expect("expires_at"));
    let statement = prover.prove(&o["pcactn"], &o["decideInput"], issued, expires).expect("compliant");
    let mut pcactn = o["pcactn"].clone();
    pcactn["zk_compliance"] = statement;
    let grant = &o["decideInput"]["grant"];
    let opts = |keys: Vec<String>| ZkVerifierOpts { trusted_prover_keys: keys, now: Some(Arc::new(move || issued)), ..Default::default() };
    let hook = create_zk_verifier(opts(vec![prover.public_key().to_string()])).expect("verifier").into_hook();
    assert_eq!(hook(&pcactn, grant, 0), HookResult::Enforced { ok: true, reason: None, t: None });
    let other = create_zk_verifier(opts(vec!["other".into()])).expect("verifier").into_hook();
    assert_eq!(other(&pcactn, grant, 0), HookResult::Enforced { ok: false, reason: Some("prover key is not trusted".into()), t: None });
}

#[test]
fn prover_attestation_binds_the_prover_key_to_hardware_evidence() {
    let c = case("createZkVerifier/ok");
    let (spec, ctx) = (&c["args"][0], &c["args"][1]);
    let prover = spec["trustedProverKeys"][0].as_str().expect("prover key").to_string();
    let now = spec["nowMs"].as_i64().expect("nowMs");
    let attestation = |label: AssuranceLabel, measurements: Vec<&str>, hw: AttResult| {
        let expect_key = prover.clone();
        ProverAttestationOpts {
            hardware_label: label,
            verify_hardware: Arc::new(move |key: &str, _ctx: &Value, at: i64, expected: &Binding| {
                assert_eq!((key, at, expected.holder_pub.as_str(), expected.grant_ref.as_str()), (expect_key.as_str(), now, expect_key.as_str(), ZK_PROVER_BINDING_REF));
                hw.clone()
            }),
            expected_binding: Arc::new(|key: &str| if key.is_empty() { Err("no prover".to_string()) } else { Ok(prover_key_binding(key, 3.0, "nonce")) }),
            measurements: measurements.into_iter().map(str::to_string).collect(),
        }
    };
    let build = |label: AssuranceLabel, measurements: Vec<&str>, hw: AttResult| {
        create_zk_verifier(ZkVerifierOpts { trusted_prover_keys: vec![prover.clone()], now: Some(Arc::new(move || now)), prover_attestation: Some(attestation(label, measurements, hw)), ..Default::default() })
    };
    let hardware = || AssuranceLabel::new("hardware").with_vendor("amd-sev-snp");
    let measured = |m: &str| {
        let mut id = Map::new();
        id.insert("runtime_measurement".into(), json!(m));
        AttResult { ok: true, bound: Some(true), measured: Some(id), ..Default::default() }
    };
    let verdict = |hw: AttResult| hook_json(build(hardware(), vec!["m1", "m2"], hw).expect("verifier").verify(ctx));
    let denied = |r: &str| json!({ "enforced": true, "ok": false, "reason": r });

    // construction: a hardware or multi-root verifier and a real allowlist, nothing less
    assert!(build(AssuranceLabel::new("software"), vec!["m1"], measured("m1")).is_err());
    assert!(build(hardware(), vec![], measured("m1")).is_err());
    assert!(build(hardware(), vec!["m1", ""], measured("m1")).is_err());
    let v = build(hardware(), vec!["m1"], measured("m1")).expect("verifier");
    assert_eq!(label_json(v.label()), json!({ "level": "attested_vm_hw", "vendor": "hardware-bound:amd-sev-snp" }));
    let v = build(AssuranceLabel::new("multi_root"), vec!["m1"], measured("m1")).expect("verifier");
    assert_eq!(label_json(v.label()), json!({ "level": "attested_vm_hw", "vendor": "hardware-bound:multi_root" }));

    // verification: only a valid, bound, measured, allowlisted identity passes
    assert_eq!(verdict(measured("m2")), json!({ "enforced": true, "ok": true }));
    assert_eq!(verdict(measured("m3")), denied("prover VM measurement is not allowlisted"));
    assert_eq!(verdict(AttResult::fail("quote expired")), denied("prover hardware evidence invalid: quote expired"));
    assert_eq!(verdict(AttResult::default()), denied("prover hardware evidence invalid: no reason given"));
    assert_eq!(verdict(AttResult { bound: Some(false), ..measured("m1") }), denied("prover hardware evidence does not bind the prover key"));
    assert_eq!(verdict(AttResult { bound: None, ..measured("m1") }), denied("prover hardware evidence does not bind the prover key"));
    assert_eq!(verdict(AttResult { measured: None, ..measured("m1") }), denied("prover hardware evidence carries no measured identity"));
    assert_eq!(verdict(AttResult { measured: Some(Map::new()), ..measured("m1") }), denied("prover hardware evidence carries no measured identity"));

    // a SNARK backend replaces the attested-VM mode, hardware binding included
    let backend: Arc<dyn SnarkBackend> = Arc::new(create_policy_vm_snark_backend(ZkProofOpts::default()));
    let unused = attestation(AssuranceLabel::new("software"), vec![], measured("m1"));
    let with_backend = create_zk_verifier(ZkVerifierOpts { snark_backend: Some(backend), prover_attestation: Some(unused), ..Default::default() }).expect("verifier");
    assert_eq!(label_json(with_backend.label()), json!({ "level": "unknown", "vendor": "policyvm-unbound", "ceremony": "single-party" }));
}

#[test]
fn the_compliance_prover_refuses_without_its_inputs() {
    let commit = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
    let mut inp = json!({ "action_commit": commit, "policy_commit": commit, "plan_commit": commit });
    for k in ["verb", "resource", "planVerb", "policySalt", "planSalt", "actionSalt", "risk", "budget"] {
        inp[k] = json!(1);
    }
    let paths = ZkProverOpts { wasm_path: Some("missing.wasm".into()), zkey_path: Some("missing.zkey".into()) };
    assert!(prove_groth16_compliance(&inp, &ZkProverOpts::default()).is_err(), "no artifacts");
    assert!(prove_groth16_compliance(&inp, &paths).is_err(), "artifacts that do not exist");
    assert!(prove_policy_vm_bound_compliance(&json!({ "verb": "7" }), &paths).is_err(), "artifacts that do not exist");
    inp["plan_commit"] = json!("!!");
    assert!(prove_groth16_compliance(&inp, &paths).unwrap_err().contains("base64url"), "a commitment that is not base64url");
    inp.as_object_mut().expect("object").remove("risk");
    assert!(prove_groth16_compliance(&inp, &paths).unwrap_err().contains("risk"), "a missing witness member");
}

/// Loosely typed input is read as the JavaScript reference reads it; where the reference throws, the answer is `Err`.
#[test]
fn odd_typed_input_is_read_as_the_reference_reads_it() {
    let action = json!({ "verb": "read", "resource": "doc:1", "params": { "amount": 100 } });
    let plain = quantize_action_struct(&action, &json!({})).expect("plain");
    let q = |a: Value, o: Value| quantize_action_struct(&a, &o);
    // options: null throws, any other non-object has no members
    assert!(q(action.clone(), Value::Null).is_err());
    for o in [json!(5), json!("x"), json!(true), json!([]), json!(["strictCatalog"])] {
        assert_eq!(q(action.clone(), o.clone()), Ok(plain), "options {o}");
    }
    // a catalog given as an array or text has its indices and `length` as own members; other values have none
    let with_verb = |verb: &str, codes: Value| q(json!({ "verb": verb, "resource": "doc:1" }), json!({ "verbCodes": codes })).map(|s| s[0]);
    assert_eq!(with_verb("0", json!([7])), Ok(7));
    assert_eq!(with_verb("length", json!([7, 8])), Ok(2));
    assert_eq!(with_verb("length", json!("abc")), Ok(3));
    assert!(with_verb("1", json!("abc")).is_err(), "a character is not a code");
    assert!(with_verb("1", json!([7, null])).is_err(), "a null element is not a code");
    let addressed = with_verb("01", json!({})).expect("content address");
    for codes in [json!([7, 8]), json!(5), json!(true), json!(""), Value::Null] {
        assert_eq!(with_verb("01", codes.clone()), Ok(addressed), "catalog {codes}: 01 is not a member");
    }
    assert_eq!(with_verb("map", json!([7])).is_ok(), true, "an inherited member is not an own member");
    // params[field]: own members, inherited members (functions: refused), nothing (0)
    let scalar = |params: Value, field: Value| q(json!({ "verb": "read", "resource": "doc:1", "params": params }), json!({ "paramScalarField": field })).map(|s| s[3]);
    assert_eq!(scalar(json!({ "amount": 100 }), json!("amount")), Ok(100));
    assert_eq!(scalar(json!({ "amount": 100 }), json!(["amount"])), Ok(100), "the field is used through its text");
    assert_eq!(scalar(json!({ "5": 9 }), json!(5)), Ok(9));
    assert_eq!(scalar(json!({ "amount": 100 }), json!(0)), Ok(0), "a falsy field reads nothing");
    assert_eq!(scalar(json!([41, 42]), json!("1")), Ok(42));
    assert_eq!(scalar(json!([41, 42]), json!(1)), Ok(42));
    assert_eq!(scalar(json!([41, 42]), json!("length")), Ok(2));
    assert_eq!(scalar(json!([41, 42]), json!("2")), Ok(0));
    assert_eq!(scalar(json!("x7"), json!("1")), Ok(7), "a digit character is integer text");
    assert_eq!(scalar(json!("x7"), json!("length")), Ok(2));
    assert!(scalar(json!("x7"), json!("0")).is_err());
    assert_eq!(scalar(json!(5), json!("amount")), Ok(0));
    assert_eq!(scalar(json!(true), json!("amount")), Ok(0));
    for falsy in [json!(0), json!(""), json!(false), Value::Null] {
        assert_eq!(scalar(falsy.clone(), json!("constructor")), Ok(0), "params {falsy}");
    }
    for (params, field) in [(json!({}), "constructor"), (json!({}), "__proto__"), (json!([1]), "map"), (json!([1]), "toString"), (json!("x"), "trim"), (json!(5), "toFixed"), (json!(true), "valueOf")] {
        assert!(scalar(params.clone(), json!(field)).is_err(), "{params}.{field} is a function");
    }
    assert_eq!(scalar(json!({}), json!("map")), Ok(0), "an object does not inherit array members");
    assert_eq!(scalar(json!(5), json!("trim")), Ok(0));

    // struct fields: an array converts through its text
    let h = |f: Value| policy_vm_struct_hash(&[f]);
    assert_eq!(h(json!([5])), h(json!(5)));
    assert_eq!(h(json!([])), h(json!(0)));
    assert_eq!(h(json!([null])), h(json!(0)));
    assert_eq!(h(json!([["0x10"]])), h(json!(16)));
    assert!(h(json!([1, 2])).is_err() && h(json!({})).is_err() && h(Value::Null).is_err());

    // context pins
    let ps: Vec<Value> = ["1", "2", "3", "4", "5", "6", "7", "1", "1", "1", "1000", "0", "0", "0", "5"].iter().map(|s| json!(s)).collect();
    let m = |ps: Value, e: Value| policy_vm_context_matches(&ps, Some(&PolicyVmExpectSource::Fixed(e)), &POLICYVM_PUBLIC_SIGNAL);
    assert_eq!(m(json!(ps), json!({ "now": 1000, "r": "7" })), Ok(true));
    assert!(m(json!(ps), json!({ "now": null })).is_err(), "a null pin throws in the reference");
    assert!(m(json!(ps), json!({ "now": 1, "blast": null })).is_ok_and(|ok| !ok), "an earlier mismatch answers before the null pin is read");
    let mut odd = ps.clone();
    odd[6] = json!("x");
    assert_eq!(m(json!(odd), json!({ "r": null })), Ok(false), "a malformed signal answers before the null pin is read");
    assert_eq!(m(json!(ps), json!({ "now": { "min": [999], "max": ["0x3e9"] } })), Ok(true), "window bounds convert as BigInt converts them");
    assert_eq!(m(json!(ps), json!({ "now": [1000] })), Ok(false), "an array pin is a window without bounds");
    odd[6] = json!(7);
    assert_eq!(m(json!(odd), json!({ "r": 7 })), Ok(true), "a numeric signal is read through its text");
    odd[6] = json!(7.5);
    assert_eq!(m(json!(odd), json!({ "r": 7 })), Ok(false));
    assert!(policy_vm_context_matches(&Value::Null, None, &POLICYVM_PUBLIC_SIGNAL).is_err());
    assert_eq!(policy_vm_context_matches(&json!(5), None, &POLICYVM_PUBLIC_SIGNAL), Ok(false));
    // a null pin reaches the caller of the proof check too
    let c = case("verifyPolicyVmProof/bn/valid");
    let (engine, _) = engine_for(true);
    let opts = ZkProofOpts { expect: Some(PolicyVmExpectSource::Fixed(json!({ "now": null }))), engine: engine.clone(), ..proof_opts(&c["args"][1], None) };
    assert!(verify_policy_vm_proof(&c["args"][0], &opts).is_err());
    assert!(create_policy_vm_snark_backend(opts).verify(&c["args"][0], &NULL, &NULL).is_err());
    let no_key = ZkProofOpts { verification_key_path: Some("no-such-key.json".into()), engine, ..Default::default() };
    assert!(verify_policy_vm_proof(&c["args"][0], &no_key).is_err(), "a verifying key that cannot be read");

    // signal decoding indexes whatever it is given
    assert!(decode_policy_vm_public(&Value::Null).is_err());
    assert_eq!(decode_policy_vm_public(&json!(5)), Ok(json!({ "actionHash": {}, "policyHash": {}, "planHash": {} })));
    assert_eq!(decode_policy_vm_public(&json!("ab")), Ok(json!({ "actionHash": { "hi": "a", "lo": "b" }, "policyHash": {}, "planHash": {} })));
    assert_eq!(decode_policy_vm_public(&json!({ "6": "9" })), Ok(json!({ "actionHash": {}, "policyHash": {}, "planHash": {}, "r": "9" })));
}

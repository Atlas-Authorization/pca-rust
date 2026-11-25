//! Differential replay of the operational side of the action kit (lint and undo shape, business rules, selectors and the signed
//! confirmation, packs and their transparency-log entry, the hosted registry and sync, approval-render wrappers, the facade view
//! and provenance facts, the example runner, the confirmation-gated undo engine) against the TypeScript reference
//! (test-data/ref-actions-{lint,rules,sel-conf,hosted,pack,pack-log,render-facade,test-runner,undo-engine}.json.gz).
//! A reference throw only requires a refusal. Skipped (counted, must stay under 10% per corpus): cases with a lone surrogate (no Rust
//! string). Not replayed: the YAML reader / writer and the starter templates (no corpus carries them; the python-only YAML corpus is
//! not used), `confirmDef` / `prepareReview` / the review queue (their corpus belongs to the import program).
mod common;
use atlas_pca::actions::{core_registry, extend_registry};
use atlas_pca::actions_kit_ops::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;
use sha2::{Digest, Sha256};

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bytes_v(b: &[u8]) -> Value {
    json!({ "$bytes": b64u(b) })
}

fn seed_of(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn arr(v: &Value) -> Result<&Vec<Value>, String> {
    v.as_array().ok_or_else(|| "not an array".to_string())
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn opt(v: &Value) -> Option<&Value> {
    Some(v).filter(|x| !x.is_null())
}

fn s_or_null(o: Option<String>) -> Value {
    o.map_or(Value::Null, Value::String)
}

fn msg(e: atlas_pca::actions::ActionKitError) -> String {
    e.message
}

fn constant(b: bool) -> impl Fn(&Value) -> bool {
    move |_| b
}

// ---- lint ------------------------------------------------------------------------------------------------------------------

fn run_lint(f: &str, a: &[Value]) -> Result<Value, String> {
    use lint::*;
    use undo::*;
    Ok(match f {
        "lintRulesDigest" => json!(lint_rules_digest()),
        "LINT_RULES" => Value::Array(LINT_RULES.iter().map(|r| json!([r.0, r.1, r.2])).collect()),
        "lintDefs" => {
            let raw = arr(&a[0])?;
            match a[1].get("att").and_then(Value::as_bool) {
                Some(b) => {
                    let c = constant(b);
                    Value::Array(lint_defs(raw, &a[1], Some(&c)))
                }
                None => Value::Array(lint_defs(raw, &a[1], None)),
            }
        }
        "lintText" => json!(lint_text(arr(&a[0])?)),
        "toSarif" => to_sarif(arr(&a[0])?, a.get(1).and_then(opt)),
        "lintFails" => json!(lint_fails(arr(&a[0])?, a[1].as_bool().unwrap_or(false))),
        "mayBeReversible" => json!(may_be_reversible(&a[0])),
        "reversibilityFor" => json!(reversibility_for(&a[0], &a[1])),
        "compensationShape" => compensation_shape(&a[0], &a[1]),
        f => panic!("unknown fn {f}"),
    })
}

// ---- rules -----------------------------------------------------------------------------------------------------------------

fn run_rules(f: &str, a: &[Value]) -> Result<Value, String> {
    use rules::*;
    Ok(match f {
        "businessRulesError" => s_or_null(business_rules_error(&a[0], &a[1])),
        "compileBusinessRules" => compile_business_rules(&a[0], &a[1]).map_err(msg)?,
        "businessRulesDigest" => json!(business_rules_digest(a[0].as_str().ok_or("verb")?, &a[1])?),
        "moneyOf" => {
            let m = money_of(&a[0]).map_err(msg)?;
            let ccy = match m.ccy {
                Ccy::Literal(l) => json!({ "literal": l }),
                Ccy::Param(p) => json!({ "param": p }),
            };
            json!({ "amount": m.amount, "exp": m.exp, "ccy": ccy })
        }
        "minorUnits" => json!(minor_units(&a[0], a[1].as_i64().ok_or("exp")?, "x").map_err(msg)?),
        "evaluateBusinessRules" => evaluate_business_rules(&a[0], &a[1]),
        "runRuleExamples" => Value::Array(run_rule_examples(&a[0], &a[1]).map_err(msg)?),
        "explainBusinessRules" => json!(explain_business_rules(&a[0], &a[1]).map_err(msg)?),
        "lintBusinessRules" => Value::Array(lint_business_rules(&a[0], &a[1])),
        "diffBusinessRules" => diff_business_rules(&a[0], opt(&a[1]), opt(&a[2])).map_err(msg)?,
        "clockAt" => clock_at(&a[0], a[1].as_str().ok_or("tz")?).map_or(Value::Null, |(dow, min)| json!({ "dow": dow, "min": min })),
        "formatMoney" => json!(format_money(a[0].as_i64().ok_or("minor")?, a[1].as_str().ok_or("ccy")?, a[2].as_i64().ok_or("exp")?)),
        "rulesReviewMessage" => bytes_v(&rules_review_message(&a[0])?),
        "signRulesReview" => sign_rules_review(&a[0], &seed_of(&a[1]))?,
        "rulesReviewError" => s_or_null(rules_review_error(&a[0], &a[1], &a[2], opt(&a[3]))),
        f => panic!("unknown fn {f}"),
    })
}

// ---- selectors + confirmation ----------------------------------------------------------------------------------------------------

fn run_sel(f: &str, a: &[Value]) -> Result<Value, String> {
    use selector::*;
    let cl = |v: &Value| strs(v).into_iter().collect::<std::collections::BTreeSet<String>>();
    Ok(match f {
        "selectorMatches" => json!(selector_matches(&a[0], &cl(&a[1]))),
        "selectorMatchesFor" => json!(selector_matches_for(&a[0], a[1].as_str().ok_or("mode")?, &cl(&a[2]), a[3].as_bool().ok_or("confirmed")?)),
        "selectorHasNot" => json!(selector_has_not(&a[0])),
        "allowSelectorError" => s_or_null(allow_selector_error(&a[0], a[1].as_bool().ok_or("pinned")?)),
        "policyDecision" => json!(policy_decision(&a[0], a[1].as_str().ok_or("verb")?, &cl(&a[2]), a[3].as_bool().ok_or("confirmed")?)),
        "blankReason" => json!(blank_reason(a[0].as_str().ok_or("string")?)),
        "reviewMessage" => bytes_v(&review_message(&a[0])?),
        "signReview" => sign_review(&a[0], &seed_of(&a[1]))?,
        "verbConfirmationError" => {
            let reg = match opt(&a[1]) {
                None => core_registry(),
                Some(defs) => extend_registry(&core_registry(), arr(defs)?).map_err(msg)?,
            };
            s_or_null(verb_confirmation_error(&a[0], &reg, Some(&a[2])))
        }
        f => panic!("unknown fn {f}"),
    })
}

/// The reference words an exception inside the confirmation check with its own runtime's text.
fn norm_sel(v: &Value) -> Value {
    match v.as_str() {
        Some(s) if s.starts_with("malformed confirmation") => json!("malformed confirmation"),
        _ => v.clone(),
    }
}

// ---- hosted + sync -----------------------------------------------------------------------------------------------------------------

fn run_hosted(f: &str, a: &[Value]) -> Result<Value, String> {
    use hosted::*;
    Ok(match f {
        "syncSource" => {
            let lock = opt(&a[2]);
            let c = constant(a[3].as_bool().unwrap_or(false));
            sync::sync_source(arr(&a[0])?, arr(&a[1])?, &"S".repeat(43), &json!(1_800_000_000), lock, None, Some(&c))?
        }
        "syncText" => json!(sync::sync_text(&a[0])),
        "rulesDocError" => s_or_null(rules_doc_error(&a[0], "acme", arr(&a[1])?)),
        "hostedVersionDigest" => json!(hosted_version_digest(&a[0])?),
        "publishGate" => publish_gate_checked(&a[0])?,
        "viewLookup" => hosted_view(arr(&a[0])?, opt(&a[1])).lookup(a[2].as_str().ok_or("verb")?),
        "viewProvenance" => hosted_view(arr(&a[0])?, opt(&a[1])).provenance(&json!({ "verb": a[2] })).cloned().unwrap_or(Value::Null),
        "viewFloor" => json!(hosted_view(arr(&a[0])?, opt(&a[1])).floor(a[2].as_str().ok_or("verb")?, &a[3], &strs(&a[4]))),
        "viewUndo" => hosted_view(arr(&a[0])?, opt(&a[1])).undo_plan(&a[2]).unwrap_or(Value::Null),
        // an explicit null second argument is read as `params[k]`, but only once `k` (the lookup's idempotency_param) is defined: the
        // reference short-circuits on `k !== undefined` first, so an absent or nullish lookup never reaches the read
        "hostedCallContext" if a.get(1).is_some_and(Value::is_null) && a.first().and_then(|l| l.get("idempotency_param")).is_some() => {
            let k = a[0]["idempotency_param"].clone();
            let shown = k.as_str().map_or_else(|| k.to_string(), String::from);
            return Err(format!("Cannot read properties of null (reading '{shown}')"));
        }
        "hostedCallContext" => json!(hosted_call_context(opt(&a[0]), opt(&a[1]))),
        "rateKeysOf" => Value::Array(rate_keys_of(&a[0], &a[1])),
        "grantFactsOf" => grant_facts_of(&a[0]),
        f => panic!("unknown fn {f}"),
    })
}

// ---- packs + transparency log -------------------------------------------------------------------------------------------------------

fn run_pack(f: &str, a: &[Value]) -> Result<Value, String> {
    use pack::*;
    Ok(match f {
        "buildPack" => build_pack(&a[0], &seed_of(&a[1]), None, None, None).map_err(msg)?,
        "shardDefs" => Value::Array(shard_defs(arr(&a[0])?, opt(&a[1])).map_err(msg)?),
        "verifyUpgrade" => verify_upgrade(&a[0], &a[1], &a[2], opt(&a[3]), opt(&a[4]), None),
        "packStatementPayload" => pack_statement_payload(&a[0])?,
        f => panic!("unknown fn {f}"),
    })
}

fn derived_seed(label: &str) -> Vec<u8> {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).to_vec()
}

fn run_pack_log(f: &str, a: &[Value]) -> Result<Value, String> {
    use atlas_pca::scitt::{sign_statement, TransparencyService};
    Ok(match f {
        "appendPackToLog" => {
            let spec = &a[1];
            let ts_seed = spec["tsSeed"].as_str().ok_or("tsSeed")?;
            let mut svc = TransparencyService::new(json!({ "alg": "EdDSA", "key": { "seed": ts_seed }, "issuer": "ts" }));
            let other = b64u(&derived_seed("ref-actions-pack-log/other"));
            for i in 0..spec["preload"].as_i64().unwrap_or(0) {
                let st =
                    sign_statement(&json!({ "i": i }), &json!({ "alg": "EdDSA", "key": { "seed": other }, "issuer": "other", "subject": format!("s{i}") }))?;
                svc.register(&st)?;
            }
            let signer = json!({ "alg": "EdDSA", "key": { "seed": spec["regSeed"] }, "issuer": spec["issuer"] });
            let e = pack::append_pack_to_log(&a[0], &mut svc, &signer)?;
            json!({ "statement": bytes_v(&e.statement), "receipt": bytes_v(&e.receipt), "index": e.index, "root": e.root })
        }
        "verifyPackLogEntry" => {
            let keys = json!({ "registry": { "pub": a[2]["registry"] }, "log": { "pub": a[2]["log"] } });
            json!(pack::verify_pack_log_entry(&a[0], &seed_of(&a[1]["statement"]), &seed_of(&a[1]["receipt"]), &keys, a[3].as_str()))
        }
        f => panic!("unknown fn {f}"),
    })
}

// ---- render + facade + provenance ------------------------------------------------------------------------------------------------------

fn run_render(f: &str, a: &[Value]) -> Result<Value, String> {
    use render::*;
    let conf = |i: usize| constant(a[i].as_bool().unwrap_or(false));
    Ok(match f {
        "renderApproval" => render_approval_with(&a[0], &a[1], Some(&conf(2))).map_err(msg)?,
        "singleTapAllowed" => json!(single_tap_allowed(&a[0])),
        "renderDigestForAction" => json!(render_digest_for_action(&a[0], &a[1], &a[2], Some(&conf(3))).map_err(msg)?),
        "approverRenderCheck" => json!(approver_render_check(&a[0], &a[1], a[2].as_str().ok_or("digest")?, Some(&conf(3))).map_err(msg)?),
        "renderersFromDefs" => {
            let c = conf(3);
            renderers_from_defs(arr(&a[0])?, Some(&c)).render(a[1].as_str().ok_or("verb")?, "", opt(&a[2])).map_err(msg)?
        }
        "specOfDef" => spec_of_def(&a[0], None, Some(&conf(2)), a[1].as_bool().unwrap_or(false)).map_err(msg)?,
        "facadeSpecs" => Value::Array(facade_specs(arr(&a[0])?, None, Some(&conf(2)), a[1].as_bool().unwrap_or(false)).map_err(msg)?),
        "provenanceInfoOf" => provenance_info_of(&a[0], None, Some(&conf(1))),
        "provenanceActions" => {
            let c = conf(1);
            let pa = provenance_actions(arr(&a[0])?, None, Some(&c))?;
            Value::Array(strs(&a[2]).iter().map(|v| pa.apply(v).cloned().unwrap_or(Value::Null)).collect())
        }
        f => panic!("unknown fn {f}"),
    })
}

// ---- example runner --------------------------------------------------------------------------------------------------------------------

fn run_runner(f: &str, a: &[Value]) -> Result<Value, String> {
    use test_runner::*;
    let core = core_registry();
    Ok(match f {
        "decideExample" => decide_example(&a[0], &a[1], &core, arr(&a[2])?)?,
        "runDefTests" => run_def_tests(arr(&a[0])?, &core, a[1].as_i64())?,
        "testText" => json!(test_text(&a[0])),
        f => panic!("unknown fn {f}"),
    })
}

// ---- undo engine ---------------------------------------------------------------------------------------------------------------------

fn run_undo(f: &str, a: &[Value]) -> Result<Value, String> {
    let core = core_registry();
    Ok(match f {
        "undoPlan" => hosted::with_verifier(opt(&a[1]), &core, |v| undo::undo_engine(arr(&a[0]).map(|x| x.as_slice()).unwrap_or(&[]), &core, v).plan(&a[2]))
            .unwrap_or(Value::Null),
        "attested" => json!(review::attestation_verifier(&core, &a[1])(&a[0])),
        f => panic!("unknown fn {f}"),
    })
}

// ---- harness ---------------------------------------------------------------------------------------------------------------------------

fn same(want: &Value, got: &Value) -> bool {
    atlas_pca::canonicalize(want) == atlas_pca::canonicalize(got)
}

fn replay(pkg: &str, run: fn(&str, &[Value]) -> Result<Value, String>, norm: fn(&Value) -> Value) {
    let cases = common::ref_cases_seeded(pkg);
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let args = c["args"].as_array().unwrap().clone();
        let got = std::panic::catch_unwind(|| run(f, &args)).unwrap_or_else(|_| Err("panic".into()));
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => same(&norm(&c["out"]), &norm(v)),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], c["out"], got));
        }
    }
    assert!(skipped * 10 < cases.len(), "{pkg}: {skipped} cases skipped");
    assert!(bad.is_empty(), "{pkg}: {} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
}

fn id(v: &Value) -> Value {
    v.clone()
}

#[test]
fn actions_lint_vectors() {
    replay("actions-lint", run_lint, id);
}

#[test]
fn actions_rules_vectors() {
    replay("actions-rules", run_rules, id);
}

#[test]
fn actions_sel_conf_vectors() {
    replay("actions-sel-conf", run_sel, norm_sel);
}

#[test]
fn actions_hosted_vectors() {
    replay("actions-hosted", run_hosted, id);
}

#[test]
fn actions_pack_vectors() {
    replay("actions-pack", run_pack, id);
}

#[test]
fn actions_pack_log_vectors() {
    replay("actions-pack-log", run_pack_log, id);
}

#[test]
fn actions_render_facade_vectors() {
    replay("actions-render-facade", run_render, id);
}

#[test]
fn actions_test_runner_vectors() {
    replay("actions-test-runner", run_runner, id);
}

#[test]
fn actions_undo_engine_vectors() {
    replay("actions-undo-engine", run_undo, id);
}

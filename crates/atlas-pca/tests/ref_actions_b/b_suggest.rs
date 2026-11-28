//! Replay of the suggestion engine corpus (test-data/ref-actions-import-suggest.json.gz): rule validation, digest, signature, matching,
//! application, the model assist and the provider adapters. Argument conventions: a rules argument "default" is the shipped rule set, a
//! registry argument "core" is the core registry, a signing seed is the label whose Ed25519 seed is sha256("atlas-pca-conformance/" + label).
//! Skips (counted, under 10%): cases with a lone surrogate (handled by `replay`) and calls whose arguments have the wrong JSON type for the
//! Rust signature (a non-string stem input, an adapter spec without a string id). Shortcuts: `vocabulary` / `promptDigest` / `buildRequest`
//! always use the core registry (the corpus only passes core or null); the test adapter returns its `answer` member as a JSON value.
use super::common::ref_cases;
use super::{cases_of, replay};
use atlas_pca::actions::{core_registry, Registry};
use atlas_pca::actions_kit_import::common::ActionKitError;
use atlas_pca::actions_kit_import::model::*;
use atlas_pca::actions_kit_import::suggest::*;
use atlas_pca::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::HashSet;
use std::sync::OnceLock;

type Out = Option<Result<Value, ActionKitError>>;

fn all() -> &'static Vec<Value> {
    static C: OnceLock<Vec<Value>> = OnceLock::new();
    C.get_or_init(|| ref_cases("actions-import-suggest"))
}

fn core() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(core_registry)
}

fn arg(a: &[Value], i: usize) -> Value {
    a.get(i).cloned().unwrap_or(Value::Null)
}

fn rules_of(v: &Value) -> Value {
    if v.as_str() == Some("default") {
        default_rules()
    } else {
        v.clone()
    }
}

fn reg_of(v: &Value) -> Option<&'static Registry> {
    if v.as_str() == Some("core") {
        Some(core())
    } else {
        None
    }
}

fn seed_of(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(format!("atlas-pca-conformance/{label}").as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

fn check(f: &str, call: impl Fn(&[Value]) -> Out) {
    let cs = cases_of(all(), f);
    assert!(!cs.is_empty(), "no corpus cases for {f}");
    let (ran, skipped) = replay(f, &cs, call);
    assert!(ran > 0, "{f}: every case was skipped");
    assert!(skipped * 10 <= cs.len().max(10), "{f}: {skipped} of {} cases skipped", cs.len());
}

struct TestAdapter {
    id: String,
    version: Option<String>,
    answer: Value,
    throws: Option<String>,
}

impl ModelAdapter for TestAdapter {
    fn id(&self) -> String {
        self.id.clone()
    }
    fn version(&self) -> Option<String> {
        self.version.clone()
    }
    fn complete(&self, _req: &Value) -> Result<Value, String> {
        match &self.throws {
            Some(m) => Err(m.clone()),
            None => Ok(self.answer.clone()),
        }
    }
}

const COVERED: [&str; 19] = [
    "stem",
    "factsOf",
    "DEFAULT_RULES",
    "DEFAULT_RULES_SEALED_DIGEST",
    "suggestRulesError",
    "rulesDigest",
    "sealRules",
    "signRules",
    "verifyRules",
    "suggestWithRules",
    "applySuggestion",
    "unionSuggestions",
    "vocabulary",
    "promptDigest",
    "buildRequest",
    "parseTraitList",
    "suggestWithModels",
    "modelConfigFromEnv",
    "providerAdapterComplete",
];

#[test]
fn every_function_is_covered() {
    let mut fns: Vec<String> = all().iter().filter_map(|c| c["fn"].as_str().map(String::from)).collect::<HashSet<_>>().into_iter().collect();
    fns.sort();
    let mut want: Vec<String> = COVERED.iter().map(|x| x.to_string()).collect();
    want.sort();
    assert_eq!(fns, want);
}

#[test]
fn stem_matches() {
    check("stem", |a| a[0].as_str().map(|t| Ok(json!(stem(t)))));
}

#[test]
fn facts_of_matches() {
    check("factsOf", |a| Some(facts_of(&a[0]).map(|f| f.to_json())));
}

#[test]
fn default_rules_match() {
    check("DEFAULT_RULES", |_| Some(Ok(default_rules())));
    check("DEFAULT_RULES_SEALED_DIGEST", |_| Some(Ok(default_rules_sealed()["digest"].clone())));
}

#[test]
fn suggest_rules_error_matches() {
    check("suggestRulesError", |a| {
        let known: Option<HashSet<String>> = a.get(1).and_then(Value::as_array).map(|k| k.iter().filter_map(|x| x.as_str().map(String::from)).collect());
        Some(Ok(suggest_rules_error(&rules_of(&a[0]), known.as_ref()).map_or(Value::Null, Value::String)))
    });
}

#[test]
fn rules_digest_and_seal_match() {
    check("rulesDigest", |a| Some(rules_digest(&rules_of(&a[0])).map(Value::String)));
    check("sealRules", |a| Some(seal_rules(&a[0])));
}

#[test]
fn sign_and_verify_rules_match() {
    check("signRules", |a| {
        let (kid, label) = (a.get(1)?.as_str()?, a.get(2)?.as_str()?);
        Some(sign_rules(&a[0], kid, &seed_of(label)))
    });
    check("verifyRules", |a| Some(Ok(verify_rules(&a[0], &arg(a, 1)))));
}

#[test]
fn suggest_with_rules_matches() {
    check("suggestWithRules", |a| {
        let reg = reg_of(&arg(a, 2));
        Some(suggest_with_rules(&a[0], &rules_of(&a[1]), reg))
    });
}

#[test]
fn apply_and_union_match() {
    check("applySuggestion", |a| Some(apply_suggestion(&a[0], &a[1], &arg(a, 2))));
    check("unionSuggestions", |a| Some(Ok(union_suggestions(&a[0], &a[1]))));
}

#[test]
fn model_prompt_matches() {
    check("vocabulary", |_| Some(Ok(vocabulary(core()))));
    check("promptDigest", |_| Some(Ok(Value::String(prompt_digest(core())))));
    check("buildRequest", |a| Some(build_request(&a[0], core())));
    check("parseTraitList", |a| a[0].as_str().map(|t| Ok(json!(parse_trait_list(t, core())))));
}

#[test]
fn suggest_with_models_matches() {
    check("suggestWithModels", |a| {
        let mut ads: Vec<TestAdapter> = vec![];
        for spec in a.get(1)?.as_array()? {
            ads.push(TestAdapter {
                id: spec.get("id")?.as_str()?.to_string(),
                version: spec.get("version").and_then(Value::as_str).map(String::from),
                answer: spec.get("answer").cloned().unwrap_or(Value::Null),
                throws: spec.get("throws").and_then(Value::as_str).map(String::from),
            });
        }
        let refs: Vec<&dyn ModelAdapter> = ads.iter().map(|x| x as &dyn ModelAdapter).collect();
        Some(suggest_with_models(&a[0], &refs, core()))
    });
}

#[test]
fn model_config_from_env_matches() {
    check("modelConfigFromEnv", |a| Some(model_config_from_env(&a[0], &arg(a, 1)).map(|c| c.to_map())));
}

#[test]
fn provider_adapter_matches() {
    check("providerAdapterComplete", |a| {
        let cfg = a.first()?;
        let (provider, model, key) = (cfg.get("provider")?.as_str()?, cfg.get("model")?.as_str()?, cfg.get("apiKey")?.as_str()?);
        let spec = a.get(1)?;
        let req = a.get(2)?;
        let calls: RefCell<Vec<Value>> = RefCell::new(vec![]);
        let fetch = |url: &str, init: &Value| -> Result<FetchResponse, String> {
            calls.borrow_mut().push(json!({"url": url, "headers": init["headers"].clone(), "body": init["body"].clone()}));
            if let Some(m) = spec.get("throws").and_then(Value::as_str) {
                return Err(m.to_string());
            }
            let badjson = spec.get("badjson").and_then(Value::as_bool).unwrap_or(false);
            Ok(FetchResponse {
                ok: spec.get("ok").and_then(Value::as_bool).unwrap_or(true),
                status: spec.get("status").and_then(Value::as_i64).unwrap_or(200),
                json: if badjson { Err("bad json".to_string()) } else { Ok(spec.get("json").cloned().unwrap_or(Value::Null)) },
            })
        };
        let adapter = provider_adapter(ModelEnvConfig::new(provider, model, key), &fetch);
        let mut out = Map::new();
        match adapter.complete(req) {
            // the reference reads `call` before the answer is awaited, so a success carries no call
            Ok(t) => {
                out.insert("call".into(), Value::Null);
                out.insert("text".into(), t);
            }
            Err(e) => {
                out.insert("call".into(), calls.borrow().first().cloned().unwrap_or(Value::Null));
                out.insert("error".into(), Value::String(e));
            }
        }
        Some(Ok(Value::Object(out)))
    });
}

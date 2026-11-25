//! Replay of the review flow, the import pipeline, the importer registry and the suggestion evaluation
//! (test-data/ref-actions-import-review.json.gz): parseHandTsv, parseCorpusJsonl, realSplit, importCorpus, evalSuggest, renderEvalMarkdown,
//! floorFailures, importActions, IMPORTERS, importAndSuggest, suggestDefs, defsToJsonl, jsonlToDefs, confirmDef, verifyAttestation,
//! reviewStatus, revertStale, reviewPriority, prepareReview, reviewQueueOrder.
//!
//! Conventions: registry "core" is `core_registry()`, rules "default" is the shipped rules (for suggestDefs the corpus uses the first 20
//! of them), a seed is a label whose Ed25519 seed is sha256("atlas-pca-conformance/" + label), models are `{id, version?, answer?, throws?}`.
//! Skips: only a case the replay itself skips (a lone surrogate, which a Rust string cannot hold) or an argument that cannot be typed
//! (a non-"core" registry, a non-array defs list). Not ported by design: `defsToYaml` (needs a YAML emitter) and everything file-system based.
//! The cases build their defs with the importers and the suggestion engine, so this also exercises those modules.

use crate::common::ref_cases;
use crate::{cases_of, replay};
use atlas_pca::actions::{core_registry, Registry};
use atlas_pca::actions_kit_import::common::ActionKitError;
use atlas_pca::actions_kit_import::model::ModelAdapter;
use atlas_pca::actions_kit_import::pipeline::SuggestOpts;
use atlas_pca::actions_kit_import::suggest::default_rules;
use atlas_pca::actions_kit_import::{eval, pipeline, review};
use atlas_pca::serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

type Out = Option<Result<Value, ActionKitError>>;

const FNS: [&str; 20] = [
    "parseHandTsv",
    "parseCorpusJsonl",
    "realSplit",
    "importCorpus",
    "evalSuggest",
    "renderEvalMarkdown",
    "floorFailures",
    "importActions",
    "IMPORTERS",
    "importAndSuggest",
    "suggestDefs",
    "defsToJsonl",
    "jsonlToDefs",
    "confirmDef",
    "verifyAttestation",
    "reviewStatus",
    "revertStale",
    "reviewPriority",
    "prepareReview",
    "reviewQueueOrder",
];

static NULL: Value = Value::Null;

fn corpus() -> &'static Vec<Value> {
    static C: OnceLock<Vec<Value>> = OnceLock::new();
    C.get_or_init(|| ref_cases("actions-import-review"))
}

fn run(fname: &str, f: impl Fn(&[Value]) -> Out) {
    let cs = cases_of(corpus(), fname);
    assert!(!cs.is_empty(), "{fname}: no cases in the corpus");
    let (ran, skipped) = replay(fname, &cs, f);
    eprintln!("{fname}: ran {ran}, skipped {skipped}");
    assert!(ran > 0, "{fname}: every case was skipped");
}

fn arg(a: &[Value], i: usize) -> &Value {
    a.get(i).unwrap_or(&NULL)
}

fn arr(v: Result<Vec<Value>, ActionKitError>) -> Result<Value, ActionKitError> {
    v.map(Value::Array)
}

fn core_of(v: &Value) -> Option<Registry> {
    // the reference falls back to the core registry when none is given
    (v.is_null() || v.as_str() == Some("core")).then(core_registry)
}

fn seed_of(label: &str) -> Vec<u8> {
    Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).to_vec()
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

fn adapters_of(models: &Value) -> Vec<TestAdapter> {
    models
        .as_array()
        .into_iter()
        .flatten()
        .map(|m| TestAdapter {
            id: m["id"].as_str().unwrap_or("").to_string(),
            version: m.get("version").and_then(Value::as_str).map(String::from),
            answer: m.get("answer").cloned().unwrap_or(Value::Null),
            throws: m.get("throws").and_then(Value::as_str).map(String::from),
        })
        .collect()
}

/// Build the suggestion options of a corpus case (`{mode?, rules?, models?}`) and hand them to `f`.
fn with_suggest<T>(so: &Value, f: impl FnOnce(&SuggestOpts) -> T) -> T {
    let adapters = adapters_of(so.get("models").unwrap_or(&NULL));
    let refs: Vec<&dyn ModelAdapter> = adapters.iter().map(|a| a as &dyn ModelAdapter).collect();
    let rules = match so.get("rules") {
        Some(Value::String(t)) if t == "default" => {
            let mut r = default_rules();
            if let Some(a) = r.get_mut("rules").and_then(Value::as_array_mut) {
                a.truncate(20);
            }
            Some(r)
        }
        Some(v) if !v.is_null() => Some(v.clone()),
        _ => None,
    };
    let opts = SuggestOpts { mode: so.get("mode").and_then(Value::as_str), rules: rules.as_ref(), registry: None, models: &refs };
    f(&opts)
}

#[test]
fn parse_hand_tsv() {
    run("parseHandTsv", |a| Some(arr(eval::parse_hand_tsv(arg(a, 0).as_str()?))));
}

#[test]
fn parse_corpus_jsonl() {
    run("parseCorpusJsonl", |a| Some(arr(eval::parse_corpus_jsonl(arg(a, 0).as_str()?))));
}

#[test]
fn real_split() {
    run("realSplit", |a| match arg(a, 0) {
        Value::Null => Some(Ok(json!(eval::real_split(None)))),
        Value::String(t) => Some(Ok(json!(eval::real_split(Some(t))))),
        _ => None,
    });
}

#[test]
fn import_corpus() {
    run("importCorpus", |a| Some(eval::import_corpus(arg(a, 0).as_array()?)));
}

#[test]
fn eval_suggest() {
    run("evalSuggest", |a| {
        let rules = match arg(a, 1) {
            Value::Null => None,
            Value::String(t) if t == "default" => None,
            v => Some(v),
        };
        let alpha = match arg(a, 2) {
            Value::Null => None,
            v => Some(v.as_f64()?),
        };
        Some(eval::eval_suggest(arg(a, 0).as_array()?, rules, None, alpha))
    });
}

#[test]
fn render_eval_markdown() {
    run("renderEvalMarkdown", |a| Some(eval::render_eval_markdown(arg(a, 0)).map(Value::String)));
}

#[test]
fn floor_failures() {
    run("floorFailures", |a| Some(eval::floor_failures(arg(a, 0), arg(a, 1)).map(|v| Value::Array(v.into_iter().map(Value::String).collect()))));
}

#[test]
fn import_actions() {
    run("importActions", |a| Some(pipeline::import_actions(arg(a, 0), arg(a, 1), arg(a, 2))));
}

#[test]
fn importers() {
    run("IMPORTERS", |a| Some(pipeline::run_importer(arg(a, 0).as_str()?, arg(a, 1), arg(a, 2))));
}

#[test]
fn import_and_suggest() {
    run("importAndSuggest", |a| Some(with_suggest(arg(a, 3), |o| pipeline::import_and_suggest(arg(a, 0), arg(a, 1), arg(a, 2), o))));
}

#[test]
fn suggest_defs() {
    run("suggestDefs", |a| {
        let defs = arg(a, 0).as_array()?;
        let none = Value::Object(Map::new());
        let so = a.get(1).filter(|v| v.is_object()).unwrap_or(&none);
        Some(with_suggest(so, |o| pipeline::suggest_defs(defs, o)))
    });
}

#[test]
fn defs_to_jsonl() {
    run("defsToJsonl", |a| Some(pipeline::defs_to_jsonl(arg(a, 0).as_array()?).map(Value::String)));
}

#[test]
fn jsonl_to_defs() {
    run("jsonlToDefs", |a| Some(arr(pipeline::jsonl_to_defs(arg(a, 0).as_str()?))));
}

#[test]
fn confirm_def() {
    run("confirmDef", |a| {
        let (d, c) = (arg(a, 0), arg(a, 1));
        let reg = core_registry();
        let mut o = Map::new();
        o.insert("finalTraits".into(), c["finalTraits"].clone());
        o.insert("ts".into(), c["ts"].clone());
        o.insert("reviewer".into(), json!({"kid": c["kid"].clone()}));
        for k in ["pins", "dismissed"] {
            if let Some(v) = c.get(k).filter(|v| !v.is_null()) {
                o.insert(k.into(), v.clone());
            }
        }
        let secret = seed_of(c["seed"].as_str()?);
        Some(review::confirm_def(d, &reg, &Value::Object(o), &secret))
    });
}

#[test]
fn verify_attestation() {
    run("verifyAttestation", |a| {
        let reg = core_of(arg(a, 2))?;
        Some(Ok(review::verify_attestation(arg(a, 0), &reg, arg(a, 1))))
    });
}

#[test]
fn review_status() {
    run("reviewStatus", |a| {
        let reg = core_of(arg(a, 2))?;
        Some(review::review_status(arg(a, 0), &reg, arg(a, 1)).map(Value::String))
    });
}

#[test]
fn revert_stale() {
    run("revertStale", |a| {
        let reg = core_of(arg(a, 2))?;
        Some(review::revert_stale(arg(a, 0), &reg, arg(a, 1)))
    });
}

#[test]
fn review_priority() {
    run("reviewPriority", |a| {
        let reg = core_registry();
        Some(review::review_priority(arg(a, 0), &reg).map(Value::from))
    });
}

#[test]
fn prepare_review() {
    run("prepareReview", |a| {
        let reg = core_registry();
        Some(review::prepare_review(arg(a, 0), &reg, a.get(1).filter(|v| !v.is_null())))
    });
}

#[test]
fn review_queue_order() {
    run("reviewQueueOrder", |a| {
        let reg = core_registry();
        Some(review::review_queue_order(arg(a, 0).as_array()?, &reg).map(Value::Array))
    });
}

#[test]
fn every_function_is_covered() {
    let mut names: Vec<String> = corpus().iter().filter_map(|c| c["fn"].as_str().map(String::from)).collect();
    names.sort();
    names.dedup();
    for n in &names {
        assert!(FNS.contains(&n.as_str()), "corpus function {n} has no replay test");
    }
    for f in FNS {
        assert!(names.iter().any(|n| n == f), "replay test {f} has no corpus cases");
    }
}

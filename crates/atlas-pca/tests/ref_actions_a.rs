//! Differential replay of the action-definition kit, authoring and derivation side (shorthands and the loader, build outputs and
//! pack signing, compat shims, the data tables, derivations, id patterns / effective profiles / semantic diffs, evolution records)
//! against the TypeScript reference (test-data/ref-actions-{author,build,compat,data,derive,diff,evolve}.json.gz). A reference
//! throw only requires a refusal.
//! Skipped (counted, must stay under 10%): the starter-template functions of the data corpus (starterTemplates, starterTemplate,
//! templateYaml, templateTraits: they belong to the templates port), and cases carrying a lone surrogate.
//! The loader's `rules` check is the rules port's `business_rules_error` (loadActionsValue cases with rules blocks).
mod common;
use atlas_pca::actions::{core_registry, extend_registry, hint_traits, Profile, Registry};
use atlas_pca::actions_kit::author::*;
use atlas_pca::actions_kit::build::*;
use atlas_pca::actions_kit::compat::*;
use atlas_pca::actions_kit::data::*;
use atlas_pca::actions_kit::derive::*;
use atlas_pca::actions_kit::diff::*;
use atlas_pca::actions_kit::evolve::*;
use atlas_pca::actions_kit::{
    all_prule_ids, eff_with_trait, effective_with, id_matches, id_pattern_contains, profile_eq, prules_violations, required_prules_violated, Verifier,
};
use atlas_pca::serde_json::{json, Value};
use std::sync::LazyLock;

static CORE: LazyLock<Registry> = LazyLock::new(core_registry);

fn rules_check(d: &Value, r: &Value) -> Option<String> {
    atlas_pca::actions_kit_ops::rules::business_rules_error(d, r)
}

fn arr(v: &Value) -> &[Value] {
    v.as_array().expect("a list").as_slice()
}

fn s(v: &Value) -> &str {
    v.as_str().expect("a string")
}

fn seed(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().expect("$bytes"))
}

fn opt_str(v: &Value) -> Option<&str> {
    v.as_str()
}

fn nn(v: Option<&Value>) -> Option<&Value> {
    v.filter(|x| !x.is_null())
}

fn profile(v: &Value) -> Result<Profile, String> {
    Profile::from_value(v).ok_or_else(|| "bad profile".to_string())
}

fn some_or_null(o: Option<String>) -> Value {
    o.map_or(Value::Null, Value::String)
}

fn yes(_: &Value) -> bool {
    true
}

fn no(_: &Value) -> bool {
    false
}

/// The caller's confirmation verifier: every def is (or is not) confirmed.
fn verifier(c: bool) -> Verifier<'static> {
    if c {
        Some(&yes)
    } else {
        Some(&no)
    }
}

/// `None`: the case is skipped.
fn run(corpus: &str, f: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let reg: &Registry = &CORE;
    let ver = |i: usize| -> Verifier<'static> { verifier(a[i].as_bool().expect("confirmed flag")) };
    let r: Result<Value, String> = match (corpus, f) {
        // ---- author
        ("author", "parseParamShorthand") => parse_param_shorthand(s(&a[0])),
        ("author", "parseResourceShorthand") => parse_resource_shorthand(s(&a[0])),
        ("author", "defaultTitle") => Ok(json!(default_title(s(&a[0])))),
        ("author", "expandAction") => expand_action(&a[0], opt_str(&a[1])),
        ("author", "loadActionsValue") => Ok(load_actions_value_with(&a[0], &rules_check)),
        ("author", "builder") => builder(s(&a[0]), &a[1..]),
        ("author", "action") => action(s(&a[0]), &a[1]),
        // ---- build
        ("build", "buildArtifacts") => build_artifacts(arr(&a[0]), &a[1], reg, None),
        ("build", "generateTypes") => Ok(json!(generate_types(arr(&a[0])))),
        ("build", "toolAction") => Ok(tool_action(arr(&a[0]), s(&a[1]), &a[2])),
        ("build", "packConsistencyError") => Ok(some_or_null(pack_consistency_error(&a[0], reg))),
        ("build", "signPack") => sign_pack(&a[0], s(&a[1]), &seed(&a[2]), reg),
        ("build", "packKeyOf") => pack_key_of(s(&a[0]), &seed(&a[1])),
        ("build", "verifyPack") => Ok(verify_signed_pack(&a[0], &a[1], reg)),
        // ---- compat
        ("compat", "normalizeReversibility") => Ok(json!(normalize_reversibility(&a[0]))),
        ("compat", "legacyOperationsClass") => Ok(json!(legacy_operations_class(s(&a[0])))),
        ("compat", "maxRevOf") => Ok(json!(max_rev_of(s(&a[0]), s(&a[1])))),
        ("compat", "unitTagOf") => Ok(unit_tag_of(&a[0])),
        ("compat", "blastOfFloat") => Ok(blast_of_float(&a[0])),
        ("compat", "blastExactOfFloat") => Ok(blast_exact_of_float(&a[0])),
        ("compat", "fromCatalogSpec") => from_catalog_spec(&a[0], nn(a.get(1))),
        ("compat", "fromCatalog") => from_catalog(&a[0], nn(a.get(1))),
        // ---- data
        ("data", "builtinDefs") => Ok(Value::Array(builtin_defs())),
        ("data", "domainDefs") => Ok(Value::Array(domain_defs())),
        ("data", "corePackDefs") => Ok(Value::Array(core_pack_defs())),
        ("data", "legacyCatalog") => Ok(legacy_catalog()),
        ("data", "legacyOntologyEffect") => Ok(legacy_ontology_effect()),
        ("data", "resolutions") => Ok(resolutions()),
        ("data", "domainBindings") => Ok(domain_verb_bindings()),
        ("data", "coreDigests") => core_digests(),
        ("data", "domainVerbs") => domain_verbs(s(&a[0]), None),
        ("data", "domainRoles") => domain_roles(s(&a[0])),
        ("data", "releasedBuiltinDefs") => Ok(json!(released_builtin_defs() == builtin_defs())),
        ("data", "builtinConfirmed") => Ok(json!(builtin_confirmed())),
        ("data", "starterTemplates" | "starterTemplate" | "templateYaml" | "templateTraits") => return None,
        // ---- derive
        ("derive", "flattenParams") => Ok(flatten_params(&a[0])),
        ("derive", "paramByRole") => param_by_role(&a[0], s(&a[1])).map(Value::String),
        ("derive", "effectClass") => Ok(json!(effect_class(&a[0]))),
        ("derive", "toSchemaVerb") => to_schema_verb(&a[0], reg, ver(1)),
        ("derive", "toSchemaDoc") => {
            let custom;
            let r: &Registry = match nn(a.get(3)) {
                None => reg,
                Some(rd) => {
                    custom = extend_registry(reg, arr(rd)).map_err(|e| e.message);
                    match &custom {
                        Ok(x) => x,
                        Err(e) => return Some(Err(e.clone())),
                    }
                }
            };
            to_schema_doc(arr(&a[0]), r, &a[1], ver(2))
        }
        ("derive", "operationOf") => Ok(operation_of(&a[0], &a[1])),
        ("derive", "riskOf") => {
            let eff = match effective_with(&a[0], reg, ver(1)) {
                Ok(e) => e,
                Err(e) => return Some(Err(e)),
            };
            Ok(risk_of(&a[0], &eff, nn(a.get(2)), a.get(3)))
        }
        ("derive", "resourceMatcher") => Ok(json!(resource_matcher(&a[0]))),
        ("derive", "predicatesOf") => predicates_of(&a[0], nn(a.get(1))),
        ("derive", "toOntology") => to_ontology(arr(&a[0]), reg, ver(1)),
        ("derive", "cardOf") => effective_with(&a[0], reg, ver(1)).and_then(|e| card_of(&a[0], &e, reg)),
        ("derive", "escalationOf") => effective_with(&a[0], reg, ver(1)).map(|e| escalation_of(&e)),
        ("derive", "mcpAnnotationsOf") => effective_with(&a[0], reg, ver(1)).map(|e| mcp_annotations_of(&a[0], &e)),
        ("derive", "explainDef") => explain_def(&a[0], reg, ver(1)).map(Value::String),
        ("derive", "REVERSIBILITY_SCORE") => Ok(reversibility_score_table()),
        // ---- diff
        ("diff", "idMatches") => Ok(json!(id_matches(&a[0], &a[1]))),
        ("diff", "idPatternContains") => Ok(json!(id_pattern_contains(&a[0], &a[1]))),
        ("diff", "join") => profile(&a[0]).and_then(|p| profile(&a[1]).map(|q| atlas_pca::actions::join(&p, &q).to_value())),
        ("diff", "leq") => profile(&a[0]).and_then(|p| profile(&a[1]).map(|q| json!(atlas_pca::actions::leq(&p, &q)))),
        ("diff", "profileEq") => profile(&a[0]).and_then(|p| profile(&a[1]).map(|q| json!(profile_eq(&p, &q)))),
        ("diff", "effective") => effective_with(&a[0], reg, ver(1)).map(|e| e.to_value()),
        ("diff", "hintTraits") => Ok(json!(hint_traits(&a[0]))),
        ("diff", "prulesViolations") => Ok(json!(prules_violations(&a[0], &all_prule_ids()))),
        ("diff", "effWithTrait") => eff_with_trait(&a[0], s(&a[1]), reg).map(|p| p.to_value()),
        ("diff", "requiredPrulesViolated") => profile(&a[1]).map(|p| json!(required_prules_violated(&a[0], &p))),
        ("diff", "diffDefs") => {
            let v: Verifier = None;
            if a.len() > 2 {
                diff_defs(&a[0], &a[1], reg, ver(2))
            } else {
                diff_defs(&a[0], &a[1], reg, v)
            }
        }
        ("diff", "diffDefsAuthoring") => diff_defs_authoring(&a[0], &a[1], reg),
        ("diff", "diffIsFree") => Ok(json!(diff_is_free(s(&a[0])))),
        ("diff", "diffPacks") => diff_packs(arr(&a[0]), arr(&a[1]), reg).map(Value::Array),
        // ---- evolve
        ("evolve", "evolutionRecords") => evolution_records(s(&a[0]), arr(&a[1]), arr(&a[2]), reg, ver(3)).map(Value::Array),
        ("evolve", "signEvolution") => sign_evolution(arr(&a[0]), s(&a[1]), &seed(&a[2])).map(Value::Array),
        ("evolve", "evolutionError") => Ok(some_or_null(evolution_error(s(&a[0]), arr(&a[1]), arr(&a[2]), &a[3], &a[4], reg, ver(5)))),
        (c, f) => panic!("unknown fn {c}/{f}"),
    };
    Some(r)
}

fn replay(corpus: &str) -> (usize, usize) {
    let cases = common::ref_cases_seeded(&format!("actions-{corpus}"));
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        let f = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap();
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let got = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(corpus, f, args))) {
            Ok(None) => {
                skipped += 1;
                continue;
            }
            Ok(Some(r)) => r,
            Err(_) => Err("panic".into()),
        };
        let ok = match (c["out"].get("$throws"), &got) {
            (Some(_), Err(_)) => true,
            (None, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            let want: String = c["out"].to_string().chars().take(400).collect();
            bad.push(format!("{}\n  want {}\n  got  {:?}", c["name"], want, got.map(|v| v.to_string().chars().take(400).collect::<String>())));
        }
    }
    assert!(bad.is_empty(), "{corpus}: {} of {} cases differ:\n{}", bad.len(), cases.len(), bad.iter().take(25).cloned().collect::<Vec<_>>().join("\n"));
    (cases.len(), skipped)
}

#[test]
fn action_kit_authoring_vectors() {
    let (mut total, mut skipped) = (0, 0);
    for corpus in ["author", "build", "compat", "data", "derive", "diff", "evolve"] {
        let (n, k) = replay(corpus);
        total += n;
        skipped += k;
    }
    assert!(skipped * 10 < total, "{skipped} of {total} cases skipped");
}

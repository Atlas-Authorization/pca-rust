//! Differential replay of test-data/ref-action-schema.json.gz and ref-action-schema-draft.json.gz (written by the TypeScript reference):
//! the vocabulary constants, value-dependent reversibility, the wallet floor test, schema lookup, signing (ed25519 / ML-DSA / hybrid, byte
//! exact), the discovery key entry, digest and verification, and the drafting importers for MCP tool lists and OpenAPI documents (todo lists
//! compared exactly, in order). Every function of each corpus has a handler and the per-function totals are asserted. A reference refusal
//! must be a refusal here; after the prefixes `schema verification error:` and `malformed schema:` the reference's own text is not compared.
mod common;
use std::collections::BTreeMap;

use atlas_pca::action_schema_draft::*;
use atlas_pca::agent::{KeyPair, PqKeyPair, Suite};
use atlas_pca::serde_json::{json, Value};
use common::replay::thrown;

fn regex(source: &str) -> Value {
    json!({ "$regex": source })
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "ACTION_SCHEMA_DOMAIN": ACTION_SCHEMA_DOMAIN,
            "ACTION_SCHEMA_KIND": ACTION_SCHEMA_KIND,
            "ACTION_SCHEMA_REF_DOMAIN": ACTION_SCHEMA_REF_DOMAIN,
            "DEFAULT_MAX_ITEMS": DEFAULT_MAX_ITEMS,
            "DEFAULT_MAX_LEN": DEFAULT_MAX_LEN,
            "MAX_SCHEMA_PARAMS": MAX_SCHEMA_PARAMS,
            "MAX_SCHEMA_VALUES": MAX_SCHEMA_VALUES,
            "MAX_SCHEMA_VERBS": MAX_SCHEMA_VERBS,
            "PARAM_PATH_RE": regex(PARAM_PATH_RE),
            "PARAM_PATH_RE_V2": regex(PARAM_PATH_RE_V2),
            "PARAM_TYPES": PARAM_TYPES,
            "PARAM_TYPES_V2": PARAM_TYPES_V2,
            "SCHEMA_REVERSIBILITY": SCHEMA_REVERSIBILITY,
            "SCHEMA_V2_CAVEATS": SCHEMA_V2_CAVEATS,
            "SCHEMA_V2_CONTEXT": SCHEMA_V2_CONTEXT,
            "SCHEMA_V2_EFFECTS": SCHEMA_V2_EFFECTS,
            "SCHEMA_V2_PROVENANCE": SCHEMA_V2_PROVENANCE,
            "SCHEMA_V2_PRULES": SCHEMA_V2_PRULES,
            "SCHEMA_V2_TAGS": SCHEMA_V2_TAGS,
            "SENSITIVITIES": SENSITIVITIES,
            "UNIT_ID_RE": regex(UNIT_ID_RE),
            "WALLET_FLOOR_EXACT": WALLET_FLOOR_EXACT,
            "WALLET_FLOOR_PREFIXES": WALLET_FLOOR_PREFIXES,
            "WELL_KNOWN_PCA_ACTIONS_PATH": WELL_KNOWN_PCA_ACTIONS_PATH,
        }),
        "reversibilityOf" => reversibility_of(&a[0], &a[1]).unwrap_or_else(thrown),
        "floorApplies" => json!(floor_applies(a[0].as_str().unwrap(), Some(&a[1]).filter(|f| !f.is_null()))),
        "schemaVerb" => schema_verb_decl(&a[0], a[1].as_str().unwrap()).unwrap_or_else(thrown),
        "signActionSchema" | "actionSchemaKeyOf" => {
            let (doc, kid, secret, spec) =
                if f == "signActionSchema" { (Some(&a[0]), &a[1], &a[2], &a[3]) } else { (None, &a[0], &a[1], &a[2]) };
            let key = KeyPair::from_seed_b64u(secret["$bytes"].as_str().unwrap()).unwrap();
            let spec = Some(spec).filter(|s| !s.is_null());
            let alg = spec.and_then(|s| s["alg"].as_str());
            let pq = match spec.filter(|_| alg != Some("ed25519")) {
                Some(s) => match s.get("pqSeed") {
                    Some(seed) => Some(PqKeyPair::from_seed("ML-DSA-65", &common::b64d(seed["$bytes"].as_str().unwrap())).unwrap()),
                    None => return thrown("mlDsa65Keygen: the seed is required"),
                },
                None => None,
            };
            let suite = Suite { alg, pq: pq.as_ref() };
            match doc {
                Some(d) => sign_action_schema_value(d, kid.as_str().unwrap(), &key, &suite).unwrap_or_else(thrown),
                None => action_schema_key_of(kid.as_str().unwrap(), &key, &suite).unwrap_or_else(thrown),
            }
        }
        "actionSchemaDigest" => {
            atlas_pca::action_schema_digest(&a[0]).map(Value::String).unwrap_or_else(|| thrown("outside the strict profile"))
        }
        "verifyActionSchema" => match atlas_pca::verify_action_schema(&a[0], &a[1]) {
            Ok(()) => json!({"ok": true}),
            Err(reason) => json!({"ok": false, "reason": reason}),
        },
        "reversibilityFromMcpHints" => reversibility_from_mcp_hints(&a[0]),
        "draftSchemaFromMcpTools" => draft_schema_from_mcp_tools(&a[0], &a[1]).unwrap_or_else(thrown),
        "draftSchemaFromOpenApi" => draft_schema_from_open_api(&a[0], &a[1]).unwrap_or_else(thrown),
        other => panic!("unhandled corpus function {other}"),
    }
}

/// The reference's own exception text after these prefixes is not compared.
fn norm(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, x)| match (k.as_str(), x.as_str()) {
                    ("reason", Some(r)) if r.starts_with("schema verification error:") => (k.clone(), json!("schema verification error:")),
                    ("reason", Some(r)) if r.starts_with("malformed schema:") => (k.clone(), json!("malformed schema:")),
                    _ => (k.clone(), x.clone()),
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

fn replay(corpus: &str, total: usize, want: &[(&str, usize)]) {
    let cases = common::ref_cases_seeded(corpus);
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = want.iter().map(|(k, n)| (k.to_string(), *n)).collect();
    assert_eq!(per_fn, want, "{corpus}: per-function case totals");
    assert_eq!(cases.len(), total);
    let mut bad = Vec::new();
    for c in &cases {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&norm(&c["out"])) != atlas_pca::canonicalize(&norm(&got))
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{corpus}: {} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

#[test]
fn action_schema_replay() {
    replay(
        "action-schema",
        173,
        &[
            ("draftSchemaFromOpenApi", 32),
            ("draftSchemaFromMcpTools", 31),
            ("verifyActionSchema", 30),
            ("reversibilityOf", 20),
            ("floorApplies", 19),
            ("signActionSchema", 12),
            ("schemaVerb", 9),
            ("reversibilityFromMcpHints", 9),
            ("actionSchemaKeyOf", 6),
            ("actionSchemaDigest", 4),
            ("constants", 1),
        ],
    );
}

#[test]
fn action_schema_draft_replay() {
    replay(
        "action-schema-draft",
        104,
        &[("reversibilityOf", 72), ("draftSchemaFromOpenApi", 16), ("reversibilityFromMcpHints", 9), ("schemaVerb", 7)],
    );
}

//! Differential replay of test-data/ref-nl-approval.json.gz (written by the TypeScript reference): the approval half of natural-language
//! policy authoring: the catalog digest, the draft binding and digests, the model completion parsed and grounded into a draft, the
//! reviewer's signed approval (v2 and the legacy v1), the loader that is the only door from a draft to policy, and the agent minted from an
//! approved draft (only the deterministic envelope members are compared: the reference mints with a random goal salt). Every function of the
//! corpus has a handler and the per-function totals are asserted. A reference refusal must be a refusal here.
mod common;
use std::collections::BTreeMap;

use atlas_pca::agent::KeyPair;
use atlas_pca::read_envelope;
use atlas_pca::facade::{builtin_catalog, ActionSpec};
use atlas_pca::nl_approval::*;
use atlas_pca::serde_json::{json, Value};
use common::replay::thrown;
use sha2::{Digest, Sha256};

fn catalog_of(extras: &Value) -> Vec<ActionSpec> {
    let mut cat = builtin_catalog();
    for e in extras.as_array().into_iter().flatten() {
        let s = |k: &str| e.get(k).and_then(Value::as_str).map(String::from);
        let (connector, action) = (s("connector").unwrap_or_default(), s("action").unwrap_or_default());
        let spec = ActionSpec {
            verb: format!("{connector}.{action}"),
            connector,
            action,
            reversibility: s("reversibility").unwrap_or_default(),
            blast_radius: e.get("blastRadius").and_then(Value::as_f64).unwrap_or(0.0),
            amount_field: s("amountField").filter(|a| !a.is_empty()),
            resource: None,
            aliases: e.get("aliases").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(String::from).collect(),
            description: s("description").unwrap_or_default(),
        };
        match cat.iter().position(|c| c.verb == spec.verb) {
            Some(i) => cat[i] = spec,
            None => cat.push(spec),
        }
    }
    cat
}

/// A number as JavaScript reads it where it is compared or tested for finiteness: a JSON number, the `{"$num"}` marker, a numeric string
/// (`ToNumber`), anything else NaN.
fn number(v: &Value) -> f64 {
    if v.is_number() {
        return v.as_f64().unwrap_or(f64::NAN);
    }
    match v {
        Value::String(s) => s.trim().parse::<f64>().unwrap_or(f64::NAN),
        _ => match v.get("$num").and_then(Value::as_str) {
            Some("Infinity") => f64::INFINITY,
            Some("-Infinity") => f64::NEG_INFINITY,
            _ => f64::NAN,
        },
    }
}

/// `opts.k ?? default`: an absent or null member is the default.
fn opt_number(o: &Value, k: &str) -> Option<f64> {
    o.get(k).filter(|v| !v.is_null()).map(number)
}

fn secret(v: &Value) -> Vec<u8> {
    common::b64d(v["$bytes"].as_str().unwrap())
}

fn keypair(label: &str) -> KeyPair {
    let d: [u8; 32] = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into();
    KeyPair::from_seed(&d)
}

fn text(r: Result<String, String>) -> Value {
    r.map(Value::String).unwrap_or_else(thrown)
}

fn complete(raw: &str) -> impl Fn(&str) -> Result<String, String> + '_ {
    move |_| if raw == "THROWS" { Err("llm down".to_string()) } else { Ok(raw.to_string()) }
}

fn model(v: &Value) -> Option<&str> {
    v.as_str()
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "NL_APPROVAL_DOMAIN": NL_APPROVAL_DOMAIN,
            "NL_APPROVAL_DOMAIN_V2": NL_APPROVAL_DOMAIN_V2,
            "MAX_NL_OUTPUT_BYTES": MAX_NL_OUTPUT_BYTES,
            "MAX_NL_APPROVAL_TTL_MS": MAX_NL_APPROVAL_TTL_MS,
        }),
        "catalogDigest" => json!(catalog_digest(&catalog_of(&a[0]))),
        "draftBinding" => draft_binding(a[0].as_str().unwrap(), &catalog_of(&a[1]), model(&a[2])),
        "draftDigestV2" => text(draft_digest_v2(&a[0], &a[1], a[2].as_str().unwrap(), &a[3])),
        "draftDigest" => text(draft_digest(&a[0], &a[1], a[2].as_str().unwrap())),
        "policyFromNL" | "draftPolicyFromNL" => {
            let (instruction, raw) = (a[0].as_str().unwrap(), a[1].as_str().unwrap());
            let cat = catalog_of(&a[2]);
            let catalog = (!a[2].is_null()).then_some(cat.as_slice());
            let r = if f == "policyFromNL" {
                policy_from_nl(instruction, &complete(raw), catalog)
            } else {
                draft_policy_from_nl(instruction, &complete(raw), catalog, model(&a[3]))
            };
            r.unwrap_or_else(thrown)
        }
        "approveDraft" | "approveDraftLegacy" => {
            // Number.isFinite does not coerce: a numeric string is not a time
            let strict = |k: &str| opt_number(&a[2], k).map(|n| if a[2][k].is_string() { f64::NAN } else { n });
            let (now, ttl) = (strict("now"), strict("ttlMs"));
            let r = if f == "approveDraft" {
                approve_draft(&a[0], &secret(&a[1]), now, ttl)
            } else {
                approve_draft_legacy_v1(&a[0], &secret(&a[1]), now, ttl)
            };
            r.unwrap_or_else(thrown)
        }
        "loadApproved" => {
            let opts = &a[2];
            let reviewers: Vec<String> = opts
                .get("reviewers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|r| r.as_str().unwrap_or("\u{0}").to_string())
                .collect();
            let catalog = opts.get("extras").filter(|e| !e.is_null()).map(catalog_of);
            load_approved_policy(
                &a[0],
                &a[1],
                &LoadApprovedOptions { reviewers: &reviewers, catalog: catalog.as_deref(), now: opt_number(opts, "now") },
            )
        }
        "agentFromApproved" => {
            let r = &a[0];
            let opts = &r["opts"];
            let reviewers: Vec<String> =
                opts["reviewers"].as_array().into_iter().flatten().map(|x| x.as_str().unwrap_or("\u{0}").to_string()).collect();
            let principal = keypair(r["principalSeed"].as_str().unwrap());
            let req = AgentFromApprovedNl {
                draft: &r["draft"],
                approval: &r["approval"],
                reviewers: &reviewers,
                catalog: opts.get("extras").filter(|e| !e.is_null()).map(catalog_of),
                now: opt_number(opts, "now"),
                principal: &principal,
                goal: r["goal"].as_str().unwrap(),
                aud: r["aud"].as_str(),
                holder: r["holderSeed"].as_str().map(keypair),
            };
            match agent_from_approved_nl(req) {
                Err(e) => thrown(e),
                Ok((agent, reviewer, legacy)) => {
                    let env = read_envelope(&agent.grant).unwrap();
                    json!({
                        "reviewer": reviewer,
                        "legacy_unbound_instruction": legacy,
                        "envelope": {
                            "predicates": env["predicates"], "caveats": env["caveats"], "risk_policy": env["risk_policy"], "agent_binding": env["agent_binding"],
                        },
                    })
                }
            }
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn nl_approval_replay() {
    let cases = common::ref_cases_seeded("nl-approval");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("loadApproved", 58),
        ("draftPolicyFromNL", 42),
        ("policyFromNL", 40),
        ("approveDraft", 24),
        ("draftDigestV2", 10),
        ("agentFromApproved", 10),
        ("draftDigest", 7),
        ("draftBinding", 6),
        ("approveDraftLegacy", 5),
        ("catalogDigest", 3),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 206);
    let mut bad = Vec::new();
    for c in &cases {
        let got = run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap());
        let differs = if c["out"].get("$throws").is_some() {
            got.get("$throws").is_none()
        } else {
            atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got)
        };
        if differs {
            bad.push(format!("{}\n  want {}\n  got  {}", c["name"], c["out"], got));
        }
    }
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

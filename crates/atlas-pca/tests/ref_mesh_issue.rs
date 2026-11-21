//! Differential replay of test-data/ref-mesh-issue.json.gz (written by the TypeScript reference): the federation side of the mesh
//! (effective authority, proof size, revocation latency, capability translation, the federated budget, the cross-reference, the
//! worked example and the fork demonstration) and the scripted domain / witness state machine (rollback, equivocation, forks,
//! revocation supersets, clocks, stores that fail, export / import / restart). A case the reference refuses must be refused here;
//! inside a script an op that fails records `{"$err": message}` and the message is compared.
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::mesh_federation::*;
use atlas_pca::mesh_issue::{key_revocation_id, MeshDomain, MeshWitness, DEFAULT_MAX_CLOCK_SKEW_MS};
use atlas_pca::mesh_witness_store::{MemoryMeshWitnessStore, MeshWitnessStore};
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, thrown};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn key(label: &str) -> KeyPair {
    let seed: [u8; 32] = Sha256::digest(format!("atlas-pca-conformance/mesh-issue/{label}").as_bytes()).into();
    KeyPair::from_seed(&seed)
}

/// A store the script and several witnesses share; with a limit, every save after the first `limit` fails.
#[derive(Clone)]
struct Shared {
    inner: Arc<MemoryMeshWitnessStore>,
    saves: Arc<AtomicUsize>,
    limit: Option<usize>,
}
impl MeshWitnessStore for Shared {
    fn load(&self) -> Result<Option<Value>, String> {
        self.inner.load()
    }
    fn save(&self, state: &Value) -> Result<(), String> {
        if self.limit.is_some_and(|l| self.saves.fetch_add(1, Ordering::SeqCst) >= l) {
            return Err("disk".into());
        }
        self.inner.save(state)
    }
}

static NULL: Value = Value::Null;

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

/// `String(v)` of a script or function argument.
fn text(v: &Value) -> String {
    match v {
        Value::String(t) => t.clone(),
        Value::Array(a) => a.iter().map(text).collect::<Vec<_>>().join(","),
        other => other.to_string(),
    }
}

/// A double as the corpus writes it (`{"$num": ...}` for a value JSON cannot carry).
fn num(f: f64) -> Value {
    if f.is_nan() {
        json!({"$num": "NaN"})
    } else if f.is_infinite() {
        json!({"$num": if f > 0.0 { "Infinity" } else { "-Infinity" }})
    } else {
        atlas_pca::prohibitions::num_value(f)
    }
}

fn cap(label: &str) -> Value {
    json!({"id": label, "issuer": format!("iss-{label}"), "holder": "h", "caveats": [{"type": "scope", "actions": [label]}]})
}

fn named<'a, T>(m: &'a HashMap<String, T>, n: &Value) -> Result<&'a T, String> {
    m.get(s(n)).ok_or_else(|| format!("unknown name {}", s(n)))
}

fn named_mut<'a, T>(m: &'a mut HashMap<String, T>, n: &Value) -> Result<&'a mut T, String> {
    m.get_mut(s(n)).ok_or_else(|| format!("unknown name {}", s(n)))
}

fn script(ops: &[Value]) -> Value {
    let mut stores: HashMap<String, Shared> = HashMap::new();
    let mut witnesses: HashMap<String, MeshWitness> = HashMap::new();
    let mut domains: HashMap<String, MeshDomain> = HashMap::new();
    let mut heads: HashMap<String, Value> = HashMap::new();
    let mut bindings: HashMap<String, Value> = HashMap::new();
    let mut out = Vec::new();
    for op in ops {
        let op = op.as_array().cloned().unwrap_or_default();
        let arg = |i: usize| op.get(i).unwrap_or(&NULL);
        let r: Result<Value, String> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value, String> {
            match s(arg(0)) {
                "domain" => {
                    let d = MeshDomain::new(s(arg(1)), key(&format!("d/{}", s(arg(2)))));
                    let id = d.id.clone();
                    domains.insert(s(arg(1)).into(), d);
                    Ok(json!(id))
                }
                "witness" => {
                    let w = MeshWitness::new(key(&format!("w/{}", s(arg(2)))));
                    let id = w.id.clone();
                    witnesses.insert(s(arg(1)).into(), w);
                    Ok(json!(id))
                }
                "witnessOpts" => {
                    let x = arg(3);
                    let store = match x.get("store").filter(|n| n.as_str().is_some_and(|n| !n.is_empty())) {
                        Some(n) => Some(Box::new(named(&stores, n)?.clone()) as Box<dyn MeshWitnessStore>),
                        None => None,
                    };
                    let clock = x.get("clock").and_then(Value::as_f64).map(|at| Box::new(move || at) as Box<dyn Fn() -> f64>);
                    let w = MeshWitness::with_options(key(&format!("w/{}", s(arg(2)))), store, clock, x.get("skew").and_then(Value::as_f64))?;
                    let id = w.id.clone();
                    witnesses.insert(s(arg(1)).into(), w);
                    Ok(json!(id))
                }
                "store" | "failStore" => {
                    let limit = if s(arg(0)) == "failStore" {
                        Some(arg(2).as_u64().unwrap_or(0) as usize)
                    } else {
                        None
                    };
                    stores.insert(
                        s(arg(1)).into(),
                        Shared {
                            inner: Arc::new(MemoryMeshWitnessStore::default()),
                            saves: Arc::new(AtomicUsize::new(0)),
                            limit,
                        },
                    );
                    Ok(json!(true))
                }
                "storeLoad" => Ok(named(&stores, arg(1))?.load()?.unwrap_or(Value::Null)),
                "record" => Ok(json!(named_mut(&mut domains, arg(1))?.record(&cap(s(arg(2)))))),
                "revoke" => {
                    named_mut(&mut domains, arg(1))?.revoke(s(arg(2)));
                    Ok(Value::Null)
                }
                "publish" => {
                    named(&domains, arg(1))?;
                    let names = arg(4).as_array().cloned().unwrap_or_default();
                    for n in &names {
                        named(&witnesses, n)?;
                    }
                    // the witnesses leave the table while the domain borrows them, and come back whatever the outcome
                    let mut owned: Vec<(String, MeshWitness)> = names.iter().filter_map(|n| witnesses.remove(s(n)).map(|w| (s(n).to_string(), w))).collect();
                    let res = {
                        let mut refs: Vec<&mut MeshWitness> = owned.iter_mut().map(|(_, w)| w).collect();
                        named_mut(&mut domains, arg(1))?.publish_head(&mut refs, arg(3).as_f64().unwrap_or(f64::NAN), arg(5).as_u64().map(|t| t as usize))
                    };
                    witnesses.extend(owned);
                    let head = res?;
                    heads.insert(s(arg(2)).into(), head.clone());
                    Ok(head)
                }
                "fork" | "forkHead" => {
                    let mut h = named(&heads, arg(2))?.clone();
                    if s(arg(0)) == "fork" {
                        h[s(arg(3))] = arg(4).clone();
                    } else {
                        h["head"][s(arg(3))] = arg(4).clone();
                    }
                    heads.insert(s(arg(1)).into(), h);
                    Ok(Value::Null)
                }
                "cosign" => {
                    named(&witnesses, arg(1))?;
                    let h = named(&heads, arg(2))?.clone();
                    let domain_id = h["head"]["domain"].as_str();
                    let d = domains.values().find(|d| Some(d.id.as_str()) == domain_id).ok_or("no such domain")?;
                    let w = named_mut(&mut witnesses, arg(1))?;
                    let consistency = match arg(3) {
                        Value::Null => None,
                        Value::String(from) if from == "domain" => match w.last_seen(domain_id.unwrap_or("")) {
                            Some(prev) => Some(d.consistency_proof(&prev["size"], Some(&h["head"]["size"]))?),
                            None => None,
                        },
                        given => Some(given.clone()),
                    };
                    let rev_ids = if arg(4).as_str() == Some("domain") {
                        json!(d.rev.list())
                    } else {
                        arg(4).clone()
                    };
                    let mut req = json!({"head": h, "rev_ids": rev_ids});
                    if let Some(c) = consistency {
                        req["consistency"] = c;
                    }
                    w.cosign(&req)
                }
                "lastSeen" => {
                    let w = named(&witnesses, arg(1))?;
                    let id = domains.get(s(arg(2))).map_or_else(|| s(arg(2)).to_string(), |d| d.id.clone());
                    Ok(w.last_seen(&id).unwrap_or(Value::Null))
                }
                "export" => Ok(named(&witnesses, arg(1))?.export_state()),
                "import" => {
                    named(&witnesses, arg(1))?;
                    let state = match arg(2).get("$export") {
                        Some(from) => named(&witnesses, from)?.export_state(),
                        None => arg(2).clone(),
                    };
                    named_mut(&mut witnesses, arg(1))?.import_state(&state)?;
                    Ok(Value::Null)
                }
                "restart" => {
                    let store = named(&stores, arg(2))?.clone();
                    let w = MeshWitness::with_options(key(&format!("w/{}", s(arg(3)))), Some(Box::new(store)), None, None)?;
                    let state = w.export_state();
                    witnesses.insert(s(arg(1)).into(), w);
                    Ok(state)
                }
                "consistency" => named(&domains, arg(1))?.consistency_proof(arg(2), Some(arg(3)).filter(|n| !n.is_null())),
                "enroll" => {
                    let b = named(&domains, arg(1))?.enroll(s(arg(3)), s(arg(4)))?;
                    bindings.insert(s(arg(2)).into(), b.clone());
                    Ok(b)
                }
                "evidence" => {
                    let d = named(&domains, arg(1))?;
                    let head = named(&heads, arg(3))?;
                    let binding = if arg(4).is_null() { None } else { Some(named(&bindings, arg(4))?) };
                    d.evidence(&cap(s(arg(2))), head, binding)
                }
                _ => Err("op".into()),
            }
        }))
        .unwrap_or_else(|_| Err("panic".into()));
        out.push(r.unwrap_or_else(|e| json!({"$err": e})));
    }
    Value::Array(out)
}

fn run(f: &str, a: &[Value]) -> Value {
    let signer = |v: &Value| v.as_str().ok_or_else(|| "not a key".to_string()).and_then(KeyPair::from_seed_b64u);
    match f {
        "constants" => {
            json!({"DEFAULT_MAX_HEAD_AGE_MS": DEFAULT_MAX_HEAD_AGE_MS, "DEFAULT_MAX_CLOCK_SKEW_MS": DEFAULT_MAX_CLOCK_SKEW_MS, "DEFAULT_MAX_CHAIN_LENGTH": DEFAULT_MAX_CHAIN_LENGTH})
        }
        "keyRevocationId" => json!(key_revocation_id(&text(&a[0]))),
        "effectiveAuthority" => effective_authority(&a[0]).unwrap_or_else(thrown),
        "buildMeshExample" => build_mesh_example(a[0].as_f64().unwrap_or(1_800_000_000_000.0)).unwrap_or_else(thrown),
        "demonstrateForkRejection" => demonstrate_fork_rejection().unwrap_or_else(thrown),
        "meshProofSize" => mesh_proof_size(&a[0]).unwrap_or_else(thrown),
        "revocationLatencyBound" => {
            let b = revocation_latency_bound(&a[0]);
            json!({"published_ms": num(b.published_ms), "unpinned_ms": num(b.unpinned_ms), "pinned_ms": num(b.pinned_ms), "honest_provers_viable": b.honest_provers_viable})
        }
        "meshIssue" => script(a[0].as_array().map(Vec::as_slice).unwrap_or(&[])),
        "translateCapability" => signer(&a[1]["bridgeSecret"])
            .and_then(|k| translate_capability(&a[0], &a[1], &k))
            .unwrap_or_else(thrown),
        "verifyTranslatedCapability" => verify_translated_capability(&a[0], a.get(1)),
        "translatedEffectiveAuthority" => translated_effective_authority(&a[0]),
        "createFederatedBudget" => create_federated_budget(&a[0]),
        "allocateSub" => allocate_sub(&a[0], &a[1]),
        "spendFederated" => spend_federated(&a[0], &a[1], &a[2]),
        "federatedSafetyBound" => num(federated_safety_bound(&a[0])),
        "meshActionDigest" => mesh_action_digest(&a[0]).map_or_else(thrown, Value::String),
        "crossReferenceCommit" => cross_reference_commit(&a[0]).map_or_else(thrown, Value::String),
        "anchorCrossReference" => signer(&a[0]).and_then(|k| anchor_cross_reference(&k, &a[1], &a[2])).unwrap_or_else(thrown),
        "verifyCrossReference" => verify_cross_reference(&a[0], &a[1]),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn the_mesh_federation_and_issuing_side_match_the_reference() {
    // 2 digests are asked of a lone surrogate
    replay("mesh-issue", 787, 2, run);
}

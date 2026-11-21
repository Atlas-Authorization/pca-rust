//! Differential replay of the issuing side of the mesh (the log witness, the domain and its revocation set, proof assembly) against the
//! TypeScript reference: the meshWitness section of ref-core-stores-java, ref-core-mesh-domain-java and ref-core-mesh-proof-java. Each case is
//! one scripted op sequence; an op that fails records `{"$err": ...}` (the witness section by message, the others as "Error").
mod common;
use atlas_pca::agent::KeyPair;
use atlas_pca::mesh_issue::{MeshDomain, MeshWitness};
use atlas_pca::mesh_witness_store::{MemoryMeshWitnessStore, MeshWitnessStore};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::signers_more::{assemble_mesh_proof, sign_mesh_action};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

fn key(label: &str) -> KeyPair {
    let seed: [u8; 32] = Sha256::digest(format!("atlas-pca-conformance/{label}").as_bytes()).into();
    KeyPair::from_seed(&seed)
}

/// A store two witnesses (and the script) can share.
struct Shared(Arc<MemoryMeshWitnessStore>);
impl MeshWitnessStore for Shared {
    fn load(&self) -> Result<Option<Value>, String> {
        self.0.load()
    }
    fn save(&self, state: &Value) -> Result<(), String> {
        self.0.save(state)
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or("")
}

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Witness,
    Domain,
    Proof,
}

fn cap(kind: Kind, label: &str) -> Value {
    match kind {
        Kind::Witness => json!({"id": label, "caveats": [{"type": "scope", "actions": [label]}]}),
        _ => json!({"id": label, "issuer": format!("iss-{label}"), "holder": "h", "caveats": [{"type": "scope", "actions": [label]}]}),
    }
}

fn run(kind: Kind, ops: &[Value]) -> Value {
    let prefix = match kind {
        Kind::Witness => "",
        Kind::Domain => "mesh-domain/",
        Kind::Proof => "mesh-proof/",
    };
    let k = |label: &str| key(&format!("{prefix}{label}"));
    let mut stores: HashMap<String, Arc<MemoryMeshWitnessStore>> = HashMap::new();
    let mut witnesses: HashMap<String, MeshWitness> = HashMap::new();
    let mut domains: HashMap<String, MeshDomain> = HashMap::new();
    let mut named: HashMap<String, Value> = HashMap::new();
    let mut out = Vec::new();
    for op in ops {
        let op = op.as_array().cloned().unwrap_or_default();
        let r: Result<Value, String> = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Value, String> {
            let get = |named: &HashMap<String, Value>, n: &str| named.get(n).cloned().ok_or_else(|| format!("unknown {n}"));
            match s(&op[0]) {
                "store" => {
                    stores.insert(s(&op[1]).into(), Arc::new(MemoryMeshWitnessStore::default()));
                    Ok(json!(true))
                }
                "witness" => {
                    let (label, store) = if kind == Kind::Witness { (s(&op[3]), op[2].as_str()) } else { (s(&op[2]), None) };
                    let st = store.map(|n| Box::new(Shared(stores[n].clone())) as Box<dyn MeshWitnessStore>);
                    let w = MeshWitness::with_options(k(label), st, None, None)?;
                    let id = w.id.clone();
                    witnesses.insert(s(&op[1]).into(), w);
                    Ok(if kind == Kind::Witness { json!(id) } else { json!(id) })
                }
                "witnessClock" => {
                    let at = op[3].as_f64().unwrap_or(f64::NAN);
                    let w = MeshWitness::with_options(k(s(&op[2])), None, Some(Box::new(move || at)), op[4].as_f64())?;
                    witnesses.insert(s(&op[1]).into(), w);
                    Ok(json!(true))
                }
                "restart" => {
                    let w = MeshWitness::with_options(k(s(&op[3])), Some(Box::new(Shared(stores[s(&op[2])].clone()))), None, None)?;
                    let st = w.export_state();
                    witnesses.insert(s(&op[1]).into(), w);
                    Ok(st)
                }
                "domain" => {
                    let d = MeshDomain::new(s(&op[1]), k(s(&op[2])));
                    let id = d.id.clone();
                    domains.insert(s(&op[1]).into(), d);
                    Ok(json!(id))
                }
                "domainId" => Ok(json!(domains[s(&op[1])].id)),
                "record" => Ok(json!(domains.get_mut(s(&op[1])).ok_or("domain")?.record(&cap(kind, s(&op[2]))))),
                "revoke" => {
                    domains.get_mut(s(&op[1])).ok_or("domain")?.revoke(s(&op[2]));
                    Ok(Value::Null)
                }
                "publish" => {
                    // witness: [D, ts, [W..], thr]; domain/proof: [D, H, ts, [W..], thr]
                    let off = if kind == Kind::Witness { 0 } else { 1 };
                    let (ts, names, thr) = (op[2 + off].as_f64().unwrap_or(f64::NAN), op[3 + off].as_array().cloned().unwrap_or_default(), op[4 + off].as_u64());
                    let mut owned: Vec<(String, MeshWitness)> = Vec::new();
                    for n in &names {
                        let w = witnesses.remove(s(n)).ok_or("witness")?;
                        owned.push((s(n).to_string(), w));
                    }
                    let res = {
                        let mut refs: Vec<&mut MeshWitness> = owned.iter_mut().map(|(_, w)| w).collect();
                        domains.get_mut(s(&op[1])).ok_or("domain")?.publish_head(&mut refs, ts, thr.map(|t| t as usize))
                    };
                    for (n, w) in owned {
                        witnesses.insert(n, w);
                    }
                    let head = res?;
                    if kind != Kind::Witness {
                        named.insert(s(&op[2]).into(), head.clone());
                    }
                    Ok(head)
                }
                "lastSeen" => Ok(witnesses[s(&op[1])].last_seen(s(&op[2])).unwrap_or(Value::Null)),
                "export" => Ok(witnesses[s(&op[1])].export_state()),
                "import" => {
                    witnesses.get_mut(s(&op[1])).ok_or("witness")?.import_state(&op[2])?;
                    Ok(Value::Null)
                }
                "load" => Ok(stores[s(&op[1])].load()?.unwrap_or(Value::Null)),
                "save" => {
                    stores[s(&op[1])].save(&op[2])?;
                    Ok(Value::Null)
                }
                "fork" => {
                    let mut h = get(&named, s(&op[2]))?;
                    h[s(&op[3])] = op[4].clone();
                    named.insert(s(&op[1]).into(), h);
                    Ok(Value::Null)
                }
                "forkHead" => {
                    let mut h = get(&named, s(&op[2]))?;
                    h["head"][s(&op[3])] = op[4].clone();
                    named.insert(s(&op[1]).into(), h);
                    Ok(Value::Null)
                }
                "subcos" => {
                    let mut h = get(&named, s(&op[2]))?;
                    let all = h["cosigs"].as_array().cloned().unwrap_or_default();
                    h["cosigs"] = Value::Array(op[3].as_array().cloned().unwrap_or_default().iter().filter_map(|i| all.get(i.as_u64()? as usize).cloned()).collect());
                    named.insert(s(&op[1]).into(), h);
                    Ok(Value::Null)
                }
                "enroll" => {
                    let b = domains[s(&op[1])].enroll(s(&op[3]), s(&op[4]))?;
                    named.insert(s(&op[2]).into(), b.clone());
                    Ok(b)
                }
                "evidence" | "ev" => {
                    // domain: [D, label, H, B|null]; proof: [D, E, label, H, B|null]
                    let off = if s(&op[0]) == "ev" { 1 } else { 0 };
                    let head = get(&named, s(&op[3 + off]))?;
                    let binding = match op[4 + off].as_str() {
                        // an unknown name is `undefined` in the reference (no binding)
                        Some(b) => named.get(b).cloned(),
                        None => None,
                    };
                    let e = domains[s(&op[1])].evidence(&cap(kind, s(&op[2 + off])), &head, binding.as_ref())?;
                    if off == 1 {
                        named.insert(s(&op[2]).into(), e.clone());
                    }
                    Ok(e)
                }
                "setEv" => {
                    let mut e = get(&named, s(&op[2]))?;
                    let field = s(&op[3]);
                    if op[4].get("$del").is_some() {
                        e.as_object_mut().ok_or("ev")?.remove(field);
                    } else if field == "head" && op[4].as_str().is_some_and(|n| named.contains_key(n)) {
                        e["head"] = named[s(&op[4])].clone();
                    } else {
                        e[field] = op[4].clone();
                    }
                    named.insert(s(&op[1]).into(), e);
                    Ok(Value::Null)
                }
                "pinProof" | "pinProofAs" => {
                    // domain: [D, pin, H]; proof: [D, P, pin, H]
                    let off = if s(&op[0]) == "pinProofAs" { 1 } else { 0 };
                    let pin = match op[2 + off].as_str() {
                        Some(n) => get(&named, n)?["head"].clone(),
                        None => op[2 + off].clone(),
                    };
                    let p = domains[s(&op[1])].pin_proof(&pin, &get(&named, s(&op[3 + off]))?)?;
                    if off == 1 {
                        named.insert(s(&op[2]).into(), p.clone());
                    }
                    Ok(p)
                }
                "nonMembership" => domains[s(&op[1])].rev.non_membership_proof(s(&op[2])),
                "assemble" => {
                    let chain: Vec<Value> = op[1].as_array().cloned().unwrap_or_default().iter().map(|l| cap(kind, s(l))).collect();
                    let hops = op[2].as_array().cloned().unwrap_or_default().iter().map(|n| get(&named, s(n))).collect::<Result<Vec<_>, _>>()?;
                    let pins = match op[5].as_array() {
                        Some(a) => Some(a.iter().map(|n| get(&named, s(n))).collect::<Result<Vec<_>, _>>()?),
                        None => None,
                    };
                    assemble_mesh_proof(&chain, &hops, &op[3], &k(s(&op[4])), pins.as_deref())
                }
                "sign" => {
                    let chain: Vec<Value> = op[1].as_array().cloned().unwrap_or_default().iter().map(|l| cap(kind, s(l))).collect();
                    Ok(json!(sign_mesh_action(&chain, &op[2], &k(s(&op[3])))?))
                }
                other => Err(format!("op {other}")),
            }
        }))
        .unwrap_or_else(|_| Err("panic".into()));
        out.push(match r {
            Ok(v) => v,
            Err(e) => json!({"$err": if kind == Kind::Witness { e } else { "Error".to_string() }}),
        });
    }
    Value::Array(out)
}

fn replay(corpus: &str, fn_name: &str, kind: Kind, expect: usize) {
    let cases = common::ref_cases(corpus);
    let (mut bad, mut ran) = (Vec::new(), 0usize);
    for c in cases.iter().filter(|c| c["fn"] == fn_name) {
        ran += 1;
        let got = run(kind, c["args"][0].as_array().map(Vec::as_slice).unwrap_or(&[]));
        if atlas_pca::canonicalize(&c["out"]) != atlas_pca::canonicalize(&got) {
            let (w, g) = (c["out"].as_array().cloned().unwrap_or_default(), got.as_array().cloned().unwrap_or_default());
            let at = (0..w.len().max(g.len())).find(|i| w.get(*i) != g.get(*i)).unwrap_or(0);
            bad.push(format!("{} op {at}\n  want {}\n  got  {}", c["name"], w.get(at).unwrap_or(&Value::Null), g.get(at).unwrap_or(&Value::Null)));
        }
    }
    assert_eq!(ran, expect, "{corpus}: cases replayed");
    assert!(bad.is_empty(), "{} cases differ:\n{}", bad.len(), bad.join("\n"));
}

#[test]
fn the_mesh_witness_matches_the_reference() {
    replay("core-stores-java", "meshWitness", Kind::Witness, 9);
}

#[test]
fn the_mesh_domain_matches_the_reference() {
    replay("core-mesh-domain-java", "meshDomain", Kind::Domain, 18);
}

#[test]
fn the_mesh_proof_assembly_matches_the_reference() {
    replay("core-mesh-proof-java", "meshProof", Kind::Proof, 8);
}

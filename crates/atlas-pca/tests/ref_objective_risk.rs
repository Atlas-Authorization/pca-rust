//! Differential replay of test-data/ref-objective-risk.json.gz (written by the TypeScript reference): the canonical action, the
//! inverse registry and reversibility, the resource graph and blast radius, the native and bring-your-own embedders, the goal
//! commitment and the committed distance, split-conformal calibration, the harm currency, the objective risk and the dispute oracle.
//! The specs of the registry, graph, embedder and context are the ones of the generator header. A case the reference refuses must be
//! refused here.
mod common;
use atlas_pca::objective_risk::*;
use atlas_pca::prohibitions::num_value;
use atlas_pca::serde_json::{json, Value};
use common::replay::{replay, thrown};
use std::collections::BTreeSet;

/// A number: a JSON number or `{"$num": "NaN" | "Infinity" | "-Infinity"}`; anything else is NaN.
fn double(v: &Value) -> f64 {
    match v.get("$num").and_then(Value::as_str) {
        Some("Infinity") => f64::INFINITY,
        Some("-Infinity") => f64::NEG_INFINITY,
        Some(_) => f64::NAN,
        None => v.as_f64().filter(|_| v.is_number()).unwrap_or(f64::NAN),
    }
}

fn doubles(v: &Value) -> Vec<f64> {
    v.as_array().map(|a| a.iter().map(double).collect()).unwrap_or_default()
}

/// A number as the reference's JSON writes it.
fn nv(f: f64) -> Value {
    if f.is_nan() {
        json!({"$num": "NaN"})
    } else if f.is_infinite() {
        json!({"$num": if f > 0.0 { "Infinity" } else { "-Infinity" }})
    } else if f == 0.0 && f.is_sign_negative() {
        Value::from(-0.0f64)
    } else {
        num_value(f)
    }
}

fn strings(v: &Value) -> Vec<String> {
    v.as_array().map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()).unwrap_or_default()
}

fn registry(spec: &Value) -> InMemoryInverseRegistry {
    let mut r = InMemoryInverseRegistry::new(&strings(&spec["trusted"]));
    for e in spec["entries"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        r.register(e[0].as_str().expect("verb"), &e[1]);
    }
    r
}

fn graph(spec: &Value) -> Result<ResourceGraph, String> {
    let mut g = ResourceGraph::new();
    for n in spec["nodes"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        g.add_node(n)?;
    }
    for e in spec["edges"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        g.add_edge(e)?;
    }
    Ok(g)
}

/// A custom embedder that returns `vector` verbatim, valid or not.
struct Fixed {
    model_id: String,
    config: Value,
    dims: f64,
    vector: Value,
}

impl Embedder for Fixed {
    fn model_id(&self) -> String {
        self.model_id.clone()
    }
    fn config(&self) -> Value {
        self.config.clone()
    }
    fn dims(&self) -> f64 {
        self.dims
    }
    fn embed(&self, _a: &Value) -> Result<Value, String> {
        Ok(self.vector.clone())
    }
}

fn infer_of(spec: &Value, dims: f64) -> InferFn {
    let spec = spec.clone();
    Box::new(move |j: &str| {
        if spec["throws"] == true {
            return Err("infer boom".into());
        }
        if spec["notArray"] == true {
            return Ok(json!("x"));
        }
        if spec["byLen"] == true {
            let len = j.encode_utf16().count() as f64;
            return Ok(Value::Array((0..dims as usize).map(|k| num_value(len + k as f64)).collect()));
        }
        Ok(spec["vector"].clone())
    })
}

fn byo(descriptor: &Value, claimed: Option<&str>, infer: &Value) -> Result<ByoEmbedder, String> {
    let dims = descriptor.get("dims").map_or(4.0, double);
    byo_embedder(descriptor, infer_of(infer, if infer["byLen"] == true { dims } else { infer.get("dims").map_or(4.0, double) }), claimed)
}

fn embedder(spec: &Value) -> Result<Box<dyn Embedder>, String> {
    match spec["scheme"].as_str() {
        Some("native") => Ok(Box::new(native_hash_embedder(&spec["config"])?)),
        Some("fixed") => Ok(Box::new(Fixed { model_id: spec["modelId"].as_str().unwrap_or("").into(), config: spec["config"].clone(), dims: double(&spec["dims"]), vector: spec["vector"].clone() })),
        _ => Ok(Box::new(byo(&spec["descriptor"], spec["claimedModelId"].as_str(), &spec["infer"])?)),
    }
}

/// The context of a spec, owned.
struct Ctx {
    registry: InMemoryInverseRegistry,
    kinds: BTreeSet<String>,
    graph: ResourceGraph,
    scope: Option<Value>,
    embedder: Box<dyn Embedder>,
    spec: Value,
    denominations: Vec<Value>,
    calibration: Option<Vec<f64>>,
}

fn ctx(c: &Value) -> Result<Ctx, String> {
    Ok(Ctx {
        registry: registry(&c["registry"]),
        kinds: strings(&c["authorizedKinds"]).into_iter().collect(),
        graph: graph(&c["graph"])?,
        scope: c.get("scope").filter(|s| !s.is_null()).cloned(),
        embedder: embedder(&c["embedder"])?,
        spec: c.clone(),
        denominations: c["denominations"].as_array().cloned().unwrap_or_default(),
        calibration: c.get("calibration").filter(|s| !s.is_null()).map(doubles),
    })
}

impl Ctx {
    fn with<R>(&self, f: impl FnOnce(&ObjectiveRiskContext) -> R) -> R {
        let c = &self.spec;
        f(&ObjectiveRiskContext {
            registry: &self.registry,
            authorized_kinds: &self.kinds,
            graph: &self.graph,
            scope: self.scope.as_ref(),
            embedder: self.embedder.as_ref(),
            goal: &c["goal"],
            commitments: &c["commitments"],
            denominations: &self.denominations,
            weights: &c["weights"],
            taint: double(&c["taint"]),
            age: double(&c["age"]),
            attested_uncertainty: c.get("attestedUncertainty").filter(|v| !v.is_null()).map(double),
            calibration: self.calibration.as_deref(),
        })
    }
}

fn scope(v: &Value) -> Option<&Value> {
    Some(v).filter(|s| !s.is_null())
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({"METRIC": METRIC, "DEFAULT_EPSILON": nv(DEFAULT_EPSILON), "NATIVE_SCHEME": NATIVE_SCHEME, "DEFAULT_MAX_PARAM_LEAVES": DEFAULT_MAX_PARAM_LEAVES, "DEFAULT_NATIVE_CONFIG": default_native_config()}),
        "canonicalAction" => canonical_action(&a[0]).unwrap_or_else(thrown),
        "canonicalActionJson" => canonical_action_json(&a[0]).map_or_else(thrown, |s| json!(s)),
        "canonicalActionDigest" => canonical_action_digest(&a[0]).map_or_else(thrown, |s| json!(s)),
        "registryOps" => {
            let mut r = InMemoryInverseRegistry::new(&strings(&a[0]));
            let mut out = Vec::new();
            for op in a[1].as_array().expect("ops") {
                out.push(match op[0].as_str() {
                    Some("register") => {
                        r.register(op[1].as_str().expect("verb"), &op[2]);
                        Value::Null
                    }
                    Some("lookup") => op[1].as_str().and_then(|v| r.lookup(v)).unwrap_or(Value::Null),
                    Some("trustedVerifiers") => json!(r.trusted_verifiers()),
                    Some("digest") => match r.digest() {
                        Ok(d) => json!(d),
                        Err(e) => return thrown(e),
                    },
                    other => panic!("unhandled registry op {other:?}"),
                });
            }
            Value::Array(out)
        }
        "registryDigest" => registry(&a[0]).digest().map_or_else(thrown, |d| json!(d)),
        "reversibility" => reversibility(&a[0], &registry(&a[1]), &strings(&a[2]).into_iter().collect()),
        "graphBuild" => match graph(&a[0]).and_then(|g| g.digest().map(|d| (g.size(), d))) {
            Ok((size, digest)) => json!({"size": size, "digest": digest}),
            Err(e) => thrown(e),
        },
        "graphReachable" => graph(&a[0]).map_or_else(thrown, |g| json!(g.reachable(a[1].as_str().unwrap_or(""), scope(&a[2])))),
        "graphNode" => graph(&a[0]).map_or_else(thrown, |g| a[1].as_str().and_then(|id| g.node(id)).cloned().unwrap_or(Value::Null)),
        "blastRadius" => graph(&a[1]).map_or_else(thrown, |g| blast_radius(&a[0], &g, scope(&a[2]))),
        "nativeEmbed" => native_hash_embedder(&a[0]).and_then(|e| e.embed(&a[1]).map(|v| json!({"modelId": e.model_id(), "dims": nv(e.dims()), "config": e.config(), "vector": v}))).unwrap_or_else(thrown),
        "byoModelId" => byo_model_id(&a[0]).map_or_else(thrown, |s| json!(s)),
        "byoEmbed" => byo(&a[0], a[1].as_str(), &a[2]).and_then(|e| e.embed(&a[3]).map(|v| json!({"modelId": e.model_id(), "dims": nv(e.dims()), "vector": v}))).unwrap_or_else(thrown),
        "validateVector" => validate_vector(&a[0], double(&a[1])).map_or_else(thrown, |v| json!(v)),
        "conformanceCheck" => embedder(&a[0]).map_or_else(thrown, |e| json!(conformance_check(e.as_ref(), a[1].as_array().expect("cases")))),
        "commitGoal" => embedder(&a[0]).and_then(|e| commit_goal(e.as_ref(), &a[1], if a[2].is_null() { DEFAULT_EPSILON } else { double(&a[2]) })).unwrap_or_else(thrown),
        "verifyGoalCommitment" => embedder(&a[1]).map_or_else(thrown, |e| verify_goal_commitment(&a[0], e.as_ref()).map_or(Value::Null, |s| json!(s))),
        "vectorDistance" => nv(vector_distance(&doubles(&a[0]), &doubles(&a[1]), if a[2].is_null() { DEFAULT_EPSILON } else { double(&a[2]) })),
        "committedDistanceChecked" => embedder(&a[2]).map_or_else(thrown, |e| match committed_distance_checked(&a[0], &a[1], e.as_ref()) {
            Ok(v) => json!({"ok": true, "value": nv(v)}),
            Err(reason) => json!({"ok": false, "reason": reason}),
        }),
        "committedDistance" => embedder(&a[2]).map_or_else(thrown, |e| nv(committed_distance(&a[0], &a[1], e.as_ref()))),
        "calibrate" => nv(calibrate(double(&a[0]), &doubles(&a[1]))),
        "conformalThreshold" => conformal_threshold(&doubles(&a[0]), double(&a[1])).map_or(Value::Null, nv),
        "calibrationDigest" => calibration_digest(&doubles(&a[0])).map_or_else(thrown, |d| json!(d)),
        "harmReport" => harm_report(&a[0], a[1].as_array().expect("denominations")),
        "objectiveRisk" => ctx(&a[1]).and_then(|c| c.with(|x| objective_risk(&a[0], x))).unwrap_or_else(thrown),
        "objectiveRiskOracle" => ctx(&a[0]).map_or_else(thrown, |c| c.with(|x| objective_risk_oracle_resolve(x, &a[1], &a[2]))),
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn objective_risk_replay() {
    replay("objective-risk", 4052, 0, run);
}

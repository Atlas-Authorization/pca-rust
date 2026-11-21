//! Differential replay of test-data/ref-taint.json.gz (written by the TypeScript reference): the taint lattice (levels, rank, value,
//! join), the trusted-input registry, the independent classification of a provenance ref and the taint of a provenance (with the
//! registry and resource graph variants: junk records, a registry that answers whatever label it is told to, one that fails, a graph
//! that fails). A case the reference refuses must be refused here.
mod common;
use atlas_pca::prohibitions::num_value;
use atlas_pca::serde_json::{json, Value};
use atlas_pca::taint::*;
use common::replay::{replay, thrown};

/// A registry that answers the same label for every digest, whatever its kind.
struct Fixed(Option<TaintLabel>);

impl TrustedInputRegistry for Fixed {
    fn lookup(&self, _digest: &str) -> Option<TaintLabel> {
        self.0.clone()
    }
}

struct Throws;

impl TrustedInputRegistry for Throws {
    fn lookup(&self, _digest: &str) -> Option<TaintLabel> {
        panic!("registry boom")
    }
}

struct Graph {
    nodes: Vec<String>,
    throws: bool,
}

impl ResourceGraphNodes for Graph {
    fn node(&self, id: &str) -> bool {
        if self.throws {
            panic!("graph boom");
        }
        self.nodes.iter().any(|n| n == id)
    }
}

/// An in-memory registry filled by `record(digest, label)` in order; a record with a digest or a label that is not well formed is one
/// the reference ignores (an empty digest or an unknown level is ignored by `record` itself).
fn filled(records: &Value) -> InMemoryTrustedInputRegistry {
    let r = InMemoryTrustedInputRegistry::new();
    for rec in records.as_array().map(Vec::as_slice).unwrap_or(&[]) {
        if let (Some(d), Some(l)) = (rec[0].as_str(), label_from_value(&rec[1])) {
            r.record(d, l);
        }
    }
    r
}

/// The registry of a spec; `None` = the context carries none.
fn registry(spec: &Value) -> Option<Box<dyn TrustedInputRegistry>> {
    if spec.is_null() {
        return None;
    }
    Some(match spec.get("mode").and_then(Value::as_str) {
        Some("fixed") => Box::new(Fixed(label_from_value(&spec["fixed"]))),
        Some("throws") => Box::new(Throws),
        _ => Box::new(filled(&spec["records"])),
    })
}

fn graph(ctx: &Value) -> Option<Graph> {
    let g = ctx.get("graph").filter(|g| !g.is_null())?;
    let nodes = g["nodes"].as_array().map(|a| a.iter().filter_map(|n| n.as_str().map(String::from)).collect()).unwrap_or_default();
    Some(Graph { nodes, throws: g.get("throws") == Some(&json!(true)) })
}

fn registry_script(ops: &[Value]) -> Value {
    let r = InMemoryTrustedInputRegistry::new();
    Value::Array(
        ops.iter()
            .map(|op| {
                let name = op[0].as_str().unwrap_or("");
                match name {
                    "lookup" => op[1].as_str().and_then(|d| r.lookup(d)).map_or(Value::Null, |l| label_to_value(&l)),
                    "size" => json!(r.size()),
                    "emptyLookup" => op[1].as_str().and_then(|d| EMPTY_REGISTRY.lookup(d)).map_or(Value::Null, |l| label_to_value(&l)),
                    "record" => {
                        // a digest that is not text or a label that is not an object with a text kind is ignored, as the reference does
                        if let (Some(d), Some(l)) = (op[1].as_str(), label_from_value(&op[2])) {
                            r.record(d, l);
                        }
                        Value::Null
                    }
                    "recordTrusted" => {
                        r.record_trusted(op[1].as_str().unwrap_or(""));
                        Value::Null
                    }
                    "recordFirstParty" => {
                        r.record_first_party(op[1].as_str().unwrap_or(""));
                        Value::Null
                    }
                    "recordTool" => {
                        r.record_tool(op[1].as_str().unwrap_or(""), op[2].as_str().unwrap_or(""));
                        Value::Null
                    }
                    "recordWeb" => {
                        r.record_web(op[1].as_str().unwrap_or(""));
                        Value::Null
                    }
                    other => panic!("unhandled registry op {other}"),
                }
            })
            .collect(),
    )
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({"TAINT_LEVELS": TAINT_LEVELS, "BOTTOM": label_to_value(&bottom()), "TOP": label_to_value(&top())}),
        "isTaintLevel" => json!(is_taint_level_value(&a[0])),
        "labelRank" => json!(label_rank_of(&a[0])),
        "taintValue" => num_value(taint_value_of(&a[0])),
        "joinLabel" => join_label_values(&a[0], &a[1]).unwrap_or_else(thrown),
        "joinLabels" => join_label_list(a[0].as_array().expect("labels")).unwrap_or_else(thrown),
        "registry" => registry_script(a[0].as_array().expect("ops")),
        "classifyRef" => {
            let g = graph(&a[1]);
            let g = g.as_ref().map(|g| g as &dyn ResourceGraphNodes);
            // without a registry the reference reads `undefined.lookup` for a usable ref and returns the worst case for any other
            let reg: Box<dyn TrustedInputRegistry> = match registry(&a[1]["registry"]) {
                Some(r) => r,
                None if a[0].as_str().is_some_and(|s| !s.is_empty()) => return thrown("Cannot read properties of undefined (reading 'lookup')"),
                None => Box::new(EmptyTrustedInputRegistry),
            };
            classify_ref_checked(&a[0], &*reg, g).map_or_else(thrown, |l| label_to_value(&l))
        }
        "computeTaint" => {
            let reg = registry(&a[1]["registry"]);
            let g = graph(&a[1]);
            compute_taint_value(&a[0], reg.as_deref(), g.as_ref().map(|g| g as &dyn ResourceGraphNodes))
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn taint_replay() {
    replay("taint", 2344, 0, run);
}

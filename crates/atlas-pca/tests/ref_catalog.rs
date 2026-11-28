//! Differential replay of test-data/ref-catalog.json.gz (written by the TypeScript reference): action definition, the fail-closed
//! spec of an unknown verb, the built-in rows with their digest, and catalogs driven through scripted lookups, pins and extensions.
//! A case the reference refuses must be refused here; an op the reference refuses records `{"$err": true}`.
mod common;
use atlas_pca::catalog::*;
use atlas_pca::serde_json::{json, Map, Value};
use common::replay::{replay, thrown};

fn err() -> Value {
    json!({"$err": true})
}

fn op(cat: &Catalog, op: &Value) -> Value {
    let text = |i: usize| op.get(i).and_then(Value::as_str);
    match (text(0), text(1), text(2)) {
        // a lookup without its argument finds nothing in the reference either
        (Some("get"), verb, _) => verb.and_then(|v| cat.get(v)).cloned().unwrap_or(Value::Null),
        (Some("forConnector"), Some(c), _) => json!(cat.for_connector(c)),
        (Some("all"), ..) => json!(cat.all()),
        (Some("resolve"), Some(c), action) => action.and_then(|a| cat.resolve(c, a)).cloned().unwrap_or(Value::Null),
        (Some("resolveAction"), Some(v), _) => resolve_action(cat, v),
        (Some("digest"), ..) => catalog_digest(cat).map_or_else(|_| err(), Value::String),
        (Some("assertPinned"), Some("$self"), _) => catalog_digest(cat).and_then(|d| assert_catalog_pinned(cat, &d)).map_or_else(|_| err(), |_| json!(true)),
        (Some("assertPinned"), Some(d), _) => assert_catalog_pinned(cat, d).map_or_else(|_| err(), |_| json!(true)),
        // a pin that is not a string equals no digest
        (Some("assertPinned"), None, _) => err(),
        (Some("extend"), ..) => match extend_catalog(cat, op[1].as_array().map(Vec::as_slice).unwrap_or(&[])) {
            Ok(e) => catalog_digest(&e).map_or_else(|_| err(), |d| json!({"all": e.all(), "digest": d})),
            Err(_) => err(),
        },
        (Some("bogus"), ..) => err(),
        other => panic!("unhandled catalog op {other:?}"),
    }
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "defineAction" => define_action(&a[0]).unwrap_or_else(thrown),
        "uncataloguedSpec" => uncatalogued_spec(a[0].as_str().expect("a verb")),
        "builtin" => {
            let blast: Map<String, Value> = BLAST.iter().map(|(k, v)| (k.to_string(), json!(v))).collect();
            json!({"actions": builtin_actions(), "digest": catalog_digest(&DEFAULT_CATALOG).expect("the built-in digest"), "blast": blast})
        }
        "catalog" => {
            let cat = a[0].as_array().map_or_else(|| DEFAULT_CATALOG.clone(), |l| build_catalog(l));
            json!(a[1].as_array().expect("ops").iter().map(|o| op(&cat, o)).collect::<Vec<_>>())
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn ref_catalog_replay() {
    replay("catalog", 75, 0, run);
}

#[test]
fn builtin_catalog_is_pinned() {
    assert_eq!(builtin_actions().len(), 21);
    assert_eq!(catalog_digest(&DEFAULT_CATALOG).as_deref(), Ok("7pXXVTal7F5wMK-5cQUaN4e4zz0m3SF5wrv19iK6BBQ"));
    assert!(assert_catalog_pinned(&DEFAULT_CATALOG, "x").is_err());
}

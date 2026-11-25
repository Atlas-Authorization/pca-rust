//! The in-process core-module host (feature `sandbox-wasm`): handle use, fuel, wall-clock, memory cap, import allow-list, egress.
#![cfg(feature = "sandbox-wasm")]
use atlas_pca::sandbox_egress::EgressPolicy;
use atlas_pca::sandbox_handles::*;
use atlas_pca::sandbox_receipts::ReceiptLog;
use atlas_pca::sandbox_reference::{build_probe_tool, build_tool};
use atlas_pca::sandbox_wasm::{run, CoreOptions};
use atlas_pca::serde_json::{json, Value};
use atlas_pca::{AuthorizedOperation, Operation};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

fn mint(t: &mut HandleTable, verb: &str, resource: &str) -> usize {
    let params = json!({});
    let bound = AuthorizedOperation {
        verb: verb.into(),
        resource: resource.into(),
        params_digest: atlas_pca::hash_canonical_strict(&params).unwrap(),
        id: "op".into(),
    };
    t.mint(
        Some(&bound),
        &Operation::new(verb, resource, params),
        &MintOptions::default(),
    )
    .unwrap()
}

fn table(policy: Arc<Mutex<EgressPolicy>>) -> Arc<Mutex<HandleTable>> {
    let mut ex: HashMap<String, Executor> = HashMap::new();
    ex.insert("fs.read".into(), Box::new(|_| Ok(vec![7, 8, 9])));
    // the guest has no network; a handle that fetches asks the egress policy, which denies by default
    let p = policy.clone();
    ex.insert(
        "net.ok".into(),
        Box::new(move |_| {
            match p
                .lock()
                .unwrap()
                .claim("GET", "https://api.example.com/v1", b"")
            {
                atlas_pca::sandbox_egress::EgressDecision::Allow { .. } => Ok(vec![1]),
                _ => Err("denied".into()),
            }
        }),
    );
    let p = policy;
    ex.insert(
        "net.evil".into(),
        Box::new(move |_| {
            match p
                .lock()
                .unwrap()
                .claim("GET", "https://evil.example/x", b"")
            {
                atlas_pca::sandbox_egress::EgressDecision::Allow { .. } => Ok(vec![1]),
                _ => Err("denied".into()),
            }
        }),
    );
    Arc::new(Mutex::new(HandleTable::new(
        "wasi_no_ambient",
        ReceiptLog::new(None, None),
        ex,
        None,
    )))
}

fn fixture() -> (Arc<Mutex<HandleTable>>, usize, usize, usize) {
    let policy = Arc::new(Mutex::new(EgressPolicy::new(Box::new(|| 0.0))));
    let op = Operation::new("net.ok", "api.example.com", json!({}));
    let bound = AuthorizedOperation {
        verb: "net.ok".into(),
        resource: "api.example.com".into(),
        params_digest: atlas_pca::hash_canonical_strict(&json!({})).unwrap(),
        id: "op".into(),
    };
    policy
        .lock()
        .unwrap()
        .admit(Some(&bound), &op, |_| Some(json!({"method": "GET", "scheme": "https", "host": "api.example.com", "path": "/v1"})), None, None)
        .unwrap();
    let t = table(policy);
    let (a, b, c) = {
        let mut g = t.lock().unwrap();
        (
            mint(&mut g, "fs.read", "/x"),
            mint(&mut g, "net.ok", "api.example.com"),
            mint(&mut g, "net.evil", "evil.example"),
        )
    };
    (t, a, b, c)
}

fn tool(spec: Value) -> Vec<u8> {
    build_tool(&spec).unwrap()
}
fn opts() -> CoreOptions {
    CoreOptions::new(10_000_000)
}

#[test]
fn handle_result_lands_in_memory() {
    let (t, h, _, _) = fixture();
    let m = tool(json!({"calls": [{"handle": h, "ptr": 0, "cap": 16}], "returns": "byte0"}));
    assert_eq!(run(&t, &m, "run", &opts()), Ok(7));
    let log = t.lock().unwrap();
    assert!(!log.log().entries.is_empty());
}

#[test]
fn probe_sees_count_and_verb() {
    let (t, _, _, _) = fixture();
    // 3 handles; first byte of handle 1's verb is 'f'
    assert_eq!(
        run(&t, &build_probe_tool(None), "run", &opts()),
        Ok(3 * 256 + b'f' as i64)
    );
}

#[test]
fn infinite_loop_hits_fuel() {
    let (t, _, _, _) = fixture();
    let m = tool(json!({"calls": [], "spin": true}));
    assert_eq!(
        run(&t, &m, "run", &CoreOptions::new(10_000)),
        Err("fuel_exhausted".into())
    );
}

#[test]
fn infinite_loop_hits_wall_clock() {
    let (t, _, _, _) = fixture();
    let m = tool(json!({"calls": [], "spin": true}));
    let mut o = CoreOptions::new(u64::MAX / 2);
    o.timeout_ms = 200;
    assert_eq!(run(&t, &m, "run", &o), Err("timeout".into()));
}

#[test]
fn fuel_is_required() {
    let (t, _, _, _) = fixture();
    let m = tool(json!({"calls": []}));
    assert_eq!(
        run(&t, &m, "run", &CoreOptions::new(0)),
        Err("bad_fuel".into())
    );
}

#[test]
fn memory_over_cap_or_undeclared_is_refused() {
    let (t, _, _, _) = fixture();
    for mem in [
        json!({"min": 1, "max": 257}),
        json!({"min": 1, "max": null}),
        json!({"min": 257, "max": 257}),
    ] {
        let m = tool(json!({"calls": [], "memory": mem}));
        assert_eq!(run(&t, &m, "run", &opts()), Err("memory_limits".into()));
    }
    let m = tool(json!({"calls": [], "memory": {"min": 1, "max": 4}}));
    let mut o = opts();
    o.max_memory_pages = 2;
    assert_eq!(run(&t, &m, "run", &o), Err("memory_limits".into()));
    assert_eq!(run(&t, &m, "run", &opts()), Ok(0));
}

#[test]
fn forbidden_imports_are_refused() {
    let (t, _, _, _) = fixture();
    for (module, name) in [
        ("wasi_snapshot_preview1", "fd_write"),
        ("env", "x"),
        ("pca:act", "other"),
    ] {
        let m = tool(json!({"calls": [], "extraImports": [{"module": module, "name": name}]}));
        assert_eq!(
            run(&t, &m, "run", &opts()),
            Err(format!("ambient_import:{module}.{name}"))
        );
    }
}

#[test]
fn malformed_size_and_entry() {
    let (t, _, _, _) = fixture();
    assert_eq!(run(&t, &[], "run", &opts()), Err("module_size".into()));
    assert_eq!(
        run(&t, &[1, 2, 3, 4, 5, 6, 7, 8, 9], "run", &opts()),
        Err("malformed_module".into())
    );
    let m = tool(json!({"calls": []}));
    assert_eq!(run(&t, &m, "nope", &opts()), Err("no_entry".into()));
    let mut o = opts();
    o.max_module_bytes = 10;
    assert_eq!(run(&t, &m, "run", &o), Err("module_size".into()));
}

#[test]
fn bad_output_window_spends_no_use() {
    let (t, h, _, _) = fixture();
    // ptr far past a 1-page memory: -4, and the single use is still there
    let m = tool(json!({"calls": [{"handle": h, "ptr": 70000, "cap": 16}]}));
    assert_eq!(run(&t, &m, "run", &opts()), Ok(-4));
    let ok = tool(json!({"calls": [{"handle": h, "ptr": 0, "cap": 16}]}));
    assert_eq!(run(&t, &ok, "run", &opts()), Ok(3));
}

#[test]
fn egress_inside_policy_passes_outside_is_refused() {
    let (t, _, ok, evil) = fixture();
    assert_eq!(
        run(
            &t,
            &tool(json!({"calls": [{"handle": ok, "ptr": 0, "cap": 16}]})),
            "run",
            &opts()
        ),
        Ok(1)
    );
    // out-of-policy host: the executor errors, the guest sees executor_error (-5)
    assert_eq!(
        run(
            &t,
            &tool(json!({"calls": [{"handle": evil, "ptr": 0, "cap": 16}]})),
            "run",
            &opts()
        ),
        Ok(-5)
    );
}

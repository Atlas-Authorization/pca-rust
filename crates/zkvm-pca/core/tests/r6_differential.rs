//! R6 (red-team round 6) guest-vs-TypeScript differential. Each case is a list of patches over a base logical document
//! (see `gen_ts_r6_differential.ts`); the TS verdict is `plan_inclusion && decide(...).admit` of the reference. Here the
//! same patches are applied, the chain and the PCActn are RE-MINTED (validly signed: the only possible causes are the
//! semantics under test), and the guest `decide` must give the same allow verdict on EVERY case.
//!
//! Golden: fixtures/ts_r6_cases.json (the field-typing matrix: every optional field x {absent, null, wrong types}).
//! `PCA_R6_CASES=<file.jsonl>` runs a large random corpus instead (the 100k box run).
use pca_zkvm_core::commit::plan_commitment;
use pca_zkvm_core::decide_from_str;
use serde_json::{json, Value};
use std::io::BufRead;

#[path = "support/chain_mint.rs"]
mod mint;

fn base() -> Value {
    serde_json::from_str(include_str!("../../fixtures/decide_input.sample.json")).unwrap()
}

fn logical(b: &Value) -> Value {
    json!({
        "root_caveats": b["grant"]["caveats"],
        "extra": [],
        "action": b["action"],
        "subject": b["subject"],
        "env": b["env"],
        "plan": b["plan"],
        "node_id": b["pcactn"]["plan"]["node_id"],
        "cond_digest": b["pcactn"]["plan"]["conditions_digest"],
        "tool_binding": b["tool_binding"],
    })
}

fn apply(l: &mut Value, patches: &[Value]) {
    for pt in patches {
        let p = pt["p"].as_array().unwrap();
        let mut cur = &mut *l;
        for seg in &p[..p.len() - 1] {
            cur = match seg {
                Value::String(s) => &mut cur[s.as_str()],
                Value::Number(n) => &mut cur[n.as_u64().unwrap() as usize],
                _ => unreachable!(),
            };
        }
        let last = &p[p.len() - 1];
        match (pt.get("v"), last) {
            (Some(v), Value::String(k)) => {
                cur.as_object_mut().unwrap().insert(k.clone(), v.clone());
            }
            (Some(v), Value::Number(n)) => {
                let a = cur.as_array_mut().unwrap();
                let i = n.as_u64().unwrap() as usize;
                if i == a.len() {
                    a.push(v.clone());
                } else {
                    a[i] = v.clone();
                }
            }
            (None, Value::String(k)) => {
                cur.as_object_mut().unwrap().remove(k);
            }
            _ => panic!("unsupported patch {pt}"),
        }
    }
}

/// Build the validly signed guest input for a logical document.
pub fn build(b: &Value, l: &Value) -> Value {
    let mut v = b.clone();
    let o = v.as_object_mut().unwrap();
    for k in ["subject", "env", "tool_binding", "node_id"] {
        o.remove(k);
    }
    for k in ["subject", "env"] {
        if let Some(x) = l.get(k) {
            v[k] = x.clone();
        }
    }
    v["action"] = l["action"].clone();
    v["pcactn"]["action"] = l["action"].clone();
    v["plan"] = l["plan"].clone();
    let pc = v["pcactn"]["plan"].as_object_mut().unwrap();
    pc.remove("node_id");
    pc.remove("conditions_digest");
    if let Some(n) = l.get("node_id") {
        v["pcactn"]["plan"]["node_id"] = n.clone();
        if n.is_string() {
            v["node_id"] = n.clone();
        }
    }
    if let Some(c) = l.get("cond_digest") {
        v["pcactn"]["plan"]["conditions_digest"] = c.clone();
    }
    if let Some(root) = l["plan"].as_array().and_then(|p| plan_commitment(p)) {
        v["pcactn"]["plan"]["root"] = json!(root);
    }
    v["pcactn"].as_object_mut().unwrap().remove("tool_binding");
    if let Some(t) = l.get("tool_binding") {
        v["tool_binding"] = t.clone();
        v["pcactn"]["tool_binding"] = t.clone();
    }
    let c0 = l["root_caveats"].clone();
    let mut c1 = c0.as_array().unwrap().clone();
    c1.extend(l["extra"].as_array().unwrap().iter().cloned());
    let g0 = mint::hop(&mint::key(1), &mint::key(2), &c0, None);
    let g1 = mint::hop(&mint::key(2), &mint::key(3), &json!(c1), Some(&g0));
    mint::with_chain(&v, vec![g0, g1], &mint::key(3))
}

struct Tally {
    n: usize,
    ts_allow: usize,
    bad: Vec<String>,
}

fn run_case(b: &Value, l0: &Value, c: &Value, t: &mut Tally) {
    let mut l = l0.clone();
    apply(&mut l, c["patches"].as_array().unwrap());
    let input = build(b, &l);
    let d = decide_from_str(&input.to_string());
    let want = c["ts"]["allow"].as_bool().unwrap();
    t.n += 1;
    if want {
        t.ts_allow += 1;
    }
    if (d.allow == 1) != want {
        t.bad.push(format!("{}: ts={} (incl={} release={} admit={}) guest={} chain_verified={}", c["name"], want, c["ts"]["incl"], c["ts"]["release"], c["ts"]["admit"], d.allow, d.chain_verified));
    }
}

#[test]
fn guest_equals_the_typescript_reference_on_every_case() {
    let b = base();
    let l0 = logical(&b);
    let mut t = Tally { n: 0, ts_allow: 0, bad: Vec::new() };
    match std::env::var("PCA_R6_CASES") {
        Ok(p) => {
            let f = std::io::BufReader::new(std::fs::File::open(&p).expect("PCA_R6_CASES readable"));
            for line in f.lines() {
                let line = line.unwrap();
                if line.is_empty() {
                    continue;
                }
                let c: Value = serde_json::from_str(&line).unwrap();
                run_case(&b, &l0, &c, &mut t);
            }
        }
        Err(_) => {
            let g: Value = serde_json::from_str(include_str!("../../fixtures/ts_r6_cases.json")).unwrap();
            for c in g["cases"].as_array().unwrap() {
                run_case(&b, &l0, c, &mut t);
            }
            assert_eq!(t.n, g["count"].as_u64().unwrap() as usize);
            assert!(t.n >= 1000, "the matrix must not be silently truncated ({})", t.n);
        }
    }
    eprintln!("r6 differential: cases={} ts_allow={} divergences={}", t.n, t.ts_allow, t.bad.len());
    assert!(t.ts_allow > 0 && t.ts_allow < t.n, "corpus must contain both verdicts");
    let show: Vec<&String> = t.bad.iter().take(60).collect();
    assert!(t.bad.is_empty(), "{} divergences, first:\n{}", t.bad.len(), show.iter().map(|s| s.as_str()).collect::<Vec<_>>().join("\n"));
}

#[test]
fn the_control_case_is_allowed_by_both() {
    let b = base();
    let input = build(&b, &logical(&b));
    assert_eq!(decide_from_str(&input.to_string()).allow, 1);
}

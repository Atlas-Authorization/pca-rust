//! Wallet-side layered intent lattice and quorum-signed layer approvals: ceiling admitters, the lattice view of a task learner, owner
//! risk, layer cell sets and k-of-n approvals of a shared-layer widening.
use super::learner::*;
use super::metrics::Acceptability;
use super::multi::*;
use super::omega::*;
use super::policy::*;
use super::*;
use crate::agent::KeyPair;
use serde_json::{Map, Value};

pub const LAYER_CEILINGS: [&str; 3] = ["org", "site", "std"];
pub const LAYER_APPROVAL_DOMAIN: &str = "atlas-pca/intent-layer-approval/v1\0";

/// The compiled ceiling layers (`None` = no ceiling).
pub struct Ceilings {
    admitters: Vec<(&'static str, Option<Admitter>)>,
}

/// Compile ceiling layers into admitters. ABSENT = no ceiling; a ceiling present as null or not an object is malformed.
pub fn ceiling_admitters(layers: &Value) -> R<Ceilings> {
    let mut out = vec![];
    for k in LAYER_CEILINGS {
        match get(layers, k) {
            None => out.push((k, None)),
            Some(l) if l.is_object() => out.push((k, Some(admitter(l)?))),
            Some(_) => return Err(format!("ceilingAdmitters: the {k} ceiling is malformed (null or not an object)")),
        }
    }
    Ok(Ceilings { admitters: out })
}

/// The first ceiling that excludes the outcome (`None` when every ceiling admits it).
pub fn ceiling_of(c: &Ceilings, vs: &VerbSpace, o: &Value) -> R<Option<&'static str>> {
    for (k, a) in &c.admitters {
        if let Some(a) = a {
            if !a.admits(vs, o)? {
                return Ok(Some(*k));
            }
        }
    }
    Ok(None)
}

/// The lattice of a task learner under ceiling layers.
pub fn lattice_view(task: &mut IntentLearner, ceilings: &Ceilings) -> R<Value> {
    let (mut effective, mut uncertain, mut ceiling) = (vec![], vec![], vec![]);
    let tau = task.tau;
    for c in task.cells() {
        let vs = task.omega.verb(&c.verb).ok_or("latticeView: unknown verb")?.clone();
        let layer = ceiling_of(ceilings, &vs, &cell_rep(&vs, &c.cell)?)?;
        let item = |extra: Option<&str>| {
            let mut m = Map::new();
            m.insert("verb".into(), jstr(&c.verb));
            m.insert("cell".into(), jarr_usize(&c.cell));
            if let Some(l) = extra {
                m.insert("layer".into(), jstr(l));
            }
            Value::Object(m)
        };
        if let Some(l) = layer {
            ceiling.push(item(Some(l)));
            continue;
        }
        if c.vetoed {
            continue;
        }
        if c.in_grant {
            effective.push(item(None));
        } else if c.p > 1e-12 && c.p < tau - 1e-12 {
            uncertain.push(item(None));
        }
    }
    Ok(obj(vec![("effective", Value::Array(effective)), ("uncertain", Value::Array(uncertain)), ("ceiling", Value::Array(ceiling))]))
}

pub fn decide_outcome_layers(task: &mut IntentLearner, ceilings: &Ceilings, o: &Value) -> R<Value> {
    let Some(vs) = get_str(o, "verb").and_then(|v| task.omega.verb(v)).cloned() else { return Ok(obj(vec![("decision", jstr("intent_denied"))])) };
    if let Some(l) = ceiling_of(ceilings, &vs, o)? {
        return Ok(obj(vec![("decision", jstr("ceiling")), ("layer", jstr(l))]));
    }
    if task.is_vetoed(o) || task.acceptance(o) <= 1e-12 {
        return Ok(obj(vec![("decision", jstr("intent_denied"))]));
    }
    if task.admits_outcome(o) {
        return Ok(obj(vec![("decision", jstr("admit")), ("by", jn(0.0))]));
    }
    Ok(obj(vec![("decision", jstr("intent_required"))]))
}

fn key_of(c: &Value) -> String {
    let cell =
        get(c, "cell").and_then(Value::as_array).map(|a| a.iter().map(crate::intent_v2::js_value_string).collect::<Vec<_>>().join(",")).unwrap_or_default();
    format!("{}|{}", get(c, "verb").map(crate::intent_v2::js_value_string).unwrap_or_else(|| "undefined".into()), cell)
}

/// A question may only be about a cell of U_k (inside every ceiling); refused otherwise.
pub fn assert_askable(view: &Value, c: &Value) -> R<()> {
    let key = key_of(c);
    let ok = get(view, "uncertain").and_then(Value::as_array).is_some_and(|u| u.iter().any(|x| key_of(x) == key));
    if ok {
        Ok(())
    } else {
        Err(format!("layers: cell {key} is not an uncertain cell inside every ceiling (never a question)"))
    }
}

fn cell_idx(v: Option<&Value>) -> R<Vec<usize>> {
    v.and_then(Value::as_array)
        .ok_or("cell must be an array")?
        .iter()
        .map(|x| as_usize(x).ok_or_else(|| "cell index must be a non-negative integer".to_string()))
        .collect()
}

/// Layer owner's own risk measure of a set of cells: sum of mu(c) (1 - a(c)) E[h | c].
pub fn owner_risk(omega: &Omega, cells: &Value, acc: &Acceptability) -> R<f64> {
    let mut r = 0.0;
    for c in cells.as_array().ok_or("ownerRisk: cells must be an array")? {
        let Some(vs) = get_str(c, "verb").and_then(|v| omega.verb(v)) else { continue };
        let idx = cell_idx(get(c, "cell"))?;
        let (mass, harm) = cell_stats(vs, &idx)?;
        r += mass * (1.0 - acc.call(vs, &cell_rep(vs, &idx)?)?) * harm;
    }
    Ok(r)
}

/// Every cell of the outcome space an admitter admits.
pub fn layer_cells(omega: &Omega, a: &Admitter) -> R<Value> {
    let mut out = vec![];
    for vs in &omega.verbs {
        for f in 0..verb_cell_count(vs) {
            let cell = decode_cell(vs, f);
            if a.admits(vs, &cell_rep(vs, &cell)?)? {
                out.push(obj(vec![("verb", jstr(&vs.verb)), ("cell", jarr_usize(&cell))]));
            }
        }
    }
    Ok(Value::Array(out))
}

pub fn cell_key_of(omega: &Omega, c: &Value) -> R<String> {
    let verb = get_str(c, "verb").ok_or("cellKeyOf: verb")?;
    let idx = cell_idx(get(c, "cell"))?;
    Ok(match omega.verb(verb) {
        Some(vs) => {
            if idx.len() < vs.dims.len() {
                return Err("cellKeyOf: cell index missing".into());
            }
            format!("{}|{}", verb, encode_cell(vs, &idx))
        }
        None => format!("{}|{}", verb, idx.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",")),
    })
}

/// The org layer as a learned map: see `mapkit::org_layer_from_maps`.
pub use super::mapkit::org_layer_from_maps;

// ---- quorum-signed layer approvals ------------------------------------------------------------------------------------------------

const STATEMENT_KEYS: [&str; 5] = ["layer", "session", "seq", "map_digest", "prev"];

/// `_statementOf`: the five statement members (`None` = absent) under the fixed `v` and `kind`.
fn statement_of(a: &Value) -> Vec<(&'static str, Option<Value>)> {
    STATEMENT_KEYS.iter().map(|k| (*k, get(a, k).cloned())).collect()
}

fn approval_message(st: &[(&'static str, Option<Value>)]) -> R<Vec<u8>> {
    let mut m = Map::new();
    m.insert("v".into(), jn(1.0));
    m.insert("kind".into(), jstr("pca-intent-layer-approval"));
    for (k, v) in st {
        m.insert((*k).to_string(), v.clone().ok_or("approval statement member is undefined")?);
    }
    let mut msg = LAYER_APPROVAL_DOMAIN.as_bytes().to_vec();
    msg.extend(crate::canonicalize_strict(&Value::Object(m))?.into_bytes());
    Ok(msg)
}

/// Sign an approval of a shared-layer widening (an Ed25519 seed, b64u).
pub fn sign_layer_approval(s: &Value, seed_b64u: &str) -> R<Value> {
    let st = statement_of(s);
    let key = KeyPair::from_seed_b64u(seed_b64u)?;
    let msg = approval_message(&st)?;
    let mut m = Map::new();
    m.insert("v".into(), jn(1.0));
    m.insert("kind".into(), jstr("pca-intent-layer-approval"));
    for (k, v) in &st {
        m.insert((*k).to_string(), v.clone().unwrap_or(Value::Null));
    }
    m.insert("signer".into(), jstr(&key.public));
    m.insert("sig".into(), jstr(&crate::b64_encode(&key.sign(&msg))));
    Ok(Value::Object(m))
}

/// `===` over JSON values: same JSON type and value; containers never equal.
fn strict_eq(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(Value::Null), Some(Value::Null)) => true,
        (Some(Value::Bool(x)), Some(Value::Bool(y))) => x == y,
        (Some(Value::Number(x)), Some(Value::Number(y))) => x.as_f64() == y.as_f64(),
        (Some(Value::String(x)), Some(Value::String(y))) => x == y,
        _ => false,
    }
}

fn refusal(reason: &str) -> Value {
    obj(vec![
        ("ok", Value::Bool(false)),
        ("signers", Value::Array(vec![])),
        ("ignored", Value::Array(vec![obj(vec![("index", jn(-1.0)), ("reason", jstr(reason))])])),
    ])
}

/// An approval counts iff its signer is a member, it is that member's first, its statement equals `expected` field by field and its
/// signature verifies; the rule is the multi-principal one over member keys.
pub fn verify_quorum_approvals(approvals: &Value, members: &Value, rule: &Value, expected: &Value) -> Value {
    let (Some(approvals), Some(members_a)) = (approvals.as_array(), members.as_array()) else {
        return refusal("approvals and members must be arrays and expected an object");
    };
    if !(expected.is_object() || expected.is_array()) {
        return refusal("approvals and members must be arrays and expected an object");
    }
    let mut members: Vec<String> = vec![];
    for m in members_a {
        match m.as_str() {
            Some(s) => members.push(s.to_string()),
            None => return refusal("members must be distinct 32-byte keys"),
        }
    }
    let distinct = members.iter().enumerate().all(|(i, m)| !members[..i].contains(m));
    if !distinct || members.iter().any(|m| crate::decode_b64u_strict(m, Some(32)).is_none()) {
        return refusal("members must be distinct 32-byte keys");
    }
    let n = match normalize_rule(rule, &members) {
        Ok(n) => n,
        Err(e) => return refusal(&e),
    };
    let want = statement_of(expected);
    let mut ignored: Vec<Value> = vec![];
    let mut counted: Vec<String> = vec![];
    let ig = |i: usize, reason: &str| obj(vec![("index", jn(i as f64)), ("reason", jstr(reason))]);
    for (i, a) in approvals.iter().enumerate() {
        if !(a.is_object() || a.is_array()) {
            ignored.push(ig(i, "not an object"));
            continue;
        }
        let signer = get(a, "signer").and_then(Value::as_str).filter(|s| members.iter().any(|m| m.as_str() == *s));
        let Some(signer) = signer else {
            ignored.push(ig(i, "signer is not a member"));
            continue;
        };
        if counted.iter().any(|c| c == signer) {
            ignored.push(ig(i, "second approval from the same member"));
            continue;
        }
        let st = statement_of(a);
        let same = st.iter().zip(want.iter()).all(|(x, y)| strict_eq(x.1.as_ref(), y.1.as_ref()))
            && strict_eq(get(a, "v"), Some(&jn(1.0)))
            && strict_eq(get(a, "kind"), Some(&jstr("pca-intent-layer-approval")));
        if !same {
            ignored.push(ig(i, "approval is for another (layer, session, seq, map_digest, prev)"));
            continue;
        }
        let ok = match (approval_message(&st), get(a, "sig").and_then(Value::as_str)) {
            (Ok(msg), Some(sig)) => crate::verify_b64u(signer, &msg, sig),
            _ => false,
        };
        if !ok {
            ignored.push(ig(i, "bad signature"));
            continue;
        }
        counted.push(signer.to_string());
    }
    let signers: Vec<Value> = members.iter().filter(|m| counted.contains(m)).map(|m| jstr(m)).collect();
    let ins: Vec<bool> = members.iter().map(|m| counted.contains(m)).collect();
    let ok = rule_admits(&n, &ins).unwrap_or(false);
    obj(vec![("ok", Value::Bool(ok)), ("signers", Value::Array(signers)), ("ignored", Value::Array(ignored))])
}

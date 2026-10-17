//! Intent Layer v2 wire batch W-B: world facts, relational dimensions and offer sets (rule 16, `oracle-facts.ts`,
//! `offer-set.ts`), per-parameter provenance with label receipts and flow rules (rule 17, `param-provenance.ts`,
//! `label-receipts.ts`), classifier verdicts (rule 18, `intent-classifier.ts`) and their composition (`intent-env.ts`
//! `decideIntentWB`). Every entry point takes the reference's input object as JSON and is total.

use serde_json::{Map, Value};

use super::intent_strict::*;
use super::MAX_SAFE;

const FACT_DOMAIN: &str = "atlas-pca/fact/v1\0";
const FACT_REF_DOMAIN: &str = "atlas-pca/fact-ref/v1";
const OFFER_SET_DOMAIN: &str = "atlas-pca/offer-set/v1\0";
const OFFER_SET_REF_DOMAIN: &str = "atlas-pca/offer-set-ref/v1";
const LABELS_DOMAIN: &str = "atlas-pca/labels/v1\0";
const LABELS_REF_DOMAIN: &str = "atlas-pca/labels-ref/v1";
const CLASSIFIER_DOMAIN: &str = "atlas-pca/intent-classifier/v1\0";
const CLASSIFIER_REF_DOMAIN: &str = "atlas-pca/intent-classifier-ref/v1";
const MAX_COMMITTED_FACTS: usize = 16;
const MAX_WORLDS: usize = 16;
const MAX_RELATIONAL: usize = 16;
const DEFAULT_WORLD_SKEW_MS: f64 = 60_000.0;
const MAX_OFFERS: usize = 256;
const MAX_OFFER_ATTRS: usize = 32;
const MAX_QUERY_KEYS: usize = 32;
const MAX_PROV_PATHS: usize = 32;
const MAX_PROV_REFS: usize = 8;
const MAX_COMMITTED_LABELS: usize = 16;
const MAX_LABEL_FIELDS: usize = 64;
const MAX_COMMITTED_CLASSES: usize = 8;
const MAX_CLASSIFIER_LABELS: usize = 32;
const LABEL_REF_PREFIX: &str = "pca-labels:";
const TAINT_LEVELS: [&str; 5] = ["trusted", "first_party", "tool", "web", "agent"];

/// `action.params`: `action` must be an object; its `params` absent = `{}`, else it must be an object.
fn action_params(action: Option<&Value>) -> Result<Value, String> {
    let a = match action {
        Some(a @ Value::Object(_)) => a,
        _ => return Err("action must be an object".into()),
    };
    match a.get("params") {
        None => Ok(Value::Object(Map::new())),
        Some(p @ Value::Object(_)) => Ok(p.clone()),
        Some(_) => Err("action.params must be an object".into()),
    }
}

/// The artifacts delivered alongside the PCActn (`facts`, `labels`, `verdicts`): absent = none, an array = its
/// entries; anything else (`null` included) fails the check closed.
fn delivered(v: Option<&Value>) -> Result<Vec<Value>, String> {
    match v {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => Ok(a.clone()),
        Some(_) => Err("delivered artifacts must be an array".into()),
    }
}

/// A non-empty JSON array (the strict activity typing of rules 16-18).
fn non_empty_array(v: Option<&Value>) -> bool {
    v.and_then(Value::as_array).is_some_and(|a| !a.is_empty())
}

// ---- rule 16: facts, relational dimensions, offer sets -----------------------------------------------------------

/// The rule-16 decision: `ok`, the world map and the single-source worlds (policy order), or the failure reason.
#[derive(Debug, Clone, PartialEq)]
pub struct IntentWorldDecision {
    pub ok: bool,
    pub world: Map<String, Value>,
    pub single_source: Vec<String>,
    pub reason: String,
}

fn validate_fact_wire(f: &Value) -> bool {
    let f = match f.as_object() {
        Some(f) => f,
        None => return false,
    };
    closed_members(f, &["v", "kind", "name", "subject", "value", "t_obs", "oracle", "sig"], &SUITE_MEMBERS)
        && same(f.get("v"), Some(&Value::from(1)))
        && s(f.get("kind")) == Some("pca-fact")
        && is_name(f.get("name"))
        && bstr(f.get("subject"), 256)
        && (sint(f.get("value")).is_some() || bstr(f.get("value"), 256))
        && nonneg(f.get("t_obs")).is_some()
        && bstr(f.get("oracle"), 64)
        && f.get("sig").is_some_and(Value::is_string)
}

/// `validateOfferPolicy(p)`. `None` = well-formed.
fn validate_offer_policy(p: &Value) -> Option<String> {
    let p = match p.as_object() {
        Some(p) => p,
        None => return Some("offers policy must be an object".into()),
    };
    if !closed_members(p, &["name", "site_keys", "max_age_ms", "offer_param", "filter"], &[]) {
        return Some("offers policy is exactly {name, site_keys, max_age_ms, offer_param, filter}".into());
    }
    if !p.get("name").is_some_and(Value::is_string) {
        return Some("offers policy needs a name".into());
    }
    let keys = match p.get("site_keys").and_then(Value::as_array) {
        Some(k) if !k.is_empty() => k,
        _ => return Some("offers policy needs at least one pinned site key".into()),
    };
    let mut kids = std::collections::BTreeSet::new();
    for k in keys {
        let ok = k.as_object().is_some_and(|k| closed_members(k, &["kid", "pk"], &["pq_pk"]) && bstr(k.get("kid"), 64) && b32(k.get("pk")) && pin_pq_ok(k.get("pq_pk"))) && kids.insert(s(k.get("kid")).unwrap_or("").to_string());
        if !ok {
            return Some("offers policy: every site key needs a unique kid, a 32-byte pk and an optional string pq_pk".into());
        }
    }
    if nonneg(p.get("max_age_ms")).is_none() {
        return Some("offers policy: max_age_ms must be a non-negative safe integer".into());
    }
    if !s(p.get("offer_param")).is_some_and(|x| x.starts_with("action.params.")) {
        return Some("offers policy: offer_param must be an action.params.* path".into());
    }
    let f = obj(p.get("filter")).filter(|f| closed_members(f, &["query", "offer"], &[]));
    let (q, o) = match f.map(|f| (obj(f.get("query")), obj(f.get("offer")))) {
        Some((Some(q), Some(o))) => (q, o),
        _ => return Some("offers policy: filter must be {query: {}, offer: {}}".into()),
    };
    if !q.values().chain(o.values()).all(|v| is_scalar(Some(v))) {
        return Some("offers policy: filter values must be scalars".into());
    }
    None
}

/// `validateWorldPolicy(p)`. `None` = well-formed.
fn validate_world_policy(p: &Value) -> Option<String> {
    let p = match p.as_object() {
        Some(p) => p,
        None => return Some("world policy must be an object".into()),
    };
    if !closed_members(p, &[], &["skew_ms", "worlds", "relational", "offers"]) {
        return Some("world policy: unknown member (it is {skew_ms?, worlds?, relational?, offers?})".into());
    }
    if p.get("skew_ms").is_some() && nonneg(p.get("skew_ms")).is_none() {
        return Some("skew_ms must be a non-negative safe integer".into());
    }
    let mut names: Vec<String> = Vec::new();
    let claim = |n: Option<&Value>, names: &mut Vec<String>| -> Option<String> {
        if !is_name(n) {
            return Some(format!("dimension name '{}' must match ^[a-z][a-z0-9_]{{0,63}}$", n.map(Value::to_string).unwrap_or_default()));
        }
        let n = s(n).unwrap_or("").to_string();
        if names.contains(&n) {
            return Some(format!("duplicate dimension name '{n}'"));
        }
        names.push(n);
        None
    };
    let worlds = match p.get("worlds") {
        None => Vec::new(),
        Some(Value::Array(w)) if w.len() <= MAX_WORLDS => w.clone(),
        _ => return Some(format!("worlds must be a list of at most {MAX_WORLDS}")),
    };
    for w in &worlds {
        let w = match w.as_object() {
            Some(w) => w,
            None => return Some("world entry must be an object".into()),
        };
        if !closed_members(w, &["name", "subject_path", "oracles", "freshness_ms", "min_oracles", "max_faulty"], &[]) {
            return Some("world entry is exactly {name, subject_path, oracles, freshness_ms, min_oracles, max_faulty}".into());
        }
        if let Some(e) = claim(w.get("name"), &mut names) {
            return Some(e);
        }
        let n = s(w.get("name")).unwrap_or("");
        if !s(w.get("subject_path")).is_some_and(|x| x.starts_with("action.")) {
            return Some(format!("world '{n}': subject_path must be rooted at action."));
        }
        if nonneg(w.get("freshness_ms")).is_none() {
            return Some(format!("world '{n}': freshness_ms must be a non-negative safe integer"));
        }
        let mf = match nonneg(w.get("max_faulty")) {
            Some(m) => m,
            None => return Some(format!("world '{n}': max_faulty must be a non-negative safe integer")),
        };
        let mo = match sint(w.get("min_oracles")) {
            Some(m) if (m as f64) >= 2.0 * mf as f64 + 1.0 => m,
            _ => return Some(format!("world '{n}': min_oracles must be a safe integer >= 2*max_faulty+1")),
        };
        let oracles = match w.get("oracles").and_then(Value::as_array) {
            Some(o) if (o.len() as i64) >= mo => o,
            _ => return Some(format!("world '{n}': fewer pinned oracles than min_oracles")),
        };
        let mut kids = std::collections::BTreeSet::new();
        for o in oracles {
            let ok = o.as_object().is_some_and(|o| closed_members(o, &["kid", "pk"], &["pq_pk"]) && bstr(o.get("kid"), 64) && b32(o.get("pk")) && pin_pq_ok(o.get("pq_pk"))) && kids.insert(s(o.get("kid")).unwrap_or("").to_string());
            if !ok {
                return Some(format!("world '{n}': every oracle needs a unique kid, a 32-byte pk and an optional string pq_pk"));
            }
        }
    }
    let rel = match p.get("relational") {
        None => Vec::new(),
        Some(Value::Array(r)) if r.len() <= MAX_RELATIONAL => r.clone(),
        _ => return Some(format!("relational must be a list of at most {MAX_RELATIONAL}")),
    };
    for r in &rel {
        let r = match r.as_object() {
            Some(r) => r,
            None => return Some("relational entry must be an object".into()),
        };
        if !closed_members(r, &["name", "fn", "a", "b"], &[]) {
            return Some("relational entry is exactly {name, fn, a, b}".into());
        }
        if let Some(e) = claim(r.get("name"), &mut names) {
            return Some(e);
        }
        let n = s(r.get("name")).unwrap_or("");
        if !matches!(s(r.get("fn")), Some("sub" | "ratio_ppm")) {
            return Some(format!("relational '{n}': fn must be \"sub\" or \"ratio_ppm\""));
        }
        for op in [r.get("a"), r.get("b")] {
            let ok = is_param_path(op)
                || s(op).and_then(|x| x.strip_prefix("env.world.")).is_some_and(|w| names.iter().any(|x| x == w) && w != n);
            if !ok {
                return Some(format!("relational '{n}': operand must be an action.params path or an earlier env.world dimension"));
            }
        }
    }
    if let Some(offers) = p.get("offers") {
        if let Some(e) = validate_offer_policy(offers) {
            return Some(e);
        }
        if let Some(e) = claim(offers.get("name"), &mut names) {
            return Some(e);
        }
    }
    None
}

/// `intentWorldActive({committed, policy})`.
pub(crate) fn intent_world_active(committed_facts: Option<&Value>, committed_offer: Option<&Value>, policy: Option<&Value>) -> bool {
    let pget = |k: &str| policy.and_then(Value::as_object).and_then(|p| p.get(k));
    non_empty_array(committed_facts)
        || committed_offer.is_some_and(Value::is_string)
        || non_empty_array(pget("worlds"))
        || non_empty_array(pget("relational"))
        || pget("offers").is_some_and(Value::is_object)
}

fn subject_of<'a>(action: &'a Value, params: &'a Value, path: &str) -> Option<&'a str> {
    if path == "action.resource" {
        return s(action.get("resource"));
    }
    if path == "action.verb" {
        return s(action.get("verb"));
    }
    resolve_param_path(params, path).and_then(Value::as_str)
}

/// `ratioPpm(a, b)` = floor(a * 10^6 / b) exactly, `None` when b <= 0, a < 0 or the result is not a safe integer.
pub(crate) fn ratio_ppm(a: i64, b: i64) -> Option<i64> {
    if b <= 0 || a < 0 {
        return None;
    }
    let q = (i128::from(a) * 1_000_000) / i128::from(b);
    (q <= i128::from(MAX_SAFE)).then_some(q as i64)
}

/// The rule-16 decision on the reference's `IntentWorldInput` (`decideIntentWorld`). Never panics.
pub fn decide_intent_world(input: &Value) -> IntentWorldDecision {
    match world_inner(input) {
        Ok(d) => d,
        Err(e) => world_fail(format!("evaluation error (fail closed): {e}")),
    }
}

fn world_fail(reason: impl Into<String>) -> IntentWorldDecision {
    IntentWorldDecision { ok: false, world: Map::new(), single_source: Vec::new(), reason: format!("facts: {}", reason.into()) }
}

fn world_inner(input: &Value) -> Result<IntentWorldDecision, String> {
    let empty_obj = Value::Object(Map::new());
    let policy = input.get("policy").unwrap_or(&empty_obj);
    if let Some(e) = validate_world_policy(policy) {
        return Ok(world_fail(format!("policy misconfigured (fail closed): {e}")));
    }
    let skew = num(policy.get("skew_ms")).unwrap_or(DEFAULT_WORLD_SKEW_MS);
    // ABSENT optional members mean empty / default; PRESENT ones of the wrong JSON type (null included) fail closed
    let action = match input.get("action") {
        Some(a @ Value::Object(_)) => a,
        _ => return Ok(world_fail("action must be an object")),
    };
    let empty_params = Value::Object(Map::new());
    let params = match action.get("params") {
        None => &empty_params,
        Some(p @ Value::Object(_)) => p,
        Some(_) => return Ok(world_fail("action.params must be an object")),
    };
    let committed = match input.get("committed") {
        None => None,
        Some(Value::Object(c)) => Some(c),
        Some(_) => return Ok(world_fail("committed must be an object")),
    };
    let cget = |k: &str| -> Option<&Value> { committed.and_then(|c| c.get(k)) };
    let cfacts = match cget("facts") {
        None => Vec::new(),
        Some(Value::Array(a)) if a.len() <= MAX_COMMITTED_FACTS => a.clone(),
        _ => return Ok(world_fail(format!("committed facts must be a list of at most {MAX_COMMITTED_FACTS} digests"))),
    };
    let mut seen = std::collections::BTreeSet::new();
    for d in &cfacts {
        if !b32(Some(d)) {
            return Ok(world_fail("a committed fact digest is not canonical base64url (32 bytes)"));
        }
        if !seen.insert(s(Some(d)).unwrap_or("").to_string()) {
            return Ok(world_fail("duplicate committed fact digest"));
        }
    }
    let committed_offer = cget("offer_set");
    if committed_offer.is_some() && !b32(committed_offer) {
        return Ok(world_fail("the committed offer_set is not canonical base64url (32 bytes)"));
    }
    let supplied = match input.get("facts") {
        None => Vec::new(),
        Some(Value::Array(a)) => a.clone(),
        Some(_) => return Ok(world_fail("facts must be an array")),
    };
    if input.get("offer_set").is_some_and(|o| !o.is_object()) {
        return Ok(world_fail("offer_set must be an object"));
    }
    let mut by_ref: Map<String, Value> = Map::new();
    for f in supplied {
        if !validate_fact_wire(&f) {
            continue;
        }
        if let Some(r) = artifact_ref(FACT_REF_DOMAIN, "f", &f) {
            by_ref.insert(r, f);
        }
    }
    let worlds: Vec<Value> = policy.get("worlds").and_then(Value::as_array).cloned().unwrap_or_default();
    let mut accepted: Vec<Value> = Vec::new();
    let mut pairs = std::collections::BTreeSet::new();
    for d in &cfacts {
        let f = match by_ref.get(s(Some(d)).unwrap_or("")) {
            Some(f) => f.clone(),
            None => return Ok(world_fail("a committed fact was not supplied (or is malformed)")),
        };
        let fo = f.as_object().ok_or("fact is not an object")?;
        if let Some(e) = artifact_suite_error(fo) {
            return Ok(world_fail(format!("fact signature suite: {e}")));
        }
        let fname = s(f.get("name")).unwrap_or("");
        let w = match worlds.iter().find(|w| s(w.get("name")) == Some(fname)) {
            Some(w) => w,
            None => return Ok(world_fail(format!("fact for undeclared world '{fname}'"))),
        };
        let oracle = s(f.get("oracle")).unwrap_or("");
        let pin = w.get("oracles").and_then(Value::as_array).and_then(|os| os.iter().find(|o| s(o.get("kid")) == Some(oracle)));
        let pin = match pin {
            Some(p) => p,
            None => return Ok(world_fail(format!("oracle '{oracle}' is not pinned for world '{fname}'"))),
        };
        if !verify_artifact_sig(FACT_DOMAIN, fo, s(pin.get("pk")).unwrap_or(""), pin.get("pq_pk")) {
            return Ok(world_fail(format!("bad oracle signature on a '{fname}' fact")));
        }
        let subject = subject_of(action, params, s(w.get("subject_path")).unwrap_or(""));
        if subject.is_none() || s(f.get("subject")) != subject {
            return Ok(world_fail(format!("a '{fname}' fact names another subject")));
        }
        if !pairs.insert((fname.to_string(), oracle.to_string())) {
            return Ok(world_fail(format!("two facts from oracle '{oracle}' for world '{fname}'")));
        }
        accepted.push(f);
    }
    // CLOCK: `now` must be a safe integer; any other value makes every fact (and every offer set) stale
    let now = sint(input.get("now"));
    let mut world = Map::new();
    let mut single_source = Vec::new();
    for w in &worlds {
        let wname = s(w.get("name")).unwrap_or("");
        let fresh_ms = num(w.get("freshness_ms")).unwrap_or(f64::NAN);
        let min_oracles = num(w.get("min_oracles")).unwrap_or(f64::NAN);
        let fresh: Vec<&Value> = match now {
            None => Vec::new(),
            Some(now) => {
                let now = now as f64;
                accepted
                    .iter()
                    .filter(|f| {
                        let t = num(f.get("t_obs")).unwrap_or(f64::NAN);
                        s(f.get("name")) == Some(wname) && t <= now + skew && now - t <= fresh_ms
                    })
                    .collect()
            }
        };
        if (fresh.len() as f64) < min_oracles {
            return Ok(world_fail(format!("world '{wname}' has {} fresh fact(s), needs {min_oracles}", fresh.len())));
        }
        let nums: Vec<i64> = fresh.iter().filter_map(|f| sint(f.get("value"))).collect();
        let n_numbers = fresh.iter().filter(|f| f.get("value").is_some_and(Value::is_number)).count();
        if n_numbers == fresh.len() {
            let mut sorted = nums.clone();
            sorted.sort_unstable();
            let m = sorted.get((sorted.len().max(1) - 1) / 2).copied().ok_or("lowerMedian: empty")?;
            world.insert(wname.to_string(), Value::from(m));
        } else if n_numbers == 0 {
            let v = fresh[0].get("value").cloned().unwrap_or(Value::Null);
            if fresh.iter().any(|f| !same(f.get("value"), Some(&v))) {
                return Ok(world_fail(format!("world '{wname}': string facts disagree")));
            }
            world.insert(wname.to_string(), v);
        } else {
            return Ok(world_fail(format!("world '{wname}': facts mix integer and string values")));
        }
        if min_oracles == 1.0 {
            single_source.push(wname.to_string());
        }
    }
    let rels: Vec<Value> = policy.get("relational").and_then(Value::as_array).cloned().unwrap_or_default();
    let operand = |path: &str, world: &Map<String, Value>| -> Option<i64> {
        match path.strip_prefix("env.world.") {
            Some(n) => sint(world.get(n)),
            None => sint(resolve_param_path(params, path)),
        }
    };
    for r in rels {
        let rname = s(r.get("name")).unwrap_or("").to_string();
        let a = operand(s(r.get("a")).unwrap_or(""), &world);
        let b = operand(s(r.get("b")).unwrap_or(""), &world);
        let (a, b) = match (a, b) {
            (Some(a), Some(b)) => (a, b),
            _ => return Ok(world_fail(format!("relational '{rname}': an operand is missing or not a safe integer"))),
        };
        let v = if s(r.get("fn")) == Some("sub") { Some(a - b).filter(|x| x.abs() <= MAX_SAFE) } else { ratio_ppm(a, b) };
        match v {
            Some(v) => {
                world.insert(rname, Value::from(v));
            }
            None => return Ok(world_fail(format!("relational '{rname}': result undefined or outside the safe integer range"))),
        }
    }
    if let Some(offers) = policy.get("offers") {
        let session = input.get("session");
        let aud = input.get("aud");
        match decide_offer_set(offers, committed_offer, input.get("offer_set"), params, aud, session, now, skew) {
            Ok(excess) => {
                world.insert(s(offers.get("name")).unwrap_or("").to_string(), Value::from(excess));
            }
            Err(e) => return Ok(world_fail(e)),
        }
    }
    Ok(IntentWorldDecision { ok: true, world, single_source, reason: String::new() })
}

fn validate_offer_set_wire(o: &Value) -> Option<String> {
    let o = match o.as_object() {
        Some(o) => o,
        None => return Some("offer set must be an object".into()),
    };
    const F: [&str; 11] = ["v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig"];
    if !closed_members(o, &F, &SUITE_MEMBERS) {
        return Some("offer set members".into());
    }
    if !same(o.get("v"), Some(&Value::from(1))) || s(o.get("kind")) != Some("pca-offer-set") {
        return Some("offer set must be {v: 1, kind: \"pca-offer-set\"}".into());
    }
    if !bstr(o.get("site"), 256) {
        return Some("'offer_set.site' must be a non-empty string (<= 256 bytes)".into());
    }
    if !b32(o.get("session")) {
        return Some("'offer_set.session' must be canonical base64url (32 bytes)".into());
    }
    let q = match obj(o.get("query")) {
        Some(q) if q.len() <= MAX_QUERY_KEYS => q,
        _ => return Some(format!("'offer_set.query' must be an object with <= {MAX_QUERY_KEYS} keys")),
    };
    for (k, v) in q {
        if k.is_empty() || k.len() > 64 || !is_scalar(Some(v)) {
            return Some(format!("'offer_set.query.{k}' must be a scalar"));
        }
    }
    if s(o.get("rank")) != Some("price_asc") {
        return Some("'offer_set.rank' must be \"price_asc\"".into());
    }
    if !o.get("complete").is_some_and(Value::is_boolean) {
        return Some("'offer_set.complete' must be a boolean".into());
    }
    let offers = match o.get("offers").and_then(Value::as_array) {
        Some(a) if !a.is_empty() && a.len() <= MAX_OFFERS => a,
        _ => return Some(format!("'offer_set.offers' must hold 1..{MAX_OFFERS} offers")),
    };
    let mut ids = std::collections::BTreeSet::new();
    for (i, of) in offers.iter().enumerate() {
        let of = match of.as_object() {
            Some(x) => x,
            None => return Some(format!("offer {i} must be an object")),
        };
        if !bstr(of.get("offer_id"), 128) {
            return Some(format!("offer {i}: 'offer_id' must be a non-empty string (<= 128 bytes)"));
        }
        if !ids.insert(s(of.get("offer_id")).unwrap_or("")) {
            return Some(format!("offer {i}: duplicate offer_id"));
        }
        if nonneg(of.get("price")).is_none() {
            return Some(format!("offer {i}: 'price' must be a non-negative safe integer"));
        }
        let attrs: Vec<&String> = of.keys().filter(|k| *k != "offer_id" && *k != "price").collect();
        if attrs.len() > MAX_OFFER_ATTRS {
            return Some(format!("offer {i}: more than {MAX_OFFER_ATTRS} attributes"));
        }
        for k in attrs {
            if k.is_empty() || k.len() > 64 || !is_scalar(of.get(k)) {
                return Some(format!("offer {i}: attribute '{k}' must be a scalar"));
            }
        }
    }
    if nonneg(o.get("issued_at")).is_none() {
        return Some("'offer_set.issued_at' must be a non-negative safe integer".into());
    }
    if !bstr(o.get("kid"), 64) {
        return Some("'offer_set.kid' must be a non-empty string (<= 64 bytes)".into());
    }
    if !o.get("sig").is_some_and(Value::is_string) {
        return Some("'offer_set.sig' must be a string".into());
    }
    None
}

/// `offerMatches(offer, f)`: every key of `f` is an own member of the offer and scalar-equal.
fn offer_matches(offer: &Value, f: &Map<String, Value>) -> bool {
    f.iter().all(|(k, v)| offer.get(k).is_some() && scalar_eq(offer.get(k), Some(v)))
}

/// `decideOfferSet`: the excess of the chosen offer over the cheapest acceptable one.
#[allow(clippy::too_many_arguments)]
fn decide_offer_set(
    policy: &Value,
    committed: Option<&Value>,
    offer_set: Option<&Value>,
    params: &Value,
    aud: Option<&Value>,
    session: Option<&Value>,
    now: Option<i64>,
    skew: f64,
) -> Result<i64, String> {
    let committed = committed.ok_or("offers: the PCActn commits no offer set but the policy requires one")?;
    let os = offer_set.ok_or("offers: the committed offer set was not supplied")?;
    if let Some(w) = validate_offer_set_wire(os) {
        return Err(format!("offers: {w}"));
    }
    let r = artifact_ref(OFFER_SET_REF_DOMAIN, "o", os).ok_or("offers: the offer set is not strictly canonical")?;
    if Some(r.as_str()) != s(Some(committed)) {
        return Err("offers: the supplied offer set does not match the committed reference".into());
    }
    let oo = os.as_object().ok_or("offers: not an object")?;
    if let Some(e) = artifact_suite_error(oo) {
        return Err(format!("offers: signature suite: {e}"));
    }
    let key = policy.get("site_keys").and_then(Value::as_array).and_then(|ks| ks.iter().find(|k| same(k.get("kid"), os.get("kid"))));
    let key = key.ok_or("offers: signing key is not pinned")?;
    if !verify_artifact_sig(OFFER_SET_DOMAIN, oo, s(key.get("pk")).unwrap_or(""), key.get("pq_pk")) {
        return Err("offers: bad site signature".into());
    }
    if !same(os.get("site"), aud) {
        return Err("offers: the offer set was issued for another audience".into());
    }
    if !same(os.get("session"), session) {
        return Err("offers: the offer set is bound to another session".into());
    }
    let now = match now {
        Some(n) if safe_integer_f64(skew) => n as f64,
        _ => return Err("offers: no usable clock (now must be a safe integer): the offer set counts as stale".into()),
    };
    let issued = num(os.get("issued_at")).unwrap_or(f64::NAN);
    if issued > now + skew {
        return Err("offers: the offer set is issued in the future".into());
    }
    if now - issued > num(policy.get("max_age_ms")).unwrap_or(f64::NAN) {
        return Err("offers: the offer set is stale".into());
    }
    if os.get("complete") != Some(&Value::Bool(true)) {
        return Err("offers: the offer set is not declared complete".into());
    }
    let fq = obj(policy.get("filter").and_then(|f| f.get("query"))).cloned().unwrap_or_default();
    let fo = obj(policy.get("filter").and_then(|f| f.get("offer"))).cloned().unwrap_or_default();
    let covers = obj(os.get("query")).is_some_and(|q| q.iter().all(|(k, v)| fq.get(k).is_some() && scalar_eq(fq.get(k), Some(v))));
    if !covers {
        return Err("offers: the search was narrowed beyond the intent filter (coverage)".into());
    }
    let id = match resolve_param_path(params, s(policy.get("offer_param")).unwrap_or("")) {
        Some(Value::String(id)) => id,
        _ => return Err("offers: the action names no offer id at the declared parameter".into()),
    };
    let offers = os.get("offers").and_then(Value::as_array).cloned().unwrap_or_default();
    let chosen = offers.iter().find(|x| s(x.get("offer_id")) == Some(id.as_str())).ok_or("offers: the chosen offer is not in the signed offer set")?;
    if !offer_matches(chosen, &fo) {
        return Err("offers: the chosen offer does not satisfy the intent filter".into());
    }
    let price = |x: &Value| nonneg(x.get("price")).unwrap_or(0);
    let mut min = price(chosen);
    for x in &offers {
        if offer_matches(x, &fo) && price(x) < min {
            min = price(x);
        }
    }
    Ok(price(chosen) - min)
}

// ---- rule 17: per-parameter provenance, label receipts, flow rules -----------------------------------------------

/// The rule-17 decision: `outcome` (`pass` | `question` | `deny`), the friction of a question, the label per
/// classified path, the data classes per parameter and `env.prov`.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvenanceDecision {
    pub outcome: String,
    pub reason: String,
    pub friction: Option<String>,
    pub labels: Map<String, Value>,
    pub classes: Map<String, Value>,
    pub env: Map<String, Value>,
}

fn rank(level: &str) -> usize {
    TAINT_LEVELS.iter().position(|x| *x == level).unwrap_or(4)
}

fn is_taint_level(v: Option<&Value>) -> bool {
    matches!(s(v), Some(x) if TAINT_LEVELS.contains(&x))
}

fn validate_flow_rules(rules: &Value) -> Option<String> {
    let r = match rules.as_object() {
        Some(r) => r,
        None => return Some("flows must be an object".into()),
    };
    for (p, sinks) in r {
        let base = if p == "*" {
            "x"
        } else if let Some(b) = p.strip_suffix(".*") {
            b
        } else {
            p.as_str()
        };
        if !is_data_class(base) {
            return Some(format!("flow pattern '{p}' is not a class, a 'prefix.*' or '*'"));
        }
        if !sinks.as_array().is_some_and(|a| a.iter().all(|x| bstr(Some(x), 256))) {
            return Some(format!("flow pattern '{p}' needs a list of audiences"));
        }
    }
    None
}

fn validate_provenance_policy(p: &Value) -> Option<String> {
    let p = match p.as_object() {
        Some(p) if p.get("params").is_some_and(Value::is_object) => p,
        _ => return Some("provenance policy needs a params map".into()),
    };
    if !closed_members(p, &["params"], &["registry", "label_keys", "critical_max", "material_tainted", "critical_tainted", "flows"]) {
        return Some("provenance policy: unknown member".into());
    }
    for (k, v) in obj(p.get("params")).into_iter().flatten() {
        if !is_param_path(Some(&Value::String(k.clone()))) {
            return Some(format!("policy param '{k}' is not an action.params path"));
        }
        if !matches!(s(Some(v)), Some("material" | "critical")) {
            return Some(format!("policy param '{k}': sensitivity must be material or critical"));
        }
    }
    if let Some(reg) = p.get("registry") {
        let reg = match reg.as_object() {
            Some(r) => r,
            None => return Some("registry must be an object".into()),
        };
        for (k, v) in reg {
            if k.is_empty() || k.len() > 256 || !is_taint_level(Some(v)) {
                return Some(format!("registry entry '{k}' must map to a taint level"));
            }
        }
    }
    if let Some(lk) = p.get("label_keys") {
        let a = match lk.as_array() {
            Some(a) => a,
            None => return Some("label_keys must be a list".into()),
        };
        if !a.iter().all(|k| k.as_object().is_some_and(|k| closed_members(k, &["site", "kid", "pk"], &["pq_pk"]) && bstr(k.get("site"), 256) && bstr(k.get("kid"), 64) && b32(k.get("pk")) && pin_pq_ok(k.get("pq_pk")))) {
            return Some("every label key needs site, kid, a 32-byte pk and an optional string pq_pk".into());
        }
    }
    if p.get("critical_max").is_some() && !is_taint_level(p.get("critical_max")) {
        return Some("critical_max must be a taint level".into());
    }
    if p.get("material_tainted").is_some() && !matches!(s(p.get("material_tainted")), Some("allow" | "question" | "question_typed" | "deny")) {
        return Some("material_tainted must be allow | question | question_typed | deny".into());
    }
    if p.get("critical_tainted").is_some() && !matches!(s(p.get("critical_tainted")), Some("question" | "question_typed" | "deny")) {
        return Some("critical_tainted must be question | question_typed | deny".into());
    }
    if let Some(f) = p.get("flows") {
        if let Some(e) = validate_flow_rules(f) {
            return Some(e);
        }
    }
    None
}

fn validate_prov_wire(prov: &Value) -> Option<String> {
    let p = match prov.as_object() {
        Some(p) => p,
        None => return Some("'prov' must be an object".into()),
    };
    if p.len() > MAX_PROV_PATHS {
        return Some(format!("'prov' holds more than {MAX_PROV_PATHS} paths"));
    }
    for (k, refs) in p {
        let proto = k.strip_prefix("action.params.").is_some_and(|n| ["__proto__", "constructor", "prototype"].contains(&n));
        if !is_top_param_path(k) || proto {
            return Some(format!("'prov' key '{k}' is not action.params.<name>"));
        }
        let ok = refs.as_array().is_some_and(|r| !r.is_empty() && r.len() <= MAX_PROV_REFS && r.iter().all(|x| bstr(Some(x), 256)));
        if !ok {
            return Some(format!("'prov.{k}' must hold 1..{MAX_PROV_REFS} refs of 1..256 bytes"));
        }
    }
    None
}

fn validate_labels_wire(l: &Value) -> bool {
    let l = match l.as_object() {
        Some(l) => l,
        None => return false,
    };
    if !closed_members(l, &["v", "kind", "site", "session", "response_digest", "fields", "issued_at", "kid", "sig"], &SUITE_MEMBERS)
        || !same(l.get("v"), Some(&Value::from(1)))
        || s(l.get("kind")) != Some("pca-labels")
        || !bstr(l.get("site"), 256)
        || !b32(l.get("session"))
        || !b32(l.get("response_digest"))
    {
        return false;
    }
    let fields = match obj(l.get("fields")) {
        Some(f) if !f.is_empty() && f.len() <= MAX_LABEL_FIELDS => f,
        _ => return false,
    };
    for (k, f) in fields {
        if k.is_empty() || k.len() > 256 {
            return false;
        }
        let ok = f.as_object().is_some_and(|f| {
            closed_members(f, &["class", "value_digest"], &[])
                && s(f.get("class")).is_some_and(|c| c.encode_utf16().count() <= 128 && is_data_class(c))
                && b32(f.get("value_digest"))
        });
        if !ok {
            return false;
        }
    }
    nonneg(l.get("issued_at")).is_some() && bstr(l.get("kid"), 64) && l.get("sig").is_some_and(Value::is_string)
}

fn flow_rule_for<'a>(rules: &'a Map<String, Value>, cls: &str) -> Option<&'a str> {
    if let Some((k, _)) = rules.get_key_value(cls) {
        return Some(k.as_str());
    }
    let mut best: Option<&str> = None;
    for p in rules.keys() {
        if let Some(prefix) = p.strip_suffix('*') {
            if p.ends_with(".*") && cls.starts_with(prefix) && best.is_none_or(|b| p.encode_utf16().count() > b.encode_utf16().count()) {
                best = Some(p.as_str());
            }
        }
    }
    if best.is_some() {
        return best;
    }
    rules.get_key_value("*").map(|(k, _)| k.as_str())
}

fn flow_allowed(rules: &Map<String, Value>, cls: &str, origin: &str, aud: &str) -> bool {
    if aud == origin || cls == "public" {
        return true;
    }
    match flow_rule_for(rules, cls) {
        Some(p) => rules.get(p).and_then(Value::as_array).is_some_and(|a| a.iter().any(|x| x.as_str() == Some(aud))),
        None => false,
    }
}

fn parse_label_ref(r: &str) -> Option<(&str, &str)> {
    let rest = r.strip_prefix(LABEL_REF_PREFIX)?;
    let (receipt, field) = rest.split_once('#')?;
    (b32(Some(&Value::String(receipt.into()))) && !field.is_empty()).then_some((receipt, field))
}

/// Place `value` at the dotted `path` under `root`; false on a collision (`setNested`).
fn set_nested(root: &mut Map<String, Value>, path: &str, value: Value) -> bool {
    let segs: Vec<&str> = path.split('.').collect();
    let mut cur = root;
    for k in &segs[..segs.len() - 1] {
        let next = cur.entry((*k).to_string()).or_insert_with(|| Value::Object(Map::new()));
        cur = match next.as_object_mut() {
            Some(m) => m,
            None => return false,
        };
    }
    let last = segs[segs.len() - 1];
    if cur.contains_key(last) {
        return false;
    }
    cur.insert(last.into(), value);
    true
}

/// The rule-17 decision on the reference's `ProvenanceInput` (`decideParamProvenance`). Never panics.
pub fn decide_param_provenance(input: &Value) -> ProvenanceDecision {
    let mut labels = Map::new();
    let mut classes = Map::new();
    match prov_inner(input, &mut labels, &mut classes) {
        Ok(Ok(d)) => d,
        Ok(Err(reason)) => ProvenanceDecision { outcome: "deny".into(), reason: format!("provenance: {reason}"), friction: None, labels, classes, env: Map::new() },
        Err(e) => ProvenanceDecision {
            outcome: "deny".into(),
            reason: format!("provenance: evaluation error (fail closed): {e}"),
            friction: None,
            labels,
            classes,
            env: Map::new(),
        },
    }
}

fn prov_inner(input: &Value, labels: &mut Map<String, Value>, classes: &mut Map<String, Value>) -> Result<Result<ProvenanceDecision, String>, String> {
    let policy = input.get("policy").cloned().unwrap_or(Value::Null);
    if let Some(e) = validate_provenance_policy(&policy) {
        return Ok(Err(format!("policy misconfigured (fail closed): {e}")));
    }
    let empty_obj = Value::Object(Map::new());
    let prov = input.get("prov").unwrap_or(&empty_obj);
    if let Some(e) = validate_prov_wire(prov) {
        return Ok(Err(e));
    }
    let committed = match input.get("committed_labels") {
        None => Vec::new(),
        Some(Value::Array(a)) if a.len() <= MAX_COMMITTED_LABELS => a.clone(),
        _ => return Ok(Err(format!("committed labels must be a list of at most {MAX_COMMITTED_LABELS} digests"))),
    };
    let mut committed_set = std::collections::BTreeSet::new();
    for d in &committed {
        if !b32(Some(d)) || !committed_set.insert(s(Some(d)).unwrap_or("").to_string()) {
            return Ok(Err("committed labels must be distinct canonical 32-byte digests".into()));
        }
    }
    // `input.action?.params ?? {}`
    let params = match action_params(input.get("action")) {
        Ok(p) => p,
        Err(e) => return Ok(Err(e)),
    };
    let prov_map = prov.as_object().cloned().unwrap_or_default();
    let mut paths: Vec<String> = prov_map.keys().cloned().collect();
    sort_utf8(&mut paths);
    for p in &paths {
        if resolve_param_path(&params, p).is_none() {
            return Ok(Err(format!("prov names '{p}', a parameter the action does not carry")));
        }
    }
    for a in &paths {
        for b in &paths {
            if a != b && b.starts_with(&format!("{a}.")) {
                return Ok(Err(format!("prov paths '{a}' and '{b}' overlap")));
            }
        }
    }
    let mut receipts: Map<String, Value> = Map::new();
    for r in delivered(input.get("labels"))? {
        if validate_labels_wire(&r) {
            if let Some(rf) = artifact_ref(LABELS_REF_DOMAIN, "l", &r) {
                receipts.insert(rf, r);
            }
        }
    }
    let pol = policy.as_object().cloned().unwrap_or_default();
    let reg = obj(pol.get("registry")).cloned().unwrap_or_default();
    let label_keys: Vec<Value> = pol.get("label_keys").and_then(Value::as_array).cloned().unwrap_or_default();
    let aud = s(input.get("aud"));
    let mut origins: Vec<(String, Vec<(String, String)>)> = Vec::new();
    for p in &paths {
        let value = resolve_param_path(&params, p).cloned().unwrap_or(Value::Null);
        let mut ranks: Vec<usize> = Vec::new();
        for rv in prov_map.get(p).and_then(Value::as_array).cloned().unwrap_or_default() {
            let r = s(Some(&rv)).unwrap_or("");
            if !r.starts_with(LABEL_REF_PREFIX) {
                // classifyRef: the registry level when the registry has the ref as an OWN key, else agent
                let lvl = match reg.get(r) {
                    Some(l) if is_taint_level(Some(l)) => s(Some(l)).unwrap_or("agent"),
                    _ => "agent",
                };
                ranks.push(rank(lvl));
                continue;
            }
            let (receipt, field) = match parse_label_ref(r) {
                Some(x) => x,
                None => return Ok(Err(format!("malformed label ref on '{p}'"))),
            };
            if !committed_set.contains(receipt) {
                return Ok(Err(format!("label ref on '{p}' names a receipt the PCActn does not commit")));
            }
            let rc = match receipts.get(receipt) {
                Some(rc) => rc,
                None => return Ok(Err(format!("label receipt for '{p}' was not supplied"))),
            };
            let rco = rc.as_object().ok_or("not an object")?;
            if let Some(e) = artifact_suite_error(rco) {
                return Ok(Err(format!("label receipt for '{p}': signature suite: {e}")));
            }
            let key = label_keys.iter().find(|k| same(k.get("site"), rc.get("site")) && same(k.get("kid"), rc.get("kid")));
            let key = match key {
                Some(k) => k,
                None => return Ok(Err(format!("label receipt for '{p}': no pinned label key"))),
            };
            if !verify_artifact_sig(LABELS_DOMAIN, rco, s(key.get("pk")).unwrap_or(""), key.get("pq_pk")) {
                return Ok(Err(format!("label receipt for '{p}': bad label receipt signature")));
            }
            if !same(rc.get("session"), input.get("session")) {
                return Ok(Err(format!("label receipt for '{p}' is bound to another session")));
            }
            let f = match rc.get("fields").and_then(|f| f.get(field)) {
                Some(f) => f,
                None => return Ok(Err(format!("label receipt for '{p}' has no field '{field}'"))),
            };
            let matched = digest_of(&value).is_some_and(|d| Some(d.as_str()) == s(f.get("value_digest")));
            let site = s(rc.get("site")).unwrap_or("");
            ranks.push(if !matched {
                rank("agent")
            } else if Some(site) == aud {
                rank("first_party")
            } else {
                rank("tool")
            });
            let cls = s(f.get("class")).unwrap_or("").to_string();
            match origins.iter_mut().find(|(k, _)| k == p) {
                Some((_, v)) => v.push((cls, site.to_string())),
                None => origins.push((p.clone(), vec![(cls, site.to_string())])),
            }
        }
        let joined = ranks.iter().copied().max().unwrap_or(4);
        labels.insert(p.clone(), Value::String(TAINT_LEVELS[joined].into()));
    }
    let pparams = obj(pol.get("params")).cloned().unwrap_or_default();
    let mut ppaths: Vec<String> = pparams.keys().cloned().collect();
    sort_utf8(&mut ppaths);
    for p in &ppaths {
        if labels.contains_key(p) {
            continue;
        }
        if resolve_param_path(&params, p).is_some() {
            labels.insert(p.clone(), Value::String("agent".into()));
        }
    }
    origins.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    let flows = obj(pol.get("flows")).cloned().unwrap_or_default();
    for (p, os) in &origins {
        let mut cls: Vec<String> = os.iter().map(|(c, _)| c.clone()).collect();
        sort_utf8(&mut cls);
        cls.dedup();
        classes.insert(p.clone(), Value::Array(cls.into_iter().map(Value::String).collect()));
        for (c, origin) in os {
            if !flow_allowed(&flows, c, origin, aud.unwrap_or("")) {
                return Ok(Err(format!("flow: class '{c}' from '{origin}' may not reach the audience (parameter '{p}')")));
            }
        }
    }
    let cap = rank(s(pol.get("critical_max")).unwrap_or("agent"));
    let mut lpaths: Vec<String> = labels.keys().cloned().collect();
    sort_utf8(&mut lpaths);
    let level = |p: &str| rank(s(labels.get(p)).unwrap_or("agent"));
    for p in &lpaths {
        if s(pparams.get(p)) == Some("critical") && level(p) > cap {
            return Ok(Err(format!("critical parameter '{p}' has a provenance above the policy maximum")));
        }
    }
    let (mut question, mut typed) = (false, false);
    for p in &lpaths {
        let sens = s(pparams.get(p));
        if sens.is_none() || level(p) < 2 {
            continue;
        }
        let mode = if sens == Some("critical") {
            s(pol.get("critical_tainted")).unwrap_or("question_typed")
        } else {
            s(pol.get("material_tainted")).unwrap_or("question")
        };
        if mode == "deny" {
            return Ok(Err(format!("tainted parameter '{p}' is denied by policy")));
        }
        if mode == "question" || mode == "question_typed" {
            question = true;
        }
        if mode == "question_typed" {
            typed = true;
        }
    }
    let mut env = Map::new();
    for p in &lpaths {
        if !set_nested(&mut env, p, labels.get(p).cloned().unwrap_or(Value::Null)) {
            return Ok(Err(format!("provenance paths overlap at '{p}'")));
        }
    }
    Ok(Ok(if question {
        ProvenanceDecision {
            outcome: "question".into(),
            reason: "provenance: a tainted value needs the principal (lazy question)".into(),
            friction: Some(if typed { "typed" } else { "tap" }.into()),
            labels: labels.clone(),
            classes: classes.clone(),
            env,
        }
    } else {
        ProvenanceDecision { outcome: "pass".into(), reason: String::new(), friction: None, labels: labels.clone(), classes: classes.clone(), env }
    }))
}

// ---- rule 18: classifier verdicts --------------------------------------------------------------------------------

/// The rule-18 decision: `ok` and the class per classifier id, or the failure reason.
#[derive(Debug, Clone, PartialEq)]
pub struct ClassifierDecision {
    pub ok: bool,
    pub classes: Map<String, Value>,
    pub reason: String,
}

fn validate_classifier_policy(p: &Value) -> Option<String> {
    if !p.as_object().is_some_and(|p| closed_members(p, &["classifiers"], &[])) {
        return Some("classifier policy is exactly {classifiers}".into());
    }
    let cs = match p.as_object().and_then(|p| p.get("classifiers")).and_then(Value::as_array) {
        Some(c) => c,
        None => return Some("classifier policy needs a classifiers list".into()),
    };
    let mut ids = std::collections::BTreeSet::new();
    for c in cs {
        let c = match c.as_object() {
            Some(c) if !closed_members(c, &["id", "param", "labels", "keys", "k"], &["measurements", "pq_keys"]) => {
                return Some("every classifier is exactly {id, param, labels, keys, k, measurements?, pq_keys?}".into())
            }
            Some(c) if is_name(c.get("id")) && ids.insert(s(c.get("id")).unwrap_or("").to_string()) => c,
            _ => return Some("every classifier needs a unique id matching ^[a-z][a-z0-9_]{0,63}$".into()),
        };
        let id = s(c.get("id")).unwrap_or("");
        if !is_param_path(c.get("param")) {
            return Some(format!("classifier '{id}': param must be an action.params path"));
        }
        let labels = match c.get("labels").and_then(Value::as_array) {
            Some(l) if !l.is_empty() && l.len() <= MAX_CLASSIFIER_LABELS => l,
            _ => return Some(format!("classifier '{id}': labels must hold 1..{MAX_CLASSIFIER_LABELS} strings")),
        };
        let distinct: std::collections::BTreeSet<&str> = labels.iter().filter_map(Value::as_str).collect();
        if !labels.iter().all(|l| bstr(Some(l), 64)) || distinct.len() != labels.len() {
            return Some(format!("classifier '{id}': labels must be distinct non-empty strings"));
        }
        let keys = match c.get("keys").and_then(Value::as_array) {
            Some(k) if !k.is_empty() && k.iter().all(|x| b32(Some(x))) => k,
            _ => return Some(format!("classifier '{id}': keys must be distinct 32-byte keys")),
        };
        let dk: std::collections::BTreeSet<&str> = keys.iter().filter_map(Value::as_str).collect();
        if dk.len() != keys.len() {
            return Some(format!("classifier '{id}': keys must be distinct 32-byte keys"));
        }
        if !sint(c.get("k")).is_some_and(|k| k >= 1 && (k as usize) <= keys.len()) {
            return Some(format!("classifier '{id}': k must be an integer in [1, {}]", keys.len()));
        }
        if let Some(m) = c.get("measurements") {
            if !m.as_array().is_some_and(|a| a.iter().all(Value::is_string)) {
                return Some(format!("classifier '{id}': measurements must be a list of strings"));
            }
        }
        if let Some(pk) = c.get("pq_keys") {
            let ok = pk.as_object().is_some_and(|m| m.iter().all(|(k, v)| keys.iter().any(|x| x.as_str() == Some(k.as_str())) && v.as_str().is_some_and(|x| !x.is_empty())));
            if !ok {
                return Some(format!("classifier '{id}': pq_keys must map allowlisted keys to PQ keys"));
            }
        }
    }
    None
}

fn validate_verdict_wire(v: &Value) -> bool {
    let v = match v.as_object() {
        Some(v) => v,
        None => return false,
    };
    closed_members(v, &["v", "kind", "classifier", "session", "content_digest", "label", "measurement", "judge", "sig"], &SUITE_MEMBERS)
        && same(v.get("v"), Some(&Value::from(1)))
        && s(v.get("kind")) == Some("pca-intent-classification")
        && is_name(v.get("classifier"))
        && b32(v.get("session"))
        && b32(v.get("content_digest"))
        && bstr(v.get("label"), 64)
        && bstr(v.get("measurement"), 256)
        && b32(v.get("judge"))
        && v.get("sig").is_some_and(Value::is_string)
}

/// `classifierCheckActive({committed, policy})`.
pub(crate) fn classifier_check_active(committed: Option<&Value>, classifiers: Option<&Value>) -> bool {
    non_empty_array(committed) || non_empty_array(classifiers)
}

/// The rule-18 decision on the reference's `ClassifierInput` (`decideClassifierDimensions`). Never panics.
pub fn decide_classifier_dimensions(input: &Value) -> ClassifierDecision {
    let fail = |r: String| ClassifierDecision { ok: false, classes: Map::new(), reason: format!("classes: {r}") };
    let policy = input.get("policy").cloned().unwrap_or(Value::Null);
    if let Some(e) = validate_classifier_policy(&policy) {
        return fail(format!("policy misconfigured (fail closed): {e}"));
    }
    let committed = match input.get("committed") {
        None => Vec::new(),
        Some(Value::Array(a)) if a.len() <= MAX_COMMITTED_CLASSES => a.clone(),
        _ => return fail(format!("committed verdicts must be a list of at most {MAX_COMMITTED_CLASSES} digests")),
    };
    let mut seen = std::collections::BTreeSet::new();
    for d in &committed {
        if !b32(Some(d)) || !seen.insert(s(Some(d)).unwrap_or("").to_string()) {
            return fail("committed verdicts must be distinct canonical 32-byte digests".into());
        }
    }
    let verdicts = match delivered(input.get("verdicts")) {
        Ok(v) => v,
        Err(e) => return fail(format!("evaluation error (fail closed): {e}")),
    };
    let mut by_ref: Map<String, Value> = Map::new();
    for v in verdicts {
        if validate_verdict_wire(&v) {
            if let Some(r) = artifact_ref(CLASSIFIER_REF_DOMAIN, "c", &v) {
                by_ref.insert(r, v);
            }
        }
    }
    let params = match action_params(input.get("action")) {
        Ok(p) => p,
        Err(e) => return fail(e),
    };
    let params = &params;
    let classifiers: Vec<Value> = policy.get("classifiers").and_then(Value::as_array).cloned().unwrap_or_default();
    // per classifier id: label -> votes (a prototype-free tally: every id and label is an ordinary key)
    let mut votes: Vec<(String, Vec<(String, i64)>)> = Vec::new();
    let mut pairs = std::collections::BTreeSet::new();
    for d in &committed {
        let v = match by_ref.get(s(Some(d)).unwrap_or("")) {
            Some(v) => v,
            None => return fail("a committed verdict was not supplied (or is malformed)".into()),
        };
        let vo = match v.as_object() {
            Some(o) => o,
            None => return fail("a committed verdict is not an object".into()),
        };
        if let Some(e) = artifact_suite_error(vo) {
            return fail(format!("verdict signature suite: {e}"));
        }
        let cname = s(v.get("classifier")).unwrap_or("");
        let c = match classifiers.iter().find(|c| s(c.get("id")) == Some(cname)) {
            Some(c) => c,
            None => return fail(format!("verdict for undeclared classifier '{cname}'")),
        };
        let judge = s(v.get("judge")).unwrap_or("");
        if !c.get("keys").and_then(Value::as_array).is_some_and(|k| k.iter().any(|x| x.as_str() == Some(judge))) {
            return fail(format!("classifier '{cname}': judge key is not on the allowlist"));
        }
        let pq = c.get("pq_keys").and_then(|m| m.get(judge));
        if !verify_artifact_sig(CLASSIFIER_DOMAIN, vo, judge, pq) {
            return fail(format!("classifier '{cname}': bad verdict signature"));
        }
        if !same(v.get("session"), input.get("session")) {
            return fail(format!("classifier '{cname}': verdict bound to another session"));
        }
        let content = match resolve_param_path(params, s(c.get("param")).unwrap_or("")) {
            Some(x) => x,
            None => return fail(format!("classifier '{cname}': the action carries no content")),
        };
        if digest_of(content).as_deref() != s(v.get("content_digest")) {
            return fail(format!("classifier '{cname}': verdict is about other content"));
        }
        let label = s(v.get("label")).unwrap_or("");
        if !c.get("labels").and_then(Value::as_array).is_some_and(|l| l.iter().any(|x| x.as_str() == Some(label))) {
            return fail(format!("classifier '{cname}': label '{label}' is not in its label set"));
        }
        if let Some(ms) = c.get("measurements") {
            let m = v.get("measurement").and_then(Value::as_str);
            if !ms.as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == m)) {
                return fail(format!("classifier '{cname}': measurement is not pinned"));
            }
        }
        if !pairs.insert((cname.to_string(), judge.to_string())) {
            return fail(format!("classifier '{cname}': two verdicts from one judge"));
        }
        let t = match votes.iter_mut().find(|(k, _)| k == cname) {
            Some((_, t)) => t,
            None => {
                votes.push((cname.to_string(), Vec::new()));
                &mut votes.last_mut().expect("just pushed").1
            }
        };
        match t.iter_mut().find(|(l, _)| l == label) {
            Some((_, n)) => *n += 1,
            None => t.push((label.to_string(), 1)),
        }
    }
    let mut classes = Map::new();
    for c in &classifiers {
        let id = s(c.get("id")).unwrap_or("");
        let k = sint(c.get("k")).unwrap_or(i64::MAX);
        let t = votes.iter().find(|(x, _)| x == id).map(|(_, t)| t.as_slice()).unwrap_or(&[]);
        let winners: Vec<&str> = c
            .get("labels")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|l| t.iter().find(|(x, _)| x == l).map_or(0, |(_, n)| *n) >= k)
            .collect();
        if winners.is_empty() {
            return fail(format!("classifier '{id}': no label reaches the quorum {k}"));
        }
        if winners.len() > 1 {
            return fail(format!("classifier '{id}': ambiguous, {} labels reach the quorum", winners.len()));
        }
        classes.insert(id.to_string(), Value::String(winners[0].into()));
    }
    ClassifierDecision { ok: true, classes, reason: String::new() }
}

// ---- activity and decideIntentWB ---------------------------------------------------------------------------------

/// Is the rule-17 check active? Iff `prov` is present (any value), `labels` is a non-empty array, or the provenance
/// policy is a JSON object.
pub(crate) fn intent_provenance_active(prov: Option<&Value>, labels: Option<&Value>, policy: Option<&Value>) -> bool {
    prov.is_some() || non_empty_array(labels) || policy.is_some_and(Value::is_object)
}

/// Which W-B checks a verifier reports (`intentWBActive`, `primitives.intent_wb_active`) for
/// `{intent_session, policy: {world?, provenance?, classifiers?}}`: `(facts, provenance, classes)`.
pub fn intent_wb_active(input: &Value) -> (bool, bool, bool) {
    let sget = |k: &str| input.get("intent_session").and_then(Value::as_object).and_then(|x| x.get(k));
    let pget = |k: &str| input.get("policy").and_then(Value::as_object).and_then(|x| x.get(k));
    let world = pget("world");
    (
        intent_world_active(sget("facts"), sget("offer_set"), world),
        intent_provenance_active(sget("prov"), sget("labels"), pget("provenance")),
        classifier_check_active(sget("classes"), pget("classifiers")),
    )
}

/// One W-B check verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WbCheck {
    Pass,
    Question,
    Fail,
}

/// The W-B result (`decideIntentWB`): reported checks in order facts, provenance, classes; the first failing one ends
/// the unit.
#[derive(Debug, Clone, PartialEq)]
pub struct IntentWbResult {
    /// `admit` | `question` | `deny`.
    pub outcome: String,
    pub checks: Vec<(&'static str, WbCheck)>,
    pub env: Map<String, Value>,
    pub reason: String,
    pub friction: Option<String>,
    pub single_source: Vec<String>,
}

/// `intentWBContextError`: `intent_session` an object; `artifacts` absent or an object whose `facts` / `labels` /
/// `verdicts` are absent or arrays and whose `offer_set` is absent or an object; `policy` absent or an object whose
/// `world` / `provenance` are absent or objects and whose `classifiers` is absent or an array (JSON `null` = malformed).
pub(crate) fn intent_wb_context_error(input: &Value) -> Option<String> {
    if !input.get("intent_session").is_some_and(Value::is_object) {
        return Some("intent_session must be an object".into());
    }
    if let Some(a) = input.get("artifacts") {
        let a = match a.as_object() {
            Some(a) => a,
            None => return Some("artifacts must be an object".into()),
        };
        if !closed_members(a, &[], &["facts", "labels", "verdicts", "offer_set"]) {
            return Some("artifacts: unknown member".into());
        }
        for k in ["facts", "labels", "verdicts"] {
            if a.get(k).is_some_and(|x| !x.is_array()) {
                return Some(format!("artifacts.{k} must be an array"));
            }
        }
        if a.get("offer_set").is_some_and(|x| !x.is_object()) {
            return Some("artifacts.offer_set must be an object".into());
        }
    }
    if let Some(p) = input.get("policy") {
        let p = match p.as_object() {
            Some(p) => p,
            None => return Some("policy must be an object".into()),
        };
        if !closed_members(p, &[], &["world", "provenance", "classifiers"]) {
            return Some("policy: unknown member".into());
        }
        for k in ["world", "provenance"] {
            if p.get(k).is_some_and(|x| !x.is_object()) {
                return Some(format!("policy.{k} must be an object"));
            }
        }
        if p.get("classifiers").is_some_and(|x| !x.is_array()) {
            return Some("policy.classifiers must be an array".into());
        }
    }
    None
}

/// `decideIntentWB(input)`: rules 16, 17 and 18 in order on the reference's `IntentWBInput`. Never panics.
pub fn decide_intent_wb(input: &Value) -> IntentWbResult {
    let mut out = IntentWbResult { outcome: "admit".into(), checks: Vec::new(), env: Map::new(), reason: String::new(), friction: None, single_source: Vec::new() };
    if let Some(e) = intent_wb_context_error(input) {
        return IntentWbResult {
            outcome: "deny".into(),
            checks: vec![("facts", WbCheck::Fail)],
            env: Map::new(),
            reason: format!("facts: the W-B context is malformed: {e}"),
            friction: None,
            single_source: Vec::new(),
        };
    }
    let is = input.get("intent_session").and_then(Value::as_object);
    let art = input.get("artifacts").and_then(Value::as_object);
    let policy = input.get("policy").and_then(Value::as_object);
    let sget = |k: &str| is.and_then(|x| x.get(k));
    let aget = |k: &str| art.and_then(|x| x.get(k));
    let pget = |k: &str| policy.and_then(|x| x.get(k));
    let world_policy = pget("world").cloned().unwrap_or_else(|| Value::Object(Map::new()));
    if intent_world_active(sget("facts"), sget("offer_set"), Some(&world_policy)) {
        let mut committed = Map::new();
        if let Some(f) = sget("facts") {
            committed.insert("facts".into(), f.clone());
        }
        if let Some(o) = sget("offer_set") {
            committed.insert("offer_set".into(), o.clone());
        }
        let mut wi = Map::new();
        for k in ["now", "aud", "session", "action"] {
            if let Some(x) = input.get(k) {
                wi.insert(k.into(), x.clone());
            }
        }
        wi.insert("committed".into(), Value::Object(committed));
        if let Some(f) = aget("facts") {
            wi.insert("facts".into(), f.clone());
        }
        if let Some(o) = aget("offer_set") {
            wi.insert("offer_set".into(), o.clone());
        }
        wi.insert("policy".into(), world_policy);
        let w = decide_intent_world(&Value::Object(wi));
        if !w.ok {
            out.outcome = "deny".into();
            out.checks.push(("facts", WbCheck::Fail));
            out.reason = w.reason;
            return out;
        }
        out.checks.push(("facts", WbCheck::Pass));
        out.env.insert("world".into(), Value::Object(w.world));
        out.single_source = w.single_source;
    }
    if intent_provenance_active(sget("prov"), sget("labels"), pget("provenance")) {
        let mut pi = Map::new();
        for k in ["aud", "session", "action"] {
            if let Some(x) = input.get(k) {
                pi.insert(k.into(), x.clone());
            }
        }
        if let Some(p) = sget("prov") {
            pi.insert("prov".into(), p.clone());
        }
        if let Some(l) = sget("labels") {
            pi.insert("committed_labels".into(), l.clone());
        }
        if let Some(l) = aget("labels") {
            pi.insert("labels".into(), l.clone());
        }
        let pp = pget("provenance").cloned().unwrap_or_else(|| serde_json::json!({ "params": {} }));
        pi.insert("policy".into(), pp);
        let p = decide_param_provenance(&Value::Object(pi));
        if p.outcome == "deny" {
            out.outcome = "deny".into();
            out.checks.push(("provenance", WbCheck::Fail));
            out.reason = p.reason;
            return out;
        }
        out.checks.push(("provenance", if p.outcome == "question" { WbCheck::Question } else { WbCheck::Pass }));
        out.env.insert("prov".into(), Value::Object(p.env));
        if p.outcome == "question" {
            out.outcome = "question".into();
            out.reason = p.reason;
            out.friction = p.friction;
        }
    }
    let classifiers = pget("classifiers").cloned().unwrap_or_else(|| Value::Array(Vec::new()));
    if classifier_check_active(sget("classes"), Some(&classifiers)) {
        let mut ci = Map::new();
        for k in ["session", "action"] {
            if let Some(x) = input.get(k) {
                ci.insert(k.into(), x.clone());
            }
        }
        if let Some(c) = sget("classes") {
            ci.insert("committed".into(), c.clone());
        }
        if let Some(v) = aget("verdicts") {
            ci.insert("verdicts".into(), v.clone());
        }
        ci.insert("policy".into(), serde_json::json!({ "classifiers": classifiers }));
        let c = decide_classifier_dimensions(&Value::Object(ci));
        if !c.ok {
            out.outcome = "deny".into();
            out.checks.push(("classes", WbCheck::Fail));
            out.reason = c.reason;
            return out;
        }
        out.checks.push(("classes", WbCheck::Pass));
        out.env.insert("class".into(), Value::Object(c.classes));
    }
    out
}

// ---- read purpose (V14, `primitives.intent_read_purpose`) -------------------------------------------------------

/// The read-purpose decision: `outcome` (`allow` | `question` | `deny`), the optional uncovered paths to minimise and
/// the required uncovered paths, each de-duplicated and sorted in UTF-8 byte order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadPurposeDecision {
    pub outcome: String,
    pub minimise: Vec<String>,
    pub uncovered: Vec<String>,
}

/// `decideReadPurpose` on `{fields: [{path, class, optional?}], purpose, coverage: {purpose: [pattern]}, on_uncovered?}`.
/// Malformed input (JSON `null` anywhere included) is `deny` with empty lists; `coverage[purpose]` is an own member; a
/// field is covered when its class is `public` or matches a pattern (a class, `p.*`, `*`). Never panics.
pub fn decide_read_purpose(input: &Value) -> ReadPurposeDecision {
    let malformed = ReadPurposeDecision { outcome: "deny".into(), minimise: Vec::new(), uncovered: Vec::new() };
    let (fields, purpose, coverage) = match (input.get("fields"), input.get("purpose"), input.get("coverage")) {
        (Some(Value::Array(f)), Some(Value::String(p)), Some(Value::Object(c))) => (f, p, c),
        _ => return malformed,
    };
    let on_uncovered = match input.get("on_uncovered") {
        None => "question",
        Some(Value::String(x)) if x == "question" || x == "deny" => x.as_str(),
        Some(_) => return malformed,
    };
    if !coverage.values().all(|v| v.as_array().is_some_and(|a| a.iter().all(Value::is_string))) {
        return malformed;
    }
    for f in fields {
        let ok = f.as_object().is_some_and(|f| {
            f.get("path").is_some_and(Value::is_string) && f.get("class").is_some_and(Value::is_string) && f.get("optional").is_none_or(Value::is_boolean)
        });
        if !ok {
            return malformed;
        }
    }
    let patterns: Vec<&str> = coverage.get(purpose.as_str()).and_then(Value::as_array).map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
    let covered = |cls: &str| {
        cls == "public" || patterns.iter().any(|p| *p == "*" || *p == cls || (p.ends_with(".*") && cls.starts_with(&p[..p.len() - 1])))
    };
    let (mut minimise, mut uncovered) = (Vec::new(), Vec::new());
    for f in fields {
        let cls = s(f.get("class")).unwrap_or("");
        if covered(cls) {
            continue;
        }
        let path = s(f.get("path")).unwrap_or("").to_string();
        if f.get("optional") == Some(&Value::Bool(true)) {
            minimise.push(path);
        } else {
            uncovered.push(path);
        }
    }
    for xs in [&mut minimise, &mut uncovered] {
        sort_utf8(xs);
        xs.dedup();
    }
    let outcome = if uncovered.is_empty() { "allow" } else { on_uncovered };
    ReadPurposeDecision { outcome: outcome.into(), minimise, uncovered }
}

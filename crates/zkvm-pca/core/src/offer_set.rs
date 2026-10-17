//! Intent Layer v2 W-B: signed offer sets and the optimality dimension `excess` (conformance rule 16, step 6).
//! Faithful port of `packages/pca/src/offer-set.ts` (`validateOfferSetWire`, `validateOfferPolicy`, `decideOfferSet`,
//! `offerMatches`, `queryCovers`). Signed under the artifact's suite with the verifier-pinned site signer `{kid, pk, pq_pk?}` (`unsupported_suite` first). Never panics.
use crate::jsnum::{non_neg, safe_int};
use crate::oracle_facts::{artifact_ref, artifact_suite_error, closed_members, pin_of, pin_pq_ok, SUITE_MEMBERS, is_bounded_string, is_digest, is_scalar, resolve_param_path, scalar_eq, verify_artifact_sig};
use serde_json::{Map, Value};

pub const OFFER_SET_DOMAIN: &str = "atlas-pca/offer-set/v1\0";
pub const OFFER_SET_REF_DOMAIN: &str = "atlas-pca/offer-set-ref/v1";
pub const MAX_OFFERS: usize = 256;
pub const MAX_OFFER_ATTRS: usize = 32;
pub const MAX_QUERY_KEYS: usize = 32;

const FIELDS: [&str; 11] = ["v", "kind", "site", "session", "query", "rank", "complete", "offers", "issued_at", "kid", "sig"];

/// `validateOfferSetWire`: `None` = well-formed.
pub fn validate_offer_set_wire(o: &Value) -> Option<String> {
    let o = match o.as_object() {
        Some(o) => o,
        None => return Some("offer set must be an object".into()),
    };
    if !closed_members(o, &FIELDS, &SUITE_MEMBERS) {
        return Some("offer set has unknown or missing members".into());
    }
    let g = |k: &str| o.get(k).unwrap_or(&Value::Null);
    if safe_int(g("v")) != Some(1) || g("kind").as_str() != Some("pca-offer-set") {
        return Some("offer set must be {v: 1, kind: \"pca-offer-set\"}".into());
    }
    if !is_bounded_string(g("site"), 256) {
        return Some("'offer_set.site' must be a non-empty string (<= 256 bytes)".into());
    }
    if !is_digest(g("session")) {
        return Some("'offer_set.session' must be canonical base64url (32 bytes)".into());
    }
    let q = match g("query").as_object() {
        Some(q) if q.len() <= MAX_QUERY_KEYS => q,
        _ => return Some(format!("'offer_set.query' must be an object with <= {MAX_QUERY_KEYS} keys")),
    };
    for (k, v) in q {
        if k.is_empty() || k.len() > 64 || !is_scalar(v) {
            return Some(format!("'offer_set.query.{k}' must be a scalar"));
        }
    }
    if g("rank").as_str() != Some("price_asc") {
        return Some("'offer_set.rank' must be \"price_asc\"".into());
    }
    if !g("complete").is_boolean() {
        return Some("'offer_set.complete' must be a boolean".into());
    }
    let offers = match g("offers").as_array() {
        Some(a) if !a.is_empty() && a.len() <= MAX_OFFERS => a,
        _ => return Some(format!("'offer_set.offers' must hold 1..{MAX_OFFERS} offers")),
    };
    let mut ids: Vec<&str> = Vec::new();
    for (i, of) in offers.iter().enumerate() {
        let of = match of.as_object() {
            Some(of) => of,
            None => return Some(format!("offer {i} must be an object")),
        };
        let id = of.get("offer_id").unwrap_or(&Value::Null);
        if !is_bounded_string(id, 128) {
            return Some(format!("offer {i}: 'offer_id' must be a non-empty string (<= 128 bytes)"));
        }
        let id = id.as_str().unwrap_or("");
        if ids.contains(&id) {
            return Some(format!("offer {i}: duplicate offer_id"));
        }
        ids.push(id);
        if of.get("price").and_then(non_neg).is_none() {
            return Some(format!("offer {i}: 'price' must be a non-negative safe integer"));
        }
        let attrs: Vec<(&String, &Value)> = of.iter().filter(|(k, _)| k.as_str() != "offer_id" && k.as_str() != "price").collect();
        if attrs.len() > MAX_OFFER_ATTRS {
            return Some(format!("offer {i}: more than {MAX_OFFER_ATTRS} attributes"));
        }
        for (k, v) in attrs {
            if k.is_empty() || k.len() > 64 || !is_scalar(v) {
                return Some(format!("offer {i}: attribute '{k}' must be a scalar"));
            }
        }
    }
    if non_neg(g("issued_at")).is_none() {
        return Some("'offer_set.issued_at' must be a non-negative safe integer".into());
    }
    if !is_bounded_string(g("kid"), 64) {
        return Some("'offer_set.kid' must be a non-empty string (<= 64 bytes)".into());
    }
    if !g("sig").is_string() {
        return Some("'offer_set.sig' must be a string".into());
    }
    None
}

/// `offerSetRef(o)`; `None` where TS throws.
pub fn offer_set_ref(o: &Value) -> Option<String> {
    artifact_ref(OFFER_SET_REF_DOMAIN, "o", o)
}

/// `offerMatches(offer, f)`: every key of `f` is an own member of the offer with a scalar-equal value.
pub fn offer_matches(offer: &Value, f: &Map<String, Value>) -> bool {
    f.iter().all(|(k, v)| offer.get(k).map_or(false, |x| scalar_eq(x, v)))
}

/// `queryCovers(query, fq)`: keys(q) ⊆ keys(fq) with scalar-equal values.
pub fn query_covers(query: &Map<String, Value>, fq: &Map<String, Value>) -> bool {
    query.iter().all(|(k, v)| fq.get(k).map_or(false, |x| scalar_eq(x, v)))
}

/// `validateOfferPolicy`: `None` = well-formed.
pub fn validate_offer_policy(p: &Value) -> Option<String> {
    let p = match p.as_object() {
        Some(p) => p,
        None => return Some("offers policy must be an object".into()),
    };
    if !closed_members(p, &["name", "site_keys", "max_age_ms", "offer_param", "filter"], &[]) {
        return Some("offers policy is exactly {name, site_keys, max_age_ms, offer_param, filter}".into());
    }
    if !p.get("name").map_or(false, Value::is_string) {
        return Some("offers policy needs a name".into());
    }
    let keys = match p.get("site_keys").and_then(Value::as_array) {
        Some(k) if !k.is_empty() => k,
        _ => return Some("offers policy needs at least one pinned site key".into()),
    };
    let mut kids: Vec<&str> = Vec::new();
    for k in keys {
        let ok = k.as_object().map_or(false, |k| {
            let kid = k.get("kid").unwrap_or(&Value::Null);
            closed_members(k, &["kid", "pk"], &["pq_pk"]) && is_bounded_string(kid, 64) && is_digest(k.get("pk").unwrap_or(&Value::Null)) && pin_pq_ok(k) && !kids.contains(&kid.as_str().unwrap_or(""))
        });
        if !ok {
            return Some("offers policy: every site key needs a unique kid and a 32-byte pk".into());
        }
        kids.push(k.get("kid").and_then(Value::as_str).unwrap_or(""));
    }
    if p.get("max_age_ms").and_then(non_neg).is_none() {
        return Some("offers policy: max_age_ms must be a non-negative safe integer".into());
    }
    if !matches!(p.get("offer_param"), Some(Value::String(s)) if s.starts_with("action.params.")) {
        return Some("offers policy: offer_param must be an action.params.* path".into());
    }
    let f = p.get("filter").and_then(Value::as_object).filter(|f| closed_members(f, &["query", "offer"], &[]));
    let (fq, fo) = match f.map(|f| (f.get("query").and_then(Value::as_object), f.get("offer").and_then(Value::as_object))) {
        Some((Some(q), Some(o))) => (q, o),
        _ => return Some("offers policy: filter must be {query: {}, offer: {}}".into()),
    };
    if !fq.values().chain(fo.values()).all(is_scalar) {
        return Some("offers policy: filter values must be scalars".into());
    }
    None
}

#[derive(Debug, Clone, PartialEq)]
pub struct OfferDecision {
    pub excess: i64,
    pub chosen_price: i64,
    pub min_price: i64,
}

/// Rule 16 step 6 (`decideOfferSet`; the policy is assumed sane). `Err(reason)` on the first failure. Never panics.
#[allow(clippy::too_many_arguments)]
pub fn decide_offer_set(
    policy: &Value,
    committed: Option<&str>,
    offer_set: Option<&Value>,
    params: &Value,
    aud: &Value,
    session: &Value,
    now: Option<i64>,
    skew_ms: i64,
) -> Result<OfferDecision, String> {
    let committed = committed.ok_or_else(|| "offers: the PCActn commits no offer set but the policy requires one".to_string())?;
    let o = offer_set.ok_or_else(|| "offers: the committed offer set was not supplied".to_string())?;
    if let Some(w) = validate_offer_set_wire(o) {
        return Err(format!("offers: {w}"));
    }
    let r = offer_set_ref(o).ok_or_else(|| "offers: the offer set is not strictly canonical".to_string())?;
    if r != committed {
        return Err("offers: the supplied offer set does not match the committed reference".into());
    }
    if let Some(se) = artifact_suite_error(o) {
        return Err(format!("offers: signature suite: {se}"));
    }
    let g = |k: &str| o.get(k).unwrap_or(&Value::Null);
    let kid = g("kid").as_str().unwrap_or("");
    let key = policy
        .get("site_keys")
        .and_then(Value::as_array)
        .and_then(|ks| ks.iter().find(|k| k.get("kid").and_then(Value::as_str) == Some(kid)))
        .ok_or_else(|| format!("offers: signing key '{kid}' is not pinned"))?;
    let (pk, pq) = pin_of(key);
    if !verify_artifact_sig(OFFER_SET_DOMAIN, o, pk, pq) {
        return Err("offers: bad site signature".into());
    }
    if g("site") != aud {
        return Err("offers: the offer set was issued for another audience".into());
    }
    if g("session") != session {
        return Err("offers: the offer set is bound to another session".into());
    }
    // `now` must be a safe integer (`isClock`), else the offer set counts as stale. Exact arithmetic on safe integers.
    let now = match now {
        Some(n) => n as i128,
        None => return Err("offers: no usable clock (now must be a safe integer): the offer set counts as stale".into()),
    };
    let issued = safe_int(g("issued_at")).unwrap_or(0) as i128;
    if issued > now + skew_ms as i128 {
        return Err("offers: the offer set is issued in the future".into());
    }
    let max_age = policy.get("max_age_ms").and_then(safe_int).unwrap_or(0) as i128;
    if now - issued > max_age {
        return Err("offers: the offer set is stale".into());
    }
    if g("complete") != &Value::Bool(true) {
        return Err("offers: the offer set is not declared complete".into());
    }
    let empty = Map::new();
    let filter = policy.get("filter");
    let fq = filter.and_then(|f| f.get("query")).and_then(Value::as_object).unwrap_or(&empty);
    let fo = filter.and_then(|f| f.get("offer")).and_then(Value::as_object).unwrap_or(&empty);
    if !query_covers(g("query").as_object().unwrap_or(&empty), fq) {
        return Err("offers: the search was narrowed beyond the intent filter (coverage)".into());
    }
    let id = match resolve_param_path(params, policy.get("offer_param").and_then(Value::as_str).unwrap_or("")) {
        Some(Value::String(s)) => s,
        _ => return Err("offers: the action names no offer id at the declared parameter".into()),
    };
    let offers = g("offers").as_array().map(Vec::as_slice).unwrap_or(&[]);
    let chosen = offers
        .iter()
        .find(|x| x.get("offer_id").and_then(Value::as_str) == Some(id.as_str()))
        .ok_or_else(|| "offers: the chosen offer is not in the signed offer set".to_string())?;
    if !offer_matches(chosen, fo) {
        return Err("offers: the chosen offer does not satisfy the intent filter".into());
    }
    let price = |x: &Value| x.get("price").and_then(safe_int).unwrap_or(0);
    let chosen_price = price(chosen);
    let mut min = chosen_price;
    for x in offers {
        if offer_matches(x, fo) && price(x) < min {
            min = price(x);
        }
    }
    Ok(OfferDecision { excess: chosen_price - min, chosen_price, min_price: min })
}

//! What you see is what you sign (track K7): a port of packages/pca/src/approval-render.ts (render shape, H(R), the approval
//! challenge, the speakable match code) and packages/pca-actions/src/approval-render.ts + approval-profiles.ts (the canonical render
//! of an action, the PSD2 RTS Art. 5 linking view, the batch commitment). A render that cannot be made completely is an
//! [`ApprovalError`], never something partial.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::actions::{def_digest, normalize};
use super::{b64_encode, decode_b64u_strict, hash_canonical_strict, merkle_root, safe_int};

pub const APPROVAL_RENDER_DOMAIN: &str = "atlas-pca/approval-render/v1";
pub const APPROVAL_CHALLENGE_DOMAIN: &str = "atlas-pca/approval-challenge/v1\0";
pub const APPROVAL_BATCH_DOMAIN: &str = "atlas-pca/approval-batch/v1";
const ITEM_DOMAIN: &str = "atlas-pca/approval-batch-item/v1";
const PAYEE_DOMAIN: &str = "atlas-pca/approval-payee/v1";
const MAX_RENDER_FIELDS: usize = 64;
const MAX_PARAM_PATH_DEPTH: usize = 3;
const MAX_SAFE: i64 = 9_007_199_254_740_991;
/// The sentinel the loaders put where the wire had a lone surrogate (a Rust string cannot hold one).
const LONE: char = '\u{10FFFF}';

pub const BINDING_WORDS: [&str; 256] = [
    "able", "acid", "aged", "also", "area", "army", "atom", "aunt",
    "away", "baby", "back", "ball", "band", "bank", "base", "bath",
    "bear", "beat", "beef", "bell", "belt", "bend", "bird", "blue",
    "boat", "body", "bold", "bone", "book", "boot", "born", "both",
    "bowl", "bulb", "burn", "bush", "busy", "cafe", "cake", "calm",
    "camp", "card", "care", "cart", "case", "cash", "cast", "cave",
    "cell", "chat", "chef", "chip", "city", "clay", "clip", "club",
    "coal", "coat", "code", "coin", "cold", "cook", "cool", "cope",
    "copy", "cord", "core", "cost", "crew", "crop", "dark", "data",
    "date", "dawn", "deal", "dear", "deck", "deep", "deer", "desk",
    "dial", "dice", "diet", "dish", "dive", "door", "dose", "down",
    "draw", "drop", "drum", "duck", "dust", "duty", "each", "earn",
    "east", "easy", "edge", "echo", "else", "even", "ever", "exit",
    "face", "fact", "fair", "fall", "farm", "fast", "fate", "fern",
    "file", "fill", "film", "find", "fine", "fire", "firm", "fish",
    "five", "flag", "flat", "flow", "foam", "fold", "folk", "food",
    "foot", "fork", "form", "fort", "four", "free", "frog", "fuel",
    "full", "fund", "gain", "game", "gate", "gear", "gift", "girl",
    "glad", "glow", "goat", "gold", "golf", "good", "grab", "gray",
    "grid", "grip", "grow", "gulf", "hair", "half", "hall", "hand",
    "hard", "harp", "hawk", "head", "heat", "help", "herb", "hill",
    "hint", "hold", "hole", "home", "hood", "hook", "hope", "horn",
    "host", "hour", "huge", "hunt", "idea", "inch", "iron", "isle",
    "item", "jade", "jazz", "join", "joke", "jump", "jury", "just",
    "keen", "keep", "kind", "king", "kite", "knee", "knot", "lake",
    "lamp", "land", "lane", "last", "late", "lawn", "lead", "leaf",
    "lean", "left", "lens", "less", "lift", "lime", "line", "link",
    "lion", "list", "live", "load", "loan", "lock", "logo", "long",
    "loop", "lord", "loud", "love", "luck", "lung", "made", "mail",
    "main", "mask", "mass", "mate", "meal", "melt", "menu", "mild",
    "milk", "mind", "mint", "mole", "moon", "more", "moss", "move",
    "much", "nail", "navy", "neat", "neck", "nest", "news", "nice",
];

/// A refusal with a stable code: `render_bad_params`, `render_undeclared_param`, `render_missing_param`, `render_bad_value`,
/// `render_unresolved_currency`, `psd2_unlinkable`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalError {
    pub code: String,
    pub message: String,
}

fn err<T>(code: &str, message: impl Into<String>) -> Result<T, ApprovalError> {
    Err(ApprovalError { code: code.into(), message: message.into() })
}

fn digest_ok(v: &Value) -> bool {
    v.as_str().and_then(|s| decode_b64u_strict(s, Some(32))).is_some()
}

fn bounded(v: &Value, n: usize) -> bool {
    v.as_str().is_some_and(|s| !s.is_empty() && s.len() <= n)
}

fn u16_key(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn closed(o: &Map<String, Value>, required: &[&str], optional: &[&str]) -> Option<String> {
    for k in o.keys() {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Some(format!("unknown member '{k}'"));
        }
    }
    required.iter().find(|k| !o.contains_key(**k)).map(|k| format!("missing member '{k}'"))
}

/// `None` if `r` is a well-formed render (closed members, sorted unique ids, bounded), else the reason.
pub fn approval_render_shape_error(r: &Value) -> Option<String> {
    let o = match r.as_object() {
        Some(o) => o,
        None => return Some("render must be an object".into()),
    };
    if let Some(e) = closed(o, &["v", "kind", "verb", "def_digest", "unreviewed", "fields"], &[]) {
        return Some(e);
    }
    if safe_int(&o["v"]) != Some(1) || o["kind"] != "pca-approval-render" {
        return Some("not a pca-approval-render v1".into());
    }
    if !bounded(&o["verb"], 128) {
        return Some("verb must be a bounded string".into());
    }
    if !digest_ok(&o["def_digest"]) {
        return Some("def_digest must be canonical base64url (32 bytes)".into());
    }
    if !o["unreviewed"].is_boolean() {
        return Some("unreviewed must be a boolean".into());
    }
    let fs = match o["fields"].as_array() {
        Some(a) if a.len() <= MAX_RENDER_FIELDS => a,
        _ => return Some(format!("fields must be an array of at most {MAX_RENDER_FIELDS}")),
    };
    let mut prev: Option<&str> = None;
    for fv in fs {
        let f = match fv.as_object() {
            Some(f) => f,
            None => return Some("a field must be an object".into()),
        };
        if let Some(e) = closed(f, &["id", "class", "value"], &["unit"]) {
            return Some(e);
        }
        if !bounded(&f["id"], 192) || !bounded(&f["class"], 128) {
            return Some("field id and class must be bounded strings".into());
        }
        let id = f["id"].as_str().unwrap_or_default();
        if prev.is_some_and(|p| u16_key(p) >= u16_key(id)) {
            return Some("fields must be sorted by id and unique".into());
        }
        prev = Some(id);
        if let Some(uv) = f.get("unit") {
            let u = match uv.as_object() {
                Some(u) => u,
                None => return Some("unit must be an object".into()),
            };
            match u.get("kind").and_then(Value::as_str) {
                Some("money") => {
                    let exp = safe_int(u.get("exp").unwrap_or(&Value::Null));
                    if closed(u, &["kind", "ccy", "exp"], &[]).is_some() || !bounded(&u["ccy"], 16) || !exp.is_some_and(|e| (0..=18).contains(&e)) {
                        return Some("a money unit needs ccy and exp".into());
                    }
                }
                Some("count" | "bytes" | "duration" | "ratio") if closed(u, &["kind"], &[]).is_none() => {}
                _ => return Some("unknown unit".into()),
            }
        }
    }
    None
}

/// H(R). A malformed render is an error (a digest is never made over a shapeless value).
pub fn approval_render_digest(render: &Value) -> Result<String, String> {
    if let Some(e) = approval_render_shape_error(render) {
        return Err(format!("approvalRenderDigest: {e}"));
    }
    hash_canonical_strict(&json!({"d": APPROVAL_RENDER_DOMAIN, "render": render})).ok_or_else(|| "approvalRenderDigest: out of the strict profile".to_string())
}

/// b64u(SHA-256(domain || action_digest || H(R))); both digests must be canonical 32-byte values.
pub fn approval_challenge(action_digest: &str, render_digest: &str) -> Result<String, String> {
    match (decode_b64u_strict(action_digest, Some(32)), decode_b64u_strict(render_digest, Some(32))) {
        (Some(a), Some(r)) => {
            let mut h = Sha256::new();
            h.update(APPROVAL_CHALLENGE_DOMAIN.as_bytes());
            h.update(&a);
            h.update(&r);
            Ok(b64_encode(&h.finalize()))
        }
        _ => Err("approvalChallenge: both digests must be canonical 32-byte values".into()),
    }
}

/// The speakable match code of a render digest (six words).
pub fn binding_words(render_digest: &str) -> Result<String, String> {
    let r = decode_b64u_strict(render_digest, Some(32)).ok_or("bindingWords: render digest must be a canonical 32-byte value")?;
    Ok(r.iter().take(6).map(|b| BINDING_WORDS[*b as usize]).collect::<Vec<_>>().join("-"))
}

// ---- the render ------------------------------------------------------------------------------------------------------------

fn flatten(params: &Map<String, Value>) -> Result<Map<String, Value>, ApprovalError> {
    fn walk(out: &mut Map<String, Value>, prefix: &str, depth: usize, v: &Value) -> Result<(), ApprovalError> {
        match v.as_object() {
            Some(m) if depth < MAX_PARAM_PATH_DEPTH && !m.is_empty() => {
                for (k, x) in m {
                    if k.contains('.') {
                        return err("render_bad_params", format!("the parameter key '{k}' contains a dot"));
                    }
                    let np = if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") };
                    walk(out, &np, depth + 1, x)?;
                }
                Ok(())
            }
            _ => {
                out.insert(prefix.to_string(), v.clone());
                Ok(())
            }
        }
    }
    let mut out = Map::new();
    for (k, v) in params {
        if k.contains('.') {
            return err("render_bad_params", format!("the parameter key '{k}' contains a dot"));
        }
        walk(&mut out, k, 1, v)?;
    }
    Ok(out)
}

fn leaf_ok(v: &Value) -> bool {
    match v {
        Value::String(s) => !s.contains(LONE),
        Value::Bool(_) => true,
        Value::Array(a) => a.iter().all(leaf_ok),
        Value::Number(_) => safe_int(v).is_some(),
        _ => false,
    }
}

fn value_ok(ty: &str, v: &Value) -> bool {
    match ty {
        "integer" | "duration" => safe_int(v).is_some(),
        "boolean" => v.is_boolean(),
        "string" | "date" | "datetime" | "object_ref" => v.as_str().is_some_and(|s| !s.contains(LONE)),
        "set" | "array" => v.as_array().is_some_and(|a| a.iter().all(leaf_ok)),
        _ => false,
    }
}

/// The canonical approval render of `def` for `params`. `confirmed`: whether the definition carries a valid signed confirmation
/// (the caller decides, as for `effective`); an unconfirmed render carries `unreviewed: true`.
pub fn render_approval(def: &Value, params: &Value, confirmed: bool) -> Result<Value, ApprovalError> {
    let params = match params.as_object() {
        Some(p) => p,
        None => return err("render_bad_params", "params must be an object"),
    };
    let n = normalize(def);
    let np = n["params"].as_object().cloned().unwrap_or_default();
    let flat = flatten(params)?;
    let verb = n["verb"].as_str().unwrap_or_default().to_string();
    for k in flat.keys() {
        if !np.contains_key(k) {
            return err("render_undeclared_param", format!("'{k}' is not a parameter of {verb}"));
        }
    }
    for (k, p) in &np {
        if p["required"] == Value::Bool(true) && !flat.contains_key(k) {
            return err("render_missing_param", format!("required parameter '{k}' of {verb} is missing"));
        }
    }
    let mut ids: Vec<&String> = flat.keys().collect();
    ids.sort_by_key(|s| u16_key(s));
    let mut fields = Vec::new();
    for id in ids {
        let p = &np[id];
        let ty = p["type"].as_str().unwrap_or_default();
        if !value_ok(ty, &flat[id]) {
            return err("render_bad_value", format!("'{id}' is not a {ty} in the canonical domain"));
        }
        let mut f = Map::new();
        f.insert("id".into(), Value::String(id.clone()));
        f.insert("class".into(), Value::String(p["role"].as_str().unwrap_or("param").to_string()));
        f.insert("value".into(), flat[id].clone());
        if let Some(u) = p.get("unit").and_then(Value::as_object) {
            if u.get("kind").and_then(Value::as_str) == Some("money") {
                let ccy = match &u["ccy"] {
                    Value::String(s) => Some(s.clone()),
                    Value::Object(r) => r.get("from").and_then(Value::as_str).and_then(|from| flat.get(from)).and_then(Value::as_str).map(String::from),
                    _ => None,
                };
                match ccy {
                    Some(c) if !c.is_empty() => {
                        f.insert("unit".into(), json!({"kind": "money", "ccy": c, "exp": u["exp"]}));
                    }
                    _ => return err("render_unresolved_currency", format!("the currency of '{id}' is not a string")),
                }
            } else {
                f.insert("unit".into(), json!({"kind": u["kind"]}));
            }
        }
        fields.push(Value::Object(f));
    }
    let dd = def_digest(def).ok_or(ApprovalError { code: "render_bad_params".into(), message: "the definition is outside the strict profile".into() })?;
    Ok(json!({"v": 1, "kind": "pca-approval-render", "verb": verb, "def_digest": dd, "unreviewed": !confirmed, "fields": fields}))
}

// ---- PSD2 RTS Art. 5 -------------------------------------------------------------------------------------------------------

/// The amount and the payee of a payment render (Art. 5(1)). Code `psd2_unlinkable`.
pub fn psd2_linking(r: &Value) -> Result<Value, ApprovalError> {
    if r["unreviewed"] == Value::Bool(true) {
        return err("psd2_unlinkable", "an unreviewed definition cannot be a payment approval");
    }
    let fs: Vec<&Value> = r["fields"].as_array().map(|a| a.iter().collect()).unwrap_or_default();
    let amts: Vec<&&Value> = fs.iter().filter(|f| f["class"] == "money.amount").collect();
    let payees: Vec<&&Value> = fs.iter().filter(|f| f["class"] == "party.payee").collect();
    if amts.len() != 1 {
        return err("psd2_unlinkable", "a payment approval needs exactly one money.amount parameter");
    }
    let a = amts[0];
    if a["unit"]["kind"] != "money" {
        return err("psd2_unlinkable", "the money.amount parameter has no money unit");
    }
    if !safe_int(&a["value"]).is_some_and(|v| v >= 0) {
        return err("psd2_unlinkable", "the amount must be a non-negative integer in minor units");
    }
    if payees.len() != 1 || !payees[0]["value"].as_str().is_some_and(|s| !s.is_empty()) {
        return err("psd2_unlinkable", "a payment approval needs exactly one non-empty party.payee parameter");
    }
    Ok(json!({"amount_minor": a["value"], "currency": a["unit"]["ccy"], "exp": a["unit"]["exp"], "payee": payees[0]["value"]}))
}

/// Minor units as the decimal string of the major unit, without floating point.
pub fn minor_to_decimal(minor: i64, exp: i64) -> Result<String, ApprovalError> {
    if minor < 0 || !(0..=18).contains(&exp) {
        return err("psd2_unlinkable", "minor units must be a non-negative safe integer");
    }
    let s = minor.to_string();
    if exp == 0 {
        return Ok(s);
    }
    let e = exp as usize;
    let s = format!("{s:0>width$}", width = e + 1);
    Ok(format!("{}.{}", &s[..s.len() - e], &s[s.len() - e..]))
}

/// One approval over N payments: per-currency totals, the payee set and every item (Art. 5(3)(b)). `items` are `{action_digest, render}`.
pub fn approval_batch(items: &[Value]) -> Result<Value, ApprovalError> {
    if items.is_empty() {
        return err("psd2_unlinkable", "a batch needs at least one payment");
    }
    let mut totals: Vec<(String, i64, i64)> = Vec::new();
    let mut payees: Vec<String> = Vec::new();
    let mut leaves = Vec::new();
    for it in items {
        let link = psd2_linking(&it["render"])?;
        let ccy = link["currency"].as_str().unwrap_or_default().to_string();
        let exp = safe_int(&link["exp"]).unwrap_or(0);
        let amt = safe_int(&link["amount_minor"]).unwrap_or(0);
        match totals.iter_mut().find(|t| t.0 == ccy) {
            Some(t) => {
                if t.1 != exp {
                    return err("psd2_unlinkable", format!("currency {ccy} appears with two exponents"));
                }
                if amt > MAX_SAFE - t.2 {
                    return err("psd2_unlinkable", "the batch total exceeds the safe integer range");
                }
                t.2 += amt;
            }
            None => totals.push((ccy, exp, amt)),
        }
        let p = link["payee"].as_str().unwrap_or_default().to_string();
        if !payees.contains(&p) {
            payees.push(p);
        }
        let rd = approval_render_digest(&it["render"]).map_err(|m| ApprovalError { code: "psd2_unlinkable".into(), message: m })?;
        leaves.push(json!({"d": ITEM_DOMAIN, "a": it["action_digest"], "r": rd}));
    }
    totals.sort_by_key(|t| u16_key(&t.0));
    payees.sort_by_key(|p| u16_key(p));
    let tl: Vec<Value> = totals.iter().map(|t| json!({"ccy": t.0, "exp": t.1, "minor": t.2})).collect();
    let pleaves: Vec<Value> = payees.iter().map(|p| json!({"d": PAYEE_DOMAIN, "payee": p})).collect();
    let bad = |m: String| ApprovalError { code: "psd2_unlinkable".into(), message: m };
    let batch = json!({
        "v": 1, "kind": "pca-approval-batch", "n": items.len(), "totals": tl,
        "payees_root": merkle_root(&pleaves).map_err(bad)?, "items_root": merkle_root(&leaves).map_err(bad)?,
    });
    let rd = hash_canonical_strict(&json!({"d": APPROVAL_BATCH_DOMAIN, "batch": batch})).ok_or_else(|| bad("batch outside the strict profile".into()))?;
    let ir = batch["items_root"].as_str().unwrap_or_default().to_string();
    let ch = approval_challenge(&ir, &rd).map_err(bad)?;
    let words = binding_words(&rd).map_err(bad)?;
    Ok(json!({"batch": batch, "action_digest": ir, "render_digest": rd, "challenge": ch, "words": words}))
}

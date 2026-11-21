//! The objective risk functional (port of `objective-risk.ts`): every input of the heuristic risk is a pure function of COMMITTED facts
//! (a registry of verified inverses, a resource graph, an embedder and a goal vector, a calibration set) and of the CANONICAL action.
//! Nothing the agent merely asserts is read. Agent and verifier recompute the same `r`; a commitment mismatch fails closed (`r = 1`,
//! `valid: false`).
//!
//! Every digest here is the LENIENT canonical hash (any finite double, printed as ECMAScript prints it), not the strict wire form.
//!
//! JSON-valued (`&Value` in, the reference's member names out). A number that is not finite is the `{"$num": "NaN"}` marker of the
//! reference's JSON: it is read as that double where a number is read, and refused by every canonical form (`canonicalize: non-finite
//! number`). A reference throw is an `Err` with the reference's message where the message is part of a result.
use std::cmp::Ordering;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::intent_v2::{js_number_string, js_value_string};
use crate::prohibitions::num_value;
use crate::risk::{risk_score, RiskInputs, RiskWeights};

/// The distance metric: `sin(theta / 2)` of the angle between two embeddings.
pub const METRIC: &str = "half-chord-v1";
/// The default rounding grid of a committed distance (1 / 4096).
pub const DEFAULT_EPSILON: f64 = 1.0 / 4096.0;
/// The scheme of the native feature-hashing embedder.
pub const NATIVE_SCHEME: &str = "pca-native-hash-ngram-v1";
/// The cap on flattened param leaves the native embedder enforces even when its config omits `maxParamLeaves`.
pub const DEFAULT_MAX_PARAM_LEAVES: usize = 256;
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// The stock native embedder config.
pub fn default_native_config() -> Value {
    json!({ "dims": 256, "ngramMin": 2, "ngramMax": 4, "seed": "pca-native-v1", "fieldWeights": { "verb": 4, "resource": 2, "param": 1 } })
}

// ---- JavaScript number and string semantics -------------------------------------------------------------------------------------

/// `{"$num": "NaN" | "Infinity" | "-Infinity"}`: the reference's JSON for a number that is not finite.
fn marker(v: &Value) -> Option<f64> {
    let m = v.as_object().filter(|m| m.len() == 1)?;
    match m.get("$num").and_then(Value::as_str)? {
        "NaN" => Some(f64::NAN),
        "Infinity" => Some(f64::INFINITY),
        "-Infinity" => Some(f64::NEG_INFINITY),
        _ => None,
    }
}

/// A JavaScript number: a JSON number or the non-finite marker.
fn num(v: Option<&Value>) -> Option<f64> {
    let v = v?;
    if v.is_number() {
        v.as_f64()
    } else {
        marker(v)
    }
}

/// `ToNumber` of a value (what `Math.max(0, x)` reads).
fn to_number(v: Option<&Value>) -> f64 {
    match v {
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => f64::from(u8::from(*b)),
        Some(Value::String(s)) => {
            let t = s.trim();
            if t.is_empty() {
                0.0
            } else {
                t.parse::<f64>().ok().filter(|_| !t.contains(['_', 'n', 'N', 'i'])).unwrap_or(f64::NAN)
            }
        }
        other => num(other).unwrap_or(f64::NAN),
    }
}

fn is_safe_integer(f: f64) -> bool {
    f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE
}

fn ok_int(v: Option<&Value>, lo: f64, hi: f64) -> bool {
    num(v).is_some_and(|x| is_safe_integer(x) && x >= lo && x <= hi)
}

/// `Math.max` (NaN wins; `0` is above `-0`).
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a > b || (a == b && a.is_sign_positive()) {
        a
    } else {
        b
    }
}

/// `Math.min` (NaN wins; `-0` is below `0`).
fn js_min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else if a < b || (a == b && a.is_sign_negative()) {
        a
    } else {
        b
    }
}

/// `x < 0 ? 0 : x > 1 ? 1 : x` for a finite `x`, else 1 (fail closed).
fn clamp01(x: f64) -> f64 {
    if !x.is_finite() {
        1.0
    } else if x < 0.0 {
        0.0
    } else if x > 1.0 {
        1.0
    } else {
        x
    }
}

/// A JavaScript number as a JSON value.
fn nv(f: f64) -> Value {
    if f == 0.0 && f.is_sign_negative() {
        Value::from(-0.0f64)
    } else if f.is_finite() {
        num_value(f)
    } else {
        json!({ "$num": js_number_string(f) })
    }
}

/// The default string order of JavaScript (`<`): UTF-16 code units.
fn cmp16(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The ECMAScript WhiteSpace and LineTerminator set `String.prototype.trim` strips (not the Unicode `White_Space` property: U+FEFF is
/// in, U+0085 is out).
fn is_js_space(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{D}' | ' ' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{2028}' | '\u{2029}' | '\u{202F}' | '\u{205F}' | '\u{3000}' | '\u{FEFF}')
}

fn nfc(s: &str) -> String {
    s.nfc().collect()
}

// ---- the lenient canonical form ---------------------------------------------------------------------------------------------------

const NON_FINITE: &str = "canonicalize: non-finite number";

/// Whether the value carries a non-finite marker anywhere.
fn has_marker(v: &Value) -> bool {
    match v {
        Value::Array(a) => a.iter().any(has_marker),
        Value::Object(m) => marker(v).is_some() || m.values().any(has_marker),
        _ => false,
    }
}

/// The lenient canonical JSON of a value: keys in UTF-8 order, any finite double as ECMAScript prints it; a non-finite number is
/// refused.
fn lenient_json(v: &Value) -> Result<String, String> {
    if has_marker(v) {
        return Err(NON_FINITE.into());
    }
    Ok(crate::canonicalize(v))
}

fn lenient_hash(v: &Value) -> Result<String, String> {
    if has_marker(v) {
        return Err(NON_FINITE.into());
    }
    Ok(crate::hash_canonical(v))
}

// ---- the canonical action ---------------------------------------------------------------------------------------------------------

fn norm_value(v: &Value) -> Result<Value, String> {
    Ok(match v {
        Value::String(s) => Value::String(nfc(s)),
        Value::Array(a) => Value::Array(a.iter().map(norm_value).collect::<Result<Vec<_>, _>>()?),
        Value::Object(m) => {
            let mut out = Map::new();
            for (k, x) in m {
                let nk = nfc(k);
                if out.contains_key(&nk) {
                    return Err("canonicalAction: duplicate key after NFC normalization".into());
                }
                out.insert(nk, norm_value(x)?);
            }
            Value::Object(out)
        }
        other => other.clone(),
    })
}

/// The canonical form of a submitted action `{verb, resource, params?}`: the verb NFC, trimmed and lower-cased, the resource NFC and
/// trimmed, every string and key of the params NFC; `{verb, resource, params}`. Re-encodings that do not change the action (key order,
/// NFC / NFD, verb case) collapse to one form. `Err` for anything without a stable encoding.
pub fn canonical_action(a: &Value) -> Result<Value, String> {
    let (Some(verb), Some(resource)) = (a.get("verb").and_then(Value::as_str), a.get("resource").and_then(Value::as_str)) else {
        return Err("canonicalAction: verb/resource must be strings".into());
    };
    let verb = nfc(verb).trim_matches(is_js_space).to_lowercase();
    let resource = nfc(resource).trim_matches(is_js_space).to_string();
    if verb.is_empty() || resource.is_empty() {
        return Err("canonicalAction: empty verb/resource".into());
    }
    let params = match a.get("params") {
        None | Some(Value::Null) => json!({}),
        Some(p) => norm_value(p)?,
    };
    if !params.is_object() {
        return Err("canonicalAction: params must be an object".into());
    }
    let c = json!({ "verb": verb, "resource": resource, "params": params });
    lenient_json(&c)?;
    Ok(c)
}

/// The lenient canonical JSON text of a canonical action.
pub fn canonical_action_json(c: &Value) -> Result<String, String> {
    lenient_json(c)
}

/// The lenient canonical hash of a canonical action.
pub fn canonical_action_digest(c: &Value) -> Result<String, String> {
    lenient_hash(c)
}

// ---- 1. reversibility -------------------------------------------------------------------------------------------------------------

/// A committed registry of verified inverses.
pub trait InverseRegistry {
    fn lookup(&self, verb: &str) -> Option<Value>;
    /// Verifier ids whose verification counts; committed as part of the digest.
    fn trusted_verifiers(&self) -> Vec<String>;
    /// The canonical digest of ALL contents; the grant commits this.
    fn digest(&self) -> Result<String, String>;
}

/// The in-memory registry: the trusted verifier ids (de-duplicated and sorted) and the entry of each verb
/// `{inverseKind, fidelity, verification?: {verifierId, evidenceDigest}}`; a later entry for a verb replaces the earlier one.
#[derive(Debug, Clone, Default)]
pub struct InMemoryInverseRegistry {
    trusted: Vec<String>,
    entries: HashMap<String, Value>,
}

impl InMemoryInverseRegistry {
    pub fn new(trusted_verifiers: &[String]) -> Self {
        let mut trusted: Vec<String> = trusted_verifiers.to_vec();
        trusted.sort_by(|a, b| cmp16(a, b));
        trusted.dedup();
        InMemoryInverseRegistry { trusted, entries: HashMap::new() }
    }

    pub fn register(&mut self, verb: &str, entry: &Value) -> &mut Self {
        self.entries.insert(verb.to_string(), entry.clone());
        self
    }
}

impl InverseRegistry for InMemoryInverseRegistry {
    fn lookup(&self, verb: &str) -> Option<Value> {
        self.entries.get(verb).cloned()
    }

    fn trusted_verifiers(&self) -> Vec<String> {
        self.trusted.clone()
    }

    fn digest(&self) -> Result<String, String> {
        let mut verbs: Vec<&String> = self.entries.keys().collect();
        verbs.sort_by(|a, b| cmp16(a, b));
        let entries: Vec<Value> = verbs
            .into_iter()
            .map(|verb| {
                let e = &self.entries[verb];
                let mut row = Map::new();
                row.insert("verb".into(), json!(verb));
                for k in ["inverseKind", "fidelity"] {
                    if let Some(v) = e.get(k) {
                        row.insert(k.into(), v.clone());
                    }
                }
                row.insert("verification".into(), e.get("verification").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Null));
                Value::Object(row)
            })
            .collect();
        lenient_hash(&json!({ "v": 1, "trusted": self.trusted, "entries": entries }))
    }
}

/// `{class, value, inverseKind?}`: reversible (value 1) iff the registry holds an inverse whose verification came from a TRUSTED
/// verifier AND the inverse verb is itself authorized by the capability, and the fidelity is `exact`; the same with any other fidelity
/// is compensable (0.5); anything else is irreversible (0). The verb is looked up exactly as given; inverses of inverses are not chased.
pub fn reversibility(action: &Value, registry: &dyn InverseRegistry, authorized_kinds: &BTreeSet<String>) -> Value {
    let irreversible = json!({ "class": "irreversible", "value": 0 });
    let Some(e) = action.get("verb").and_then(Value::as_str).and_then(|v| registry.lookup(v)) else { return irreversible };
    let trusted = e
        .get("verification")
        .filter(|v| !v.is_null())
        .is_some_and(|v| v.get("verifierId").and_then(Value::as_str).is_some_and(|id| registry.trusted_verifiers().iter().any(|t| t == id)));
    let Some(kind) = e.get("inverseKind").and_then(Value::as_str).filter(|k| trusted && authorized_kinds.contains(*k)) else { return irreversible };
    if e.get("fidelity").and_then(Value::as_str) == Some("exact") {
        json!({ "class": "reversible", "value": 1, "inverseKind": kind })
    } else {
        json!({ "class": "compensable", "value": 0.5, "inverseKind": kind })
    }
}

// ---- 2. blast radius ----------------------------------------------------------------------------------------------------------------

/// An adjacency model with a content digest the grant commits.
#[derive(Debug, Clone, Default)]
pub struct ResourceGraph {
    /// Node ids in insertion order.
    order: Vec<String>,
    nodes: HashMap<String, Value>,
    out: HashMap<String, Vec<Value>>,
}

impl ResourceGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a node `{id, harm?: {unit: number}}`; the same id again replaces the node and keeps its edges.
    pub fn add_node(&mut self, n: &Value) -> Result<&mut Self, String> {
        let id = n.get("id").and_then(Value::as_str).ok_or("node id must be a string")?.to_string();
        if !self.nodes.contains_key(&id) {
            self.order.push(id.clone());
        }
        self.nodes.insert(id.clone(), n.clone());
        self.out.entry(id).or_default();
        Ok(self)
    }

    /// Adds an edge `{from, to, kind}`; `Err` when an endpoint is not a node.
    pub fn add_edge(&mut self, e: &Value) -> Result<&mut Self, String> {
        let (from, to) = (e.get("from").and_then(Value::as_str), e.get("to").and_then(Value::as_str));
        match (from, to) {
            (Some(f), Some(t)) if self.nodes.contains_key(f) && self.nodes.contains_key(t) => {
                self.out.entry(f.to_string()).or_default().push(e.clone());
                Ok(self)
            }
            _ => Err("edge endpoints must exist".into()),
        }
    }

    pub fn size(&self) -> usize {
        self.nodes.len()
    }

    pub fn node(&self, id: &str) -> Option<&Value> {
        self.nodes.get(id)
    }

    /// The BFS reachable set (including `start`), restricted by the scope's `edgeKinds` and `maxDepth`, sorted (UTF-16 order). An
    /// unknown start reaches nothing.
    pub fn reachable(&self, start: &str, scope: Option<&Value>) -> Vec<String> {
        if !self.nodes.contains_key(start) {
            return Vec::new();
        }
        let kinds: Option<Vec<&str>> = scope.and_then(|s| s.get("edgeKinds")).filter(|k| !k.is_null()).map(|k| k.as_array().map(|a| a.iter().filter_map(Value::as_str).collect()).unwrap_or_default());
        let max_depth = match scope.and_then(|s| s.get("maxDepth")).filter(|d| !d.is_null()) {
            None => f64::INFINITY,
            Some(d) => to_number(Some(d)),
        };
        let mut seen: Vec<String> = vec![start.to_string()];
        let mut frontier: Vec<String> = vec![start.to_string()];
        let mut depth = 0.0;
        while depth < max_depth && !frontier.is_empty() {
            let mut next: Vec<String> = Vec::new();
            for u in &frontier {
                for e in self.out.get(u).map(Vec::as_slice).unwrap_or(&[]) {
                    let Some(to) = e.get("to").and_then(Value::as_str) else { continue };
                    let allowed = kinds.as_ref().is_none_or(|k| e.get("kind").and_then(Value::as_str).is_some_and(|ek| k.contains(&ek)));
                    if allowed && !seen.iter().any(|s| s == to) {
                        seen.push(to.to_string());
                        next.push(to.to_string());
                    }
                }
            }
            frontier = next;
            depth += 1.0;
        }
        seen.sort_by(|a, b| cmp16(a, b));
        seen
    }

    /// The digest of the whole graph: its nodes (with their harm) and edges, each sorted. `Err` for a node whose harm cannot be
    /// canonicalized (a non-finite weight).
    pub fn digest(&self) -> Result<String, String> {
        let mut nodes: Vec<(&String, Value)> = self.nodes.iter().map(|(id, n)| (id, json!({ "id": id, "harm": n.get("harm").filter(|h| !h.is_null()).cloned().unwrap_or_else(|| json!({})) }))).collect();
        nodes.sort_by(|a, b| cmp16(a.0, b.0));
        let mut edges: Vec<(String, Value)> = Vec::new();
        for id in &self.order {
            for e in &self.out[id] {
                let mut row = Map::new();
                for k in ["from", "to", "kind"] {
                    if let Some(v) = e.get(k) {
                        row.insert(k.into(), v.clone());
                    }
                }
                let text = |k: &str| e.get(k).map(js_value_string).unwrap_or_else(|| "undefined".into());
                edges.push((format!("{}\u{0}{}\u{0}{}", text("from"), text("to"), text("kind")), Value::Object(row)));
            }
        }
        edges.sort_by(|a, b| cmp16(&a.0, &b.0));
        lenient_hash(&json!({ "v": 1, "n": nodes.into_iter().map(|n| n.1).collect::<Vec<_>>(), "e": edges.into_iter().map(|e| e.1).collect::<Vec<_>>() }))
    }
}

/// `{count, reachable, normalized, harm}`: the resources reachable from the action's resource, their share of the graph (an unknown
/// resource or an empty graph is 1: fail closed), and the summed harm per denomination (only finite values above 0 count).
pub fn blast_radius(action: &Value, graph: &ResourceGraph, scope: Option<&Value>) -> Value {
    let reachable = action.get("resource").and_then(Value::as_str).map(|r| graph.reachable(r, scope)).unwrap_or_default();
    if reachable.is_empty() || graph.size() == 0 {
        return json!({ "count": 0, "reachable": reachable, "normalized": 1, "harm": {} });
    }
    let mut harm: Vec<(String, f64)> = Vec::new();
    for id in &reachable {
        let Some(units) = graph.node(id).and_then(|n| n.get("harm")).and_then(Value::as_object) else { continue };
        for (d, v) in units {
            if let Some(x) = v.as_f64().filter(|x| v.is_number() && x.is_finite() && *x > 0.0) {
                match harm.iter_mut().find(|(k, _)| *k == *d) {
                    Some((_, sum)) => *sum += x,
                    None => harm.push((d.clone(), x)),
                }
            }
        }
    }
    let harm: Map<String, Value> = harm.into_iter().map(|(k, v)| (k, nv(v))).collect();
    json!({ "count": reachable.len(), "reachable": reachable, "normalized": nv(reachable.len() as f64 / graph.size() as f64), "harm": harm })
}

// ---- 3. committed embeddings --------------------------------------------------------------------------------------------------------

/// An embedder maps the CANONICAL action to an integer vector. It never sees agent-supplied features. Its `model_id` is a committed
/// identity: a hash of its config (native) or of its descriptor (BYO).
pub trait Embedder {
    fn model_id(&self) -> String;
    /// The committed descriptor behind the model id.
    fn config(&self) -> Value;
    fn dims(&self) -> f64;
    /// `dims` safe integers, deterministic for equal canonical actions; `Err` when the embedding fails. The result is NOT trusted:
    /// [`validate_vector`] is applied to it.
    fn embed(&self, action: &Value) -> Result<Value, String>;
}

/// The largest |component| such that dot products of two `dims`-vectors stay exact in a double.
fn max_component(dims: f64) -> f64 {
    (MAX_SAFE / (2.0 * js_max(1.0, dims))).sqrt().floor()
}

/// A vector of exactly `dims` safe integers within the exactness limit; `-0` becomes 0.
pub fn validate_vector(v: &Value, dims: f64) -> Result<Vec<i64>, String> {
    let list = v.as_array().filter(|l| l.len() as f64 == dims).ok_or_else(|| format!("vector must have exactly {} components", js_number_string(dims)))?;
    let lim = max_component(dims);
    let mut out = Vec::with_capacity(list.len());
    for x in list {
        let f = x.is_number().then(|| x.as_f64()).flatten().filter(|f| is_safe_integer(*f)).ok_or("vector components must be safe integers")?;
        if f.abs() > lim {
            return Err("vector component out of range".into());
        }
        out.push(f as i64);
    }
    Ok(out)
}

static WORDS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"[^\p{L}\p{N}]+").expect("word split"));

/// Code-point n-grams of `U+0002 text U+0003` for each n in the range, then the lower-cased word tokens.
fn text_features(prefix: &str, text: &str, nmin: usize, nmax: usize) -> Vec<String> {
    let mut out = Vec::new();
    let cps: Vec<char> = std::iter::once('\u{2}').chain(text.chars()).chain(std::iter::once('\u{3}')).collect();
    for n in nmin..=nmax {
        for i in 0..cps.len().saturating_sub(n - 1) {
            if i + n <= cps.len() {
                out.push(format!("{prefix}c{n}:{}", cps[i..i + n].iter().collect::<String>()));
            }
        }
    }
    for w in WORDS.split(text).filter(|w| !w.is_empty()) {
        out.push(format!("{prefix}w:{}", w.to_lowercase()));
    }
    out
}

/// Flattens params into `path=value` leaves; an empty object or array adds none.
fn param_leaves(v: &Value, path: &str, out: &mut Vec<String>) -> Result<(), String> {
    match v {
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                param_leaves(x, &format!("{path}[{i}]"), out)?;
            }
        }
        Value::Object(m) if marker(v).is_none() => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            for k in keys {
                param_leaves(&m[k.as_str()], &if path.is_empty() { k.clone() } else { format!("{path}.{k}") }, out)?;
            }
        }
        scalar => out.push(format!("{path}={}", lenient_json(scalar)?)),
    }
    Ok(())
}

/// The native embedder: integer feature hashing over the n-grams and words of the canonical action. Each feature `f` is hashed as
/// SHA-256(seed 0x1F f); its bucket is the big-endian u32 of the first four bytes mod `dims`, its sign the low bit of the fifth byte,
/// and the bucket accumulates the field weight with that sign.
#[derive(Debug, Clone)]
pub struct NativeEmbedder {
    model_id: String,
    committed: Value,
    dims: usize,
    ngram_min: usize,
    ngram_max: usize,
    seed: String,
    weights: [i64; 3],
    max_param_leaves: usize,
    digest_params: bool,
}

/// A native embedder over a config `{dims, ngramMin, ngramMax, seed, fieldWeights: {verb, resource, param}, maxParamLeaves?,
/// paramMode?}`; `Err` for a config out of bounds. The committed config (and so the model id) keeps an absent `maxParamLeaves` or
/// `paramMode` absent.
pub fn native_hash_embedder(config: &Value) -> Result<NativeEmbedder, String> {
    let get = |k: &str| config.get(k);
    if !ok_int(get("dims"), 8.0, 65536.0) {
        return Err("native config: dims must be an integer in [8, 65536]".into());
    }
    let nmin = num(get("ngramMin")).unwrap_or(f64::NAN);
    if !ok_int(get("ngramMin"), 1.0, 8.0) || !ok_int(get("ngramMax"), nmin, 8.0) {
        return Err("native config: need 1 <= ngramMin <= ngramMax <= 8".into());
    }
    let seed = get("seed").and_then(Value::as_str).filter(|s| !s.is_empty()).ok_or("native config: seed required")?;
    let fw = get("fieldWeights").ok_or("Cannot read properties of undefined (reading 'verb')")?;
    for k in ["verb", "resource", "param"] {
        if !ok_int(fw.get(k), 0.0, 1000.0) {
            return Err(format!("native config: fieldWeights.{k} must be an integer in [0, 1000]"));
        }
    }
    if let Some(m) = get("maxParamLeaves") {
        if !ok_int(Some(m), 1.0, 1_000_000.0) {
            return Err("native config: maxParamLeaves must be an integer in [1, 1000000]".into());
        }
    }
    if let Some(m) = get("paramMode") {
        if !matches!(m.as_str(), Some("leaves" | "digest")) {
            return Err("native config: paramMode must be 'leaves' or 'digest'".into());
        }
    }
    let mut committed = Map::new();
    committed.insert("scheme".into(), json!(NATIVE_SCHEME));
    for (k, v) in config.as_object().into_iter().flatten() {
        committed.insert(k.clone(), v.clone());
    }
    let committed = Value::Object(committed);
    let model_id = format!("native:{}", lenient_hash(&committed)?);
    let int = |v: Option<&Value>| num(v).unwrap_or(0.0);
    Ok(NativeEmbedder {
        model_id,
        committed,
        dims: int(get("dims")) as usize,
        ngram_min: nmin as usize,
        ngram_max: int(get("ngramMax")) as usize,
        seed: seed.to_string(),
        weights: [int(fw.get("verb")) as i64, int(fw.get("resource")) as i64, int(fw.get("param")) as i64],
        max_param_leaves: get("maxParamLeaves").map_or(DEFAULT_MAX_PARAM_LEAVES, |m| int(Some(m)) as usize),
        digest_params: get("paramMode").and_then(Value::as_str) == Some("digest"),
    })
}

impl NativeEmbedder {
    fn add(&self, v: &mut [i64], feature: &str, w: i64) {
        if w == 0 {
            return;
        }
        let mut h = Sha256::new();
        h.update(self.seed.as_bytes());
        h.update([0x1f]);
        h.update(feature.as_bytes());
        let d = h.finalize();
        let bucket = (u32::from_be_bytes([d[0], d[1], d[2], d[3]]) as usize) % self.dims;
        v[bucket] += if d[4] & 1 == 0 { w } else { -w };
    }
}

impl Embedder for NativeEmbedder {
    fn model_id(&self) -> String {
        self.model_id.clone()
    }

    fn config(&self) -> Value {
        self.committed.clone()
    }

    fn dims(&self) -> f64 {
        self.dims as f64
    }

    fn embed(&self, a: &Value) -> Result<Value, String> {
        let text = |k: &str| a.get(k).and_then(Value::as_str).ok_or_else(|| "Cannot read properties of undefined (reading 'normalize')".to_string());
        let mut v = vec![0i64; self.dims];
        for f in text_features("v:", text("verb")?, self.ngram_min, self.ngram_max) {
            self.add(&mut v, &f, self.weights[0]);
        }
        for f in text_features("r:", text("resource")?, self.ngram_min, self.ngram_max) {
            self.add(&mut v, &f, self.weights[1]);
        }
        let params = a.get("params").cloned().unwrap_or(Value::Null);
        let mut leaves = Vec::new();
        param_leaves(&params, "", &mut leaves)?;
        // fail CLOSED on a param-stuffed action: more leaves than the cap can never produce a (diluted) favorable embedding
        if leaves.len() > self.max_param_leaves {
            return Err(format!("param leaf count {} exceeds cap {}", leaves.len(), self.max_param_leaves));
        }
        if self.digest_params {
            let token = lenient_hash(&json!({ "t": "pca-objrisk-params-v1", "params": params }))?;
            self.add(&mut v, &format!("p#:{token}"), self.weights[2]);
        } else {
            for leaf in &leaves {
                for f in text_features("p:", leaf, self.ngram_min, self.ngram_max) {
                    self.add(&mut v, &f, self.weights[2]);
                }
            }
        }
        Ok(Value::Array(v.into_iter().map(Value::from).collect()))
    }
}

/// The model id of a BYO descriptor: `byo:` + the lenient hash of the descriptor.
pub fn byo_model_id(descriptor: &Value) -> Result<String, String> {
    Ok(format!("byo:{}", lenient_hash(descriptor)?))
}

/// The inference of a BYO embedder: the canonical action JSON in, a vector out.
pub type InferFn = Box<dyn Fn(&str) -> Result<Value, String>>;

/// A customer-supplied model that meets the determinism contract (pinned weights, fixed-point inference, the canonical action JSON as
/// input, fixed `dims` and `quantization`).
pub struct ByoEmbedder {
    model_id: String,
    descriptor: Value,
    dims: f64,
    qmax: f64,
    infer: InferFn,
}

/// `x > 0` as JavaScript evaluates it: a numeric string and a boolean are coerced (ToNumber), anything else is not greater than zero.
fn js_gt_zero(x: &Value) -> bool {
    match x {
        Value::Number(n) => n.as_f64().is_some_and(|f| f > 0.0),
        Value::Bool(b) => *b,
        Value::String(t) => {
            let t = t.trim();
            !t.is_empty() && t.bytes().all(|c| c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-')) && t.parse::<f64>().is_ok_and(|f| f > 0.0)
        }
        _ => false,
    }
}

/// A BYO embedder: `Err` for a bad descriptor (dims a positive integer, `quantization.bits` 2..31, `quantization.scale` > 0,
/// `inputEncoding` exactly `pca-canonical-action-json-v1`) or a claimed model id that is not the descriptor hash.
pub fn byo_embedder(descriptor: &Value, infer: InferFn, claimed_model_id: Option<&str>) -> Result<ByoEmbedder, String> {
    let dims = num(descriptor.get("dims")).filter(|d| is_safe_integer(*d) && *d >= 1.0).ok_or("byo: dims must be a positive integer")?;
    let q = descriptor.get("quantization").filter(|q| !q.is_null()).ok_or("Cannot read properties of undefined (reading 'bits')")?;
    let bits = num(q.get("bits"));
    if !bits.is_some_and(|b| is_safe_integer(b) && (2.0..=31.0).contains(&b)) || !q.get("scale").is_some_and(|s| js_gt_zero(s)) {
        return Err("byo: invalid quantization".into());
    }
    if descriptor.get("inputEncoding").and_then(Value::as_str) != Some("pca-canonical-action-json-v1") {
        return Err("byo: unsupported inputEncoding".into());
    }
    let model_id = byo_model_id(descriptor)?;
    if claimed_model_id.is_some_and(|c| c != model_id) {
        return Err("byo: modelId does not match the committed descriptor".into());
    }
    Ok(ByoEmbedder { model_id, descriptor: descriptor.clone(), dims, qmax: 2f64.powf(bits.unwrap_or(0.0) - 1.0) - 1.0, infer })
}

impl Embedder for ByoEmbedder {
    fn model_id(&self) -> String {
        self.model_id.clone()
    }

    fn config(&self) -> Value {
        self.descriptor.clone()
    }

    fn dims(&self) -> f64 {
        self.dims
    }

    fn embed(&self, a: &Value) -> Result<Value, String> {
        let v = validate_vector(&(self.infer)(&canonical_action_json(a)?)?, self.dims)?;
        if v.iter().any(|x| (*x as f64).abs() > self.qmax) {
            return Err("byo: component exceeds declared quantization range".into());
        }
        Ok(Value::Array(v.into_iter().map(Value::from).collect()))
    }
}

/// Runs conformance cases `{action, vector}` shipped with a model: true iff every one reproduces exactly.
pub fn conformance_check(e: &dyn Embedder, cases: &[Value]) -> bool {
    cases.iter().all(|c| {
        let Ok(v) = canonical_action(&c["action"]).and_then(|a| e.embed(&a)) else { return false };
        match (v.as_array(), c.get("vector").and_then(Value::as_array)) {
            (Some(got), Some(want)) => got.len() == want.len() && got.iter().zip(want).all(|(x, y)| num(Some(x)) == num(Some(y))),
            _ => false,
        }
    })
}

// ---- goal commitment and distance -------------------------------------------------------------------------------------------------------

fn goal_commit_input(g: &Value) -> Value {
    let mut m = Map::new();
    for k in ["embedderModelId", "config", "goalVector", "metric", "epsilon"] {
        if let Some(v) = g.get(k) {
            m.insert(k.into(), v.clone());
        }
    }
    Value::Object(m)
}

/// Embeds the goal's CANONICAL action and binds it to this embedder: `{embedderModelId, config, goalVector, metric, epsilon,
/// commit}`. `Err` for an `epsilon` outside (0, 1] or any invalid input.
pub fn commit_goal(embedder: &dyn Embedder, goal_action: &Value, epsilon: f64) -> Result<Value, String> {
    if !(epsilon > 0.0 && epsilon <= 1.0) {
        return Err("epsilon must be in (0, 1]".into());
    }
    let goal_vector = validate_vector(&embedder.embed(&canonical_action(goal_action)?)?, embedder.dims())?;
    let mut g = json!({ "embedderModelId": embedder.model_id(), "config": embedder.config(), "goalVector": goal_vector, "metric": METRIC, "epsilon": nv(epsilon) });
    g["commit"] = json!(lenient_hash(&goal_commit_input(&g))?);
    Ok(g)
}

/// Verifies the commitment hashes AND that the goal is bound to exactly this embedder (id, config, dims): `None` when valid, else the
/// first failing reason (metric, epsilon, commit hash, model id, config, vector); a thrown error's message is the reason.
pub fn verify_goal_commitment(g: &Value, embedder: &dyn Embedder) -> Option<String> {
    let check = || -> Result<Option<&'static str>, String> {
        if g.is_null() {
            return Err("Cannot read properties of null (reading 'metric')".into());
        }
        if g.get("metric").and_then(Value::as_str) != Some(METRIC) {
            return Ok(Some("unknown metric"));
        }
        let eps = to_number(g.get("epsilon"));
        if !(eps > 0.0 && eps <= 1.0) {
            return Ok(Some("bad epsilon"));
        }
        if g.get("commit").and_then(Value::as_str) != Some(lenient_hash(&goal_commit_input(g))?.as_str()) {
            return Ok(Some("goal commitment hash mismatch"));
        }
        if g.get("embedderModelId").and_then(Value::as_str) != Some(embedder.model_id().as_str()) {
            return Ok(Some("embedder modelId mismatch"));
        }
        if lenient_hash(g.get("config").unwrap_or(&Value::Null))? != lenient_hash(&embedder.config())? {
            return Ok(Some("embedder config mismatch"));
        }
        validate_vector(g.get("goalVector").unwrap_or(&Value::Null), embedder.dims())?;
        Ok(None)
    };
    match check() {
        Ok(reason) => reason.map(String::from),
        Err(e) => Some(e),
    }
}

/// Integer vectors to `sin(theta / 2) = sqrt((1 - cos) / 2)`, rounded UP to the `epsilon` grid, clamped to [0, 1]; vectors of different
/// length, or a zero vector, are at distance 1, identical vectors at 0. Only IEEE `*`, `+`, `/` and `sqrt`, in this order (no fused
/// multiply-add), so every implementation rounds the same.
pub fn vector_distance(a: &[f64], b: &[f64], epsilon: f64) -> f64 {
    if a.len() != b.len() {
        return 1.0;
    }
    let (mut dot, mut na, mut nb, mut same) = (0.0, 0.0, 0.0, true);
    for i in 0..a.len() {
        dot += a[i] * b[i];
        na += a[i] * a[i];
        nb += b[i] * b[i];
        if a[i] != b[i] {
            same = false;
        }
    }
    if na == 0.0 || nb == 0.0 {
        return 1.0;
    }
    if same {
        return 0.0;
    }
    let cos = js_max(-1.0, js_min(1.0, dot / (na * nb).sqrt()));
    let d = ((1.0 - cos) / 2.0).sqrt();
    if d < 1e-9 {
        return 0.0; // float noise floor, far below epsilon
    }
    clamp01((d / epsilon).ceil() * epsilon)
}

/// The distance of a canonical action to the committed goal; `Err(reason)` (distance 1) on any commitment or embedding failure.
pub fn committed_distance_checked(action: &Value, goal: &Value, embedder: &dyn Embedder) -> Result<f64, String> {
    if let Some(bad) = verify_goal_commitment(goal, embedder) {
        return Err(bad);
    }
    let v = validate_vector(&embedder.embed(action)?, embedder.dims())?;
    let goal_vector: Vec<f64> = goal.get("goalVector").and_then(Value::as_array).into_iter().flatten().map(|x| to_number(Some(x))).collect();
    let v: Vec<f64> = v.into_iter().map(|x| x as f64).collect();
    Ok(vector_distance(&v, &goal_vector, to_number(goal.get("epsilon"))))
}

/// Accepts an agent submission, canonicalizes it and returns the distance (1 on any failure).
pub fn committed_distance(action: &Value, goal: &Value, embedder: &dyn Embedder) -> f64 {
    canonical_action(action).and_then(|c| committed_distance_checked(&c, goal, embedder)).unwrap_or(1.0)
}

// ---- 4. split-conformal calibration ------------------------------------------------------------------------------------------------------

/// The calibrated risk of a raw score against held-out benign scores: `1 - (1 + #{s >= raw}) / (n + 1)`, non-decreasing in `raw`; an
/// empty set or a non-finite raw score is 1.
pub fn calibrate(raw_score: f64, benign_scores: &[f64]) -> f64 {
    let n = benign_scores.len();
    if n == 0 || !raw_score.is_finite() {
        return 1.0;
    }
    let ge = benign_scores.iter().filter(|s| **s >= raw_score).count();
    1.0 - (1.0 + ge as f64) / (n as f64 + 1.0)
}

/// `Array.prototype.sort((a, b) => a - b)` of V8 for an array shorter than 64 (a natural-run detection, then a binary insertion sort), which
/// is what a comparator that answers NaN for a NaN element sees; a longer array is sorted stably.
fn js_numeric_sort(v: &[f64]) -> Vec<f64> {
    let mut a = v.to_vec();
    let n = a.len();
    if n >= 64 {
        a.sort_by(|x, y| (x - y).partial_cmp(&0.0).unwrap_or(Ordering::Equal));
        return a;
    }
    if n < 2 {
        return a;
    }
    let less = |x: f64, y: f64| x - y < 0.0;
    // the natural run at the start
    let mut run = 2;
    let descending = less(a[1], a[0]);
    let mut idx = 2;
    while idx < n {
        let ord_less = less(a[idx], a[idx - 1]);
        if descending && !ord_less || !descending && ord_less {
            break;
        }
        run += 1;
        idx += 1;
    }
    if descending {
        a[..run].reverse();
    }
    for start in run..n {
        let (mut left, mut right) = (0, start);
        let pivot = a[start];
        while left < right {
            let mid = left + ((right - left) >> 1);
            if less(pivot, a[mid]) {
                right = mid;
            } else {
                left = mid + 1;
            }
        }
        let mut p = start;
        while p > left {
            a[p] = a[p - 1];
            p -= 1;
        }
        a[left] = pivot;
    }
    a
}

/// The split-conformal quantile: a benign raw score is at most it with probability `>= 1 - alpha`. Infinity when the set is too small;
/// `None` when the reference's index falls outside the sorted set (`alpha >= 1`, or a NaN `alpha`).
pub fn conformal_threshold(benign_scores: &[f64], alpha: f64) -> Option<f64> {
    let n = benign_scores.len() as f64;
    let k = ((n + 1.0) * (1.0 - alpha)).ceil();
    if n == 0.0 || k > n {
        return Some(f64::INFINITY);
    }
    let i = k - 1.0;
    if !(i >= 0.0 && i.fract() == 0.0) {
        return None;
    }
    js_numeric_sort(benign_scores).get(i as usize).copied()
}

/// The digest of a calibration set, committed by the grant: the lenient hash of `{v: 1, scores}` over the numerically sorted scores.
/// `Err` for a non-finite score.
pub fn calibration_digest(scores: &[f64]) -> Result<String, String> {
    if scores.iter().any(|s| !s.is_finite()) {
        return Err(NON_FINITE.into());
    }
    lenient_hash(&json!({ "v": 1, "scores": js_numeric_sort(scores).into_iter().map(nv).collect::<Vec<_>>() }))
}

// ---- 5. harm currency ---------------------------------------------------------------------------------------------------------------------

/// `{units, normalized}`: the weighted saturating normalization in [0, 1] of the harm units over the denominations
/// `{id, ceiling, weight}` (a denomination with a weight or ceiling that is not above 0 is skipped; none counted is 1). `units` is
/// returned as given.
pub fn harm_report(units: &Value, denoms: &[Value]) -> Value {
    let (mut sum, mut den) = (0.0, 0.0);
    for d in denoms {
        let (weight, ceiling) = (num(d.get("weight")).unwrap_or(f64::NAN), num(d.get("ceiling")).unwrap_or(f64::NAN));
        if !(weight > 0.0) || !(ceiling > 0.0) {
            continue;
        }
        // own members only: a denomination named like an Object.prototype member reads 0
        let u = d.get("id").and_then(Value::as_str).and_then(|id| units.get(id)).map_or(0.0, |u| to_number(Some(u)));
        sum += weight * js_min(1.0, js_max(0.0, u) / ceiling);
        den += weight;
    }
    json!({ "units": units, "normalized": nv(if den == 0.0 { 1.0 } else { clamp01(sum / den) }) })
}

// ---- composition ----------------------------------------------------------------------------------------------------------------------------

/// What an objective risk is computed from.
pub struct ObjectiveRiskContext<'a> {
    pub registry: &'a dyn InverseRegistry,
    pub authorized_kinds: &'a BTreeSet<String>,
    pub graph: &'a ResourceGraph,
    /// `{edgeKinds?, maxDepth?}` from the grant, never from the agent.
    pub scope: Option<&'a Value>,
    pub embedder: &'a dyn Embedder,
    /// The committed goal.
    pub goal: &'a Value,
    /// The digests the grant committed `{registryDigest, graphDigest, calibrationDigest?}`.
    pub commitments: &'a Value,
    pub denominations: &'a [Value],
    /// `{alpha, beta, gamma, delta, epsilon, zeta}`.
    pub weights: &'a Value,
    /// The verifier-computed information-flow taint.
    pub taint: f64,
    pub age: f64,
    /// Uncertainty from the uncertainty attestation (higher is more uncertain); it can only RAISE `r`.
    pub attested_uncertainty: Option<f64>,
    /// Committed benign raw scores: `r` becomes the conformal-calibrated value.
    pub calibration: Option<&'a [f64]>,
}

fn sorted_strings(list: Vec<&str>) -> Vec<String> {
    let mut l: Vec<String> = list.into_iter().map(String::from).collect();
    l.sort_by(|a, b| cmp16(a, b));
    l
}

fn reject(reasons: Vec<String>) -> Value {
    json!({
        "r": 1, "valid": false, "reasons": reasons, "raw": 1,
        "inputs": { "semanticDistance": 1, "reversibility": 0, "blastRadius": 1, "taint": 1, "confidence": 0, "age": 1 },
        "reversibility": { "class": "irreversible", "value": 0 },
        "blast": { "count": 0, "reachable": [], "normalized": 1, "harm": {} },
        "harm": { "units": {}, "normalized": 1 },
        "evidenceDigest": "",
    })
}

/// A pure function of the submitted action and the committed context: `{r, valid, reasons, raw, inputs, reversibility, blast, harm,
/// evidenceDigest}`. A commitment mismatch (registry, graph, goal and embedder binding, calibration set) or an action without a stable
/// encoding is the fail-closed `r = 1` with `valid: false` and ALL the reasons. `Err` only where the reference throws: a digest that
/// cannot be formed (a non-finite graph harm weight or calibration score).
pub fn objective_risk(submitted: &Value, ctx: &ObjectiveRiskContext) -> Result<Value, String> {
    let action = match canonical_action(submitted) {
        Ok(a) => a,
        Err(e) => return Ok(reject(vec![format!("action: {e}")])),
    };
    let committed = |k: &str| ctx.commitments.get(k).filter(|v| !v.is_null());
    let mut reasons: Vec<String> = Vec::new();
    if Some(ctx.registry.digest()?.as_str()) != committed("registryDigest").and_then(Value::as_str) {
        reasons.push("registry digest does not match the committed digest".into());
    }
    if Some(ctx.graph.digest()?.as_str()) != committed("graphDigest").and_then(Value::as_str) {
        reasons.push("graph digest does not match the committed digest".into());
    }
    if let Some(cal) = ctx.calibration {
        match committed("calibrationDigest") {
            None => reasons.push("calibration set used without a committed digest".into()),
            Some(d) => {
                if Some(calibration_digest(cal)?.as_str()) != d.as_str() {
                    reasons.push("calibration digest does not match the committed digest".into());
                }
            }
        }
    }
    let dist = committed_distance_checked(&action, ctx.goal, ctx.embedder);
    if let Err(why) = &dist {
        reasons.push(format!("goal/embedder: {why}"));
    }
    let Ok(distance) = dist else { return Ok(reject(reasons)) };
    if !reasons.is_empty() {
        return Ok(reject(reasons));
    }

    let rev = reversibility(&action, ctx.registry, ctx.authorized_kinds);
    let blast = blast_radius(&action, ctx.graph, ctx.scope);
    let harm = harm_report(&blast["harm"], ctx.denominations);
    let uncertainty = clamp01(ctx.attested_uncertainty.unwrap_or(0.0));
    let harm_counts = !ctx.denominations.is_empty() && blast["harm"].as_object().is_some_and(|h| !h.is_empty());
    let f = |v: &Value| num(Some(v)).unwrap_or(f64::NAN);
    let inputs = RiskInputs {
        semantic_distance: distance,
        reversibility: f(&rev["value"]),
        blast_radius: js_max(f(&blast["normalized"]), if harm_counts { f(&harm["normalized"]) } else { 0.0 }),
        // a verifier that forgot (or corrupted) taint or age gets the worst value, never a throw or a NaN risk
        taint: if ctx.taint.is_finite() { ctx.taint } else { 1.0 },
        confidence: 1.0 - uncertainty,
        age: if ctx.age.is_finite() { ctx.age } else { 1.0 },
    };
    let w = |k: &str| num(ctx.weights.get(k)).unwrap_or(f64::NAN);
    let weights = RiskWeights { alpha: w("alpha"), beta: w("beta"), gamma: w("gamma"), delta: w("delta"), epsilon: w("epsilon"), zeta: w("zeta") };
    let raw = risk_score(&inputs, &weights);
    let r = ctx.calibration.map_or(raw, |c| calibrate(raw, c));
    let inputs_value = json!({
        "semanticDistance": nv(inputs.semantic_distance), "reversibility": nv(inputs.reversibility), "blastRadius": nv(inputs.blast_radius),
        "taint": nv(inputs.taint), "confidence": nv(inputs.confidence), "age": nv(inputs.age),
    });
    let edge_kinds = ctx.scope.and_then(|s| s.get("edgeKinds")).and_then(Value::as_array).map(|a| sorted_strings(a.iter().filter_map(Value::as_str).collect()));
    let evidence_digest = lenient_hash(&json!({
        "action": canonical_action_digest(&action)?,
        "scope": { "edgeKinds": edge_kinds, "maxDepth": ctx.scope.and_then(|s| s.get("maxDepth")).filter(|d| !d.is_null()).cloned().unwrap_or(Value::Null) },
        "authorized": sorted_strings(ctx.authorized_kinds.iter().map(String::as_str).collect()),
        "registry": committed("registryDigest").cloned().unwrap_or(Value::Null),
        "graph": committed("graphDigest").cloned().unwrap_or(Value::Null),
        "goal": ctx.goal.get("commit").cloned().unwrap_or(Value::Null),
        "calibration": committed("calibrationDigest").cloned().unwrap_or(Value::Null),
        "inputs": inputs_value,
    }))?;
    Ok(json!({ "r": nv(r), "valid": true, "reasons": [], "raw": nv(raw), "inputs": inputs_value, "reversibility": rev, "blast": blast, "harm": harm, "evidenceDigest": evidence_digest }))
}

// ---- the dispute-game oracle -----------------------------------------------------------------------------------------------------------------

/// The oracle of the contestable dispute game, backed by the objective risk functional: given a disputed input (`reversibility_class`,
/// `reversibility`, `blastRadius` or `semanticDistance`) and the frozen open-time snapshot, it recomputes the input from the committed
/// facts over the snapshot's canonical action and returns the server-authoritative `{input, class | value, valid: true}`. It fails
/// CLOSED: a commitment mismatch, an action without a stable encoding, an unknown input or any error is `{input, valid: false,
/// reason}` (the dispute is indeterminate and slashes no one), never a fabricated worst case.
pub fn objective_risk_oracle_resolve(ctx: &ObjectiveRiskContext, input: &Value, snapshot: &Value) -> Value {
    let fail = |reason: String| json!({ "input": input, "valid": false, "reason": reason });
    let a = snapshot.get("action").and_then(|a| a.get("action")).filter(|a| !a.is_null());
    let (Some(verb), Some(resource)) = (a.and_then(|a| a.get("verb")).and_then(Value::as_str), a.and_then(|a| a.get("resource")).and_then(Value::as_str)) else {
        return fail("snapshot action is missing a canonical verb/resource".into());
    };
    let params = a.and_then(|a| a.get("params")).filter(|p| p.is_object()).cloned().unwrap_or_else(|| json!({}));
    let res = match objective_risk(&json!({ "verb": verb, "resource": resource, "params": params }), ctx) {
        Ok(r) => r,
        Err(e) => return fail(format!("objective oracle error (fail closed): {e}")),
    };
    if res["valid"] != true {
        let reasons: Vec<&str> = res["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        return fail(if reasons.is_empty() { "objective risk could not be reproduced".into() } else { reasons.join("; ") });
    }
    match input.as_str() {
        Some("reversibility_class") => json!({ "input": input, "class": res["reversibility"]["class"], "valid": true }),
        Some("reversibility") => json!({ "input": input, "value": res["inputs"]["reversibility"], "valid": true }),
        Some("blastRadius") => json!({ "input": input, "value": res["inputs"]["blastRadius"], "valid": true }),
        Some("semanticDistance") => json!({ "input": input, "value": res["inputs"]["semanticDistance"], "valid": true }),
        _ => fail(format!("unknown disputed input: {}", js_value_string(input))),
    }
}

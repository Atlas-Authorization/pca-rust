//! Intent Layer v2 V15, rule 19 (conformance README "19. Committed map and Z0 disclosure"; TS reference
//! `packages/pca/src/intent-map-commit.ts` `decideMapDisclosure`): the committed (Merkle, per-leaf salted) Intent Map, the
//! cell of ω and the `map` check. In the guest (Z1) the disclosure is a PRIVATE input: the journal carries only
//! `(map_commit, ε, ok)` and the verifier-context digest excludes `map.disclosure` (see `intent_v2::ctx_digest_value`), so a
//! relying party learns that the action's cell is inside the committed grant and that the committed residual risk is at
//! most ε, and nothing else about the map (T28).
use crate::canonical::canonical_bytes;
use crate::chain::decode_b64u_strict;
use crate::commit::{b64u, hash_canonical, sha256};
use crate::jsnum::safe_int;
use serde_json::{Map, Value};

pub const MAP_TAG_HEADER: &[u8] = b"atlas-pca/intent-map/header/v1\0";
pub const MAP_TAG_CELL: &[u8] = b"atlas-pca/intent-map/cell/v1\0";
pub const MAP_TAG_METRICS: &[u8] = b"atlas-pca/intent-map/metrics/v1\0";
pub const MAP_TAG_LEARNER: &[u8] = b"atlas-pca/intent-map/learner/v1\0";
pub const MAP_TAG_NODE: &[u8] = b"atlas-pca/intent-map/node/v1\0";
pub const MAP_TAG_COMMIT: &[u8] = b"atlas-pca/intent-map/commit/v1\0";
pub const MAP_OTHER: &str = "\u{22A5}";
pub const MAX_MAP_LEAVES: i64 = 1 << 24;
pub const MAX_VERB_CELLS: i64 = 1 << 20;
pub const MAX_MAP_DIMS: usize = 16;
pub const MAX_MAP_CUTS: usize = 256;
pub const MAX_MAP_VALUES: usize = 256;
pub const MAX_MAP_STRING_BYTES: usize = 256;
pub const METRIC_FIELDS: [&str; 9] = [
    "residual_risk_ppm",
    "burden_ppm",
    "uncertainty_ppm",
    "disagreement_ppm",
    "mean_harm_ppm",
    "fidelity_est_ppm",
    "entropy_mbits",
    "questions",
    "conflicts",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafKind {
    Header,
    Cell,
    Metrics,
    Learner,
}

fn tag(k: LeafKind) -> &'static [u8] {
    match k {
        LeafKind::Header => MAP_TAG_HEADER,
        LeafKind::Cell => MAP_TAG_CELL,
        LeafKind::Metrics => MAP_TAG_METRICS,
        LeafKind::Learner => MAP_TAG_LEARNER,
    }
}

/// SHA-256(TAG_kind || salt || strictCanonical(leaf)).
pub fn leaf_hash(kind: LeafKind, salt: &[u8], leaf: &Value) -> [u8; 32] {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(tag(kind));
    b.extend_from_slice(salt);
    b.extend_from_slice(&canonical_bytes(leaf));
    sha256(&b)
}
pub fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    let mut b = Vec::with_capacity(MAP_TAG_NODE.len() + 64);
    b.extend_from_slice(MAP_TAG_NODE);
    b.extend_from_slice(l);
    b.extend_from_slice(r);
    sha256(&b)
}
/// map_commit = b64u(SHA-256(TAG_COMMIT || u64be(size) || root)).
pub fn map_commit_of(size: u64, root: &[u8; 32]) -> String {
    let mut b = Vec::with_capacity(MAP_TAG_COMMIT.len() + 40);
    b.extend_from_slice(MAP_TAG_COMMIT);
    b.extend_from_slice(&size.to_be_bytes());
    b.extend_from_slice(root);
    b64u(&sha256(&b))
}

/// RFC 9162 §2.1.3.2 with [`node_hash`]: the root the audit path recomputes, or None when it does not fit (index, size).
pub fn root_from_path(index: u64, size: u64, leaf: [u8; 32], path: &[[u8; 32]]) -> Option<[u8; 32]> {
    if index >= size {
        return None;
    }
    let (mut fn_, mut sn) = (index, size - 1);
    let mut r = leaf;
    for p in path {
        if sn == 0 {
            return None;
        }
        if fn_ % 2 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ % 2 == 0 {
                while fn_ % 2 == 0 && fn_ != 0 {
                    fn_ /= 2;
                    sn /= 2;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ /= 2;
        sn /= 2;
    }
    (sn == 0).then_some(r)
}

// ---- shapes ---------------------------------------------------------------------------------------------------------

fn closed(o: &Map<String, Value>, allowed: &[&str], required: &[&str]) -> bool {
    o.keys().all(|k| allowed.contains(&k.as_str())) && required.iter().all(|k| o.contains_key(*k))
}
fn str_ok(v: &Value, max: usize) -> Option<&str> {
    v.as_str().filter(|s| s.len() <= max)
}
fn non_neg(v: Option<&Value>) -> Option<i64> {
    v.and_then(safe_int).filter(|i| *i >= 0)
}
fn is_param_path(p: &str) -> bool {
    p.strip_prefix("action.params.")
        .is_some_and(|n| (1..=64).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
}

/// The numeric cells [lo, hi] (empty ranges dropped).
pub fn num_cells(lo: i64, hi: i64, cuts: &[i64]) -> Vec<(i64, i64)> {
    let mut out = Vec::new();
    let mut cur = lo;
    for &c in cuts {
        if cur <= c - 1 {
            out.push((cur, c - 1));
        }
        out.push((c, c));
        cur = c + 1;
    }
    if cur <= hi {
        out.push((cur, hi));
    }
    out
}

fn num_parts(d: &Map<String, Value>) -> (i64, i64, Vec<i64>) {
    let lo = safe_int(&d["lo"]).unwrap_or(0);
    let hi = safe_int(&d["hi"]).unwrap_or(0);
    let cuts = d["cuts"].as_array().map(|a| a.iter().filter_map(safe_int).collect()).unwrap_or_default();
    (lo, hi, cuts)
}
fn dim_cells(d: &Map<String, Value>) -> i64 {
    if d["kind"] == "num" {
        let (lo, hi, cuts) = num_parts(d);
        num_cells(lo, hi, &cuts).len() as i64
    } else {
        d["values"].as_array().map_or(0, |a| a.len() as i64)
    }
}

fn dim_error(d: &Value, j: usize) -> Option<String> {
    let Some(o) = d.as_object() else { return Some(format!("dims[{j}] must be an object")) };
    match o.get("kind").and_then(Value::as_str) {
        Some("num") => {
            if !closed(o, &["kind", "path", "lo", "hi", "cuts"], &["kind", "path", "lo", "hi", "cuts"]) {
                return Some(format!("dims[{j}] must be exactly {{kind, path, lo, hi, cuts}}"));
            }
            if !o["path"].as_str().is_some_and(is_param_path) {
                return Some(format!("dims[{j}].path must be action.params.<name>"));
            }
            let (Some(lo), Some(hi)) = (safe_int(&o["lo"]), safe_int(&o["hi"])) else {
                return Some(format!("dims[{j}] lo / hi must be safe integers with lo <= hi"));
            };
            if lo > hi {
                return Some(format!("dims[{j}] lo / hi must be safe integers with lo <= hi"));
            }
            let Some(cuts) = o["cuts"].as_array().filter(|a| a.len() <= MAX_MAP_CUTS) else {
                return Some(format!("dims[{j}].cuts must be an array of at most {MAX_MAP_CUTS}"));
            };
            let mut prev: Option<i64> = None;
            for c in cuts {
                match safe_int(c) {
                    Some(c) if prev.map_or(true, |p| c > p) && c >= lo && c <= hi => prev = Some(c),
                    _ => return Some(format!("dims[{j}].cuts must be strictly increasing safe integers in [lo, hi]")),
                }
            }
            None
        }
        Some("cat") => {
            if !closed(o, &["kind", "path", "values"], &["kind", "path", "values"]) {
                return Some(format!("dims[{j}] must be exactly {{kind, path, values}}"));
            }
            if !o["path"].as_str().is_some_and(|p| p == "action.resource" || is_param_path(p)) {
                return Some(format!("dims[{j}].path must be action.resource or action.params.<name>"));
            }
            let Some(vals) = o["values"].as_array().filter(|a| !a.is_empty() && a.len() <= MAX_MAP_VALUES) else {
                return Some(format!("dims[{j}].values must be an array of 1..{MAX_MAP_VALUES}"));
            };
            let mut seen = std::collections::BTreeSet::new();
            for (i, v) in vals.iter().enumerate() {
                let Some(vo) = v.as_object().filter(|vo| closed(vo, &["kind", "value"], &["kind", "value"])) else {
                    return Some(format!("dims[{j}].values[{i}] must be exactly {{kind, value}}"));
                };
                let kind = vo["kind"].as_str().filter(|k| ["exact", "prefix", "other"].contains(k));
                let Some(kind) = kind else { return Some(format!("dims[{j}].values[{i}].kind must be exact, prefix or other")) };
                let Some(value) = str_ok(&vo["value"], MAX_MAP_STRING_BYTES) else {
                    return Some(format!("dims[{j}].values[{i}].value must be a string of at most {MAX_MAP_STRING_BYTES} UTF-8 bytes"));
                };
                let misplaced = if kind == "other" { i != vals.len() - 1 || value != MAP_OTHER } else { kind == "prefix" && value.is_empty() };
                if misplaced {
                    return Some(format!("dims[{j}].values: exactly one other ('{MAP_OTHER}'), last; prefixes non-empty"));
                }
                if !seen.insert((kind, value)) {
                    return Some(format!("dims[{j}].values must be distinct"));
                }
            }
            if vals[vals.len() - 1]["kind"] != "other" {
                return Some(format!("dims[{j}].values must end with the other value"));
            }
            None
        }
        _ => Some(format!("dims[{j}].kind must be num or cat")),
    }
}

pub fn header_error(h: &Value) -> Option<String> {
    let Some(o) = h.as_object().filter(|o| closed(o, &["verb", "first", "cells", "dims"], &["verb", "first", "cells", "dims"])) else {
        return Some("the header leaf must be exactly {verb, first, cells, dims}".into());
    };
    if !str_ok(&o["verb"], 128).is_some_and(|s| !s.is_empty()) {
        return Some("header.verb must be a non-empty string of at most 128 UTF-8 bytes".into());
    }
    if !non_neg(o.get("first")).is_some_and(|f| f < MAX_MAP_LEAVES) {
        return Some("header.first must be a leaf index".into());
    }
    let Some(cells) = safe_int(&o["cells"]).filter(|c| (1..=MAX_VERB_CELLS).contains(c)) else {
        return Some(format!("header.cells must be a safe integer in [1, {MAX_VERB_CELLS}]"));
    };
    let Some(dims) = o["dims"].as_array().filter(|a| a.len() <= MAX_MAP_DIMS) else {
        return Some(format!("header.dims must be an array of at most {MAX_MAP_DIMS}"));
    };
    let mut paths = std::collections::BTreeSet::new();
    let mut n: i64 = 1;
    for (j, d) in dims.iter().enumerate() {
        if let Some(e) = dim_error(d, j) {
            return Some(format!("header.{e}"));
        }
        let dobj = d.as_object().unwrap();
        if !paths.insert(dobj["path"].as_str().unwrap_or("").to_string()) {
            return Some("header.dims paths must be distinct".into());
        }
        n = n.saturating_mul(dim_cells(dobj));
        if n > MAX_VERB_CELLS {
            return Some("header: too many cells".into());
        }
    }
    if n != cells {
        return Some("header.cells is not the product of the dimensions' cell counts".into());
    }
    None
}

pub fn cell_error(c: &Value) -> Option<String> {
    let Some(o) = c.as_object().filter(|o| closed(o, &["verb", "cell", "p_ppm", "in_grant"], &["verb", "cell", "p_ppm", "in_grant"])) else {
        return Some("the cell leaf must be exactly {verb, cell, p_ppm, in_grant}".into());
    };
    if !str_ok(&o["verb"], 128).is_some_and(|s| !s.is_empty()) {
        return Some("cell.verb must be a non-empty string of at most 128 UTF-8 bytes".into());
    }
    if !o["cell"].as_array().is_some_and(|a| a.len() <= MAX_MAP_DIMS && a.iter().all(|x| non_neg(Some(x)).is_some())) {
        return Some("cell.cell must be an array of non-negative safe integers".into());
    }
    if !non_neg(o.get("p_ppm")).is_some_and(|p| p <= 1_000_000) {
        return Some("cell.p_ppm must be a safe integer in [0, 1000000]".into());
    }
    if !o["in_grant"].is_boolean() {
        return Some("cell.in_grant must be a boolean".into());
    }
    None
}

pub fn metrics_error(m: &Value) -> Option<String> {
    let mut allowed: Vec<&str> = METRIC_FIELDS.to_vec();
    allowed.push("log2_vs_mbits");
    let Some(o) = m.as_object().filter(|o| closed(o, &allowed, &METRIC_FIELDS)) else {
        return Some("the metrics leaf must be exactly the metric fields (log2_vs_mbits optional)".into());
    };
    for k in allowed {
        match o.get(k) {
            None if k == "log2_vs_mbits" => {}
            v if non_neg(v).is_some() => {}
            _ => return Some(format!("metrics.{k} must be a non-negative safe integer")),
        }
    }
    None
}

fn entry_shape(e: &Value, what: &str) -> Option<String> {
    let Some(o) = e.as_object().filter(|o| closed(o, &["index", "salt", "leaf", "path"], &["index", "salt", "leaf", "path"])) else {
        return Some(format!("disclosure.{what} must be exactly {{index, salt, leaf, path}}"));
    };
    if non_neg(o.get("index")).is_none() {
        return Some(format!("disclosure.{what}.index must be a non-negative safe integer"));
    }
    if !o["salt"].as_str().is_some_and(|s| decode_b64u_strict(s, 32).is_some()) {
        return Some(format!("disclosure.{what}.salt must be canonical base64url (32 bytes)"));
    }
    if !o["path"].as_array().is_some_and(|a| a.len() <= 64 && a.iter().all(|h| h.as_str().is_some_and(|s| decode_b64u_strict(s, 32).is_some()))) {
        return Some(format!("disclosure.{what}.path must be an array of 32-byte digests"));
    }
    None
}

pub fn disclosure_error(d: &Value) -> Option<String> {
    let Some(o) = d.as_object().filter(|o| closed(o, &["size", "header", "cell", "metrics"], &["size", "header", "cell", "metrics"])) else {
        return Some("the disclosure must be exactly {size, header, cell, metrics}".into());
    };
    if !safe_int(&o["size"]).is_some_and(|s| (4..=MAX_MAP_LEAVES).contains(&s)) {
        return Some(format!("disclosure.size must be a safe integer in [4, {MAX_MAP_LEAVES}]"));
    }
    for k in ["header", "cell", "metrics"] {
        if let Some(e) = entry_shape(&o[k], k) {
            return Some(e);
        }
    }
    header_error(&o["header"]["leaf"]).or_else(|| cell_error(&o["cell"]["leaf"])).or_else(|| metrics_error(&o["metrics"]["leaf"]))
}

/// Cell of ω under a WELL-FORMED header: (per-dimension indices, flat index), or the reason it lies outside the map.
pub fn cell_of(header: &Value, resource: Option<&Value>, params: Option<&Value>) -> Result<(Vec<i64>, i64), String> {
    let mut cell = Vec::new();
    let mut flat: i64 = 0;
    for d in header["dims"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        let o = d.as_object().ok_or("malformed dimension")?;
        let path = o["path"].as_str().unwrap_or("");
        let x = if path == "action.resource" {
            resource
        } else {
            params.and_then(Value::as_object).and_then(|p| p.get(&path["action.params.".len()..]))
        };
        let mut i: i64 = -1;
        if o["kind"] == "num" {
            if let Some(v) = x.and_then(safe_int) {
                let (lo, hi, cuts) = num_parts(o);
                if let Some(k) = num_cells(lo, hi, &cuts).iter().position(|(a, b)| v >= *a && v <= *b) {
                    i = k as i64;
                }
            }
        } else if let Some(s) = x.and_then(Value::as_str) {
            let vals = o["values"].as_array().map(Vec::as_slice).unwrap_or(&[]);
            let mut best: i64 = -1;
            let mut best_len: usize = 0;
            for (k, v) in vals.iter().enumerate() {
                let value = v["value"].as_str().unwrap_or("");
                if v["kind"] == "exact" && value == s {
                    best = k as i64;
                    break;
                }
                if v["kind"] == "prefix" && s.starts_with(value) && (best < 0 || value.len() > best_len) {
                    best = k as i64;
                    best_len = value.len();
                }
            }
            i = if best >= 0 { best } else { vals.len() as i64 - 1 };
        }
        if i < 0 {
            return Err(format!("the action's {path} lies outside the committed map's dimension"));
        }
        cell.push(i);
        flat = flat * dim_cells(o) + i;
    }
    Ok((cell, flat))
}

fn opens(kind: LeafKind, e: &Value, size: i64, commit: &str) -> bool {
    let salt = match e["salt"].as_str().and_then(|s| decode_b64u_strict(s, 32)) {
        Some(s) => s,
        None => return false,
    };
    let mut path = Vec::new();
    for h in e["path"].as_array().map(Vec::as_slice).unwrap_or(&[]) {
        match h.as_str().and_then(|s| decode_b64u_strict(s, 32)) {
            Some(b) => path.push(<[u8; 32]>::try_from(b.as_slice()).unwrap()),
            None => return false,
        }
    }
    let index = non_neg(e.get("index")).unwrap_or(-1);
    if index < 0 {
        return false;
    }
    match root_from_path(index as u64, size as u64, leaf_hash(kind, &salt, &e["leaf"]), &path) {
        Some(root) => map_commit_of(size as u64, &root) == commit,
        None => false,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MapPass {
    pub cell: Vec<i64>,
    pub p_ppm: i64,
    pub residual_risk_ppm: i64,
}

/// `decideMapDisclosure` (rule 19, steps 1-8). `action` is the PCActn's action object, `params` the verifier's plaintext
/// params (None = `{}`), `eps` ε when the policy sets it. Total.
pub fn decide_map_disclosure(map_commit: Option<&Value>, action: Option<&Value>, params: Option<&Value>, disclosure: &Value, eps: Option<i64>) -> Result<MapPass, String> {
    if let Some(e) = disclosure_error(disclosure) {
        return Err(format!("map disclosure malformed: {e}"));
    }
    let commit = match map_commit.and_then(Value::as_str) {
        Some(c) if decode_b64u_strict(c, 32).is_some() => c,
        _ => return Err("the PCActn carries no map commitment".into()),
    };
    if params.is_some_and(|p| !p.is_object()) {
        return Err("params must be an object".into());
    }
    let empty = Value::Object(Map::new());
    let params_v = params.unwrap_or(&empty);
    let action = action.unwrap_or(&Value::Null);
    if action.get("params_digest") != Some(&Value::String(hash_canonical(params_v))) {
        return Err("the params do not hash to action.params_digest".into());
    }
    let size = safe_int(&disclosure["size"]).unwrap_or(0);
    let (he, ce, me) = (&disclosure["header"], &disclosure["cell"], &disclosure["metrics"]);
    let h = &he["leaf"];
    if action.get("verb") != Some(&h["verb"]) {
        return Err("the disclosed header is not the action's verb".into());
    }
    let first = safe_int(&h["first"]).unwrap_or(0);
    let cells = safe_int(&h["cells"]).unwrap_or(0);
    if !(safe_int(&he["index"]).unwrap_or(i64::MAX) < first) || !(first + cells <= size - 2) {
        return Err("the disclosed header does not fit the committed layout".into());
    }
    if !opens(LeafKind::Header, he, size, commit) {
        return Err("the header leaf does not open the map commitment".into());
    }
    if !opens(LeafKind::Cell, ce, size, commit) {
        return Err("the cell leaf does not open the map commitment".into());
    }
    if !opens(LeafKind::Metrics, me, size, commit) {
        return Err("the metrics leaf does not open the map commitment".into());
    }
    let (cell, flat) = cell_of(h, action.get("resource"), Some(params_v))?;
    let c = &ce["leaf"];
    let leaf_cell: Vec<i64> = c["cell"].as_array().map(|a| a.iter().filter_map(safe_int).collect()).unwrap_or_default();
    if safe_int(&ce["index"]) != Some(first + flat) || c["verb"] != h["verb"] || leaf_cell != cell {
        return Err("the disclosed cell is not the action's cell".into());
    }
    if c["in_grant"] != Value::Bool(true) {
        return Err("the action's cell is outside the committed grant".into());
    }
    if safe_int(&me["index"]) != Some(size - 2) {
        return Err("the disclosed metrics leaf is not at its committed position".into());
    }
    let rr = safe_int(&me["leaf"]["residual_risk_ppm"]).unwrap_or(i64::MAX);
    if let Some(eps) = eps {
        if rr > eps {
            return Err(format!("the committed residual risk {rr} ppm exceeds \u{3b5} = {eps}"));
        }
    }
    Ok(MapPass { cell, p_ppm: safe_int(&c["p_ppm"]).unwrap_or(0), residual_risk_ppm: rr })
}

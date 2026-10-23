//! The committed Intent Map and its Z0 disclosure (Intent Layer v2 rule 19, V15). Mirrors
//! `packages/pca/src/intent-map-commit.ts` (`mapLeafHash`, `mapRootFromPath`, the closed leaf shapes, `mapCellOf`,
//! `decideMapDisclosure`) and recomputes a full commitment (`primitives.intent_map_commit`).
//!
//! Leaves are salted per leaf and tagged per kind: `leaf_hash = SHA-256(TAG_kind || salt || strictCanonical(leaf))`,
//! `node_hash = SHA-256(TAG_NODE || l || r)`, the RFC 9162 tree shape, and `map_commit = b64u(SHA-256(TAG_COMMIT ||
//! u64be(n) || root))`.

use serde_json::{Map, Value};

use super::intent_strict::*;
use super::{b64_encode, canonicalize_strict, decode_b64u_strict, sha};

const TAG_HEADER: &str = "atlas-pca/intent-map/header/v1\0";
const TAG_CELL: &str = "atlas-pca/intent-map/cell/v1\0";
const TAG_METRICS: &str = "atlas-pca/intent-map/metrics/v1\0";
const TAG_LEARNER: &str = "atlas-pca/intent-map/learner/v1\0";
const TAG_NODE: &str = "atlas-pca/intent-map/node/v1\0";
const TAG_COMMIT: &str = "atlas-pca/intent-map/commit/v1\0";
const MAP_OTHER: &str = "⊥";
const MAX_MAP_LEAVES: i64 = 1 << 24;
const MAX_VERB_CELLS: i64 = 1 << 20;
const MAX_MAP_DIMS: usize = 16;
const MAX_MAP_CUTS: usize = 256;
const MAX_MAP_VALUES: usize = 256;
const MAX_MAP_STRING_BYTES: usize = 256;
const MAX_PATH_LEN: usize = 64;
const PPM_ONE: i64 = 1_000_000;
const METRIC_FIELDS: [&str; 9] =
    ["residual_risk_ppm", "burden_ppm", "uncertainty_ppm", "disagreement_ppm", "mean_harm_ppm", "fidelity_est_ppm", "entropy_mbits", "questions", "conflicts"];

fn tag_of(kind: &str) -> Option<&'static str> {
    Some(match kind {
        "header" => TAG_HEADER,
        "cell" => TAG_CELL,
        "metrics" => TAG_METRICS,
        "learner" => TAG_LEARNER,
        _ => return None,
    })
}

/// `mapLeafHash(kind, salt, leaf)`; `None` for an unknown kind, a salt that is not 32 bytes or an out-of-profile leaf.
fn leaf_hash(kind: &str, salt: &[u8], leaf: &Value) -> Option<Vec<u8>> {
    if salt.len() != 32 {
        return None;
    }
    let mut m = tag_of(kind)?.as_bytes().to_vec();
    m.extend_from_slice(salt);
    m.extend_from_slice(canonicalize_strict(leaf).ok()?.as_bytes());
    Some(sha(&m))
}

fn node_hash(l: &[u8], r: &[u8]) -> Vec<u8> {
    let mut m = TAG_NODE.as_bytes().to_vec();
    m.extend_from_slice(l);
    m.extend_from_slice(r);
    sha(&m)
}

fn commit_of(size: u64, root: &[u8]) -> String {
    let mut m = TAG_COMMIT.as_bytes().to_vec();
    m.extend_from_slice(&size.to_be_bytes());
    m.extend_from_slice(root);
    b64_encode(&sha(&m))
}

fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

fn tree_root(hs: &[Vec<u8>]) -> Vec<u8> {
    if hs.len() == 1 {
        return hs[0].clone();
    }
    let k = split(hs.len());
    node_hash(&tree_root(&hs[..k]), &tree_root(&hs[k..]))
}

/// `mapRootFromPath(index, size, leafHash, path)`: RFC 9162 §2.1.3.2 with `node_hash`; `None` when the path length does
/// not match (index, size).
fn root_from_path(index: u64, size: u64, leaf: Vec<u8>, path: &[Vec<u8>]) -> Option<Vec<u8>> {
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

/// `primitives.intent_map_commit`: the commitment of a full leaf list `[{kind, salt, leaf}]` (in leaf order). `None` when
/// an entry is malformed (not exactly `{kind, salt, leaf}`, unknown kind, salt not 32 bytes, an out-of-profile leaf) or
/// the list is empty.
pub fn map_commit_of_leaves(leaves: &Value) -> Option<String> {
    let ls = leaves.as_array()?;
    if ls.is_empty() {
        return None;
    }
    let mut hs = Vec::with_capacity(ls.len());
    for l in ls {
        if !l.as_object().is_some_and(|o| closed(o, &["kind", "salt", "leaf"])) {
            return None;
        }
        let salt = decode_b64u_strict(s(l.get("salt"))?, Some(32))?;
        hs.push(leaf_hash(s(l.get("kind"))?, &salt, l.get("leaf")?)?);
    }
    Some(commit_of(hs.len() as u64, &tree_root(&hs)))
}

// ---- closed and typed leaves ------------------------------------------------------------------------------------

/// `closed(o, allowed, required)`: every member allowed and every required one present (own).
fn closed(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.keys().all(|k| keys.contains(&k.as_str())) && keys.iter().all(|k| o.contains_key(*k))
}

/// `isStr(v, max)` of intent-map-commit.ts: a string of at most `max` UTF-8 bytes (empty allowed).
fn map_str(v: Option<&Value>, max: usize) -> Option<&str> {
    s(v).filter(|x| x.len() <= max)
}

fn is_dim_path(p: &str) -> bool {
    p == "action.resource" || is_top_param_path(p)
}

/// The numeric cells `[lo, c1-1], {c1}, [c1+1, c2-1], ..., {ck}, [ck+1, hi]` (empty ranges dropped).
fn num_cells(lo: i64, hi: i64, cuts: &[i64]) -> Vec<(i64, i64)> {
    let mut out = Vec::new();
    let mut cur = lo;
    for &c in cuts {
        if cur < c {
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

/// A validated dimension.
enum Dim {
    Num { path: String, cells: Vec<(i64, i64)> },
    Cat { path: String, values: Vec<(String, String)> },
}

impl Dim {
    fn path(&self) -> &str {
        match self {
            Dim::Num { path, .. } | Dim::Cat { path, .. } => path,
        }
    }
    fn n(&self) -> usize {
        match self {
            Dim::Num { cells, .. } => cells.len(),
            Dim::Cat { values, .. } => values.len(),
        }
    }
}

fn dim_of(d: &Value, j: usize) -> Result<Dim, String> {
    let o = d.as_object().ok_or_else(|| format!("dims[{j}] must be an object"))?;
    match s(o.get("kind")) {
        Some("num") => {
            if !closed(o, &["kind", "path", "lo", "hi", "cuts"]) {
                return Err(format!("dims[{j}] must be exactly {{kind, path, lo, hi, cuts}}"));
            }
            let path = s(o.get("path")).filter(|p| is_top_param_path(p)).ok_or_else(|| format!("dims[{j}].path must be action.params.<name>"))?;
            let (lo, hi) = match (sint(o.get("lo")), sint(o.get("hi"))) {
                (Some(lo), Some(hi)) if lo <= hi => (lo, hi),
                _ => return Err(format!("dims[{j}] lo / hi must be safe integers with lo <= hi")),
            };
            let cuts_v = o.get("cuts").and_then(Value::as_array).filter(|c| c.len() <= MAX_MAP_CUTS);
            let cuts_v = cuts_v.ok_or_else(|| format!("dims[{j}].cuts must be an array of at most {MAX_MAP_CUTS}"))?;
            let mut cuts = Vec::with_capacity(cuts_v.len());
            let mut prev: Option<i64> = None;
            for c in cuts_v {
                match sint(Some(c)) {
                    Some(c) if prev.is_none_or(|p| c > p) && c >= lo && c <= hi => {
                        cuts.push(c);
                        prev = Some(c);
                    }
                    _ => return Err(format!("dims[{j}].cuts must be strictly increasing safe integers in [lo, hi]")),
                }
            }
            Ok(Dim::Num { path: path.to_string(), cells: num_cells(lo, hi, &cuts) })
        }
        Some("cat") => {
            if !closed(o, &["kind", "path", "values"]) {
                return Err(format!("dims[{j}] must be exactly {{kind, path, values}}"));
            }
            let path = s(o.get("path")).filter(|p| is_dim_path(p)).ok_or_else(|| format!("dims[{j}].path must be action.resource or action.params.<name>"))?;
            let vs = o.get("values").and_then(Value::as_array).filter(|v| !v.is_empty() && v.len() <= MAX_MAP_VALUES);
            let vs = vs.ok_or_else(|| format!("dims[{j}].values must be an array of 1..{MAX_MAP_VALUES}"))?;
            let mut values: Vec<(String, String)> = Vec::with_capacity(vs.len());
            for (i, v) in vs.iter().enumerate() {
                let vo = v.as_object().filter(|vo| closed(vo, &["kind", "value"])).ok_or_else(|| format!("dims[{j}].values[{i}] must be exactly {{kind, value}}"))?;
                let kind = s(vo.get("kind")).filter(|k| matches!(*k, "exact" | "prefix" | "other"));
                let kind = kind.ok_or_else(|| format!("dims[{j}].values[{i}].kind must be exact, prefix or other"))?;
                let value = map_str(vo.get("value"), MAX_MAP_STRING_BYTES).ok_or_else(|| format!("dims[{j}].values[{i}].value must be a string of at most {MAX_MAP_STRING_BYTES} UTF-8 bytes"))?;
                let bad = if kind == "other" { i != vs.len() - 1 || value != MAP_OTHER } else { kind == "prefix" && value.is_empty() };
                if bad {
                    return Err(format!("dims[{j}].values: exactly one other ('{MAP_OTHER}'), last; prefixes non-empty"));
                }
                if values.iter().any(|(k, x)| k == kind && x == value) {
                    return Err(format!("dims[{j}].values must be distinct"));
                }
                values.push((kind.to_string(), value.to_string()));
            }
            if values.last().is_none_or(|(k, _)| k != "other") {
                return Err(format!("dims[{j}].values must end with the other value"));
            }
            Ok(Dim::Cat { path: path.to_string(), values })
        }
        _ => Err(format!("dims[{j}].kind must be num or cat")),
    }
}

/// A validated header leaf.
struct Header {
    verb: String,
    first: i64,
    cells: i64,
    dims: Vec<Dim>,
}

/// `mapHeaderError` + the parsed header.
fn header_of(h: &Value) -> Result<Header, String> {
    let o = h.as_object().filter(|o| closed(o, &["verb", "first", "cells", "dims"])).ok_or("the header leaf must be exactly {verb, first, cells, dims}")?;
    let verb = map_str(o.get("verb"), 128).filter(|v| !v.is_empty()).ok_or("header.verb must be a non-empty string of at most 128 UTF-8 bytes")?;
    let first = nonneg(o.get("first")).filter(|f| *f < MAX_MAP_LEAVES).ok_or("header.first must be a leaf index")?;
    let cells = sint(o.get("cells")).filter(|c| (1..=MAX_VERB_CELLS).contains(c)).ok_or_else(|| format!("header.cells must be a safe integer in [1, {MAX_VERB_CELLS}]"))?;
    let dv = o.get("dims").and_then(Value::as_array).filter(|d| d.len() <= MAX_MAP_DIMS).ok_or_else(|| format!("header.dims must be an array of at most {MAX_MAP_DIMS}"))?;
    let mut dims: Vec<Dim> = Vec::with_capacity(dv.len());
    let mut n: i64 = 1;
    for (j, d) in dv.iter().enumerate() {
        let dd = dim_of(d, j).map_err(|e| format!("header.{e}"))?;
        if dims.iter().any(|x| x.path() == dd.path()) {
            return Err("header.dims paths must be distinct".into());
        }
        n = n.saturating_mul(dd.n() as i64);
        if n > MAX_VERB_CELLS {
            return Err("header: too many cells".into());
        }
        dims.push(dd);
    }
    if n != cells {
        return Err("header.cells is not the product of the dimensions' cell counts".into());
    }
    Ok(Header { verb: verb.to_string(), first, cells, dims })
}

fn cell_error(c: &Value) -> Option<String> {
    let o = match c.as_object().filter(|o| closed(o, &["verb", "cell", "p_ppm", "in_grant"])) {
        Some(o) => o,
        None => return Some("the cell leaf must be exactly {verb, cell, p_ppm, in_grant}".into()),
    };
    if map_str(o.get("verb"), 128).is_none_or(str::is_empty) {
        return Some("cell.verb must be a non-empty string of at most 128 UTF-8 bytes".into());
    }
    if !o.get("cell").and_then(Value::as_array).is_some_and(|a| a.len() <= MAX_MAP_DIMS && a.iter().all(|x| nonneg(Some(x)).is_some())) {
        return Some("cell.cell must be an array of non-negative safe integers".into());
    }
    if !nonneg(o.get("p_ppm")).is_some_and(|p| p <= PPM_ONE) {
        return Some("cell.p_ppm must be a safe integer in [0, 1000000]".into());
    }
    if !o.get("in_grant").is_some_and(Value::is_boolean) {
        return Some("cell.in_grant must be a boolean".into());
    }
    None
}

fn metrics_error(m: &Value) -> Option<String> {
    let o = m.as_object()?;
    let allowed_ok = o.keys().all(|k| METRIC_FIELDS.contains(&k.as_str()) || k == "log2_vs_mbits");
    if !allowed_ok || !METRIC_FIELDS.iter().all(|k| o.contains_key(*k)) {
        return Some(format!("the metrics leaf must be exactly {{{}, log2_vs_mbits?}}", METRIC_FIELDS.join(", ")));
    }
    for k in METRIC_FIELDS.iter().copied().chain(["log2_vs_mbits"]) {
        match o.get(k) {
            None if k == "log2_vs_mbits" => {}
            v => {
                if nonneg(v).is_none() {
                    return Some(format!("metrics.{k} must be a non-negative safe integer"));
                }
            }
        }
    }
    None
}

/// The disclosure entry `{index, salt, leaf, path}`: (index, salt, path) when well-formed.
fn entry_of(e: Option<&Value>, what: &str) -> Result<(u64, Vec<u8>, Vec<Vec<u8>>), String> {
    let o = e.and_then(Value::as_object).filter(|o| closed(o, &["index", "salt", "leaf", "path"]));
    let o = o.ok_or_else(|| format!("disclosure.{what} must be exactly {{index, salt, leaf, path}}"))?;
    let index = nonneg(o.get("index")).ok_or_else(|| format!("disclosure.{what}.index must be a non-negative safe integer"))?;
    let salt = s(o.get("salt")).and_then(|x| decode_b64u_strict(x, Some(32))).ok_or_else(|| format!("disclosure.{what}.salt must be canonical base64url (32 bytes)"))?;
    let pv = o.get("path").and_then(Value::as_array).filter(|p| p.len() <= MAX_PATH_LEN).ok_or_else(|| format!("disclosure.{what}.path must be an array of 32-byte digests"))?;
    let mut path = Vec::with_capacity(pv.len());
    for h in pv {
        path.push(s(Some(h)).and_then(|x| decode_b64u_strict(x, Some(32))).ok_or_else(|| format!("disclosure.{what}.path must be an array of 32-byte digests"))?);
    }
    Ok((index as u64, salt, path))
}

/// The rule-19 Z0 decision: `ok`, and when ok the action's cell indices and its `p_ppm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MapDecision {
    pub ok: bool,
    pub cell: Vec<i64>,
    pub p_ppm: i64,
    pub reason: String,
}

fn map_fail(reason: impl Into<String>) -> MapDecision {
    MapDecision { ok: false, cell: Vec::new(), p_ppm: 0, reason: reason.into() }
}

/// The cell of ω under a header (`mapCellOf`): per dimension the numeric cell containing the safe-integer value, or the
/// exact category, else the LONGEST prefix, else `other`; `flat` row-major.
fn cell_of(h: &Header, resource: Option<&Value>, params: &Map<String, Value>) -> Result<(Vec<i64>, i64), String> {
    let mut cell = Vec::with_capacity(h.dims.len());
    let mut flat: i64 = 0;
    for d in &h.dims {
        let x = if d.path() == "action.resource" { resource } else { params.get(d.path().strip_prefix("action.params.").unwrap_or("")) };
        let i: Option<usize> = match d {
            Dim::Num { cells, .. } => sint(x).and_then(|v| cells.iter().position(|(lo, hi)| v >= *lo && v <= *hi)),
            Dim::Cat { values, .. } => s(x).map(|xs| {
                let exact = values.iter().position(|(k, v)| k == "exact" && v == xs);
                exact.unwrap_or_else(|| {
                    let mut best: Option<(usize, usize)> = None;
                    for (k, (kind, v)) in values.iter().enumerate() {
                        if kind == "prefix" && xs.starts_with(v.as_str()) && best.is_none_or(|(_, l)| v.len() > l) {
                            best = Some((k, v.len()));
                        }
                    }
                    best.map_or(values.len() - 1, |(k, _)| k)
                })
            }),
        };
        let i = i.ok_or_else(|| format!("the action's {} lies outside the committed map's dimension", d.path()))?;
        cell.push(i as i64);
        flat = flat * d.n() as i64 + i as i64;
    }
    Ok((cell, flat))
}

/// `decideMapDisclosure({mapCommit, action: {verb, resource, params_digest}, params, disclosure, maxResidualRiskPpm})`
/// (NORMATIVE, rule 19 steps 1-8). `params` absent = `{}`; never panics.
pub fn decide_map_disclosure(map_commit: Option<&Value>, action: &Value, params: Option<&Value>, disclosure: Option<&Value>, max_residual_risk_ppm: Option<i64>) -> MapDecision {
    let d = match disclosure.and_then(Value::as_object).filter(|o| closed(o, &["size", "header", "cell", "metrics"])) {
        Some(d) => d,
        None => return map_fail("map disclosure malformed: the disclosure must be exactly {size, header, cell, metrics}"),
    };
    let size = match sint(d.get("size")) {
        Some(n) if (4..=MAX_MAP_LEAVES).contains(&n) => n as u64,
        _ => return map_fail("map disclosure malformed: disclosure.size must be a safe integer in [4, 16777216]"),
    };
    let entries = (entry_of(d.get("header"), "header"), entry_of(d.get("cell"), "cell"), entry_of(d.get("metrics"), "metrics"));
    let (he, ce, me) = match entries {
        (Ok(h), Ok(c), Ok(m)) => (h, c, m),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return map_fail(format!("map disclosure malformed: {e}")),
    };
    let leaf = |k: &str| d.get(k).and_then(|e| e.get("leaf")).cloned().unwrap_or(Value::Null);
    let (hl, cl, ml) = (leaf("header"), leaf("cell"), leaf("metrics"));
    let header = match header_of(&hl) {
        Ok(h) => h,
        Err(e) => return map_fail(format!("map disclosure malformed: {e}")),
    };
    if let Some(e) = cell_error(&cl).or_else(|| metrics_error(&ml).or_else(|| (!ml.is_object()).then(|| "the metrics leaf must be an object".to_string()))) {
        return map_fail(format!("map disclosure malformed: {e}"));
    }
    let commit = match map_commit {
        Some(Value::String(c)) if decode_b64u_strict(c, Some(32)).is_some() => c.as_str(),
        _ => return map_fail("the PCActn carries no map commitment"),
    };
    let params = match params {
        None => Map::new(),
        Some(Value::Object(p)) => p.clone(),
        Some(_) => return map_fail("params must be an object"),
    };
    if digest_of(&Value::Object(params.clone())).as_deref() != s(action.get("params_digest")) {
        return map_fail("the params do not hash to action.params_digest");
    }
    if s(action.get("verb")) != Some(header.verb.as_str()) {
        return map_fail("the disclosed header is not the action's verb");
    }
    if !((he.0 as i64) < header.first) || !(header.first + header.cells <= size as i64 - 2) {
        return map_fail("the disclosed header does not fit the committed layout");
    }
    let opens = |kind: &str, (index, salt, path): &(u64, Vec<u8>, Vec<Vec<u8>>), lv: &Value| -> bool {
        leaf_hash(kind, salt, lv).and_then(|h| root_from_path(*index, size, h, path)).is_some_and(|root| commit_of(size, &root) == commit)
    };
    if !opens("header", &he, &hl) {
        return map_fail("the header leaf does not open the map commitment");
    }
    if !opens("cell", &ce, &cl) {
        return map_fail("the cell leaf does not open the map commitment");
    }
    if !opens("metrics", &me, &ml) {
        return map_fail("the metrics leaf does not open the map commitment");
    }
    let (cell, flat) = match cell_of(&header, action.get("resource"), &params) {
        Ok(x) => x,
        Err(e) => return map_fail(e),
    };
    let leaf_cell: Vec<i64> = cl.get("cell").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| sint(Some(x))).collect()).unwrap_or_default();
    if ce.0 as i64 != header.first + flat || s(cl.get("verb")) != Some(header.verb.as_str()) || leaf_cell != cell {
        return map_fail("the disclosed cell is not the action's cell");
    }
    if cl.get("in_grant") != Some(&Value::Bool(true)) {
        return map_fail("the action's cell is outside the committed grant");
    }
    if me.0 != size - 2 {
        return map_fail("the disclosed metrics leaf is not at its committed position");
    }
    let rr = nonneg(ml.get("residual_risk_ppm")).unwrap_or(i64::MAX);
    if let Some(eps) = max_residual_risk_ppm {
        if rr > eps {
            return map_fail(format!("the committed residual risk {rr} ppm exceeds ε = {eps}"));
        }
    }
    MapDecision { ok: true, cell, p_ppm: nonneg(cl.get("p_ppm")).unwrap_or(0), reason: String::new() }
}

#[cfg(test)]
#[path = "k042_intent_map_test.rs"]
mod k042_test;

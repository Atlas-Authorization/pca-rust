//! The wallet side of the committed (Merkle, per-leaf salted) form of an Intent Map (`map-commit.ts` over `intent-map-commit.ts`):
//! maps an Intent Map onto the leaf layout of rule 19, builds the tree and discloses a header / cell / metrics opening.
//! Mirrors the verifier in `crate::intent_map` (same closed and typed leaf shapes, same tree) and adds the builder.
use super::R;
use crate::intent_kit::hash_strict;
use crate::intent_strict::{nonneg, s, sint};
use crate::{b64_encode, canonicalize_strict, decode_b64u_strict, sha};
use serde_json::{json, Map, Value};

const TAG_HEADER: &str = "atlas-pca/intent-map/header/v1\0";
const TAG_CELL: &str = "atlas-pca/intent-map/cell/v1\0";
const TAG_METRICS: &str = "atlas-pca/intent-map/metrics/v1\0";
const TAG_LEARNER: &str = "atlas-pca/intent-map/learner/v1\0";
const TAG_NODE: &str = "atlas-pca/intent-map/node/v1\0";
const TAG_COMMIT: &str = "atlas-pca/intent-map/commit/v1\0";
const TAG_SALT: &str = "atlas-pca/intent-map/salt/v1\0";
const MAP_OTHER: &str = "⊥";
const MAX_MAP_LEAVES: i64 = 1 << 24;
const MAX_VERB_CELLS: i64 = 1 << 20;
const MAX_MAP_DIMS: usize = 16;
const MAX_MAP_CUTS: usize = 256;
const MAX_MAP_VALUES: usize = 256;
const MAX_MAP_STRING_BYTES: usize = 256;
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

fn leaf_salt(secret: &[u8], index: u64) -> Vec<u8> {
    let mut m = TAG_SALT.as_bytes().to_vec();
    m.extend_from_slice(secret);
    m.extend_from_slice(&index.to_be_bytes());
    sha(&m)
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

fn audit_path(hs: &[Vec<u8>], idx: usize, out: &mut Vec<Vec<u8>>) {
    if hs.len() == 1 {
        return;
    }
    let k = split(hs.len());
    if idx < k {
        audit_path(&hs[..k], idx, out);
        out.push(tree_root(&hs[k..]));
    } else {
        audit_path(&hs[k..], idx - k, out);
        out.push(tree_root(&hs[..k]));
    }
}

// ---- closed and typed leaves (the verifier's shapes) ---------------------------------------------------------------------------

fn closed(o: &Map<String, Value>, keys: &[&str]) -> bool {
    o.keys().all(|k| keys.contains(&k.as_str())) && keys.iter().all(|k| o.contains_key(*k))
}

fn map_str(v: Option<&Value>, max: usize) -> Option<&str> {
    s(v).filter(|x| x.len() <= max)
}

fn is_dim_path(p: &str) -> bool {
    p == "action.resource" || crate::intent_strict::is_top_param_path(p)
}

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

fn dim_of(d: &Value, j: usize) -> R<Dim> {
    let o = d.as_object().ok_or_else(|| format!("dims[{j}] must be an object"))?;
    match s(o.get("kind")) {
        Some("num") => {
            if !closed(o, &["kind", "path", "lo", "hi", "cuts"]) {
                return Err(format!("dims[{j}] must be exactly {{kind, path, lo, hi, cuts}}"));
            }
            let path = s(o.get("path"))
                .filter(|p| crate::intent_strict::is_top_param_path(p))
                .ok_or_else(|| format!("dims[{j}].path must be action.params.<name>"))?;
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
                let vo = v
                    .as_object()
                    .filter(|vo| closed(vo, &["kind", "value"]))
                    .ok_or_else(|| format!("dims[{j}].values[{i}] must be exactly {{kind, value}}"))?;
                let kind = s(vo.get("kind")).filter(|k| matches!(*k, "exact" | "prefix" | "other"));
                let kind = kind.ok_or_else(|| format!("dims[{j}].values[{i}].kind must be exact, prefix or other"))?;
                let value = map_str(vo.get("value"), MAX_MAP_STRING_BYTES)
                    .ok_or_else(|| format!("dims[{j}].values[{i}].value must be a string of at most {MAX_MAP_STRING_BYTES} UTF-8 bytes"))?;
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

struct Header {
    first: i64,
    dims: Vec<Dim>,
}

fn header_of(h: &Value) -> R<Header> {
    let o = h.as_object().filter(|o| closed(o, &["verb", "first", "cells", "dims"])).ok_or("the header leaf must be exactly {verb, first, cells, dims}")?;
    map_str(o.get("verb"), 128).filter(|v| !v.is_empty()).ok_or("header.verb must be a non-empty string of at most 128 UTF-8 bytes")?;
    let first = nonneg(o.get("first")).filter(|f| *f < MAX_MAP_LEAVES).ok_or("header.first must be a leaf index")?;
    let cells = sint(o.get("cells"))
        .filter(|c| (1..=MAX_VERB_CELLS).contains(c))
        .ok_or_else(|| format!("header.cells must be a safe integer in [1, {MAX_VERB_CELLS}]"))?;
    let dv = o
        .get("dims")
        .and_then(Value::as_array)
        .filter(|d| d.len() <= MAX_MAP_DIMS)
        .ok_or_else(|| format!("header.dims must be an array of at most {MAX_MAP_DIMS}"))?;
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
    Ok(Header { first, dims })
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
    let Some(o) = m.as_object() else { return Some("the metrics leaf must be an object".into()) };
    let allowed = o.keys().all(|k| METRIC_FIELDS.contains(&k.as_str()) || k == "log2_vs_mbits");
    if !allowed || !METRIC_FIELDS.iter().all(|k| o.contains_key(*k)) {
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

/// The cell of omega under a header: per dimension the numeric cell containing the safe-integer value, or the exact category, else
/// the LONGEST prefix, else `other`; `flat` is row-major.
fn cell_of(h: &Header, resource: Option<&Value>, params: &Map<String, Value>) -> R<(Vec<i64>, i64)> {
    let mut cell = Vec::with_capacity(h.dims.len());
    let mut flat: i64 = 0;
    for d in &h.dims {
        let x = if d.path() == "action.resource" { resource } else { params.get(d.path().strip_prefix("action.params.").unwrap_or("")) };
        let i: Option<usize> = match d {
            Dim::Num { cells, .. } => sint(x).and_then(|v| cells.iter().position(|(lo, hi)| v >= *lo && v <= *hi)),
            Dim::Cat { values, .. } => s(x).map(|xs| {
                let exact = values.iter().position(|(k, v)| k == "exact" && v == xs);
                exact.unwrap_or_else(|| {
                    let best =
                        values.iter().enumerate().filter(|(_, (kind, v))| kind == "prefix" && xs.starts_with(v.as_str())).max_by_key(|(_, (_, v))| v.len());
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

// ---- the builder -------------------------------------------------------------------------------------------------------------

/// A committed map: the leaves in order (kind, leaf, salt), their hashes and the commitment.
pub struct Committed {
    pub map_commit: String,
    pub size: usize,
    pub leaves: Vec<(String, Value, Vec<u8>)>,
    hashes: Vec<Vec<u8>>,
    headers: Vec<(String, Header)>,
}

impl Committed {
    /// `{map_commit, size, leaves: [{kind, leaf, salt}]}`.
    pub fn to_json(&self) -> Value {
        let leaves: Vec<Value> = self.leaves.iter().map(|(k, l, salt)| json!({"kind": k, "leaf": l, "salt": b64_encode(salt)})).collect();
        json!({"map_commit": self.map_commit, "size": self.size, "leaves": leaves})
    }

    fn entry(&self, i: usize) -> Value {
        let mut path = vec![];
        audit_path(&self.hashes, i, &mut path);
        let p: Vec<String> = path.iter().map(|h| b64_encode(h)).collect();
        json!({"index": i, "salt": b64_encode(&self.leaves[i].2), "leaf": self.leaves[i].1, "path": p})
    }

    /// The opening of the header, cell and metrics leaves an action `{verb, resource}` with plaintext `params` falls on.
    pub fn disclose(&self, verb: &str, resource: Option<&Value>, params: &Map<String, Value>) -> R<Value> {
        let hi = self.headers.iter().position(|(v, _)| v == verb).ok_or_else(|| format!("commit_map.disclose: verb {verb} is not in the map"))?;
        let (cell, flat) = cell_of(&self.headers[hi].1, resource, params).map_err(|e| format!("commit_map.disclose: {e}"))?;
        let _ = cell;
        Ok(
            json!({"size": self.size, "header": self.entry(hi), "cell": self.entry(self.headers[hi].1.first as usize + flat as usize), "metrics": self.entry(self.size - 2)}),
        )
    }
}

fn dim_cell_count(d: &Value) -> R<i64> {
    if d["kind"] == json!("num") {
        let (lo, hi) = (sint(d.get("lo")).ok_or("lo")?, sint(d.get("hi")).ok_or("hi")?);
        let mut n = 0i64;
        let mut cur = lo;
        for c in d.get("cuts").and_then(Value::as_array).into_iter().flatten() {
            let c = sint(Some(c)).ok_or("cut")?;
            if c < lo || c > hi {
                continue;
            }
            if cur <= c - 1 {
                n += 1;
            }
            n += 1;
            cur = c + 1;
        }
        Ok(if cur <= hi { n + 1 } else { n })
    } else {
        Ok(d.get("values").and_then(Value::as_array).map_or(0, |v| v.len() as i64))
    }
}

/// Commit an Intent Map; `secret` (32 bytes kept per session) derives every leaf salt. Refuses a malformed map.
pub fn commit_intent_map(m: &Value, secret: &[u8]) -> R<Committed> {
    if secret.len() != 32 {
        return Err("commit_map: the secret is 32 bytes".into());
    }
    let verbs = m["omega"]["verbs"].as_array().ok_or("Cannot read properties of undefined (reading 'verbs')")?;
    let mut heads: Vec<(String, Vec<Value>, i64)> = vec![]; // (verb, header dims, cell count)
    for v in verbs {
        let verb = v["verb"].as_str().ok_or("verb")?.to_string();
        let mut dims = vec![];
        let mut total: i64 = 1;
        for d in v["dims"].as_array().ok_or("dims")? {
            if d["kind"] == json!("num") {
                let (lo, hi) = (sint(d.get("lo")).ok_or("lo")?, sint(d.get("hi")).ok_or("hi")?);
                let cuts: Vec<Value> = d
                    .get("cuts")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter(|c| sint(Some(c)).is_some_and(|x| lo <= x && x <= hi))
                    .cloned()
                    .collect();
                dims.push(json!({"kind": "num", "path": d["path"], "lo": d["lo"], "hi": d["hi"], "cuts": cuts}));
            } else {
                let vals: Vec<Value> =
                    d.get("values").and_then(Value::as_array).into_iter().flatten().map(|x| json!({"kind": x["kind"], "value": x["value"]})).collect();
                dims.push(json!({"kind": "cat", "path": d["path"], "values": vals}));
            }
            total = total.saturating_mul(dim_cell_count(&dims[dims.len() - 1])?);
            if total > MAX_VERB_CELLS {
                return Err("commit_map: too many cells".into());
            }
        }
        heads.push((verb, dims, total));
    }
    heads.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
    if heads.windows(2).any(|w| w[0].0 == w[1].0) {
        return Err("commit_map: duplicate verb".into());
    }
    let mut leaves: Vec<(String, Value)> = vec![];
    let mut nxt = heads.len() as i64;
    let mut firsts = vec![];
    for (verb, dims, n) in &heads {
        firsts.push(nxt);
        leaves.push(("header".into(), json!({"verb": verb, "first": nxt, "cells": n, "dims": dims})));
        nxt += n;
    }
    let all_cells = m["cells"].as_array().ok_or("cells")?;
    for (verb, dims, n) in &heads {
        let counts: Vec<i64> = dims.iter().map(dim_cell_count).collect::<R<_>>()?;
        let mut slots: Vec<Option<Value>> = vec![None; *n as usize];
        for c in all_cells.iter().filter(|c| c["verb"].as_str() == Some(verb.as_str())) {
            let cell = c["cell"].as_array().ok_or("cell")?;
            if cell.len() != counts.len() {
                return Err(format!("commitIntentMap: cell of {verb} has the wrong arity"));
            }
            let mut flat: i64 = 0;
            for (j, i) in cell.iter().enumerate() {
                match nonneg(Some(i)) {
                    Some(i) if i < counts[j] => flat = flat * counts[j] + i,
                    _ => return Err(format!("commitIntentMap: cell index out of range for {verb}")),
                }
            }
            let (p, g) = (c.get("p_ppm").ok_or("p_ppm")?, c.get("in_grant").ok_or("in_grant")?);
            slots[flat as usize] = Some(json!({"verb": verb, "cell": c["cell"], "p_ppm": p, "in_grant": g}));
        }
        if slots.iter().any(Option::is_none) {
            return Err(format!("commitIntentMap: the map does not list every cell of {verb}"));
        }
        leaves.extend(slots.into_iter().flatten().map(|l| ("cell".to_string(), l)));
    }
    let mm = m["metrics"].as_object().ok_or("metrics")?;
    let mut metrics = Map::new();
    for (k, v) in mm {
        if k != "log2_vs_mbits" {
            metrics.insert(k.clone(), v.clone());
        }
    }
    if let Some(l) = mm.get("log2_vs_mbits").filter(|v| !v.is_null()) {
        metrics.insert("log2_vs_mbits".into(), l.clone());
    }
    leaves.push(("metrics".into(), Value::Object(metrics)));
    leaves.push(("learner".into(), json!({"learner_digest": hash_strict(&m["learner"])?})));
    let mut parsed = vec![];
    for (kind, leaf) in &leaves {
        let e = match kind.as_str() {
            "header" => header_of(leaf).map(|h| parsed.push(h)).err(),
            "cell" => cell_error(leaf),
            "metrics" => metrics_error(leaf),
            _ => (!matches!(s(leaf.get("learner_digest")), Some(d) if decode_b64u_strict(d, Some(32)).is_some()))
                .then(|| "learner.learner_digest must be canonical base64url (32 bytes)".to_string()),
        };
        if let Some(e) = e {
            return Err(format!("commit_map: {e}"));
        }
    }
    let size = leaves.len();
    if size < 4 || size as i64 > MAX_MAP_LEAVES {
        return Err("commit_map: the map has too few or too many leaves".into());
    }
    let mut out = Vec::with_capacity(size);
    let mut hashes = Vec::with_capacity(size);
    for (i, (kind, leaf)) in leaves.into_iter().enumerate() {
        let salt = leaf_salt(secret, i as u64);
        hashes.push(leaf_hash(&kind, &salt, &leaf).ok_or("commit_map: a leaf has no strict canonical form")?);
        out.push((kind, leaf, salt));
    }
    let map_commit = commit_of(size as u64, &tree_root(&hashes));
    let headers = heads.iter().map(|h| h.0.clone()).zip(parsed).collect();
    Ok(Committed { map_commit, size, leaves: out, hashes, headers })
}

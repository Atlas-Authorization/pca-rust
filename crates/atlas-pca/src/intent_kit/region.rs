//! Regions: the part of the outcome space a cell question was about, written in value terms so an observation keeps its meaning when
//! the space is refined.
use super::omega::*;
use super::*;
use serde_json::{Map, Value};

pub fn region_of_cell(vs: &VerbSpace, idx: &[usize]) -> R<Value> {
    let mut dims = Map::new();
    for (k, d) in vs.dims.iter().enumerate() {
        let i = *idx.get(k).ok_or("regionOfCell: cell index missing")?;
        match d {
            Dim::Num { cells, path, .. } => {
                let (lo, hi) = *cells.get(i).ok_or_else(|| format!("cell index {i} out of range"))?;
                dims.insert(path.clone(), obj(vec![("kind", jstr("num")), ("lo", jn(lo)), ("hi", jn(hi))]));
            }
            Dim::Cat { values, path } => {
                let vals: Vec<Value> = values.iter().map(|v| obj(vec![("kind", jstr(&v.kind)), ("value", jstr(&v.value))])).collect();
                dims.insert(path.clone(), obj(vec![("kind", jstr("cat")), ("values", Value::Array(vals)), ("cells", jarr_usize(&[i]))]));
            }
        }
    }
    Ok(obj(vec![("verb", jstr(&vs.verb)), ("dims", Value::Object(dims))]))
}

fn parse_cat_values(rd: &Value) -> R<Vec<CatVal>> {
    let a = get(rd, "values").and_then(Value::as_array).ok_or("region: a categorical region dimension needs values")?;
    let mut out = vec![];
    for x in a {
        out.push(CatVal {
            kind: get_str(x, "kind").ok_or("region: bad value kind")?.to_string(),
            value: get_str(x, "value").ok_or("region: bad value")?.to_string(),
        });
    }
    Ok(out)
}

/// The cells of dimension d covered by the region dimension: `inner` (wholly inside) or `outer` (meeting it).
fn dim_cells_in(d: &Dim, rd: Option<&Value>, inner: bool) -> R<Vec<usize>> {
    let n = d.cell_count();
    let all: Vec<usize> = (0..n).collect();
    let Some(rd) = rd.filter(|r| truthy(Some(r))) else { return Ok(all) };
    let kind = get_str(rd, "kind");
    match d {
        Dim::Num { cells, path, .. } => {
            if kind != Some("num") {
                return Err(format!("region: {path} is numeric in \u{3a9} but categorical in the region"));
            }
            let rlo = get_num(rd, "lo").ok_or("region: a numeric region dimension needs lo")?;
            let rhi = get_num(rd, "hi").ok_or("region: a numeric region dimension needs hi")?;
            let mut out = vec![];
            for (i, (lo, hi)) in cells.iter().enumerate() {
                let ok = if inner { *lo >= rlo && *hi <= rhi } else { *hi >= rlo && *lo <= rhi };
                if ok {
                    out.push(i);
                }
            }
            Ok(out)
        }
        Dim::Cat { path, .. } => {
            if kind != Some("cat") {
                return Err(format!("region: {path} is categorical in \u{3a9} but numeric in the region"));
            }
            let rvals = parse_cat_values(rd)?;
            let in_set: Vec<usize> = get(rd, "cells").and_then(Value::as_array).map(|a| a.iter().filter_map(as_usize).collect()).unwrap_or_default();
            let mut out = vec![];
            for i in all {
                let rep = cat_rep(d, i)?;
                if cat_cell_of_vals(&rvals, &rep).is_some_and(|c| in_set.contains(&c)) {
                    out.push(i);
                }
            }
            Ok(out)
        }
    }
}

/// Flat cell indices of vs covered by the region (row-major, last dimension fastest); refuses a restriction the space lacks.
pub fn region_cells(vs: &VerbSpace, r: &Value, mode: &str) -> R<Vec<usize>> {
    if get_str(r, "verb") != Some(vs.verb.as_str()) {
        return Err(format!("region: verb {} does not match {}", get_str(r, "verb").unwrap_or("undefined"), vs.verb));
    }
    let dims = get(r, "dims").and_then(Value::as_object).ok_or("region: dims must be an object")?;
    for p in dims.keys() {
        if !vs.dims.iter().any(|d| d.path() == p) {
            return Err(format!("region: restricts {p}, which \u{3a9} has no dimension for"));
        }
    }
    let mut per: Vec<Vec<usize>> = vec![];
    for d in &vs.dims {
        per.push(dim_cells_in(d, dims.get(d.path()), mode == "inner")?);
    }
    if per.iter().any(|x| x.is_empty()) {
        return Ok(vec![]);
    }
    let mut acc: Vec<usize> = vec![0];
    for (k, cells) in per.iter().enumerate() {
        let size = vs.dims[k].cell_count();
        let mut next = Vec::with_capacity(acc.len() * cells.len());
        for f in &acc {
            for c in cells {
                next.push(f * size + c);
            }
        }
        acc = next;
    }
    Ok(acc)
}

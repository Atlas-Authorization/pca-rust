//! The Intent Map: a content-addressed, replayable artifact holding the outcome space, the learner parameters, every answer, the
//! learned cells, the conservative grant and the quantified fidelity (all probabilities and metrics are integer ppm so the digest is
//! language-portable). Native port of `@atlasauth/pca-intent` map.ts (learner construction and emission, and the shared-omega
//! aggregation the wallet's org layer uses; the committed-map verifier is `crate::intent_map`).
use super::learner::*;
use super::multi::*;
use super::omega::*;
use super::*;
use crate::wallet_omega::fdlibm;
use serde_json::{Map, Value};
use std::collections::HashMap;

const ORDER: [&str; 3] = ["reversible", "rate_limited", "irreversible"];

fn qz(x: f64) -> f64 {
    js_round(x * PPM) / PPM
}

pub fn ppm_i(x: f64) -> Value {
    jn(js_round(x * PPM))
}

/// `omegaToJson`: the map form of an outcome space (weights as ppm integers).
pub fn omega_to_json(o: &Omega) -> Value {
    let equal = match o.verbs.first() {
        None => true,
        Some(f) => o.verbs.iter().all(|v| (v.weight - f.weight).abs() < 1e-15),
    };
    let verbs: Vec<Value> = o
        .verbs
        .iter()
        .map(|v| {
            let mut m = Map::new();
            m.insert("verb".into(), jstr(&v.verb));
            if let Some(r) = &v.reversibility {
                m.insert("reversibility".into(), jstr(r));
            }
            m.insert("w".into(), jn(if equal { 1.0 } else { js_max(1.0, js_round(v.weight * PPM)) }));
            m.insert("dims".into(), Value::Array(v.dims.iter().map(Dim::to_json).collect()));
            Value::Object(m)
        })
        .collect();
    obj(vec![("verbs", Value::Array(verbs)), ("approximate", Value::Array(o.approximate.iter().map(|s| jstr(s)).collect()))])
}

/// `omegaFromJson`: the inverse (weights are the ppm integers over their total).
pub fn omega_from_json(j: &Value) -> R<Omega> {
    let vs = get(j, "verbs").and_then(Value::as_array).ok_or("omegaFromJson: verbs must be an array")?;
    let mut tot = 0.0;
    for v in vs {
        tot += get_num(v, "w").ok_or("omegaFromJson: every verb needs a numeric w")?;
    }
    let mut verbs = vec![];
    for v in vs {
        let mut dims = vec![];
        for d in get(v, "dims").and_then(Value::as_array).ok_or("omegaFromJson: dims must be an array")? {
            let mut dd = d.clone();
            if get_str(d, "kind") == Some("num") {
                if let Value::Object(m) = &mut dd {
                    if m.get("dist").map_or(true, Value::is_null) {
                        m.insert("dist".into(), jstr("uniform"));
                    }
                }
            }
            dims.push(Dim::from_json(&dd)?);
        }
        verbs.push(VerbSpace {
            verb: get_str(v, "verb").ok_or("omegaFromJson: verb")?.to_string(),
            reversibility: get_str(v, "reversibility").map(String::from),
            weight: get_num(v, "w").unwrap_or(0.0) / tot,
            dims,
        });
    }
    let mut approximate = vec![];
    for a in get(j, "approximate").and_then(Value::as_array).ok_or("omegaFromJson: approximate must be an array")? {
        approximate.push(a.as_str().ok_or("omegaFromJson: approximate must hold strings")?.to_string());
    }
    Ok(Omega { verbs, approximate })
}

pub fn grant_digest(g: &Value) -> R<String> {
    let mut inner = Map::new();
    if let Some(p) = get(g, "predicates").filter(|p| !p.is_null()) {
        inner.insert("predicates".into(), p.clone());
    }
    inner.insert("caveats".into(), get(g, "caveats").cloned().unwrap_or_else(|| Value::Array(vec![])));
    hash_strict(&obj(vec![("d", jstr("atlas-pca/intent-grant/v1")), ("g", Value::Object(inner))]))
}

fn null_mass_of(o: &Value, verb: &str) -> f64 {
    let nm = get(o, "nullMass");
    if let Some(n) = nm.and_then(num) {
        return n;
    }
    if let Some(v) = nm.and_then(Value::as_object).and_then(|m| m.get(verb)).filter(|v| !v.is_null()) {
        return num(v).unwrap_or(f64::NAN);
    }
    opt(o, "defaultNullMass").and_then(num).unwrap_or(0.2)
}

fn quantize_class(h: Option<&Value>) -> Value {
    let Some(h) = h.filter(|h| truthy(Some(h))) else { return obj(vec![("kind", jstr("box"))]) };
    if get_str(h, "kind") == Some("box") {
        return obj(vec![("kind", jstr("box"))]);
    }
    let decay = jn(qz(opt(h, "decay").and_then(num).unwrap_or(0.25)));
    if get_str(h, "kind") == Some("union") {
        return obj(vec![("kind", jstr("union")), ("k", get(h, "k").cloned().unwrap_or(Value::Null)), ("decay", decay)]);
    }
    obj(vec![
        ("kind", jstr("decision-list")),
        ("maxRules", get(h, "maxRules").cloned().unwrap_or(Value::Null)),
        ("decay", decay),
        ("conditions", opt(h, "conditions").cloned().unwrap_or_else(|| jstr("box"))),
    ])
}

fn anchor_opt(a: &Value) -> R<(Value, f64)> {
    let pol = get(a, "policy").ok_or("anchor: policy")?;
    let policy = obj(vec![
        ("predicates", get(pol, "predicates").cloned().unwrap_or(Value::Null)),
        ("caveats", opt(pol, "caveats").cloned().unwrap_or_else(|| Value::Array(vec![]))),
    ]);
    let lam = get_num(a, "lambda").ok_or("anchor: lambda must be a number")?;
    Ok((policy, js_round(lam * 1000.0) / 1000.0))
}

fn anchor_json(a: &Value) -> R<Value> {
    let pol = get(a, "policy").ok_or("anchor: policy")?;
    let lam = get_num(a, "lambda").ok_or("anchor: lambda must be a number")?;
    Ok(obj(vec![
        (
            "policy",
            obj(vec![
                ("predicates", get(pol, "predicates").cloned().unwrap_or(Value::Null)),
                ("caveats", opt(pol, "caveats").cloned().unwrap_or_else(|| Value::Array(vec![]))),
            ]),
        ),
        ("lambda_milli", jn(js_round(lam * 1000.0))),
    ]))
}

/// The learner's `priorMix` function for a data-form population prior (ppm-quantised like every map number).
fn prior_mix_of(pm: &Value) -> R<(f64, Box<dyn Fn(&VerbSpace, &dyn Fn(f64) -> bool) -> f64>)> {
    let mut by_verb: HashMap<String, Vec<(f64, f64, f64)>> = HashMap::new();
    for c in get(pm, "cells").and_then(Value::as_array).ok_or("pca-intent: priorMix needs cells")? {
        let q = qz(get_num(c, "q").ok_or("pca-intent: priorMix cells need q")?);
        let cell = get_num(c, "cell");
        let ok_cell = cell.is_some_and(|x| x.is_finite() && x.fract() == 0.0 && x.abs() <= 9007199254740991.0 && x >= 0.0);
        if !(q >= 0.0 && q <= 1.0) || !ok_cell {
            return Err("pca-intent: priorMix cells need q in [0, 1] and a cell index >= 0".into());
        }
        let verb = get_str(c, "verb").ok_or("pca-intent: priorMix cells need a verb")?.to_string();
        by_verb.entry(verb).or_default().push((cell.unwrap(), js_ln(q), js_ln(1.0 - q)));
    }
    let beta = qz(get_num(pm, "beta").ok_or("pca-intent: priorMix.beta must be a number")?);
    let f = move |vs: &VerbSpace, contains: &dyn Fn(f64) -> bool| -> f64 {
        let mut lw = 0.0f64;
        if let Some(ts) = by_verb.get(&vs.verb) {
            for (cell, lq, lnq) in ts {
                lw += if contains(*cell) { *lq } else { *lnq };
            }
        }
        crate::detmath::det_exp(lw)
    };
    Ok((beta, Box::new(f)))
}

fn js_ln(x: f64) -> f64 {
    // the weights are recomputed and compared by verifiers: the integer-arithmetic logarithm, not libm
    crate::detmath::det_ln(x)
}

/// Build a learner whose parameters are exactly representable in an Intent Map (ppm-quantised). `o` = the plain map parameters
/// (`eta`, `tau`, `strategy`, `nullMass` number or per-verb object, `defaultNullMass`, `hypothesisClass`, `agnosticSlack`, `anchor(s)`,
/// `monotone`, `etaPos`/`etaNeg`, `priorMix` `{beta, cells}`).
pub fn create_learner(omega: &Omega, o: Option<&Value>) -> R<IntentLearner> {
    let empty = Value::Object(Map::new());
    let o = o.filter(|v| !v.is_null()).unwrap_or(&empty);
    let eta0 = match opt(o, "eta") {
        None => 0.0,
        Some(v) => num(v).ok_or("pca-intent: eta must be a number")?,
    };
    let mut lo = LearnerOpts::default_opts();
    lo.eta = qz(eta0);
    lo.tau = Some(qz(match opt(o, "tau") {
        None => {
            if eta0 == 0.0 {
                1.0
            } else {
                0.95
            }
        }
        Some(v) => num(v).ok_or("pca-intent: tau must be a number")?,
    }));
    if let Some(s) = opt(o, "strategy") {
        lo.strategy = s.as_str().ok_or("pca-intent: strategy must be a string")?.to_string();
    }
    let oc = o.clone();
    lo.null_mass = Some(Box::new(move |vs: &VerbSpace| qz(null_mass_of(&oc, &vs.verb))));
    lo.hypothesis_class = Hc::from_json(Some(&quantize_class(get(o, "hypothesisClass"))))?;
    if let Some(a) = get(o, "agnosticSlack").filter(|v| !v.is_null()) {
        lo.agnostic_slack = Some(num(a).ok_or("pca-intent: agnosticSlack must be a non-negative integer")?);
    }
    if let Some(a) = opt(o, "anchor").filter(|a| truthy(Some(a))) {
        lo.anchors.push(anchor_opt(a)?);
    }
    if let Some(Value::Array(a)) = opt(o, "anchors") {
        for x in a {
            lo.anchors.push(anchor_opt(x)?);
        }
    }
    if let Some(m) = opt(o, "monotone").filter(|m| truthy(Some(m))) {
        let paths: Vec<String> = get(m, "paths")
            .and_then(Value::as_array)
            .ok_or("pca-intent: monotone.paths must be an array")?
            .iter()
            .filter_map(|p| p.as_str().map(String::from))
            .collect();
        lo.monotone = Some((paths, qz(opt(m, "offMass").and_then(num).unwrap_or(0.0))));
    }
    if let Some(v) = get(o, "etaPos") {
        lo.eta_pos = Some(qz(num(v).ok_or("pca-intent: etaPos must be a number")?));
    }
    if let Some(v) = get(o, "etaNeg") {
        lo.eta_neg = Some(qz(num(v).ok_or("pca-intent: etaNeg must be a number")?));
    }
    if let Some(pm) = opt(o, "priorMix").filter(|p| truthy(Some(p))) {
        lo.prior_mix = Some(prior_mix_of(pm)?);
    }
    let mut l = IntentLearner::new(omega, lo)?;
    l.map_params = Some(o.clone());
    Ok(l)
}

fn metrics_of(l: &mut IntentLearner) -> R<Value> {
    let m = l.metrics();
    let mut rmax = 0.0f64;
    for c in l.cells() {
        rmax += c.mass * (1.0 - c.p) * c.harm;
    }
    let g = |k: &str| get_num(&m, k).unwrap_or(f64::NAN);
    let rr = g("residualRisk");
    Ok(obj(vec![
        ("residual_risk_ppm", ppm_i(rr)),
        ("burden_ppm", ppm_i(g("burden"))),
        ("uncertainty_ppm", ppm_i(g("uncertainty"))),
        ("disagreement_ppm", ppm_i(g("disagreementMass"))),
        ("mean_harm_ppm", ppm_i(g("meanHarm"))),
        ("fidelity_est_ppm", ppm_i(if rmax > 0.0 { 1.0 - rr / rmax } else { 1.0 })),
        ("entropy_mbits", jn(js_round(g("entropyBits") * 1000.0))),
        (
            "log2_vs_mbits",
            match get(&m, "log2VersionSpace") {
                Some(v) if !v.is_null() => jn(js_round(num(v).unwrap_or(f64::NAN) * 1000.0)),
                _ => Value::Null,
            },
        ),
        ("questions", get(&m, "questions").cloned().unwrap_or(Value::Null)),
        ("conflicts", get(&m, "conflicts").cloned().unwrap_or(Value::Null)),
    ]))
}

/// Emit the Intent Map of a learner built with [`create_learner`].
pub fn emit_intent_map(l: &mut IntentLearner, intent_ref: Option<&str>) -> R<Value> {
    let o = l.map_params.clone().ok_or("pca-intent: build the learner with createLearner() so its parameters are serialisable")?;
    let mut null_mass_ppm = Map::new();
    for vs in &l.omega.verbs {
        null_mass_ppm.insert(vs.verb.clone(), ppm_i(null_mass_of(&o, &vs.verb)));
    }
    let grant = l.synthesize()?;
    let hc = l.hypothesis_class.clone();
    let mut learner = Map::new();
    learner.insert("hypothesis_class".into(), jstr(hc.name()));
    match &hc {
        Hc::Union { k, decay } => {
            learner.insert("class_params".into(), obj(vec![("k", jn(*k as f64)), ("decay_ppm", ppm_i(*decay))]));
        }
        Hc::DList { max_rules, decay, .. } => {
            learner.insert("class_params".into(), obj(vec![("max_rules", jn(*max_rules as f64)), ("decay_ppm", ppm_i(*decay))]));
        }
        Hc::Box => {}
    }
    if let Some(s) = l.agnostic_slack {
        learner.insert("agnostic_slack".into(), jn(s));
    }
    learner.insert("eta_ppm".into(), ppm_i(l.eta));
    learner.insert("tau_ppm".into(), ppm_i(l.tau));
    learner.insert("strategy".into(), jstr(&l.strategy));
    learner.insert("null_mass_ppm".into(), Value::Object(null_mass_ppm));
    if let Some(a) = opt(&o, "anchor").filter(|a| truthy(Some(a))) {
        learner.insert("anchor".into(), anchor_json(a)?);
    }
    if let Some(Value::Array(a)) = opt(&o, "anchors") {
        if !a.is_empty() {
            let mut v = vec![];
            for x in a {
                v.push(anchor_json(x)?);
            }
            learner.insert("anchors".into(), Value::Array(v));
        }
    }
    if let Some(m) = opt(&o, "monotone").filter(|m| truthy(Some(m))) {
        let paths = get(m, "paths").cloned().unwrap_or(Value::Null);
        learner.insert("monotone".into(), obj(vec![("paths", paths), ("off_ppm", ppm_i(opt(m, "offMass").and_then(num).unwrap_or(0.0)))]));
    }
    if get(&o, "etaPos").is_some() || get(&o, "etaNeg").is_some() {
        learner.insert("noise".into(), obj(vec![("eta_pos_ppm", ppm_i(l.eta_pos)), ("eta_neg_ppm", ppm_i(l.eta_neg))]));
    }
    if let Some(pm) = opt(&o, "priorMix").filter(|p| truthy(Some(p))) {
        let mut cells = vec![];
        for c in get(pm, "cells").and_then(Value::as_array).ok_or("priorMix cells")? {
            cells.push(obj(vec![
                ("verb", get(c, "verb").cloned().unwrap_or(Value::Null)),
                ("cell", get(c, "cell").cloned().unwrap_or(Value::Null)),
                ("q_ppm", ppm_i(get_num(c, "q").unwrap_or(f64::NAN))),
            ]));
        }
        learner.insert("prior_mix".into(), obj(vec![("beta_ppm", ppm_i(get_num(pm, "beta").unwrap_or(f64::NAN))), ("cells", Value::Array(cells))]));
    }
    let mut observations = vec![];
    for x in &l.observations {
        let mut ob = Map::new();
        for k in ["verb", "values", "y", "source"] {
            ob.insert(k.into(), get(x, k).cloned().unwrap_or(Value::Null));
        }
        if let Some(r) = get(x, "region").filter(|r| !r.is_null()) {
            ob.insert("region".into(), r.clone());
        }
        observations.push(Value::Object(ob));
    }
    let cells: Vec<Value> = l
        .cells()
        .iter()
        .map(|c| obj(vec![("verb", jstr(&c.verb)), ("cell", jarr_usize(&c.cell)), ("p_ppm", ppm_i(c.p)), ("in_grant", Value::Bool(c.in_grant))]))
        .collect();
    let gd = grant_digest(&grant)?;
    let metrics = metrics_of(l)?;
    Ok(obj(vec![
        ("v", jn(1.0)),
        ("kind", jstr("pca-intent-map")),
        ("intent_ref", intent_ref.map(jstr).unwrap_or(Value::Null)),
        ("principals", Value::Array(intent_ref.filter(|r| !r.is_empty()).map(|r| vec![jstr(r)]).unwrap_or_default())),
        ("omega", omega_to_json(&l.omega)),
        ("learner", Value::Object(learner)),
        ("observations", Value::Array(observations)),
        ("cells", Value::Array(cells)),
        ("grant", grant),
        ("grant_digest", jstr(&gd)),
        ("metrics", metrics),
    ]))
}

pub const INTENT_MAP_DOMAIN: &str = "atlas-pca/intent-map/v1";

/// Content address of an Intent Map.
pub fn intent_map_digest(m: &Value) -> R<String> {
    hash_strict(&obj(vec![("d", jstr(INTENT_MAP_DOMAIN)), ("m", m.clone())]))
}

fn cp_get<'a>(cp: Option<&'a Value>, k: &str) -> Option<&'a Value> {
    cp.and_then(|c| opt(c, k))
}

/// The learner parameters a map records (the inverse of what [`emit_intent_map`] writes): `createLearner` options as plain data.
pub fn map_learner_options(m: &Value) -> R<Value> {
    let lr = &m["learner"];
    let mut null_mass = Map::new();
    for (k, v) in lr["null_mass_ppm"].as_object().ok_or("learner.null_mass_ppm must be an object")? {
        null_mass.insert(k.clone(), jn(num(v).ok_or("null mass must be a number")? / PPM));
    }
    let cp = get(lr, "class_params");
    let hcn = lr["hypothesis_class"].as_str().unwrap_or("");
    let decay = match cp_get(cp, "decay_ppm") {
        Some(v) => num(v).ok_or("decay_ppm must be a number")? / PPM,
        None => 250_000.0 / PPM,
    };
    let conditions = if hcn == "per-verb-decision-list/v1" { "atomic" } else { "box" };
    let hc = if hcn == "per-verb-union/v1" {
        obj(vec![("kind", jstr("union")), ("k", cp_get(cp, "k").cloned().unwrap_or_else(|| jn(2.0))), ("decay", jn(decay))])
    } else if hcn == "per-verb-decision-list/v1" || hcn == "per-verb-decision-list/v2" {
        obj(vec![
            ("kind", jstr("decision-list")),
            ("maxRules", cp_get(cp, "max_rules").cloned().unwrap_or_else(|| jn(2.0))),
            ("decay", jn(decay)),
            ("conditions", jstr(conditions)),
        ])
    } else {
        obj(vec![("kind", jstr("box"))])
    };
    let mut out = Map::new();
    out.insert("eta".into(), jn(num(&lr["eta_ppm"]).ok_or("eta_ppm")? / PPM));
    out.insert("tau".into(), jn(num(&lr["tau_ppm"]).ok_or("tau_ppm")? / PPM));
    out.insert("strategy".into(), lr["strategy"].clone());
    out.insert("nullMass".into(), Value::Object(null_mass));
    out.insert("hypothesisClass".into(), hc);
    if let Some(s) = opt(lr, "agnostic_slack") {
        out.insert("agnosticSlack".into(), s.clone());
    }
    let anchor =
        |a: &Value| -> R<Value> { Ok(obj(vec![("policy", a["policy"].clone()), ("lambda", jn(num(&a["lambda_milli"]).ok_or("lambda_milli")? / 1000.0))])) };
    if let Some(a) = get(lr, "anchor").filter(|x| truthy(Some(x))) {
        out.insert("anchor".into(), anchor(a)?);
    }
    if let Some(list) = get(lr, "anchors").filter(|x| truthy(Some(x))).and_then(Value::as_array) {
        let mut v = vec![];
        for a in list {
            v.push(anchor(a)?);
        }
        out.insert("anchors".into(), Value::Array(v));
    }
    if let Some(mo) = get(lr, "monotone").filter(|x| truthy(Some(x))) {
        out.insert("monotone".into(), obj(vec![("paths", mo["paths"].clone()), ("offMass", jn(num(&mo["off_ppm"]).ok_or("off_ppm")? / PPM))]));
    }
    if let Some(nz) = get(lr, "noise").filter(|x| truthy(Some(x))) {
        out.insert("etaPos".into(), jn(num(&nz["eta_pos_ppm"]).ok_or("eta_pos_ppm")? / PPM));
        out.insert("etaNeg".into(), jn(num(&nz["eta_neg_ppm"]).ok_or("eta_neg_ppm")? / PPM));
    }
    if let Some(pm) = get(lr, "prior_mix").filter(|x| truthy(Some(x))) {
        let mut cells = vec![];
        for c in pm["cells"].as_array().ok_or("prior_mix.cells must be an array")? {
            cells.push(obj(vec![("verb", c["verb"].clone()), ("cell", c["cell"].clone()), ("q", jn(num(&c["q_ppm"]).ok_or("q_ppm")? / PPM))]));
        }
        out.insert("priorMix".into(), obj(vec![("beta", jn(num(&pm["beta_ppm"]).ok_or("beta_ppm")? / PPM)), ("cells", Value::Array(cells))]));
    }
    Ok(Value::Object(out))
}

/// Rebuild the learner a map describes (omega + prior + observations).
pub fn learner_from_map(m: &Value) -> R<IntentLearner> {
    let mut l = create_learner(&omega_from_json(&m["omega"])?, Some(&map_learner_options(m)?))?;
    for o in m["observations"].as_array().ok_or("observations must be an array")? {
        let y = num(&o["y"]).ok_or("observation y must be a number")?;
        let source = o["source"].as_str().ok_or("observation source must be a string")?;
        l.observe(&obj(vec![("verb", o["verb"].clone()), ("values", o["values"].clone())]), y as i64, source, get(o, "region"))?;
    }
    Ok(l)
}

/// Two probabilities in ppm are close only when both are numbers within 2 of each other. Written as the positive condition so a
/// missing, non-numeric or NaN claim is a mismatch (the old `> 2` test let it through).
fn close2(a: &Value, b: &Value) -> bool {
    matches!((num(a), num(b)), (Some(x), Some(y)) if (x - y).abs() <= 2.0)
}

/// Replay a single-principal map and check every number, every cell and the grant: `{ok, problems}`.
pub fn verify_intent_map(m: &Value) -> Value {
    let mut problems: Vec<String> = vec![];
    let r: R<()> = (|| -> R<()> {
        if !(m.is_object() && num(&m["v"]) == Some(1.0) && m["kind"].as_str() == Some("pca-intent-map")) {
            problems.push("not an intent map v1".into());
            return Ok(());
        }
        if m["principals"].as_array().ok_or("principals must be an array")?.len() > 1 || opt(m, "aggregation").is_some() {
            problems.push("combined map: verify each principal map and recombine with verifyAggregate".into());
            return Ok(());
        }
        let mut l = learner_from_map(m)?;
        let r = emit_intent_map(&mut l, m["intent_ref"].as_str())?;
        let claimed = &m["grant_digest"];
        if &r["grant_digest"] != claimed || Value::String(grant_digest(&m["grant"])?) != *claimed {
            problems.push("grant does not match the replayed posterior".into());
        }
        let (rc, mc) = (r["cells"].as_array().ok_or("cells must be an array")?, m["cells"].as_array().ok_or("cells must be an array")?);
        if rc.len() != mc.len() {
            problems.push("cell count differs".into());
        } else {
            for (i, c) in rc.iter().enumerate() {
                let x = &mc[i];
                if c["verb"] != x["verb"] || c["in_grant"] != x["in_grant"] || !close2(&c["p_ppm"], &x["p_ppm"]) {
                    problems.push(format!("cell {i} differs"));
                }
            }
        }
        if let Some(rm) = r["metrics"].as_object() {
            for (k, a) in rm {
                let b = get(&m["metrics"], k);
                let bad =
                    if a.is_null() || b.is_some_and(Value::is_null) { !(a.is_null() && b.is_some_and(Value::is_null)) } else { !b.is_some_and(|b| close2(a, b)) };
                if bad {
                    problems.push(format!(
                        "metric {k} differs ({} claimed, {} replayed)",
                        b.map(crate::intent_v2::js_value_string).unwrap_or_else(|| "undefined".into()),
                        crate::intent_v2::js_value_string(a)
                    ));
                }
            }
        }
        Ok(())
    })();
    if let Err(e) = r {
        problems.push(format!("replay failed: {e}"));
    }
    obj(vec![("ok", Value::Bool(problems.is_empty())), ("problems", Value::Array(problems.iter().map(|p| jstr(p)).collect()))])
}

/// Aggregate single-principal maps over a SHARED omega under a rule; the result has `aggregation` set.
pub fn aggregate_intent_maps(maps: &Value, rule: &Value, opts: Option<&Value>) -> R<Value> {
    let ms = maps.as_array().ok_or("aggregateIntentMaps: maps must be an array")?;
    if ms.is_empty() {
        return Err("aggregateIntentMaps: no maps".into());
    }
    let om0 = crate::js_stringify(get(&ms[0], "omega").ok_or("aggregateIntentMaps: map without omega")?);
    for m in ms {
        if crate::js_stringify(get(m, "omega").ok_or("aggregateIntentMaps: map without omega")?) != om0 {
            return Err("aggregateIntentMaps: maps must share \u{3a9} (lift them with crossOrgAggregate)".into());
        }
    }
    for m in ms {
        let single = get(m, "principals").and_then(Value::as_array).is_some_and(|p| p.len() == 1);
        if opt(m, "aggregation").is_some() || !single || !get(m, "intent_ref").is_some_and(Value::is_string) {
            return Err("aggregateIntentMaps: every input must be a single-principal map with an intent_ref".into());
        }
    }
    let refs: Vec<String> = ms.iter().map(|m| get_str(m, "intent_ref").unwrap_or("").to_string()).collect();
    for (i, r) in refs.iter().enumerate() {
        if refs[..i].contains(r) {
            return Err("aggregateIntentMaps: duplicate principal".into());
        }
    }
    let n = normalize_rule(rule, &refs)?;
    let omega = omega_from_json(get(&ms[0], "omega").unwrap())?;
    let mut stats: Vec<(f64, f64)> = vec![];
    for vs in &omega.verbs {
        for c in 0..verb_cell_count(vs) {
            stats.push(cell_stats(vs, &decode_cell(vs, c))?);
        }
    }
    let cells0 = get(&ms[0], "cells").and_then(Value::as_array).ok_or("aggregateIntentMaps: cells must be an array")?;
    let mcell = |m: &Value, i: usize| -> R<Value> {
        get(m, "cells").and_then(Value::as_array).and_then(|a| a.get(i)).cloned().ok_or_else(|| "aggregateIntentMaps: cell index out of range".to_string())
    };
    let mut cells: Vec<Value> = vec![];
    let mut in_grants: Vec<bool> = vec![];
    for (i, c) in cells0.iter().enumerate() {
        let mut ps = vec![];
        let mut ins = vec![];
        for m in ms {
            let x = mcell(m, i)?;
            ps.push(get_num(&x, "p_ppm").unwrap_or(f64::NAN) / PPM);
            ins.push(truthy(get(&x, "in_grant")));
        }
        let ig = rule_admits(&n, &ins)?;
        in_grants.push(ig);
        cells.push(obj(vec![
            ("verb", get(c, "verb").cloned().unwrap_or(Value::Null)),
            ("cell", get(c, "cell").cloned().unwrap_or(Value::Null)),
            ("p_ppm", ppm_i(joint_acceptance(&n, &ps)?)),
            ("in_grant", Value::Bool(ig)),
        ]));
    }
    let mut predicates: Vec<Value> = vec![];
    let mut worst: i32 = -1;
    let mut off = 0usize;
    for vs in &omega.verbs {
        let nc = verb_cell_count(vs);
        let mut allowed = vec![0u8; nc];
        let mut any = false;
        for c in 0..nc {
            if *in_grants.get(off + c).ok_or("aggregateIntentMaps: cell count differs")? {
                allowed[c] = 1;
                any = true;
            }
        }
        off += nc;
        if !any {
            continue;
        }
        let rv = vs.reversibility.as_deref().and_then(|r| ORDER.iter().position(|x| *x == r)).map(|i| i as i32).unwrap_or(-1);
        worst = worst.max(rv);
        predicates.extend(boxes_to_predicates(vs, &allowed)?);
    }
    let grant = obj(vec![
        ("predicates", Value::Array(predicates)),
        (
            "caveats",
            Value::Array(if worst >= 0 { vec![obj(vec![("type", jstr("reversibility_max")), ("class", jstr(ORDER[worst as usize]))])] } else { vec![] }),
        ),
    ]);
    // each principal's own posterior estimate of the JOINT grant
    let orgs = opts.and_then(|o| get(o, "orgs"));
    let mut per: Vec<(String, Option<Value>, f64, f64, f64)> = vec![];
    for (i, m) in ms.iter().enumerate() {
        let (mut r, mut b, mut rmax) = (0.0f64, 0.0f64, 0.0f64);
        let cs = get(m, "cells").and_then(Value::as_array).ok_or("aggregateIntentMaps: cells must be an array")?;
        for (j, c) in cs.iter().enumerate() {
            let p = get_num(c, "p_ppm").unwrap_or(f64::NAN) / PPM;
            let (mass, harm) = *stats.get(j).ok_or("aggregateIntentMaps: cell count differs")?;
            rmax += mass * (1.0 - p) * harm;
            if *in_grants.get(j).ok_or("aggregateIntentMaps: cell count differs")? {
                r += mass * (1.0 - p) * harm;
            } else {
                b += mass * p;
            }
        }
        let org = orgs.and_then(|o| get(o, &refs[i])).filter(|v| truthy(Some(v))).cloned();
        per.push((refs[i].clone(), org, r, b, if rmax > 0.0 { 1.0 - r / rmax } else { 1.0 }));
    }
    let metric_of =
        |m: &Value, k: &str| -> Value { get(get(m, "metrics").unwrap_or(&Value::Null), k).cloned().filter(|v| !v.is_null()).unwrap_or_else(|| jn(0.0)) };
    let worst_metric = |k: &str, sum: bool| -> f64 {
        let vals: Vec<f64> = ms.iter().map(|m| num(&metric_of(m, k)).unwrap_or(f64::NAN)).collect();
        if sum {
            vals.iter().sum()
        } else {
            vals.iter().cloned().fold(f64::NEG_INFINITY, js_max)
        }
    };
    let kind = get_str(rule, "kind").unwrap_or("");
    let mut aggregation = Map::new();
    aggregation.insert("rule".into(), jstr(kind));
    if kind == "quorum" {
        aggregation.insert("k".into(), get(rule, "k").cloned().unwrap_or(Value::Null));
    }
    if kind == "weighted" {
        let mut w = Map::new();
        for (i, r) in refs.iter().enumerate() {
            w.insert(r.clone(), jn(n.weights[i]));
        }
        aggregation.insert("weights".into(), Value::Object(w));
        aggregation.insert("threshold".into(), get(rule, "threshold").cloned().unwrap_or(Value::Null));
    }
    aggregation.insert("vetoers".into(), Value::Array(refs.iter().enumerate().filter(|(i, _)| n.veto[*i]).map(|(_, r)| jstr(r)).collect()));
    let mut pp = vec![];
    let (mut max_r, mut max_b) = (f64::NEG_INFINITY, f64::NEG_INFINITY);
    for (r, org, rr, bb, _) in &per {
        let mut e = Map::new();
        e.insert("intent_ref".into(), jstr(r));
        if let Some(o) = org {
            e.insert("org".into(), o.clone());
        }
        let (rp, bp) = (js_round(rr * PPM), js_round(bb * PPM));
        max_r = js_max(max_r, rp);
        max_b = js_max(max_b, bp);
        e.insert("residual_risk_ppm".into(), jn(rp));
        e.insert("burden_ppm".into(), jn(bp));
        pp.push(Value::Object(e));
    }
    aggregation.insert("per_principal".into(), Value::Array(pp));
    let min_f = per.iter().map(|x| x.4).fold(f64::INFINITY, js_min);
    let log2_null = ms.iter().any(|m| get(get(m, "metrics").unwrap_or(&Value::Null), "log2_vs_mbits").map_or(true, Value::is_null));
    let metrics = obj(vec![
        ("residual_risk_ppm", jn(max_r)),
        ("burden_ppm", jn(max_b)),
        ("uncertainty_ppm", jn(worst_metric("uncertainty_ppm", false))),
        ("disagreement_ppm", jn(worst_metric("disagreement_ppm", false))),
        ("mean_harm_ppm", get(get(&ms[0], "metrics").unwrap_or(&Value::Null), "mean_harm_ppm").cloned().unwrap_or(Value::Null)),
        ("fidelity_est_ppm", ppm_i(min_f)),
        ("entropy_mbits", jn(worst_metric("entropy_mbits", true))),
        ("log2_vs_mbits", if log2_null { Value::Null } else { jn(worst_metric("log2_vs_mbits", true)) }),
        ("questions", jn(worst_metric("questions", true))),
        ("conflicts", jn(worst_metric("conflicts", true))),
    ]);
    let observations: Vec<Value> = ms.iter().flat_map(|m| get(m, "observations").and_then(Value::as_array).cloned().unwrap_or_default()).collect();
    let gd = grant_digest(&grant)?;
    Ok(obj(vec![
        ("v", jn(1.0)),
        ("kind", jstr("pca-intent-map")),
        ("intent_ref", Value::Null),
        ("principals", Value::Array(refs.iter().map(|r| jstr(r)).collect())),
        ("omega", get(&ms[0], "omega").cloned().unwrap_or(Value::Null)),
        ("learner", get(&ms[0], "learner").cloned().unwrap_or(Value::Null)),
        ("observations", Value::Array(observations)),
        ("cells", Value::Array(cells)),
        ("grant", grant),
        ("grant_digest", jstr(&gd)),
        ("metrics", metrics),
        ("aggregation", Value::Object(aggregation)),
    ]))
}

/// `orgLayerFromMaps`: an org layer that is itself a LEARNED map over a shared omega: the joint grant of the org approvers' maps under the
/// org's rule; its uncertain cells go to the org's approvers.
pub fn org_layer_from_maps(maps: &Value, rule: &Value) -> R<Value> {
    let m = aggregate_intent_maps(maps, rule, None)?;
    let policy = get(&m, "grant").cloned().unwrap_or(Value::Null);
    Ok(obj(vec![("map", m), ("policy", policy)]))
}

#[cfg(test)]
mod close_tests {
    use super::close2;
    use serde_json::{json, Value};

    #[test]
    fn a_claim_that_is_missing_or_not_a_number_is_never_close() {
        assert!(close2(&json!(100), &json!(102)));
        assert!(close2(&json!(100), &json!(98.0)));
        assert!(!close2(&json!(100), &json!(103)));
        assert!(!close2(&json!(100), &Value::Null)); // a deleted claim reads as null/absent
        assert!(!close2(&json!(100), &json!("100")));
        assert!(!close2(&json!(100), &json!(true)));
        assert!(!close2(&json!(100), &json!([100])));
        assert!(!close2(&Value::Null, &json!(100)));
    }
}

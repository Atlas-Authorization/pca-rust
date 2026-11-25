//! Lazy just-in-time elicitation: the ordered per-visit decision, the cell coordinates carried by a signed `pca-intent-required`, its
//! wallet-side body and check, the delta cells between two answers and the minted delta grant.
use super::learner::*;
use super::omega::*;
use super::*;
use crate::agent::{KeyPair, Suite};
use serde_json::{Map, Value};

pub const INTENT_ACTION_DOMAIN: &str = "atlas-pca/intent-action/v1";

/// A ceiling check: `false` puts the outcome outside the ceiling.
pub type Ceiling = fn(&VerbSpace, &Value) -> bool;

/// The named ceilings of the conformance corpus: `all`, `none`, `amountLe60` (the amount value, when a number, is <= 60) and `notGmail`.
pub fn named_ceiling(name: &str) -> R<Ceiling> {
    fn all(_: &VerbSpace, _: &Value) -> bool {
        true
    }
    fn none(_: &VerbSpace, _: &Value) -> bool {
        false
    }
    fn amount_le_60(_: &VerbSpace, o: &Value) -> bool {
        match get(o, "values").and_then(|v| get(v, "action.params.amount")).and_then(num) {
            Some(a) => a <= 60.0,
            None => true,
        }
    }
    fn not_gmail(_: &VerbSpace, o: &Value) -> bool {
        get_str(o, "verb") != Some("gmail.send")
    }
    match name {
        "all" => Ok(all),
        "none" => Ok(none),
        "amountLe60" => Ok(amount_le_60),
        "notGmail" => Ok(not_gmail),
        _ => Err(format!("unknown ceiling {name}")),
    }
}

/// The ordered lazy-elicitation decision: schema violation, ceiling, denied, admit, or intent_required. `conform` is
/// `{ok, code?, reason?}`.
pub fn decide_visit(l: &mut IntentLearner, lifted: &Value, conform: &Value, ceilings: &[Ceiling], in_effective: bool) -> R<Value> {
    if !truthy(get(conform, "ok")) {
        let part = |k: &str| get(conform, k).map(crate::intent_v2::js_value_string).unwrap_or_else(|| "undefined".to_string());
        return Ok(obj(vec![("kind", jstr("schema_violation")), ("reason", jstr(&format!("{}: {}", part("code"), part("reason"))))]));
    }
    let vs = get_str(lifted, "verb").and_then(|v| l.omega.verb(v)).cloned();
    let cell = vs.as_ref().and_then(|v| cell_of(v, lifted));
    let (Some(vs), Some(cell)) = (vs, cell) else {
        return Ok(obj(vec![("kind", jstr("schema_violation")), ("reason", jstr("the lifted action lies outside \u{3a9}\u{303}"))]));
    };
    for c in ceilings {
        if !c(&vs, lifted) {
            return Ok(obj(vec![("kind", jstr("ceiling"))]));
        }
    }
    let vetoed = l.is_vetoed(lifted);
    let p = l.acceptance(lifted);
    if vetoed || p <= 0.0 {
        return Ok(obj(vec![("kind", jstr("intent_denied")), ("vetoed", Value::Bool(vetoed))]));
    }
    if in_effective {
        return Ok(obj(vec![("kind", jstr("admit")), ("cell", jarr_usize(&cell))]));
    }
    Ok(obj(vec![("kind", jstr("intent_required")), ("cell", jarr_usize(&cell)), ("p", jn(p))]))
}

/// The coordinates of one cell (numeric: `[i, i]`; categorical: the cell's value). Never text about the value.
pub fn cell_coords(vs: &VerbSpace, cell: &[usize]) -> R<Value> {
    let mut out = Map::new();
    for (k, d) in vs.dims.iter().enumerate() {
        let i = *cell.get(k).ok_or("cellCoords: cell index missing")?;
        let v = match d {
            Dim::Num { .. } => Value::Array(vec![jn(i as f64), jn(i as f64)]),
            Dim::Cat { values, .. } => Value::Array(vec![jstr(&values.get(i).ok_or("cellCoords: cell index out of range")?.value)]),
        };
        out.insert(d.path().to_string(), v);
    }
    Ok(Value::Object(out))
}

/// Coordinates -> per-dimension cell indices (the inverse of [`cell_coords`] for one cell), or `None`.
pub fn cell_from_coords(vs: &VerbSpace, coords: &Value) -> Option<Vec<f64>> {
    let m = coords.as_object()?;
    if m.len() != vs.dims.len() {
        return None;
    }
    let mut out = vec![];
    for d in &vs.dims {
        let c = m.get(d.path())?.as_array()?;
        match d {
            Dim::Num { .. } => {
                if c.len() < 2 {
                    return None;
                }
                let (a, b) = (num(&c[0])?, num(&c[1])?);
                if a != b {
                    return None;
                }
                out.push(a);
            }
            Dim::Cat { values, .. } => {
                if c.len() != 1 {
                    return None;
                }
                let s = c[0].as_str()?;
                out.push(values.iter().position(|v| v.value == s)? as f64);
            }
        }
    }
    Some(out)
}

/// The action digest a JIT consent is bound to.
pub fn intent_action_digest(action: &Value) -> R<String> {
    let mut a = Map::new();
    for k in ["verb", "resource", "params_digest", "reversibility_class"] {
        a.insert(k.into(), get(action, k).cloned().ok_or_else(|| format!("intentActionDigest: action.{k} is missing"))?);
    }
    hash_strict(&obj(vec![("d", jstr(INTENT_ACTION_DOMAIN)), ("action", Value::Object(a))]))
}

/// The site's `pca-intent-required` body for a visited uncertain cell (sign it with [`signed_intent_required`]). `i` =
/// `{session, mapDigest, schemaDigest, pcactn, questionId, friction, deliveredTo, expiresAt, vs, cell}`.
pub fn intent_required_body(i: &Value) -> R<Value> {
    let m = |k: &str| get(i, k).cloned().ok_or_else(|| format!("intentRequiredBody: {k} is missing"));
    let vs = VerbSpace::from_json(get(i, "vs").ok_or("Cannot read properties of undefined (reading 'verb')")?)?;
    let cell: Vec<usize> =
        get(i, "cell").and_then(Value::as_array).ok_or("intentRequiredBody: cell is missing")?.iter().map(|x| as_usize(x).unwrap_or(usize::MAX)).collect();
    let pcactn = m("pcactn")?;
    Ok(obj(vec![
        ("v", jn(1.0)),
        ("kind", jstr("pca-intent-required")),
        ("session", m("session")?),
        ("map_digest", m("mapDigest")?),
        ("schema", m("schemaDigest")?),
        ("pcactn_digest", jstr(&hash_strict(&pcactn)?)),
        ("action_digest", jstr(&intent_action_digest(get(&pcactn, "action").ok_or("intentRequiredBody: pcactn.action is missing")?)?)),
        ("cell", obj(vec![("verb", jstr(&vs.verb)), ("coords", cell_coords(&vs, &cell)?)])),
        ("reason", jstr("uncertain")),
        ("question_id", m("questionId")?),
        ("friction", m("friction")?),
        ("delivered_to", m("deliveredTo")?),
        ("expires_at", m("expiresAt")?),
    ]))
}

/// The body signed as the site (`kid`, the site's Ed25519 key from its b64u seed).
pub fn signed_intent_required(i: &Value, kid: &str, site_seed: &str) -> R<Value> {
    let body = intent_required_body(i)?;
    let key = KeyPair::from_seed_b64u(site_seed)?;
    crate::signers_more::sign_intent_required(&body, kid, &key, &Suite::default())
}

/// The wallet's check of an intent_required: the site signature under its keys and the expiry are verified first; the session, map,
/// action and the cell are then re-derived from the wallet's own space. Any disagreement refuses the question. `w` =
/// `{keys, now, session, mapDigest, pcactn, lifted, omegaTilde}`.
pub fn wallet_check_intent_required(body: &Value, w: &Value) -> R<Value> {
    let v = crate::wallet_channel::verify_intent_required(body, get(w, "keys"), get(w, "now"));
    if get(&v, "ok") != Some(&Value::Bool(true)) {
        return Ok(v);
    }
    let no = |reason: &str| -> R<Value> { Ok(obj(vec![("ok", Value::Bool(false)), ("reason", jstr(reason))])) };
    if get(body, "session") != get(w, "session") || get(body, "map_digest") != get(w, "mapDigest") {
        return no("the question is for another session or map");
    }
    let pcactn = get(w, "pcactn").ok_or("walletCheck: pcactn is missing")?;
    if get_str(body, "pcactn_digest") != Some(hash_strict(pcactn)?.as_str())
        || get_str(body, "action_digest") != Some(intent_action_digest(get(pcactn, "action").ok_or("walletCheck: pcactn.action")?)?.as_str())
    {
        return no("the question is about another action");
    }
    let lifted = get(w, "lifted").ok_or("walletCheck: lifted is missing")?;
    let raw_vs = get(w, "omegaTilde")
        .and_then(|o| get(o, "verbs"))
        .and_then(Value::as_array)
        .and_then(|vs| vs.iter().find(|x| get_str(x, "verb") == get_str(lifted, "verb")))
        .cloned();
    let vs = raw_vs.as_ref().map(VerbSpace::from_json).transpose()?;
    let mine = vs.as_ref().and_then(|v| cell_of(v, lifted));
    let (Some(vs), Some(mine), Some(raw_vs)) = (vs, mine, raw_vs) else { return no("the wallet cannot place the action in \u{3a9}\u{303}") };
    if get(get(body, "cell").unwrap_or(&Value::Null), "verb").and_then(Value::as_str) != Some(vs.verb.as_str()) {
        return no("the wallet cannot place the action in \u{3a9}\u{303}");
    }
    let theirs = get(get(body, "cell").unwrap_or(&Value::Null), "coords").and_then(|c| cell_from_coords(&vs, c));
    match theirs {
        Some(t) if t.iter().enumerate().all(|(k, x)| *x == mine[k] as f64) => {
            Ok(obj(vec![("ok", Value::Bool(true)), ("vs", raw_vs), ("cell", jarr_usize(&mine))]))
        }
        _ => no("the site cell differs from the cell the wallet derives"),
    }
}

fn key_of(verb: &str, cell: &[usize]) -> String {
    format!("{}|{}", verb, cell.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(","))
}

/// Per verb, the cells the next learner's grant adds over the previous one's (0/1 arrays over the flat cell index), in verb order.
pub fn delta_cells(prev: &mut IntentLearner, next: &mut IntentLearner) -> Vec<(String, Vec<u8>)> {
    let prev_in: std::collections::HashSet<String> = prev.cells().iter().filter(|c| c.in_grant).map(|c| key_of(&c.verb, &c.cell)).collect();
    let cells = next.cells();
    let mut out = vec![];
    for vs in &next.omega.verbs {
        let mut a = vec![0u8; verb_cell_count(vs)];
        let mut any = false;
        for c in &cells {
            if c.verb != vs.verb || !c.in_grant || prev_in.contains(&key_of(&c.verb, &c.cell)) {
                continue;
            }
            a[encode_cell(vs, &c.cell)] = 1;
            any = true;
        }
        if any {
            out.push((vs.verb.clone(), a));
        }
    }
    out
}

pub fn delta_to_json(delta: &[(String, Vec<u8>)]) -> Value {
    let mut m = Map::new();
    for (v, a) in delta {
        m.insert(v.clone(), Value::Array(a.iter().map(|x| jn(*x as f64)).collect()));
    }
    Value::Object(m)
}

/// The predicates of a delta (one maximal box per covered region, per verb).
pub fn delta_predicates(omega_tilde: &Omega, delta: &[(String, Vec<u8>)]) -> R<Vec<Value>> {
    let mut out = vec![];
    for vs in &omega_tilde.verbs {
        if let Some((_, a)) = delta.iter().find(|(v, _)| *v == vs.verb) {
            out.extend(boxes_to_predicates(vs, a)?);
        }
    }
    Ok(out)
}

/// Mint D_k from the k-th answer: `None` when the answer added no cell. `args` = `{prevGrant, holder, session, seq, root, mapDigest,
/// prev?, salt?, mapForm?, caveats?}`; the PRINCIPAL key (from its b64u seed) signs, the agent's key never does.
pub fn mint_delta(prev: &mut IntentLearner, next: &mut IntentLearner, args: &Value, principal_seed: &str) -> R<Option<Value>> {
    let delta = delta_cells(prev, next);
    let cells: usize = delta.iter().map(|(_, a)| a.iter().map(|x| *x as usize).sum::<usize>()).sum();
    if cells == 0 {
        return Ok(None);
    }
    let prev_grant = get(args, "prevGrant").ok_or("mintDelta: prevGrant is missing")?;
    let prev_grant_id = get_str(prev_grant, "id").ok_or("mintDelta: prevGrant.id is missing")?;
    if let Some(p) = opt(args, "prev") {
        if p.as_str() != Some(prev_grant_id) {
            return Err("mintDelta: prev must be the id of the previous session grant".into());
        }
    }
    let predicates = Value::Array(delta_predicates(&next.omega, &delta)?);
    let key = KeyPair::from_seed_b64u(principal_seed)?;
    let s = |k: &str| get_str(args, k).ok_or_else(|| format!("mintDelta: {k} must be a string"));
    let seq = get_num(args, "seq").filter(|x| x.is_finite() && x.fract() == 0.0).ok_or("mintDelta: seq must be an integer")? as i64;
    let caveats = opt(args, "caveats");
    let input = crate::signers_more::SessionGrantInput {
        principal: &key,
        holder: s("holder")?,
        holder_pq: None,
        session: s("session")?,
        seq,
        prev: Some(prev_grant_id),
        root: s("root")?,
        map_digest: s("mapDigest")?,
        map_form: opt(args, "mapForm").and_then(Value::as_str),
        predicates: &predicates,
        caveats,
        agent_binding: None,
        risk_policy: None,
        salt: opt(args, "salt").and_then(Value::as_str),
        suite: Suite::default(),
    };
    let (grant, salt) = crate::signers_more::mint_session_grant(&input)?;
    Ok(Some(obj(vec![("grant", grant), ("goalSalt", jstr(&salt)), ("cells", jn(cells as f64))])))
}

//! Rule 22 (`traits`) in the guest: the trait algebra of the action kit (`packages/pca-actions/src/{traits,core-traits,effective}.ts`,
//! `derive.ts` `schemaVerbFloorError` / `registryOfSchema` / `schemaFloorError`, `rule22.ts`) restricted to what the verifier
//! needs: the embedded core table of 22 traits, loading and checking a document's custom traits, the traits digest, the integrity
//! check of a version 2 schema (a forged floor, a dropped implied trait, an unknown trait, a wrong trait digest), and the
//! floor decision of a verb's materialized floors against the grant's facts and the verifier-observed call context.
//!
//! All integer-and-set arithmetic over `BTreeSet`s (sorted, distinct). Total: every error is a `String` reason that starts with
//! the TS error code (`schema_floor_forged`, `schema_traits_forged`, `unknown_trait`, `traits_digest_mismatch`, `bad_registry`).
//! The semantic diff and packs are host tooling and are not in the guest. The verifier's reviewer pins ARE: a verb counts as
//! human-confirmed only with a valid signed `confirmation` by a pinned `reviewer` key; every other verb is unconfirmed and must
//! carry EVERY trait of the registry ("unconfirmed means maximally dangerous"). No pins = nothing is confirmed.
use crate::commit::hash_canonical;
use crate::jsnum::safe_int;
use serde_json::{json, Map, Value};
use std::collections::{BTreeMap, BTreeSet};

pub const CAVEAT_KINDS: [&str; 8] = ["amount_cap", "count_cap", "window", "resource_scope", "recipient_scope", "approval_ref", "short_expiry", "rate_cap"];
pub const CONTEXT_KEYS: [&str; 6] = ["approval_ref", "dry_run_first", "fresh_revocation", "idempotency", "revocable", "sandbox_attested"];
pub const PARAM_RULE_IDS: [&str; 8] =
    ["array_bounded", "export_bounded", "id_not_wildcard", "money_amount_bounded", "money_has_currency", "pay_has_idempotency", "recipient_param_declared", "secret_not_logged"];
pub const REVERSIBILITY: [&str; 3] = ["reversible", "rate_limited", "irreversible"];
const TRAITS_DIGEST_DOMAIN: &str = "atlas-pca/action-traits/v1";
const REVIEW_DOMAIN: &str = "atlas-pca/action-review/v2\0";
const VERB_FACTS_DOMAIN: &str = "atlas-pca/action-verb-facts/v1";
const KEY_ROLES: [&str; 4] = ["reviewer", "importer", "model", "publisher"];
const MAX_REGISTRY_TRAITS: usize = 512;
const MAX_IMPLIES_DEPTH: usize = 8;
const PPM_MAX: i64 = 1_000_000;

fn rev_rank(r: &str) -> usize {
    REVERSIBILITY.iter().position(|x| *x == r).unwrap_or(2)
}

/// `TAINT_CONTEXT_RE`: `^session_taint_max:[a-z_]{1,16}$`.
fn taint_key(s: &str) -> bool {
    s.strip_prefix("session_taint_max:").is_some_and(|t| (1..=16).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'))
}
pub fn is_context_key(s: &str) -> bool {
    CONTEXT_KEYS.contains(&s) || taint_key(s)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Profile {
    pub risk: i64,
    pub rev: String,
    pub blast_ppm: i64,
    pub esc: i64,
    pub caveats: BTreeSet<String>,
    pub context: BTreeSet<String>,
    pub prules: BTreeSet<String>,
}

impl Profile {
    pub fn bottom() -> Self {
        Profile { risk: 0, rev: "reversible".into(), blast_ppm: 0, esc: 0, caveats: BTreeSet::new(), context: BTreeSet::new(), prules: BTreeSet::new() }
    }
    pub fn join(&self, q: &Profile) -> Profile {
        Profile {
            risk: self.risk.max(q.risk),
            rev: if rev_rank(&self.rev) >= rev_rank(&q.rev) { self.rev.clone() } else { q.rev.clone() },
            blast_ppm: self.blast_ppm.max(q.blast_ppm),
            esc: self.esc.max(q.esc),
            caveats: self.caveats.union(&q.caveats).cloned().collect(),
            context: self.context.union(&q.context).cloned().collect(),
            prules: self.prules.union(&q.prules).cloned().collect(),
        }
    }
    pub fn leq(&self, q: &Profile) -> bool {
        self.risk <= q.risk
            && rev_rank(&self.rev) <= rev_rank(&q.rev)
            && self.blast_ppm <= q.blast_ppm
            && self.esc <= q.esc
            && self.caveats.is_subset(&q.caveats)
            && self.context.is_subset(&q.context)
            && self.prules.is_subset(&q.prules)
    }
    pub fn to_value(&self) -> Value {
        json!({
            "risk": self.risk, "rev": self.rev, "blast_ppm": self.blast_ppm, "esc": self.esc,
            "caveats": self.caveats.iter().collect::<Vec<_>>(), "context": self.context.iter().collect::<Vec<_>>(), "prules": self.prules.iter().collect::<Vec<_>>(),
        })
    }
}

/// `profileError` + parse: a well-formed canonical profile (closed members, ranges, known sorted distinct sets of at most 64).
pub fn profile_from(v: &Value) -> Result<Profile, String> {
    let o = v.as_object().ok_or("profile must be an object")?;
    if let Some(k) = o.keys().find(|k| !["risk", "rev", "blast_ppm", "esc", "caveats", "context", "prules"].contains(&k.as_str())) {
        return Err(format!("profile: unknown member '{k}'"));
    }
    let rng = |k: &str, lo: i64, hi: i64| o.get(k).and_then(safe_int).filter(|x| (lo..=hi).contains(x));
    let risk = rng("risk", 0, 3).ok_or("profile.risk must be an integer in 0..3")?;
    let rev = match o.get("rev").and_then(Value::as_str) {
        Some(r) if REVERSIBILITY.contains(&r) => r.to_string(),
        _ => return Err("profile.rev is not a reversibility class".into()),
    };
    let blast_ppm = rng("blast_ppm", 0, PPM_MAX).ok_or("profile.blast_ppm must be an integer in 0..1000000")?;
    let esc = rng("esc", 0, 3).ok_or("profile.esc must be an integer in 0..3")?;
    let set = |name: &str, ok: &dyn Fn(&str) -> bool| -> Result<BTreeSet<String>, String> {
        let a = o.get(name).and_then(Value::as_array).filter(|a| a.len() <= 64);
        let a = a.ok_or_else(|| format!("profile.{name} must be an array of known {name} entries"))?;
        let mut out = BTreeSet::new();
        let mut prev: Option<&str> = None;
        for x in a {
            let s = x.as_str().filter(|s| ok(s)).ok_or_else(|| format!("profile.{name} must be an array of known {name} entries"))?;
            if prev.is_some_and(|p| p >= s) {
                return Err(format!("profile.{name} must be sorted and distinct"));
            }
            prev = Some(s);
            out.insert(s.to_string());
        }
        Ok(out)
    };
    Ok(Profile {
        risk,
        rev,
        blast_ppm,
        esc,
        caveats: set("caveats", &|s| CAVEAT_KINDS.contains(&s))?,
        context: set("context", &is_context_key)?,
        prules: set("prules", &|s| PARAM_RULE_IDS.contains(&s))?,
    })
}

#[derive(Clone, Debug)]
pub struct TraitDef {
    pub implies: Vec<String>,
    pub floor: Profile,
    pub card_phrase: String,
}
pub struct Registry {
    pub traits: BTreeMap<String, TraitDef>,
}

// [name, implies, risk, rev, blast_ppm, esc, caveats, context, prules, card phrase]  (core-traits.ts TABLE)
type Row = (&'static str, &'static [&'static str], i64, &'static str, i64, i64, &'static [&'static str], &'static [&'static str], &'static [&'static str], &'static str);
const R: &str = "reversible";
const RL: &str = "rate_limited";
const IRR: &str = "irreversible";
const TABLE: [Row; 22] = [
    ("money_moving", &[], 3, RL, 700_000, 2, &["amount_cap", "count_cap", "window"], &["idempotency"], &["money_has_currency", "money_amount_bounded", "pay_has_idempotency"], "moves money"),
    ("destructive", &[], 2, RL, 0, 1, &["resource_scope"], &[], &["id_not_wildcard"], "deletes or destroys data"),
    ("irreversible", &[], 2, IRR, 0, 1, &[], &["fresh_revocation"], &[], "cannot be undone"),
    ("external_communication", &[], 2, IRR, 0, 0, &["recipient_scope", "rate_cap"], &[], &["recipient_param_declared"], "sends to people outside your organisation"),
    ("data_export", &[], 2, R, 0, 0, &["resource_scope", "count_cap"], &[], &["export_bounded"], "exports data"),
    ("privilege_change", &[], 3, R, 0, 3, &["resource_scope", "short_expiry"], &[], &[], "changes who can do what"),
    ("code_execution", &[], 3, IRR, 0, 2, &["resource_scope"], &["sandbox_attested"], &[], "runs code or commands"),
    ("credential_access", &[], 3, R, 0, 3, &[], &[], &["secret_not_logged"], "reads or handles credentials"),
    ("bulk", &[], 2, R, 0, 0, &["count_cap"], &[], &["array_bounded"], "acts on many items at once"),
    ("pii_access", &[], 1, R, 0, 0, &["resource_scope"], &[], &[], "touches personal data"),
    ("public_exposure", &[], 2, IRR, 0, 1, &[], &[], &[], "makes content public"),
    ("persistence", &[], 2, R, 0, 0, &["short_expiry"], &["revocable"], &[], "creates standing access or infrastructure"),
    ("infra_mutation", &[], 2, RL, 0, 0, &["resource_scope"], &[], &[], "changes infrastructure"),
    ("cost_incurring", &[], 1, R, 0, 0, &["amount_cap"], &[], &[], "incurs cost"),
    ("legal_binding", &[], 3, IRR, 0, 3, &[], &[], &[], "legally or cryptographically binds you"),
    ("impersonation", &["external_communication"], 2, R, 0, 1, &[], &[], &[], "acts as a person"),
    ("network_egress", &[], 1, R, 0, 0, &["recipient_scope"], &[], &[], "reaches out to the network"),
    ("financial_data_read", &[], 1, R, 0, 0, &["resource_scope"], &[], &[], "reads financial data"),
    ("regulated_data", &[], 2, R, 0, 1, &[], &[], &[], "handles regulated data"),
    ("scheduled", &[], 2, R, 0, 0, &["short_expiry", "count_cap"], &[], &[], "runs later or repeatedly"),
    ("unreviewed", &[], 3, IRR, 1_000_000, 2, &["approval_ref", "resource_scope"], &["dry_run_first"], &[], "has not been reviewed yet"),
    ("agent_spawning", &[], 2, R, 0, 0, &["count_cap"], &[], &[], "starts another agent"),
];

fn set_of(xs: &[&str]) -> BTreeSet<String> {
    xs.iter().map(|s| s.to_string()).collect()
}

/// The embedded core registry (floor = own highlights joined with the floors of the traits it implies).
pub fn core_registry() -> Registry {
    let mut traits: BTreeMap<String, TraitDef> = BTreeMap::new();
    for (name, implies, risk, rev, blast, esc, cav, ctx, pr, phrase) in TABLE {
        let mut floor = Profile { risk, rev: rev.into(), blast_ppm: blast, esc, caveats: set_of(cav), context: set_of(ctx), prules: set_of(pr) };
        let imp: Vec<String> = implies.iter().map(|n| format!("pca.{n}")).collect();
        for u in &imp {
            floor = floor.join(&traits[u].floor);
        }
        traits.insert(format!("pca.{name}"), TraitDef { implies: imp, floor, card_phrase: phrase.into() });
    }
    Registry { traits }
}

fn trait_id_ok(s: &str) -> bool {
    // TRAIT_ID_RE: ^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}$
    let Some((a, b)) = s.split_once('.') else { return false };
    let part = |p: &str, max: usize| p.len() >= 1 && p.len() <= max && p.as_bytes()[0].is_ascii_lowercase() && p.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_');
    part(a, 32) && part(b, 64)
}

/// `extendRegistry(CORE, custom)`: parse and check a document's `trait_defs` on top of the core registry. Errors start `bad_registry:`.
pub fn extend_registry(custom: &[Value]) -> Result<Registry, String> {
    let bad = |m: String| Err(format!("bad_registry: {m}"));
    let mut reg = core_registry();
    let mut ids: Vec<String> = Vec::new();
    for c in custom {
        let o = match c.as_object() {
            Some(o) => o,
            None => return bad("trait must be an object".into()),
        };
        let id = match o.get("id").and_then(Value::as_str) {
            Some(id) if trait_id_ok(id) => id.to_string(),
            _ => return bad(format!("trait id '{}' is malformed", crate::canonical::js_string(o.get("id")))),
        };
        if id.starts_with("pca.") || reg.traits.contains_key(&id) {
            return bad(format!("custom trait '{id}' may not redefine a core trait"));
        }
        let implies: Vec<String> = match o.get("implies").and_then(Value::as_array) {
            Some(a) if a.len() <= 8 && a.iter().all(Value::is_string) => a.iter().filter_map(|x| x.as_str().map(String::from)).collect(),
            _ => return bad(format!("trait '{id}': implies must be up to 8 distinct trait ids")),
        };
        if implies.iter().collect::<BTreeSet<_>>().len() != implies.len() {
            return bad(format!("trait '{id}': implies must be up to 8 distinct trait ids"));
        }
        let floor = match o.get("floor").map(profile_from) {
            Some(Ok(f)) => f,
            Some(Err(e)) => return bad(format!("trait '{id}': {e}")),
            None => return bad(format!("trait '{id}': profile must be an object")),
        };
        let phrase = match o.get("card_phrase").and_then(Value::as_str) {
            Some(p) if !p.is_empty() && p.encode_utf16().count() <= 120 => p.to_string(),
            _ => return bad(format!("trait '{id}': card_phrase must be a non-empty string up to 120 characters")),
        };
        if ids.contains(&id) {
            return bad(format!("trait '{id}' is defined twice"));
        }
        ids.push(id.clone());
        reg.traits.insert(id, TraitDef { implies, floor, card_phrase: phrase });
    }
    if reg.traits.len() > MAX_REGISTRY_TRAITS {
        return bad(format!("a registry holds at most {MAX_REGISTRY_TRAITS} traits"));
    }
    for (id, t) in &reg.traits {
        for u in &t.implies {
            match reg.traits.get(u) {
                None => return bad(format!("trait '{id}' implies unknown trait '{u}'")),
                Some(ud) if !ud.floor.leq(&t.floor) => return bad(format!("trait '{id}': floor is below the floor of implied '{u}' (a trait may only extend what it implies)")),
                _ => {}
            }
        }
    }
    // cycles and depth (iterative deepening over the DAG; a path longer than the limit or a revisit on the stack is refused)
    fn depth(reg: &Registry, id: &str, stack: &mut Vec<String>, memo: &mut BTreeMap<String, usize>) -> Option<usize> {
        if let Some(d) = memo.get(id) {
            return Some(*d);
        }
        if stack.iter().any(|s| s == id) {
            return None;
        }
        stack.push(id.to_string());
        let mut d = 1;
        for u in &reg.traits[id].implies {
            d = d.max(depth(reg, u, stack, memo)? + 1);
        }
        stack.pop();
        memo.insert(id.to_string(), d);
        Some(d)
    }
    let mut memo = BTreeMap::new();
    for id in reg.traits.keys() {
        match depth(&reg, id, &mut Vec::new(), &mut memo) {
            None => return bad(format!("trait '{id}': implies cycle")),
            Some(d) if d > MAX_IMPLIES_DEPTH => return bad(format!("trait '{id}': implies depth {d} exceeds {MAX_IMPLIES_DEPTH}")),
            _ => {}
        }
    }
    Ok(reg)
}

/// `traitsDigest(reg)`.
pub fn traits_digest(reg: &Registry) -> String {
    let traits: Vec<Value> = reg
        .traits
        .iter()
        .map(|(id, t)| {
            let mut imp = t.implies.clone();
            imp.sort();
            json!({"id": id, "implies": imp, "floor": t.floor.to_value(), "card_phrase": t.card_phrase})
        })
        .collect();
    hash_canonical(&json!({"d": TRAITS_DIGEST_DOMAIN, "traits": traits}))
}

/// `cl_R(S)`, sorted; `unknown_trait: ...` for an id the registry lacks.
pub fn closure(reg: &Registry, ids: &[String]) -> Result<BTreeSet<String>, String> {
    let mut seen = BTreeSet::new();
    let mut stack: Vec<String> = ids.to_vec();
    while let Some(id) = stack.pop() {
        if seen.contains(&id) {
            continue;
        }
        let t = reg.traits.get(&id).ok_or_else(|| format!("unknown_trait: unknown trait '{id}'"))?;
        seen.insert(id);
        stack.extend(t.implies.iter().cloned());
    }
    Ok(seen)
}
pub fn floor_of(reg: &Registry, ids: &[String]) -> Result<Profile, String> {
    Ok(closure(reg, ids)?.iter().fold(Profile::bottom(), |acc, id| acc.join(&reg.traits[id].floor)))
}

/// `registryOfSchema(doc)`: core + the document's `trait_defs`; a present `traits_digest` must match.
pub fn registry_of_schema(doc: &Value) -> Result<Registry, String> {
    let custom: &[Value] = doc.get("trait_defs").and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[]);
    let reg = if custom.is_empty() { core_registry() } else { extend_registry(custom)? };
    if let Some(d) = doc.get("traits_digest") {
        if d.as_str() != Some(traits_digest(&reg).as_str()) {
            return Err("traits_digest_mismatch: the document's traits_digest does not match its trait registry".into());
        }
    }
    Ok(reg)
}

fn effect_traits(e: &str) -> &'static [&'static str] {
    match e {
        "delete" => &["pca.destructive"],
        "send" => &["pca.external_communication"],
        "pay" => &["pca.money_moving"],
        "exec" => &["pca.code_execution"],
        "privilege" => &["pca.privilege_change"],
        "export" => &["pca.data_export"],
        "publish" => &["pca.public_exposure"],
        "provision" => &["pca.persistence", "pca.scheduled"],
        "sign" => &["pca.legal_binding"],
        _ => &[],
    }
}
fn tag_traits(t: &str) -> &'static [&'static str] {
    match t {
        "pii" => &["pca.pii_access"],
        "phi" => &["pca.pii_access", "pca.regulated_data"],
        "pci" => &["pca.regulated_data"],
        "secret" | "credential" => &["pca.credential_access"],
        _ => &[],
    }
}
fn role_traits(r: &str) -> &'static [&'static str] {
    match r {
        "credential.secret" | "credential.token" | "credential.key" => &["pca.credential_access"],
        "url.target" => &["pca.network_egress"],
        _ => &[],
    }
}

/// `worstReversibility` over a schema verb's declaration (the class any call can have).
fn worst_reversibility(v: &Map<String, Value>, params: &Map<String, Value>) -> String {
    let read = v.get("kind").and_then(Value::as_str) == Some("read");
    if let Some(r) = v.get("reversibility_by").and_then(Value::as_object) {
        let by = r.get("param").and_then(Value::as_str).unwrap_or("");
        let map = r.get("map").and_then(Value::as_object);
        let d = params.get(by);
        let domain: Option<Vec<String>> = match d.and_then(|d| d.get("type")).and_then(Value::as_str) {
            Some("boolean") => Some(vec!["true".into(), "false".into()]),
            Some("string") => d.and_then(|d| d.get("values")).and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()),
            _ => None,
        };
        let mut mapped: Vec<&str> = map.map(|m| m.values().filter_map(Value::as_str).collect()).unwrap_or_default();
        let covered = domain.is_some_and(|dm| dm.iter().all(|x| map.is_some_and(|m| m.contains_key(x))));
        if !covered {
            mapped.push(r.get("default").and_then(Value::as_str).unwrap_or("irreversible"));
        }
        return mapped.iter().fold("reversible", |a, b| if rev_rank(b) > rev_rank(a) { b } else { a }).to_string();
    }
    match v.get("reversibility").and_then(Value::as_str) {
        Some(r) => r.to_string(),
        None => (if read { "reversible" } else { "irreversible" }).to_string(),
    }
}

fn utf16_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// `reviewerPinsError(p)`: `None` iff the pin set is sound (distinct kids, canonical keys, known roles, no key that is both a
/// reviewer and a machine, no reviewer key material that is also pinned as an importer or model key).
pub fn reviewer_pins_error(p: &Value) -> Option<String> {
    let Some(keys) = p.get("keys").and_then(Value::as_array) else { return Some("pins must be {keys: [...]}".into()) };
    let mut kids: BTreeSet<&str> = BTreeSet::new();
    let mut machine_pks: BTreeSet<&str> = BTreeSet::new();
    for k in keys {
        let kid = match k.get("kid").and_then(Value::as_str) {
            Some(s) if (1..=128).contains(&s.encode_utf16().count()) => s,
            _ => return Some("a pinned key needs a kid".into()),
        };
        if !kids.insert(kid) {
            return Some(format!("kid '{kid}' is pinned twice"));
        }
        let pk = k.get("pk").and_then(Value::as_str).filter(|s| crate::chain::decode_b64u_strict(s, 32).is_some());
        let Some(pk) = pk else { return Some(format!("key '{kid}': pk is not canonical base64url (32 bytes)")) };
        let roles: Option<Vec<&str>> = k.get("roles").and_then(Value::as_array).and_then(|a| a.iter().map(Value::as_str).collect::<Option<Vec<_>>>());
        let roles = match roles {
            Some(r) if !r.is_empty() && r.iter().all(|x| KEY_ROLES.contains(x)) && r.iter().collect::<BTreeSet<_>>().len() == r.len() => r,
            _ => return Some(format!("key '{kid}': roles must be distinct known roles")),
        };
        let machine = roles.contains(&"importer") || roles.contains(&"model");
        if roles.contains(&"reviewer") && machine {
            return Some(format!("key '{kid}': an importer or model key cannot hold the reviewer role"));
        }
        for t in ["not_before", "not_after"] {
            if k.get(t).is_some_and(|x| crate::jsnum::non_neg(x).is_none()) {
                return Some(format!("key '{kid}': {t} must be a non-negative integer"));
            }
        }
        if machine {
            machine_pks.insert(pk);
        }
    }
    for k in keys {
        let reviewer = k["roles"].as_array().is_some_and(|r| r.iter().any(|x| x.as_str() == Some("reviewer")));
        if reviewer && k["pk"].as_str().is_some_and(|pk| machine_pks.contains(pk)) {
            return Some(format!("key '{}': the same key material is pinned as an importer or model key", k["kid"].as_str().unwrap_or("")));
        }
    }
    None
}

/// `factsDigest(verb)`: the digest of the verb's own facts (everything but `traits`, `floors`, `confirmation`, `def`), so a
/// confirmation holds only for the verb whose facts the reviewer saw.
fn facts_digest(v: &Value) -> String {
    let mut facts = v.as_object().cloned().unwrap_or_default();
    for k in ["traits", "floors", "confirmation", "def"] {
        facts.remove(k);
    }
    hash_canonical(&json!({"d": VERB_FACTS_DOMAIN, "verb": facts}))
}

/// `reviewMessage(body)`: `REVIEW_DOMAIN \0 || strictCanonical({def_digest, traits_digest, facts_digest, final_traits (sorted, distinct),
/// dismissed (sorted by trait), reviewer_kid, ts})`. `None` where the strict canonical form would throw.
fn review_message(a: &Map<String, Value>, ts: i64, final_traits: &[&str], dismissed: &[(&str, &str)]) -> Option<Vec<u8>> {
    let mut fin: Vec<&str> = final_traits.to_vec();
    fin.sort_by(|x, y| utf16_cmp(x, y));
    fin.dedup();
    let mut dm = dismissed.to_vec();
    dm.sort_by(|x, y| utf16_cmp(x.0, y.0));
    let body = json!({
        "def_digest": a.get("def_digest"), "traits_digest": a.get("traits_digest"), "facts_digest": a.get("facts_digest"), "final_traits": fin,
        "dismissed": dm.iter().map(|(t, r)| json!({"trait": t, "reason": r})).collect::<Vec<_>>(),
        "reviewer_kid": a.get("reviewer_kid"), "ts": ts,
    });
    if crate::canonical::strict_violation(&body).is_some() {
        return None;
    }
    let mut m = REVIEW_DOMAIN.as_bytes().to_vec();
    m.extend_from_slice(&crate::canonical::canonical_bytes(&body));
    Some(m)
}

/// `verbConfirmationError(v, reg, pins)`: `None` iff the verb carries a VALID human confirmation (over exactly its `def`, against
/// an accepted trait registry digest, final traits all carried by the verb, signed by a pinned `reviewer` key inside its
/// validity window). Every other case - absent, malformed, unpinned, wrong role, stale digest, bad signature, no pins - is a
/// reason and the verb is UNCONFIRMED. Total.
pub fn verb_confirmation_error(v: &Value, reg: &Registry, pins: Option<&Value>) -> Option<String> {
    let s = |m: &str| Some(m.to_string());
    let Some(pins) = pins else { return s("no reviewer keys are pinned") };
    if let Some(e) = reviewer_pins_error(pins) {
        return Some(format!("bad pins: {e}"));
    }
    let Some(a) = v.get("confirmation") else { return s("no confirmation") };
    let Some(a) = a.as_object() else { return s("confirmation is not an object") };
    let Some(sig) = a.get("sig").and_then(Value::as_str) else { return s("the confirmation is unsigned") };
    let def = v.get("def").and_then(Value::as_str);
    if def.is_none() || a.get("def_digest").and_then(Value::as_str) != def {
        return s("the confirmation covers a different def digest");
    }
    let extra: Vec<&str> = match pins.get("traits_digests") {
        None | Some(Value::Null) => vec![],
        Some(Value::Array(d)) => d.iter().filter_map(Value::as_str).collect(),
        Some(_) => return s("malformed confirmation: traits_digests"),
    };
    let td = a.get("traits_digest").and_then(Value::as_str);
    if !td.is_some_and(|d| extra.contains(&d) || d == traits_digest(reg)) {
        return s("the confirmation was made against a different trait registry");
    }
    if a.get("facts_digest").and_then(Value::as_str) != Some(facts_digest(v).as_str()) {
        return s("the confirmation covers different verb facts");
    }
    let (Some(fin), Some(dism), Some(ts), Some(kid)) =
        (a.get("final_traits").and_then(Value::as_array), a.get("dismissed").and_then(Value::as_array), a.get("ts").and_then(crate::jsnum::safe_int), a.get("reviewer_kid").and_then(Value::as_str))
    else {
        return s("malformed confirmation");
    };
    let carried: BTreeSet<&str> = v.get("traits").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
    let Some(fin) = fin.iter().map(Value::as_str).collect::<Option<Vec<&str>>>().filter(|f| f.iter().all(|t| carried.contains(t))) else {
        return s("the verb does not carry every trait the reviewer signed");
    };
    let dismissed: Option<Vec<(&str, &str)>> = dism
        .iter()
        .map(|d| Some((d.get("trait")?.as_str()?, d.get("reason")?.as_str()?)))
        .collect::<Option<Vec<_>>>()
        .filter(|d| d.iter().all(|(t, r)| !fin.contains(t) && !r.trim_matches(crate::action_schema::js_space).is_empty()));
    let Some(dismissed) = dismissed else { return s("a dismissed trait is also final, or has no reason") };
    let Some(key) = pins["keys"].as_array().into_iter().flatten().find(|k| k["kid"].as_str() == Some(kid)) else { return Some(format!("no pinned key '{kid}'")) };
    if !key["roles"].as_array().is_some_and(|r| r.iter().any(|x| x.as_str() == Some("reviewer"))) {
        return Some(format!("key '{kid}' does not hold the reviewer role"));
    }
    let bound = |t: &str| key.get(t).and_then(crate::jsnum::safe_int);
    if bound("not_before").is_some_and(|b| ts < b) || bound("not_after").is_some_and(|b| ts > b) {
        return s("the confirmation time is outside the key validity");
    }
    let ok = review_message(a, ts, &fin, &dismissed).is_some_and(|m| crate::chain::ed25519_verify_b64u(key["pk"].as_str().unwrap_or(""), &m, sig));
    if ok {
        None
    } else {
        s("the confirmation signature is invalid")
    }
}

/// `schemaVerbFloorError(v, reg, reviewers)`: the verb's traits contain every trait its own facts imply, an unconfirmed verb
/// carries every trait of the registry, and its floors are at least the floor of its traits' closure and of its worst declared
/// reversibility.
pub fn schema_verb_floor_error(v: &Value, reg: &Registry, pins: Option<&Value>) -> Option<String> {
    let o = v.as_object()?;
    let (Some(effects), Some(traits), Some(floors)) = (o.get("effects").and_then(Value::as_array), o.get("traits").and_then(Value::as_array), o.get("floors")) else {
        return Some("schema_floor_forged: not a v2 verb".into());
    };
    let empty = Map::new();
    let params = o.get("params").and_then(Value::as_object).unwrap_or(&empty);
    let by_name: Map<String, Value> = params.iter().map(|(p, d)| (p.strip_prefix("action.params.").unwrap_or(p).to_string(), d.clone())).collect();
    // reversibility_by.param is a path: compare by name
    let mut vv = o.clone();
    if let Some(Value::Object(r)) = vv.get_mut("reversibility_by") {
        if let Some(Value::String(p)) = r.get_mut("param") {
            *p = p.strip_prefix("action.params.").unwrap_or(p).to_string();
        }
    }
    let worst = worst_reversibility(&vv, &by_name);
    let effects: Vec<&str> = effects.iter().filter_map(Value::as_str).collect();
    let read_only = !effects.is_empty() && effects.iter().all(|e| *e == "read");
    let mut implied: BTreeSet<String> = BTreeSet::new();
    for e in &effects {
        implied.extend(effect_traits(e).iter().map(|s| s.to_string()));
    }
    for d in params.values() {
        if let Some(role) = d.get("role").and_then(Value::as_str) {
            implied.extend(role_traits(role).iter().map(|s| s.to_string()));
            if read_only && role.starts_with("money.") {
                implied.insert("pca.financial_data_read".into());
            }
        }
        for t in d.get("tags").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
            implied.extend(tag_traits(t).iter().map(|s| s.to_string()));
        }
        if d.get("type").and_then(Value::as_str) == Some("array") && d.get("max_items").is_none() {
            implied.insert("pca.bulk".into());
        }
    }
    if worst == "irreversible" {
        implied.insert("pca.irreversible".into());
    }
    let carried: Vec<String> = traits.iter().filter_map(|t| t.as_str().map(String::from)).collect();
    for t in &implied {
        if !carried.contains(t) {
            return Some(format!("schema_traits_forged: missing implied trait {t}"));
        }
    }
    if verb_confirmation_error(v, reg, pins).is_some() {
        if let Some(t) = reg.traits.keys().find(|t| !carried.contains(t)) {
            return Some(format!("schema_traits_forged: unconfirmed action must carry every trait (missing {t})"));
        }
    }
    let floor = match floor_of(reg, &carried) {
        Ok(f) => f,
        Err(e) => return Some(e),
    };
    let stated = match profile_from(floors) {
        Ok(p) => p,
        Err(_) => return Some("schema_floor_forged: floors are not a profile".into()),
    };
    if !floor.leq(&stated) {
        return Some("schema_floor_forged: floors are below the floor of the carried traits".into());
    }
    if rev_rank(&stated.rev) < rev_rank(&worst) {
        return Some("schema_floor_forged: floors.rev is below the declared reversibility".into());
    }
    None
}

/// `schemaFloorError(doc, reviewers)`: rule 22's integrity half for a whole v2 document. `None` = consistent. `pins` = the
/// verifier's reviewer keys (`{keys: [...], traits_digests?: [...]}`); absent = no verb is confirmed.
pub fn schema_floor_error(doc: &Value, pins: Option<&Value>) -> Option<String> {
    let reg = match registry_of_schema(doc) {
        Ok(r) => r,
        Err(e) => return Some(e),
    };
    for v in doc.get("verbs").and_then(Value::as_array).into_iter().flatten() {
        if let Some(e) = schema_verb_floor_error(v, &reg, pins) {
            return Some(format!("{}: {e}", v.get("verb").and_then(Value::as_str).unwrap_or("")));
        }
    }
    None
}

/// What the stored grant provides for the floor decision.
pub struct GrantFacts {
    pub caveats: BTreeSet<String>,
    pub max_esc: i64,
    pub preauth_esc: i64,
}

/// `FloorDecision(G, call, rho)`: `0` deny, `1` escalate, `2` allow.
pub fn floor_decision(g: &GrantFacts, call_context: &BTreeSet<String>, rho: &Profile) -> u8 {
    if rho.esc > g.max_esc {
        0
    } else if !rho.caveats.is_subset(&g.caveats) || !rho.context.is_subset(call_context) || rho.esc > g.preauth_esc {
        1
    } else {
        2
    }
}

/// `RULE22_ENGINE.decide`: the verb's materialized floors against the facts; deny for an unknown verb or malformed floors.
pub fn decide(doc: &Value, verb: &str, g: &GrantFacts, context: &[String]) -> u8 {
    let v = doc.get("verbs").and_then(Value::as_array).and_then(|a| a.iter().find(|x| x.get("verb").and_then(Value::as_str) == Some(verb)));
    let Some(floors) = v.and_then(|v| v.get("floors")) else { return 0 };
    let Ok(rho) = profile_from(floors) else { return 0 };
    let ctx: BTreeSet<String> = context.iter().filter(|s| is_context_key(s)).cloned().collect();
    let g2 = GrantFacts { caveats: g.caveats.iter().filter(|c| CAVEAT_KINDS.contains(&c.as_str())).cloned().collect(), max_esc: g.max_esc, preauth_esc: g.preauth_esc };
    floor_decision(&g2, &ctx, &rho)
}

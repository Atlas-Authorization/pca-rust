//! Trust ramp and drift (start narrow, widen only through confirmed behaviour, veto on every negative runtime signal, and a one-sided
//! Bernoulli CUSUM that freezes widening on drift) plus the signed runtime observations that feed it (Ed25519 signing; a suite-agile
//! observation verifies under the verifier's pin).
use super::learner::*;
use super::util::*;
use crate::intent_suite::{bind_suite_fields, domain_message, suite_of, verify_pinned_suite};
use crate::wallet_omega::fdlibm;
use serde_json::{json, Map, Value};

pub const INTENT_OBS_SIG_DOMAIN: &str = "atlas-pca/intent-obs/v1\0";
const SOURCES: [&str; 4] = ["runtime", "witness", "elicitation", "import"];
const OBS_KEYS: [&str; 9] = ["v", "map_digest", "verb", "values", "y", "source", "observed_at", "pcactn_digest", "signer"];

fn is_b32(v: Option<&Value>) -> bool {
    v.and_then(Value::as_str).and_then(|s| crate::decode_b64u_strict(s, Some(32))).is_some()
}

fn obs_body(o: &Value) -> Map<String, Value> {
    let mut b = Map::new();
    for k in OBS_KEYS {
        if let Some(v) = member(o, k) {
            b.insert(k.to_string(), v.clone());
        }
    }
    b
}

/// `None` when the observation is well-formed.
pub fn obs_shape_error(o: &Value) -> Option<String> {
    if !o.is_object() || fnum(&o["v"]) != Some(1.0) {
        return Some("not an intent observation v1".into());
    }
    if !is_b32(o.get("map_digest")) {
        return Some("map_digest is not canonical base64url (32 bytes)".into());
    }
    if o["verb"].as_str().map_or(true, str::is_empty) {
        return Some("verb must be a non-empty string".into());
    }
    match o["values"].as_object() {
        Some(m) if m.values().all(|x| x.is_string() || is_finite_number(x)) => {}
        _ => return Some("values must map paths to numbers or strings".into()),
    }
    if !matches!(fnum(&o["y"]), Some(y) if y == 0.0 || y == 1.0) {
        return Some("y must be 0 or 1".into());
    }
    if !o["source"].as_str().is_some_and(|s| SOURCES.contains(&s)) {
        return Some("unknown observation source".into());
    }
    if !(is_safe_int(&o["observed_at"]) && fnum(&o["observed_at"]).is_some_and(|x| x >= 0.0)) {
        return Some("observed_at must be a non-negative safe integer".into());
    }
    if let Some(d) = o.get("pcactn_digest") {
        if !is_b32(Some(d)) {
            return Some("pcactn_digest is not canonical base64url (32 bytes)".into());
        }
    }
    if !is_b32(o.get("signer")) {
        return Some("signer is not canonical base64url (32 bytes)".into());
    }
    None
}

/// Sign a runtime observation with an Ed25519 seed (the signer is the key of the seed).
pub fn sign_intent_observation(o: &Value, seed_b64u: &str) -> R<Value> {
    use ed25519_dalek::{Signer, SigningKey};
    let seed: [u8; 32] =
        crate::decode_b64u_strict(seed_b64u, Some(32)).and_then(|b| <[u8; 32]>::try_from(b).ok()).ok_or("secret key must be a 32-byte seed")?;
    let sk = SigningKey::from_bytes(&seed);
    let mut with = o.as_object().cloned().unwrap_or_default();
    with.insert("v".into(), json!(1));
    with.insert("signer".into(), json!(crate::b64_encode(&sk.verifying_key().to_bytes())));
    let body = obs_body(&Value::Object(with));
    if let Some(bad) = obs_shape_error(&Value::Object(body.clone())) {
        return Err(format!("signIntentObservation: {bad}"));
    }
    let msg = domain_message(INTENT_OBS_SIG_DOMAIN, body.clone()).ok_or("observation is not canonicalizable")?;
    let mut out = body;
    out.insert("sig".into(), json!(crate::b64_encode(&sk.sign(&msg).to_bytes())));
    Ok(Value::Object(out))
}

/// Verify a signed observation: `{ok}` or `{ok: false, reason}` (a PQ key must be pinned in `opts.pqPins`).
pub fn verify_intent_observation(o: &Value, opts: &Value) -> Value {
    let fail = |r: &str| json!({"ok": false, "reason": r});
    if let Some(bad) = obs_shape_error(o) {
        return fail(&bad);
    }
    let signer = o["signer"].as_str().unwrap_or("");
    if let Some(es) = member(opts, "expectedSigner") {
        if es.as_str() != Some(signer) {
            return fail("signer mismatch");
        }
    }
    let suite = match suite_of(o.get("alg")) {
        Ok(s) => s,
        Err(_) => return fail("unknown signature suite"),
    };
    if suite.alg == "ed25519" && (o.get("pq_pk").is_some() || o.get("pq_sig").is_some()) {
        return fail("an ed25519 artifact must not carry pq_pk / pq_sig");
    }
    let mut body = obs_body(o);
    match bind_suite_fields(&mut body, o.get("alg"), o.get("pq_pk")) {
        Ok(true) => {}
        _ => return fail("malformed intent observation: canonicalize: unsupported type undefined"),
    }
    let msg = match domain_message(INTENT_OBS_SIG_DOMAIN, body) {
        Some(m) => m,
        None => return fail("malformed intent observation: the observation is not canonicalizable"),
    };
    let pin = member(opts, "pqPins").and_then(|p| member(p, signer)).map(|p| (signer, p));
    match verify_pinned_suite(o.get("alg"), signer, o.get("pq_pk"), &msg, o.get("sig"), o.get("pq_sig"), pin) {
        Ok(true) => json!({"ok": true}),
        _ => fail("bad signature"),
    }
}

pub fn signal_label(s: &str) -> f64 {
    if s == "jit-approve" || s == "principal-confirm" {
        1.0
    } else {
        0.0
    }
}

/// The narrow starting configuration for a learner that will be ramped (`{eta, tau, nullMass}`).
pub fn narrow_start(omega: &Value, slots: &Value, opts: Option<&Value>) -> R<Value> {
    let empty = json!({});
    let opts = opts.unwrap_or(&empty);
    let slot_mass = nn(opts, "slotNullMass").and_then(fnum).unwrap_or(0.5);
    let other_mass = nn(opts, "otherNullMass").and_then(fnum).unwrap_or(0.95);
    let verbs = arr(&slots["verbs"], "slots.verbs")?;
    let mut nm = Map::new();
    for vs in arr(&omega["verbs"], "omega.verbs")? {
        let in_slots = verbs.contains(&vs["verb"]);
        nm.insert(js_str(&vs["verb"]), num(if in_slots { slot_mass } else { other_mass }));
    }
    Ok(json!({"eta": 0, "tau": 1, "nullMass": Value::Object(nm)}))
}

#[derive(Clone, Debug)]
pub struct DriftState {
    pub statistic: f64,
    pub alarm: bool,
    pub informative: f64,
    pub divergences: f64,
}

impl DriftState {
    pub fn to_json(&self) -> Value {
        json!({"statistic": num(self.statistic), "alarm": self.alarm, "informative": num(self.informative), "divergences": num(self.divergences)})
    }
}

pub struct DriftDetector {
    rho0: f64,
    rho1: f64,
    h: f64,
    s: DriftState,
}

fn fresh() -> DriftState {
    DriftState { statistic: 0.0, alarm: false, informative: 0.0, divergences: 0.0 }
}

impl DriftDetector {
    /// `o` is `{rho0?, rho1?, h?}` (null / absent members take the defaults).
    pub fn new(o: &Value) -> R<DriftDetector> {
        let get = |k: &str, d: f64| -> R<f64> {
            match nn(o, k) {
                None => Ok(d),
                Some(v) => fnum(v).ok_or_else(|| format!("DriftDetector: {k} must be a number")),
            }
        };
        let rho0 = get("rho0", 0.02)?;
        let rho1 = get("rho1", 0.25)?;
        let h = get("h", fdlibm::log(100.0))?;
        if !(0.0 < rho0 && rho0 < rho1 && rho1 < 1.0) {
            return Err("DriftDetector: need 0 < rho0 < rho1 < 1".into());
        }
        if !(h > 0.0) {
            return Err("DriftDetector: h must be positive".into());
        }
        Ok(DriftDetector { rho0, rho1, h, s: fresh() })
    }

    /// Feed one signal about an action that was inside the grant: `diverged` = true for a negative signal.
    pub fn update(&mut self, diverged: bool) -> DriftState {
        let inc = if diverged { fdlibm::log(self.rho1 / self.rho0) } else { fdlibm::log((1.0 - self.rho1) / (1.0 - self.rho0)) };
        let statistic = jmax(0.0, self.s.statistic + inc);
        self.s = DriftState {
            statistic,
            alarm: self.s.alarm || statistic >= self.h,
            informative: self.s.informative + 1.0,
            divergences: self.s.divergences + if diverged { 1.0 } else { 0.0 },
        };
        self.s.clone()
    }

    pub fn state(&self) -> DriftState {
        self.s.clone()
    }

    pub fn reset(&mut self) {
        self.s = fresh();
    }
}

pub struct TrustRamp {
    pub l: Learner,
    pub drift: DriftDetector,
    queued: Vec<Value>,
    log: Vec<Value>,
}

impl TrustRamp {
    pub fn new(l: Learner, drift: &Value) -> R<TrustRamp> {
        Ok(TrustRamp { l, drift: DriftDetector::new(drift)?, queued: vec![], log: vec![] })
    }

    /// Widening is frozen while a drift alarm stands.
    pub fn frozen(&self) -> bool {
        self.drift.state().alarm
    }

    /// Positive signals held back by a freeze (released only by rebase): `[{o, signal}]`.
    pub fn pending(&self) -> &[Value] {
        &self.queued
    }

    pub fn log(&self) -> &[Value] {
        &self.log
    }

    fn grant_size(&mut self) -> usize {
        self.l.cells().iter().filter(|c| c.in_grant).count()
    }

    pub fn record(&mut self, o: &Value, signal: &str) -> R<Value> {
        let y = signal_label(signal);
        let was_in_grant = self.l.admits_outcome(o);
        let before = self.grant_size();
        let mut drift = self.drift.state();
        if was_in_grant {
            drift = self.drift.update(y == 0.0);
        }
        let mut applied = true;
        if y == 1.0 && self.frozen() {
            self.queued.push(json!({"o": o, "signal": signal}));
            applied = false;
        } else {
            self.l.observe(o, y, "runtime", None)?;
        }
        let after = self.grant_size();
        let rec =
            json!({"signal": signal, "y": num(y), "wasInGrant": was_in_grant, "before": before, "after": after, "applied": applied, "drift": drift.to_json()});
        self.log.push(rec.clone());
        Ok(rec)
    }

    /// Record a SIGNED runtime observation: the signature must verify (`ctx.verify` are the verifier options), the signer must be trusted and
    /// the observation must be about this map: `{ok: true, record}` or `{ok: false, reason}`.
    pub fn record_observation(&mut self, obs: &Value, ctx: &Value) -> R<Value> {
        let none = json!({});
        let v = verify_intent_observation(obs, nn(ctx, "verify").unwrap_or(&none));
        if v["ok"] != json!(true) {
            return Ok(json!({"ok": false, "reason": v["reason"]}));
        }
        let signer = &obs["signer"];
        if !arr(&ctx["trustedSigners"], "ctx.trustedSigners")?.contains(signer) {
            return Ok(json!({"ok": false, "reason": "untrusted observation signer"}));
        }
        if obs["map_digest"] != ctx["mapDigest"] {
            return Ok(json!({"ok": false, "reason": "observation is about a different map"}));
        }
        if obs["source"].as_str() != Some("runtime") {
            return Ok(json!({"ok": false, "reason": "only runtime observations feed the ramp"}));
        }
        let sig = if fnum(&obs["y"]) == Some(1.0) { "principal-confirm" } else { "postcondition-violation" };
        let rec = self.record(&json!({"verb": obs["verb"], "values": obs["values"]}), sig)?;
        Ok(json!({"ok": true, "record": rec}))
    }

    /// Re-base on a new, signed intent statement (the only way to clear an alarm); queued positive signals are discarded.
    pub fn rebase(&mut self, next: Learner) {
        self.l = next;
        self.queued = vec![];
        self.drift.reset();
    }
}

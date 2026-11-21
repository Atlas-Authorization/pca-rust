//! Runtime drift monitoring, tighten-only (`drift.ts`). A monitor compares the action stream to the goal's expected profile (verbs,
//! resources, magnitude, rate, novelty). Anomalies convert Allow to Escalate; the strike counter is a ratchet (never decreases); at
//! `lockdown` strikes every Allow becomes Escalate. [`apply_drift`] never relaxes a decision. The state is a JSON object
//! `{strikes, times, novel, seen}`.
use super::examples::decide_case;
use super::*;
use hmac::{Hmac, Mac};
use serde_json::{json, Map};
use sha2::Sha256;

#[derive(Debug, Clone, Copy)]
pub struct DriftOpts {
    pub window_ms: f64,
    pub max_per_window: f64,
    pub max_novel: f64,
    pub magnitude_factor: f64,
    pub warmup: f64,
    pub lockdown: f64,
}
pub const DEFAULT_DRIFT: DriftOpts = DriftOpts { window_ms: 60_000.0, max_per_window: 20.0, max_novel: 3.0, magnitude_factor: 3.0, warmup: 5.0, lockdown: 5.0 };
impl DriftOpts {
    /// `{...DEFAULT_DRIFT, ...opts}` for `{windowMs?, maxPerWindow?, maxNovel?, magnitudeFactor?, warmup?, lockdown?}`.
    pub fn from_json(o: &Value) -> DriftOpts {
        let d = DEFAULT_DRIFT;
        let f = |k: &str, dv: f64| o.get(k).and_then(Value::as_f64).unwrap_or(dv);
        DriftOpts {
            window_ms: f("windowMs", d.window_ms),
            max_per_window: f("maxPerWindow", d.max_per_window),
            max_novel: f("maxNovel", d.max_novel),
            magnitude_factor: f("magnitudeFactor", d.magnitude_factor),
            warmup: f("warmup", d.warmup),
            lockdown: f("lockdown", d.lockdown),
        }
    }
}

pub fn expected_verbs(gl: &Value) -> Vec<Value> {
    uniq_v(&arr(g(gl, "grants")).iter().map(|x| g(x, "verb").clone()).collect::<Vec<_>>())
}
fn res_ids(s: &Value) -> Vec<Value> {
    match st(g(s, "k")) {
        "exact" => vec![g(s, "id").clone()],
        "oneof" => arr(g(s, "ids")).to_vec(),
        "all_of" => arr(g(s, "parts")).iter().flat_map(res_ids).collect(),
        _ => vec![],
    }
}
fn known_resources(gl: &Value) -> Vec<Value> {
    uniq_v(&arr(g(gl, "grants")).iter().flat_map(|x| res_ids(g(x, "res"))).collect::<Vec<_>>())
}
fn fresh_state() -> Value {
    json!({"strikes": 0, "times": [], "novel": [], "seen": {}})
}
/// Node's lenient `Buffer.from(s, "hex")`: decoding stops at the first invalid pair.
fn node_hex(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = vec![];
    let mut i = 0;
    while i + 1 < b.len() {
        let pair = std::str::from_utf8(&b[i..i + 2]).ok().and_then(|p| u8::from_str_radix(p, 16).ok().filter(|_| p.bytes().all(|c| c.is_ascii_hexdigit())));
        match pair {
            Some(v) => out.push(v),
            None => break,
        }
        i += 2;
    }
    out
}
fn mac_of(state: &Value, key: &[u8]) -> Vec<u8> {
    let mut m = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    m.update(jstr(state).as_bytes());
    m.finalize().into_bytes().to_vec()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub struct DriftMonitor {
    goal: Value,
    o: DriftOpts,
    st: Value,
}
impl DriftMonitor {
    pub fn new(goal: &Value, opts: DriftOpts) -> Self {
        DriftMonitor { goal: goal.clone(), o: opts, st: fresh_state() }
    }
    /// Observe one action at time `t`: `{anomalous, strikes, lockdown, reasons}`.
    pub fn observe(&mut self, a: &Value, t: &Value) -> Res<Value> {
        let mut reasons: Vec<String> = vec![];
        let o = self.o;
        let verb = g(a, "verb");
        if !includes_v(&expected_verbs(&self.goal), verb) {
            reasons.push(format!("verb {} outside the goal profile", js_s(verb)));
        }
        let known = known_resources(&self.goal);
        let res = g(a, "res");
        if !known.is_empty() && !includes_v(&known, res) && !includes_v(arr(&self.st["novel"]), res) {
            self.st["novel"].as_array_mut().ok_or("novel")?.push(res.clone());
        }
        if arr(&self.st["novel"]).len() as f64 > o.max_novel {
            reasons.push("novel resources beyond the allowance".into());
        }
        let tn = nm(t);
        let mut times: Vec<Value> = arr(&self.st["times"]).iter().filter(|x| nm(x) > tn - o.window_ms).cloned().collect();
        times.push(t.clone());
        let nt = times.len();
        self.st["times"] = Value::Array(times);
        if nt as f64 > o.max_per_window {
            reasons.push("rate above the profile".into());
        }
        for (p, l) in g(a, "params").as_object().into_iter().flatten() {
            if st(g(l, "k")) != "q" {
                continue;
            }
            let hist: Vec<Value> = self.st["seen"].get(p).map(|h| arr(h).to_vec()).unwrap_or_default();
            let v = g(g(l, "q"), "n").clone();
            if hist.len() as f64 >= o.warmup {
                let mean = hist.iter().map(nm).sum::<f64>() / hist.len() as f64; // warmup 0: 0 / 0 is NaN, never above
                if mean > 0.0 && nm(&v) > mean * o.magnitude_factor {
                    reasons.push(format!("{p} magnitude {}x above the running mean", crate::intent_v2::js_number_string(o.magnitude_factor)));
                }
            }
            let mut nh = hist;
            nh.push(v);
            let from = nh.len().saturating_sub(50);
            let nh: Vec<Value> = nh[from..].to_vec();
            self.st["seen"].as_object_mut().ok_or("seen")?.insert(p.clone(), Value::Array(nh));
        }
        if !reasons.is_empty() {
            let s = self.st["strikes"].as_i64().unwrap_or(0);
            self.st["strikes"] = json!(s + 1); // ratchet: only ever increases
        }
        let strikes = self.st["strikes"].as_i64().unwrap_or(0);
        Ok(json!({"anomalous": !reasons.is_empty(), "strikes": strikes, "lockdown": strikes as f64 >= o.lockdown, "reasons": reasons}))
    }
    pub fn state(&self) -> &Value {
        &self.st
    }
    /// Sealed state: durable and not agent-writable (the monitor key is held outside the agent). `{state, mac}`.
    pub fn seal(&self, key: &[u8]) -> Value {
        json!({"state": self.st, "mac": hex(&mac_of(&self.st, key))})
    }
    /// Restore; a state that fails its MAC locks down (fail closed).
    pub fn restore(goal: &Value, sealed: &Value, key: &[u8], opts: DriftOpts) -> Res<DriftMonitor> {
        let mut m = DriftMonitor::new(goal, opts);
        let want = mac_of(g(sealed, "state"), key);
        let got = node_hex(sealed["mac"].as_str().ok_or("the first argument must be a string")?);
        let same = got.len() == want.len() && got.iter().zip(want.iter()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0;
        if same {
            m.st = g(sealed, "state").clone();
        } else {
            let mut s = Map::new();
            s.insert("strikes".into(), numv(m.o.lockdown));
            s.insert("times".into(), json!([]));
            s.insert("novel".into(), json!([]));
            s.insert("seen".into(), json!({}));
            m.st = Value::Object(s);
        }
        Ok(m)
    }
}
/// Tighten-only: Allow becomes Escalate on an anomaly or lockdown; nothing else changes.
pub fn apply_drift(d: &str, s: &Value) -> String {
    let t = |k: &str| crate::goal::js::truthy(s.get(k));
    if d == "allow" && (t("anomalous") || t("lockdown")) {
        "escalate".into()
    } else {
        d.to_string()
    }
}

/// Decide, observe, tighten. `c`: `{act, rels, hist?}`. `{decision, signal}`.
pub fn guarded_decide(goal: &Value, ont: &Value, mon: &mut DriftMonitor, c: &Value, t: &Value) -> Res<Value> {
    let base = decide_case(goal, ont, c)?;
    let signal = mon.observe(g(c, "act"), t)?;
    Ok(json!({"decision": apply_drift(st(&base["decision"]), &signal), "signal": signal}))
}

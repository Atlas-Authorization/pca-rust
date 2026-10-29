//! Assurance labels: what a passing check RESTS ON.
//!
//! A check's status (`pass` / `fail` / `not-enforced` / `unsupported`) says WHETHER it held; the assurance report says WHAT a
//! pass rests on: software or hardware attestation, a SNARK proof or an attested-VM statement, a post-quantum or an Ed25519
//! signature, independent multisig shares or a FROST (awaiting audit) aggregate. It also names features the verifier does not
//! implement (`unsupported`), which are reported and never count as a pass.
//!
//! Labels come from the VERIFIER'S configuration ([`AssuranceHooks`]), never from the presented evidence: a software
//! attestation verifier is `software` whatever the document claims. A hook without a label is `unknown`, which satisfies no
//! requirement. [`AssuranceRequirement`] turns the report into a gate (`AuthorizeInput::require_assurance`): weaker, missing,
//! failed, unlabelled, awaiting-audit, degraded or unsupported evidence fails the `assurance` check and the request is denied.

use serde_json::{json, Map, Value};

use crate::authorize::CheckStatus;
use crate::intent_v2::js_value_string;

/// What a hook, hardware verifier or SNARK backend declares about itself.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AssuranceLabel {
    /// Attestation: `software` | `hardware` | `multi_root`. ZK: `groth16` | `policyvm_snark` | `stark` | `zkvm` | `attested_vm` |
    /// `attested_vm_hw`. Threshold: `multisig` | `frost` | `frost_dkg` | `mpc`. Anything else is `unknown`.
    pub level: String,
    /// Vendor or root id, for example `amd-sev-snp`.
    pub vendor: Option<String>,
    /// Crypto awaiting audit (not production): FROST, DKG, MPC.
    pub awaiting_audit: bool,
    /// SNARK backends: `single-party` or `multi-party` (only from a verified, pinned ceremony transcript).
    pub ceremony: Option<String>,
}

impl AssuranceLabel {
    pub fn new(level: impl Into<String>) -> Self {
        AssuranceLabel { level: level.into(), ..Default::default() }
    }

    pub fn with_vendor(mut self, vendor: impl Into<String>) -> Self {
        self.vendor = Some(vendor.into());
        self
    }

    pub fn with_awaiting_audit(mut self) -> Self {
        self.awaiting_audit = true;
        self
    }

    pub fn with_ceremony(mut self, ceremony: impl Into<String>) -> Self {
        self.ceremony = Some(ceremony.into());
        self
    }

    /// From `{level, vendor?, awaiting_audit?, ceremony?}`; `None` without a string `level`.
    pub fn from_json(v: &Value) -> Option<AssuranceLabel> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Some(AssuranceLabel { level: s("level")?, vendor: s("vendor"), awaiting_audit: (v.get("awaiting_audit") == Some(&Value::Bool(true)) || v.get("preview") == Some(&Value::Bool(true))), ceremony: s("ceremony") })
    }
}

/// Implemented by a verifier hook, hardware verifier or SNARK-like backend to declare its own assurance label.
pub trait AssuranceLabelled {
    fn assurance_label(&self) -> Option<AssuranceLabel>;
}

/// A configured hook: present with a label, or present without one (`unknown`).
#[derive(Debug, Clone, PartialEq)]
pub enum HookDecl {
    Unlabelled,
    Labelled(AssuranceLabel),
}

impl HookDecl {
    /// The declaration of a hook object.
    pub fn of(hook: &dyn AssuranceLabelled) -> HookDecl {
        hook.assurance_label().map_or(HookDecl::Unlabelled, HookDecl::Labelled)
    }

    fn label(&self) -> Option<&AssuranceLabel> {
        match self {
            HookDecl::Labelled(l) => Some(l),
            HookDecl::Unlabelled => None,
        }
    }

    /// `"unlabelled"` or a label object.
    pub fn from_json(v: &Value) -> Option<HookDecl> {
        if v == "unlabelled" {
            return Some(HookDecl::Unlabelled);
        }
        AssuranceLabel::from_json(v).map(HookDecl::Labelled)
    }
}

/// The verifier's configured hooks and their labels.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AssuranceHooks {
    pub attestation: Option<HookDecl>,
    pub zk: Option<HookDecl>,
    pub threshold: Option<HookDecl>,
    pub revocation: Option<HookDecl>,
}

/// The outcome of one check in the report.
#[derive(Debug, Clone, PartialEq)]
pub struct CheckAssurance {
    pub outcome: CheckStatus,
    /// Present only on a pass that rests on labelled evidence.
    pub level: Option<String>,
    pub vendor: Option<String>,
    pub awaiting_audit: bool,
    pub ceremony: Option<String>,
    /// Signature checks: the suites involved (leaf, or the chain).
    pub suites: Option<Vec<String>>,
    /// Threshold: the `t` the hook enforced.
    pub t: Option<f64>,
    /// Why the outcome is `unsupported`, or why a passing check is `degraded`.
    pub reason: Option<String>,
    /// A passing check that rests on a compatibility mode.
    pub degraded: bool,
}

impl CheckAssurance {
    pub fn new(outcome: CheckStatus) -> Self {
        CheckAssurance { outcome, level: None, vendor: None, awaiting_audit: false, ceremony: None, suites: None, t: None, reason: None, degraded: false }
    }

    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("outcome".into(), json!(self.outcome.as_str()));
        if let Some(l) = &self.level {
            m.insert("level".into(), json!(l));
        }
        if let Some(v) = &self.vendor {
            m.insert("vendor".into(), json!(v));
        }
        if self.awaiting_audit {
            m.insert("awaiting_audit".into(), json!(true));
        }
        if let Some(c) = &self.ceremony {
            m.insert("ceremony".into(), json!(c));
        }
        if let Some(s) = &self.suites {
            m.insert("suites".into(), json!(s));
        }
        if let Some(t) = self.t {
            m.insert("t".into(), if t.fract() == 0.0 && t.abs() < 9.0e15 { json!(t as i64) } else { json!(t) });
        }
        if let Some(r) = &self.reason {
            m.insert("reason".into(), json!(r));
        }
        if self.degraded {
            m.insert("degraded".into(), json!(true));
        }
        Value::Object(m)
    }

    pub fn from_json(v: &Value) -> Option<CheckAssurance> {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        Some(CheckAssurance {
            outcome: CheckStatus::parse(v.get("outcome")?.as_str()?)?,
            level: s("level"),
            vendor: s("vendor"),
            awaiting_audit: (v.get("awaiting_audit") == Some(&Value::Bool(true)) || v.get("preview") == Some(&Value::Bool(true))),
            ceremony: s("ceremony"),
            suites: v.get("suites").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()),
            t: v.get("t").and_then(Value::as_f64),
            reason: s("reason"),
            degraded: v.get("degraded") == Some(&Value::Bool(true)),
        })
    }
}

/// Per check: was it enforced, and on what evidence. Insertion-ordered; the keys are the verdict's check names (the chain
/// check is reported as `cap_chain`, as the reference names it).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AssuranceReport {
    entries: Vec<(String, CheckAssurance)>,
}

impl AssuranceReport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> Option<&CheckAssurance> {
        self.entries.iter().find(|(n, _)| n == name).map(|(_, e)| e)
    }

    pub fn set(&mut self, name: &str, e: CheckAssurance) {
        match self.entries.iter_mut().find(|(n, _)| n == name) {
            Some(slot) => slot.1 = e,
            None => self.entries.push((name.to_string(), e)),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &CheckAssurance)> {
        self.entries.iter().map(|(n, e)| (n.as_str(), e))
    }

    pub fn to_json(&self) -> Value {
        Value::Object(self.entries.iter().map(|(n, e)| (n.clone(), e.to_json())).collect())
    }

    pub fn from_json(v: &Value) -> Option<AssuranceReport> {
        let mut r = AssuranceReport::new();
        for (k, x) in v.as_object()? {
            r.set(k, CheckAssurance::from_json(x)?);
        }
        Some(r)
    }
}

/// The awaiting_audit threshold schemes (FROST, DKG, MPC).
pub fn is_awaiting_audit_scheme(s: &str) -> bool {
    matches!(s, "frost" | "frost_dkg" | "mpc")
}

fn att_rank(level: &str) -> i32 {
    match level {
        "software" => 1,
        "hardware" => 2,
        "multi_root" => 3,
        _ => 0,
    }
}

fn zk_rank(level: &str) -> i32 {
    match level {
        "attested_vm" | "attested_vm_hw" => 1,
        "stark" | "zkvm" => 2,
        "groth16" | "policyvm_snark" => 3,
        _ => 0,
    }
}

/// One root of a multi-root attestation policy.
#[derive(Debug, Clone, Default)]
pub struct RootDecl {
    /// The root verifier's label (`None`: unlabelled, `unknown`).
    pub label: Option<AssuranceLabel>,
    pub required: bool,
}

/// The attestation level a multi-root N-of-M policy guarantees: the fewest hardware roots any accepted subset can contain (all
/// required roots, filled up to `threshold` with the weakest optional ones). Two or more => `multi_root`, one => `hardware`,
/// none => the weakest level among the roots that could make up the quorum.
pub fn multi_root_level(roots: &[RootDecl], threshold: i64) -> &'static str {
    let rank = |r: &RootDecl| att_rank(r.label.as_ref().map_or("unknown", |l| l.level.as_str()));
    let req: Vec<&RootDecl> = roots.iter().filter(|r| r.required).collect();
    let mut opt: Vec<&RootDecl> = roots.iter().filter(|r| !r.required).collect();
    opt.sort_by_key(|r| rank(*r));
    let take = (threshold - req.len() as i64).max(0) as usize;
    let chosen: Vec<&RootDecl> = req.into_iter().chain(opt.into_iter().take(take)).collect();
    let hw = chosen.iter().filter(|r| rank(*r) >= 2).count();
    if hw >= 2 {
        return "multi_root";
    }
    if hw == 1 {
        return "hardware";
    }
    // an empty quorum has no weakest member: `Math.min()` of nothing is +Infinity, which counts as software
    let min = chosen.iter().map(|r| rank(*r)).min().unwrap_or(i32::MAX);
    if min >= 1 {
        "software"
    } else {
        "unknown"
    }
}

/// Classify one signature suite (absent or null = Ed25519). An unregistered suite is `unknown` (a registered one this build cannot verify still classifies by its name).
pub fn signature_level(alg: Option<&Value>) -> &'static str {
    let a = match alg {
        None | Some(Value::Null) => return "ed25519",
        Some(a) => a,
    };
    if a == "ed25519" {
        return "ed25519";
    }
    match a.as_str() {
        Some(s) if crate::REGISTERED_SUITES.contains(&s) => {
            if s.starts_with("hybrid-") {
                "hybrid"
            } else {
                "pq"
            }
        }
        _ => "unknown",
    }
}

/// The weakest level in a chain: any unknown suite, then any Ed25519-only signer, then any hybrid, else pure PQ.
fn weakest(levels: &[&'static str]) -> &'static str {
    for l in ["unknown", "ed25519", "hybrid"] {
        if levels.contains(&l) {
            return l;
        }
    }
    if levels.is_empty() {
        "unknown"
    } else {
        "pq"
    }
}

/// What the report is built from.
#[derive(Debug, Clone, Copy, Default)]
pub struct AssuranceSources<'a> {
    pub checks: &'a [(String, CheckStatus)],
    pub pcactn: Option<&'a Value>,
    pub hooks: Option<&'a AssuranceHooks>,
    /// The attestation hook actually used (it wins over `hooks.attestation`).
    pub attestation_hook: Option<&'a HookDecl>,
    /// The `t` the threshold hook reported.
    pub threshold_t: Option<f64>,
    pub allow_unbound_pq: bool,
    /// Passing checks that rest on a compatibility mode: check name -> why.
    pub degraded: &'a [(String, String)],
}

/// Build the per-check assurance report (pure; never panics on odd input).
pub fn assurance_report(src: &AssuranceSources<'_>) -> AssuranceReport {
    let mut out = AssuranceReport::new();
    let hooks = src.hooks.cloned().unwrap_or_default();
    for (name, status) in src.checks {
        let mut e = CheckAssurance::new(*status);
        if *status == CheckStatus::Unsupported {
            e.reason = Some(format!("{name} is not implemented by this verifier"));
        }
        if *status == CheckStatus::Pass {
            let hook: Option<&HookDecl> = match name.as_str() {
                "attestation" => src.attestation_hook.or(hooks.attestation.as_ref()),
                "zk_compliance" => hooks.zk.as_ref(),
                "threshold" => hooks.threshold.as_ref(),
                "revocation" => hooks.revocation.as_ref(),
                _ => None,
            };
            let label = hook.and_then(HookDecl::label);
            if name == "attestation" || name == "zk_compliance" || (name == "threshold" && hook.is_some()) {
                let level = label.map_or("unknown", |l| l.level.as_str()).to_string();
                e.vendor = label.and_then(|l| l.vendor.clone());
                if name == "zk_compliance" {
                    e.ceremony = label.and_then(|l| l.ceremony.clone());
                }
                e.awaiting_audit = label.is_some_and(|l| l.awaiting_audit) || (name == "threshold" && is_awaiting_audit_scheme(&level));
                if name == "threshold" {
                    e.t = src.threshold_t;
                }
                e.level = Some(level);
            } else if let Some(l) = label {
                e.level = Some(l.level.clone());
                e.vendor = l.vendor.clone();
                e.awaiting_audit = l.awaiting_audit;
            }
            if let Some(p) = src.pcactn {
                if name == "leaf_signature" {
                    let alg = p.get("alg").filter(|a| !a.is_null());
                    e.suites = Some(vec![alg.map_or("ed25519".to_string(), js_value_string)]);
                    let classical = alg.is_none_or(|a| a == "ed25519");
                    e.level = Some((if src.allow_unbound_pq && !classical { "unbound_pq" } else { signature_level(alg) }).to_string());
                }
                if name == "cap_chain" {
                    if let Some(chain) = p.get("cap_chain").and_then(Value::as_array) {
                        let algs: Vec<Option<&Value>> = chain.iter().map(|c| c.get("alg").filter(|a| !a.is_null())).collect();
                        e.suites = Some(algs.iter().map(|a| a.map_or("ed25519".to_string(), js_value_string)).collect());
                        let any_pq = algs.iter().any(|a| a.is_some_and(|x| x != "ed25519"));
                        let levels: Vec<&'static str> = algs.iter().map(|a| signature_level(*a)).collect();
                        e.level = Some((if src.allow_unbound_pq && any_pq { "unbound_pq" } else { weakest(&levels) }).to_string());
                    }
                }
            }
        }
        out.set(name, e);
    }
    for (name, why) in src.degraded {
        if let Some(cur) = out.get(name).filter(|c| c.outcome == CheckStatus::Pass) {
            let mut d = cur.clone();
            d.degraded = true;
            d.reason = Some(why.clone());
            out.set(name, d);
        }
    }
    // Features the verifier does not implement: reported, never a pass.
    if src.pcactn.is_some_and(|p| p.get("bond_ref").is_some()) {
        let mut b = CheckAssurance::new(CheckStatus::Unsupported);
        b.reason = Some("bond verification is not implemented by this verifier".into());
        out.set("bond", b);
    }
    out
}

/// Refresh a report after more checks were decided: a check that is no longer `pass` loses its level, a new check is added,
/// `unsupported` stays.
pub fn refresh_assurance(report: &mut AssuranceReport, checks: &[(String, CheckStatus)]) {
    for (name, status) in checks {
        let was = report.get(name).map(|w| w.outcome);
        if was == Some(CheckStatus::Unsupported) {
            continue;
        }
        if *status != CheckStatus::Pass {
            report.set(name, CheckAssurance::new(*status));
        } else if was != Some(CheckStatus::Pass) {
            report.set(name, CheckAssurance::new(CheckStatus::Pass));
        }
    }
}

/// A high-assurance policy. Every listed dimension must be met by a PASSING check; otherwise the `assurance` check fails.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AssuranceRequirement {
    /// Minimum attestation level: `software` < `hardware` < `multi_root`.
    pub attestation: Option<String>,
    /// `attested_vm` | `attested_vm_hardware` | `proof` | `snark`.
    pub zk: Option<String>,
    /// `pq`: the leaf signature and every capability in the chain use a hybrid or pure post-quantum suite.
    pub signature_pq: bool,
    /// Accepted threshold schemes (which must pass on an enforced, labelled hook).
    pub threshold: Option<Vec<String>>,
    /// Accept passing evidence labelled awaiting audit outside an explicit `threshold` list. Default false.
    pub allow_awaiting_audit: bool,
}

impl AssuranceRequirement {
    /// From `{attestation?, zk?, signature?: "pq", threshold?: [..], allowAwaitingAudit?}`.
    pub fn from_json(v: &Value) -> AssuranceRequirement {
        let s = |k: &str| v.get(k).and_then(Value::as_str).map(str::to_string);
        AssuranceRequirement {
            attestation: s("attestation"),
            zk: s("zk"),
            signature_pq: v.get("signature") == Some(&json!("pq")),
            threshold: v.get("threshold").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()),
            allow_awaiting_audit: (v.get("allowAwaitingAudit") == Some(&Value::Bool(true)) || v.get("allowPreview") == Some(&Value::Bool(true))),
        }
    }
}

/// Check a report against a requirement. Returns the reason of the first unmet dimension (prefixed `assurance:`), or `None`
/// when every listed dimension is met. Missing, failed, not-enforced, unlabelled, weaker, awaiting-audit, degraded and unsupported
/// evidence never meet a requirement.
pub fn unmet_assurance(report: &AssuranceReport, req: &AssuranceRequirement) -> Option<String> {
    for (name, e) in report.iter() {
        if e.outcome == CheckStatus::Unsupported {
            return Some(format!(
                "assurance: unsupported: {name} ({}); a high-assurance policy never accepts it",
                e.reason.as_deref().unwrap_or("not implemented")
            ));
        }
    }
    for (name, e) in report.iter() {
        if e.outcome == CheckStatus::Pass && e.degraded {
            return Some(format!(
                "assurance: {name} rests on a degraded compatibility mode ({}); a high-assurance policy never accepts it",
                e.reason.as_deref().unwrap_or("degraded")
            ));
        }
    }
    let need = |name: &str, what: &str| -> Result<&CheckAssurance, String> {
        match report.get(name) {
            None => Err(format!("assurance: {what} required but there is no {name} evidence")),
            Some(e) if e.outcome != CheckStatus::Pass => Err(format!("assurance: {what} required but the {name} check is {}", e.outcome.as_str())),
            Some(e) => Ok(e),
        }
    };
    let run = || -> Result<(), String> {
        if let Some(att) = &req.attestation {
            let e = need("attestation", &format!("{att} attestation"))?;
            let level = e.level.as_deref().unwrap_or("unknown");
            let want = match att.as_str() {
                "software" | "hardware" | "multi_root" => att_rank(att),
                _ => 99,
            };
            if att_rank(level) < want {
                return Err(format!("assurance: {att} attestation required but the evidence is {level}"));
            }
        }
        if let Some(zk) = &req.zk {
            let e = need("zk_compliance", &format!("zk compliance ({zk})"))?;
            let level = e.level.as_deref().unwrap_or("unknown");
            if zk == "attested_vm_hardware" && matches!(level, "attested_vm" | "unknown") {
                return Err(format!("assurance: zk compliance ({zk}) required but the prover key is not bound to hardware evidence"));
            }
            let want = match zk.as_str() {
                "attested_vm" | "attested_vm_hardware" => 1,
                "proof" => 2,
                "snark" => 3,
                _ => return Err(format!("assurance: zk compliance ({zk}) is not a known requirement")),
            };
            if zk_rank(level) < want {
                return Err(format!("assurance: zk compliance ({zk}) required but the evidence is {level}"));
            }
        }
        if req.signature_pq {
            for name in ["leaf_signature", "cap_chain"] {
                let e = need(name, "post-quantum signatures")?;
                let level = e.level.as_deref().unwrap_or("unknown");
                if level != "pq" && level != "hybrid" {
                    return Err(format!("assurance: post-quantum signatures required but {name} is {level}"));
                }
            }
        }
        if let Some(list) = &req.threshold {
            let shown = list.join(" | ");
            let e = need("threshold", &format!("threshold ({shown})"))?;
            let Some(level) = e.level.as_deref() else {
                return Err(format!("assurance: threshold ({shown}) required but no threshold verifier enforced it"));
            };
            if !list.iter().any(|s| s == level) {
                return Err(format!("assurance: threshold ({shown}) required but the scheme is {level}"));
            }
        }
        if !req.allow_awaiting_audit {
            for (name, e) in report.iter() {
                if e.outcome != CheckStatus::Pass || !e.awaiting_audit {
                    continue;
                }
                if name == "threshold" && req.threshold.as_ref().is_some_and(|l| l.iter().any(|s| Some(s.as_str()) == e.level.as_deref().or(Some("")))) {
                    continue;
                }
                return Err(format!(
                    "assurance: {name} rests on crypto awaiting audit ({}); set allowAwaitingAudit or list the scheme to accept it",
                    e.level.as_deref().unwrap_or("unknown")
                ));
            }
        }
        Ok(())
    };
    run().err()
}

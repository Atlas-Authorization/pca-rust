//! The Bayesian elicitation learner, JSON-valued view (deprecated): the posterior itself is
//! [`crate::intent_kit::learner::IntentLearner`], the single implementation shared with the flagship's design (typed
//! [`crate::intent_kit::omega::Omega`], `createLearner(omega, options)`). A [`Learner`] here is a thin wrapper that holds an
//! `IntentLearner` and keeps the JSON-valued fields older callers read (`omega`, `omega_t`, `params`, `observations`, ...).
//! New code should use `intent_kit::mapkit::create_learner` and `IntentLearner` directly.
use super::omega::*;
use super::util::*;
use crate::intent_kit::learner::{Hc, IntentLearner, LearnerOpts};
use crate::intent_kit::omega::VerbSpace;
use crate::wallet_omega::fdlibm;
use serde_json::{json, Value};

pub use crate::intent_kit::learner::CellInfo;

pub fn jmax(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

pub fn jmin(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

fn is_integer(x: f64) -> bool {
    x.is_finite() && x == x.floor()
}

/// The hypothesis class as the options record it (`k` / `maxRules` stay JSON values until the learner is built).
#[derive(Clone, Debug)]
pub enum HClass {
    Boxes,
    Union { k: Value, decay: f64 },
    DList { max_rules: Value, decay: f64, conditions: String },
}

impl HClass {
    pub fn decay(&self) -> f64 {
        match self {
            HClass::Boxes => 1.0,
            HClass::Union { decay, .. } | HClass::DList { decay, .. } => *decay,
        }
    }

    /// The canonical name of the class (stored in the Intent Map).
    pub fn name(&self) -> &'static str {
        match self {
            HClass::Boxes => "per-verb-box/v1",
            HClass::Union { .. } => "per-verb-union/v1",
            HClass::DList { conditions, .. } => {
                if conditions == "atomic" {
                    "per-verb-decision-list/v1"
                } else {
                    "per-verb-decision-list/v2"
                }
            }
        }
    }

    /// The typed class of the shared learner; refuses what the reference refuses (`k` / `maxRules` not an integer >= 1, bad `conditions`).
    pub fn to_core(&self) -> R<Hc> {
        Ok(match self {
            HClass::Boxes => Hc::Box,
            HClass::Union { k, decay } => {
                let kf = fnum(k).filter(|x| is_integer(*x) && *x >= 1.0).ok_or("pca-intent: union class needs an integer k \u{2265} 1")?;
                Hc::Union { k: kf as usize, decay: *decay }
            }
            HClass::DList { max_rules, decay, conditions } => {
                let mr =
                    fnum(max_rules).filter(|x| is_integer(*x) && *x >= 1.0).ok_or("pca-intent: decision-list class needs an integer maxRules \u{2265} 1")?;
                if conditions != "box" && conditions != "atomic" {
                    return Err("pca-intent: decision-list conditions must be 'box' or 'atomic'".into());
                }
                Hc::DList { max_rules: mr as usize, atomic: conditions == "atomic", decay: *decay }
            }
        })
    }
}

#[derive(Clone, Debug)]
pub struct PmCell {
    pub verb: String,
    pub cell: f64,
    pub lq: f64,
    pub lnq: f64,
}

#[derive(Clone, Debug)]
pub struct PriorMix {
    pub beta: f64,
    pub cells: Vec<PmCell>,
}

/// The learner parameters (already quantised the way an Intent Map records them).
pub struct LOpts {
    pub eta: f64,
    pub eta_pos: f64,
    pub eta_neg: f64,
    pub tau: f64,
    pub strategy: String,
    pub hc: HClass,
    pub agnostic_slack: Option<f64>,
    /// per-verb null mass: (quantised) values by verb plus the default
    pub null_mass: Box<dyn Fn(&str) -> f64>,
    pub anchors: Vec<(Value, f64)>,
    pub monotone: Option<(Vec<String>, f64)>,
    pub prior_mix: Option<PriorMix>,
    pub max_hypotheses: f64,
    pub max_enumeration: f64,
}

impl LOpts {
    /// The options of the shared learner.
    fn into_core(self) -> R<LearnerOpts> {
        let mut o = LearnerOpts::default_opts();
        o.eta = self.eta;
        o.eta_pos = Some(self.eta_pos);
        o.eta_neg = Some(self.eta_neg);
        o.tau = Some(self.tau);
        o.strategy = self.strategy;
        o.hypothesis_class = self.hc.to_core()?;
        o.agnostic_slack = self.agnostic_slack;
        let nm = self.null_mass;
        o.null_mass = Some(Box::new(move |vs: &VerbSpace| nm(&vs.verb)));
        o.anchors = self.anchors;
        o.monotone = self.monotone;
        o.prior_mix = self.prior_mix.map(|pm| {
            let cells = pm.cells;
            let w: Box<dyn Fn(&VerbSpace, &dyn Fn(f64) -> bool) -> f64> = Box::new(move |vs: &VerbSpace, contains: &dyn Fn(f64) -> bool| {
                let mut lw = 0.0;
                for t in cells.iter().filter(|t| t.verb == vs.verb) {
                    lw += if contains(t.cell) { t.lq } else { t.lnq };
                }
                fdlibm::exp(lw)
            });
            (pm.beta, w)
        });
        o.max_hypotheses = self.max_hypotheses;
        o.max_enumeration = self.max_enumeration;
        Ok(o)
    }
}

#[derive(Clone, Debug)]
pub struct Question {
    pub verb: String,
    pub cell: Vec<usize>,
    pub outcome: Value,
    pub p: f64,
    pub score: f64,
}

impl Question {
    pub fn to_json(&self) -> Value {
        json!({"verb": self.verb, "cell": self.cell, "outcome": self.outcome, "p": num(self.p), "score": num(self.score)})
    }

    fn from_core(v: &Value) -> R<Question> {
        let g = |k: &str| fnum(&v[k]).unwrap_or(f64::NAN);
        Ok(Question {
            verb: text(&v["verb"], "question verb")?.to_string(),
            cell: arr(&v["cell"], "question cell")?.iter().map(|x| fnum(x).unwrap_or(0.0) as usize).collect(),
            outcome: v["outcome"].clone(),
            p: g("p"),
            score: g("score"),
        })
    }
}

#[derive(Clone, Debug)]
pub struct Metrics {
    pub residual_risk: f64,
    pub burden: f64,
    pub uncertainty: f64,
    pub entropy_bits: f64,
    pub log2_vs: Option<f64>,
    pub disagreement_mass: f64,
    pub mean_harm: f64,
    pub questions: usize,
    pub conflicts: usize,
}

impl Metrics {
    pub fn to_json(&self) -> Value {
        json!({"residualRisk": num(self.residual_risk), "burden": num(self.burden), "uncertainty": num(self.uncertainty), "entropyBits": num(self.entropy_bits),
            "log2VersionSpace": self.log2_vs.map(num).unwrap_or(Value::Null), "disagreementMass": num(self.disagreement_mass), "meanHarm": num(self.mean_harm),
            "questions": self.questions, "conflicts": self.conflicts})
    }

    fn from_core(m: &Value) -> Metrics {
        let g = |k: &str| fnum(&m[k]).unwrap_or(f64::NAN);
        Metrics {
            residual_risk: g("residualRisk"),
            burden: g("burden"),
            uncertainty: g("uncertainty"),
            entropy_bits: g("entropyBits"),
            log2_vs: fnum(&m["log2VersionSpace"]),
            disagreement_mass: g("disagreementMass"),
            mean_harm: g("meanHarm"),
            questions: fnum(&m["questions"]).unwrap_or(0.0) as usize,
            conflicts: fnum(&m["conflicts"]).unwrap_or(0.0) as usize,
        }
    }
}

/// The exact posterior over Theta = prod_v Theta_v (JSON-valued view of [`IntentLearner`]).
pub struct Learner {
    pub omega: Value,
    pub omega_t: Omega,
    pub eta: f64,
    pub eta_pos: f64,
    pub eta_neg: f64,
    pub tau: f64,
    pub strategy: String,
    pub hypothesis_class: HClass,
    pub agnostic_slack: Option<f64>,
    pub observations: Vec<Value>,
    /// the serialisable parameters the learner was built with (`createLearner` options)
    pub params: Value,
    core: IntentLearner,
}

impl Learner {
    pub fn new(omega: &Value, opts: LOpts, params: Value) -> R<Learner> {
        let omega_t = Omega::parse(omega)?;
        for vs in &omega_t.verbs {
            vs.weight_of()?;
        }
        let (eta, eta_pos, eta_neg, tau, strategy, hc, slack) =
            (opts.eta, opts.eta_pos, opts.eta_neg, opts.tau, opts.strategy.clone(), opts.hc.clone(), opts.agnostic_slack);
        let mut core = IntentLearner::new(&omega_t.to_core(), opts.into_core()?)?;
        core.map_params = Some(params.clone());
        Ok(Learner {
            omega: omega.clone(),
            omega_t,
            eta,
            eta_pos,
            eta_neg,
            tau,
            strategy,
            hypothesis_class: hc,
            agnostic_slack: slack,
            observations: vec![],
            params,
            core,
        })
    }

    /// The JSON-valued view of a learner built by the shared `create_learner` (`omega` is the JSON form of the space it was built over).
    pub(crate) fn from_core(omega: Value, core: IntentLearner) -> R<Learner> {
        let omega_t = Omega::parse(&omega)?;
        let hypothesis_class = match &core.hypothesis_class {
            Hc::Box => HClass::Boxes,
            Hc::Union { k, decay } => HClass::Union { k: num(*k as f64), decay: *decay },
            Hc::DList { max_rules, atomic, decay } => {
                HClass::DList { max_rules: num(*max_rules as f64), decay: *decay, conditions: if *atomic { "atomic" } else { "box" }.to_string() }
            }
        };
        Ok(Learner {
            omega,
            omega_t,
            eta: core.eta,
            eta_pos: core.eta_pos,
            eta_neg: core.eta_neg,
            tau: core.tau,
            strategy: core.strategy.clone(),
            hypothesis_class,
            agnostic_slack: core.agnostic_slack,
            observations: core.observations.clone(),
            params: core.map_params.clone().unwrap_or(Value::Null),
            core,
        })
    }

    /// The shared learner underneath.
    pub fn core(&self) -> &IntentLearner {
        &self.core
    }

    /// Mutable access for the map emitter (it refreshes the posterior's caches; it never changes the observations the view mirrors).
    pub(crate) fn core_mut(&mut self) -> &mut IntentLearner {
        &mut self.core
    }

    /// p_n(omega) for a concrete outcome (0 if outside Omega: the conservative reading).
    pub fn acceptance(&mut self, o: &Value) -> f64 {
        self.core.acceptance(o)
    }

    pub fn admits_outcome(&mut self, o: &Value) -> bool {
        self.core.admits_outcome(o)
    }

    pub fn is_vetoed(&self, o: &Value) -> bool {
        self.core.is_vetoed(o)
    }

    /// Record the principal's answer `y` to "should omega be allowed?" (or, with a region, "should EVERY outcome in it be allowed?") and
    /// update the posterior. `None` when the outcome is outside Omega or the region covers no cell.
    pub fn observe(&mut self, o: &Value, y: f64, source: &str, region: Option<&Value>) -> R<Option<Value>> {
        let r = self.core.observe(o, y as i64, source, region)?;
        if let Some(ob) = &r {
            self.observations.push(ob.clone());
        }
        Ok(r)
    }

    pub fn cells(&mut self) -> Vec<CellInfo> {
        self.core.cells()
    }

    pub fn metrics(&mut self) -> Metrics {
        Metrics::from_core(&self.core.metrics())
    }

    /// The next question: argmax expected information (x mu*h for the risk strategy). `None` when nothing is uncertain.
    pub fn next_question(&mut self) -> R<Option<Question>> {
        match self.core.next_question()? {
            Some(q) => Ok(Some(Question::from_core(&q)?)),
            None => Ok(None),
        }
    }

    /// Grant cells INFERRED but never directly observed, most consequential first: (verb, cell, weight).
    pub fn unconfirmed_grant_cells(&mut self) -> Vec<(String, Vec<usize>, f64)> {
        self.core.unconfirmed_grant_cells()
    }

    /// The conservative grant G_tau as a real PCA policy: allow only cells with p_n >= tau.
    pub fn synthesize(&mut self) -> R<Value> {
        self.core.synthesize()
    }
}

/// Cover the allowed cell set exactly with greedily-grown maximal boxes; one predicate per box.
pub fn boxes_to_predicates(vs: &Vs, allowed: &[u8]) -> R<Vec<Value>> {
    crate::intent_kit::learner::boxes_to_predicates(&vs.to_core(), allowed)
}

//! Differential replay of test-data/ref-progress.json.gz (written by the TypeScript reference): the potentials and their registry, goal
//! commitment, state and step digests, trajectory anchoring, signed state attestations and the attested source, the tracker (op scripts
//! with guards, sources and budgets), step and trajectory verification and signed steps. Every function of the corpus has a handler and the
//! per-function totals are asserted. A reference refusal must be a refusal here; `{"$err": m}` inside a result list is one op that refused
//! (its message is compared). The 4 attestation verdicts the reference accepts only through its legacy unbound post-quantum opt-out are
//! asserted REFUSED (that option is not offered). One case carries a non-finite number, which is not a JSON value: not run.
mod common;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::Arc;

use atlas_pca::agent::{KeyPair, Suite};
use atlas_pca::ledger_store::TransparencyLedger;
use atlas_pca::progress::*;
use atlas_pca::serde_json::{json, Map, Value};
use common::replay::{replay_cases, skip, thrown};

fn fnum(f: f64) -> Value {
    if f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0 {
        json!(f as i64)
    } else {
        Value::Null
    }
}

fn pot(r: Result<f64, String>) -> Value {
    r.map(fnum).unwrap_or_else(thrown)
}

fn text<T: AsRef<str>>(r: Result<T, String>) -> Value {
    r.map(|s| json!(s.as_ref())).unwrap_or_else(thrown)
}

fn has_marker(v: &Value) -> bool {
    match v {
        Value::Object(m) => (m.len() == 1 && m.contains_key("$num")) || m.values().any(has_marker),
        Value::Array(a) => a.iter().any(has_marker),
        _ => false,
    }
}

// ---- host objects from their specs ---------------------------------------------------------------------------------------------------

fn kind(k: &str) -> PotentialFn {
    match k {
        "l1-feature-v1" => Arc::new(l1_feature_potential),
        "dag-remaining-v1" => Arc::new(dag_remaining_potential),
        "dag-weighted-v1" => Arc::new(dag_weighted_potential),
        "v" => Arc::new(|_: &Value, s: &Value| Ok(s.get("v").and_then(Value::as_f64).unwrap_or(f64::NAN))),
        "throws" => Arc::new(|_: &Value, _: &Value| Err("potential boom".into())),
        "negative" => Arc::new(|_: &Value, _: &Value| Ok(-1.0)),
        "frac" => Arc::new(|_: &Value, _: &Value| Ok(0.5)),
        "nan" => Arc::new(|_: &Value, _: &Value| Ok(f64::NAN)),
        "big" => Arc::new(|_: &Value, _: &Value| Ok(9007199254740992.0)),
        c if c.starts_with("const:") => {
            let n: f64 = c[6..].parse().unwrap();
            Arc::new(move |_: &Value, _: &Value| Ok(n))
        }
        other => panic!("bad potential kind {other}"),
    }
}

fn registry(s: &Value) -> Result<Option<PotentialRegistry>, String> {
    if s.is_null() {
        return Ok(None);
    }
    let mut r = PotentialRegistry::new();
    for p in s["potentials"].as_array().unwrap() {
        r.register(
            p[0].as_str().unwrap(),
            kind(p[1].as_str().unwrap()),
            p.get(2).and_then(Value::as_str).unwrap_or(""),
        )?;
    }
    Ok(Some(r))
}

type Guard = Box<dyn Fn(&Transition<'_>) -> bool>;

fn guard(g: &Value) -> Option<Guard> {
    let g = g.as_str()?;
    let b: Guard = match g {
        "allow" => Box::new(|_: &Transition<'_>| true),
        "deny" | "throws" | "truthy" => Box::new(|_: &Transition<'_>| false), // a throw and a truthy non-boolean both deny
        _ if g.starts_with("action:") => {
            let d = g[7..].to_string();
            Box::new(move |t: &Transition<'_>| t.action_digest != d)
        }
        _ if g.starts_with("seq:") => {
            let n: f64 = g[4..].parse().unwrap();
            Box::new(move |t: &Transition<'_>| t.seq != n)
        }
        _ if g.starts_with("after-v:") => {
            let n: f64 = g[8..].parse().unwrap();
            Box::new(move |t: &Transition<'_>| t.after.get("v").and_then(Value::as_f64) != Some(n))
        }
        other => panic!("bad guard {other}"),
    };
    Some(b)
}

type Att = Box<dyn Fn(&Value) -> bool + Send + Sync>;

fn attestation(a: &Value) -> Result<Option<Att>, String> {
    Ok(match a {
        Value::Null => None,
        Value::String(s) if s == "allow" => Some(Box::new(|_: &Value| true)),
        Value::String(_) => Some(Box::new(|_: &Value| false)), // deny, throws, truthy
        other => Some(attested_state_verifier(&other["attested"])?),
    })
}

/// The owned side of the reference options (`registry` / `guard` / `attestation` are specs there).
struct Own<'a> {
    o: &'a Value,
    registry: Option<PotentialRegistry>,
    guard: Option<Guard>,
    att: Option<Att>,
    trusted: Option<Vec<String>>,
    eads: Option<Vec<String>>,
}

impl<'a> Own<'a> {
    fn new(o: &'a Value) -> Result<Own<'a>, String> {
        let strings = |k: &str| -> Option<Vec<String>> {
            o.get(k)
                .and_then(Value::as_array)
                .map(|a| a.iter().map(|x| x.as_str().unwrap_or("\u{0}bad").to_string()).collect())
        };
        Ok(Own {
            o,
            registry: match o.get("registry") {
                Some(r) => registry(r)?,
                None => None,
            },
            guard: o.get("guard").and_then(guard),
            att: match o.get("attestation") {
                Some(a) => attestation(a)?,
                None => None,
            },
            trusted: strings("trustedStateSources"),
            eads: strings("expectedActionDigests"),
        })
    }

    fn checks(&self) -> Checks<'_> {
        Checks {
            registry: self.registry.as_ref(),
            guard: self.guard.as_deref(),
            trusted_state_sources: self.trusted.as_deref(),
            require_attested_state: self.o.get("requireAttestedState").and_then(Value::as_bool),
            attestation: self.att.as_deref().map(|a| a as &dyn Fn(&Value) -> bool),
        }
    }

    fn step(&self) -> VerifyStepOptions<'_> {
        let s = |k: &str| self.o.get(k).and_then(Value::as_str);
        VerifyStepOptions {
            expected_seq: self.o.get("expectedSeq").and_then(Value::as_f64),
            expected_prev: s("expectedPrev"),
            expected_action_digest: s("expectedActionDigest"),
            expected_before_digest: s("expectedBeforeDigest"),
            expected_after_digest: s("expectedAfterDigest"),
            checks: self.checks(),
        }
    }

    fn trajectory(&self) -> VerifyTrajectoryOptions<'_> {
        VerifyTrajectoryOptions {
            initial: self.o.get("initial"),
            initial_digest: self.o.get("initialDigest").and_then(Value::as_str),
            expected_action_digests: self.eads.as_deref(),
            checks: self.checks(),
        }
    }
}

fn own(o: &Value) -> Result<Own<'_>, String> {
    Own::new(o)
}

// ---- state sources ---------------------------------------------------------------------------------------------------------------------

trait TestSource: StateSource {
    fn as_source(&mut self) -> &mut dyn StateSource;
    fn set(&mut self, v: &Value) -> Result<(), String>;
    fn attestations(&self) -> Option<Vec<Value>> {
        None
    }
}

struct Mem(InMemoryStateSource);

impl StateSource for Mem {
    fn id(&self) -> &str {
        self.0.id()
    }
    fn observe(&mut self, req: &Value) -> Result<Value, String> {
        self.0.observe(req)
    }
}

impl TestSource for Mem {
    fn as_source(&mut self) -> &mut dyn StateSource {
        self
    }
    fn set(&mut self, v: &Value) -> Result<(), String> {
        self.0.apply(v)
    }
}

/// `throws` / `null` / `liar-digest` / `liar-source`: an in-memory source that misreports.
struct Wrap {
    kind: String,
    mem: InMemoryStateSource,
}

impl StateSource for Wrap {
    fn id(&self) -> &str {
        self.mem.id()
    }
    fn observe(&mut self, req: &Value) -> Result<Value, String> {
        match self.kind.as_str() {
            "throws" => Err("source boom".into()),
            "null" => Ok(Value::Null),
            k => {
                let mut ob = self.mem.observe(req)?;
                match k {
                    "liar-digest" => ob["state_digest"] = json!("x".repeat(43)),
                    "liar-source" => ob["source"] = json!("someone-else"),
                    _ => {}
                }
                Ok(ob)
            }
        }
    }
}

impl TestSource for Wrap {
    fn as_source(&mut self) -> &mut dyn StateSource {
        self
    }
    fn set(&mut self, v: &Value) -> Result<(), String> {
        self.mem.apply(v)
    }
}

struct Attested<'a> {
    src: AttestedStateSource<'a>,
    world: Rc<RefCell<Value>>,
}

impl StateSource for Attested<'_> {
    fn id(&self) -> &str {
        self.src.id()
    }
    fn observe(&mut self, req: &Value) -> Result<Value, String> {
        self.src.observe(req)
    }
}

impl TestSource for Attested<'_> {
    fn as_source(&mut self) -> &mut dyn StateSource {
        self
    }
    fn set(&mut self, v: &Value) -> Result<(), String> {
        *self.world.borrow_mut() = v.clone();
        Ok(())
    }
    fn attestations(&self) -> Option<Vec<Value>> {
        Some(self.src.attestations().to_vec())
    }
}

fn source(s: &Value) -> Result<Box<dyn TestSource + '_>, String> {
    let (id, initial) = (s["id"].as_str().unwrap(), &s["initial"]);
    let k = s["kind"].as_str().unwrap();
    if k == "attested" {
        let world = Rc::new(RefCell::new(initial.clone()));
        let w = world.clone();
        let secret = common::b64d(s["signerSecret"].as_str().unwrap());
        let suite = Suite {
            alg: s["alg"].as_str(),
            pq: None,
        };
        let src = AttestedStateSource::new(id, &secret, move |_| Ok(w.borrow().clone()), Some(suite))?;
        return Ok(Box::new(Attested { src, world }));
    }
    let mem = InMemoryStateSource::new(initial, id)?;
    Ok(if k == "memory" {
        Box::new(Mem(mem))
    } else {
        Box::new(Wrap { kind: k.to_string(), mem })
    })
}

// ---- ops -------------------------------------------------------------------------------------------------------------------------------

fn err(e: String) -> Value {
    json!({"$err": e})
}

fn registry_op(r: &mut Option<PotentialRegistry>, name: &str, a: &[Value]) -> Result<Value, String> {
    match name {
        "new" => *r = Some(PotentialRegistry::new()),
        "defaults" => *r = Some(PotentialRegistry::defaults()),
        "default-frozen" => *r = Some((*DEFAULT_POTENTIALS).clone()),
        "from" => {
            let mut entries: Vec<(&str, PotentialFn, Option<&str>)> = Vec::new();
            for (id, v) in a[0].as_object().unwrap() {
                entries.push(match v.as_str() {
                    Some(k) => (id.as_str(), kind(k), None),
                    None => (
                        id.as_str(),
                        kind(v["fn"].as_str().unwrap()),
                        v.get("embedder").and_then(Value::as_str),
                    ),
                });
            }
            *r = Some(PotentialRegistry::from_record(&entries)?);
        }
        "register" => {
            let k = kind(a[1].as_str().unwrap());
            r.as_mut().unwrap().register_json(&a[0], k, a.get(2))?;
        }
        "get" => {
            return Ok(match a[0].as_str().and_then(|id| r.as_ref().unwrap().get(id)) {
                Some(spec) => json!({"embedder": spec.embedder}),
                None => Value::Null,
            })
        }
        "has" => return Ok(json!(a[0].as_str().is_some_and(|id| r.as_ref().unwrap().has(id)))),
        "ids" => return Ok(json!(r.as_ref().unwrap().ids())),
        "freeze" => {
            r.as_mut().unwrap().freeze();
        }
        _ => return Err("bad op".into()),
    }
    Ok(Value::Null)
}

fn tracker(a: &[Value]) -> Value {
    let (goal, initial) = (&a[0], &a[2]);
    let go = || -> Result<Value, String> {
        let commitment = if a[1].is_null() { json!(goal_digest(goal)?) } else { a[1].clone() };
        let reg = registry(&a[3])?;
        let mut srcs: Vec<Box<dyn TestSource + '_>> = Vec::new();
        for s in a[5].as_array().unwrap() {
            srcs.push(source(s)?);
        }
        let mut t = ProgressTracker::new(goal, &commitment, initial, reg.as_ref(), guard(&a[4]))?;
        let mut out = Vec::new();
        for op in a[6].as_array().unwrap() {
            let (name, args) = (op[0].as_str().unwrap(), &op.as_array().unwrap()[1..]);
            out.push(match name {
                "step" => t.step(&args[0], &args[1]),
                "stepObserved" => t.step_observed(srcs[args[0].as_u64().unwrap() as usize].as_source(), &args[1]),
                "apply" => match srcs[args[0].as_u64().unwrap() as usize].set(&args[1]) {
                    Ok(()) => Value::Null,
                    Err(e) => err(e),
                },
                "steps" => Value::Array(t.steps()),
                "state" => t.state().clone(),
                "currentStateDigest" => json!(t.current_state_digest()),
                "spent" => fnum(t.spent()),
                "remaining" => fnum(t.remaining()),
                "reached" => t.reached().map(|b| json!(b)).unwrap_or_else(err),
                _ => Value::Null,
            });
        }
        Ok(Value::Array(out))
    };
    go().unwrap_or_else(thrown)
}

fn attested_source(a: &[Value]) -> Value {
    let go = || -> Result<Value, String> {
        let mut s = source(&a[0])?;
        let obs: Vec<Value> = a[1].as_array().unwrap().iter().map(|r| s.observe(r).unwrap_or_else(err)).collect();
        Ok(json!({"observations": obs, "attestations": s.attestations()}))
    };
    go().unwrap_or_else(thrown)
}

fn run(f: &str, a: &[Value]) -> Value {
    match f {
        "constants" => json!({
            "PROGRESS_VERSION": PROGRESS_VERSION,
            "PROGRESS_SIG_DOMAIN": PROGRESS_SIG_DOMAIN,
            "TRAJECTORY_ANCHOR_DOMAIN": TRAJECTORY_ANCHOR_DOMAIN,
            "STATE_ATTESTATION_DOMAIN": STATE_ATTESTATION_DOMAIN,
        }),
        "l1FeaturePotential" => pot(l1_feature_potential(&a[0], &a[1])),
        "dagRemainingPotential" => pot(dag_remaining_potential(&a[0], &a[1])),
        "dagWeightedPotential" => pot(dag_weighted_potential(&a[0], &a[1])),
        "registryOps" => {
            let mut r = None;
            Value::Array(
                a[0].as_array()
                    .unwrap()
                    .iter()
                    .map(|op| registry_op(&mut r, op[0].as_str().unwrap(), &op.as_array().unwrap()[1..]).unwrap_or_else(err))
                    .collect(),
            )
        }
        "goalDigest" => text(goal_digest(&a[0])),
        "commitGoal" => commit_goal(&a[0]).unwrap_or_else(thrown),
        "verifyGoalCommitment" => json!(verify_goal_commitment(&a[0], &a[1])),
        "stateDigest" if has_marker(&a[0]) => skip("a non-finite number is not a JSON value"),
        "stateDigest" => text(state_digest(&a[0])),
        "trajectoryHead" => trajectory_head(a[0].as_array().unwrap()).unwrap_or_else(thrown),
        "progressStepDigest" => progress_step_digest(&a[0]).unwrap_or_else(thrown),
        "trajectoryAnchorCommit" => text(trajectory_anchor_commit(&a[0], &a[1])),
        "verifyTrajectoryAnchor" => json!(verify_trajectory_anchor(&a[0], &a[1], &a[2])),
        "anchorTrajectoryHead" => {
            let prior: Vec<String> = a[2].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_string()).collect();
            let mut ledger = TransparencyLedger::from_entries(Vec::new());
            for c in &prior {
                ledger.append_commitment(c).unwrap();
            }
            anchor_trajectory_head(&mut ledger, a[0].as_array().unwrap(), a[1].as_str()).unwrap_or_else(thrown)
        }
        "verifyStateAttestation" => json!(verify_state_attestation(
            &a[0],
            &a[1],
            if a[2].is_null() { None } else { Some(&a[2]) }
        )),
        "attestedStateVerifier" => match attested_state_verifier(&a[0]) {
            Ok(v) => json!(v(&a[1])),
            Err(e) => thrown(e),
        },
        "attestedSource" => attested_source(a),
        "tracker" => tracker(a),
        "verifyProgressStep" => match own(&a[3]) {
            Ok(o) => verify_progress_step(&a[0], &a[1], &a[2], &o.step()),
            Err(e) => thrown(e),
        },
        "verifyTrajectory" => match own(&a[3]) {
            Ok(o) => verify_trajectory(&a[0], &a[1], &a[2], &o.trajectory()),
            Err(e) => thrown(e),
        },
        "verifySignedProgressStep" => match own(&a[3]) {
            Ok(o) => verify_signed_progress_step(
                &a[0],
                &a[1],
                &a[2],
                a[3]["expectedHolder"].as_str().unwrap_or("\u{0}none"),
                &o.step(),
            ),
            Err(e) => thrown(e),
        },
        "verifySignedTrajectory" => match own(&a[3]) {
            Ok(o) => verify_signed_trajectory(
                &a[0],
                &a[1],
                &a[2],
                a[3]["expectedHolder"].as_str().unwrap_or("\u{0}none"),
                &o.trajectory(),
            )
            .unwrap_or_else(thrown),
            Err(e) => thrown(e),
        },
        "signProgressStep" => {
            let key = KeyPair::from_seed_b64u(a[1]["$bytes"].as_str().unwrap()).unwrap();
            sign_progress_step(&a[0], &key, a[2].as_str().unwrap()).unwrap_or_else(thrown)
        }
        other => panic!("unhandled corpus function {other}"),
    }
}

#[test]
fn progress_replay() {
    let cases = common::ref_cases_seeded("progress");
    let mut per_fn: BTreeMap<String, usize> = BTreeMap::new();
    for c in &cases {
        *per_fn.entry(c["fn"].as_str().unwrap().to_string()).or_default() += 1;
    }
    let want: BTreeMap<String, usize> = [
        ("verifyProgressStep", 147),
        ("verifyTrajectory", 130),
        ("verifyStateAttestation", 55),
        ("verifyGoalCommitment", 53),
        ("tracker", 40),
        ("progressStepDigest", 37),
        ("goalDigest", 31),
        ("commitGoal", 31),
        ("verifySignedProgressStep", 26),
        ("dagWeightedPotential", 24),
        ("dagRemainingPotential", 21),
        ("l1FeaturePotential", 20),
        ("verifyTrajectoryAnchor", 17),
        ("attestedStateVerifier", 15),
        ("verifySignedTrajectory", 15),
        ("stateDigest", 14),
        ("anchorTrajectoryHead", 10),
        ("trajectoryAnchorCommit", 8),
        ("attestedSource", 8),
        ("registryOps", 7),
        ("signProgressStep", 7),
        ("trajectoryHead", 6),
        ("constants", 1),
    ]
    .iter()
    .map(|(k, n)| (k.to_string(), *n))
    .collect();
    assert_eq!(per_fn, want, "per-function case totals");
    assert_eq!(cases.len(), 723);

    // the reference accepts a post-quantum attestation without a pin only through its legacy unbound opt-out, which is not offered here:
    // those verdicts are refusals
    let (unbound, rest): (Vec<Value>, Vec<Value>) = cases
        .into_iter()
        // only the post-quantum attestations (the plain Ed25519 ones a0 / a1 ignore the pin option and verify as the reference says)
        .partition(|c| c["args"].to_string().contains("allowUnboundPq") && c["out"] == json!(true) && c["name"].as_str().is_some_and(|n| n.contains("ml-dsa") || n.contains("hybrid")));
    assert_eq!(unbound.len(), 2, "reference acceptances through the unbound opt-out");
    for c in &unbound {
        assert_eq!(
            run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap()),
            json!(false),
            "{} must be refused",
            c["name"]
        );
    }
    let n = rest.len();
    replay_cases("progress", rest, n, 1, run);
}

#[test]
fn a_guard_that_panics_denies() {
    let g = |_: &Transition<'_>| -> bool { panic!("boom") };
    let goal = json!({"objective": {"target": [0]}, "potential": "l1-feature-v1", "embedder": "", "metric": "l1", "epsilon": 1, "explorationBudget": 0});
    let c = commit_goal(&goal).unwrap();
    let commitment = c["commitment"].clone();
    let mut t = ProgressTracker::new(&goal, &commitment, &json!({"x": [2]}), None, Some(Box::new(g))).unwrap();
    let r = t.step(&json!({"x": [1]}), &json!("a"));
    assert_eq!(r, json!({"ok": false, "reason": "prohibited", "stepUp": false}));
}

#[test]
fn a_signed_state_attestation_round_trips_and_a_tampered_one_is_refused() {
    let seed = [7u8; 32];
    let world = Rc::new(RefCell::new(json!({"x": [1]})));
    let w = world.clone();
    let mut src = AttestedStateSource::new("att", &seed, move |_| Ok(w.borrow().clone()), None).unwrap();
    let pk = json!(src.public_key);
    let req = json!({"action_digest": "a", "goal_commitment": "g", "prior_digest": "p"});
    let obs = src.observe(&req).unwrap();
    let att = obs["evidence"].clone();
    assert!(verify_state_attestation(&att, &pk, None));
    let mut forged = att.clone();
    forged["state_digest"] = json!("z");
    assert!(!verify_state_attestation(&forged, &pk, None));
    let mut m: Map<String, Value> = att.as_object().unwrap().clone();
    m.insert("alg".into(), json!("ml-dsa-65"));
    assert!(
        !verify_state_attestation(&Value::Object(m), &pk, None),
        "a post-quantum suite without a pinned key is refused"
    );
}

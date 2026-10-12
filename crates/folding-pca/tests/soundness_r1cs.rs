//! Soundness audit of the Nova step circuit at the R1CS level: does ANY assignment that violates the
//! intended relation satisfy the constraints? (Folding/IVC soundness is Nova's; this file covers the
//! circuit that Nova folds.)
//!
//! The real `ActionCircuit::synthesize` is run against a small recording constraint system (`Mini`) that
//! keeps every aux assignment and every `A*B = C` constraint, so assignments can be edited and each
//! constraint evaluated. The intended relation for one step, given the incoming state `(c_in, b_in)`:
//!
//!   cost in [0, 2^32),  b_out = b_in + cost,  b_out <= B_MAX,  c_out = Poseidon(c_in, Poseidon(action_digest, cost)).
//!
//! 1. `honest_*`  : honest witnesses are satisfiable and equal the native replay; over-budget / out-of-range /
//!                  field-negative witnesses are unsatisfiable; accept/reject equals the native replay on a
//!                  corpus of 2400 histories.
//! 2. `no_free_wires`: every auxiliary wire is pinned: moving any single wire to another value violates at
//!                  least one constraint (so no wire is unconstrained).
//! 3. `constraint_ablation`: each of the 593 constraints is dropped in turn ("mutant"); a mutant is KILLED if
//!                  some assignment violating the relation satisfies all other constraints. Attack kinds:
//!                  natural provers on malicious inputs, bit-absorbing edits that break one booleanity
//!                  constraint, and forward propagation (free one wire, recompute everything downstream
//!                  honestly). Survivors must be exactly the documented redundant gadget; that gadget is then
//!                  shown equivalent on a corpus when dropped as a whole.
//!
//! Run: `cargo test --release --test soundness_r1cs -- --nocapture`.

use ff::{Field, PrimeField};
use nova_snark::frontend::{num::AllocatedNum, ConstraintSystem, Index, LinearCombination, SynthesisError, Variable};
use nova_snark::traits::circuit::StepCircuit;
use pca_folding_ivc::{hash2_native, ActionCircuit, ActionStep, Scalar, B_MAX, native_final_state, within_budget};
use std::collections::{BTreeMap, BTreeSet};

type Lc = LinearCombination<Scalar>;

#[derive(Clone)]
struct Mini {
    inputs: Vec<Scalar>,
    aux: Vec<Scalar>,
    names: Vec<String>,
    cons: Vec<(Lc, Lc, Lc, String)>,
    ns: Vec<String>,
}
impl Mini {
    fn new() -> Self {
        Mini { inputs: vec![Scalar::ONE], aux: vec![], names: vec![], cons: vec![], ns: vec![] }
    }
    fn path(&self, t: &str) -> String {
        if self.ns.is_empty() { t.to_string() } else { format!("{}/{}", self.ns.join("/"), t) }
    }
    fn val(&self, v: Variable) -> Scalar {
        match v.get_unchecked() {
            Index::Input(i) => self.inputs[i],
            Index::Aux(i) => self.aux[i],
        }
    }
    fn ev(&self, lc: &Lc) -> Scalar {
        lc.eval(&self.inputs, &self.aux)
    }
    fn is_violated(&self, j: usize) -> bool {
        let (a, b, c, _) = &self.cons[j];
        self.ev(a) * self.ev(b) != self.ev(c)
    }
    fn violated(&self) -> Vec<usize> {
        (0..self.cons.len()).filter(|&j| self.is_violated(j)).collect()
    }
    fn idx(&self, name: &str) -> usize {
        self.names.iter().position(|n| n == name).unwrap_or_else(|| panic!("no wire {name}"))
    }
}
impl ConstraintSystem<Scalar> for Mini {
    type Root = Self;
    fn alloc<F, A, AR>(&mut self, a: A, f: F) -> Result<Variable, SynthesisError>
    where F: FnOnce() -> Result<Scalar, SynthesisError>, A: FnOnce() -> AR, AR: Into<String> {
        let i = self.aux.len();
        let p = self.path(&a().into());
        self.aux.push(f()?);
        self.names.push(p);
        Ok(Variable::new_unchecked(Index::Aux(i)))
    }
    fn alloc_input<F, A, AR>(&mut self, a: A, f: F) -> Result<Variable, SynthesisError>
    where F: FnOnce() -> Result<Scalar, SynthesisError>, A: FnOnce() -> AR, AR: Into<String> {
        let i = self.inputs.len();
        let _ = a();
        self.inputs.push(f()?);
        Ok(Variable::new_unchecked(Index::Input(i)))
    }
    fn enforce<A, AR, LA, LB, LC>(&mut self, a: A, la: LA, lb: LB, lc: LC)
    where A: FnOnce() -> AR, AR: Into<String>,
          LA: FnOnce(Lc) -> Lc, LB: FnOnce(Lc) -> Lc, LC: FnOnce(Lc) -> Lc {
        let p = self.path(&a().into());
        self.cons.push((la(Lc::zero()), lb(Lc::zero()), lc(Lc::zero()), p));
    }
    fn push_namespace<NR, N>(&mut self, n: N) where NR: Into<String>, N: FnOnce() -> NR {
        self.ns.push(n().into());
    }
    fn pop_namespace(&mut self) {
        self.ns.pop();
    }
    fn get_root(&mut self) -> &mut Self::Root {
        self
    }
}

#[derive(Clone)]
struct Run {
    cs: Mini,
    zout: [Variable; 2],
    c_in: Scalar,
    b_in: Scalar,
}

/// Synthesize the REAL step circuit for the witness `(action_digest, cost)` from state `(c_in, b_in)`.
fn synth(a: Scalar, cost: Scalar, c_in: Scalar, b_in: Scalar) -> Run {
    let c = ActionCircuit::from_field_witness(a, cost);
    let mut cs = Mini::new();
    let z0 = AllocatedNum::alloc(cs.namespace(|| "z_in_0"), || Ok(c_in)).unwrap();
    let z1 = AllocatedNum::alloc(cs.namespace(|| "z_in_1"), || Ok(b_in)).unwrap();
    let out = c.synthesize(&mut cs, &[z0, z1]).unwrap();
    Run { zout: [out[0].get_variable(), out[1].get_variable()], cs, c_in, b_in }
}

fn small(x: &Scalar) -> Option<u128> {
    let r = x.to_repr();
    let b = r.as_ref();
    if b[16..].iter().any(|&y| y != 0) { None } else { Some(u128::from_le_bytes(b[..16].try_into().unwrap())) }
}
fn neg(k: u64) -> Scalar {
    -Scalar::from(k)
}

/// The intended relation, evaluated on whatever the (possibly edited) assignment says.
fn relation_holds(r: &Run) -> bool {
    let cost = r.cs.aux[r.cs.idx("cost/num")];
    let a = r.cs.aux[r.cs.idx("action_digest/num")];
    let (cout, bout) = (r.cs.val(r.zout[0]), r.cs.val(r.zout[1]));
    matches!(small(&cost), Some(c) if c < (1u128 << 32))
        && bout == r.b_in + cost
        && matches!(small(&bout), Some(b) if b <= B_MAX as u128)
        && cout == hash2_native(r.c_in, hash2_native(a, cost))
}

fn chain_start() -> Scalar {
    hash2_native(Scalar::from(11u64), Scalar::from(22u64))
}

// ------------------------------------------------------------------------------------------- 1

#[test]
fn honest_and_malicious_witnesses_agree_with_the_native_replay() {
    let mut seed = 0x1234_5678_9abc_def0u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let shape_ref = synth(Scalar::ONE, Scalar::ONE, chain_start(), Scalar::ZERO);
    let (mut n, mut sat_n, mut unsat_n) = (0usize, 0usize, 0usize);
    let mut cases: Vec<(u64, u64, u64)> = Vec::new(); // (action, cost, b_in)
    for _ in 0..1200 {
        let b_in = rnd() % (B_MAX + 1);
        cases.push((rnd(), rnd() % (B_MAX - b_in + 1), b_in)); // within budget
    }
    for _ in 0..600 {
        let b_in = rnd() % (B_MAX + 1);
        cases.push((rnd(), B_MAX - b_in + 1 + rnd() % 5_000_000, b_in)); // over budget
    }
    for d in 0..40u64 {
        cases.push((d, B_MAX, 0)); // exact boundary
        cases.push((d, 1, B_MAX)); // one over
        cases.push((d, 0, B_MAX)); // zero cost at the ceiling
        cases.push((d, 1u64 << 32, 0)); // out of the cost range
        cases.push((d, (1u64 << 32) - 1, 0));
        cases.push((d, u64::MAX - d, d));
    }
    for (a, cost, b_in) in cases {
        let run = synth(Scalar::from(a), Scalar::from(cost), chain_start(), Scalar::from(b_in));
        n += 1;
        // identical shape for every witness (a witness-dependent shape would be unsound for folding)
        assert_eq!(run.cs.cons.len(), shape_ref.cs.cons.len());
        assert_eq!(run.cs.names, shape_ref.cs.names);
        let sat = run.cs.violated().is_empty();
        // native replay of the same single step (the native code takes the cost as given)
        let history = [ActionStep { action_digest: a, cost }];
        let native_in_budget = (b_in as u128 + cost as u128) <= B_MAX as u128 && cost < (1u64 << 32);
        assert_eq!(sat, native_in_budget, "accept/reject differs from the native rule for a={a} cost={cost} b_in={b_in}");
        if b_in == 0 {
            assert_eq!(sat && cost <= B_MAX, within_budget(&history) && cost < (1 << 32), "within_budget vs circuit");
        }
        assert_eq!(relation_holds(&run), sat, "relation oracle vs satisfiability, a={a} cost={cost} b_in={b_in}");
        if sat {
            sat_n += 1;
            let (nc, nb) = {
                let mut chain = chain_start();
                chain = hash2_native(chain, hash2_native(Scalar::from(a), Scalar::from(cost)));
                (chain, Scalar::from(b_in) + Scalar::from(cost))
            };
            assert_eq!((run.cs.val(run.zout[0]), run.cs.val(run.zout[1])), (nc, nb), "outputs equal the native replay");
            let _ = native_final_state(&history);
        } else {
            unsat_n += 1;
        }
    }
    // field-negative costs (not expressible as a u64): all unsatisfiable, whatever the incoming budget
    for k in [1u64, 2, 5, 1000, 1 << 32, B_MAX, 1 << 50] {
        for b_in in [0u64, 1, 5, 1_000, B_MAX - 1, B_MAX] {
            let run = synth(Scalar::from(3u64), neg(k), chain_start(), Scalar::from(b_in));
            n += 1;
            assert!(!run.cs.violated().is_empty(), "field-negative cost -{k} with b_in={b_in} was satisfiable");
            unsat_n += 1;
        }
    }
    eprintln!("{n} single-step cases (satisfiable {sat_n}, unsatisfiable {unsat_n}); every verdict equals the native rule");
    assert!(n >= 2000 && sat_n > 500 && unsat_n > 500);
}

#[test]
fn multi_step_history_outputs_equal_the_native_replay() {
    let mut chain = Scalar::ZERO;
    let mut budget = Scalar::ZERO;
    let hist: Vec<ActionStep> = (0..30u64).map(|i| ActionStep { action_digest: 0xAB00 + i * 7, cost: 33_000 + i }).collect();
    assert!(within_budget(&hist));
    for a in &hist {
        let run = synth(Scalar::from(a.action_digest), Scalar::from(a.cost), chain, budget);
        assert!(run.cs.violated().is_empty());
        chain = run.cs.val(run.zout[0]);
        budget = run.cs.val(run.zout[1]);
    }
    assert_eq!((chain, budget), native_final_state(&hist));
}

// ------------------------------------------------------------------------------------------- 2

#[test]
fn no_free_wires() {
    let bases = [
        (7u64, 5u64, 10u64),
        (0, 0, 0),
        (u64::MAX, B_MAX, 0),
        (9, 1, B_MAX - 1),
        (12345, 999_999, 1),
    ];
    let mut checked = 0usize;
    for (a, cost, b_in) in bases {
        let run = synth(Scalar::from(a), Scalar::from(cost), chain_start(), Scalar::from(b_in));
        assert!(run.cs.violated().is_empty());
        for j in 2..run.cs.aux.len() {
            // wires 0 and 1 are the incoming state (public)
            let v = run.cs.aux[j];
            for p in [v + Scalar::ONE, v - Scalar::ONE, Scalar::ZERO, Scalar::ONE, -v, v.double(), v + Scalar::from(1u64 << 40)] {
                if p == v {
                    continue;
                }
                let mut m = run.clone();
                m.cs.aux[j] = p;
                assert!(!m.cs.violated().is_empty(), "wire {} is free: changing it to another value violates nothing", run.cs.names[j]);
                checked += 1;
            }
        }
    }
    eprintln!("no_free_wires: {checked} single-wire edits, each violates at least one constraint");
}

// ------------------------------------------------------------------------------------------- 3

fn highest_aux(cs: &Mini, j: usize, fixed: &BTreeSet<usize>) -> Option<usize> {
    let (a, b, c, _) = &cs.cons[j];
    [a, b, c]
        .iter()
        .flat_map(|lc| lc.iter().filter_map(|(v, _)| match v.get_unchecked() { Index::Aux(i) => Some(i), _ => None }))
        .filter(|i| !fixed.contains(i))
        .max()
}
fn coeff_of(lc: &Lc, w: usize) -> Scalar {
    lc.iter().filter(|(v, _)| v.get_unchecked() == Index::Aux(w)).fold(Scalar::ZERO, |s, (_, c)| s + *c)
}

/// Re-solve constraint `j` for its highest unfixed wire when the constraint is linear in that wire.
fn solve(cs: &mut Mini, j: usize, fixed: &BTreeSet<usize>) -> bool {
    let Some(w) = highest_aux(cs, j, fixed) else { return false };
    let (a, b, c, _) = cs.cons[j].clone();
    let (ca, cb, cc) = (coeff_of(&a, w), coeff_of(&b, w), coeff_of(&c, w));
    let (ea, eb, ec) = (cs.ev(&a), cs.ev(&b), cs.ev(&c));
    let cur = cs.aux[w];
    let new = if ca == Scalar::ZERO && cb == Scalar::ZERO && cc != Scalar::ZERO {
        (ea * eb - (ec - cc * cur)) * cc.invert().unwrap()
    } else if ca != Scalar::ZERO && cb == Scalar::ZERO && cc == Scalar::ZERO && eb != Scalar::ZERO {
        (ec * eb.invert().unwrap() - (ea - ca * cur)) * ca.invert().unwrap()
    } else if cb != Scalar::ZERO && ca == Scalar::ZERO && cc == Scalar::ZERO && ea != Scalar::ZERO {
        (ec * ea.invert().unwrap() - (eb - cb * cur)) * cb.invert().unwrap()
    } else {
        return false;
    };
    cs.aux[w] = new;
    true
}

fn bits_of(cs: &Mini, gadget: &str) -> Vec<usize> {
    let mut v = Vec::new();
    let mut i = 0;
    while let Some(p) = cs.names.iter().position(|n| n == &format!("{gadget}/bit {i}/boolean")) {
        v.push(p);
        i += 1;
    }
    v
}

/// Rebuild the bit wires of a range gadget from the current value of its target when that value fits.
fn rebuild_bits(cs: &mut Mini, gadget: &str, target: Scalar) -> bool {
    let bits = bits_of(cs, gadget);
    match small(&target) {
        Some(x) if x < (1u128 << bits.len()) => {
            for (i, &p) in bits.iter().enumerate() {
                cs.aux[p] = Scalar::from(((x >> i) & 1) as u64);
            }
            true
        }
        _ => false,
    }
}

/// Forward-propagate an edit: repeatedly re-solve violated constraints (other than `dropped`) for the
/// wire each one defines; range gadgets are rebuilt from their target value.
fn repair(cs: &mut Mini, dropped: usize, fixed: &BTreeSet<usize>) {
    for _ in 0..6 {
        let mut changed = false;
        for j in 0..cs.cons.len() {
            if j == dropped || !cs.is_violated(j) {
                continue;
            }
            let name = cs.cons[j].3.clone();
            if let Some(g) = name.strip_suffix("/bit decomposition") {
                let c = cs.cons[j].2.clone();
                let target = cs.ev(&c);
                if rebuild_bits(cs, g, target) {
                    changed = true;
                }
            } else if name.ends_with("/boolean constraint") {
                continue;
            } else if solve(cs, j, fixed) {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

struct Base {
    name: &'static str,
    run: Run,
}
fn bases() -> Vec<Base> {
    let c = chain_start();
    let mk = |name, a: u64, cost: Scalar, b: u64| Base { name, run: synth(Scalar::from(a), cost, c, Scalar::from(b)) };
    vec![
        mk("honest", 7, Scalar::from(5u64), 10),
        mk("over_budget_by_5", 7, Scalar::from(5u64), B_MAX),
        mk("over_budget_big", 7, Scalar::from(4_000_000u64), 3),
        mk("field_negative_cost", 7, neg(1), 5),
        mk("field_negative_cost_to_zero", 7, neg(10), 10),
        mk("field_negative_big", 7, neg(B_MAX), 3),
        mk("cost_2_32", 7, Scalar::from(1u64 << 32), 0),
        mk("cost_2_40", 7, Scalar::from(1u64 << 40), 0),
        mk("at_ceiling", 7, Scalar::from(5u64), B_MAX - 5),
    ]
}

#[derive(Default)]
struct Kill {
    by: Vec<String>,
}

fn family(name: &str) -> String {
    if name.starts_with("chain_hash") || name.starts_with("leaf_commit") { "chain_hash (Poseidon)".into() }
    else if name.ends_with("/boolean constraint") { format!("{} booleanity", name.split('/').next().unwrap()) }
    else if name.ends_with("bit decomposition") { format!("{} decomposition", name.split('/').next().unwrap()) }
    else { name.to_string() }
}

#[test]
fn constraint_ablation() {
    let bases = bases();
    let n_cons = bases[0].run.cs.cons.len();
    assert_eq!(n_cons, 593, "circuit shape changed: re-audit");
    let fixed: BTreeSet<usize> = [0usize, 1].into_iter().collect(); // incoming state is public
    let mut kills: Vec<Kill> = (0..n_cons).map(|_| Kill::default()).collect();
    let record = |kills: &mut Vec<Kill>, run: &Run, label: String| {
        let v = run.cs.violated();
        if v.len() == 1 && !relation_holds(run) {
            kills[v[0]].by.push(label);
        }
    };

    for b in &bases {
        // (a) the natural prover on a malicious input: violates only the constraints that actually reject it
        record(&mut kills, &b.run, format!("{}: natural", b.name));
        // (b) absorb the discrepancy of one range gadget into one bit (breaks that bit's booleanity only)
        for (gadget, target) in [("cost_range", "cost/num"), ("budget_range", "budget_add/sum num"), ("headroom_range", "headroom/num")] {
            let tgt = b.run.cs.aux[b.run.cs.idx(target)];
            let bits = bits_of(&b.run.cs, gadget);
            for k in 0..bits.len() {
                let mut r = b.run.clone();
                let others = bits.iter().enumerate().filter(|(i, _)| *i != k).fold(Scalar::ZERO, |s, (i, &p)| s + r.cs.aux[p] * Scalar::from(2u64).pow_vartime([i as u64]));
                r.cs.aux[bits[k]] = (tgt - others) * Scalar::from(2u64).pow_vartime([k as u64]).invert().unwrap();
                record(&mut kills, &r, format!("{}: absorb {gadget} bit {k}", b.name));
            }
        }
        // (c) free one wire and recompute everything downstream honestly
        for i in 0..n_cons {
            let Some(u) = highest_aux(&b.run.cs, i, &fixed) else { continue };
            let cur = b.run.cs.aux[u];
            for (tag, nv) in [("+1", cur + Scalar::ONE), ("-1", cur - Scalar::ONE), ("=0", Scalar::ZERO), ("=7", Scalar::from(7u64)), ("x2", cur.double())] {
                if nv == cur {
                    continue;
                }
                let mut r = b.run.clone();
                r.cs.aux[u] = nv;
                repair(&mut r.cs, i, &fixed);
                let v = r.cs.violated();
                if v.iter().all(|&j| j == i) && !v.is_empty() && !relation_holds(&r) {
                    kills[i].by.push(format!("{}: free wire {} {tag}", b.name, b.run.cs.names[u]));
                }
            }
        }
    }

    // classification
    let names: Vec<String> = bases[0].run.cs.cons.iter().map(|c| c.3.clone()).collect();
    let mut by_family: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    let mut survivors: Vec<usize> = Vec::new();
    for (i, k) in kills.iter().enumerate() {
        let e = by_family.entry(family(&names[i])).or_default();
        e.0 += 1;
        if k.by.is_empty() {
            survivors.push(i);
        } else {
            e.1 += 1;
        }
    }
    for (f, (total, killed)) in &by_family {
        eprintln!("{f:34} constraints {total:3}  killed {killed:3}");
    }
    let surv_fams: BTreeSet<String> = survivors.iter().map(|&i| family(&names[i])).collect();
    eprintln!("survivors: {} constraints in families {surv_fams:?}", survivors.len());
    // every non-survivor documents at least one concrete killing assignment
    for (i, k) in kills.iter().enumerate() {
        if !k.by.is_empty() && i % 40 == 0 {
            eprintln!("  e.g. constraint {i} ({}) killed by: {}", names[i], k.by[0]);
        }
    }

    // The only expected survivors: the range gadget on `budget_out` (redundant: b_in <= B_MAX and
    // cost < 2^32 already bound budget_out < 2^33, and the headroom gadget bounds it again).
    let expected: BTreeSet<String> = ["budget_range booleanity", "budget_range decomposition"].iter().map(|s| s.to_string()).collect();
    assert_eq!(surv_fams, expected, "unexpected surviving mutants (possible under-constrained circuit): {:?}", survivors.iter().map(|&i| names[i].clone()).collect::<Vec<_>>());
    assert_eq!(survivors.len(), 41, "all of budget_range, and nothing else");

    // Group-drop equivalence for the surviving gadget: on a large corpus of natural provers the mutant
    // (budget_range removed) accepts exactly when the real circuit does.
    let drop: BTreeSet<usize> = survivors.iter().copied().collect();
    let mut seed = 0xfeed_beef_u64;
    let mut rnd = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut n = 0usize;
    for t in 0..3000 {
        let b_in = match t % 4 { 0 => rnd() % (B_MAX + 1), 1 => B_MAX, 2 => B_MAX - rnd() % 10, _ => rnd() % 3 };
        let cost = match t % 5 {
            0 => Scalar::from(rnd() % 2_000_000),
            1 => Scalar::from(rnd()),
            2 => neg(rnd() % (1 << 33)),
            3 => Scalar::from((1u64 << 32) + rnd() % 4),
            _ => Scalar::from(B_MAX - b_in + (rnd() % 3)),
        };
        let run = synth(Scalar::from(rnd()), cost, chain_start(), Scalar::from(b_in));
        let real = run.cs.violated().is_empty();
        let mutant = run.cs.violated().iter().all(|j| drop.contains(j));
        assert_eq!(real, mutant, "budget_range is not redundant: b_in={b_in} cost={cost:?}");
        n += 1;
    }
    eprintln!("budget_range group-drop equivalence: {n} natural-prover witnesses agree");
}

// ------------------------------------------------------------------------------------------- Nova level

#[test]
fn nova_rejects_witnesses_that_only_the_range_gadgets_stop() {
    // The field-negative cost is the witness that only `cost_range` rejects (the running total stays in
    // range): at the Nova level the prover must fail too, not just the bare R1CS.
    use pca_folding_ivc::{initial_state, public_params, Recursive};
    let honest = |a: u64, c: u64| ActionCircuit::from_field_witness(Scalar::from(a), Scalar::from(c));
    let pp = public_params(&honest(1, 1)).expect("public params");
    let z0 = initial_state();
    let attempts: Vec<(&str, Vec<ActionCircuit<Scalar>>)> = vec![
        ("control: two honest steps", vec![honest(1, 5), honest(2, 5)]),
        ("field-negative cost after an honest step", vec![honest(1, 5), ActionCircuit::from_field_witness(Scalar::from(2u64), neg(1))]),
        ("field-negative cost that cancels the budget to zero", vec![honest(1, 5), ActionCircuit::from_field_witness(Scalar::from(2u64), neg(5))]),
        ("cost 2^32", vec![honest(1, 5), honest(2, 1 << 32)]),
        ("one over the ceiling", vec![honest(1, B_MAX), honest(2, 1)]),
    ];
    for (name, steps) in attempts {
        let r: Result<(), String> = (|| {
            let mut rs = Recursive::new(&pp, &steps[0], &z0).map_err(|e| e.to_string())?;
            for c in &steps {
                rs.prove_step(&pp, c).map_err(|e| e.to_string())?;
            }
            rs.verify(&pp, steps.len(), &z0).map(|_| ()).map_err(|e| e.to_string())
        })();
        eprintln!("{name}: {r:?}");
        if name.starts_with("control") {
            assert!(r.is_ok(), "{name}");
        } else {
            assert!(r.is_err(), "{name}: a malicious witness folded and verified");
        }
    }
}

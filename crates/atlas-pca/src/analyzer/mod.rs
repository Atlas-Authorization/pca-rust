//! Static analyzability of authority (`@atlasauth/pca-analyzer`): the bounded decision engine, reachability / subsumption / equivalence /
//! intent conformance, quantitative exposure, residual policies and what-may-I-do, SQL and UCAST filters, narrowing, coverage,
//! minimal-flip counterfactuals, schema validation and the policy test runner.
//!
//! Policies and results are plain JSON trees (`serde_json::Value`): a policy is a bare `{predicates, caveats?, vetoes?, tighten?, meet?}`
//! object. Every function returns `Err(message)` where the reference throws. Optional arguments are `&Value`: pass [`NONE`]
//! (`Value::Null`) for an omitted one. A number that is not finite is written `{"$num": "Infinity" | "-Infinity" | "NaN"}` in a result and
//! read back from the same encoding in an argument. JavaScript semantics (binary64 numbers, `Math.min` / `Math.max` NaN propagation,
//! string-vs-number comparison, UTF-16 string order) are followed throughout; `re:` resource matchers use the crate's linear-time matcher.
//!
//! The decision engine enumerates a finite distinguishing grid of representative actions and evaluates the crate's real predicate
//! evaluator at each, so a verdict is exact over the decided fragment and fails safe (`approximate`) outside it.

mod caveats;
mod coverage;
mod dag;
mod enumerate;
mod exposure;
mod field;
mod filter;
mod flip;
mod js;
mod narrowing;
mod query;
mod residual;
mod testrunner;
mod validate;

pub use enumerate::{Asg, ProbeField, Probes, Rep};
pub use field::{Iv, FULL_INTERVAL};

use crate::agent::KeyPair;
use js::{try_js, undef_v};
use serde_json::Value;

/// An omitted optional argument.
pub const NONE: Value = Value::Null;

/// The JavaScript `undefined` marker (only for callers that must tell an omitted member from `null`).
pub fn undefined() -> Value {
    undef_v()
}

type R<T> = Result<T, String>;

// ---- pure engine pieces -----------------------------------------------------------------------------------------------------

/// `{sat, reason?, revCap?}`: the static satisfiability of an envelope caveat set.
pub fn analyze_caveats(caveats: &Value) -> R<Value> {
    try_js(|| caveats::analyze_caveats(caveats))
}

/// Is the numeric part of a field's `where` conjunction satisfiable?
pub fn numeric_conjunction_satisfiable(conditions: &Value) -> R<bool> {
    try_js(|| field::numeric_conjunction_satisfiable(conditions))
}

/// `numeric_conjunction_satisfiable` of a predicate's `where` (anything but a list is satisfiable).
pub fn predicate_numeric_satisfiable(where_: &Value) -> R<bool> {
    try_js(|| field::predicate_numeric_satisfiable(where_))
}

/// Tightens an interval by one numeric condition (a non-numeric operand returns it as is).
pub fn tighten_interval(iv: Iv, op: &Value, value: &Value) -> Iv {
    field::tighten(iv, op, value)
}

pub fn interval_empty(iv: Iv) -> bool {
    field::interval_empty(iv)
}

/// The representative probe values of one field from the conjunction of `where` conditions on it.
pub fn field_probes(conditions: &Value) -> R<Value> {
    try_js(|| Value::Array(field::field_probes(conditions)))
}

/// Maps a constitution's stateless invariants to analyzer vetoes: `{vetoes, unmodeled}`.
pub fn vetoes_from_constitution(constitution: &Value) -> R<Value> {
    try_js(|| caveats::vetoes_from_constitution(constitution))
}

/// The analyzable model of a policy.
pub fn to_model(policy: &Value) -> R<Value> {
    try_js(|| enumerate::to_model(policy))
}

/// The grid dimensions of `{predicateSets, extraVerbs?, extraResources?, extraFieldConditions?, varyReversibility?}`.
pub fn collect_probes(inputs: &Value) -> R<Probes> {
    try_js(|| enumerate::collect_probes(inputs))
}

/// Every grid point of `inputs` as `[{verb, resource, revClass?, assignments, action}]`; refused when the grid is larger than `max_grid`.
pub fn representatives(inputs: &Value, max_grid: f64) -> R<Value> {
    try_js(|| {
        let pr = enumerate::collect_probes(inputs);
        if pr.product_size() > max_grid {
            js::fail("grid too large");
        }
        let mut out: Vec<Value> = vec![];
        enumerate::each_rep(&pr, &mut |r: &Rep| {
            let mut m = js::u_map(vec![
                ("verb", r.verb.clone()),
                ("resource", r.resource.clone()),
                ("assignments", r.asg.to_json()),
                ("action", enumerate::rep_to_action(r)),
            ]);
            if !r.rev_class.is_null() {
                m.insert("revClass".into(), r.rev_class.clone());
            }
            out.push(Value::Object(m));
            false
        });
        Value::Array(out)
    })
}

/// The ternary decision `allow` | `escalate` | `deny` of a fully-specified action under a policy.
pub fn decide_action(policy: &Value, action: &Value) -> R<String> {
    try_js(|| enumerate::decide_action(&enumerate::to_model(policy), action).to_string())
}

/// The same under an already-built model.
pub fn decide_action_model(model: &Value, action: &Value) -> R<String> {
    try_js(|| enumerate::decide_action(model, action).to_string())
}

/// The exact admission of a fully-specified action (no existential search).
pub fn admits_concrete(policy: &Value, action: &Value) -> R<bool> {
    try_js(|| query::admits_concrete(policy, action))
}

/// Does a veto apply at this context (`{action, subject, env}`)? Whatever cannot be decided counts as applying.
pub fn veto_applies(veto: &Value, ctx: &Value) -> R<bool> {
    try_js(|| enumerate::veto_applies(veto, ctx))
}

/// Every numeric literal the policy compares `path` against, ascending and de-duplicated.
pub fn thresholds_of(policy: &Value, path: &str) -> R<Value> {
    try_js(|| Value::Array(exposure::thresholds_of(&enumerate::to_model(policy), path)))
}

/// The digest of a policy's analyzable model.
pub fn policy_digest(policy: &Value) -> R<String> {
    try_js(|| residual::policy_digest_of(&enumerate::to_model(policy)))
}

// ---- relational queries -----------------------------------------------------------------------------------------------------

/// Can any input complete `action` into one the policy admits?
pub fn reachable(policy: &Value, action: &Value, opts: &Value) -> R<Value> {
    try_js(|| query::reachable(policy, action, opts))
}

/// Does the policy deny everything (optionally restricted to `verb`)?
pub fn always_denies(policy: &Value, verb: &Value, opts: &Value) -> R<Value> {
    try_js(|| query::always_denies(policy, verb, opts))
}

/// Does the policy admit EVERY action of `verb`?
pub fn always_allows(policy: &Value, verb: &Value, opts: &Value) -> R<Value> {
    try_js(|| query::always_allows(policy, verb, opts))
}

/// Does `a` permit everything `b` permits?
pub fn subsumes(a: &Value, b: &Value, opts: &Value) -> R<Value> {
    try_js(|| query::subsumes(a, b, opts))
}

/// Is there no action both policies admit?
pub fn disjoint(a: &Value, b: &Value, opts: &Value) -> R<Value> {
    try_js(|| query::disjoint(a, b, opts))
}

/// Do the policies admit exactly the same actions?
pub fn equivalent(a: &Value, b: &Value, opts: &Value) -> R<Value> {
    try_js(|| query::equivalent(a, b, opts))
}

/// Does the policy admit ONLY actions inside the declared intent envelope?
pub fn intent_conformance(policy: &Value, intent: &Value, opts: &Value) -> R<Value> {
    try_js(|| query::intent_conformance(policy, intent, opts))
}

// ---- exposure ---------------------------------------------------------------------------------------------------------------

/// The most that can ever leave under a policy.
pub fn max_exposure(policy: &Value, opts: &Value) -> R<Value> {
    try_js(|| exposure::max_exposure(policy, opts))
}

/// The set of actions admitted only with a human.
pub fn escalation_surface(policy: &Value, opts: &Value) -> R<Value> {
    try_js(|| exposure::escalation_surface(policy, opts))
}

/// The join of everything any holder of the leaf could do, with the remaining delegation depth.
pub fn delegation_envelope(chain: &Value, opts: &Value) -> R<Value> {
    try_js(|| exposure::delegation_envelope(chain, opts))
}

/// Which actions move between allow / escalate / deny between two policies, with witnesses.
pub fn diff_policies(a: &Value, b: &Value, opts: &Value) -> R<Value> {
    try_js(|| exposure::diff_policies(a, b, opts))
}

/// A CI gate over a diff.
pub fn diff_gate(diff: &Value, allow: &Value) -> R<Value> {
    try_js(|| exposure::diff_gate(diff, allow))
}

/// Checks what an external solver returned for `query`: a witness is re-checked by the real evaluator (never trusted); an unsat claim
/// is labelled as solver-claimed. `result` is the backend's `{witness?, unsat?}`.
pub fn find_with_backend(query: &Value, backend_name: &Value, result: &Value) -> R<Value> {
    try_js(|| exposure::find_with_backend(query, backend_name, result))
}

/// Static exposure of a workflow body (steps, dependency DAG, edges, budget).
pub fn dag_exposure(body: &Value) -> R<Value> {
    try_js(|| dag::dag_exposure(body))
}

// ---- residual, filters ------------------------------------------------------------------------------------------------------

/// Specialises `policy` to `known`; everything under `opts.unknown` stays symbolic.
pub fn residual(policy: &Value, known: &Value, opts: &Value) -> R<Value> {
    try_js(|| residual::residual(policy, known, opts))
}

/// The residual as a policy the analyzer and the real evaluator both understand.
pub fn residual_policy(residual: &Value) -> R<Value> {
    try_js(|| residual::residual_policy(residual))
}

/// The ternary decision of a residual once the unknown fields are bound (`ctx` is `{action, subject, env}`).
pub fn evaluate_residual(residual: &Value, ctx: &Value) -> R<String> {
    try_js(|| residual::evaluate_residual(residual, ctx).to_string())
}

/// Per verb shape, what the known principal may do.
pub fn what_may_i_do(policy: &Value, verbs: &Value, known: &Value, opts: &Value) -> R<Value> {
    try_js(|| residual::what_may_i_do(policy, verbs, known, opts))
}

/// Compiles a residual to a parameterized SQL filter and a UCAST tree, or `{ok: false, reason}` when it cannot be done exactly.
pub fn residual_to_filter(residual: &Value, filter_opts: &Value) -> R<Value> {
    try_js(|| filter::to_filter(residual, filter_opts))
}

/// `residual_to_filter(residual(policy, known, residual_opts), filter_opts)`.
pub fn to_filter(policy: &Value, known: &Value, residual_opts: &Value, filter_opts: &Value) -> R<Value> {
    try_js(|| filter::to_filter(&residual::residual(policy, known, residual_opts), filter_opts))
}

/// Evaluates a filter expression over one row with SQL's three-valued logic: true, false or null.
pub fn eval_filter(expr: &Value, row: &Value) -> R<Value> {
    try_js(|| filter::eval_filter(expr, row))
}

/// The filter as a UCAST tree.
pub fn to_ucast(expr: &Value) -> R<Value> {
    try_js(|| filter::to_ucast(expr))
}

/// Evaluates a UCAST tree over one row (two-valued).
pub fn eval_ucast(ucast: &Value, row: &Value) -> R<bool> {
    try_js(|| filter::eval_ucast(ucast, row))
}

// ---- narrowing, coverage, counterfactuals -----------------------------------------------------------------------------------

/// Proposes a narrower replacement for `policy` from ledger-sourced `observed` actions, plus findings and access requests.
pub fn suggest_narrowing(policy: &Value, observed: &Value, opts: &Value) -> R<Value> {
    try_js(|| narrowing::suggest_narrowing(policy, observed, opts))
}

/// The holder's signed ask: `{request, signer, sig}`.
pub fn sign_access_request(request: &Value, key: &KeyPair) -> R<Value> {
    try_js(|| narrowing::sign_access_request(request, key))
}

/// Verifies a signed access request, optionally against an expected signer public key (`NONE` for any); any failure is `false`.
pub fn verify_access_request(signed: &Value, expected_signer: &Value) -> bool {
    narrowing::verify_access_request(signed, expected_signer)
}

/// The decision with the clause that decided it (`model` as [`to_model`] builds it).
pub fn witness_of(model: &Value, action: &Value) -> R<Value> {
    try_js(|| coverage::witness_of(model, action))
}

/// Coverage of `policy` by `traffic`: clauses, boundaries, mutants and the 0..1 scores.
pub fn coverage(policy: &Value, traffic: &Value, opts: &Value) -> R<Value> {
    try_js(|| coverage::coverage(policy, traffic, opts))
}

/// A CI gate over a coverage report.
pub fn coverage_gate(report: &Value, minimum: &Value) -> R<Value> {
    try_js(|| coverage::coverage_gate(report, minimum))
}

/// The smallest verified change that gets `action` to the wanted decision.
pub fn minimal_flip(policy: &Value, action: &Value, opts: &Value) -> R<Value> {
    try_js(|| flip::minimal_flip(policy, action, opts))
}

// ---- schema validation, policy tests ----------------------------------------------------------------------------------------

pub fn verb_shapes_from_action_defs(defs: &Value) -> R<Value> {
    try_js(|| validate::verb_shapes_from_action_defs(defs))
}

/// The verbs and parameters of a signed action schema, a list of shapes, or a list of action definitions.
pub fn verb_shapes(src: &Value) -> R<Value> {
    try_js(|| validate::verb_shapes(src))
}

/// Lints a policy against the schema it is written for: `{ok, findings}`.
pub fn validate_policy_against_schema(policy: &Value, src: &Value, opts: &Value) -> R<Value> {
    try_js(|| validate::validate_policy_against_schema(policy, src, opts))
}

/// Alias of [`validate_policy_against_schema`].
pub fn validate_policy(policy: &Value, src: &Value, opts: &Value) -> R<Value> {
    validate_policy_against_schema(policy, src, opts)
}

pub fn policy_tests_doc(policy: &Value, cases: &Value) -> R<Value> {
    try_js(|| testrunner::policy_tests_doc(policy, cases))
}

/// Runs a test document against a policy: `{total, passed, failures, digestMatch, ok}`.
pub fn run_policy_tests(policy: &Value, doc: &Value, opts: &Value) -> R<Value> {
    try_js(|| testrunner::run_policy_tests(policy, doc, opts))
}

/// Boundary examples for every clause and numeric threshold.
pub fn generate_boundary_tests(policy: &Value, opts: &Value) -> R<Value> {
    try_js(|| testrunner::generate_boundary_tests(policy, opts))
}

/// The decision of every case of a test document under `policy`.
pub fn decide_all(policy: &Value, doc: &Value) -> R<Value> {
    try_js(|| testrunner::decide_all(policy, doc))
}

/// The principal signs the confirmed examples: `{doc, signer, sig}`.
pub fn sign_policy_tests(doc: &Value, key: &KeyPair) -> R<Value> {
    try_js(|| testrunner::sign_policy_tests(doc, key))
}

/// Verifies a signed test document against the expected signer; any failure is `false`.
pub fn verify_policy_tests(signed: &Value, expected_signer: &Value) -> bool {
    testrunner::verify_policy_tests(signed, expected_signer)
}

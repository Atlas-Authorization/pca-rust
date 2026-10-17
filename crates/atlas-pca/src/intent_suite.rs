//! The suite-agile signature seam of the Intent Layer v2 artifacts (session roots, action schemas, reservation
//! receipts, sequencer key sets, revocation epochs): `pq.ts` `verifyPinnedSuite` and `bindSuiteFields`, routed through
//! this crate's ONE suite dispatch (`resolve_sig_alg` / `verify_suite`). An `alg` the dispatch refuses (unknown, or a
//! registered suite this build does not implement) fails closed with the reason `unsupported_suite`; no suite list
//! lives here.

use serde_json::{Map, Value};

use super::{pinned, resolve_sig_alg, verify_suite};

/// The fail-closed reason of a suite the dispatch does not implement.
pub(crate) const UNSUPPORTED_SUITE: &str = "unsupported_suite";

/// What the v2 artifacts need to know about a resolved suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Suite {
    /// The canonical suite name (what `bindSuiteFields` binds).
    pub alg: &'static str,
    /// The suite carries a PQ key (`pq_pk`): every non-classical suite. A classical suite binds nothing.
    pub needs_pq_pk: bool,
}

/// The suite the dispatch resolves for `alg` (absent = the default suite). A non-string `alg` is malformed; a string the
/// dispatch refuses is `Err("unsupported_suite: ...")` (`suiteCapabilityError`).
pub(crate) fn suite_of(alg: Option<&Value>) -> Result<Suite, String> {
    if alg.is_some_and(|a| !a.is_string()) {
        return Err("alg must be a string".into()); // malformed (null included), not a suite question
    }
    match resolve_sig_alg(alg) {
        Some(x) => Ok(Suite { alg: x.alg, needs_pq_pk: x.needs_pq_pk }),
        None => Err(format!("{UNSUPPORTED_SUITE}: alg {} is not a suite this verifier implements", alg.map_or_else(|| "undefined".into(), Value::to_string))),
    }
}

/// `verifyPinnedSuite(alg, identity, artifactPqPk, msg, {sig, pq_sig}, {pqPins: pin})`: the suite's signature over
/// `msg` under `identity`; a PQ / hybrid suite needs the PQ key PINNED for `identity` (`pin = (identity, pq_pk)`) and
/// byte-equal to the artifact's own `pq_pk` (`resolvePqVerifyKey`). `Err(unsupported_suite)` when the dispatch refuses
/// the suite; `Ok(false)` on any other failure.
pub(crate) fn verify_pinned_suite(
    alg: Option<&Value>,
    identity: &str,
    artifact_pq: Option<&Value>,
    msg: &[u8],
    sig: Option<&Value>,
    pq_sig: Option<&Value>,
    pin: Option<(&str, &Value)>,
) -> Result<bool, String> {
    let suite = suite_of(alg)?;
    let alg_v = Value::String(suite.alg.into());
    if !suite.needs_pq_pk {
        return Ok(verify_suite(Some(&alg_v), identity, None, msg, sig, pq_sig));
    }
    let artifact = match artifact_pq {
        Some(Value::String(p)) if !p.is_empty() => p.as_str(),
        _ => return Ok(false),
    };
    match pin {
        Some((who, Value::String(p))) if who == identity && p == artifact => {}
        _ => return Ok(false),
    }
    let key = match pinned::PinnedPq::caller_vouched(artifact) {
        Some(k) => k,
        None => return Ok(false),
    };
    Ok(verify_suite(Some(&alg_v), identity, Some(&key), msg, sig, pq_sig))
}

/// `bindSuiteFields(base, alg, pq_pk)`: for a PQ / hybrid suite add `alg` and `pq_pk` (an absent `pq_pk` is an
/// `undefined` member the strict canonical encoder refuses: `Ok(false)`); a classical suite binds nothing.
pub(crate) fn bind_suite_fields(base: &mut Map<String, Value>, alg: Option<&Value>, pq_pk: Option<&Value>) -> Result<bool, String> {
    let suite = suite_of(alg)?;
    if !suite.needs_pq_pk {
        return Ok(true);
    }
    base.insert("alg".into(), Value::String(suite.alg.into()));
    match pq_pk {
        Some(p) => {
            base.insert("pq_pk".into(), p.clone());
            Ok(true)
        }
        None => Ok(false),
    }
}

/// The shape rule every v2 artifact shares: a resolvable suite, and a classical suite carries no `pq_pk` / `pq_sig`.
pub(crate) fn suite_shape_error(o: &Map<String, Value>, what: &str) -> Option<String> {
    match suite_of(o.get("alg")) {
        Err(e) => Some(e),
        Ok(x) if !x.needs_pq_pk && (o.get("pq_pk").is_some() || o.get("pq_sig").is_some()) => {
            Some(format!("a classical-suite {what} must not carry pq_pk / pq_sig"))
        }
        Ok(_) => (!o.get("sig").is_some_and(Value::is_string)).then(|| format!("{what} sig must be a string")),
    }
}

/// An OPTIONAL `alg` member (a principal, a holder root, a key-set entry): absent, or a suite the dispatch resolves.
pub(crate) fn optional_alg_error(v: Option<&Value>) -> Option<String> {
    v.and_then(|a| suite_of(Some(a)).err())
}

/// utf8(domain) || strictCanonical(body); `None` where the reference throws.
pub(crate) fn domain_message(domain: &str, body: Map<String, Value>) -> Option<Vec<u8>> {
    let c = super::canonicalize_strict(&Value::Object(body)).ok()?;
    let mut m = domain.as_bytes().to_vec();
    m.extend_from_slice(c.as_bytes());
    Some(m)
}

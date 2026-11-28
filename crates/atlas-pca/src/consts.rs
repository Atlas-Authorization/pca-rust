//! The public constants and small pure helpers of the reference that have no module of their own here, each with the TypeScript file it
//! mirrors. Values are the reference's; nothing here is a tunable.
use crate::authorize::CheckStatus;
use std::collections::BTreeMap;

// ---- pca-need.ts (the `pca_need` challenge of the A2A / HTTP extensions) -----------------------------------------------------------------
pub const PCA_NEED_PARAM: &str = "pca_need";
/// Domain of the need digest (`crate::a2a::need_digest`).
pub const PCA_NEED_DOMAIN: &str = "atlas-pca/need/v1";
/// Longest encoded need accepted: a header value past this is refused, never truncated.
pub const PCA_NEED_MAX_ENCODED: usize = 2048;

// ---- pca-grant-details.ts -------------------------------------------------------------------------------------------------------------
/// Most `authorization_details` entries of type `pca_grant` in one request.
pub const PCA_GRANT_MAX_DETAILS: usize = 16;
/// Longest chain a `pca_grant` detail names.
pub const PCA_GRANT_MAX_CHAIN_LEN: usize = 16;

// ---- pcactn.ts / replay.ts -------------------------------------------------------------------------------------------------------------
/// The PCActn wire version.
pub const PCACTN_VERSION: u8 = 2;
/// Longest `exp - iat` a verifier accepts (1 hour).
pub const PCACTN_MAX_LIFETIME_MS: i64 = crate::MAX_LIFETIME_MS;
/// How far in the future `iat` may be (clock skew allowance, 60 s).
pub const PCACTN_MAX_SKEW_MS: i64 = crate::MAX_SKEW_MS;
/// The lifetime the agent client stamps (20 minutes: it covers the 15-minute principal step-up window).
pub const PCACTN_DEFAULT_TTL_MS: i64 = 20 * 60_000;
/// Default freshness epoch granularity.
pub const DEFAULT_FRESHNESS_EPOCH_MS: i64 = 60_000;
/// Longest component (audience, grant id, holder) of a replay key.
pub const MAX_REPLAY_COMPONENT_LEN: usize = 512;
/// Minimum time a consumed nonce must be retained: the longest action lifetime plus the clock-skew allowance in both directions. A pruning
/// horizon below this can free a still-valid nonce.
pub const REPLAY_MIN_RETENTION_MS: i64 = PCACTN_MAX_LIFETIME_MS + 2 * PCACTN_MAX_SKEW_MS;

// ---- escalation.ts / forbid-certificate.ts / policy-classes.ts / merkle.ts / threshold.ts --------------------------------------------
pub const ESCALATION_POLICY_DOMAIN: &str = "atlas-pca/escalation-policy/v1";
pub const ESCALATION_ACTION_DOMAIN: &str = "atlas-pca/escalation-action/v1";
pub const ESCALATION_HISTORY_DOMAIN: &str = "atlas-pca/escalation-history/v1";
pub const FORBID_CERT_VERSION: u8 = 1;
pub const FORBID_CERT_KIND: &str = "forbid-wins";
/// The number of policy classes (constitution, regulatory, org, blueprint, user).
pub const MAX_POLICY_CLASSES: usize = crate::policy_classes::POLICY_CLASSES.len();
/// The reversibility class of a plan node that names none.
pub const DEFAULT_REVERSIBILITY_CLASS: &str = "reversible";
/// The thresholds a signer set may demand (1 auto, 2 guardian, 3 human).
pub const VALID_THRESHOLDS: [u8; 3] = [1, 2, 3];
pub const AGENT_LEAF_SHARE_BINDING_VERSION: &str = "2.1";
/// Largest JSON text the strict parser accepts (1 MiB).
pub const MAX_JSON_BYTES: usize = 1 << 20;

// ---- policy-link.ts -----------------------------------------------------------------------------------------------------------------------
pub const TEMPLATE_KIND: &str = "pca-policy-template";
pub const TIGHTEN_KIND: &str = "pca-template-tighten";

// ---- decision.ts ----------------------------------------------------------------------------------------------------------------------------
/// The `env` roots a model decides: a grant's `where` can never read them (rule 21).
pub const MODEL_ENV_ROOTS: [&str; 4] = ["class", "prov", "judge", "detect"];
/// Prefixes of the verifier reasons that read as an escalate rather than a deny.
pub const ESCALATE_REASON_PREFIXES: [&str; 2] = ["intent_required:", "escalate:"];

// ---- regex-budget.ts / regex-cache.ts --------------------------------------------------------------------------------------------------
pub const REGEX_REQUEST_SCALE: usize = 4;
pub const REGEX_CACHE_MAX_ENTRIES: usize = 512;
pub const REGEX_CACHE_MAX_PER_SOURCE: usize = 64;
pub const REGEX_CACHE_MAX_WEIGHT: usize = 131_072;

// ---- workflow.ts (WORKFLOW_LIMITS) ---------------------------------------------------------------------------------------------------------
pub const WORKFLOW_MAX_STEPS: usize = 64;
pub const WORKFLOW_MAX_EDGES: usize = 256;
pub const WORKFLOW_MAX_DEPS: usize = 16;
pub const WORKFLOW_MAX_LABELS: usize = 16;
pub const WORKFLOW_MAX_FIELDS: usize = 32;
pub const WORKFLOW_MAX_COST: usize = 8;
pub const WORKFLOW_MAX_ID: usize = 64;

// ---- catalog-risk.ts -------------------------------------------------------------------------------------------------------------------------
/// Reversibility score per class (1 = fully reversible), the scale the hosted adjudicator uses. A class not listed scores 0.
pub const CATALOG_REVERSIBILITY_SCORE: [(&str, f64); 4] = [("reversible", 1.0), ("rate_limited", 0.4), ("costly", 0.4), ("irreversible", 0.0)];

// ---- server/verify.ts: the required-check profiles and the default-deny fold ---------------------------------------------------------------
/// The profile a STATEFUL resource server demands: the stateless one plus `replay`, the strictly-increasing-counter check against stored
/// state (it is `not-enforced` without a store, so the request is denied).
pub const STATEFUL_REQUIRED_CHECKS: [&str; 7] = ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound"];
/// The checks a full-policy decision must PASS: the stateful profile plus the params digest and the policy itself.
pub const EXECUTION_REQUIRED_CHECKS: [&str; 9] =
    ["counter_format", "replay", "revocation", "plan_root_authorized", "audience", "validity", "grant_ref_bound", "params_digest", "policy"];

/// Default-deny: turn every required check that is not `pass` into a failure. `counter` (the old name) means `replay` when that check is
/// present, else `counter_format`. A check already `fail` keeps its own reason; one that is absent, `not-enforced` or `unsupported` becomes
/// `fail` (`unsupported` stays `unsupported`) with a reason. Returns whether the verdict still allows: never more than `allow`.
pub fn enforce_required(allow: bool, checks: &mut BTreeMap<String, CheckStatus>, reasons: &mut Vec<String>, required: &[&str]) -> bool {
    let mut allow = allow;
    for name in required {
        let name = if *name == "counter" && !checks.contains_key("counter") {
            if checks.contains_key("replay") {
                "replay"
            } else {
                "counter_format"
            }
        } else {
            *name
        };
        let was = checks.get(name).copied();
        if was == Some(CheckStatus::Pass) {
            continue;
        }
        allow = false;
        if was == Some(CheckStatus::Fail) {
            continue;
        }
        let shown = if was == Some(CheckStatus::Unsupported) { "unsupported" } else { was.map_or("absent", |s| s.as_str()) };
        reasons.push(format!("{name}: required check is {shown} (default-deny: not enforced by this resource server)"));
        if was != Some(CheckStatus::Unsupported) {
            checks.insert(name.to_string(), CheckStatus::Fail);
        }
    }
    allow
}

// ---- threshold.ts ----------------------------------------------------------------------------------------------------------------------------

/// Collect shares into a threshold signature `{shares: [...]}` (a defensive copy; JSON in, JSON out as the verifier takes it).
pub fn assemble_threshold(shares: &[serde_json::Value]) -> serde_json::Value {
    serde_json::json!({ "shares": shares })
}

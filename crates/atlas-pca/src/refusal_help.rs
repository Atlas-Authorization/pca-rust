//! `explain_refusal(reason)`: turn a refusal reason from `authorize` / the axum guard into what it means, how to fix it and
//! the page that explains it. The reasons themselves are pinned across all ten languages and the conformance vectors, so
//! they are never reworded; this maps them (by their leading check name) to guidance instead. The text is the same as
//! `explainRefusal` in `@atlasauth/pca`. An unknown reason returns a generic entry that still links the table.

/// Base of the published PCA docs.
pub const PCA_DOCS: &str = "https://github.com/Atlas-Authorization/pca/blob/main/docs";

/// Guidance for one refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusalHelp {
    /// The check that refused (the reason's leading token), or `unknown`.
    pub check: String,
    pub meaning: String,
    pub fix: String,
    pub docs: String,
}

const CONFIG_MEANING: &str = "The guard was built without a required component, so it refuses every request (fail closed).";
const CONFIG_FIX: &str = "Add the component the reason names (audience, resolveGrant, budgetStore, hooks.revocation). protect() fills them with safe defaults.";
const GRANT_FIX: &str = "Register the principal's grant with the server (its grants list or resolveGrant). The grant comes from your store, never from the request.";
const WIRE_FIX: &str = "Send the proof exactly as encoded by encodePCActn (header PCA-Action, or body { pcactn }).";

/// (check, meaning, fix, docs path under [`PCA_DOCS`]).
const TABLE: &[(&str, &str, &str, &str)] = &[
    ("authorize_config", CONFIG_MEANING, CONFIG_FIX, "guides/resource-server-quickstart.md"),
    ("authorize", CONFIG_MEANING, CONFIG_FIX, "guides/resource-server-quickstart.md"),
    ("operation", "The signed action is not the operation this route executes (other verb, resource or params).", "Sign the action the route runs, with the same params. If this is a tool server, use one tool-to-action mapping on both sides.", "reference/refusals.md#operation"),
    ("audience", "The proof was signed for a different server.", "Make the agent sign with the same audience string the server is configured with.", "reference/refusals.md#audience"),
    ("replay", "This proof (or an older counter) was already used.", "Each action needs a fresh proof. If this is a retry of an action that already ran, use an operation record instead of resending.", "reference/refusals.md#replay"),
    ("counter_format", "The proof carries no valid anti-replay counter.", "Build the proof with the agent facade (act) or buildPCActn, which set it.", "reference/refusals.md#replay"),
    ("plan_root_authorized", "The plan the action belongs to was not authorized by the principal.", "Use plan: single-step (protect() does) for one-action proofs, or have the principal authorize the committed plan root.", "reference/refusals.md#plan_root_authorized"),
    ("plan_state", "The plan is committed but not executable now (not authorized, expired or revoked).", "Check the plan state named in the reason and re-authorize or recommit.", "reference/refusals.md#plan_root_authorized"),
    ("revocation", "The grant, or the revocation source, refused.", "The grant was revoked, or no revocation source is configured. Configure hooks.revocation (protect() does).", "reference/refusals.md#revocation"),
    ("validity", "The proof is outside its validity window.", "Check clocks on both sides; request a fresh proof.", "reference/refusals.md#validity"),
    ("grant_ref", "The proof does not name a grant this server knows.", GRANT_FIX, "reference/refusals.md#grant_ref"),
    ("grant_ref_bound", "The proof does not name a grant this server knows.", GRANT_FIX, "reference/refusals.md#grant_ref"),
    ("policy", "The grant does not permit this action or these parameters (a predicate or limit failed).", "Widen the grant if the action is legitimate (the principal signs a new one); otherwise this is the guard working.", "reference/refusals.md#policy"),
    ("delegated_caveats", "A caveat added by a delegation refused the action.", "The sub-agent was narrowed below this action. Delegate with the caveats you intend.", "reference/refusals.md#policy"),
    ("threshold", "The risk needs a co-signature from the principal (step-up).", "Collect the co-sign through the step-up flow, or lower the risk the server prices.", "concepts/threshold-and-step-up.md"),
    ("risk_inputs", "A risk input the server must vouch for was not supplied.", "Supply it in the risk option (catalogRisk derives the common ones; protect() uses it).", "reference/refusals.md#risk_inputs"),
    ("chain", "The delegation chain does not verify back to the grant.", "Rebuild the chain with delegate()/subAgent(); do not edit a grant or hop after signing.", "reference/refusals.md#chain"),
    ("leaf_signature", "The proof signature does not verify.", "The proof was altered, or signed by a key that is not the chain leaf.", "reference/refusals.md#chain"),
    ("wire", "The proof is not well-formed under the strict wire profile.", WIRE_FIX, "reference/wire-formats.md"),
    ("malformed", "The proof could not be read.", WIRE_FIX, "reference/wire-formats.md"),
    ("freshness", "The consistency token or revocation epoch is stale.", "Refresh the token from the guardian and retry.", "reference/refusals.md#freshness"),
    ("provenance_flow", "The action, or an argument of it, derives from content the principal did not write (a tool result, a page, an unpinned or missing provenance bundle), or the bundle is forged or unreadable.", "Present the provenance bundle your pinned mediator recorded (PCA-Provenance header), have the principal confirm the escalation, or run the call from a principal-authorized plan.", "guides/prompt-injection-provenance.md"),
    ("undo_window", "The action ran under a veto window: the principal can undo it until the window ends.", "Report the effect to your undo coordinator and let the window run.", "guides/undo-windows.md"),
    ("template", "The grant is not an instantiation of a linked policy template.", "Mint the grant from the template the server requires.", "guides/policy-analysis.md"),
];

/// Guidance for a refusal reason. Never panics; any input (empty, non-ASCII, unknown) gets an entry.
pub fn explain_refusal(reason: &str) -> RefusalHelp {
    let head_len = reason.bytes().take_while(|b| b.is_ascii_lowercase() || *b == b'_').count();
    let head = &reason[..head_len];
    let hit = TABLE.iter().find(|e| e.0 == head).or_else(|| TABLE.iter().find(|e| reason.contains(&format!("{}:", e.0))));
    match hit {
        Some(&(check, meaning, fix, docs)) => RefusalHelp { check: check.into(), meaning: meaning.into(), fix: fix.into(), docs: format!("{PCA_DOCS}/{docs}") },
        None => RefusalHelp {
            check: "unknown".into(),
            meaning: "The guard refused and the reason is not in the table.".into(),
            fix: "Read the reason as written; every refusal names the check that failed.".into(),
            docs: format!("{PCA_DOCS}/reference/refusals.md"),
        },
    }
}

//! BUILT-IN, release-signed pins for the Azure MAA token-signing keys: the offline root of the first accepted key set (port of
//! `attest-maa-pins.ts`).
//!
//! WHAT SHIPS: a signed allowlist manifest (`maa_pins_data.json`) carrying (a) `maa-signing-spki` pins for the self-signed per-instance MAA
//! keys, (b) the SPKI pin of the Microsoft chain root and of the `Microsoft Azure Attestation PCA 2019` intermediate Microsoft-chained
//! keys must pass through, and (c) a signed `attest-corroboration` record of how many independent network vantage points saw identical
//! key material and by what method. The manifest is verified at load against the release issuer key EMBEDDED here, with the usual expiry
//! and version-floor checks ([`super::allowlist::verify_allowlist_manifest`]).
//!
//! GUARANTEED: with the default key trust there is NO trust-on-first-use (the first accepted key set must overlap these signed pins, then
//! the rotation rules apply; Microsoft-chained keys only through the pinned root AND intermediate, with the leaf CN
//! `Microsoft Azure Attestation 2020`); the manifest cannot be edited, re-signed by another key, rolled back below the shipped version
//! floor or used after its expiry (fail closed: pins expire; ship a new release or pass explicit `initialPins`); the pin set was
//! corroborated by at least three independent vantages at signing time and that count is inside the signed bytes.
//!
//! NOT guaranteed: the offline root is the release signing key plus the recorded corroboration, not a Microsoft-issued root for the
//! self-signed instance keys (Microsoft publishes none); no CRL or Microsoft revocation is consulted; a key the release does not know is
//! accepted only through the rotation rules, never as a fresh root.
use std::sync::OnceLock;

use serde_json::{json, Map, Value};

use super::allowlist::{project_allowlist, verify_allowlist_manifest, JsNum, VerifyOptions};

/// The leaf CN Microsoft's MAA signing certificates carry.
pub const BUILTIN_CHAIN_LEAF_CN: [&str; 1] = ["Microsoft Azure Attestation 2020"];

const MAX_LIFETIME_MS: f64 = 400.0 * 24.0 * 3_600_000.0;
const MIN_VANTAGES: f64 = 3.0;

fn shipped() -> &'static Value {
    static DATA: OnceLock<Value> = OnceLock::new();
    DATA.get_or_init(|| serde_json::from_str(include_str!("maa_pins_data.json")).expect("the shipped pin data is valid JSON"))
}

/// The release signing key that roots the shipped pins: `{<issuer id>: {alg, keys}}`.
pub fn builtin_maa_pins_issuer_keys() -> Value {
    let d = shipped();
    json!({ d["issuer_id"].as_str().unwrap_or(""): d["issuer_key"] })
}

/// The id of the shipped pins' issuer.
pub fn builtin_maa_pins_issuer_id() -> &'static str {
    shipped()["issuer_id"].as_str().unwrap_or("")
}

fn no(reason: impl Into<String>) -> Value {
    json!({"ok": false, "reason": reason.into()})
}

/// Evaluate a pin source `{manifest, issuerKeys, minVersion?}`: `(value, notBefore, expiresAt)` or the reason.
fn evaluate(manifest: &Value, issuer_keys: &Value, min_version: f64, now_ms: f64) -> Result<(Value, f64, f64), Value> {
    // signature and structure are checked at a time inside the window; the window itself is re-checked on every call
    let at = manifest.get("body").and_then(|b| b.get("notBefore")).and_then(Value::as_f64).unwrap_or(now_ms);
    let opts = VerifyOptions {
        now_ms: JsNum::Num(at),
        min_version: JsNum::Num(min_version),
        max_lifetime_ms: JsNum::Num(MAX_LIFETIME_MS),
        ..VerifyOptions::default()
    };
    let v0 = verify_allowlist_manifest(manifest, issuer_keys, &opts);
    if v0["ok"] != json!(true) {
        return Err(no(format!("{}: {}", v0["code"].as_str().unwrap_or(""), v0["reason"].as_str().unwrap_or(""))));
    }
    let not_before = v0["body"]["notBefore"].as_f64().unwrap_or(f64::NAN);
    let p = project_allowlist(&v0, not_before);
    let corr = p["corroboration"].as_array().cloned().unwrap_or_default();
    if corr.len() != 1 {
        return Err(no("manifest must carry exactly one attest-corroboration entry"));
    }
    // /^vantages=([0-9]+);method=(.*)$/ (`.` does not match a line terminator)
    let label = corr[0]["label"].as_str().unwrap_or("");
    let parsed = label.strip_prefix("vantages=").and_then(|r| {
        let digits = r.bytes().take_while(u8::is_ascii_digit).count();
        let method = r[digits..].strip_prefix(";method=")?;
        (digits > 0 && !method.contains(['\n', '\r', '\u{2028}', '\u{2029}'])).then(|| (r[..digits].parse::<f64>().unwrap_or(f64::NAN), method.to_string()))
    });
    let vantages = parsed.as_ref().map_or(0.0, |p| p.0);
    let Some((_, method)) = parsed.filter(|_| vantages >= MIN_VANTAGES) else {
        return Err(no(format!("corroboration records {vantages} vantages < required {MIN_VANTAGES}")));
    };
    if p["maaSigningSpkis"].as_object().map_or(true, Map::is_empty) {
        return Err(no("manifest pins no MAA signing key"));
    }
    if p["maaChainRootSpkis"].as_array().map_or(true, Vec::is_empty) || p["maaChainIntermediateSpkis"].as_array().map_or(true, Vec::is_empty) {
        return Err(no("manifest lacks the Microsoft chain root / intermediate pins"));
    }
    let mut revoked: Map<String, Value> = Map::new();
    for r in p["revoked"].as_array().into_iter().flatten() {
        if r["kind"] == json!("maa-signing-spki") {
            let slot = revoked.entry(r["label"].as_str().unwrap_or("").to_string()).or_insert_with(|| json!([]));
            slot.as_array_mut().expect("array").push(r["value"].clone());
        }
    }
    let expires_at = v0["body"]["expiresAt"].as_f64().unwrap_or(f64::NAN);
    let value = json!({
        "ok": true,
        "version": v0["version"],
        "digest": v0["digest"],
        "expiresAt": v0["body"]["expiresAt"],
        "maaSigningSpkis": p["maaSigningSpkis"],
        "revokedSigningSpkis": Value::Object(revoked),
        "maaChainRootSpkis": p["maaChainRootSpkis"],
        "maaChainIntermediateSpkis": p["maaChainIntermediateSpkis"],
        "vantages": vantages,
        "method": method,
    });
    Ok((value, not_before, expires_at))
}

/// Load and verify the built-in pin set at `now_ms` (a safe integer): `{ok: true, version, digest, expiresAt, maaSigningSpkis,
/// revokedSigningSpkis, maaChainRootSpkis, maaChainIntermediateSpkis, vantages, method}` or `{ok: false, reason}`. Never fails. `source`
/// substitutes another signed source `{manifest, issuerKeys, minVersion?}` (tests, or a fork that signs its own pins; default floor 1).
pub fn load_builtin_maa_pins(now_ms: &Value, source: Option<&Value>) -> Value {
    let Some(now) = now_ms.as_f64().filter(|n| n.is_finite() && n.fract() == 0.0 && n.abs() <= 9_007_199_254_740_991.0) else {
        return no("nowMs must be an integer");
    };
    let (manifest, keys, floor) = match source {
        Some(s) => (s.get("manifest").cloned().unwrap_or(Value::Null), s.get("issuerKeys").cloned().unwrap_or(Value::Null), s.get("minVersion").and_then(Value::as_f64).unwrap_or(1.0)),
        None => (shipped()["manifest"].clone(), builtin_maa_pins_issuer_keys(), shipped()["min_version"].as_f64().unwrap_or(1.0)),
    };
    match evaluate(&manifest, &keys, floor, now) {
        Err(reason) => reason,
        Ok((value, not_before, expires_at)) => {
            if now < not_before {
                return no("built-in pins are not yet valid (clock behind the release)");
            }
            if now > expires_at {
                return no("built-in pins expired; update the package or pass explicit initialPins");
            }
            value
        }
    }
}

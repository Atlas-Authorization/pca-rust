//! k05 differential oracle for the caveat language v2 (K1): tests/data/k05-caveatlang.json.gz, written by the TypeScript
//! reference (tools/pca-audit/k05-oracles/caveatlang-oracle.mts; every native replays the same file). Typed-port mappings: a
//! clock that is not a JSON integer is `i64::MAX` (refused by the clock check exactly as the reference refuses it); pins /
//! revoked lists that are not arrays are empty / absent and their non-conforming entries are dropped; a non-object k1 input
//! is "not configured" (None).
use super::*;
use crate::k042_support::{k05_run, K05};

fn clock(v: Option<&Value>) -> i64 {
    match v.and_then(Value::as_f64) {
        Some(f) if f.fract() == 0.0 && f.abs() < 9.3e18 => f as i64,
        _ => i64::MAX,
    }
}

/// The verifier's pins; a pin whose pk is not a string keeps its label and class with an unusable key (the reference keeps the
/// entry, so its signature check fails).
fn pins_of(v: Option<&Value>) -> Vec<DischargePin> {
    let pin = |p: &Value| {
        DischargePin::from_json(p).or_else(|| {
            let m = p.as_object()?;
            let get = |k: &str| m.get(k).and_then(Value::as_str).map(String::from);
            Some(DischargePin { label: get("label")?, class: get("class")?, pk: String::new(), pq_pk: get("pq_pk"), spiffe_id: get("spiffe_id") })
        })
    };
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(pin).collect()).unwrap_or_default()
}

fn strings(v: Option<&Value>) -> Option<Vec<String>> {
    v.and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
}

fn k1_of(v: Option<&Value>) -> Option<K1Input> {
    let v = v.filter(|v| v.is_object())?;
    Some(K1Input {
        pins: pins_of(v.get("pins")),
        discharges: v.get("discharges").and_then(Value::as_array).cloned().unwrap_or_default(),
        narrow: v.get("narrow").cloned(),
        action_digest: v.get("action_digest").and_then(Value::as_str).map(String::from),
        revoked_discharges: strings(v.get("revoked_discharges")),
        spiffe_id: v.get("spiffe_id").and_then(Value::as_str).map(String::from),
        history: v.get("history").and_then(Value::as_array).cloned(),
    })
}

fn bound_json(b: &[BoundCaveat]) -> Value {
    Value::Array(b.iter().map(|x| json!({"caveat": x.caveat, "hop": x.hop, "cap_hash": x.cap_hash})).collect())
}

static NUL: Value = Value::Null;

#[test]
fn k05_caveatlang_matches_the_reference() {
    k05_run("caveatlang", 15000, |_, f, a| {
        let arg = |i: usize| a.get(i).unwrap_or(&NUL);
        match f {
            "spiffeIdError" => K05::Val(json!(spiffe_id_error(arg(0)))),
            "needsDischargeError" => K05::Val(json!(needs_discharge_error(arg(0)))),
            "dischargeShapeError" => K05::Val(json!(discharge_shape_error(arg(0)))),
            "narrowShapeError" => K05::Val(json!(narrow_shape_error(arg(0)))),
            "maxUsesError" => K05::Val(json!(max_uses_error(arg(0)))),
            "spiffeBoundError" => K05::Val(json!(spiffe_bound_error(arg(0)))),
            "deriveError" => K05::Val(json!(derive_error(arg(0)))),
            "maxUsesSlotKey" => match (arg(0).as_str(), arg(1).as_str(), arg(2).as_u64()) {
                (Some(c), Some(id), Some(i)) => K05::Val(json!(max_uses_slot_key(c, id, i))),
                _ => K05::Skip("non-string / non-u64 slot arguments (typed port)"),
            },
            "evaluateDerive" => {
                let inp = arg(1);
                let empty = Map::new();
                let history: Option<&[Value]> = inp.get("history").and_then(Value::as_array).map(Vec::as_slice);
                let d = DeriveInput {
                    now: clock(inp.get("now")),
                    action: inp.get("action").filter(|x| !x.is_null()),
                    history,
                    claims: inp.get("claims").and_then(Value::as_object).unwrap_or(&empty),
                };
                K05::Val(json!(evaluate_derive(arg(0), &d)))
            }
            "verifyDischarge" => {
                let b = arg(2);
                if !b.get("pins").is_some_and(Value::is_array) {
                    return K05::Skip("pins that are not a list (typed port: a slice of pins)");
                }
                let pins = pins_of(b.get("pins"));
                let revoked = strings(b.get("revoked"));
                let bind = DischargeBinding {
                    cap_hash: b.get("cap_hash").and_then(Value::as_str).unwrap_or(""),
                    action_digest: b.get("action_digest").and_then(Value::as_str),
                    pins: &pins,
                    now: clock(b.get("now")),
                    revoked: revoked.as_deref(),
                };
                K05::Val(match verify_discharge(arg(0), arg(1), &bind) {
                    DischargeVerdict::Ok { digest, claims } => json!({"ok": true, "digest": digest, "claims": claims}),
                    DischargeVerdict::Fail { reason } => json!({"ok": false, "reason": reason}),
                })
            }
            "verifyNarrow" => {
                let b = arg(3);
                let bind = NarrowBinding { now: clock(b.get("now")), action_digest: b.get("action_digest").and_then(Value::as_str) };
                K05::Val(match verify_narrow(arg(0), arg(1), arg(2), &bind) {
                    NarrowVerdict::Ok { caveats } => json!({"ok": true, "caveats": caveats}),
                    NarrowVerdict::Fail { reason } => json!({"ok": false, "reason": reason}),
                })
            }
            "boundCaveats" => K05::Val(bound_caveats(arg(0), arg(1)).map_or(Value::Null, |b| bound_json(&b))),
            "dischargeRequests" => K05::Skip("the discharge-request builder (producer side) is not in the Rust SDK"),
            "evaluateK1" => {
                let ctx = arg(3);
                let k1 = k1_of(a.get(2));
                let r = evaluate_k1(arg(0), arg(1), k1.as_ref(), &K1Ctx { now: clock(ctx.get("now")), action: ctx.get("action") });
                K05::Val(json!({"ok": r.ok, "failed": r.failed, "reasons": r.reasons, "plain": r.plain, "bound": bound_json(&r.bound)}))
            }
            "evaluateCaveatsK1" => {
                let (allow, failed) = evaluate_caveats_k1(arg(0), arg(1), k1_of(a.get(2)).as_ref(), arg(3));
                K05::Val(json!({"allow": allow, "failed": failed}))
            }
            "presentedK1" => {
                let Some(h) = arg(0).as_object() else { return K05::Skip("non-object headers") };
                let pairs: Vec<(&str, &str)> = h.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.as_str(), v))).collect();
                K05::Val(match presented_k1(pairs) {
                    Ok(p) => {
                        let mut value = Map::new();
                        if let Some(d) = p.discharges {
                            value.insert("discharges".into(), Value::Array(d));
                        }
                        if let Some(n) = p.narrow {
                            value.insert("narrow".into(), n);
                        }
                        json!({"ok": true, "value": value})
                    }
                    Err(_) => json!({"ok": false}),
                })
            }
            _ => K05::Skip("fn not in this module"),
        }
    });
}

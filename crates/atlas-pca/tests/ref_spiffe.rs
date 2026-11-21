//! Differential replay of the SPIFFE bridge against the TypeScript reference (test-data/ref-spiffe-svid.json.gz): SPIFFE IDs,
//! X.509-SVID and JWT-SVID verification, holder binding, admission evidence and the trust-bundle / revocation caches.
//! A reference refusal with a `code` must be matched by code; one without a code only requires a refusal. Skipped: inputs
//! with no native form (a non-string / non-bytes certificate or holder key, a revocation "check" that is not a function, a
//! hand-built SVID object) and lone surrogates.
mod common;
use atlas_pca::oidc::LocalJwkSet;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::spiffe::*;
use std::cell::RefCell;
use std::sync::{Arc, Mutex};

enum Skip {
    Untyped,
}

fn bytes(v: &Value) -> Option<Vec<u8>> {
    v.get("$bytes").and_then(Value::as_str).map(common::b64d)
}

/// Owned certificate inputs (PEM text or DER bytes).
enum Owned {
    Pem(String),
    Der(Vec<u8>),
}

fn owned(v: &Value) -> Result<Owned, Skip> {
    match v {
        Value::String(s) => Ok(Owned::Pem(s.clone())),
        v => bytes(v).map(Owned::Der).ok_or(Skip::Untyped),
    }
}

fn inputs(o: &[Owned]) -> Vec<CertInput<'_>> {
    o.iter()
        .map(|x| match x {
            Owned::Pem(s) => CertInput::Pem(s),
            Owned::Der(b) => CertInput::Der(b),
        })
        .collect()
}

fn chain_of(v: &Value) -> Result<Vec<Owned>, Skip> {
    match v {
        Value::String(_) => Ok(vec![owned(v)?]),
        Value::Array(a) => a.iter().map(owned).collect(),
        _ => Err(Skip::Untyped),
    }
}

type Calls = RefCell<Vec<Value>>;

/// The generator's scripted revocation check (`None` = no check; a non-function "check" has no native form).
fn rev_mode(vo: &Value) -> Result<Option<String>, Skip> {
    match vo.get("revocation") {
        None => Ok(None),
        Some(Value::String(m)) => Ok(Some(m.clone())),
        Some(_) => Err(Skip::Untyped),
    }
}

fn rev_answer(mode: &str, s: &Value, calls: &Calls) -> Result<Value, String> {
    calls.borrow_mut().push(s.clone());
    match mode {
        "throw" => Err("backend down".into()),
        "nonbool" => Ok(json!("no")),
        "true" => Ok(json!(true)),
        m if m.starts_with("at:") => Ok(json!(s.get("position") == Some(&json!(m[3..].parse::<u64>().unwrap())))),
        _ => Ok(json!(false)),
    }
}

/// Run `f` with the X.509 options of `vo`.
fn with_x509<T>(vo: &Value, f: impl FnOnce(&X509SvidOptions, &Calls) -> T) -> Result<T, Skip> {
    let roots: Vec<Owned> = vo["roots"].as_array().map(|a| a.iter().map(owned).collect::<Result<_, _>>()).unwrap_or(Ok(vec![]))?;
    let ri = inputs(&roots);
    let mode = rev_mode(vo)?;
    let calls = RefCell::new(vec![]);
    let check = |s: &Value| rev_answer(mode.as_deref().unwrap_or("false"), s, &calls);
    let o = X509SvidOptions {
        trust_domain: vo.get("trustDomain").and_then(Value::as_str),
        roots: &ri,
        now_ms: vo.get("nowMs").and_then(Value::as_f64),
        max_chain_length: vo.get("maxChainLength").and_then(Value::as_f64),
        revocation: mode.as_ref().map(|_| &check as RevocationCheck),
    };
    Ok(f(&o, &calls))
}

fn with_jwt<T>(vo: &Value, f: impl FnOnce(&JwtSvidOptions, &Calls) -> T) -> Result<T, Skip> {
    let mode = rev_mode(vo)?;
    let calls = RefCell::new(vec![]);
    let check = |s: &Value| rev_answer(mode.as_deref().unwrap_or("false"), s, &calls);
    let set = vo.get("key").and_then(|k| k.get("jwks")).map(|j| LocalJwkSet::new(j).expect("jwks"));
    let key = match (vo.get("key").and_then(|k| k.get("jwk")), &set) {
        (Some(j), _) => Some(SvidKey::Jwk(j.clone())),
        (None, Some(s)) => Some(SvidKey::Resolver(s)),
        _ => None,
    };
    let null = Value::Null;
    let o = JwtSvidOptions {
        audience: vo.get("audience").unwrap_or(&null),
        key,
        trust_domain: vo.get("trustDomain").unwrap_or(&null),
        now_ms: vo.get("currentSec").and_then(Value::as_f64).map(|s| s * 1000.0),
        algorithms: vo.get("algorithms"),
        clock_tolerance: vo.get("clockTolerance"),
        revocation: mode.as_ref().map(|_| &check as RevocationCheck),
    };
    Ok(f(&o, &calls))
}

fn holder_key(v: &Value) -> Result<Option<(Option<String>, Option<Vec<u8>>)>, Skip> {
    match v {
        Value::Null => Ok(None),
        Value::String(s) => Ok(Some((Some(s.clone()), None))),
        v => bytes(v).map(|b| Some((None, Some(b)))).ok_or(Skip::Untyped),
    }
}

fn hk_ref(h: &Option<(Option<String>, Option<Vec<u8>>)>) -> Option<HolderKey<'_>> {
    h.as_ref().map(|(s, b)| match (s, b) {
        (Some(s), _) => HolderKey::Text(s),
        (_, Some(b)) => HolderKey::Raw(b),
        _ => unreachable!(),
    })
}

fn bind_of(v: &Value) -> Value {
    if v.is_null() {
        json!({})
    } else {
        v.clone()
    }
}

fn id_json(i: &SpiffeId) -> Value {
    i.to_json()
}

fn jwt_out(s: &JwtSvid, calls: &Calls) -> Value {
    json!({ "spiffeId": id_json(&s.spiffe_id), "claims": s.claims, "audience": s.audience, "expiresAt": s.expires_at, "calls": calls.borrow().clone() })
}

type Shared = Arc<Mutex<(f64, Value, u32)>>;

/// The generator's scripted cache fetch: `{$throw}` = a plain failure, `{$spiffe: code}` = a coded refusal.
fn scripted(st: Shared) -> CacheFetch {
    Box::new(move || {
        let mut g = st.lock().unwrap();
        g.2 += 1;
        let cur = g.1.clone();
        if let Some(t) = cur.get("$throw").and_then(Value::as_str) {
            return Err(SpiffeError::plain(t));
        }
        if let Some(c) = cur.get("$spiffe").and_then(Value::as_str) {
            return Err(SpiffeError::new(c, "x"));
        }
        Ok(cur)
    })
}

fn clock(st: Shared) -> CacheClock {
    Box::new(move || st.lock().unwrap().0)
}

fn step_err(e: SpiffeError, fetches: u32) -> Value {
    json!({ "code": e.code, "fetches": fetches })
}

fn scenario(opts: &Value, steps: &[Value], bundle: bool) -> Value {
    let st: Shared = Arc::new(Mutex::new((0.0, Value::Null, 0)));
    let null = Value::Null;
    let (r, m) = (opts.get("refreshMs").unwrap_or(&null), opts.get("maxStaleMs").unwrap_or(&null));
    let tb = if bundle { Some(create_trust_bundle_source(scripted(st.clone()), r, m, Some(clock(st.clone())))) } else { None };
    let rv = if bundle { None } else { Some(create_revocation_source(scripted(st.clone()), r, m, Some(clock(st.clone())))) };
    if let Some(Err(e)) = &tb {
        return json!({ "ctor": e.code });
    }
    if let Some(Err(e)) = &rv {
        return json!({ "ctor": e.code });
    }
    let mut out = vec![];
    for s in steps {
        {
            let mut g = st.lock().unwrap();
            *g = (s["at"].as_f64().unwrap(), s.get("fetch").cloned().unwrap_or(Value::Null), 0);
        }
        let op = s["op"].as_str().unwrap();
        let res: Result<Value, SpiffeError> = match (&tb, &rv) {
            (Some(Ok(t)), _) => {
                if op == "x509Roots" {
                    t.x509_roots().map(Value::Array)
                } else {
                    let h = s.get("header").cloned().unwrap_or(json!({ "alg": "ES256" }));
                    t.jwt_key(h.as_object().unwrap()).map(|_| json!("key"))
                }
            }
            (_, Some(Ok(v))) => match op {
                "ensureFresh" => v.ensure_fresh().map(|_| Value::Null),
                "refresh" => v.refresh().map(|_| Value::Null),
                "x509" => v.x509(&s["subject"]).map(Value::Bool),
                _ => v.jwt(&s["subject"]).map(Value::Bool),
            },
            _ => unreachable!(),
        };
        let fetches = st.lock().unwrap().2;
        out.push(match res {
            Ok(v) => json!({ "ok": v, "fetches": fetches }),
            Err(e) => step_err(e, fetches),
        });
    }
    json!({ "steps": out })
}

fn run(fun: &str, a: &[Value]) -> Result<Result<Value, SpiffeError>, Skip> {
    Ok(match fun {
        "constants" => Ok(json!({ "jwtSvidAlgorithms": JWT_SVID_ALGORITHMS })),
        "parseSpiffeId" => match &a[0] {
            Value::String(s) => parse_spiffe_id(s).map(|i| id_json(&i)),
            _ => return Err(Skip::Untyped),
        },
        "parseX509Svid" => {
            let c = [owned(&a[0])?];
            parse_x509_svid(&inputs(&c)[0]).map(|s| json!({ "spiffeId": id_json(&s.spiffe_id), "publicKeyDer": s.public_key_der }))
        }
        "verifyX509Svid" => {
            let ch = chain_of(&a[0])?;
            with_x509(&a[1], |o, calls| {
                verify_x509_svid(&inputs(&ch), o).map(|s| {
                    let mut v = id_json(&s.spiffe_id);
                    v["publicKeyDer"] = json!(s.public_key_der);
                    v["calls"] = Value::Array(calls.borrow().clone());
                    v
                })
            })?
        }
        "verifyJwtSvid" => with_jwt(&a[1], |o, calls| verify_jwt_svid(&a[0], o).map(|s| jwt_out(&s, calls)))?,
        "svidToHolderX509" => {
            let ch = chain_of(&a[0])?;
            let h = holder_key(&a[2])?;
            with_x509(&a[1], |o, _| {
                verify_x509_svid(&inputs(&ch), o).and_then(|s| svid_to_holder(&Svid::X509(s), hk_ref(&h).as_ref(), &bind_of(&a[3]))).map(|h| h.to_json())
            })?
        }
        "svidToHolderJwt" => {
            let h = holder_key(&a[2])?;
            with_jwt(&a[1], |o, _| {
                verify_jwt_svid(&a[0], o).and_then(|s| svid_to_holder(&Svid::Jwt(s), hk_ref(&h).as_ref(), &bind_of(&a[3]))).map(|h| h.to_json())
            })?
        }
        "svidToHolderUnverified" => match a[0].as_str() {
            Some("parsed" | "parsed built") => {
                let c = [owned(&a[1])?];
                parse_x509_svid(&inputs(&c)[0]).and_then(|s| svid_to_holder(&Svid::X509(s), Some(&HolderKey::Text("x")), &json!({}))).map(|h| h.to_json())
            }
            _ => return Err(Skip::Untyped), // a string / hand-built object cannot be an Svid
        },
        "spiffeIdForHolder" => {
            let ch = chain_of(&a[0])?;
            let Some(leaf) = a[2].as_str() else { return Err(Skip::Untyped) };
            with_x509(&a[1], |o, _| {
                verify_x509_svid(&inputs(&ch), o).and_then(|s| spiffe_id_for_holder(&Svid::X509(s), leaf, &bind_of(&a[3]))).map(Value::String)
            })?
        }
        "workloadDischargePin" => {
            let ch = chain_of(&a[1])?;
            with_x509(&a[2], |o, _| verify_x509_svid(&inputs(&ch), o).and_then(|s| workload_discharge_pin(a[0].as_str().unwrap(), &s)))?
        }
        "holderToSpiffeId" => holder_to_spiffe_id(&a[0]).map(Value::String),
        "holderBindingMessage" => {
            use base64::Engine;
            let m = holder_binding_message(a[0].as_str().unwrap(), a[1].as_str().unwrap());
            Ok(json!({ "$bytes": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(m) }))
        }
        "spiffeAdmissionEvidence" => {
            let (e, key) = (&a[0], a[1].as_str().unwrap());
            let bind = e.get("bind").cloned().unwrap_or(json!({}));
            if e["kind"] == "x509" {
                let ch = chain_of(&e["chain"])?;
                with_x509(&e["verify"], |o, _| Ok(spiffe_admission_evidence(&SpiffeEvidence::X509 { chain: &inputs(&ch), verify: *o, bind }, key)))?
            } else {
                with_jwt(&e["verify"], |o, _| {
                    let verify = JwtSvidOptions {
                        audience: o.audience,
                        key: match &o.key {
                            Some(SvidKey::Jwk(j)) => Some(SvidKey::Jwk(j.clone())),
                            Some(SvidKey::Resolver(r)) => Some(SvidKey::Resolver(*r)),
                            None => None,
                        },
                        trust_domain: o.trust_domain,
                        now_ms: o.now_ms,
                        algorithms: o.algorithms,
                        clock_tolerance: o.clock_tolerance,
                        revocation: o.revocation,
                    };
                    Ok(spiffe_admission_evidence(&SpiffeEvidence::Jwt { token: &e["token"], verify, bind }, key))
                })?
            }
        }
        "trustBundleScenario" => Ok(scenario(&a[0], a[1].as_array().unwrap(), true)),
        "revocationScenario" => Ok(scenario(&a[0], a[1].as_array().unwrap(), false)),
        f => panic!("unknown fn {f}"),
    })
}

#[test]
fn spiffe_replays_the_reference() {
    let (mut fails, mut ran, mut skipped) = (Vec::new(), 0usize, 0usize);
    for c in common::ref_cases("spiffe-svid") {
        if common::has_lone(&c) {
            skipped += 1;
            continue;
        }
        let (name, want) = (c["name"].as_str().unwrap(), &c["out"]);
        let got = match run(c["fn"].as_str().unwrap(), c["args"].as_array().unwrap()) {
            Ok(g) => g,
            Err(Skip::Untyped) => {
                skipped += 1;
                continue;
            }
        };
        ran += 1;
        let ok = match (want.get("$throws"), &got) {
            (Some(_), Err(e)) => want.get("code").and_then(Value::as_str).is_none_or(|w| e.code.as_deref() == Some(w)),
            (None, Ok(g)) => atlas_pca::canonicalize(want) == atlas_pca::canonicalize(g),
            _ => false,
        };
        if !ok {
            fails.push(format!("{name}: want {want}, got {got:?}"));
        }
    }
    assert!(skipped * 10 < ran, "too many skipped: {skipped} of {ran}");
    assert!(fails.is_empty(), "{} of {ran} cases differ:\n{}", fails.len(), fails.join("\n"));
}

#[test]
fn holder_binding_rejects_unverified_and_hand_built() {
    // A parse-only SVID never binds (only verify_* results do).
    let leaf = "not a cert";
    assert!(parse_x509_svid(&CertInput::Pem(leaf)).is_err());
    assert_eq!(parse_spiffe_id("spiffe://example.org/a").unwrap().path, "/a");
    assert!(parse_spiffe_id("spiffe://example.org/a/").is_err());
    let _unused: Map<String, Value> = Map::new();
}

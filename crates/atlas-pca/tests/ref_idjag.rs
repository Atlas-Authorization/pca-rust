//! Differential replay of the ID-JAG bridge against the TypeScript reference (test-data/ref-idjag.json.gz): verification on top
//! of the OIDC verifier, principal / capability projection, caveat readers and the XAA request shapes.
//! A reference error with a `code` must be matched by code, and by message when it is one of the package's own texts; a
//! JavaScript runtime TypeError only requires a refusal. Cases with a lone surrogate (not representable in a Rust string)
//! are skipped.
mod common;
use atlas_pca::agent::Suite;
use atlas_pca::idjag::*;
use atlas_pca::oidc::{LocalJwkSet, OidcError, OidcKey};
use atlas_pca::serde_json::{json, Value};

const OWN: [&str; 9] = [
    "verifyIdJag:",
    "verifyIdToken:",
    "ID-JAG",
    "id token",
    "idJagTo",
    "oidcPrincipal:",
    "tokenExchangeRequest:",
    "jwtBearerAssertion:",
    "non-canonical compact JWS:",
];

fn same(want: &Value, got: &Result<Value, OidcError>) -> bool {
    let Some(m) = want.get("$throws").and_then(Value::as_str) else {
        return got.as_ref().is_ok_and(|v| atlas_pca::canonicalize(want) == atlas_pca::canonicalize(v));
    };
    let Err(e) = got else { return false };
    if want.get("code").and_then(Value::as_str).is_some_and(|c| c != e.code) {
        return false;
    }
    if m.starts_with("non-canonical compact JWS: bad-json") {
        return e.message.starts_with("non-canonical compact JWS: bad-json");
    }
    let own = OWN.iter().any(|p| m.starts_with(p)) && m != "id token verification failed";
    !own || m == e.message
}

fn verify(t: &Value, opts: &Value) -> Result<Value, OidcError> {
    let mode = opts.get("consumeJti").and_then(|c| c.get("mode")).and_then(Value::as_str).map(String::from);
    let consume = mode.map(|m| {
        move |_: &str, _: f64| -> Result<bool, String> {
            match m.as_str() {
                "throw" => Err("store down".into()),
                "fresh" => Ok(true),
                _ => Ok(false), // "seen", and "truthy" (the reference's 1, not true): never a first use
            }
        }
    });
    let consume_ref = consume.as_ref().map(|f| f as &dyn Fn(&str, f64) -> Result<bool, String>);
    let local;
    let key = match opts.get("key") {
        None => None,
        Some(k) if k.get("jwks").is_some() => {
            local = LocalJwkSet::new(&k["jwks"]).map_err(|m| OidcError { code: "type_error".into(), message: m })?;
            Some(OidcKey::Resolver(&local))
        }
        Some(k) => Some(OidcKey::Jwk(k.clone())),
    };
    verify_id_jag(t, opts, key.as_ref(), None, consume_ref)
}

fn capability(g: &Value, o: &Value) -> Result<Value, OidcError> {
    let secret = o.get("principalSecret").and_then(|s| s.get("$bytes")).and_then(Value::as_str).map(common::b64d);
    id_jag_to_capability(g, o, secret.as_deref(), &Suite::default())
}

/// The replay runs at the corpus generator's frozen clock (the age checks of the `clockCases` read it).
#[test]
fn idjag_vectors() {
    atlas_pca::jose::with_clock_sec((common::ref_clock_ms("idjag") / 1000.0).floor(), idjag_vectors_at_clock);
}

fn idjag_vectors_at_clock() {
    let cases = common::ref_cases("idjag");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    let none = Value::Null;
    for c in &cases {
        if common::has_lone(c) {
            skipped += 1;
            continue;
        }
        let a = c["args"].as_array().unwrap();
        let arg = |i: usize| a.get(i).unwrap_or(&none);
        let got: Result<Value, OidcError> = match c["fn"].as_str().unwrap() {
            "verifyIdJag" => verify(arg(0), arg(1)),
            "idJagToPcaPrincipal" => id_jag_to_pca_principal(arg(0), a.get(1)),
            "idJagToCapability" => capability(arg(0), arg(1)),
            "isIdJagAuthorityCaveat" => Ok(json!(is_id_jag_authority_caveat(arg(0)))),
            "isIdJagProvenanceCaveat" => Ok(json!(is_id_jag_provenance_caveat(arg(0)))),
            "readIdJagAuthority" => read_id_jag_authority(arg(0)),
            "readIdJagProvenance" => read_id_jag_provenance(arg(0)),
            "tokenExchangeRequest" => token_exchange_request(arg(0)),
            "jwtBearerAssertion" => jwt_bearer_assertion(arg(0)),
            "constants" => Ok(json!({
                "MAX_ID_JAG_CHARS": MAX_ID_JAG_CHARS,
                "IDJAG_AUTHORITY_CAVEAT": IDJAG_AUTHORITY_CAVEAT,
                "IDJAG_PROVENANCE_CAVEAT": IDJAG_PROVENANCE_CAVEAT,
                "GRANT_TYPE_TOKEN_EXCHANGE": GRANT_TYPE_TOKEN_EXCHANGE,
                "GRANT_TYPE_JWT_BEARER": GRANT_TYPE_JWT_BEARER,
                "TOKEN_TYPE_ID_JAG": TOKEN_TYPE_ID_JAG,
                "TOKEN_TYPE_ID_TOKEN": TOKEN_TYPE_ID_TOKEN,
                "TOKEN_TYPE_ACCESS_TOKEN": TOKEN_TYPE_ACCESS_TOKEN,
                "TOKEN_TYPE_JWT": TOKEN_TYPE_JWT,
                "CLIENT_ASSERTION_TYPE_JWT_BEARER": CLIENT_ASSERTION_TYPE_JWT_BEARER,
            })),
            f => panic!("unknown fn {f}"),
        };
        if !same(&c["out"], &got) {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} lone-surrogate cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

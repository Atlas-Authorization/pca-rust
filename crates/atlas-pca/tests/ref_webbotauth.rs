//! Differential replay of Web Bot Auth (RFC 9421 message signatures in the web-bot-auth profile, signed key directory, Content-Digest,
//! PCA proof binding) against the TypeScript reference (test-data/ref-webbotauth.json.gz). A reference throw only requires a refusal.
//! Bytes are `{"$bytes": base64url}` in the corpus; keys are passed to the module as base64url strings. Skipped: cases with a lone
//! surrogate (no Rust string) and any case whose arguments are not of the type the Rust signature takes (non-string header, non-bytes
//! body) when the reference did not throw.
mod common;
use atlas_pca::serde_json::{json, Map, Value};
use atlas_pca::webbotauth::*;
use base64::Engine;
use std::cell::RefCell;
use std::collections::HashMap;

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    v.as_object().filter(|o| o.len() == 1).and_then(|o| o.get("$bytes")).and_then(Value::as_str).map(common::b64d)
}

/// A body: a string (UTF-8) or `{"$bytes"}`.
fn body_of(v: &Value) -> Result<Vec<u8>, String> {
    match v {
        Value::String(s) => Ok(s.as_bytes().to_vec()),
        o => bytes_of(o).ok_or_else(|| "the body must be a string or bytes".to_string()),
    }
}

fn bytes_val(b: &[u8]) -> Value {
    json!({ "$bytes": b64u(b) })
}

/// `{"$bytes": s}` public keys of a key list become the base64url string the module takes.
fn plain_keys(keys: &Value) -> Value {
    let Some(a) = keys.as_array() else {
        return keys.clone();
    };
    Value::Array(
        a.iter()
            .map(|k| {
                let mut k = k.clone();
                if let Some(o) = k.as_object_mut() {
                    if let Some(b) = o.get("publicKey").and_then(bytes_of) {
                        o.insert("publicKey".into(), Value::String(b64u(&b)));
                    }
                }
                k
            })
            .collect(),
    )
}

static NULL: Value = Value::Null;

struct Fixed(Result<bool, &'static str>);

impl ReplayCache for Fixed {
    fn claim(&self, _key: &str, _expires: f64, _now: f64) -> Result<bool, String> {
        self.0.map_err(|e| e.to_string())
    }
}

fn cache_of(spec: Option<&Value>) -> Option<Box<dyn ReplayCache>> {
    let s = spec?.as_str()?;
    let cache: Box<dyn ReplayCache> = match s {
        "always" => Box::new(Fixed(Ok(true))),
        "never" => Box::new(Fixed(Ok(false))),
        "throw" => Box::new(Fixed(Err("cache down"))),
        "memory" => Box::new(memory_replay_cache(None)),
        m => Box::new(memory_replay_cache(m.strip_prefix("memory:").and_then(|n| n.parse::<usize>().ok()))),
    };
    Some(cache)
}

fn norm(mut r: Value) -> Value {
    if let Some(reason) = r.get("reason").and_then(Value::as_str) {
        if reason.starts_with("invalid PCActn in PCA-Action: ") {
            r["reason"] = json!("invalid PCActn in PCA-Action");
        }
    }
    r
}

fn resolver_of(opts: &Value) -> impl Fn(&str) -> Result<ResolvedKey, String> {
    let spec = opts.get("resolveKey").cloned().unwrap_or(Value::Null);
    move |kid: &str| match spec.get(kid) {
        None | Some(Value::Null) => Ok(ResolvedKey::None),
        Some(v) if v.get("$throw").is_some() => Err("resolver down".to_string()),
        Some(v) => Ok(match bytes_of(v) {
            Some(b) => ResolvedKey::Raw(b),
            None => ResolvedKey::Jwk(v.clone()),
        }),
    }
}

fn fetch_run(url: &str, spec: &Value) -> Value {
    let called: RefCell<Option<Value>> = RefCell::new(None);
    let res = &spec["response"];
    let fetch = |u: &str, init: &Value| -> Result<FetchResponse, String> {
        *called.borrow_mut() = Some(json!({ "url": u, "headers": init["headers"].clone(), "redirect": init["redirect"].clone() }));
        if res.as_str() == Some("throw") {
            return Err("network down".into());
        }
        let headers: HashMap<String, String> = res["headers"]
            .as_object()
            .map(|h| h.iter().filter_map(|(k, v)| v.as_str().map(|v| (k.to_lowercase(), v.to_string()))).collect())
            .unwrap_or_default();
        Ok(FetchResponse { status: res["status"].as_i64().unwrap_or(0), headers, body: res["body"].as_str().ok_or("body")?.to_string() })
    };
    let options = spec.get("options").cloned().unwrap_or_else(|| json!({}));
    let out = fetch_key_directory(url, &options, &fetch);
    let called = called.borrow().clone().unwrap_or(Value::Null);
    match out {
        Ok(d) => json!({ "directory": d, "called": called }),
        Err(e) => {
            let message = if e.starts_with("directory signature: ") {
                "directory signature".to_string()
            } else if e.starts_with("directory ") || e.starts_with("Invalid URL") {
                e
            } else {
                "other".to_string()
            };
            json!({ "error": true, "message": message, "called": called })
        }
    }
}

/// `None` = a case whose arguments the Rust signature cannot take (skipped unless the reference threw).
fn run(f: &str, a: &[Value]) -> Option<Result<Value, String>> {
    let arg = |i: usize| a.get(i).unwrap_or(&NULL);
    Some(match f {
        "constants" => Ok(json!({
            "tag": WEB_BOT_AUTH_TAG, "alg": WEB_BOT_AUTH_ALG, "path": WELL_KNOWN_DIRECTORY_PATH, "ct": DIRECTORY_CONTENT_TYPE,
            "label": DEFAULT_SIGNATURE_LABEL, "exp": DEFAULT_EXPIRES_SEC, "agent": SIGNATURE_AGENT_HEADER, "pca": PCA_HEADER,
            "comp": PCA_PROOF_COMPONENT, "cd": CONTENT_DIGEST_HEADER, "algs": CONTENT_DIGEST_ALGS, "dtag": DIRECTORY_SIGNATURE_TAG,
        })),
        "jwkThumbprint" => Ok(json!(jwk_thumbprint(&bytes_of(arg(0))?))),
        "signRequest" => sign_request(arg(0), None),
        "verifySignedRequest" => {
            let opts = arg(1);
            let resolver = resolver_of(opts);
            let r: KeyResolver<'_> = &resolver;
            // the corpus encodes the resolver function as `resolveKey`; without it the verifier gets none and uses `jwks` (or refuses)
            let r = opts.get("resolveKey").is_some_and(|v| !v.is_null()).then_some(r);
            let cache = cache_of(opts.get("replayCache"));
            let times = a.get(2).and_then(Value::as_u64).unwrap_or(1);
            let rs: Vec<Value> = (0..times).map(|_| norm(verify_signed_request(arg(0), opts, r, cache.as_deref()))).collect();
            Ok(if times == 1 { rs[0].clone() } else { Value::Array(rs) })
        }
        "buildKeyDirectory" => build_key_directory(&plain_keys(arg(0))),
        "resolveFromDirectory" => resolve_from_directory(arg(0), arg(1).as_str()?).map(|o| o.unwrap_or(Value::Null)),
        "directoryHandler" => {
            let h = match directory_handler(&plain_keys(arg(0))) {
                Ok(h) => h,
                Err(e) => return Some(Err(e)),
            };
            let paths = arg(1).as_array()?;
            Ok(Value::Array(paths.iter().map(|x| h(x.as_str().unwrap_or("")).unwrap_or(Value::Null)).collect()))
        }
        "memoryReplayCache" => {
            let c = memory_replay_cache(arg(0).as_u64().map(|n| n as usize));
            let ops = arg(1).as_array()?;
            Ok(Value::Array(
                ops.iter()
                    .map(|op| match c.claim(op[0].as_str().unwrap_or(""), op[1].as_f64().unwrap_or(0.0), op[2].as_f64().unwrap_or(0.0)) {
                        Ok(b) => Value::Bool(b),
                        Err(_) => json!("throw"),
                    })
                    .collect(),
            ))
        }
        "proofHeaders" => proof_headers(arg(0)),
        "decodeProofHeader" => decode_proof_header(arg(0).as_str()?),
        "signRequestWithProof" => sign_request_with_proof(arg(0), None),
        "verifySignedRequestWithProof" => {
            let opts = arg(1);
            let resolver = resolver_of(opts);
            let r: KeyResolver<'_> = &resolver;
            let r = opts.get("resolveKey").is_some_and(|v| !v.is_null()).then_some(r);
            let cache = cache_of(opts.get("replayCache"));
            verify_signed_request_with_proof(arg(0), opts, r, cache.as_deref()).map(norm)
        }
        "contentDigestBytes" => content_digest_bytes(&body_of(arg(0)).ok()?, arg(1).as_str()?).map(|b| bytes_val(&b)),
        "contentDigestHeader" => content_digest_header(&body_of(arg(0)).ok()?, a.get(1)).map(Value::String),
        "verifyContentDigest" => {
            let header = match arg(0) {
                Value::Null => None,
                v => Some(v.as_str()?),
            };
            Ok(verify_content_digest(header, &body_of(arg(1)).ok()?, a.get(2)))
        }
        "parseContentDigest" => {
            parse_content_digest(arg(0).as_str()?).map(|m| Value::Object(m.into_iter().map(|(k, v)| (k, bytes_val(&v))).collect::<Map<String, Value>>()))
        }
        "parseKeyDirectory" => parse_key_directory(arg(0).as_str()?),
        "signDirectoryResponse" => sign_directory_response(arg(0), None),
        "verifyDirectoryResponse" => Ok(verify_directory_response(arg(0), None)),
        "fetchKeyDirectory" => Ok(fetch_run(arg(0).as_str()?, arg(1))),
        f => panic!("unknown fn {f}"),
    })
}

#[test]
fn webbotauth_vectors() {
    let cases = common::ref_cases_seeded("webbotauth");
    let (mut bad, mut skipped) = (Vec::new(), 0);
    for c in &cases {
        if common::has_lone(&c["args"]) {
            skipped += 1;
            continue;
        }
        let f = c["fn"].as_str().unwrap();
        let args = c["args"].as_array().unwrap();
        let throws = c["out"].get("$throws").is_some();
        let got = match std::panic::catch_unwind(|| run(f, args)) {
            Ok(Some(r)) => r,
            Ok(None) if throws => Err("unsupported argument".into()),
            Ok(None) => {
                skipped += 1;
                continue;
            }
            Err(_) => Err("panic".into()),
        };
        let ok = match (throws, &got) {
            (true, Err(_)) => true,
            (false, Ok(v)) => atlas_pca::canonicalize(&c["out"]) == atlas_pca::canonicalize(v),
            _ => false,
        };
        if !ok {
            bad.push(format!("{}\n  want {}\n  got  {got:?}", c["name"], c["out"]));
        }
    }
    assert!(skipped * 10 < cases.len(), "{skipped} cases skipped");
    assert!(bad.is_empty(), "{} of {} cases differ:\n{}", bad.len(), cases.len(), bad.join("\n"));
}

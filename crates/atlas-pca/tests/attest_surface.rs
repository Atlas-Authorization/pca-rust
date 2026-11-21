//! The small public helpers beside the hardware-attestation verifiers: suite labels, JWT parsers, JWKS fetchers over an injected transport,
//! the PCS issuer-chain header decoder, the TD report reader, the P-256 key reader and the default tpm2-tools runner.
use atlas_pca::attest::surface::*;
use atlas_pca::serde_json::{json, Value};
use base64::Engine;

fn b64u(b: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
}

fn token(header: &Value, payload: &Value, sig: &[u8]) -> String {
    format!("{}.{}.{}", b64u(header.to_string().as_bytes()), b64u(payload.to_string().as_bytes()), b64u(sig))
}

#[test]
fn labels_and_statuses() {
    assert_eq!(INTEL_DCAP_SUITE, "intel-tdx-dcap-ecdsa-p256");
    assert_eq!(AZURE_MAA_SUITE, "azure-maa-jwt");
    assert_eq!(AZURE_MAA_SUITES, ["ES256", "RS256"]);
    assert_eq!(GCP_CS_SUITE, "gcp-confidential-space-jwt");
    assert_eq!(GCP_CS_SUITES, ["RS256", "ES256"]);
    assert_eq!(DEFAULT_ACCEPTED_STATUSES, ["UpToDate", "SWHardeningNeeded"]);
}

#[test]
fn jwt_parsers_read_and_refuse() {
    let t = token(&json!({"alg": "RS256", "kid": "k1", "x5c": ["AAAA"]}), &json!({"iss": "https://x"}), b"sig");
    let j = parse_maa_jwt(&t).unwrap();
    assert_eq!((j.alg.as_str(), j.kid.as_deref()), ("RS256", Some("k1")));
    assert_eq!(j.x5c, Some(vec!["AAAA".to_string()]));
    assert_eq!(j.payload["iss"], "https://x");
    assert_eq!(j.signature, b"sig");
    assert_eq!(j.signing_input, t.rsplit_once('.').unwrap().0.as_bytes());
    assert_eq!(parse_gcp_cs_jwt(&t).unwrap().alg, "RS256");
    assert_eq!(parse_maa_jwt("").unwrap_err(), "parseMaaJwt: empty token");
    assert_eq!(parse_gcp_cs_jwt("a.b").unwrap_err(), "parseGcpCsJwt: a compact JWS has exactly three dot-separated parts");
    assert_eq!(parse_maa_jwt("a..c").unwrap_err(), "parseMaaJwt: empty JWS segment");
    assert!(parse_maa_jwt(&token(&json!({}), &json!({}), b"s")).unwrap_err().starts_with("parseMaaJwt: header has no alg"));
}

#[test]
fn jwks_fetchers_use_the_injected_transport_only() {
    let jwks = json!({"keys": [{"kid": "a", "kty": 7, "alg": "RS256", "x5c": ["QQ"], "n": "nn"}, "junk", {"x5c": [1]}]}).to_string();
    let seen = std::cell::RefCell::new(Vec::new());
    let fetch = |u: &str| -> Result<(u16, String), String> {
        seen.borrow_mut().push(u.to_string());
        Ok((200, jwks.clone()))
    };
    let r = fetch_maa_jwks("https://maa.example//", &fetch, None).unwrap();
    assert_eq!(r, json!({"keys": [{"kid": "a", "alg": "RS256", "x5c": ["QQ"]}, {}]}));
    assert_eq!(seen.borrow().as_slice(), ["https://maa.example/certs"]);
    let r = fetch_gcp_confidential_space_jwks("https://g.example", &fetch, Some("https://g.example/keys")).unwrap();
    assert_eq!(r["keys"][0]["n"], "nn");
    let conf = |u: &str| -> Result<(u16, String), String> {
        Ok(if u.ends_with("/.well-known/openid-configuration") { (200, json!({"jwks_uri": "https://g.example/j"}).to_string()) } else { (200, jwks.clone()) })
    };
    assert!(fetch_gcp_confidential_space_jwks("https://g.example/", &conf, None).is_ok());
    let down = |_: &str| -> Result<(u16, String), String> { Ok((503, String::new())) };
    assert_eq!(fetch_maa_jwks("https://m", &down, Some("/c")).unwrap_err(), "MAA JWKS fetch failed: HTTP 503 for https://m/c");
    let none = |_: &str| -> Result<(u16, String), String> { Ok((200, "{}".into())) };
    assert!(fetch_maa_jwks("https://m", &none, None).unwrap_err().ends_with("response has no keys array"));
}

#[test]
fn issuer_chain_header_is_uri_decoded() {
    assert_eq!(decode_issuer_chain_header("-----BEGIN%20CERTIFICATE-----%0AMII%0A").unwrap(), "-----BEGIN CERTIFICATE-----\nMII\n");
    assert_eq!(decode_issuer_chain_header("%E2%82%AC").unwrap(), "\u{20ac}");
    assert!(decode_issuer_chain_header("%zz").is_err());
    assert!(decode_issuer_chain_header("%FF").is_err());
}

#[test]
fn td_report_fields_sit_at_their_offsets() {
    assert!(parse_dcap_td_report(&[0u8; 583]).unwrap_err().ends_with("(583 < 584)"));
    let mut body: Vec<u8> = (0..600).map(|i| (i % 251) as u8).collect();
    body[136] = 0xAA;
    body[520] = 0xBB;
    let r = parse_dcap_td_report(&body).unwrap();
    assert_eq!((r.mr_td[0], r.report_data[0], r.tee_tcb_svn.len(), r.raw.len()), (0xAA, 0xBB, 16, 584));
    assert_eq!((r.rtmr3.len(), r.td_attributes.len(), r.mr_signer_seam[0]), (48, 8, body[64]));
}

#[test]
fn p256_keys_are_validated_and_expanded() {
    // the generator point, compressed and uncompressed
    let g = hex("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296");
    let full = ecdsa_p256_public_key(&g).unwrap();
    assert_eq!((full.len(), full[0]), (65, 4));
    assert_eq!(ecdsa_p256_public_key(&full).unwrap(), full);
    let mut off = full.clone();
    off[64] ^= 1;
    assert!(ecdsa_p256_public_key(&off).is_err());
    assert!(ecdsa_p256_public_key(&[]).is_err());
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn the_default_runner_fails_closed() {
    let r = default_tpm_command_runner("/definitely/not/a/tpm2-tool", &[]);
    assert!(r.status.is_none() && r.error.as_deref().is_some_and(|e| e.starts_with("/definitely/not/a/tpm2-tool: ")));
    if cfg!(unix) {
        let ok = default_tpm_command_runner("/bin/sh", &["-c".into(), "printf abc".into()]);
        assert_eq!((ok.status, ok.stdout.as_deref(), ok.error), (Some(0), Some(&b"abc"[..]), None));
        let bad = default_tpm_command_runner("/bin/sh", &["-c".into(), "echo no >&2; exit 3".into()]);
        assert_eq!((bad.status, bad.stderr.as_deref().map(str::trim)), (Some(3), Some("no")));
    }
}

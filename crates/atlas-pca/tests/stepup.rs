//! Step-up client: the device key (RFC 8032 vector, import / export), the ISO time reader, and the list / approve / deny
//! flow against a scripted transport (URLs, headers, bodies, error mapping).
use std::sync::{Arc, Mutex};

use atlas_pca::stepup::*;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::{json, Value};

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap()).collect()
}

fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

fn verify(pub_b64: &str, msg: &[u8], sig_b64: &str) -> bool {
    let pk: [u8; 32] = URL_SAFE_NO_PAD.decode(pub_b64).unwrap().try_into().unwrap();
    let sig: [u8; 64] = URL_SAFE_NO_PAD.decode(sig_b64).unwrap().try_into().unwrap();
    VerifyingKey::from_bytes(&pk).unwrap().verify(msg, &Signature::from_bytes(&sig)).is_ok()
}

fn key_from(seed: [u8; 32]) -> (PrincipalDeviceKey, String) {
    let k = PrincipalDeviceKey::new(InMemorySecretStore::new());
    let pubk = k.generate_with(|b| *b = seed).unwrap();
    (k, pubk)
}

#[test]
fn rfc8032_vector_1_and_import_export() {
    let seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let k = PrincipalDeviceKey::new(InMemorySecretStore::new());
    assert!(!k.exists());
    let pubk = k.import_secret(&b64(&seed)).unwrap();
    assert!(k.exists());
    assert_eq!(URL_SAFE_NO_PAD.decode(&pubk).unwrap(), hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"));
    assert_eq!(
        URL_SAFE_NO_PAD.decode(k.sign(b"").unwrap()).unwrap(),
        hex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    );
    let k2 = PrincipalDeviceKey::new(InMemorySecretStore::new());
    assert_eq!(k2.import_secret(&k.export_secret().unwrap()).unwrap(), pubk);
    assert_eq!(k2.public_key().unwrap(), pubk);
    k2.delete().unwrap();
    assert!(!k2.exists());
}

#[test]
fn bad_secrets_and_missing_keys_fail_closed() {
    let k = PrincipalDeviceKey::new(InMemorySecretStore::new());
    assert_eq!(k.sign(b"m"), Err(StepUpError::NoDeviceKey));
    assert_eq!(k.public_key(), Err(StepUpError::NoDeviceKey));
    let bad_secrets: Vec<String> = vec!["AAAA".into(), String::new(), b64(&[1u8; 31]), b64(&[1u8; 33]), "not base64 !!".into()];
    for bad in &bad_secrets {
        assert_eq!(k.import_secret(bad), Err(StepUpError::InvalidSecret), "{bad}");
    }
    assert!(!k.exists());
    // an all-zero fill is a broken random source, never a key
    assert_eq!(k.generate_with(|_| {}), Err(StepUpError::InvalidSecret));
    assert!(!k.exists());
}

#[test]
fn iso_times_are_read_as_utc_milliseconds() {
    assert_eq!(parse_iso_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_iso_ms("1970-01-01T00:00:01.5Z"), Some(1500));
    assert_eq!(parse_iso_ms("2000-03-01T00:00:00.123456Z"), Some(951_868_800_123));
    assert_eq!(parse_iso_ms("2026-10-06T18:00:00.000Z"), Some(1_791_309_600_000));
    assert_eq!(parse_iso_ms("1969-12-31T23:59:59.999Z"), Some(-1));
    for bad in ["", "yesterday", "2026-13-01T00:00:00Z", "2026-10-06 18:00:00Z", "2026-10-06T18:00:00.Z", "2026-1x-06T18:00:00Z"] {
        assert_eq!(parse_iso_ms(bad), None, "{bad}");
    }
}

struct Script {
    seen: Mutex<Vec<HttpRequest>>,
    replies: Mutex<Vec<Result<HttpResponse, String>>>,
}

impl StepUpTransport for Script {
    fn send(&self, request: HttpRequest) -> Result<HttpResponse, String> {
        self.seen.lock().unwrap().push(request);
        self.replies.lock().unwrap().remove(0)
    }
}

fn script(replies: Vec<Result<HttpResponse, String>>) -> Arc<Script> {
    Arc::new(Script { seen: Mutex::new(Vec::new()), replies: Mutex::new(replies) })
}

fn ok(status: u16, body: Value) -> Result<HttpResponse, String> {
    Ok(HttpResponse { status, body: body.to_string() })
}

const NOW: i64 = 1_791_309_600_000; // 2026-10-06T18:00:00Z

fn client(t: &Arc<Script>, key: PrincipalDeviceKey) -> StepUpClient {
    StepUpClient::new("https://dash.example/", "https://atlas.example", "acc 1", "ins", key, || "dsk_x".to_string(), t.clone()).with_clock(|| NOW)
}

#[test]
fn list_approve_deny() {
    let (key, pubk) = key_from([7u8; 32]);
    let msg = [1u8, 2, 3, 250, 251];
    let t = script(vec![
        ok(
            200,
            json!({"stepups": [
                {"id": "su_1", "grant_ref": "g1", "action": {"verb": "pay", "resource": "order/1"}, "required_t": 3, "threshold_message": b64(&msg), "expires_at": "2026-10-06T18:10:00.000Z", "status": "pending"},
                {"id": "old", "grant_ref": "g", "action": {"verb": "v", "resource": "r"}, "required_t": 3, "threshold_message": "AA", "expires_at": "2001-01-01T00:00:00.000Z", "status": "pending"}
            ]}),
        ),
        ok(200, json!({"status": "approved", "allow": true})),
        ok(200, json!({})),
    ]);
    let c = client(&t, key);
    let items = c.pending().unwrap();
    assert_eq!(items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(), ["su_1"]);
    assert_eq!((items[0].summary(), items[0].required_t, items[0].expires_at), ("pay on order/1".to_string(), 3, NOW + 600_000));

    let r = c.approve(&items[0]).unwrap();
    assert_eq!(r, ApproveResult { status: "approved".into(), anchored: true, http_status: 200 });
    c.deny(&items[0], Some("no")).unwrap();

    let seen = t.seen.lock().unwrap();
    assert_eq!(seen[0].method, "GET");
    assert_eq!(seen[0].url, "https://dash.example/v1/dashboard/accounts/acc%201/instances/ins/pca/stepups?status=pending");
    assert!(seen[0].headers.contains(&("Authorization".to_string(), "Bearer dsk_x".to_string())));
    assert_eq!((seen[1].method, seen[1].url.as_str()), ("POST", "https://atlas.example/v1/pca/stepups/su_1/cosign"));
    assert!(!seen[1].headers.iter().any(|(k, _)| k == "Authorization"), "the cosign route is self-authenticating: no dashboard token");
    let body: Value = serde_json::from_str(seen[1].body.as_deref().unwrap()).unwrap();
    assert_eq!((body["role"].as_str(), body["publicKey"].as_str()), (Some("principal"), Some(pubk.as_str())));
    assert!(verify(&pubk, &msg, body["sig"].as_str().unwrap()));
    assert_eq!(seen[2].url, "https://dash.example/v1/dashboard/accounts/acc%201/instances/ins/pca/stepups/su_1/deny");
    assert_eq!(serde_json::from_str::<Value>(seen[2].body.as_deref().unwrap()).unwrap(), json!({"reason": "no"}));
}

#[test]
fn error_mapping() {
    let su = PendingStepUp {
        id: "s".into(),
        grant_ref: "g".into(),
        action_verb: "v".into(),
        action_resource: "r".into(),
        required_t: 3,
        threshold_message_b64u: "AAEC".into(),
        expires_at: 0,
    };
    let t = script(vec![
        ok(403, json!({"errors": [{"code": "forbidden", "message": "The share is not from this grant's principal key."}]})),
        ok(409, json!({"errors": [{"code": "conflict", "message": "already approved"}]})),
        Ok(HttpResponse { status: 502, body: "<html>".into() }),
        Err("connection refused".into()),
    ]);
    let (key, _) = key_from([9u8; 32]);
    let c = client(&t, key);
    assert_eq!(c.approve(&su), Err(StepUpError::PrincipalMismatch("The share is not from this grant's principal key.".into())));
    assert_eq!(c.approve(&su), Err(StepUpError::Api { status: 409, message: "already approved".into() }));
    assert_eq!(c.approve(&su), Err(StepUpError::Api { status: 502, message: "The request failed.".into() }));
    assert_eq!(c.approve(&su), Err(StepUpError::Transport("connection refused".into())));
    let bad = PendingStepUp { threshold_message_b64u: "a".into(), ..su };
    assert_eq!(c.approve(&bad), Err(StepUpError::InvalidThresholdMessage));
    // nothing was sent for the unreadable message
    assert_eq!(t.seen.lock().unwrap().len(), 4);
}

#[test]
fn an_unreadable_list_is_a_transport_error() {
    let t = script(vec![ok(200, json!({"nope": 1})), ok(200, json!({"stepups": [{"id": "x"}]}))]);
    let (key, _) = key_from([3u8; 32]);
    let c = client(&t, key);
    assert_eq!(c.pending(), Err(StepUpError::Transport("Unreadable step-up list.".into())));
    assert_eq!(c.pending(), Err(StepUpError::Transport("Unreadable step-up entry.".into())));
}

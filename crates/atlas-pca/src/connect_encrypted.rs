//! Envelope encryption for stored OAuth tokens (the vault's `EncryptedConnectionStore`). Every secret gets its own random data key
//! (DEK); the DEK is wrapped by a [`KeyWrapper`]: the local key ring [`LocalKeyWrapper`] or your KMS behind the same two methods.
//! The AAD binds the wrapped key to the exact connection and field, so a ciphertext copied to another connection or field fails
//! to open. Envelope: `pca1.<b64u key id>.<b64u wrapped DEK>.<b64u iv(12) | ciphertext | tag(16)>` (AES-256-GCM).
//!
//! Fails closed: a stored token that is not an envelope (a plaintext record, a downgrade), fails authentication, or was sealed
//! under an unknown key makes `get` return a `StoreError` that carries no detail from the failure.
use crate::connect::{store_error, ConnectionStore, VaultError};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use base64::alphabet::URL_SAFE;
use base64::engine::{general_purpose::GeneralPurpose, general_purpose::GeneralPurposeConfig, DecodePaddingMode};
use base64::Engine;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

const PREFIX: &str = "pca1";

fn engine() -> GeneralPurpose {
    GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new().with_encode_padding(false).with_decode_padding_mode(DecodePaddingMode::Indifferent).with_decode_allow_trailing_bits(true),
    )
}

fn b64u(b: &[u8]) -> String {
    engine().encode(b)
}

/// Node's `Buffer.from(s, 'base64url')` after the reference's `^[A-Za-z0-9_-]*$` gate (a lone trailing character is dropped).
fn unb64u(s: &str) -> Result<Vec<u8>, String> {
    if !s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-') {
        return Err("bad encoding".into());
    }
    let s = if s.len() % 4 == 1 { &s[..s.len() - 1] } else { s };
    engine().decode(s).map_err(|_| "bad encoding".to_string())
}

fn seal(key: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    let mut iv = [0u8; 12];
    getrandom::getrandom(&mut iv).map_err(|e| e.to_string())?;
    seal_with_iv(key, &iv, aad, plain)
}

fn seal_with_iv(key: &[u8], iv: &[u8; 12], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>, String> {
    let c = Aes256Gcm::new_from_slice(key).map_err(|_| "bad key".to_string())?;
    let ct = c.encrypt(Nonce::from_slice(iv), Payload { msg: plain, aad }).map_err(|_| "seal failed".to_string())?;
    let mut out = iv.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

fn open(key: &[u8], aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if sealed.len() < 12 + 16 {
        return Err("short ciphertext".into());
    }
    let c = Aes256Gcm::new_from_slice(key).map_err(|_| "bad key".to_string())?;
    c.decrypt(Nonce::from_slice(&sealed[..12]), Payload { msg: &sealed[12..], aad }).map_err(|_| "authentication failed".to_string())
}

/// Wraps and unwraps data keys (a local key ring, or a KMS: AWS KMS, GCP KMS, Vault transit).
pub trait KeyWrapper: Send + Sync {
    /// The key id the DEK was wrapped under, and the wrapped bytes.
    fn wrap(&self, dek: &[u8], aad: &[u8]) -> Result<(String, Vec<u8>), String>;
    fn unwrap(&self, key_id: &str, wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>, String>;
}

struct Ring {
    keys: HashMap<String, Vec<u8>>,
    active: String,
}

/// A key ring held in process memory. Rotation: add the new key under a new id and make it active; records written under old ids
/// still open until you remove the old key. For production keys implement [`KeyWrapper`] over a KMS. [`Self::destroy`] overwrites the
/// key bytes.
pub struct LocalKeyWrapper(Mutex<Ring>);

impl LocalKeyWrapper {
    pub fn new(keys: &[(&str, &[u8])], active_id: &str) -> Result<Self, String> {
        let mut r = Ring { keys: HashMap::new(), active: String::new() };
        for (id, k) in keys {
            add(&mut r, id, k)?;
        }
        if !r.keys.contains_key(active_id) {
            return Err("LocalKeyWrapper: the active key id is not in the key ring".into());
        }
        r.active = active_id.to_string();
        Ok(Self(Mutex::new(r)))
    }

    fn ring(&self) -> Result<std::sync::MutexGuard<'_, Ring>, String> {
        self.0.lock().map_err(|_| "key ring unavailable".to_string())
    }

    pub fn add_key(&self, id: &str, key: &[u8]) -> Result<(), String> {
        add(&mut *self.ring()?, id, key)
    }

    pub fn set_active(&self, id: &str) -> Result<(), String> {
        let mut r = self.ring()?;
        if !r.keys.contains_key(id) {
            return Err("LocalKeyWrapper: the active key id is not in the key ring".into());
        }
        r.active = id.to_string();
        Ok(())
    }

    pub fn remove_key(&self, id: &str) -> Result<(), String> {
        let mut r = self.ring()?;
        if id == r.active {
            return Err("LocalKeyWrapper: cannot remove the active key".into());
        }
        if let Some(mut k) = r.keys.remove(id) {
            k.zeroize();
        }
        Ok(())
    }

    pub fn destroy(&self) {
        if let Ok(mut r) = self.0.lock() {
            for k in r.keys.values_mut() {
                k.zeroize();
            }
            r.keys.clear();
        }
    }
}

fn add(r: &mut Ring, id: &str, key: &[u8]) -> Result<(), String> {
    if id.is_empty() {
        return Err("LocalKeyWrapper: key id must not be empty".into());
    }
    if key.len() != 32 {
        return Err("LocalKeyWrapper: keys must be 32 bytes".into());
    }
    r.keys.insert(id.to_string(), key.to_vec());
    Ok(())
}

impl KeyWrapper for LocalKeyWrapper {
    fn wrap(&self, dek: &[u8], aad: &[u8]) -> Result<(String, Vec<u8>), String> {
        let r = self.ring()?;
        let k = r.keys.get(&r.active).ok_or("no active key")?;
        Ok((r.active.clone(), seal(k, aad, dek)?))
    }

    fn unwrap(&self, key_id: &str, wrapped: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        let r = self.ring()?;
        open(r.keys.get(key_id).ok_or("unknown key id")?, aad, wrapped)
    }
}

fn str_of<'a>(v: &'a Value, k: &str) -> Result<&'a str, String> {
    v.get(k).and_then(Value::as_str).ok_or_else(|| format!("{k} must be a string"))
}

fn aad_for(key: &Value, field: &str) -> Result<Vec<u8>, String> {
    let parts = ["pca-connect/v1", field, str_of(key, "agentId")?, str_of(key, "provider")?, str_of(key, "connectionId")?];
    Ok(parts.iter().map(|p| format!("{}:{p}", p.len())).collect::<Vec<_>>().join("|").into_bytes())
}

fn encrypt_field(w: &dyn KeyWrapper, key: &Value, field: &str, plain: &Value) -> Result<String, String> {
    let plain = plain.as_str().ok_or("not a string")?;
    let aad = aad_for(key, field)?;
    let mut dek = [0u8; 32];
    getrandom::getrandom(&mut dek).map_err(|e| e.to_string())?;
    let out = (|| {
        let (key_id, wrapped) = w.wrap(&dek, &aad)?;
        let sealed = seal(&dek, &aad, plain.as_bytes())?;
        Ok([PREFIX.to_string(), b64u(key_id.as_bytes()), b64u(&wrapped), b64u(&sealed)].join("."))
    })();
    dek.zeroize();
    out
}

fn decrypt_field(w: &dyn KeyWrapper, key: &Value, field: &str, value: &Value) -> Result<String, String> {
    let value = value.as_str().ok_or("not an envelope")?;
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 4 || parts[0] != PREFIX {
        return Err("not an envelope".into());
    }
    let aad = aad_for(key, field)?;
    let kid = String::from_utf8_lossy(&unb64u(parts[1])?).into_owned();
    let mut dek = w.unwrap(&kid, &unb64u(parts[2])?, &aad)?;
    let out = open(&dek, &aad, &unb64u(parts[3])?).map(|b| String::from_utf8_lossy(&b).into_owned());
    dek.zeroize();
    out
}

/// Wraps any [`ConnectionStore`] so `accessToken` and `refreshToken` are encrypted before they reach it. Everything else in a record
/// stays readable so the inner store can index and expire it.
pub struct EncryptedConnectionStore {
    inner: Arc<dyn ConnectionStore>,
    wrapper: Arc<dyn KeyWrapper>,
}

impl EncryptedConnectionStore {
    pub fn new(inner: Arc<dyn ConnectionStore>, wrapper: Arc<dyn KeyWrapper>) -> Self {
        Self { inner, wrapper }
    }

    fn open_record(&self, raw: &Value, key: &Value) -> Result<Value, String> {
        let k = serde_json::json!({ "agentId": raw.get("agentId"), "provider": raw.get("provider"), "connectionId": raw.get("connectionId") });
        for f in ["agentId", "provider", "connectionId"] {
            if k.get(f) != key.get(f) || !k.get(f).is_some_and(Value::is_string) {
                return Err("record key mismatch".into());
            }
        }
        let mut out = raw.clone();
        out["accessToken"] = Value::String(decrypt_field(&*self.wrapper, &k, "access", raw.get("accessToken").unwrap_or(&Value::Null))?);
        if let Some(rt) = raw.get("refreshToken") {
            out["refreshToken"] = Value::String(decrypt_field(&*self.wrapper, &k, "refresh", rt)?);
        }
        Ok(out)
    }

    /// Re-encrypt one record under the wrapper's active key (run after rotating the key ring).
    pub fn reencrypt(&self, key: &Value) -> Result<bool, VaultError> {
        match self.get(key)? {
            None => Ok(false),
            Some(c) => self.set(&c).map(|_| true),
        }
    }
}

impl ConnectionStore for EncryptedConnectionStore {
    fn get(&self, key: &Value) -> Result<Option<Value>, VaultError> {
        let Some(raw) = self.inner.get(key)? else { return Ok(None) };
        self.open_record(&raw, key).map(Some).map_err(|_| store_error("a stored token could not be decrypted"))
    }

    fn set(&self, connection: &Value) -> Result<(), VaultError> {
        let sealed = (|| {
            let k = serde_json::json!({ "agentId": connection.get("agentId"), "provider": connection.get("provider"), "connectionId": connection.get("connectionId") });
            let mut out = connection.clone();
            out["accessToken"] = Value::String(encrypt_field(&*self.wrapper, &k, "access", connection.get("accessToken").unwrap_or(&Value::Null))?);
            if let Some(rt) = connection.get("refreshToken") {
                out["refreshToken"] = Value::String(encrypt_field(&*self.wrapper, &k, "refresh", rt)?);
            }
            Ok::<Value, String>(out)
        })()
        .map_err(|_| store_error("a token could not be encrypted; nothing was stored"))?;
        self.inner.set(&sealed)
    }

    fn delete(&self, key: &Value) -> Result<(), VaultError> {
        self.inner.delete(key)
    }

    fn encrypted(&self) -> bool {
        true
    }
}

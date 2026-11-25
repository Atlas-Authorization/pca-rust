//! Crash-safe, tamper-evident, multi-process-safe persistent key/value state (Unix only: it needs link(2), fsync and
//! kill(pid, 0)). A faithful port of the reference durable store.
//!
//! WHY: rollback protection for signed allowlist manifests and key sets is only as good as the persistence of "the
//! highest thing I ever accepted". This module is that persistence.
//!
//! LAYOUT (a directory you own, mode 0700): `state.journal` (hash-chained records, one JSON object per line),
//! `state.head` (seq + hash of the last record, written AFTER the journal), `state.lock.<g>` (the generation lock),
//! `state.fence*` (operator-recovery cuts).
//!
//! GUARANTEES (see the reference for the long form; the protocol here is identical, byte for byte on disk):
//! - CRASH SAFETY: every mutation is write-temp, fsync(file), rename, fsync(directory). The head trails the journal by at most one
//!   record and is repaired by the next writer.
//! - NO LOST UPDATES: every mutation runs under an exclusive lock made of immutable numbered generation files created
//!   with link(2); a lock is taken over only from a provably dead holder on this host and PID namespace, never by age; the
//!   generation is re-checked right before the journal rename and right before every head rename.
//! - FENCING AGAINST A PAUSED HOLDER: every record and the head carry the writer's lock generation; operator recovery
//!   ([`recover_durable_state`]) takes the lock, cuts and fences the released generation, then releases. On load a record
//!   below a fence that covers it, below an earlier record's generation, or below the generation that wrote the head is refused
//!   (`corrupt`); a stale late head is recognised and repaired.
//! - TAMPER / TRUNCATION EVIDENCE: records are hash-chained; truncation or an older copy is caught by the head and by the
//!   highest (seq, hash) this handle has seen; with an HMAC key every record and the head are tagged.
//! - FAIL CLOSED: corrupt / rolled-back state makes every operation fail with a [`DurableStateError`]; the only way past is
//!   the explicit `recover_from_corruption` option, which quarantines the files (never deletes) and starts from genesis.
//!
//! NOT GUARANTEED: one host and one PID namespace per directory; a LOCAL filesystem with working hard links (the open
//! probes it and fails with `link-unsupported`); a stalled live holder blocks until it dies (waiters fail with
//! `lock-timeout`). Do not downgrade a directory to an older version.
//!
//! Differences from the reference that are forced by Rust: the API is synchronous; an I/O failure the reference lets escape as a
//! raw exception is a [`DurableStateErrorCode::Io`] error here; a value is a `serde_json::Value` (always serialisable).

use std::collections::HashMap;
use std::ffi::{c_char, c_int};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

extern "C" {
    fn gethostname(name: *mut c_char, len: usize) -> c_int;
    fn kill(pid: c_int, sig: c_int) -> c_int;
    fn getpid() -> c_int;
}

/// The failure classes of the store (the reference's `DurableStateErrorCode`, plus `Io`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DurableStateErrorCode {
    Corrupt,
    Rollback,
    LockTimeout,
    LockLost,
    LinkUnsupported,
    KeyMismatch,
    Invalid,
    TooLarge,
    /// An operating-system error the reference lets escape as a raw exception.
    Io,
}

impl DurableStateErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Corrupt => "corrupt",
            Self::Rollback => "rollback",
            Self::LockTimeout => "lock-timeout",
            Self::LockLost => "lock-lost",
            Self::LinkUnsupported => "link-unsupported",
            Self::KeyMismatch => "key-mismatch",
            Self::Invalid => "invalid",
            Self::TooLarge => "too-large",
            Self::Io => "io",
        }
    }
}

/// An error of the durable store. `message` is the full text, `"<code>: <detail>"`, exactly as the reference formats it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableStateError {
    pub code: DurableStateErrorCode,
    pub message: String,
}

impl DurableStateError {
    pub fn new(code: DurableStateErrorCode, detail: impl AsRef<str>) -> Self {
        Self { code, message: format!("{}: {}", code.as_str(), detail.as_ref()) }
    }
}

impl std::fmt::Display for DurableStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for DurableStateError {}

type Res<T> = Result<T, DurableStateError>;
use DurableStateErrorCode as C;

fn err<T>(code: C, detail: impl AsRef<str>) -> Res<T> {
    Err(DurableStateError::new(code, detail))
}

fn io<T>(r: std::io::Result<T>) -> Res<T> {
    r.map_err(|e| DurableStateError::new(C::Io, e.to_string()))
}

/// The persistence interface the allowlist / key-trust modules use. Values must be JSON-serialisable.
pub trait DurableKv: Send + Sync {
    fn get(&self, key: &str) -> Res<Option<Value>>;
    /// Unconditional write (still serialised and hash-chained). Prefer `update` for monotone state.
    fn set(&self, key: &str, value: &Value) -> Res<()>;
    /// Atomic read-modify-write: `f` receives the current value and returns the next, or `None` to leave the key unchanged.
    /// Returns the value now stored. `f` runs under the cross-process lock and must be quick.
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<Value>) -> Option<Value>) -> Res<Option<Value>>;
    fn keys(&self) -> Res<Vec<String>>;
}

/// JavaScript's default string order (UTF-16 code units), which the reference's `sort()` and key comparator use.
fn cmp16(a: &str, b: &str) -> std::cmp::Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// In-memory implementation (tests / single process): the same semantics, no durability.
#[derive(Default)]
pub struct MemoryDurableKv {
    m: Mutex<HashMap<String, String>>,
}

pub fn create_memory_durable_kv() -> MemoryDurableKv {
    MemoryDurableKv::default()
}

impl MemoryDurableKv {
    pub fn snapshot(&self) -> HashMap<String, Value> {
        let m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        m.iter().map(|(k, v)| (k.clone(), serde_json::from_str(v).unwrap_or(Value::Null))).collect()
    }
}

impl DurableKv for MemoryDurableKv {
    fn get(&self, key: &str) -> Res<Option<Value>> {
        let m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        Ok(m.get(key).map(|s| serde_json::from_str(s).unwrap_or(Value::Null)))
    }
    fn set(&self, key: &str, value: &Value) -> Res<()> {
        let s = serde_json::to_string(value).map_err(|_| DurableStateError::new(C::Invalid, "value is not JSON-serialisable"))?;
        self.m.lock().unwrap_or_else(|e| e.into_inner()).insert(key.to_string(), s);
        Ok(())
    }
    fn update(&self, key: &str, f: &mut dyn FnMut(Option<Value>) -> Option<Value>) -> Res<Option<Value>> {
        let mut m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        let cur = m.get(key).map(|s| serde_json::from_str(s).unwrap_or(Value::Null));
        if let Some(next) = f(cur) {
            let s = serde_json::to_string(&next).map_err(|_| DurableStateError::new(C::Invalid, "value is not JSON-serialisable"))?;
            m.insert(key.to_string(), s);
        }
        Ok(m.get(key).map(|s| serde_json::from_str(s).unwrap_or(Value::Null)))
    }
    fn keys(&self) -> Res<Vec<String>> {
        let m = self.m.lock().unwrap_or_else(|e| e.into_inner());
        let mut k: Vec<String> = m.keys().cloned().collect();
        k.sort_by(|a, b| cmp16(a, b));
        Ok(k)
    }
}

/// TEST ONLY: SIGKILL this process at the named point of a commit, to prove crash safety.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashAt {
    AfterTempWrite,
    AfterJournalRename,
}

pub struct DurableStateOptions {
    /// Directory holding the state (created 0700 if missing).
    pub dir: PathBuf,
    /// Optional >= 32-byte HMAC key: records and head are tagged; forging or re-chaining then needs the key.
    pub hmac_key: Option<Vec<u8>>,
    /// Explicit recovery: quarantine corrupt / rolled-back files and start from genesis. Default false (fail closed).
    pub recover_from_corruption: bool,
    /// Give up acquiring the lock after this long (default 10 s).
    pub lock_timeout_ms: Option<i64>,
    /// Compact the journal into a checkpoint every N records (default 256, minimum 2).
    pub compact_every: Option<i64>,
    /// Max serialised value size in UTF-16 code units (default 1 MiB).
    pub max_value_bytes: Option<usize>,
    /// Clock for record timestamps (default: milliseconds since the epoch).
    pub now: Option<Box<dyn Fn() -> i64 + Send + Sync>>,
    /// TEST ONLY.
    pub test_crash_at: Option<CrashAt>,
}

impl DurableStateOptions {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            hmac_key: None,
            recover_from_corruption: false,
            lock_timeout_ms: None,
            compact_every: None,
            max_value_bytes: None,
            now: None,
            test_crash_at: None,
        }
    }
}

/// The holder record of the lock file an operator has confirmed dead (copy it from the lock-timeout error / the `state.lock.N` file).
#[derive(Clone, Debug, PartialEq)]
pub struct ExpectedLockHolder {
    pub host: String,
    pub pid: f64,
    /// The per-acquisition nonce in the lock file: a match proves the operator looked at THIS lock.
    pub nonce: String,
}

impl ExpectedLockHolder {
    pub fn new(host: impl Into<String>, pid: i64, nonce: impl Into<String>) -> Self {
        Self { host: host.into(), pid: pid as f64, nonce: nonce.into() }
    }
}

/// The holder the operator attests is gone: a complete record copied exactly, or `Unreadable` for a top lock file that is
/// unreadable or INCOMPLETE. A complete record never accepts `Unreadable`, an unreadable / incomplete one never accepts copied fields.
#[derive(Clone, Debug, PartialEq)]
pub enum ExpectedHolder {
    Unreadable,
    Holder(ExpectedLockHolder),
}

impl ExpectedHolder {
    /// Validate a dynamic value the way the reference does: the string `"unreadable"` or `{ host, pid, nonce }` with a non-empty nonce.
    pub fn from_value(v: &Value) -> Res<Self> {
        if v.as_str() == Some("unreadable") {
            return Ok(Self::Unreadable);
        }
        if let Value::Object(o) = v {
            if let (Some(Value::String(h)), Some(Value::Number(p)), Some(Value::String(n))) = (o.get("host"), o.get("pid"), o.get("nonce")) {
                if !n.is_empty() {
                    return Ok(Self::Holder(ExpectedLockHolder { host: h.clone(), pid: p.as_f64().unwrap_or(f64::NAN), nonce: n.clone() }));
                }
            }
        }
        err(C::Invalid, "expectedHolder must be { host, pid, nonce } as recorded in the lock file, or 'unreadable'")
    }
}

pub struct RecoverDurableStateOptions {
    pub dir: PathBuf,
    /// Must be `true`: this is an out-of-band operator action, never automatic.
    pub force: bool,
    pub expected_holder: ExpectedHolder,
    /// Release the LEGACY single-file `state.lock` of an older version (moved aside to `state.lock.legacy-recovered-<time>-<rand>`).
    pub legacy_lock: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoverDurableStateResult {
    pub released: bool,
    /// `not-held` or `released`.
    pub reason: &'static str,
    /// The lock file that was superseded.
    pub lock_file: Option<PathBuf>,
}

/// A fence: records after journal `seq` must come from lock generation >= `gen`; `h` is the hash of the record at `seq`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DurableFence {
    pub gen: i64,
    pub seq: i64,
    pub h: String,
}

/// The highest chain position a handle has observed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position {
    pub seq: i64,
    pub hash: String,
}

const FENCE_FILE: &str = "state.fence";
const DOMAIN: &str = "pca-durable-state/v1\n";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const MAX_KEY: usize = 256;
/// Honoured only with `PCA_DURABLE_TEST=1`: the point at which operator recovery (or the takeover of a crashed recovery) SIGKILLs itself.
pub const RECOVER_CRASH_ENV: &str = "PCA_DURABLE_TEST_RECOVER_CRASH_AT";
const MAX_SAFE: f64 = 9007199254740991.0;

// ------------------------------------------------------------------------------------------------------------------
// small helpers

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn rand_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    if getrandom::getrandom(&mut b).is_err() {
        // never reuse a name: fall back to the clock and the address of a local
        let t = now_ms().to_le_bytes();
        for (i, x) in b.iter_mut().enumerate() {
            *x = t[i % 8] ^ (i as u8).wrapping_mul(31);
        }
    }
    hex(&b)
}

fn sha(s: &str) -> String {
    hex(&Sha256::digest(s.as_bytes()))
}

fn is_hex64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn js(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

fn utf16_len(s: &str) -> usize {
    s.encode_utf16().count()
}

/// JavaScript `Number.isSafeInteger` over a parsed JSON value: `Some((integer, is_negative_zero))`.
fn safe_int(v: Option<&Value>) -> Option<(i64, bool)> {
    let n = match v? {
        Value::Number(n) => n,
        _ => return None,
    };
    if let Some(i) = n.as_i64() {
        return ((i as f64).abs() <= MAX_SAFE).then_some((i, false));
    }
    if let Some(u) = n.as_u64() {
        return ((u as f64) <= MAX_SAFE).then_some((u as i64, false));
    }
    let f = n.as_f64()?;
    (f.is_finite() && f.fract() == 0.0 && f.abs() <= MAX_SAFE).then_some((f as i64, f == 0.0 && f.is_sign_negative()))
}

fn is_gen(v: Option<&Value>) -> bool {
    matches!(safe_int(v), Some((g, _)) if g >= 1)
}

fn read_text(p: &Path) -> Res<String> {
    let mut b = Vec::new();
    io(io(File::open(p))?.read_to_end(&mut b))?;
    Ok(String::from_utf8_lossy(&b).into_owned())
}

fn exists(p: &Path) -> bool {
    p.exists()
}

fn mac_of(key: &[u8], msg: &str) -> String {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    m.update(msg.as_bytes());
    hex(&m.finalize().into_bytes())
}

fn mac_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn fsync_dir(dir: &Path) -> Res<()> {
    // a directory cannot be opened for a flush on Windows; the write-through rename (durable_rename) is the durable step there
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
    #[cfg(unix)]
    io(io(File::open(dir))?.sync_all())
}

fn errno_name(e: &std::io::Error) -> String {
    match e.raw_os_error() {
        Some(1) => "EPERM",
        Some(2) => "ENOENT",
        Some(5) => "EIO",
        Some(13) => "EACCES",
        Some(17) => "EEXIST",
        Some(18) => "EXDEV",
        Some(30) => "EROFS",
        Some(31) => "EMLINK",
        Some(38) | Some(78) => "ENOSYS",
        Some(45) | Some(95) => "ENOTSUP",
        _ => "error",
    }
    .to_string()
}

fn hostname() -> String {
    let mut buf = [0 as c_char; 256];
    // SAFETY: the buffer is 256 bytes and the length passed is 256.
    let rc = unsafe { gethostname(buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return String::new();
    }
    let bytes: Vec<u8> = buf.iter().take_while(|c| **c != 0).map(|c| *c as u8).collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn self_pid() -> i64 {
    // SAFETY: getpid has no preconditions.
    unsafe { getpid() as i64 }
}

/// kill(pid, 0): the process exists (or exists but is not ours: EPERM).
fn pid_alive(pid: f64) -> bool {
    if !(pid.fract() == 0.0 && pid.abs() <= i32::MAX as f64) {
        return false;
    }
    // SAFETY: signal 0 only probes.
    let rc = unsafe { kill(pid as c_int, 0) };
    rc == 0 || std::io::Error::last_os_error().raw_os_error() == Some(1)
}

fn boot_id() -> &'static str {
    static B: OnceLock<String> = OnceLock::new();
    B.get_or_init(|| rand_hex(12))
}

/// Process start time (field 22 of /proc/<pid>/stat), None off Linux or when gone.
fn proc_start_of(pid: f64) -> Option<String> {
    let st = read_text(Path::new(&format!("/proc/{}/stat", js_num(pid)))).ok()?;
    let at = st.rfind(')')? + 2;
    st.get(at..)?.split(' ').nth(19).map(|s| s.to_string())
}

fn my_ns() -> Option<String> {
    fs::read_link("/proc/self/ns/pid").ok().map(|p| p.to_string_lossy().into_owned())
}

/// A number as JavaScript prints it in a template string.
fn js_num(f: f64) -> String {
    if f.fract() == 0.0 && f.abs() < 1e21 {
        format!("{}", f as i128)
    } else {
        format!("{f}")
    }
}

fn kill_self_if(env_point: &str) {
    if std::env::var("PCA_DURABLE_TEST").as_deref() == Ok("1") && std::env::var(RECOVER_CRASH_ENV).as_deref() == Ok(env_point) {
        kill_self();
    }
}

fn kill_self() -> ! {
    // SAFETY: SIGKILL to this process only (the test-only crash hook).
    unsafe {
        kill(getpid(), 9);
    }
    // The kernel may deliver a self-sent SIGKILL on another thread (macOS): park so this thread can never run past the crash point.
    loop {
        std::thread::park();
    }
}

fn lock_name_gen(name: &str) -> Option<u64> {
    let d = name.strip_prefix("state.lock.")?;
    (!d.is_empty() && d.bytes().all(|c| c.is_ascii_digit())).then(|| d.parse::<u64>().unwrap_or(u64::MAX))
}

fn fence_entry(name: &str) -> Option<f64> {
    let rest = name.strip_prefix("state.fence.")?;
    let (g, tag) = rest.split_once('-')?;
    (!g.is_empty() && g.bytes().all(|c| c.is_ascii_digit()) && !tag.is_empty() && tag.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)))
        .then(|| g.parse::<f64>().unwrap_or(f64::MAX))
}

fn list_dir(dir: &Path) -> Res<Vec<String>> {
    let mut v = Vec::new();
    for e in io(fs::read_dir(dir))? {
        v.push(io(e)?.file_name().to_string_lossy().into_owned());
    }
    Ok(v)
}

// ------------------------------------------------------------------------------------------------------------------
// atomic file write

fn atomic_write(path: &Path, data: &str, crash_after_temp: bool, before_rename: Option<&dyn Fn() -> Res<()>>) -> Res<()> {
    let tmp = PathBuf::from(format!("{}.tmp-{}-{}", path.display(), self_pid(), rand_hex(6)));
    {
        let mut f = io(OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp))?;
        io(f.write_all(data.as_bytes()))?;
        io(f.sync_all())?;
    }
    if crash_after_temp {
        kill_self();
    }
    if let Some(b) = before_rename {
        if let Err(e) = b() {
            let _ = fs::remove_file(&tmp); // best effort: the orphan temp is harmless
            return Err(e);
        }
    }
    io(crate::durable_rename::replace_file(&tmp, path))?;
    fsync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
}

// ------------------------------------------------------------------------------------------------------------------
// fences

fn parse_fence(f: &Value, whence: &str) -> Res<DurableFence> {
    let bad = || DurableStateError::new(C::Corrupt, format!("{whence} has an invalid entry"));
    let o = f.as_object().ok_or_else(bad)?;
    let gen = safe_int(o.get("gen")).filter(|(g, _)| *g >= 1).ok_or_else(bad)?.0;
    let (seq, nz) = safe_int(o.get("seq")).filter(|(s, _)| *s >= 0).ok_or_else(bad)?;
    let h = o.get("h").and_then(|h| h.as_str()).filter(|h| is_hex64(h)).ok_or_else(bad)?;
    if nz {
        return Err(bad());
    }
    Ok(DurableFence { gen, seq, h: h.to_string() })
}

/// Every fence: the list in `state.fence` (absent = none) then each `state.fence.<gen>-<rand>` by generation. Malformed = `corrupt`.
pub fn read_fences(dir: &Path) -> Res<Vec<DurableFence>> {
    let mut out = Vec::new();
    let p = dir.join(FENCE_FILE);
    if exists(&p) {
        let o: Value = serde_json::from_str(&read_text(&p)?).map_err(|_| DurableStateError::new(C::Corrupt, "state.fence is not valid JSON"))?;
        let v1 = matches!(o.get("v").and_then(|v| v.as_f64()), Some(x) if x == 1.0);
        let fences = match (&o, v1) {
            (Value::Object(r), true) => r.get("fences").and_then(|f| f.as_array()),
            _ => None,
        };
        let fences = fences.ok_or_else(|| DurableStateError::new(C::Corrupt, "state.fence has an invalid shape"))?;
        for f in fences {
            out.push(parse_fence(f, "state.fence")?);
        }
    }
    let mut entries: Vec<(String, f64)> = list_dir(dir)?.into_iter().filter_map(|n| fence_entry(&n).map(|g| (n, g))).collect();
    entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal).then_with(|| a.0.cmp(&b.0)));
    for (name, gen) in entries {
        let o: Value =
            serde_json::from_str(&read_text(&dir.join(&name))?).map_err(|_| DurableStateError::new(C::Corrupt, format!("{name} is not valid JSON")))?;
        let v1 = matches!(o.get("v").and_then(|v| v.as_f64()), Some(x) if x == 1.0);
        if !o.is_object() || !v1 {
            return err(C::Corrupt, format!("{name} has an invalid shape"));
        }
        let f = parse_fence(o.get("fence").unwrap_or(&Value::Null), &name)?;
        if f.gen as f64 != gen {
            return err(C::Corrupt, format!("{name} names generation {} but holds {}", js_num(gen), f.gen));
        }
        out.push(f);
    }
    Ok(out)
}

/// (seq, hash) of the last journal record as it is on disk right now; absent or unparsable gives (0, zeros).
fn journal_tail(dir: &Path) -> (i64, String) {
    let none = (0, GENESIS.to_string());
    let Ok(text) = read_text(&dir.join("state.journal")) else { return none };
    let Some(last) = text.split('\n').filter(|l| !l.is_empty()).last() else { return none };
    let Ok(o) = serde_json::from_str::<Value>(last) else { return none };
    match (safe_int(o.get("seq")), o.get("h").and_then(|h| h.as_str())) {
        (Some((s, _)), Some(h)) if s >= 1 && is_hex64(h) => (s, h.to_string()),
        _ => none,
    }
}

/// The operator's CUT: called while recovery itself holds generation g+1.
fn write_fence(dir: &Path, g: i64, before_rename: Option<&dyn Fn() -> Res<()>>) -> Res<()> {
    read_fences(dir)?; // an unreadable fence set fails closed here too, before anything new is written
    let (seq, h) = journal_tail(dir);
    let fence = format!("{{\"gen\":{},\"seq\":{},\"h\":{},\"from\":{},\"t\":{}}}", g + 1, seq, js(&h), g, now_ms());
    let path = dir.join(format!("{FENCE_FILE}.{}-{}", g + 1, rand_hex(6)));
    atomic_write(&path, &format!("{{\"v\":1,\"fence\":{fence}}}\n"), false, before_rename)
}

// ------------------------------------------------------------------------------------------------------------------
// lock files

#[derive(Clone, Debug, Default)]
struct LockBody {
    held: bool,
    pid: Option<f64>,
    host: Option<String>,
    nonce: Option<String>,
    start: Option<String>,
    ns: Option<String>,
    recovering: Option<i64>,
}

fn read_body(path: &Path) -> Option<LockBody> {
    let o: Value = serde_json::from_str(&read_text(path).ok()?).ok()?;
    if o.is_null() || !(o.is_object() || o.is_array()) {
        return None;
    }
    let g = |k: &str| o.get(k);
    Some(LockBody {
        held: g("st").and_then(|s| s.as_str()) != Some("free"),
        pid: g("pid").and_then(|p| p.as_f64()),
        host: g("host").and_then(|s| s.as_str()).map(String::from),
        nonce: g("nonce").and_then(|s| s.as_str()).map(String::from),
        start: g("start").and_then(|s| s.as_str()).map(String::from),
        ns: g("ns").and_then(|s| s.as_str()).map(String::from),
        recovering: safe_int(g("recovering")).map(|x| x.0),
    })
}

/// The part of a holder record that liveness is judged from.
struct HolderView {
    pid: Option<f64>,
    host: Option<String>,
    ns: Option<String>,
    start: Option<String>,
}

/// Is the recorded holder demonstrably ALIVE here? Judged by PID-namespace identity when the record names one, else by hostname.
fn holder_alive_here(b: &HolderView) -> bool {
    let Some(pid) = b.pid else { return false };
    let ns_now = my_ns();
    let judgeable = match &b.ns {
        Some(ns) => ns_now.as_deref() == Some(ns.as_str()),
        None => b.host.as_deref() == Some(hostname().as_str()),
    };
    if !judgeable || !pid_alive(pid) {
        return false;
    }
    if let Some(start) = &b.start {
        if let Ok(st) = read_text(Path::new(&format!("/proc/{}/stat", js_num(pid)))) {
            if let Some(at) = st.rfind(')') {
                if let Some(cur) = st.get(at + 2..).and_then(|s| s.split(' ').nth(19)) {
                    if cur != start {
                        return false; // the pid was reused by a different process
                    }
                }
            }
        }
    }
    true
}

enum Classified {
    Unreadable,
    Free,
    Incomplete(Value),
    Complete(LockBody, Value),
}

/// A holder record is COMPLETE only with a numeric pid, a host and a non-empty nonce; JSON that is not a plain object is unreadable.
fn classify_lock_file(path: &Path) -> Classified {
    let Some(o) = read_text(path).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok()) else { return Classified::Unreadable };
    match &o {
        Value::Object(r) => {
            if r.get("st").and_then(|s| s.as_str()) == Some("free") {
                return Classified::Free;
            }
            let complete = r.get("pid").is_some_and(|p| p.is_number())
                && r.get("host").is_some_and(|h| h.is_string())
                && r.get("nonce").and_then(|n| n.as_str()).is_some_and(|n| !n.is_empty());
            if complete {
                let body = read_body(path).unwrap_or_default();
                Classified::Complete(body, o.clone())
            } else {
                Classified::Incomplete(o.clone())
            }
        }
        Value::Array(_) => Classified::Incomplete(o.clone()),
        _ => Classified::Unreadable,
    }
}

fn view_of_value(v: &Value) -> HolderView {
    HolderView {
        pid: v.get("pid").and_then(|p| p.as_f64()),
        host: v.get("host").and_then(|s| s.as_str()).map(String::from),
        ns: v.get("ns").and_then(|s| s.as_str()).map(String::from),
        start: v.get("start").and_then(|s| s.as_str()).map(String::from),
    }
}

fn slice16(s: &str, n: usize) -> String {
    let mut used = 0;
    let mut out = String::new();
    for c in s.chars() {
        used += c.len_utf16();
        if used > n {
            break;
        }
        out.push(c);
    }
    out
}

fn confirm_holder(c: &Classified, exp: &ExpectedHolder, path: &Path) -> Res<()> {
    let p = path.display();
    match c {
        Classified::Unreadable => {
            if !matches!(exp, ExpectedHolder::Unreadable) {
                return err(C::Invalid, format!("{p} is unreadable; pass expectedHolder: 'unreadable' to release it"));
            }
            Ok(())
        }
        Classified::Incomplete(raw) => {
            if !matches!(exp, ExpectedHolder::Unreadable) {
                return err(
                    C::Invalid,
                    format!(
                        "{p} has an incomplete holder record ({}); after confirming its holder is gone, pass expectedHolder: 'unreadable' to release it",
                        slice16(&serde_json::to_string(raw).unwrap_or_default(), 160)
                    ),
                );
            }
            if holder_alive_here(&view_of_value(raw)) {
                let pid = raw.get("pid").map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                });
                return err(
                    C::Invalid,
                    format!(
                        "the holder of {p} (pid {}) is alive in this PID namespace; refusing to release a live holder",
                        pid.unwrap_or_else(|| "undefined".into())
                    ),
                );
            }
            Ok(())
        }
        Classified::Free => Ok(()),
        Classified::Complete(body, _) => {
            let pid = body.pid.unwrap_or(f64::NAN);
            let host = body.host.clone().unwrap_or_default();
            let nonce = body.nonce.clone().unwrap_or_default();
            let ExpectedHolder::Holder(e) = exp else {
                return err(C::Invalid, format!("{p} is readable (holder pid={} host={host}); expectedHolder 'unreadable' does not match", js_num(pid)));
            };
            if host != e.host || pid != e.pid || nonce != e.nonce {
                return err(
                    C::Invalid,
                    format!(
                        "expectedHolder does not match the holder recorded in {p} (recorded pid={} host={host} nonce={nonce}); nothing was changed",
                        js_num(pid)
                    ),
                );
            }
            let view = HolderView { pid: body.pid, host: body.host.clone(), ns: body.ns.clone(), start: body.start.clone() };
            if holder_alive_here(&view) {
                return err(C::Invalid, format!("the holder of {p} (pid {}) is alive in this PID namespace; refusing to release a live holder", js_num(pid)));
            }
            Ok(())
        }
    }
}

fn top_gen_in(dir: &Path) -> Res<u64> {
    Ok(list_dir(dir)?.iter().filter_map(|f| lock_name_gen(f)).max().unwrap_or(0))
}

/// Operator recovery for a lock whose holder cannot be judged dead automatically (another PID namespace, a changed hostname,
/// an unreadable or incomplete top lock file, or a legacy single-file `state.lock`).
///
/// The order matters (formal model DurableFence): TAKE the lock as generation g+1 (EEXIST: the holder released, abort), CUT (read
/// the journal tail under that lock), FENCE (records after the cut need generation >= g+1), RELEASE (generation g+2 "free").
/// Recovery may itself crash after any step; its lock is marked `recovering`, so whoever takes it over cuts and fences first.
pub fn recover_durable_state(opts: &RecoverDurableStateOptions) -> Res<RecoverDurableStateResult> {
    if !opts.force {
        return err(C::Invalid, "recoverDurableState requires force: true");
    }
    let exp = &opts.expected_holder;
    let dir = opts.dir.as_path();
    let g = top_gen_in(dir)?;
    let path = dir.join(format!("state.lock.{g}"));
    let top = (g != 0).then(|| classify_lock_file(&path));
    let legacy_path = dir.join("state.lock");
    let not_held = |f: Option<PathBuf>| RecoverDurableStateResult { released: false, reason: "not-held", lock_file: f };
    if opts.legacy_lock {
        if let Some(t) = &top {
            if !matches!(t, Classified::Free) {
                return err(
                    C::Invalid,
                    format!("legacyLock: true, but the blocking lock is the generation lock {}; call recoverDurableState without legacyLock", path.display()),
                );
            }
        }
        if !exists(&legacy_path) {
            return Ok(not_held(None));
        }
        let legacy = classify_lock_file(&legacy_path);
        if matches!(legacy, Classified::Free) {
            return Ok(not_held(Some(legacy_path)));
        }
        confirm_holder(&legacy, exp, &legacy_path)?;
        // A legacy writer stamps no generation (reads as 0): every record after the cut needs >= g + 1 >= 1.
        write_fence(dir, g as i64, None)?;
        io(fs::rename(&legacy_path, dir.join(format!("state.lock.legacy-recovered-{}-{}", now_ms(), rand_hex(3)))))?;
        fsync_dir(dir)?;
        return Ok(RecoverDurableStateResult { released: true, reason: "released", lock_file: Some(legacy_path) });
    }
    let top = match top {
        Some(t) if !matches!(t, Classified::Free) => t,
        other => {
            if exists(&legacy_path) {
                let lb = classify_lock_file(&legacy_path);
                let who = match &lb {
                    Classified::Complete(b, _) => format!(
                        "holder pid={} host={} nonce={}",
                        js_num(b.pid.unwrap_or(f64::NAN)),
                        b.host.clone().unwrap_or_default(),
                        b.nonce.clone().unwrap_or_default()
                    ),
                    Classified::Unreadable => "unreadable holder record".to_string(),
                    Classified::Incomplete(_) => "incomplete holder record".to_string(),
                    Classified::Free => "free holder record".to_string(),
                };
                return err(C::Invalid, format!("the blocking lock is the legacy single-file {} ({who}); after confirming that holder is gone, pass legacyLock: true with its expectedHolder (or 'unreadable')", legacy_path.display()));
            }
            return Ok(if other.is_none() { not_held(None) } else { not_held(Some(path)) });
        }
    };
    confirm_holder(&top, exp, &path)?;
    let link_body = |gen: u64, body: Value, crash_point: &str| -> Res<()> {
        let tmp = dir.join(format!("state.lock.tmp-{}-{}", self_pid(), rand_hex(6)));
        {
            let mut f = io(OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp))?;
            io(f.write_all(body.to_string().as_bytes()))?;
            io(f.sync_all())?;
        }
        kill_self_if(crash_point);
        let r = fs::hard_link(&tmp, dir.join(format!("state.lock.{gen}")));
        let _ = fs::remove_file(&tmp);
        match r {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                err(C::Invalid, format!("{} was superseded while recovering; re-read the lock state and retry", path.display()))
            }
            Err(e) => io(Err(e)),
        }
    };
    kill_self_if("before-lock");
    // `start` lets a waiter tell this process from a later one that reuses its pid.
    let start = proc_start_of(self_pid() as f64);
    let mut held = Map::new();
    held.insert("st".into(), json!("held"));
    held.insert("pid".into(), json!(self_pid()));
    held.insert("host".into(), json!(hostname()));
    held.insert("nonce".into(), json!(rand_hex(12)));
    held.insert("boot".into(), json!(boot_id()));
    if let Some(ns) = my_ns() {
        held.insert("ns".into(), json!(ns));
    }
    if let Some(s) = start {
        held.insert("start".into(), json!(s));
    }
    held.insert("recovering".into(), json!(g));
    held.insert("t".into(), json!(now_ms()));
    link_body(g + 1, Value::Object(held), "after-lock-temp")?;
    kill_self_if("after-lock");
    write_fence(
        dir,
        g as i64,
        Some(&|| {
            kill_self_if("after-fence-temp");
            Ok::<(), DurableStateError>(())
        }),
    )?;
    kill_self_if("after-fence");
    link_body(g + 2, json!({"st": "free", "t": now_ms(), "recoveredFrom": g}), "after-release-temp")?;
    kill_self_if("after-release");
    Ok(RecoverDurableStateResult { released: true, reason: "released", lock_file: Some(path) })
}

/// The dynamic entry point (a CLI or a JSON harness): the options as a JSON object `{force, expectedHolder, legacyLock?}`.
/// Validation happens in the reference's order: `force` first, then `expectedHolder`.
pub fn recover_durable_state_value(dir: impl Into<PathBuf>, opts: &Value) -> Res<RecoverDurableStateResult> {
    if opts.get("force") != Some(&Value::Bool(true)) {
        return err(C::Invalid, "recoverDurableState requires force: true");
    }
    let expected_holder = ExpectedHolder::from_value(opts.get("expectedHolder").unwrap_or(&Value::Null))?;
    recover_durable_state(&RecoverDurableStateOptions {
        dir: dir.into(),
        force: true,
        expected_holder,
        legacy_lock: opts.get("legacyLock") == Some(&Value::Bool(true)),
    })
}

// ------------------------------------------------------------------------------------------------------------------
// records, head, the store

#[derive(Clone, Debug)]
struct Rec {
    seq: i64,
    prev: String,
    op: &'static str,
    payload: String,
    ts: i64,
    gen: Option<i64>,
    h: String,
    mac: Option<String>,
}

#[derive(Clone, Debug)]
struct Head {
    seq: i64,
    h: String,
    gen: Option<i64>,
}

fn rec_hash(seq: i64, prev: &str, op: &str, payload: &str, ts: i64, gen: Option<i64>) -> String {
    let arr = match gen {
        None => format!("[{seq},{},{},{},{ts}]", js(prev), js(op), js(payload)),
        Some(g) => format!("[{seq},{},{},{},{ts},{g}]", js(prev), js(op), js(payload)),
    };
    sha(&format!("{DOMAIN}{arr}"))
}

fn head_msg(seq: i64, h: &str, gen: Option<i64>) -> String {
    match gen {
        None => format!("head\n{seq}\n{h}"),
        Some(g) => format!("head\n{seq}\n{h}\n{g}"),
    }
}

fn rec_line(r: &Rec) -> String {
    let mut s = format!("{{\"seq\":{},\"prev\":{},\"op\":{},\"payload\":{},\"ts\":{}", r.seq, js(&r.prev), js(r.op), js(&r.payload), r.ts);
    if let Some(g) = r.gen {
        s.push_str(&format!(",\"gen\":{g}"));
    }
    s.push_str(&format!(",\"h\":{}", js(&r.h)));
    if let Some(m) = &r.mac {
        s.push_str(&format!(",\"mac\":{}", js(m)));
    }
    s.push('}');
    s
}

struct Loaded {
    recs: Vec<Rec>,
    state: HashMap<String, String>,
    head: Option<Head>,
}

struct Inner {
    seen_seq: i64,
    seen_hash: String,
    recovered: bool,
    held_nonce: Option<String>,
    my_gen: i64,
}

/// An open durable state. All operations take the cross-process lock; one handle may be shared between threads.
pub struct DurableState {
    dir: PathBuf,
    key: Option<Vec<u8>>,
    lock_timeout: i64,
    compact_every: usize,
    max_value: usize,
    now: Box<dyn Fn() -> i64 + Send + Sync>,
    recover_from_corruption: bool,
    test_crash_at: Option<CrashAt>,
    my_ns: Option<String>,
    my_start: Option<String>,
    inner: Mutex<Inner>,
}

/// Open (creating if needed) a durable state directory. Fails with a [`DurableStateError`] on corrupt or rolled-back state unless recovering.
pub fn open_durable_state(opts: DurableStateOptions) -> Res<DurableState> {
    if opts.dir.as_os_str().is_empty() {
        return err(C::Invalid, "dir is required");
    }
    if opts.hmac_key.as_ref().is_some_and(|k| k.len() < 32) {
        return err(C::Invalid, "hmacKey must be at least 32 bytes");
    }
    let dir = opts.dir;
    let mut b = fs::DirBuilder::new();
    b.recursive(true).mode(0o700);
    io(b.create(&dir))?;
    let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)); // not ours to chmod (e.g. a shared parent): keep going
    let st = DurableState {
        key: opts.hmac_key,
        lock_timeout: opts.lock_timeout_ms.unwrap_or(10_000),
        compact_every: opts.compact_every.unwrap_or(256).max(2) as usize,
        max_value: opts.max_value_bytes.unwrap_or(1_048_576),
        now: opts.now.unwrap_or_else(|| Box::new(now_ms) as Box<dyn Fn() -> i64 + Send + Sync>),
        recover_from_corruption: opts.recover_from_corruption,
        test_crash_at: opts.test_crash_at,
        my_ns: my_ns(),
        my_start: proc_start_of(self_pid() as f64),
        inner: Mutex::new(Inner { seen_seq: 0, seen_hash: GENESIS.to_string(), recovered: false, held_nonce: None, my_gen: -1 }),
        dir,
    };
    st.probe_links()?;
    {
        // Initial open: verify under the lock (so a half-finished writer is not mistaken for corruption), repair the head.
        let mut inner = st.inner.lock().unwrap_or_else(|e| e.into_inner());
        st.with_lock(&mut inner, |inner| {
            let l = st.load_or_recover(inner)?;
            st.observe(inner, &l);
            if let Some(last) = l.recs.last() {
                if l.head.as_ref().map_or(true, |h| h.seq != last.seq) {
                    st.write_head(inner, last, "nothing was written")?;
                }
            }
            Ok(())
        })?;
    }
    Ok(st)
}

impl DurableState {
    fn journal_path(&self) -> PathBuf {
        self.dir.join("state.journal")
    }
    fn head_path(&self) -> PathBuf {
        self.dir.join("state.head")
    }

    /// True when this open quarantined corrupt state (see `recover_from_corruption`).
    pub fn recovered(&self) -> bool {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).recovered
    }

    /// Highest chain position this handle has observed.
    pub fn position(&self) -> Position {
        let i = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        Position { seq: i.seen_seq, hash: i.seen_hash.clone() }
    }

    /// Verify the chain from disk now; fails on any problem.
    pub fn verify(&self) -> Res<Position> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.with_lock(&mut inner, |inner| {
            let l = self.load(inner)?;
            self.observe(inner, &l);
            Ok(Position { seq: inner.seen_seq, hash: inner.seen_hash.clone() })
        })
    }

    fn encode(&self, value: &Value) -> Res<String> {
        let s = serde_json::to_string(value).map_err(|_| DurableStateError::new(C::Invalid, "value is not JSON-serialisable"))?;
        if utf16_len(&s) > self.max_value {
            return err(C::TooLarge, format!("value exceeds maxValueBytes={}", self.max_value));
        }
        Ok(s)
    }

    fn check_key(k: &str) -> Res<()> {
        if k.is_empty() || utf16_len(k) > MAX_KEY || k.contains('\n') {
            return err(C::Invalid, "key must be 1..256 chars without newlines");
        }
        Ok(())
    }

    fn read_head(&self) -> Res<Option<Head>> {
        let p = self.head_path();
        if !exists(&p) {
            return Ok(None);
        }
        let o: Value = serde_json::from_str(&read_text(&p)?).map_err(|_| DurableStateError::new(C::Corrupt, "state.head is not valid JSON"))?;
        let shape = || DurableStateError::new(C::Corrupt, "state.head has an invalid shape");
        let r = o.as_object().ok_or_else(shape)?;
        let (seq, nz) = safe_int(r.get("seq")).filter(|(s, _)| *s >= 0).ok_or_else(shape)?;
        let h = r.get("h").and_then(|h| h.as_str()).filter(|h| is_hex64(h)).ok_or_else(shape)?;
        if nz || (r.get("gen").is_some() && !is_gen(r.get("gen"))) {
            return Err(shape());
        }
        let head = Head { seq, h: h.to_string(), gen: safe_int(r.get("gen")).map(|g| g.0) };
        if let Some(key) = &self.key {
            let mac = r.get("mac").and_then(|m| m.as_str());
            if mac.map_or(true, |m| !mac_eq(m, &mac_of(key, &head_msg(head.seq, &head.h, head.gen)))) {
                return err(C::KeyMismatch, "state.head MAC does not verify (wrong key or forged head)");
            }
        }
        Ok(Some(head))
    }

    fn load(&self, inner: &Inner) -> Res<Loaded> {
        let head = self.read_head()?;
        let fences = read_fences(&self.dir)?;
        let jp = self.journal_path();
        if !exists(&jp) {
            if head.as_ref().is_some_and(|h| h.seq > 0) {
                return err(C::Rollback, format!("state.journal is missing but state.head records seq {}", head.as_ref().map(|h| h.seq).unwrap_or(0)));
            }
            if let Some(cut) = fences.iter().find(|f| f.seq > 0) {
                return err(C::Rollback, format!("state.journal is missing but operator recovery cut it at seq {}", cut.seq));
            }
            if inner.seen_seq > 0 {
                return err(C::Rollback, "state was deleted while open");
            }
            return Ok(Loaded { recs: Vec::new(), state: HashMap::new(), head });
        }
        let text = read_text(&jp)?;
        let mut lines: Vec<&str> = text.split('\n').collect();
        if lines.last() != Some(&"") {
            return err(C::Corrupt, "journal does not end with a newline (torn or truncated)");
        }
        lines.pop();
        let mut recs: Vec<Rec> = Vec::new();
        let mut state: HashMap<String, String> = HashMap::new();
        let mut prev_hash = GENESIS.to_string();
        let mut prev_seq = 0i64;
        let mut prev_gen = 0i64;
        for (i, line) in lines.iter().enumerate() {
            let n = i + 1;
            let o: Value = serde_json::from_str(line).map_err(|_| DurableStateError::new(C::Corrupt, format!("journal line {n} is not valid JSON")))?;
            let shape = || DurableStateError::new(C::Corrupt, format!("journal line {n} has an invalid shape"));
            let r = o.as_object().ok_or_else(shape)?;
            let seq = safe_int(r.get("seq")).ok_or_else(shape)?.0;
            let prev = r.get("prev").and_then(|v| v.as_str()).filter(|v| is_hex64(v)).ok_or_else(shape)?;
            let op: &'static str = match r.get("op").and_then(|v| v.as_str()) {
                Some("set") => "set",
                Some("checkpoint") => "checkpoint",
                _ => return Err(shape()),
            };
            let payload = r.get("payload").and_then(|v| v.as_str()).ok_or_else(shape)?;
            let (ts, ts_nz) = safe_int(r.get("ts")).ok_or_else(shape)?;
            let h = r.get("h").and_then(|v| v.as_str()).filter(|v| is_hex64(v)).ok_or_else(shape)?;
            if ts_nz || (r.get("gen").is_some() && !is_gen(r.get("gen"))) {
                return Err(shape());
            }
            let rec = Rec {
                seq,
                prev: prev.to_string(),
                op,
                payload: payload.to_string(),
                ts,
                gen: safe_int(r.get("gen")).map(|g| g.0),
                h: h.to_string(),
                mac: r.get("mac").and_then(|m| m.as_str()).map(String::from),
            };
            if i == 0 {
                if rec.op == "set" && (rec.seq != 1 || rec.prev != GENESIS) {
                    return err(C::Corrupt, "journal does not start at genesis");
                }
                if rec.op == "checkpoint" && rec.seq < 1 {
                    return err(C::Corrupt, "bad checkpoint seq");
                }
            } else {
                if rec.seq != prev_seq + 1 {
                    return err(C::Corrupt, format!("journal line {n}: sequence gap"));
                }
                if rec.prev != prev_hash {
                    return err(C::Corrupt, format!("journal line {n}: hash chain broken"));
                }
            }
            if rec_hash(rec.seq, &rec.prev, rec.op, &rec.payload, rec.ts, rec.gen) != rec.h {
                return err(C::Corrupt, format!("journal line {n}: record hash mismatch (edited)"));
            }
            match (&self.key, &rec.mac) {
                (Some(key), mac) => {
                    if mac.as_deref().map_or(true, |m| !mac_eq(m, &mac_of(key, &rec.h))) {
                        return err(C::KeyMismatch, format!("journal line {n}: MAC does not verify (wrong key or forged record)"));
                    }
                }
                (None, Some(_)) => return err(C::KeyMismatch, "journal is MAC-tagged but no hmacKey was supplied"),
                (None, None) => {}
            }
            // Generation fencing (the record is authentic here: hash and MAC verified above).
            let rg = rec.gen.unwrap_or(0);
            if rg < prev_gen {
                return err(C::Corrupt, format!("journal line {n} (seq {}) was written by lock generation {rg}, older than generation {prev_gen} of an earlier record: a stale writer's record (refused)", rec.seq));
            }
            for f in &fences {
                if rec.seq > f.seq && rg < f.gen {
                    return err(C::Corrupt, format!("journal line {n} (seq {}) was written by lock generation {rg}, but operator recovery fenced generations below {} after seq {}: a holder paused across recoverDurableState resumed and replaced the journal late (refused; records committed after the recovery may be lost; recoverFromCorruption quarantines the files)", rec.seq, f.gen, f.seq));
                }
            }
            prev_gen = rg;
            if rec.op == "checkpoint" {
                let entries: Value = serde_json::from_str(&rec.payload).map_err(|_| DurableStateError::new(C::Corrupt, "checkpoint payload is not JSON"))?;
                let arr = entries.as_array().ok_or_else(|| DurableStateError::new(C::Corrupt, "checkpoint payload is not an array"))?;
                state.clear();
                for e in arr {
                    match e.as_array().map(|a| a.as_slice()) {
                        Some([Value::String(k), Value::String(v)]) => {
                            state.insert(k.clone(), v.clone());
                        }
                        _ => return err(C::Corrupt, "checkpoint entry is malformed"),
                    }
                }
            } else {
                let nl = rec
                    .payload
                    .find('\n')
                    .filter(|nl| *nl >= 1)
                    .ok_or_else(|| DurableStateError::new(C::Corrupt, format!("journal line {n}: malformed payload")))?;
                state.insert(rec.payload[..nl].to_string(), rec.payload[nl + 1..].to_string());
            }
            prev_hash = rec.h.clone();
            prev_seq = rec.seq;
            recs.push(rec);
        }
        let last = recs.last();
        let last_seq = last.map(|l| l.seq).unwrap_or(0);
        // The journal must EXTEND the exact journal each recovery cut at (it reaches the cut, and the record at the cut is the one
        // the operator saw, unless a later generation compacted past it).
        for f in &fences {
            if last_seq < f.seq {
                return err(
                    C::Rollback,
                    format!("journal is at seq {last_seq} but operator recovery cut it at seq {} (truncation, or a stale writer replaced it)", f.seq),
                );
            }
            if f.seq > 0 {
                if let Some(at_cut) = recs.iter().find(|r| r.seq == f.seq) {
                    if at_cut.h != f.h {
                        return err(C::Corrupt, format!("journal record at seq {} is not the record operator recovery cut at: a stale writer replaced the journal (refused; recoverFromCorruption quarantines the files)", f.seq));
                    }
                }
            }
        }
        if let Some(head) = &head {
            let hg = head.gen.unwrap_or(0);
            if last_seq < head.seq {
                return err(C::Rollback, format!("journal is at seq {last_seq} but state.head recorded seq {} (truncation or older copy)", head.seq));
            }
            // The head is written by the lock holder of generation `hg`; any record AFTER it, or a different record AT its position,
            // from a LOWER generation was written by a writer that had already lost the lock to `hg`.
            if let Some(l) = last {
                if l.gen.unwrap_or(0) < hg && (last_seq == head.seq + 1 || (last_seq == head.seq && l.h != head.h)) {
                    return err(C::Corrupt, format!("journal tail (seq {last_seq}) was written by lock generation {}, older than generation {hg} that wrote state.head: a stale writer replaced the journal (refused)", l.gen.unwrap_or(0)));
                }
            }
            // A stale LATE head: a holder paused between its journal rename and its head rename resumed after operator recovery and
            // wrote a head for ITS record while newer generations extended the journal past the cut. Recognised exactly, repaired by the next writer.
            let stale_head = last_seq > head.seq + 1
                && fences.iter().any(|f| hg < f.gen && head.seq <= f.seq && last_seq > f.seq)
                && recs.iter().any(|r| r.seq == head.seq && r.h == head.h);
            if last_seq > head.seq + 1 && !stale_head {
                return err(C::Corrupt, format!("journal (seq {last_seq}) is more than one record ahead of state.head (seq {})", head.seq));
            }
            if let Some(l) = last {
                if last_seq == head.seq && l.h != head.h {
                    return err(C::Corrupt, "journal tail does not match state.head");
                }
                if last_seq == head.seq + 1 && l.prev != head.h {
                    return err(C::Corrupt, "journal tail is not chained from state.head");
                }
            }
        } else if last_seq > 1 {
            return err(C::Rollback, format!("state.head is missing but the journal is at seq {last_seq}"));
        }
        if let Some(l) = last {
            if l.seq < inner.seen_seq {
                return err(C::Rollback, format!("state moved backwards from seq {} to {} while open", inner.seen_seq, l.seq));
            }
            if l.seq == inner.seen_seq && l.h != inner.seen_hash {
                return err(C::Rollback, format!("state forked at seq {} while open", l.seq));
            }
        } else if inner.seen_seq > 0 {
            return err(C::Rollback, "state was emptied while open");
        }
        Ok(Loaded { recs, state, head })
    }

    fn quarantine(&self, inner: &mut Inner) -> Res<()> {
        let tag = format!("{}-{}", (self.now)(), rand_hex(3));
        self.assert_lock_held(inner, "nothing was written")?; // a writer that lost the lock must not move a newer holder's files aside
                                                              // After an operator recovery the journal restarts from genesis, so the old cuts no longer describe it. The fence list is
                                                              // replaced (old one kept aside) by "every record from genesis on needs generation >= mine".
        let fence_path = self.dir.join(FENCE_FILE);
        let old_entries: Vec<String> = list_dir(&self.dir)?.into_iter().filter(|n| fence_entry(n).is_some()).collect();
        if exists(&fence_path) || !old_entries.is_empty() {
            if exists(&fence_path) {
                io(fs::hard_link(&fence_path, format!("{}.quarantine-{tag}", fence_path.display())))?;
                // keep the old one; the list file itself is never absent
            }
            let g = inner.my_gen;
            atomic_write(
                &fence_path,
                &format!("{{\"v\":1,\"fences\":[{{\"gen\":{g},\"seq\":0,\"h\":{},\"from\":{},\"t\":{}}}]}}\n", js(GENESIS), g - 1, (self.now)()),
                false,
                None,
            )?;
            for name in old_entries {
                io(fs::rename(self.dir.join(&name), self.dir.join(format!("{name}.quarantine-{tag}"))))?;
            }
        }
        for p in [self.journal_path(), self.head_path()] {
            if exists(&p) {
                io(fs::rename(&p, format!("{}.quarantine-{tag}", p.display())))?;
            }
        }
        fsync_dir(&self.dir)?;
        inner.seen_seq = 0;
        inner.seen_hash = GENESIS.to_string();
        inner.recovered = true;
        Ok(())
    }

    fn load_or_recover(&self, inner: &mut Inner) -> Res<Loaded> {
        match self.load(inner) {
            Ok(l) => Ok(l),
            Err(e) if self.recover_from_corruption && e.code != C::Io => {
                self.quarantine(inner)?;
                self.load(inner)
            }
            Err(e) => Err(e),
        }
    }

    fn observe(&self, inner: &mut Inner, l: &Loaded) {
        if let Some(last) = l.recs.last() {
            if last.seq >= inner.seen_seq {
                inner.seen_seq = last.seq;
                inner.seen_hash = last.h.clone();
            }
        }
    }

    // ---- the lock: immutable, numbered generation files (formal model DurableLockGen) ----

    fn lock_file(&self, g: u64) -> PathBuf {
        self.dir.join(format!("state.lock.{g}"))
    }

    /// Highest numbered generation: (g, body); g = 0 and no body when there is none; body None = unreadable.
    fn top_lock(&self) -> Res<(u64, Option<LockBody>)> {
        let g = top_gen_in(&self.dir)?;
        Ok(if g >= 1 { (g, read_body(&self.lock_file(g))) } else { (0, None) })
    }

    fn holder_dead(&self, b: Option<&LockBody>, legacy_age_ms: f64) -> bool {
        let Some(b) = b else { return legacy_age_ms > 1000.0 }; // an unreadable legacy file (torn by an old version) older than 1 s
        let Some(pid) = b.pid else { return false };
        if b.host.as_deref() != Some(hostname().as_str()) {
            return false; // another host: cannot judge, never break
        }
        if b.ns.is_some() && b.ns != self.my_ns {
            return false; // another PID namespace (container) or unknowable: cannot judge, never break
        }
        if !pid_alive(pid) {
            return true;
        }
        if let Some(start) = &b.start {
            if let Some(now) = proc_start_of(pid) {
                if &now != start {
                    return true; // the pid was reused by a different process
                }
            }
        }
        false
    }

    /// Create generation g atomically with its body. false = somebody else created it first.
    fn create_gen(&self, g: u64, mut body: Map<String, Value>) -> Res<bool> {
        let tmp = self.dir.join(format!("state.lock.tmp-{}-{}", self_pid(), rand_hex(6)));
        body.insert("t".into(), json!(now_ms()));
        {
            let mut f = io(OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp))?;
            io(f.write_all(Value::Object(body).to_string().as_bytes()))?;
            io(f.sync_all())?;
        }
        let r = fs::hard_link(&tmp, self.lock_file(g));
        let _ = fs::remove_file(&tmp);
        match r {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            Err(e) => err(C::Invalid, format!("the state directory's filesystem cannot create the lock atomically (link: {})", errno_name(&e))),
        }
    }

    fn gc_locks(&self, keep_from: i64) {
        let Ok(names) = list_dir(&self.dir) else { return };
        for f in names {
            if let Some(g) = lock_name_gen(&f) {
                if (g as i64) < keep_from && fs::remove_file(self.dir.join(&f)).is_err() {
                    return;
                }
            } else if let Some(rest) = f.strip_prefix("state.lock.tmp-") {
                let pid = rest.split('-').next().and_then(|p| p.parse::<f64>().ok()).unwrap_or(0.0);
                if pid != 0.0 && !pid_alive(pid) && fs::remove_file(self.dir.join(&f)).is_err() {
                    return;
                }
            }
        }
    }

    /// Fail closed at open time when this filesystem cannot give the lock its atomic hard-link semantics.
    fn probe_links(&self) -> Res<()> {
        let a = self.dir.join(format!("state.probe-{}-{}", self_pid(), rand_hex(6)));
        let b = PathBuf::from(format!("{}.lnk", a.display()));
        let r: Result<(), String> = (|| -> Result<(), String> {
            let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&a).map_err(|e| errno_name(&e))?;
            f.write_all(b"probe").map_err(|e| errno_name(&e))?;
            fs::hard_link(&a, &b).map_err(|e| errno_name(&e))?;
            let second = matches!(fs::hard_link(&a, &b), Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists);
            let nlink = fs::metadata(&a).map(|m| m.nlink()).map_err(|e| errno_name(&e))?;
            if !second || nlink != 2 {
                return Err("link(2) is not atomic/exclusive here".into());
            }
            Ok(())
        })();
        for f in [&a, &b] {
            let _ = fs::remove_file(f);
        }
        r.map_err(|code| DurableStateError::new(C::LinkUnsupported, format!("the state directory's filesystem does not provide working hard links with exclusive-create semantics ({code}); use a local filesystem (ext4, xfs, btrfs, tmpfs, APFS), not NFS/SMB/FUSE")))
    }

    fn with_lock<T>(&self, inner: &mut Inner, f: impl FnOnce(&mut Inner) -> Res<T>) -> Res<T> {
        let nonce = rand_hex(12);
        let mut must_fence = false;
        let deadline = now_ms() + self.lock_timeout;
        let legacy_lock = self.dir.join("state.lock");
        loop {
            let top = self.top_lock()?;
            // A single-file state.lock left by (or still used by) an older version counts as a holder too: wait for it unless its
            // owner is provably dead. We never delete or rename it.
            let mut legacy_blocks = false;
            if exists(&legacy_lock) {
                let age = fs::metadata(&legacy_lock)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| SystemTime::now().duration_since(t).ok())
                    .map(|d| d.as_secs_f64() * 1000.0)
                    .unwrap_or(0.0);
                legacy_blocks = !self.holder_dead(read_body(&legacy_lock).as_ref(), age);
            }
            let free = top.0 == 0 || top.1.as_ref().is_some_and(|b| !b.held);
            if !legacy_blocks && (free || self.holder_dead(top.1.as_ref(), 0.0)) {
                // Taking over a DEAD holder whose lock is marked `recovering`: carry the mark and cut + fence before loading.
                let recovering = if free { None } else { top.1.as_ref().and_then(|b| b.recovering) };
                let mut body = Map::new();
                body.insert("st".into(), json!("held"));
                body.insert("pid".into(), json!(self_pid()));
                body.insert("host".into(), json!(hostname()));
                body.insert("nonce".into(), json!(nonce));
                body.insert("boot".into(), json!(boot_id()));
                if let Some(ns) = &self.my_ns {
                    body.insert("ns".into(), json!(ns));
                }
                if let Some(s) = &self.my_start {
                    body.insert("start".into(), json!(s));
                }
                if let Some(r) = recovering {
                    body.insert("recovering".into(), json!(r));
                }
                if self.create_gen(top.0 + 1, body)? {
                    // The generation must still be the HIGHEST one (an ABA grab of a collected generation is buried, not a lock).
                    if self.top_lock()?.0 != top.0 + 1 {
                        continue;
                    }
                    inner.my_gen = (top.0 + 1) as i64;
                    must_fence = recovering.is_some();
                    break;
                }
                continue; // lost the race for that generation: look again immediately
            }
            if now_ms() > deadline {
                let me_ns = &self.my_ns;
                let desc = |b: Option<&LockBody>| -> String {
                    match b {
                        None => "an unreadable holder record".to_string(),
                        Some(b) => match (b.pid, &b.host, &b.nonce) {
                            (Some(pid), Some(host), Some(nonce)) if !nonce.is_empty() => format!(
                                "holder pid={} host={host} nonce={nonce}{}",
                                js_num(pid),
                                if b.ns.is_some() && &b.ns != me_ns { " (another PID namespace)" } else { "" }
                            ),
                            _ => format!(
                                "an incomplete holder record (pid={} host={} nonce={}); release it with expectedHolder: 'unreadable'",
                                b.pid.map(js_num).unwrap_or_else(|| "?".into()),
                                b.host.clone().unwrap_or_else(|| "?".into()),
                                match &b.nonce {
                                    Some(n) if !n.is_empty() => n.clone(),
                                    _ => "?".into(),
                                }
                            ),
                        },
                    }
                };
                let timeout = self.lock_timeout;
                let dir = self.dir.display();
                // name the file that actually blocks (the legacy single-file lock is not a generation)
                if legacy_blocks && (free || self.holder_dead(top.1.as_ref(), 0.0)) {
                    return err(C::LockTimeout, format!("could not acquire the state lock in {dir} within {timeout} ms; blocked by {} (legacy single-file lock of an older version; {}). If that holder is provably gone, an operator can release it with recoverDurableState({{ dir, force: true, legacyLock: true, expectedHolder }}) after confirming the holder is dead; see the durable-state docs", legacy_lock.display(), desc(read_body(&legacy_lock).as_ref())));
                }
                return err(C::LockTimeout, format!("could not acquire the state lock in {dir} within {timeout} ms; blocked by {} ({}). If that holder is provably gone (e.g. a crashed container in another PID namespace), an operator can release it with recoverDurableState({{ dir, force: true, expectedHolder }}) after confirming the holder is dead; see the durable-state docs", self.lock_file(top.0).display(), desc(top.1.as_ref())));
            }
            let mut r = [0u8; 1];
            let _ = getrandom::getrandom(&mut r);
            std::thread::sleep(std::time::Duration::from_millis(5 + (r[0] % 15) as u64));
        }
        inner.held_nonce = Some(nonce);
        self.gc_locks(inner.my_gen - 16);
        let result = (|| -> Res<T> {
            if must_fence {
                // The recovery we took over may have died before (or after) writing its fence; cut and fence now, under OUR generation,
                // before anything is loaded.
                kill_self_if("takeover-after-lock");
                write_fence(
                    &self.dir,
                    inner.my_gen - 1,
                    Some(&|| {
                        kill_self_if("takeover-after-fence-temp");
                        Ok::<(), DurableStateError>(())
                    }),
                )?;
            }
            f(inner)
        })();
        inner.held_nonce = None;
        // release; a live holder is never superseded, so this cannot lose a race
        let mut free_body = Map::new();
        free_body.insert("st".into(), json!("free"));
        if self.create_gen((inner.my_gen + 1) as u64, free_body).is_ok() {
            self.gc_locks(inner.my_gen - 15);
        }
        result
    }

    /// Immediately before EVERY rename this writer makes (journal, head, quarantine): this handle's generation must still be the
    /// highest and must still name us. It is NOT sufficient alone (a holder paused between the check and the rename(2) still
    /// renames): that window is closed on the READ side by the generation in every record and the fence (see `load`).
    fn assert_lock_held(&self, inner: &Inner, outcome: &str) -> Res<()> {
        let top = self.top_lock()?;
        let ok = match (&inner.held_nonce, &top.1) {
            (Some(n), Some(b)) => top.0 as i64 == inner.my_gen && b.held && b.nonce.as_deref() == Some(n.as_str()),
            _ => false,
        };
        if !ok {
            let st = match &top.1 {
                Some(b) if b.held => "held",
                Some(_) => "free",
                None => "unreadable",
            };
            return err(
                C::LockLost,
                format!("the state lock is no longer held by this writer (generation {}, highest {} {st}); {outcome}", inner.my_gen, top.0),
            );
        }
        Ok(())
    }

    /// Head write, stamped with this writer's generation and guarded by the same lock re-check as the journal.
    fn write_head(&self, inner: &Inner, tail: &Rec, outcome: &str) -> Res<()> {
        let g = inner.my_gen;
        let mut s = format!("{{\"seq\":{},\"h\":{},\"gen\":{g}", tail.seq, js(&tail.h));
        if let Some(key) = &self.key {
            s.push_str(&format!(",\"mac\":{}", js(&mac_of(key, &head_msg(tail.seq, &tail.h, Some(g))))));
        }
        s.push_str("}\n");
        atomic_write(&self.head_path(), &s, false, Some(&|| self.assert_lock_held(inner, outcome)))
    }

    fn commit(&self, inner: &mut Inner, l: &Loaded, key_: &str, value_json: &str) -> Res<()> {
        let last = l.recs.last();
        let seq = last.map(|r| r.seq).unwrap_or(0) + 1;
        let prev = last.map(|r| r.h.clone()).unwrap_or_else(|| GENESIS.to_string());
        let gen = inner.my_gen;
        let payload = format!("{key_}\n{value_json}");
        let ts = (self.now)();
        let mut rec =
            Rec { seq, prev: prev.clone(), op: "set", h: rec_hash(seq, &prev, "set", &payload, ts, Some(gen)), payload, ts, gen: Some(gen), mac: None };
        if let Some(k) = &self.key {
            rec.mac = Some(mac_of(k, &rec.h));
        }
        let mut all: Vec<Rec> = l.recs.clone();
        all.push(rec);
        if all.len() > self.compact_every {
            // Compact: ONE checkpoint at the same seq the new record would have, chained from the current tail and carrying the
            // full state (including the new value). Head lag stays at most one record.
            let mut next = l.state.clone();
            next.insert(key_.to_string(), value_json.to_string());
            let mut entries: Vec<(&String, &String)> = next.iter().collect();
            entries.sort_by(|x, y| cmp16(x.0, y.0));
            let cp_payload = format!("[{}]", entries.iter().map(|(k, v)| format!("[{},{}]", js(k), js(v))).collect::<Vec<_>>().join(","));
            let ts2 = (self.now)();
            let mut cp = Rec {
                seq,
                prev: prev.clone(),
                op: "checkpoint",
                h: rec_hash(seq, &prev, "checkpoint", &cp_payload, ts2, Some(gen)),
                payload: cp_payload,
                ts: ts2,
                gen: Some(gen),
                mac: None,
            };
            if let Some(k) = &self.key {
                cp.mac = Some(mac_of(k, &cp.h));
            }
            all = vec![cp];
        }
        let tail = all.last().cloned().expect("at least one record");
        // Journal first (atomic), head second (atomic). A crash between leaves the head one record behind: repaired by the next writer.
        // The lock re-check runs AFTER the temp file is written and fsynced, i.e. as close to the rename as possible.
        let text = format!("{}\n", all.iter().map(rec_line).collect::<Vec<_>>().join("\n"));
        atomic_write(
            &self.journal_path(),
            &text,
            self.test_crash_at == Some(CrashAt::AfterTempWrite),
            Some(&|| self.assert_lock_held(inner, "nothing was written")),
        )?;
        if self.test_crash_at == Some(CrashAt::AfterJournalRename) {
            kill_self();
        }
        self.write_head(inner, &tail, &format!("the journal record (seq {}) was renamed into place but state.head was not written; whether it counts depends on whether operator recovery cut before it (re-read the value)", tail.seq))?;
        inner.seen_seq = tail.seq;
        inner.seen_hash = tail.h;
        Ok(())
    }

    fn repair_head(&self, inner: &Inner, l: &Loaded) -> Res<()> {
        if let Some(last) = l.recs.last() {
            if l.head.as_ref().map_or(true, |h| h.seq != last.seq) {
                self.write_head(inner, last, "nothing was written")?;
            }
        }
        Ok(())
    }
}

impl DurableKv for DurableState {
    fn get(&self, key: &str) -> Res<Option<Value>> {
        Self::check_key(key)?;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.with_lock(&mut inner, |inner| {
            let l = self.load(inner)?;
            self.observe(inner, &l);
            Ok(l.state.get(key).map(|v| serde_json::from_str(v).unwrap_or(Value::Null)))
        })
    }

    fn keys(&self) -> Res<Vec<String>> {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.with_lock(&mut inner, |inner| {
            let l = self.load(inner)?;
            self.observe(inner, &l);
            let mut k: Vec<String> = l.state.keys().cloned().collect();
            k.sort_by(|a, b| cmp16(a, b));
            Ok(k)
        })
    }

    fn set(&self, key: &str, value: &Value) -> Res<()> {
        Self::check_key(key)?;
        let vj = self.encode(value)?;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.with_lock(&mut inner, |inner| {
            let l = self.load(inner)?;
            self.repair_head(inner, &l)?;
            self.commit(inner, &l, key, &vj)
        })
    }

    fn update(&self, key: &str, f: &mut dyn FnMut(Option<Value>) -> Option<Value>) -> Res<Option<Value>> {
        Self::check_key(key)?;
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        self.with_lock(&mut inner, |inner| {
            let l = self.load(inner)?;
            self.repair_head(inner, &l)?;
            let cur_json = l.state.get(key);
            let parse = |s: &String| serde_json::from_str::<Value>(s).unwrap_or(Value::Null);
            let Some(next) = f(cur_json.map(parse)) else { return Ok(cur_json.map(parse)) };
            let vj = self.encode(&next)?;
            if cur_json != Some(&vj) {
                self.commit(inner, &l, key, &vj)?;
            }
            Ok(Some(serde_json::from_str(&vj).unwrap_or(Value::Null)))
        })
    }
}

/// The durable store as the crate's atomic key/value seam: `KvOperationStore::new(Arc::new(state))` is the reference `durableOperationStore(kv)`,
/// and [`crate::durable_pca_store::durable_pca_state_store`] over it is `durablePcaStateStore(kv)`.
impl crate::kv::AtomicKv for DurableState {
    fn get(&self, key: &str) -> Result<Option<Value>, crate::StoreError> {
        DurableKv::get(self, key).map_err(|e| crate::StoreError(e.message))
    }

    fn update(&self, key: &str, f: &mut dyn FnMut(Option<&Value>) -> Option<Value>) -> Result<Option<Value>, crate::StoreError> {
        DurableKv::update(self, key, &mut |prev: Option<Value>| f(prev.as_ref())).map_err(|e| crate::StoreError(e.message))
    }

    fn list(&self, prefix: &str) -> Result<Option<Vec<Value>>, crate::StoreError> {
        let mut out = Vec::new();
        for k in DurableKv::keys(self).map_err(|e| crate::StoreError(e.message))?.into_iter().filter(|k| k.starts_with(prefix)) {
            if let Some(v) = DurableKv::get(self, &k).map_err(|e| crate::StoreError(e.message))? {
                out.push(v);
            }
        }
        Ok(Some(out))
    }
}

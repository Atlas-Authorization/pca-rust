//! The durable state store on a non-Unix target: it FAILS CLOSED with `link-unsupported`, the reference's code for a filesystem it cannot
//! prove has working hard links with exclusive-create semantics. The store needs the link count of a file to detect a lock that was made
//! twice (stable `std` offers it on Unix only: `MetadataExt::nlink`), so on Windows an open refuses rather than run without that check.
//! Use a database-backed `AtomicKv` there. The error types are the Unix module's.
use std::path::PathBuf;

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

fn unsupported<T>() -> Res<T> {
    Err(DurableStateError::new(
        DurableStateErrorCode::LinkUnsupported,
        "this platform has no stable link-count API, so the state directory's hard-link exclusive-create semantics cannot be verified; the durable state store is Unix only (use a database-backed store here)",
    ))
}

/// Refuses on this platform (see the module docs).
pub fn open_durable_state(_dir: impl Into<PathBuf>) -> Res<()> {
    unsupported()
}

/// Refuses on this platform (see the module docs).
pub fn recover_durable_state(_dir: impl Into<PathBuf>) -> Res<()> {
    unsupported()
}

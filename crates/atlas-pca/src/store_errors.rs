//! Typed failures shared by the durable stores (the reference's `RangeError` and the coded `LedgerStoreError`, `BondStoreError` and
//! `BudgetLedgerError`). `code` is stable; the message of a coded error is `"<code>: <text>"`.
use crate::authorize::StoreError;
use serde_json::Value;

/// A failure with a stable `code`: `RangeError` for an argument outside its range (the caller's bug, never a store state), else the
/// store's own code (`store_corrupt`, `store_unavailable`, `rollback`, `tamper`, ...).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodedError {
    pub code: String,
    pub message: String,
}

pub type R<T> = Result<T, CodedError>;

impl CodedError {
    pub fn new(code: &str, message: impl AsRef<str>) -> Self {
        CodedError { code: code.to_string(), message: message.as_ref().to_string() }
    }
    pub fn range(message: impl AsRef<str>) -> Self {
        CodedError::new("RangeError", message)
    }
    pub fn is_range(&self) -> bool {
        self.code == "RangeError"
    }
}

impl std::fmt::Display for CodedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_range() {
            f.write_str(&self.message)
        } else {
            write!(f, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for CodedError {}

/// The failure of the backing key-value store, as a store error.
pub fn kv_err(e: StoreError) -> CodedError {
    CodedError::new("store_unavailable", if e.0.is_empty() { "store failed" } else { &e.0 })
}

/// A JavaScript safe integer (finite, integral, `|x| <= 2^53 - 1`).
pub fn safe_int(v: &Value) -> Option<i64> {
    v.as_f64().filter(|f| f.is_finite() && f.fract() == 0.0 && f.abs() <= 9_007_199_254_740_991.0).map(|f| f as i64)
}

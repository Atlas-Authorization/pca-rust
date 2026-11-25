//! The networked MPC driver (feature `mpc-net-driver`): every party is its own node holding only its own shares, and every opening
//! is a message over a mutual TLS 1.3 mesh with pinned self-signed certificates. It is built on the pure codecs of
//! [`crate::mpc_net`] and the engines of [`crate::mpc`], [`crate::mpc_ot`] and [`crate::mpc_mascot`]; nothing here re-implements them.
//!
//! - [`certs`]: per-run P-256 identities, certificate pins, signing / verifying with the pinned certificate.
//! - [`clock`]: the injectable mesh clock (wall clock and a virtual one for tests).
//! - [`mesh`]: the authenticated, fail-closed point-to-point mesh (strict framing, sequence numbers, abort propagation).
//! - [`protocol`]: the distributed malicious-with-abort composition (trusted-dealer and no-dealer offline phases).
//! - [`offline`]: the no-dealer offline phase (base OT, KOS extension, Gilboa products, pairwise tags).
//! - [`gadget`], [`forensics`]: the signed gadget seed agreement and the committed forensic disclosure exchange.
//! - [`ot_net`]: the pairwise base-OT demonstration over the network.
//! - [`launch_local`], [`party_main`], [`faults`]: the local launcher, the node entry point (JSON config) and the fault injectors.
//!
//! This is a research prototype in the same sense as the reference: there is no security proof, the echo broadcast is a hash
//! exchange, and the trusted-dealer mode trusts one process with every share and key.
use crate::mpc_net::{NetAbort, NetAbortOpts};
use serde_json::Value;
use std::fmt;

pub mod certs;
pub mod clock;
pub mod faults;
pub mod forensics;
pub mod gadget;
pub mod launch_local;
pub mod mesh;
pub mod offline;
pub mod ot_net;
pub mod party_main;
pub mod prep;
pub mod protocol;

/// A shared JSON null to hand out as a `&Value` default.
pub(crate) static NULL: Value = Value::Null;

impl fmt::Display for NetAbort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for NetAbort {}

/// An abort of `kind` blaming `blamed` (when the evidence names one), reported by `reporter`.
pub(crate) fn nab(kind: &str, blamed: Option<i64>, reporter: i64, detail: &str) -> NetAbort {
    NetAbort::new(kind, blamed, reporter, detail, None, None, NetAbortOpts::default())
}

/// A local (unattributed) abort: a refused configuration or an internal failure of this node.
pub(crate) fn local(reporter: i64, detail: &str) -> NetAbort {
    nab("local", None, reporter, detail)
}

/// The detail of a local abort that stands for a test-only crash / silence of the node (see [`protocol::Behavior`]).
pub const CRASH_DETAIL: &str = "crash";
/// See [`CRASH_DETAIL`].
pub const SILENT_DETAIL: &str = "silent";

/// The JSON object of a [`NetAbort`] as the node entry point prints it.
pub fn abort_json(e: &NetAbort) -> serde_json::Value {
    serde_json::json!({
        "kind": e.kind,
        "blamed": e.blamed,
        "reporter": e.reporter,
        "claimedKind": e.claimed_kind,
        "claimedBlame": e.claimed_blame,
        "reason": e.reason,
        "evidence": e.evidence,
        "deadlineMs": e.deadline_ms,
        "message": e.message,
    })
}

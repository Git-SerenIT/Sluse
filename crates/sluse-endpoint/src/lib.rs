// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! # sluse-endpoint — the boundary crossing
//!
//! Runs **in the guest**, and is the sole path file content takes across the
//! boundary (invariant 1). It holds no credential (invariant 3) and asserts
//! nothing about its own scope (invariant 2): everything it does, it does by
//! asking the Gate, and the Gate's answer is the decision.
//!
//! ## The shape of every call
//!
//! **Ask, journal, then narrow.** A tool call goes to the Gate even when the
//! endpoint could guess the answer, because the Gate's record has to be the
//! complete one — a refusal the host never saw is a refusal that did not happen,
//! as far as the audit trail is concerned. Then [`blinders`] decides what the
//! agent is told, which is less than what happened.
//!
//! The one exception is a path that cannot be parsed at all. That is refused
//! locally and journaled here (`MalformedPath`), because forwarding it would put
//! unparseable strings in the host's log and the Gate could not audit it
//! meaningfully either.
//!
//! ## Two records, one join
//!
//! The Gate hashes the bytes it sends; this hashes the bytes it receives
//! (invariant 7). The hash is deliberately not on the wire, so the two records
//! are joined by `admission_id` and the scorer asserts the join is one-to-one
//! with equal hashes — a stronger check than a header either end could have
//! copied from the other.
//!
//! ## M3, and what is not here yet
//!
//! Both halves are built. `--mcp` is M3; `--console` — the loopback API and
//! the views in `ui/console` — is M5. See [`console`].

pub mod blinders;
pub mod gate_client;
pub mod console;
pub mod enrol;
pub mod extract;
pub mod envelope;
pub mod journal;
pub mod kvp;
pub mod manifest;
pub mod render;
pub mod runtime_policy;
pub mod server;
pub mod session;
pub mod workspace;

pub use blinders::{tell, Told};
pub use gate_client::{Admitted, GateClient, PinnedVerifier};
pub use journal::Journal;
pub use session::Resumed;

/// This crate's version, which is the workspace's.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

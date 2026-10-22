// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! # sluse-broker — the thing that decides
//!
//! The broker runs on the host, as the signed-in user, and is the only party
//! that says whether a file may cross into the guest. Everything the guest can
//! do, it does by asking this. The guest asserts nothing about its own scope
//! (invariant 2), holds no credential (invariant 3), and has no filesystem path
//! into a source (invariant 1) — so the checks in this crate are not a second
//! opinion, they are the opinion.
//!
//! ## What is here, and what is not yet
//!
//! M2 in `docs/sluse_prototype.md`. This crate is being built in two halves,
//! and the split is not arbitrary:
//!
//! - **The deciding half, here now.** [`scope`] resolves a request-form path to
//!   a real one or refuses it; [`sources`] reaches the source behind a trait;
//!   [`audit`] writes the record; [`volume`] watches for bulk admission;
//!   [`identity`] says who the broker is acting as. No async runtime, no TLS, no
//!   HTTP — every decision this crate makes is testable without a socket, and
//!   the tests are the cheaper place to find out that a junction escapes a root.
//! - **The serving half, next.** The mTLS listener with a client verifier, the
//!   eight routes, and the streaming read body. `tls.rs`, `http.rs` and `app.rs`
//!   land when they land; nothing in the deciding half changes to accommodate
//!   them, which is the point of writing it first.
//!
//! The order was forced by this machine — the MSVC C headers `stdarg.h` and
//! `stddef.h` are missing, so `aws-lc-sys` cannot compile and no crypto provider
//! builds — and kept because it is the better order anyway.
//!
//! ## The one rule for everything in here
//!
//! **Refuse, record, then answer.** A refusal is normal operation
//! (`docs/audit.md`): the broker's record is complete whatever the guest is told
//! afterwards. The blinders that make out-of-scope material *absent* rather than
//! *forbidden* (D-008) are applied at the endpoint, on the far side of the
//! boundary, from the [`SluseError`](sluse_proto::SluseError) this crate
//! returns. That is why `scope` distinguishes an unknown source from a path that
//! does not exist from a path that exists out of scope, and the agent does not.

pub mod app;
pub mod as_user;
pub mod control;
pub mod enrol;
pub mod entra;
pub mod audit;
pub mod http;
pub mod identity;
pub mod preflight;
pub mod proxy;
pub mod remote;
pub mod scope;
pub mod serve;
pub mod session;
pub mod sources;
pub mod tls;
pub mod volume;

pub use scope::{Compiled, CompiledScope, CompiledSource, Scoped};
pub use volume::VolumeMonitor;

/// This crate's version, which is the workspace's. Reported on `/v1/health` as
/// `brokerVersion`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

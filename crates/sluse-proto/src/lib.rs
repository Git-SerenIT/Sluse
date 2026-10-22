// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! # sluse-proto — the Sluse shared contract
//!
//! The single definition of everything two Sluse components have to agree
//! about: the config file's schema, the endpoint-to-broker wire types, the
//! exhaustive error enum, the audit record, and the content hash. The broker,
//! the endpoint and the lifecycle CLI all import it, so a change one side does
//! not honour is a compile error rather than a scope disagreement discovered in
//! a log.
//!
//! ## The rule that comes with the error enum
//!
//! **Add the failure mode to [`SluseError`] first.** A refusal that arrives as a
//! string is one the endpoint cannot map to an agent-facing message, the console
//! cannot render, and the audit record cannot categorise — and by the time
//! anyone notices, three call sites have invented three phrasings for the same
//! condition. Chaperone learned this; it is the one convention from there worth
//! restating at the top of the file.
//!
//! ## What lives here, and what deliberately does not
//!
//! Nearly pure data: no async runtime, no networking, no Win32, and no
//! knowledge of any source. Two deliberate exceptions, both because the
//! alternative is the same logic written twice and drifting:
//!
//! - [`config::load`] reads the config's two files and hashes the authored one. It validates everything
//!   decidable from the file's own contents and touches nothing else — no
//!   canonicalisation, no existence checks, no certificates. See that module for
//!   why that line is drawn there.
//! - [`ids`] mints identifiers, which needs the clock and the OS random source.
//!   The broker and the endpoint each mint some, and one grammar implemented
//!   twice is a grammar that drifts.
//!
//! Path canonicalisation — UNC resolution, junctions, `\\?\` prefixes,
//! case-insensitive comparison — needs the platform and is the **broker's**, not
//! this crate's. It is the enforcing check and it belongs on the host
//! (`docs/config.md`, What enforces what).
//!
//! ## The invariants these types are shaped around
//!
//! From `CLAUDE.md`:
//!
//! 2. *The box cannot assert its own scope.* Nothing in [`wire`] lets the guest
//!    send a scope, a root or a resolved host path to the broker. It sends a
//!    request-form path and is told what happened.
//! 3. *No durable credential exists inside the box.* The one token-shaped thing
//!    on the wire is a header the guest forwards and never stores.
//! 6. *Config absent, invalid or of an unknown schema version means nothing
//!    runs.* Every [`config::ConfigError`] is a reason not to start.
//! 7. *Audit is uniform even when transport is not.* One [`audit::AuditRecord`]
//!    for both writers, joined by an [`ids::AdmissionId`].
//!
//! ## Module map
//!
//! - [`error`] — [`SluseError`], every way an operation can fail.
//! - [`hash`] — [`ContentHash`], SHA-256, and a streaming hasher for invariant 7.
//! - [`ids`] — the typed identifier newtypes and their shared grammar.
//! - [`config`] — the config file's types and its fail-closed loader.
//! - [`wire`] — the routes, headers and request/response types.
//! - [`audit`] — the audit record, and the preflight snapshot it points at.
//! - [`ports`] — the one port block, 7580 to 7589 (D-029).
//! - [`pipe`] — the host shell's pipe to the lifecycle service, and the KVP
//!   bootstrap the service hands the box.

pub mod audit;
pub mod config;
pub mod error;
pub mod hash;
pub mod ids;
pub mod pipe;
pub mod ports;
pub mod wire;

// Flat re-export of the whole contract, so a downstream crate names a type
// without tracking which module it lives in.
pub use audit::{
    AdmissionState, AuditRecord, Capability, Check, CheckList, CheckOutcome, LineageItem, Op, Outcome,
    PostureSnapshot, UserKind, UserRef, Writer,
};
pub use config::{
    AuditConfig, AuditSinkKind, Authored, BoxSettings, BrokerConfig, Config, ConfigError, Deployment, Device,
    EgressConfig, EgressLog, EndpointConfig, EntraConfig, Environment, Loaded, SensitivityLevel, SourceConfig,
    SourceKind, VolumeConfig, SCHEMA_VERSION,
};
pub use error::{Result, SluseError};
pub use hash::{ContentHash, ContentHasher};
pub use ids::{AdmissionId, BoxId, PostureId, PublishId, SessionId, SourceName};
pub use wire::{
    AlertsQuery, ArtifactManifest, Audience, AuditTailQuery, AuditTailResponse, ConfigView,
    EntryKind, Health, ListEntry, ListRequest, ListResponse, Pin, PublishManifest, PublishResponse,
    PublishedArtifact, ReadHeaders, ReadRequest, ReadVerb, SourceLastSeen, SourceView, StatRequest,
    HostSignInResult, SignInView, SignedOut, StatResponse, Status, VolumeAlert,
};

/// This crate's version, which is the workspace's. Reported by the broker on
/// `/v1/health` so a guest and a host of different ages are visible as such.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Between Gate Front and its parent (D-071).
//!
//! Sluse Gate is one thing at two trust levels. **Gate Front**, one per box,
//! runs without privilege and holds no token: it terminates the box's TLS,
//! parses what the box sends, and runs the egress proxy. Its parent is **Gate
//! Core**, as SYSTEM, for an open box, or the service for a base build, which
//! has no Core. Front can ask its parent; it cannot act.
//!
//! The channel is HTTP/2 over Front's stdin and stdout, handed to it at its
//! start: nothing else holds that pipe, so the pipe names the box, and a Front
//! cannot speak for another. Front is the client and the parent serves. Its
//! first request is [`route::START`], which answers with everything Front needs
//! ([`FrontStart`]), its TLS key included, so Front reads no file and needs no
//! right to any. The box's own requests go to the parent on their `/v1/` paths,
//! after Front has parsed them; what only Front sees goes up as a [`Claim`].
//!
//! **Front may refuse; only its parent may allow.** Core checks scope again on
//! every request against the config it loaded itself (invariant 2). A claim is
//! recorded as Front's, and is only as true as Front.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::EgressConfig;

/// The parent's routes for Front, beside the box's own `/v1/` ones.
pub mod route {
    /// `GET`: [`super::FrontStart`].
    pub const START: &str = "/front/start";
    /// `POST`: one [`super::Claim`].
    pub const CLAIM: &str = "/front/claim";
    /// `POST`: a [`super::WindowAsk`], answered with a [`super::WindowAnswer`]
    /// (D-075): whether a sign-in window the person opened lets the box
    /// reach this host now.
    pub const WINDOW: &str = "/front/window";
}

/// Front asks for a host on `egress.window`. Front may refuse; only Core
/// may allow (D-071, D-075).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WindowAsk {
    pub host: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowAnswer {
    pub open: bool,
}

/// Everything Front runs on, from its parent at start.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FrontStart {
    /// The box's side, for an open; none for a base build, whose Front is its
    /// egress proxy only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<FrontGate>,
    /// The egress proxy; none in LOCAL without an egress block.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<FrontProxy>,
}

/// The listener the box's endpoint talks to, and enrolment beside it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FrontGate {
    /// `host:port`, the config's `gate.listen`.
    pub listen: String,
    /// The Gate's leaf chain and key (PEM). The key identifies the host to
    /// the box, not a person.
    pub cert_pem: String,
    pub key_pem: String,
    /// The CA whose leaves the Gate accepts from clients (PEM).
    pub client_ca_pem: String,
    /// Accept only the leaf enrolment issues for this open (D-058), and the
    /// device's own (point 4). False in LOCAL and in the tests, where the CA
    /// is the whole check.
    pub pinned: bool,
    /// The device's own client leaf (PEM), the service's, always accepted
    /// when pinned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_leaf_pem: Option<String>,
    /// `host:port` for enrolment, when this open enrols a box (slice 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrol_listen: Option<String>,
}

/// The egress proxy (M9, D-035).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FrontProxy {
    /// `host:port`.
    pub listen: String,
    pub allow: EgressConfig,
    /// What every record carries: the box, the config, who opened it.
    pub about: Value,
    /// Send every connection up as a [`Claim::Connection`] (D-038 point 7);
    /// refusals go up either way.
    pub log_connections: bool,
    /// Production's rules: public addresses, ports 80 and 443. A test turns
    /// them off for its loopback servers.
    pub public_only: bool,
}

/// What Front saw and its parent records, as Front's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", tag = "kind", content = "record")]
pub enum Claim {
    /// The proxy refused a destination: the Event Log's 1201.
    EgressRefused(Value),
    /// One connection, for `egress.jsonl`.
    Connection(Value),
}

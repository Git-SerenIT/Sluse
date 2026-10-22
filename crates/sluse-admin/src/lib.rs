// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Setup's engine (D-037, D-039 slice 4): everything the tenant admin's side
//! does, as a library, so the "Sluse Admin" window (slice 6) and the
//! `sluse admin setup` CLI drive the same code.
//!
//! - [`signin`]: the admin's interactive sign-in, the request and the code.
//! - [`setup`]: Sluse's Entra registration, the tenant's `sluse.json` and the
//!   tenant package with its install script.
//! - [`roles`]: which of setup's steps the signed-in account may do.
//! - [`consent`]: whether admin consent has been granted, for polling.
//! - [`assign`]: Entra's "Assignment required" and the group that may sign in.
//! - [`browse`]: sites, Teams, libraries, folders and shares, for the scope
//!   picker.
//! - [`catalog`]: the egress bundles this install ships.
//! - [`intunewin`]: our own `.intunewin` writer (D-039 point 2).
//! - [`intune`]: publishing straight to Intune through Graph (D-037 point 2).
//! - [`author`]: the authored file from the admin's choices, validated by
//!   the box's own loader, with warnings for what is risky but allowed.
//!
//! Everything that talks to Graph is tested against a local stand-in; none
//! of it has run against a tenant until the test run says so.

/// The HTTP client the setup UI hands `graph::Graph`, at this crate's version.
pub use reqwest;

#[cfg(windows)]
mod acl;
pub mod author;
pub mod assign;
pub mod browse;
pub mod catalog;
pub mod consent;
pub mod graph;
pub mod intune;
pub mod intunewin;
pub mod msi;
pub mod roles;
pub mod setup;
pub mod signin;
mod zip;
#[cfg(test)]
mod stand_in;

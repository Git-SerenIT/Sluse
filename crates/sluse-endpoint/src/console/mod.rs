// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The console: what a person sees of a run, from inside the guest.
//!
//! M5. The console is a loopback HTTP API plus the views in `ui/console`. It
//! shows the run's state, the sources as the *user's* audience sees them
//! (out-of-scope entries greyed rather than absent, D-008), the journal, an
//! artifact's provenance, the workspace inventory, open volume alerts and a
//! tail of the audit trail.
//!
//! **It asserts nothing of its own.** Every answer here is the Gate's answer,
//! relayed; the console adds presentation and the inventory's comparison, and
//! the comparison is careful not to over-claim ([`inventory`]).
//!
//! ## Loopback, and no authentication
//!
//! The API binds `consoleListen`, which is a loopback address, and there is no
//! auth on it. In LOCAL that is the prototype's stated limitation rather than a
//! design: anything already running in the guest can reach it, and anything
//! already running in the guest can reach the endpoint's MCP surface too. It is
//! recorded here and in `docs/sluse_prototype.md` so it is a known gap rather
//! than an oversight, and it is the guest boundary — not this listener — that
//! the product's claim rests on.

pub mod api;
pub mod assets;
pub mod inventory;

pub use api::{router, serve, Console};
pub use inventory::{classify, items_from_journal, InventoryItem, InventoryState};

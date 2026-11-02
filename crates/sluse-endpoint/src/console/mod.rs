// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The console: what a person sees of a run, from inside the guest.
//!
//! The run's state, the sources as the agents see them, the journal, an
//! artifact's provenance, the workspace inventory, open volume alerts and, in
//! LOCAL, a tail of the host's audit trail, as calls on [`Console`]. The
//! console that draws them is `crates/sluse-console` (D-079), which makes
//! them in its own process.
//!
//! **It asserts nothing of its own.** Every answer here is the Gate's answer,
//! relayed; the console adds presentation and the inventory's comparison, and
//! the comparison is careful not to over-claim ([`inventory`]).
//!
//! ## No port
//!
//! Until 0.3 these were a loopback HTTP API with no authentication, which
//! anything running in the box could call, the agent included: clear the
//! inventory, sign the box out, launch an app. There is no listener now. The
//! limit, written with it: an agent runs as the box's user and can still
//! reach sway and drive the console's window; it lost the trivial route, not
//! every route. The guest boundary, not this module, is what the product's
//! claim rests on.

pub mod api;
pub mod inventory;

pub use api::Console;
pub use inventory::{classify, items_from_journal, InventoryItem, InventoryState};

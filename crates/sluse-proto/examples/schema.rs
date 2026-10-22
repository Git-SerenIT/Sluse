// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Emit `config/schema.json` from the types in [`sluse_proto::config`].
//!
//! The schema is the product boundary (`docs/config.md`): the box consumes the
//! file, and the platform will one day produce it. Generating the schema from
//! the types rather than maintaining it by hand is what keeps the two halves of
//! that boundary honest — a hand-written schema drifts from the loader within a
//! release, and then the platform emits something the box refuses.
//!
//! Regenerate:
//!
//! ```text
//! cargo run -p sluse-proto --example schema > config/schema.json
//! cargo run -p sluse-proto --example schema -- device > config/device.schema.json
//! ```
//!
//! `tests/schema_current.rs` fails if the file on disk is not what this prints,
//! so the drift is caught by `cargo test` rather than by a customer.

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("device") => print!("{}", sluse_proto::config::device_schema_json()),
        _ => print!("{}", sluse_proto::config::schema_json()),
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! `config/schema.json` must be what the types say it is.
//!
//! The schema is the product boundary (`docs/config.md`), which means it is
//! read by people who are not looking at this crate: whoever writes a config by
//! hand in v1, and the platform's compiler in v2. A schema file that has drifted
//! from the loader is worse than none, because it invites a config the box then
//! refuses — so the drift is a test failure here rather than a support call
//! later.
//!
//! When this fails, regenerate rather than edit:
//!
//! ```text
//! cargo run -p sluse-proto --example schema > config/schema.json
//! cargo run -p sluse-proto --example schema -- device > config/device.schema.json
//! ```

use std::path::PathBuf;

fn config_dir() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/sluse-proto.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("config")
}

#[test]
fn the_published_schema_matches_the_types() {
    same("schema.json", &sluse_proto::config::schema_json(), "");
}

#[test]
fn the_published_device_schema_matches_the_types() {
    same("device.schema.json", &sluse_proto::config::device_schema_json(), " -- device");
}

fn same(file: &str, generated: &str, arg: &str) {
    let path = config_dir().join(file);
    let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} could not be read ({e}). Generate it with:\n  \
             cargo run -p sluse-proto --example schema{arg} > config/{file}",
            path.display()
        )
    });

    // Compare the parsed values, not the bytes: a checkout with CRLF line
    // endings, or an editor that trimmed a trailing newline, would otherwise
    // fail this test for a reason that has nothing to do with the schema.
    let on_disk: serde_json::Value = serde_json::from_str(&on_disk).expect("the schema on disk is not valid JSON");
    let generated: serde_json::Value = serde_json::from_str(generated).expect("generated schema parses");

    assert_eq!(
        on_disk,
        generated,
        "config/{file} has drifted from sluse_proto::config. Regenerate it:\n  \
         cargo run -p sluse-proto --example schema{arg} > config/{file}"
    );
}

#[test]
fn the_example_config_validates_against_the_loader() {
    // Not a JSON Schema validation — that would need a validator crate and
    // would test schemars rather than us. This checks the thing that actually
    // matters: the example we ship is a config the box would start on.
    // Its device half is `local.example.device.json`, beside it.
    let path = config_dir().join("local.example.json");
    let loaded = sluse_proto::config::load(&path)
        .unwrap_or_else(|e| panic!("config/local.example.json does not load: {e}"));

    assert_eq!(loaded.config.environment, sluse_proto::Environment::Local);
    assert!(
        !loaded.config.sources.is_empty(),
        "the example should show at least one source"
    );
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The journal's mirror on the host (slice 4, D-027 point 5): what the box
//! journals reaches the host's copy, a line missed while the Gate was away
//! arrives with the next record, and nothing is ever there twice.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use sluse_gate_core::app::Core;
use sluse_gate_core::audit::MemorySink;
use sluse_gate_core::{http, preflight, scope, tls};
use sluse_endpoint::gate_client::GateClient;
use sluse_endpoint::journal;
use sluse_proto::wire::JournalAppend;
use sluse_proto::Loaded;

mod certs;

struct Host {
    dir: tempfile::TempDir,
    loaded: Loaded,
    _served: sluse_gate_front::testing::Served,
}

async fn host() -> Host {
    tls::install_provider();
    let dir = tempfile::tempdir().unwrap();
    let c = certs::make();
    certs::write(dir.path(), &c);
    std::fs::create_dir_all(dir.path().join("fixture/in-scope")).unwrap();
    let config = dir.path().join("gate.json");
    certs::write_config(&config, &dir.path().join("fixture"), &c.pin);
    let loaded = sluse_proto::config::load(&config).unwrap();
    let compiled = scope::compile(&loaded).unwrap();
    let posture = preflight::run(&loaded, preflight::CertCheck::Ok { pin: c.pin.clone() });
    let gate = Core::new(loaded.clone(), compiled, Arc::new(MemorySink::new()), posture)
        .with_journal_mirror(Some(dir.path().join("mirror")));
    let front = sluse_gate_core::front::gate_start(&loaded, "127.0.0.1:0", false).unwrap();
    let served = sluse_gate_front::testing::serve(front, http::router(Arc::new(gate))).await;
    let port = served.addr().port();
    let mut loaded = loaded;
    loaded.config.gate.url = format!("https://localhost:{port}");
    Host { dir, loaded, _served: served }
}

fn append(path: &std::path::Path, text: &str) {
    use std::io::Write;
    std::fs::OpenOptions::new().create(true).append(true).open(path).unwrap().write_all(text.as_bytes()).unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_host_copy_catches_up_and_never_holds_a_line_twice() {
    let h = host().await;
    let (client, _) = GateClient::connect(&h.loaded).await.unwrap();
    let session = client.session().clone();
    let local = h.dir.path().join("journal.jsonl");
    let host_copy = h.dir.path().join("mirror").join(format!("{session}.jsonl"));
    let cursor = AtomicU64::new(0);

    append(&local, "{\"n\":1}\n");
    journal::mirror(&client, &local, &session, &cursor).await;
    assert_eq!(std::fs::read_to_string(&host_copy).unwrap(), "{\"n\":1}\n");

    // Two records written while the Gate was away. A mirror call that
    // fails stores nothing, so the cursor is where these two found it.
    append(&local, "{\"n\":2}\n");
    append(&local, "{\"n\":3}\n");
    journal::mirror(&client, &local, &session, &cursor).await;
    assert_eq!(std::fs::read_to_string(&host_copy).unwrap(), std::fs::read_to_string(&local).unwrap());

    // A restarted process starts its cursor at 0 and re-offers everything:
    // the host keeps one copy of each line.
    let fresh = AtomicU64::new(0);
    append(&local, "{\"n\":4}\n");
    journal::mirror(&client, &local, &session, &fresh).await;
    assert_eq!(std::fs::read_to_string(&host_copy).unwrap(), std::fs::read_to_string(&local).unwrap());

    // Half a line waits until it is whole.
    append(&local, "{\"n\":");
    journal::mirror(&client, &local, &session, &fresh).await;
    assert!(!std::fs::read_to_string(&host_copy).unwrap().contains("{\"n\":\n"));
    append(&local, "5}\n");
    journal::mirror(&client, &local, &session, &fresh).await;
    assert_eq!(std::fs::read_to_string(&host_copy).unwrap(), std::fs::read_to_string(&local).unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gap_is_answered_with_where_the_host_is() {
    let h = host().await;
    let (client, _) = GateClient::connect(&h.loaded).await.unwrap();
    let session = client.session().clone();
    let at = |offset, lines: &str| JournalAppend { session: session.clone(), offset, lines: lines.into() };
    assert_eq!(client.mirror_journal(&at(0, "a\n")).await.unwrap(), 2);
    // Ahead of the host: nothing written, and the host's length back.
    assert_eq!(client.mirror_journal(&at(10, "z\n")).await.unwrap(), 2);
    // Not whole lines: refused the same way.
    assert_eq!(client.mirror_journal(&at(2, "b")).await.unwrap(), 2);
    assert_eq!(client.mirror_journal(&at(2, "b\n")).await.unwrap(), 4);
    let copy = h.dir.path().join("mirror").join(format!("{session}.jsonl"));
    assert_eq!(std::fs::read_to_string(copy).unwrap(), "a\nb\n");
}

/// Review R-12: a journal past one request's worth reaches the host in
/// pieces, and a restarted process sends only what the host lacks.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_long_journal_goes_in_chunks_and_a_restart_resumes() {
    let h = host().await;
    let (client, _) = GateClient::connect(&h.loaded).await.unwrap();
    let session = client.session().clone();
    let local = h.dir.path().join("journal.jsonl");
    let host_copy = h.dir.path().join("mirror").join(format!("{session}.jsonl"));

    // 3 MiB of lines: over the 2 MiB a single request was held to.
    let line = format!("{{\"pad\":\"{}\"}}\n", "x".repeat(1000));
    append(&local, &line.repeat(3 * 1024));
    let cursor = AtomicU64::new(0);
    journal::mirror(&client, &local, &session, &cursor).await;
    assert_eq!(std::fs::read(&host_copy).unwrap(), std::fs::read(&local).unwrap());

    let fresh = AtomicU64::new(0);
    append(&local, "{\"n\":1}\n");
    journal::mirror(&client, &local, &session, &fresh).await;
    assert_eq!(std::fs::read(&host_copy).unwrap(), std::fs::read(&local).unwrap());
    assert_eq!(fresh.load(std::sync::atomic::Ordering::SeqCst), std::fs::metadata(&local).unwrap().len());
}

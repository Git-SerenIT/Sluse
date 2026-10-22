// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The endpoint against a real broker, over a real handshake.
//!
//! The broker's own `tests/mtls.rs` proves the listener with a hand-rolled
//! rustls client, which is the right tool for asserting what the *handshake*
//! does. This proves a different thing, and the more important one for M3: that
//! **the client the guest actually ships** — `BrokerClient`, reqwest,
//! `PinnedVerifier` — can talk to it, and that the two records join.
//!
//! The thing to watch here is [`a_client_without_the_pin_is_not_talking_to_the_broker`].
//! reqwest 0.13's `rustls` feature, given no explicit roots, installs
//! `rustls-platform-verifier` — the operating system root store. If
//! `use_preconfigured_tls` were ever dropped from `build_client`, the guest would
//! silently start trusting every public CA, the pin would never be consulted, and
//! nothing else in this file would fail. That test is the one that would.

use std::sync::Arc;

use sluse_broker::app::Broker;
use sluse_broker::audit::MemorySink;
use sluse_broker::{http, preflight, scope, serve, tls};
use sluse_endpoint::broker_client::BrokerClient;
use sluse_endpoint::journal::Journal;
use sluse_proto::{ContentHash, Loaded, Op, Outcome, SluseError};

mod certs;

// ---------------------------------------------------------------------------
// A broker and a config that names it
// ---------------------------------------------------------------------------

struct Fixture {
    dir: tempfile::TempDir,
    loaded: Loaded,
    sink: Arc<MemorySink>,
    running: serve::Running,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.running.shutdown_now();
    }
}

impl Fixture {
    fn workspace(&self) -> std::path::PathBuf {
        self.loaded.resolve(&self.loaded.config.workspace)
    }
    fn journal_dir(&self) -> std::path::PathBuf {
        self.loaded.resolve(&self.loaded.config.journal_dir)
    }
    fn artifacts(&self) -> std::path::PathBuf {
        self.loaded.resolve(&self.loaded.config.artifacts)
    }
}

async fn start() -> Fixture {
    start_with_pin(None).await
}

/// `pin_override` replaces `broker.certPin` in the config the *endpoint* reads,
/// so the client expects a certificate the broker will not present.
async fn start_with_pin(pin_override: Option<ContentHash>) -> Fixture {
    tls::install_provider();

    let dir = tempfile::tempdir().unwrap();
    let c = certs::make();
    certs::write(dir.path(), &c);

    let root = dir.path().join("fixture");
    std::fs::create_dir_all(root.join("in-scope").join("docs")).unwrap();
    std::fs::create_dir_all(root.join("elsewhere")).unwrap();
    std::fs::write(root.join("in-scope").join("docs").join("note.txt"), b"a note in scope").unwrap();
    std::fs::write(root.join("in-scope").join("docs").join("data.bin"), [0u8, 159, 146, 150]).unwrap();
    std::fs::write(root.join("in-scope").join("docs").join("blåbær grød.txt"), b"danish").unwrap();
    std::fs::write(root.join("elsewhere").join("secret.txt"), b"secret").unwrap();

    // The broker enforces from its own config, which always carries the true
    // pin. Only the endpoint's copy is tampered with below.
    let broker_config = dir.path().join("broker.json");
    certs::write_config(&broker_config, &root, &c.pin);
    let loaded_broker: Loaded = sluse_proto::config::load(&broker_config).unwrap();

    let guest_pin = pin_override.unwrap_or_else(|| c.pin.clone());
    let guest_config = dir.path().join("guest.json");
    certs::write_config(&guest_config, &root, &guest_pin);
    let loaded_guest: Loaded = sluse_proto::config::load(&guest_config).unwrap();

    let compiled = scope::compile(&loaded_broker).unwrap();
    let server_tls = tls::server_config(&loaded_broker).unwrap();
    let posture = preflight::run(&loaded_broker, preflight::CertCheck::Ok { pin: c.pin.clone() });
    assert!(posture.gate_passed());

    let sink = Arc::new(MemorySink::new());
    let broker = Arc::new(Broker::new(loaded_broker, compiled, sink.clone(), posture));

    let listener = serve::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let (running, _task) = serve::serve(listener, server_tls.config, http::router(broker)).unwrap();

    // The config was written with a placeholder port; point the guest's copy at
    // the ephemeral one the OS chose.
    let mut loaded = loaded_guest;
    loaded.config.broker.url = format!("https://localhost:{}", addr.port());

    Fixture { dir, loaded, sink, running }
}

async fn connect(fx: &Fixture) -> (BrokerClient, sluse_proto::Health) {
    BrokerClient::connect(&fx.loaded).await.expect("the endpoint should reach the broker")
}

// ---------------------------------------------------------------------------
// The pin
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_with_the_right_pin_reaches_the_broker() {
    let fx = start().await;
    let (_client, health) = connect(&fx).await;

    assert!(health.ok);
    assert_eq!(health.box_id.as_str(), "box-local-test");
    // The session comes from the broker; the guest does not choose it.
    assert!(health.session_id.as_str().starts_with("sess-"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_without_the_pin_is_not_talking_to_the_broker() {
    // The guest's config names a certificate the broker will never present.
    let fx = start_with_pin(Some(ContentHash::of(b"some other certificate"))).await;

    let err = BrokerClient::connect(&fx.loaded)
        .await
        .expect_err("a broker that is not the pinned one must not be talked to");

    // This is also the test that fails if `use_preconfigured_tls` is ever
    // dropped: without it reqwest would verify against the OS root store, this
    // handshake would fail for an unrelated reason or — on a machine where the
    // certificate happened to chain — succeed.
    assert_eq!(err.reason_code(), "BROKER_UNREACHABLE");
    assert!(
        err.to_string().contains("pin"),
        "the failure should name the pin, not just fail: {err}"
    );
    assert!(fx.sink.records().is_empty(), "nothing reached the broker");
}

// ---------------------------------------------------------------------------
// The two records, and the join
// ---------------------------------------------------------------------------

/// A resolved path is a header value, and header values are ASCII. Until
/// 2026-09-25 the broker dropped a non-ASCII one silently, so a file with a
/// Danish name reached the guest's journal with no resolved path at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_danish_file_name_reaches_the_journal_as_the_broker_resolved_it() {
    let fx = start().await;
    let (client, _) = connect(&fx).await;
    let admitted = client.read("fixture/in-scope/docs/blåbær grød.txt").await.unwrap();
    assert_eq!(admitted.value, b"danish");
    let broker_rec = fx.sink.records().into_iter().find(|r| r.op == Op::Read).unwrap();
    assert!(admitted.resolved.ends_with("blåbær grød.txt"), "{}", admitted.resolved);
    assert_eq!(Some(admitted.resolved), broker_rec.path_resolved);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_produces_two_records_that_join_on_one_admission_with_equal_hashes() {
    let fx = start().await;
    let (client, health) = connect(&fx).await;
    let mut journal = Journal::open_session(&fx.journal_dir(), client.session()).unwrap();

    let path = "fixture/in-scope/docs/note.txt";
    let admitted = client.read(path).await.unwrap();
    assert_eq!(admitted.value, b"a note in scope");

    journal.record(
        sluse_proto::AuditRecord::new(
            sluse_proto::Writer::Endpoint,
            health.box_id.clone(),
            health.user.clone(),
            health.config_version.clone(),
            client.session().clone(),
            Op::Read,
            path,
        )
        .resolved(admitted.resolved.clone())
        .admitted(admitted.admission_id.clone(), admitted.hash.clone(), admitted.bytes),
    );

    // Invariant 7: the broker hashed what it sent, the endpoint hashed what it
    // received, and neither took the other's word for it — the hash is
    // deliberately not on the wire.
    let broker_rec = fx
        .sink
        .records()
        .into_iter()
        .find(|r| r.op == Op::Read && r.outcome == Outcome::Admitted)
        .expect("the broker recorded the admission");
    let endpoint_rec = &journal.records()[0];

    assert_eq!(broker_rec.admission_id, endpoint_rec.admission_id, "the join key");
    assert_eq!(broker_rec.hash, endpoint_rec.hash, "both sides hashed the same bytes");
    assert_eq!(broker_rec.hash, Some(ContentHash::of(b"a note in scope")));
    assert_eq!(broker_rec.bytes, endpoint_rec.bytes);
    // And the two writers are distinguishable, which is the whole two-record
    // design: one is the host's account, one is the guest's.
    assert_eq!(broker_rec.writer, sluse_proto::Writer::Broker);
    assert_eq!(endpoint_rec.writer, sluse_proto::Writer::Endpoint);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_streams_to_the_workspace_and_hashes_what_it_wrote() {
    let fx = start().await;
    let (client, _) = connect(&fx).await;

    let destination = fx.workspace().join("admitted").join("fixture").join("note.txt");
    let admitted = client
        .fetch_to_file("fixture/in-scope/docs/note.txt", &destination)
        .await
        .unwrap();

    assert_eq!(std::fs::read(&destination).unwrap(), b"a note in scope");
    assert_eq!(admitted.hash, ContentHash::of(b"a note in scope"));
    assert_eq!(admitted.bytes, 15);

    let broker_rec = fx.sink.records().into_iter().find(|r| r.op == Op::Fetch).unwrap();
    assert_eq!(broker_rec.hash, Some(admitted.hash));
}

// ---------------------------------------------------------------------------
// The blinders
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_broker_keeps_the_reason_and_the_agent_gets_one_message() {
    let fx = start().await;
    let (client, _) = connect(&fx).await;

    let out_of_scope = client.read("fixture/elsewhere/secret.txt").await.unwrap_err();
    let missing = client.read("fixture/in-scope/docs/nothing.txt").await.unwrap_err();
    let unknown = client.read("nosuchsource/a.txt").await.unwrap_err();

    // The guest holds only the hidden form (D-033 point 2): all three are a
    // path that is not there, as a value, and none carries the resolved host
    // path or the scopes, so neither the box's journal nor its console can.
    for e in [&out_of_scope, &missing, &unknown] {
        assert_eq!(e.reason_code(), "NOT_FOUND", "{e:?}");
        assert!(matches!(e.error, SluseError::NotFound { .. }), "{e:?}");
    }

    // And what the agent is told is one indistinguishable message (D-008).
    let told: Vec<String> = [&out_of_scope, &missing, &unknown]
        .iter()
        .map(|e| sluse_endpoint::tell(e, "fixture/x").message)
        .collect();
    assert_eq!(told[0], told[1]);
    assert_eq!(told[1], told[2]);
    assert!(!told[0].contains("scope"), "{}", told[0]);

    // The host's record has all three, distinctly. Nothing is hidden from the
    // user; the agent is the one wearing the blinders.
    let reasons: Vec<String> =
        fx.sink.records().into_iter().filter_map(|r| r.reason).collect();
    assert!(reasons.contains(&"OUT_OF_SCOPE".to_owned()));
    assert!(reasons.contains(&"NOT_FOUND".to_owned()));
    assert!(reasons.contains(&"UNKNOWN_SOURCE".to_owned()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listing_omits_what_is_out_of_scope() {
    let fx = start().await;
    let (client, _) = connect(&fx).await;

    let listing = client.list("fixture").await.unwrap();
    let names: Vec<&str> = listing.entries.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(names, vec!["in-scope"], "`elsewhere` is absent, not refused");
}

// ---------------------------------------------------------------------------
// Publish
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_carries_the_lineage_of_the_whole_session() {
    let fx = start().await;
    let (client, health) = connect(&fx).await;
    let mut journal = Journal::open_session(&fx.journal_dir(), client.session()).unwrap();

    let rec = |op, path: &str| {
        sluse_proto::AuditRecord::new(
            sluse_proto::Writer::Endpoint,
            health.box_id.clone(),
            health.user.clone(),
            health.config_version.clone(),
            client.session().clone(),
            op,
            path,
        )
    };

    // Two admissions, then a delivery of two files.
    for path in ["fixture/in-scope/docs/note.txt"] {
        let a = client.read(path).await.unwrap();
        journal.record(rec(Op::Read, path).admitted(a.admission_id, a.hash, a.bytes));
    }

    let lineage = journal.lineage();
    assert_eq!(lineage.len(), 1);

    // The library declares the note as its source; the notes declare none (D-055).
    let files = vec![
        ("crates/x/src/lib.rs".to_owned(), b"pub fn f() {}".to_vec(), lineage.clone()),
        ("NOTES.md".to_owned(), b"# notes".to_vec(), vec![]),
    ];
    let response = client.publish(&files, lineage.clone()).await.unwrap();

    assert_eq!(response.artifacts.len(), 2);
    // The nested shape survives, which is what makes a delivery something a
    // person can open (jok, 2026-09-16), in the delivery's own folder (D-031).
    let folder = std::fs::read_dir(fx.artifacts()).unwrap().next().unwrap().unwrap().path();
    assert_eq!(
        std::fs::read(folder.join("crates").join("x").join("src").join("lib.rs")).unwrap(),
        b"pub fn f() {}"
    );
    assert!(folder.join("NOTES.md").exists());

    // Both artifacts of one delivery share a publish id and carry the same
    // lineage — the fix for S-2 finding 8, where the second file of a delivery
    // got none.
    let publishes: Vec<_> =
        fx.sink.records().into_iter().filter(|r| r.op == Op::Publish).collect();
    assert_eq!(publishes.len(), 2);
    assert_eq!(publishes[0].publish_id, publishes[1].publish_id);
    for p in &publishes {
        assert_eq!(p.lineage.as_ref().unwrap().len(), 1);
        let declared = if p.artifact.as_deref() == Some("NOTES.md") { 0 } else { 1 };
        assert_eq!(p.sources.as_ref().unwrap().len(), declared, "{:?}", p.artifact);
        // Q-4 and Q-5 are open, so nothing writes a label it cannot honour.
        assert_eq!(p.label, None);
    }

    // A second delivery of the same names is a second folder, and the first
    // is not overwritten (D-031 point 5).
    let again = client.publish(&files, lineage.clone()).await.unwrap();
    assert_ne!(again.publish_id, response.publish_id);
    assert_ne!(again.artifacts[0].path, response.artifacts[0].path);
    assert_eq!(std::fs::read_dir(fx.artifacts()).unwrap().count(), 2);

    // A declared source the delivery's admitted set does not hold is refused
    // whole, by the broker as well as the endpoint (D-055).
    let stray = sluse_proto::LineageItem { hash: sluse_proto::ContentHash::of(b"never"), ..lineage[0].clone() };
    let refused = client.publish(&[("x.md".to_owned(), b"x".to_vec(), vec![stray])], lineage).await.unwrap_err();
    assert_eq!(refused.reason_code(), "SOURCE_NOT_ADMITTED");
    assert_eq!(std::fs::read_dir(fx.artifacts()).unwrap().count(), 2, "nothing was written");
}

// ---------------------------------------------------------------------------
// The session across a restart
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_rejoins_the_run_so_lineage_and_the_volume_window_continue() {
    let fx = start().await;
    let workspace = fx.workspace();
    std::fs::create_dir_all(&workspace).unwrap();

    // First process.
    let (client, health) = connect(&fx).await;
    let session = client.session().clone();
    sluse_endpoint::session::attach(&workspace, &session, false, chrono::Utc::now()).unwrap();

    let mut journal = Journal::open_session(&fx.journal_dir(), &session).unwrap();
    let a = client.read("fixture/in-scope/docs/note.txt").await.unwrap();
    journal.record(
        sluse_proto::AuditRecord::new(
            sluse_proto::Writer::Endpoint,
            health.box_id.clone(),
            health.user.clone(),
            health.config_version.clone(),
            session.clone(),
            Op::Read,
            "fixture/in-scope/docs/note.txt",
        )
        .admitted(a.admission_id, a.hash, a.bytes),
    );
    drop(journal);
    drop(client);

    // Second process: it finds the run on disk and the broker still holds it.
    let remembered = sluse_endpoint::session::remembered(&workspace).unwrap();
    assert_eq!(remembered, session);

    let (fresh, _) = connect(&fx).await;
    let resumed_client = fresh.with_session(remembered.clone());
    assert!(
        resumed_client.config_view().await.is_ok(),
        "the broker should still recognise a session it issued minutes ago"
    );

    let resumed = sluse_endpoint::session::attach(
        &workspace,
        &remembered,
        true,
        chrono::Utc::now(),
    )
    .unwrap();
    // Stated, not inferred.
    assert!(resumed.describe().contains("rejoined"), "{}", resumed.describe());

    // The journal continued, so a publish now carries what was admitted before
    // the restart.
    let journal = Journal::open_session(&fx.journal_dir(), &remembered).unwrap();
    assert_eq!(journal.lineage().len(), 1, "lineage survived the reconnect");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_the_broker_never_issued_is_refused() {
    let fx = start().await;
    let (client, _) = connect(&fx).await;

    // An agent minting its own to reset the volume window ends up here.
    let forged = client.with_session(sluse_proto::SessionId::mint());
    let err = forged.config_view().await.unwrap_err();
    assert_eq!(err.reason_code(), "UNKNOWN_SESSION");
}

// ---------------------------------------------------------------------------
// Volume
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_admission_through_the_real_client_raises_one_alert() {
    let fx = start().await;
    let (client, _) = connect(&fx).await;

    // The fixture's threshold is 3 distinct files in 60 s. Each read twice: the
    // window counts distinct content, so the repeats do not count.
    let dir = fx.dir.path().join("fixture").join("in-scope").join("docs");
    std::fs::write(dir.join("third.txt"), b"a third file").unwrap();

    for _ in 0..2 {
        for name in ["note.txt", "data.bin", "third.txt"] {
            client
                .fetch_to_file(
                    &format!("fixture/in-scope/docs/{name}"),
                    &fx.workspace().join(name),
                )
                .await
                .unwrap();
        }
    }

    let alerts = client.alerts(None).await.unwrap();
    assert_eq!(alerts.len(), 1, "one alert per crossing, not one per admission");
    assert_eq!(alerts[0].count, 3);
    assert_eq!(alerts[0].session_id, *client.session());
}

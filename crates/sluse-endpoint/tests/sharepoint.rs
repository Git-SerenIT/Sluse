// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A SharePoint library end to end: the guest's own client, a real broker
//! over mTLS, and a stand-in for Entra, Graph and the download host. **M7**,
//! in bytes mode since D-046.
//!
//! What it proves is invariant 7 with both ends measuring: the broker streams
//! the download and hashes it, the endpoint hashes what arrived, and the two
//! records join on one admission id with the same hash. The guest's only
//! client is the pinned one; it reaches nothing but the broker.

use std::sync::Arc;

use serde_json::Value;
use sluse_broker::app::Broker;
use sluse_broker::audit::MemorySink;
use sluse_broker::entra::Entra;
use sluse_broker::{control, http, preflight, scope, serve, tls};
use sluse_endpoint::broker_client::BrokerClient;
use sluse_proto::audit::Capability;
use sluse_proto::{ContentHash, Loaded, Op, UserKind, UserRef};

mod certs;

#[path = "../../sluse-broker/tests/support/entra_mock.rs"]
mod entra_mock;

struct Fx {
    _dir: tempfile::TempDir,
    loaded: Loaded,
    broker: Arc<Broker>,
    sink: Arc<MemorySink>,
    stand_in: entra_mock::Running,
    running: Vec<serve::Running>,
}

impl Drop for Fx {
    fn drop(&mut self) {
        for r in &self.running {
            r.shutdown_now();
        }
    }
}

async fn start() -> Fx {
    tls::install_provider();
    let stand_in = entra_mock::start().await;
    let dir = tempfile::tempdir().unwrap();
    let c = certs::make();
    certs::write(dir.path(), &c);

    // One config: the LOCAL fixture source, plus the library.
    let root = dir.path().join("fixture");
    std::fs::create_dir_all(root.join("in-scope")).unwrap();
    let (authored, device) = certs::config_json(&root, &c.pin);
    let mut v: Value = serde_json::from_str(&authored).unwrap();
    v["sources"].as_array_mut().unwrap().push(entra_mock::sharepoint_source());
    v["entra"] = entra_mock::entra_block();
    let path = dir.path().join("demo.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    std::fs::write(sluse_proto::config::device_path(&path), device).unwrap();
    let loaded_broker: Loaded = sluse_proto::config::load(&path).unwrap();
    let mut loaded: Loaded = sluse_proto::config::load(&path).unwrap();

    let compiled = scope::compile(&loaded_broker).unwrap();
    let server_tls = tls::server_config(&loaded_broker).unwrap();
    let posture = preflight::run(&loaded_broker, preflight::CertCheck::Ok { pin: c.pin.clone() });
    let base = stand_in.base.clone();
    let entra = Entra::new(loaded_broker.config.entra.as_ref().unwrap(), &base, &format!("{base}/v1.0")).unwrap();
    let sink = Arc::new(MemorySink::new());
    let broker = Arc::new(Broker::new(loaded_broker, compiled, sink.clone(), posture).with_entra(Some(entra)));

    let listener = serve::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (running, _) = serve::serve(listener, server_tls.config, http::router(broker.clone())).unwrap();
    loaded.config.broker.url = format!("https://localhost:{port}");

    Fx { _dir: dir, loaded, broker, sink, stand_in, running: vec![running] }
}

impl Fx {
    /// Alice signs in on the host (D-036), as the service hands it over.
    async fn sign_in_alice(&self) {
        assert_eq!(control::sign_in(&self.broker, &self.stand_in.alice()).await.error, None);
    }

    /// The guest's client on a box Alice signed in to.
    async fn client(&self) -> BrokerClient {
        self.sign_in_alice().await;
        self.unsigned_client().await
    }

    /// The same client, without signing anyone in first.
    async fn unsigned_client(&self) -> BrokerClient {
        BrokerClient::connect(&self.loaded).await.unwrap().0
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_joins_on_one_admission_and_both_ends_hash_the_same() {
    let fx = start().await;
    let client = fx.client().await;

    let admitted = client.read("spo/in-scope/a.txt").await.expect("a URL-mode read");
    assert_eq!(admitted.value, b"alpha");
    assert_eq!(admitted.hash, ContentHash::of(b"alpha"));
    assert_eq!(admitted.bytes, 5);
    assert_eq!(admitted.capability, Capability::Bytes);

    let broker_rec = fx
        .sink
        .records()
        .into_iter()
        .find(|r| r.admission_id.as_ref() == Some(&admitted.admission_id))
        .expect("the broker recorded the admission the endpoint received");
    assert_eq!(broker_rec.op, Op::Read);
    assert_eq!(broker_rec.capability, Capability::Bytes);
    // The trusted side measured the delivery too (D-046).
    assert_eq!(broker_rec.hash.as_ref(), Some(&admitted.hash));
    assert!(fx.stand_in.faults().is_empty(), "{:?}", fx.stand_in.faults());
}

/// Graph's listed size is promised, not measured: an Office file can come down
/// larger (L1, 2026-10-01). The download's own length is what is checked, and
/// the bytes that arrived are what is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_larger_than_listed_is_delivered_as_it_arrived() {
    let fx = start().await;
    let client = fx.client().await;

    let body: &[u8] = b"alpha, with the document's properties written in";
    let admitted = client.read("spo/in-scope/grown.docx").await.expect("larger than listed");
    assert_eq!(admitted.value, body);
    assert_eq!(admitted.bytes, body.len() as u64);

    let dest = fx._dir.path().join("grown.docx");
    let fetched = client.fetch_to_file("spo/in-scope/grown.docx", &dest).await.expect("and as a fetch");
    assert_eq!(fetched.bytes, body.len() as u64);
    assert_eq!(std::fs::read(&dest).unwrap(), body);
}

/// A download the source refuses is the broker's refusal, recorded on the
/// host, before any byte reaches the box.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_download_the_source_refuses_is_refused_by_the_broker() {
    let fx = start().await;
    let client = fx.client().await;

    let failed = client.read("spo/in-scope/gone.txt").await.expect_err("the host refuses");
    assert!(failed.admission_id.is_none(), "nothing was admitted");
    let rec = fx.sink.records().into_iter().find(|r| r.path_requested.ends_with("gone.txt")).expect("recorded");
    assert_ne!(rec.outcome, sluse_proto::Outcome::Admitted);

    let refused = client.read("spo/out/secret.txt").await.expect_err("out of scope");
    assert!(refused.admission_id.is_none());
}

/// Without a sign-in the library is not reachable, and the refusal comes from
/// the broker before any source is asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_a_sign_in_nothing_is_admitted() {
    let fx = start().await;
    let (client, _) = BrokerClient::connect(&fx.loaded).await.unwrap();
    let err = client.read("spo/in-scope/a.txt").await.expect_err("no user");
    assert_eq!(err.reason_code(), "SIGN_IN_REQUIRED");
    assert_eq!(fx.stand_in.mock.graph_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

/// D-022 and D-036 over the real wire: the host signs the box in, and every
/// session of the box — the console's and the MCP process's, neither ever
/// given a token — reads as that person, until the console's sign-out ends it
/// for both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sign_in_on_the_host_is_what_every_session_reads_as() {
    let fx = start().await;
    let (console, _) = BrokerClient::connect(&fx.loaded).await.unwrap();
    let mcp = fx.unsigned_client().await;
    assert_ne!(console.session(), mcp.session());

    // Started before anyone signed in: the broker's own identity.
    let unbound = mcp.acting_as();
    assert_eq!(unbound.kind, UserKind::OsProcess);

    fx.sign_in_alice().await;
    assert_eq!(console.status_now().await.unwrap().signed_in.unwrap().name, "alice@contoso.example");
    let admitted = mcp.read("spo/in-scope/a.txt").await.expect("the MCP session acts for Alice");
    assert_eq!(admitted.value, b"alpha");
    // The MCP process never saw the sign-in, and its journal must still name
    // Alice, as the broker's record of the same admission does (2026-09-25:
    // the first tenant run had the guest name the process identity).
    assert_eq!(mcp.acting_as(), UserRef::entra("alice@contoso.example"));
    let broker_side = fx.sink.records().into_iter().find(|r| r.op == Op::Read).unwrap();
    assert_eq!(broker_side.user, mcp.acting_as());

    let out = console.sign_out().await.unwrap();
    assert_eq!(out.user.unwrap().name, "alice@contoso.example");
    let err = mcp.read("spo/in-scope/a.txt").await.expect_err("signed out");
    assert_eq!(err.reason_code(), "SIGN_IN_REQUIRED");
    // A refusal says who too: nobody signed in, so the broker's own identity.
    assert_eq!(mcp.acting_as(), unbound);

    let ops: Vec<Op> = fx.sink.records().iter().map(|r| r.op).filter(|o| matches!(o, Op::Signin | Op::Signout)).collect();
    assert_eq!(ops, [Op::Signin, Op::Signout]);
}

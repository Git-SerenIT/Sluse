// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Enrolment end to end (slice 2): a bootstrap in a KVP pool file, the
//! Gate's enrolment listener behind a real handshake, and then **the
//! identity it produced used on the mTLS listener**. The last step is what
//! shows the leaf chains to the client CA; a leaf that merely parsed would
//! pass everything before it.

use std::sync::Arc;

use sluse_gate_core::app::Core;
use sluse_gate_core::audit::MemorySink;
use sluse_gate_core::enrol::Enrolment;
use sluse_gate_core::{http, preflight, scope, tls};
use sluse_endpoint::gate_client::GateClient;
use sluse_endpoint::enrol::{self, Outcome};
use sluse_proto::pipe::{Bootstrap, KVP_KEY};
use sluse_proto::ContentHash;

mod certs;

fn pool_with(value: &str) -> Vec<u8> {
    let mut rec = vec![0u8; 512 + 2048];
    rec[..KVP_KEY.len()].copy_from_slice(KVP_KEY.as_bytes());
    rec[512..512 + value.len()].copy_from_slice(value.as_bytes());
    rec
}

struct Host {
    _dir: tempfile::TempDir,
    root: std::path::PathBuf,
    mtls_port: u16,
    enrol_port: u16,
    pin: ContentHash,
    _served: sluse_gate_front::testing::Served,
}

/// A Gate's two listeners, with `token`'s hash as this open's.
async fn host(token: &str) -> Host {
    tls::install_provider();
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_owned();
    let c = certs::make();
    certs::write(&root, &c);
    std::fs::create_dir_all(root.join("fixture/in-scope")).unwrap();
    let config = root.join("gate.json");
    certs::write_config(&config, &root.join("fixture"), &c.pin);
    let loaded = sluse_proto::config::load(&config).unwrap();

    let compiled = scope::compile(&loaded).unwrap();
    // Pinned as an open's Front is (D-058): the leaf this enrolment issues,
    // and the device's own, the service's (point 4).
    let mut front = sluse_gate_core::front::gate_start(&loaded, "127.0.0.1:0", true).unwrap();
    front.enrol_listen = Some("127.0.0.1:0".into());
    let posture = preflight::run(&loaded, preflight::CertCheck::Ok { pin: c.pin.clone() });
    let enrolment = Enrolment::load(&loaded, ContentHash::of(token.as_bytes())).unwrap();
    let gate = Arc::new(Core::new(loaded, compiled, Arc::new(MemorySink::new()), posture));

    let router = http::router(gate).merge(http::enrol_router(Arc::new(enrolment)));
    let served = sluse_gate_front::testing::serve(front, router).await;
    let mtls_port = served.addr().port();
    let enrol_port = served.enrol.as_ref().unwrap().addr.port();
    Host { _dir: dir, root, mtls_port, enrol_port, pin: c.pin, _served: served }
}

fn bootstrap(h: &Host, token: &str, pin: ContentHash) -> String {
    let mut b = Bootstrap::new("dk", format!("https://localhost:{}", h.enrol_port), pin).unwrap();
    b.token = token.into();
    serde_json::to_string(&b).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_box_enrols_once_and_its_identity_passes_the_mtls_listener() {
    let h = host("this-open").await;
    let guest = h.root.join("home/Sluse/sluse.json");
    let pool = h.root.join("kvp_pool_0");
    std::fs::write(&pool, pool_with(&bootstrap(&h, "this-open", h.pin.clone()))).unwrap();

    // The device's own leaf, the service's: it passes before the box enrols,
    // or the service could not ask the Gate it started anything (L1,
    // 2026-10-20: every check was refused with the alert AccessDenied).
    let mut device = sluse_proto::config::load(&h.root.join("gate.json")).unwrap();
    device.config.gate.url = format!("https://localhost:{}", h.mtls_port);
    GateClient::connect(&device).await.expect("the device's own leaf passes before enrolment");

    // Another leaf from the same client CA, as one copied out of another
    // user's box would be (review R-03): refused before and after enrolment.
    let mut other = device.clone();
    other.config.endpoint.client_cert_path = "certs/other.pem".into();
    other.config.endpoint.client_key_path = "certs/other.key".into();
    assert!(GateClient::connect(&other).await.is_err(), "no box's leaf passes before the box enrols");

    assert_eq!(enrol::run(&guest, &pool, None).await.unwrap(), Outcome::Enrolled);
    assert!(GateClient::connect(&other).await.is_err(), "a CA-signed leaf that is not this open's");
    // The config is the Gate's, byte for byte: both halves.
    assert_eq!(std::fs::read(&guest).unwrap(), std::fs::read(h.root.join("gate.json")).unwrap());
    assert_eq!(
        std::fs::read(h.root.join("home/Sluse/sluse.device.json")).unwrap(),
        std::fs::read(h.root.join("gate.device.json")).unwrap()
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key = h.root.join("home/Sluse/certs/endpoint.key");
        assert_eq!(std::fs::metadata(&key).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // The same bootstrap again: the identity stands, and no second token is
    // asked for (the Gate would refuse it).
    assert_eq!(enrol::run(&guest, &pool, None).await.unwrap(), Outcome::Unchanged);

    // The proof: the enrolled identity talks to the mTLS listener.
    let mut loaded = sluse_proto::config::load(&guest).unwrap();
    loaded.config.gate.url = format!("https://localhost:{}", h.mtls_port);
    GateClient::connect(&loaded).await.expect("the enrolled leaf should pass the mTLS listener");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_used_token_a_wrong_token_and_a_wrong_pin_are_all_refused() {
    let h = host("this-open").await;
    let guest = h.root.join("home/Sluse/sluse.json");
    let pool = h.root.join("kvp_pool_0");

    std::fs::write(&pool, pool_with(&bootstrap(&h, "a-guess", h.pin.clone()))).unwrap();
    let e = enrol::run(&guest, &pool, None).await.unwrap_err();
    assert!(e.contains("not this open's token"), "{e}");

    // A pin that is not the Gate's leaf: refused at the handshake, before
    // the token is sent anywhere.
    std::fs::write(&pool, pool_with(&bootstrap(&h, "this-open", ContentHash::of(b"another leaf")))).unwrap();
    assert!(enrol::run(&guest, &pool, None).await.is_err());

    std::fs::write(&pool, pool_with(&bootstrap(&h, "this-open", h.pin.clone()))).unwrap();
    assert_eq!(enrol::run(&guest, &pool, None).await.unwrap(), Outcome::Enrolled);
    // Forget the marker, so the box asks again with the same token.
    std::fs::remove_file(h.root.join("home/Sluse/.enrolled")).unwrap();
    let e = enrol::run(&guest, &pool, None).await.unwrap_err();
    assert!(e.contains("already used"), "{e}");
    assert!(!guest.with_extension("new").exists());
}

#[tokio::test]
async fn no_pool_or_no_bootstrap_in_it_is_not_yet_rather_than_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let guest = dir.path().join("Sluse/sluse.json");
    let missing = dir.path().join("no-pool");
    assert_eq!(enrol::run(&guest, &missing, None).await.unwrap(), Outcome::NoBootstrap);
    let empty = dir.path().join("pool");
    std::fs::write(&empty, vec![0u8; 2560]).unwrap();
    assert_eq!(enrol::run(&guest, &empty, None).await.unwrap(), Outcome::NoBootstrap);
}

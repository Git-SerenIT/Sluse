// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The listener, over real mTLS.
//!
//! The plan put the first TLS test in the endpoint at M3. That would have
//! shipped the listener with nothing exercising the handshake, and the handshake
//! is where the one structural claim about this transport lives: **a client
//! without a certificate from the configured CA does not get an HTTP
//! connection.** Not a route that checks and refuses — a socket that never
//! becomes a request. A test that only drove the routes would pass just as well
//! against a Gate Core that had quietly stopped requiring one.
//!
//! So this file asserts the negative cases with a raw rustls client, and the
//! route behaviour with a real one. M3's `tests/mtls.rs` in the endpoint then
//! does the same through `GateClient`, which is a different thing worth
//! testing: that the client the guest actually ships can talk to it.
//!
//! Certificates are generated in-process rather than by shelling out to `sluse
//! devcert` — a test that spawns a binary proves less and flakes more — but by
//! the same code, so a change to `devcert` that broke the chain would break this.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use sluse_gate_core::app::Core;
use sluse_gate_core::audit::MemorySink;
use sluse_gate_core::{http, preflight, scope, tls};
use sluse_proto::{ContentHash, Loaded};

// ---------------------------------------------------------------------------
// A Gate Core on an ephemeral port
// ---------------------------------------------------------------------------

struct Fixture {
    _dir: tempfile::TempDir,
    /// The source root, so a test can take it away mid-run (D-015).
    root: std::path::PathBuf,
    addr: std::net::SocketAddr,
    ca: CertificateDer<'static>,
    client_cert: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    sink: Arc<MemorySink>,
    served: sluse_gate_front::testing::Served,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.served.gate.shutdown_now();
    }
}

/// Everything `devcert` produces, without a filesystem round trip.
struct Certs {
    ca_pem: String,
    core_cert_pem: String,
    core_key_pem: String,
    endpoint_cert_pem: String,
    endpoint_key_pem: String,
    pin: ContentHash,
}

fn make_certs() -> Certs {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
        IsCa, Issuer, KeyPair, KeyUsagePurpose,
    };

    let dn = |cn: &str| {
        let mut d = DistinguishedName::new();
        d.push(DnType::CommonName, cn);
        d
    };

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.distinguished_name = dn("Sluse test CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let core_key = KeyPair::generate().unwrap();
    let mut core_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
    core_params.distinguished_name = dn("sluse-gate-core");
    core_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let core_cert = core_params.signed_by(&core_key, &issuer).unwrap();
    let pin = ContentHash::of(core_cert.der());

    let endpoint_key = KeyPair::generate().unwrap();
    let mut endpoint_params = CertificateParams::new(vec!["sluse-endpoint".to_owned()]).unwrap();
    endpoint_params.distinguished_name = dn("sluse-endpoint");
    endpoint_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let endpoint_cert = endpoint_params.signed_by(&endpoint_key, &issuer).unwrap();

    Certs {
        ca_pem,
        core_cert_pem: core_cert.pem(),
        core_key_pem: core_key.serialize_pem(),
        endpoint_cert_pem: endpoint_cert.pem(),
        endpoint_key_pem: endpoint_key.serialize_pem(),
        pin,
    }
}

fn config_json(
    dir: &std::path::Path,
    fixture_root: &std::path::Path,
    pin: &ContentHash,
    max_fetch_bytes: Option<u64>,
) -> (String, String) {
    // Absent unless a test sets it, which is also the product default (D-016).
    let fetch_cap = match max_fetch_bytes {
        Some(n) => format!(r#""maxFetchBytes": {n},"#),
        None => String::new(),
    };
    let authored = format!(
        r#"{{
          "schemaVersion": 3,
          "sources": [{{
            "name": "fixture",
            "kind": {{ "type": "local-folder", "address": {{ "root": {root} }} }},
            "scope": ["in-scope"],
            "sensitivity": 2
          }}],
          {fetch_cap}
          "volume": {{ "admissions": 3, "windowSeconds": 60 }}
        }}"#,
        root = serde_json::to_string(fixture_root).unwrap(),
    );
    let device = format!(
        r#"{{
          "boxId": "box-local-test",
          "environment": "local",
          "maxReadBytes": 64,
          "gate": {{
            "listen": "127.0.0.1:7580",
            "url": "https://127.0.0.1:7580",
            "certPath": "certs/core.pem",
            "keyPath": "certs/core.key",
            "clientCaPath": "certs/client-ca.pem",
            "certPin": "{pin}"
          }},
          "endpoint": {{
            "clientCertPath": "certs/endpoint.pem",
            "clientKeyPath": "certs/endpoint.key",
            "consoleListen": "127.0.0.1:7582"
          }},
          "artifacts": "artifacts",
          "workspace": "workspace",
          "journalDir": "journal",
          "audit": {{ "sink": "jsonl", "path": "audit/core.jsonl" }}
        }}"#,
        pin = pin.as_str(),
    )
    .replace("DIR", &dir.display().to_string());
    (authored, device)
}

async fn start() -> Fixture {
    start_with(None).await
}

/// `max_fetch_bytes` is `None` for every test but the one that checks the cap
/// exists, because absent is the product default (D-016).
async fn start_with(max_fetch_bytes: Option<u64>) -> Fixture {
    tls::install_provider();

    let dir = tempfile::tempdir().unwrap();
    let certs = make_certs();

    std::fs::create_dir_all(dir.path().join("certs")).unwrap();
    for (name, body) in [
        ("client-ca.pem", &certs.ca_pem),
        ("core.pem", &certs.core_cert_pem),
        ("core.key", &certs.core_key_pem),
        ("endpoint.pem", &certs.endpoint_cert_pem),
        ("endpoint.key", &certs.endpoint_key_pem),
    ] {
        std::fs::write(dir.path().join("certs").join(name), body).unwrap();
    }

    // A small fixture: one scope with two files, one file outside it.
    let root = dir.path().join("fixture");
    std::fs::create_dir_all(root.join("in-scope").join("docs")).unwrap();
    std::fs::create_dir_all(root.join("elsewhere")).unwrap();
    std::fs::write(root.join("in-scope").join("docs").join("note.txt"), b"note").unwrap();
    std::fs::write(root.join("in-scope").join("docs").join("big.bin"), vec![b'x'; 200]).unwrap();
    std::fs::write(root.join("elsewhere").join("secret.txt"), b"secret").unwrap();

    let config_path = dir.path().join("local.json");
    let (authored, device) = config_json(dir.path(), &root, &certs.pin, max_fetch_bytes);
    std::fs::write(&config_path, authored).unwrap();
    std::fs::write(sluse_proto::config::device_path(&config_path), device).unwrap();

    let loaded: Loaded = sluse_proto::config::load(&config_path).unwrap();
    let compiled = scope::compile(&loaded).unwrap();
    let posture = preflight::run(&loaded, preflight::CertCheck::Ok { pin: certs.pin.clone() });
    assert!(posture.required_passed(), "the fixture config should pass the required checks");

    let sink = Arc::new(MemorySink::new());
    let front = sluse_gate_core::front::gate_start(&loaded, "127.0.0.1:0", false).unwrap();
    let core = Arc::new(
        Core::new(loaded, compiled, sink.clone(), posture)
            .with_journal_mirror(Some(dir.path().join("boxes").join("me").join("journal"))),
    );

    let served = sluse_gate_front::testing::serve(front, http::router(core)).await;
    let addr = served.addr();

    Fixture {
        _dir: dir,
        root,
        addr,
        ca: CertificateDer::from_pem_slice_owned(certs.ca_pem.as_bytes()),
        client_cert: certs_from_pem(&certs.endpoint_cert_pem),
        client_key: key_from_pem(&certs.endpoint_key_pem),
        sink,
        served,
    }
}

fn certs_from_pem(pem: &str) -> Vec<CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem.as_bytes()).map(|c| c.unwrap()).collect()
}

fn key_from_pem(pem: &str) -> PrivateKeyDer<'static> {
    use rustls::pki_types::pem::PemObject;
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).unwrap()
}

trait PemOwned {
    fn from_pem_slice_owned(b: &[u8]) -> Self;
}

impl PemOwned for CertificateDer<'static> {
    fn from_pem_slice_owned(b: &[u8]) -> Self {
        use rustls::pki_types::pem::PemObject;
        CertificateDer::pem_slice_iter(b).next().unwrap().unwrap()
    }
}

// ---------------------------------------------------------------------------
// A minimal HTTP/1.1 client over rustls
// ---------------------------------------------------------------------------
//
// Hand-rolled rather than reqwest, for one reason: these tests are about what
// the *handshake* does, and a client library that retries, falls back or hides a
// TLS error behind a generic "request failed" would make the interesting cases
// indistinguishable from each other.

fn client_config(fx: &Fixture, with_client_cert: bool, trust_ca: bool) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    if trust_ca {
        roots.add(fx.ca.clone()).unwrap();
    } else {
        // A CA that signed nothing in play.
        let other = make_certs();
        roots.add(CertificateDer::from_pem_slice_owned(other.ca_pem.as_bytes())).unwrap();
    }

    let builder = ClientConfig::builder().with_root_certificates(roots);
    if with_client_cert {
        builder
            .with_client_auth_cert(fx.client_cert.clone(), fx.client_key.clone_key())
            .unwrap()
    } else {
        builder.with_no_client_auth()
    }
}

#[derive(Debug)]
struct Reply {
    status: u16,
    body: String,
}

fn request(
    fx: &Fixture,
    config: ClientConfig,
    method: &str,
    path: &str,
    session: Option<&str>,
    body: Option<&str>,
) -> std::io::Result<Reply> {
    let server_name = ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(std::io::Error::other)?;
    let mut sock = TcpStream::connect(fx.addr)?;
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let body = body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         Content-Type: application/json\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(s) = session {
        req.push_str(&format!("x-sluse-session: {s}\r\n"));
    }
    req.push_str("\r\n");
    req.push_str(body);

    tls.write_all(req.as_bytes())?;
    tls.flush()?;

    let mut raw = Vec::new();
    // `close_notify` is not always sent before the socket closes; an unexpected
    // EOF after a complete response is not a failure of the thing under test.
    match tls.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => return Err(e),
    }

    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| std::io::Error::other(format!("no status line in {text:?}")))?;
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_owned()).unwrap_or_default();
    // Chunked bodies from axum: strip the framing rather than parse it.
    let body = body
        .lines()
        .filter(|l| !l.trim().is_empty() && u32::from_str_radix(l.trim(), 16).is_err())
        .collect::<Vec<_>>()
        .join("");
    Ok(Reply { status, body })
}

fn good(fx: &Fixture) -> ClientConfig {
    client_config(fx, true, true)
}

fn health_session(fx: &Fixture) -> String {
    let reply = request(fx, good(fx), "GET", "/v1/health", None, None).unwrap();
    assert_eq!(reply.status, 200);
    let v: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    v["sessionId"].as_str().unwrap().to_owned()
}

// ---------------------------------------------------------------------------
// The handshake
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_without_a_certificate_never_gets_an_http_connection() {
    let fx = start().await;

    // No client certificate: the handshake itself fails. Not a 401, not a 403 —
    // there is no response at all, because there is no connection to answer on.
    // This is the transport's one structural claim and it is worth an assertion
    // that would fail loudly if the verifier were ever relaxed.
    let err = request(&fx, client_config(&fx, false, true), "GET", "/v1/health", None, None)
        .expect_err("an anonymous client must not reach a route");
    // Under TLS 1.3 the client finishes its half before the server rejects it,
    // so a write can race the alert and see the socket aborted (Windows 10053)
    // or reset instead. Still no response; still the handshake that refused it.
    let text = err.to_string().to_lowercase();
    let torn_down = matches!(
        err.kind(),
        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset
    );
    assert!(
        torn_down
            || text.contains("certificate")
            || text.contains("handshake")
            || text.contains("alert"),
        "expected a TLS failure, got: {err}"
    );

    // And nothing was recorded, because nothing reached Gate Core.
    assert!(fx.sink.records().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_that_does_not_trust_the_core_refuses_it() {
    let fx = start().await;
    // The other direction: the endpoint trusts one certificate and no CA bundle,
    // so a Gate Core it does not recognise is not one it will talk to.
    assert!(request(&fx, client_config(&fx, true, false), "GET", "/v1/health", None, None).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_client_with_the_right_certificate_gets_through() {
    let fx = start().await;
    let reply = request(&fx, good(&fx), "GET", "/v1/health", None, None).unwrap();
    assert_eq!(reply.status, 200);

    let v: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["boxId"], "box-local-test");
    // LOCAL identity is accountability-grade, not evidence-grade, and the record
    // says which it is rather than leaving it to be assumed.
    assert_eq!(v["user"]["kind"], "osProcess");
    assert!(v["postureId"].as_str().unwrap().starts_with("post-"));
    assert!(v["sessionId"].as_str().unwrap().starts_with("sess-"));
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_session_the_core_did_not_issue_is_refused() {
    let fx = start().await;

    // A well-formed id the guest minted for itself. This is the case that
    // matters: an agent rotating session ids to keep the volume window from ever
    // filling up.
    let forged = sluse_proto::SessionId::mint();
    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(forged.as_str()),
        Some(r#"{"path":"fixture/in-scope","audience":"agent"}"#),
    )
    .unwrap();

    assert_eq!(reply.status, 401);
    assert!(reply.body.contains("UNKNOWN_SESSION"), "{}", reply.body);

    // Recorded, under the sentinel rather than under the string the caller
    // invented.
    let records = fx.sink.records();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].reason.as_deref(), Some("UNKNOWN_SESSION"));
    assert_eq!(records[0].session_id.as_str(), "sess-unknown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_session_header_at_all_is_the_same_refusal() {
    let fx = start().await;
    let reply = request(&fx, good(&fx), "GET", "/v1/config-view", None, None).unwrap();
    assert_eq!(reply.status, 401);
    assert!(reply.body.contains("UNKNOWN_SESSION"));
}

// ---------------------------------------------------------------------------
// The routes
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_config_view_shows_scopes_in_request_form_and_no_host_path() {
    let fx = start().await;
    let s = health_session(&fx);
    let reply = request(&fx, good(&fx), "GET", "/v1/config-view", Some(&s), None).unwrap();
    assert_eq!(reply.status, 200);

    let v: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let scopes = v["sources"][0]["scopes"].as_array().unwrap();
    // Request form, not a host path: this is the field the agent navigates by,
    // and a host path in it would tell the guest about a filesystem it has not
    // asked about (invariant 2).
    assert_eq!(scopes[0], "fixture/in-scope");
    for s in scopes {
        assert!(
            !s.as_str().unwrap().contains('\\'),
            "a host path in the scope list: {s}"
        );
    }
    assert!(v.get("fetch").is_none(), "D-019 removed the toggle; the view does not carry it");
    assert_eq!(v["maxReadBytes"], 64);

    // `address`, by contrast, **is** the host root, by M1's deliberate choice —
    // "where it is, for the console to show a person" (`wire.rs`). It is left as
    // written rather than quietly narrowed here, and it sits oddly beside the
    // `scopes` field's own promise that the guest is never told a host path it
    // did not ask about, since the console runs inside the guest. Flagged for
    // jok; not this milestone's to decide.
    // Asserted as equality with the host root rather than "contains a
    // backslash": the claim is that the address is left as written, and the
    // separator it happens to use is the platform's business (D-011).
    let host_root = fx._dir.path().join("fixture");
    assert_eq!(v["sources"][0]["address"].as_str().unwrap(), host_root.to_str().unwrap());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_console_audience_greys_what_the_agent_never_sees() {
    // M5. The same directory, listed twice, is the whole of D-008 in one test:
    // the agent's world is smaller than the user's, and the difference is
    // `elsewhere` — absent from one listing, present and greyed in the other.
    let fx = start().await;
    let s = health_session(&fx);

    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture","audience":"user"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 200, "user is served at M5: {}", reply.body);

    let v: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let entries = v["entries"].as_array().unwrap();
    let by_name: std::collections::BTreeMap<&str, bool> = entries
        .iter()
        .map(|e| (e["name"].as_str().unwrap(), e["inScope"].as_bool().unwrap()))
        .collect();

    assert_eq!(by_name.get("in-scope"), Some(&true), "a scope is not greyed");
    assert_eq!(
        by_name.get("elsewhere"),
        Some(&false),
        "the console shows what the agent cannot have, greyed; that is what it is for"
    );

    // A listing is not a refusal, at either audience.
    assert!(fx.sink.records().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_console_may_walk_out_of_scope_and_the_agent_may_not() {
    // The audiences differ in how far out they may look, not only in what is
    // hidden from the listing they get.
    let fx = start().await;
    let s = health_session(&fx);

    let user = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture/elsewhere","audience":"user"}"#),
    )
    .unwrap();
    assert_eq!(user.status, 200, "{}", user.body);
    let v: serde_json::Value = serde_json::from_str(&user.body).unwrap();
    let names: Vec<&str> =
        v["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(names, vec!["secret.txt"]);
    assert_eq!(v["entries"][0]["inScope"], false);

    let agent = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture/elsewhere","audience":"agent"}"#),
    )
    .unwrap();
    // The hidden form for the guest (D-033 point 2): a path that is not there,
    // with that status too, so neither tells it from out of scope. The host's
    // record keeps the truth.
    assert_eq!(agent.status, 404, "{}", agent.body);
    let e: serde_json::Value = serde_json::from_str(&agent.body).unwrap();
    assert_eq!(e["code"], "NOT_FOUND");
    assert!(e.get("scopes").is_none() && e.get("resolved").is_none(), "{e}");

    let records = fx.sink.records();
    assert_eq!(records.len(), 1, "the agent's refusal is recorded; the console's listing is not");
    assert_eq!(records[0].reason.as_deref(), Some("OUT_OF_SCOPE"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_listing_omits_what_is_out_of_scope_rather_than_refusing_it() {
    let fx = start().await;
    let s = health_session(&fx);

    // The source root. `in-scope` leads to a scope, `elsewhere` does not.
    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture","audience":"agent"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 200);

    let v: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    let names: Vec<&str> =
        v["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    // D-008: absent, not forbidden. `elsewhere` is not listed and not refused —
    // an agent that could enumerate what it may not have has been told what
    // exists.
    assert_eq!(names, vec!["in-scope"]);

    // A listing is not a refusal, so nothing was recorded.
    assert!(fx.sink.records().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_returns_the_bytes_and_records_the_admission_on_completion() {
    let fx = start().await;
    let s = health_session(&fx);

    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/read",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope/docs/note.txt","verb":"read"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 200);
    assert!(reply.body.contains("note"), "{:?}", reply.body);

    let records = fx.sink.records();
    assert_eq!(records.len(), 1);
    let rec = &records[0];
    assert_eq!(rec.op, sluse_proto::Op::Read);
    assert_eq!(rec.outcome, sluse_proto::Outcome::Admitted);
    assert_eq!(rec.bytes, Some(4));
    // Gate Core hashed what it sent. The endpoint hashes what it received and
    // `admission_id` joins the two records (invariant 7).
    assert_eq!(rec.hash, Some(ContentHash::of(b"note")));
    assert!(rec.admission_id.is_some());
    assert_eq!(rec.scope.as_deref(), Some("fixture/in-scope"));
    assert_eq!(rec.session_id.as_str(), s);
    assert!(rec.posture_id.is_some());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_over_the_cap_is_refused_before_a_byte_and_fetch_is_not() {
    let fx = start().await;
    let s = health_session(&fx);

    // `maxReadBytes` is 64 in the fixture and big.bin is 200.
    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/read",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope/docs/big.bin","verb":"read"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 413);
    assert!(reply.body.contains("TOO_LARGE"));

    // The same file by fetch, which streams to the guest's disk and is not
    // capped **by default**. The read cap exists because `read` puts bytes
    // inline in a context window, not because 200 bytes is a lot. A deployment
    // can set `maxFetchBytes` (D-016); this fixture does not, which is what the
    // product default looks like.
    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/read",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope/docs/big.bin","verb":"fetch"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 200);

    let records = fx.sink.records();
    assert_eq!(records[0].reason.as_deref(), Some("TOO_LARGE"));
    assert_eq!(records[0].outcome, sluse_proto::Outcome::Refused);
    assert_eq!(records[1].op, sluse_proto::Op::Fetch);
    assert_eq!(records[1].bytes, Some(200));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_config_view_reports_whether_a_source_last_answered() {
    // **D-015 point 4.** On 2026-09-22 the file server powered off and
    // `sluse_sources` went on advertising both trees for thirteen minutes, so
    // the agent had no way to tell "I am asking wrongly" from "the source is
    // gone" — and concluded that 125 files it had just listed did not exist.
    let fx = start().await;
    let s = health_session(&fx);

    // Nothing has asked it yet, so there is nothing to report. Absent rather
    // than optimistic: this is an observation log, not a guess.
    let view = request(&fx, good(&fx), "GET", "/v1/config-view", Some(&s), None).unwrap();
    let v: serde_json::Value = serde_json::from_str(&view.body).unwrap();
    assert!(v["sources"][0].get("lastSeen").is_none(), "no observation yet");

    // A listing that works is an observation that it answered.
    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope","audience":"agent"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 200);

    let view = request(&fx, good(&fx), "GET", "/v1/config-view", Some(&s), None).unwrap();
    let v: serde_json::Value = serde_json::from_str(&view.body).unwrap();
    assert_eq!(v["sources"][0]["lastSeen"]["reachable"], true);
    assert!(v["sources"][0]["lastSeen"]["at"].is_string(), "with when");

    // And a refusal that is *about the path* says nothing about the source:
    // out of scope means the source answered perfectly well.
    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture/elsewhere","audience":"agent"}"#),
    )
    .unwrap();
    assert_ne!(reply.status, 200);

    let view = request(&fx, good(&fx), "GET", "/v1/config-view", Some(&s), None).unwrap();
    let v: serde_json::Value = serde_json::from_str(&view.body).unwrap();
    assert_eq!(
        v["sources"][0]["lastSeen"]["reachable"], true,
        "a path refusal is not a source failure"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_that_goes_away_mid_run_is_reported_as_a_fault_not_as_absence() {
    // **The whole of D-015, end to end, in the shape the scored run had it.**
    // The source is there, Gate Core starts, the agent works — and then the
    // machine serving it goes away. Before this, every call after that moment
    // came back as D-008's blinded "No such path", the trail recorded 33
    // `NOT_FOUND`s, and `sluse_sources` kept advertising the source as fine.
    let fx = start().await;
    let s = health_session(&fx);

    let ok = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope","audience":"agent"}"#),
    )
    .unwrap();
    assert_eq!(ok.status, 200, "the source answers to begin with");

    std::fs::remove_dir_all(&fx.root).unwrap();

    let gone = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/list",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope","audience":"agent"}"#),
    )
    .unwrap();
    assert!(
        gone.body.contains("SOURCE_UNAVAILABLE"),
        "an outage is not an absence: {}",
        gone.body
    );

    // The record says which it was, and carries what the source said.
    let records = fx.sink.records();
    let last = records.last().unwrap();
    assert_eq!(last.reason.as_deref(), Some("SOURCE_UNAVAILABLE"));
    assert!(last.detail.is_some(), "the only evidence this was an outage (D-015 p3)");

    // And the next `sluse_sources` will say so rather than advertising it.
    let view = request(&fx, good(&fx), "GET", "/v1/config-view", Some(&s), None).unwrap();
    let v: serde_json::Value = serde_json::from_str(&view.body).unwrap();
    assert_eq!(v["sources"][0]["lastSeen"]["reachable"], false);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_fetch_over_max_fetch_bytes_is_refused_when_one_is_configured() {
    // D-016. The scored run moved a 500 MB file through `fetch` with no cap,
    // warning or confirmation, and the agent was the one who noticed. The answer
    // is not a default cap — admission is the control point, not size
    // (invariant 4) — but a deployment that wants a ceiling can have one, and it
    // has to actually refuse.
    let fx = start_with(Some(128)).await;
    let s = health_session(&fx);

    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/read",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope/docs/big.bin","verb":"fetch"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 413, "200 bytes over a 128-byte fetch cap");
    assert!(reply.body.contains("TOO_LARGE"));

    // And under the cap still works, so the cap is a cap and not a switch.
    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/read",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope/docs/note.txt","verb":"fetch"}"#),
    )
    .unwrap();
    assert_eq!(reply.status, 200);

    let records = fx.sink.records();
    assert_eq!(records[0].reason.as_deref(), Some("TOO_LARGE"));
    assert_eq!(records[0].op, sluse_proto::Op::Fetch, "refused as a fetch, not as a read");
    assert_eq!(records[0].bytes, None, "refused before a byte was opened");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_out_of_scope_read_is_refused_and_the_record_keeps_what_the_agent_is_not_told() {
    let fx = start().await;
    let s = health_session(&fx);

    let reply = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/read",
        Some(&s),
        Some(r#"{"path":"fixture/elsewhere/secret.txt","verb":"read"}"#),
    )
    .unwrap();
    // The guest is told the hidden form (D-033 point 2); Gate Core's record is
    // complete — the resolved host path and the enforcing scope list.
    assert_eq!(reply.status, 404);
    assert!(reply.body.contains("NOT_FOUND") && !reply.body.contains("scopes"), "{}", reply.body);
    let rec = &fx.sink.records()[0];
    assert_eq!(rec.outcome, sluse_proto::Outcome::Refused);
    assert_eq!(rec.reason.as_deref(), Some("OUT_OF_SCOPE"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stat_takes_the_quick_path_when_the_pin_still_matches() {
    let fx = start().await;
    let s = health_session(&fx);

    let first = request(
        &fx,
        good(&fx),
        "POST",
        "/v1/stat",
        Some(&s),
        Some(r#"{"path":"fixture/in-scope/docs/note.txt"}"#),
    )
    .unwrap();
    assert_eq!(first.status, 200);
    let v: serde_json::Value = serde_json::from_str(&first.body).unwrap();
    assert_eq!(v["size"], 4);
    assert_eq!(v["hash"], ContentHash::of(b"note").as_str());
    assert!(v["matchesPinned"].is_null(), "no pin was sent");

    let pin = serde_json::json!({
        "path": "fixture/in-scope/docs/note.txt",
        "pinned": { "hash": v["hash"], "size": v["size"], "modified": v["modified"] }
    });
    let second =
        request(&fx, good(&fx), "POST", "/v1/stat", Some(&s), Some(&pin.to_string())).unwrap();
    let v2: serde_json::Value = serde_json::from_str(&second.body).unwrap();
    assert_eq!(v2["matchesPinned"], true);

    // Every call, including the quick path. The console's inventory refresh is
    // user-initiated rather than polled, which is what keeps this bounded.
    let records = fx.sink.records();
    assert_eq!(records.len(), 2);
    assert!(records.iter().all(|r| r.op == sluse_proto::Op::Metadata));
    // Review R-26: the quick path's hash is the box's pin, not Gate Core's.
    assert_eq!(records[0].hash, Some(ContentHash::of(b"note")));
    assert_eq!(records[1].hash, None);
    assert_eq!(records[1].reason.as_deref(), Some("PIN_MATCHED"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_publish_lands_in_its_own_folder_and_a_name_twice_in_one_is_refused() {
    let fx = start().await;
    let s = health_session(&fx);
    read_note(&fx, &s);

    let body = b"a summary";
    let manifest = serde_json::json!({
        "artifacts": [{
            "name": "summary.md",
            "hash": ContentHash::of(body).as_str(),
            "bytes": body.len(),
            "sources": [{ "path": "fixture/in-scope/docs/note.txt", "hash": ContentHash::of(b"note").as_str() }],
        }],
        "lineage": [{
            "path": "fixture/in-scope/docs/note.txt",
            "hash": ContentHash::of(b"note").as_str(),
            "state": "read",
        }],
    });

    let reply = multipart(&fx, &s, &manifest.to_string(), &[("summary.md", body)]);
    assert_eq!(reply.status, 200, "{}", reply.body);

    let artifacts = fx._dir.path().join("artifacts");
    // All or nothing, and the staging directory does not survive either way.
    assert!(!artifacts.join(".incoming").exists());

    let rec = fx.sink.records().into_iter().find(|r| r.op == sluse_proto::Op::Publish).unwrap();
    assert_eq!(rec.artifact.as_deref(), Some("summary.md"));
    assert_eq!(rec.lineage.as_ref().unwrap().len(), 1);
    assert_eq!(rec.lineage.as_ref().unwrap()[0].state, Some(sluse_proto::AdmissionState::Read), "the box's word on state");
    assert!(rec.lineage.as_ref().unwrap()[0].admission_id.is_some(), "Gate Core's own admission");
    assert_eq!(rec.sources.as_ref().unwrap()[0].path, "fixture/in-scope/docs/note.txt");
    // Q-4 and Q-5 are open, so nothing writes a label it cannot honour.
    assert_eq!(rec.label, None);

    // One folder per delivery (D-031 point 5): `<date> <time> <what it is>`,
    // and the record and the reply both name it.
    let landed = std::path::PathBuf::from(rec.path_resolved.as_deref().unwrap());
    assert_eq!(std::fs::read(&landed).unwrap(), body);
    let folder = landed.parent().unwrap();
    assert_eq!(folder.parent().unwrap(), artifacts);
    let folder_name = folder.file_name().unwrap().to_str().unwrap();
    assert!(folder_name.ends_with(" summary"), "{folder_name}");
    assert_eq!(rec.path_requested, format!("artifacts/{folder_name}/summary.md"));
    assert!(reply.body.contains(folder_name), "{}", reply.body);
    // The Internet zone, in the stream Windows writes on a download (D-031
    // point 4). NTFS only, so CI's Windows job is where this is asserted.
    #[cfg(windows)]
    {
        let mut stream = landed.as_os_str().to_owned();
        stream.push(":Zone.Identifier");
        assert!(std::fs::read_to_string(stream).unwrap().contains("ZoneId=3"));
    }

    // The same name again is a second delivery in a second folder, and the
    // first is untouched.
    let again = multipart(&fx, &s, &manifest.to_string(), &[("summary.md", body)]);
    assert_eq!(again.status, 200, "{}", again.body);
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 2);
    assert_eq!(std::fs::read(&landed).unwrap(), body);

    // Within one delivery a name twice is refused: the second write would win
    // silently and its record would describe the first.
    let twice = serde_json::json!({
        "artifacts": [
            { "name": "summary.md", "hash": ContentHash::of(body).as_str(), "bytes": body.len(), "sources": [] },
            { "name": "summary.md", "hash": ContentHash::of(body).as_str(), "bytes": body.len(), "sources": [] },
        ],
        "lineage": [],
    });
    let refused = multipart(&fx, &s, &twice.to_string(), &[("summary.md", body), ("summary.md", body)]);
    assert_eq!(refused.status, 409);
    assert!(refused.body.contains("ARTIFACT_EXISTS"));
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 2, "nothing of the refused one");

    // R-52: names NTFS takes for one file are one name here too, on every
    // platform, so the second cannot overwrite the first in staging.
    let other: &[u8] = b"other bytes\n";
    let folded = serde_json::json!({
        "artifacts": [
            { "name": "x/summary.md", "hash": ContentHash::of(body).as_str(), "bytes": body.len(), "sources": [] },
            { "name": "X\\SUMMARY.md", "hash": ContentHash::of(other).as_str(), "bytes": other.len(), "sources": [] },
        ],
        "lineage": [],
    });
    let refused = multipart(&fx, &s, &folded.to_string(), &[("x/summary.md", body), ("X\\SUMMARY.md", other)]);
    assert_eq!(refused.status, 409, "{}", refused.body);
    assert!(refused.body.contains("ARTIFACT_EXISTS"));
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 2, "nothing of the folded pair");
}

fn read_note(fx: &Fixture, s: &str) {
    let body = r#"{"path":"fixture/in-scope/docs/note.txt","verb":"read"}"#;
    let reply = request(fx, good(fx), "POST", "/v1/read", Some(s), Some(body)).unwrap();
    assert_eq!(reply.status, 200, "{}", reply.body);
}

/// D-059, review R-07: the lineage on the record is what Gate Core admitted
/// under the session, whatever the manifest says. A source Gate Core never
/// admitted is refused even when the manifest's lineage lists it, and a
/// manifest that leaves an admission out does not take it off the record.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_publish_record_carries_the_cores_lineage_not_the_guests() {
    let fx = start().await;
    let s = health_session(&fx);
    read_note(&fx, &s);
    let body = b"a summary";
    let secret = ContentHash::of(b"secret");

    let forged = serde_json::json!({
        "artifacts": [{
            "name": "summary.md", "hash": ContentHash::of(body).as_str(), "bytes": body.len(),
            "sources": [{ "path": "fixture/elsewhere/secret.txt", "hash": secret.as_str() }],
        }],
        "lineage": [{ "path": "fixture/elsewhere/secret.txt", "hash": secret.as_str(), "state": "read" }],
    });
    let reply = multipart(&fx, &s, &forged.to_string(), &[("summary.md", body)]);
    assert!(reply.body.contains("SOURCE_NOT_ADMITTED"), "{} {}", reply.status, reply.body);

    let omitted = serde_json::json!({
        "artifacts": [{ "name": "summary.md", "hash": ContentHash::of(body).as_str(), "bytes": body.len(), "sources": [] }],
        "lineage": [],
    });
    let reply = multipart(&fx, &s, &omitted.to_string(), &[("summary.md", body)]);
    assert_eq!(reply.status, 200, "{}", reply.body);
    let rec = fx.sink.records().into_iter().find(|r| r.op == sluse_proto::Op::Publish && r.outcome == sluse_proto::Outcome::Admitted).unwrap();
    let lineage = rec.lineage.unwrap();
    assert_eq!(lineage.len(), 1, "{lineage:?}");
    assert_eq!(lineage[0].hash, ContentHash::of(b"note"));
    assert_eq!(lineage[0].state, None, "the box said nothing about it");
}

/// Review R-11: axum's 2 MiB default no longer caps a delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_over_two_mebibytes_lands() {
    let fx = start().await;
    let s = health_session(&fx);
    let body = vec![b'd'; 3 * 1024 * 1024];
    let manifest = serde_json::json!({
        "artifacts": [{ "name": "deck.pptx", "hash": ContentHash::of(&body).as_str(), "bytes": body.len(), "sources": [] }],
        "lineage": [],
    });
    let reply = multipart(&fx, &s, &manifest.to_string(), &[("deck.pptx", &body)]);
    assert_eq!(reply.status, 200, "{}", reply.body);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_publish_whose_bytes_do_not_match_the_manifest_writes_nothing() {
    let fx = start().await;
    let s = health_session(&fx);

    let manifest = serde_json::json!({
        "artifacts": [
            { "name": "good.md", "hash": ContentHash::of(b"good").as_str(), "bytes": 4, "sources": [] },
            { "name": "bad.md", "hash": ContentHash::of(b"declared").as_str(), "bytes": 4, "sources": [] },
        ],
        "lineage": [],
    });

    let reply = multipart(
        &fx,
        &s,
        &manifest.to_string(),
        &[("good.md", b"good"), ("bad.md", b"sent")],
    );
    assert_eq!(reply.status, 422);
    assert!(reply.body.contains("HASH_MISMATCH"));

    // The whole publish, not just the bad file. The good one came from the same
    // place, and an artifact whose manifest does not describe its bytes is the
    // one thing a provenance record must never carry.
    // Not even its folder: nothing is created before every hash has matched.
    let artifacts = fx._dir.path().join("artifacts");
    assert_eq!(std::fs::read_dir(&artifacts).unwrap().count(), 0, "a half-written delivery");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bulk_admission_raises_exactly_one_alert_and_the_alerts_route_shows_it() {
    let fx = start().await;
    let s = health_session(&fx);

    // The fixture's threshold is 3 distinct files in 60 s, and there are three
    // readable files in scope once `big.bin` is fetched. Read each twice: the
    // window counts **distinct content hashes**, so the repeats do not count.
    let dir = fx._dir.path().join("fixture").join("in-scope").join("docs");
    std::fs::write(dir.join("third.txt"), b"third").unwrap();

    for _ in 0..2 {
        for name in ["note.txt", "big.bin", "third.txt"] {
            let body = format!(r#"{{"path":"fixture/in-scope/docs/{name}","verb":"fetch"}}"#);
            let reply =
                request(&fx, good(&fx), "POST", "/v1/read", Some(&s), Some(&body)).unwrap();
            assert_eq!(reply.status, 200, "{name}");
        }
    }

    let alerts = fx
        .sink
        .records()
        .into_iter()
        .filter(|r| r.op == sluse_proto::Op::Alert)
        .collect::<Vec<_>>();
    assert_eq!(alerts.len(), 1, "one alert per crossing, not one per admission");
    // Raised, not Refused: the admissions that caused it were permitted and
    // happened. Detective, not preventive.
    assert_eq!(alerts[0].outcome, sluse_proto::Outcome::Raised);

    let reply = request(&fx, good(&fx), "GET", "/v1/alerts", Some(&s), None).unwrap();
    assert_eq!(reply.status, 200);
    let v: serde_json::Value = serde_json::from_str(&reply.body).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);
    assert_eq!(v[0]["count"], 3);
    assert_eq!(v[0]["source"], "fixture");
}

/// A multipart publish, hand-built for the same reason the HTTP client is.
fn multipart(fx: &Fixture, session: &str, manifest: &str, files: &[(&str, &[u8])]) -> Reply {
    const BOUNDARY: &str = "----sluse-test-boundary";

    let mut body: Vec<u8> = Vec::new();
    let part = |name: &str, filename: Option<&str>, content: &[u8], body: &mut Vec<u8>| {
        body.extend_from_slice(format!("--{BOUNDARY}\r\n").as_bytes());
        match filename {
            Some(f) => body.extend_from_slice(
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{f}\"\r\n\r\n"
                )
                .as_bytes(),
            ),
            None => body.extend_from_slice(
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            ),
        }
        body.extend_from_slice(content);
        body.extend_from_slice(b"\r\n");
    };

    part("manifest", None, manifest.as_bytes(), &mut body);
    for (name, content) in files {
        part(name, Some(name), content, &mut body);
    }
    body.extend_from_slice(format!("--{BOUNDARY}--\r\n").as_bytes());

    let server_name = ServerName::try_from("localhost").unwrap();
    let mut conn = rustls::ClientConnection::new(Arc::new(good(fx)), server_name).unwrap();
    let mut sock = TcpStream::connect(fx.addr).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    let head = format!(
        "POST /v1/publish HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\
         x-sluse-session: {session}\r\n\
         Content-Type: multipart/form-data; boundary={BOUNDARY}\r\n\
         Content-Length: {}\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes()).unwrap();
    tls.write_all(&body).unwrap();
    tls.flush().unwrap();

    let mut raw = Vec::new();
    match tls.read_to_end(&mut raw) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {}
        Err(e) => panic!("{e}"),
    }

    let text = String::from_utf8_lossy(&raw).into_owned();
    let status = text.split_whitespace().nth(1).and_then(|s| s.parse().ok()).unwrap_or(0);
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b.to_owned()).unwrap_or_default();
    let body = body
        .lines()
        .filter(|l| !l.trim().is_empty() && u32::from_str_radix(l.trim(), 16).is_err())
        .collect::<Vec<_>>()
        .join("");
    Reply { status, body }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_of_nested_paths_lands_as_a_tree() {
    let fx = start().await;
    let s = health_session(&fx);

    // The shape S-2 actually published, and the reason artifact names may carry
    // subdirectories at all: a delivery that is a source tree is a delivery a
    // person can open.
    let lib = b"pub mod ids;";
    let ids = b"pub struct Id;";
    let manifest = serde_json::json!({
        "artifacts": [
            { "name": "crates/chapr-proto/src/lib.rs",
              "hash": ContentHash::of(lib).as_str(), "bytes": lib.len(), "sources": [] },
            { "name": "crates/chapr-proto/src/ids.rs",
              "hash": ContentHash::of(ids).as_str(), "bytes": ids.len(), "sources": [] },
        ],
        "lineage": [],
    });

    let reply = multipart(
        &fx,
        &s,
        &manifest.to_string(),
        &[("crates/chapr-proto/src/lib.rs", lib), ("crates/chapr-proto/src/ids.rs", ids)],
    );
    assert_eq!(reply.status, 200, "{}", reply.body);

    // Two artifacts, one act: same publish id on both records, one folder, and
    // the path in request form keeps the tree under it.
    let recs: Vec<_> = fx
        .sink
        .records()
        .into_iter()
        .filter(|r| r.op == sluse_proto::Op::Publish)
        .collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].publish_id, recs[1].publish_id);
    assert!(recs[0].path_requested.ends_with("/crates/chapr-proto/src/lib.rs"), "{}", recs[0].path_requested);

    let lib_at = std::path::PathBuf::from(recs[0].path_resolved.as_deref().unwrap());
    let root = lib_at.parent().unwrap();
    assert!(root.ends_with(std::path::Path::new("crates").join("chapr-proto").join("src")));
    assert_eq!(std::fs::read(root.join("lib.rs")).unwrap(), lib);
    assert_eq!(std::fs::read(root.join("ids.rs")).unwrap(), ids);
    assert!(!fx._dir.path().join("artifacts").join(".incoming").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_nested_name_that_climbs_out_is_refused_before_anything_is_written() {
    let fx = start().await;
    let s = health_session(&fx);

    let body = b"escaped";
    let manifest = serde_json::json!({
        "artifacts": [{
            "name": "../../escaped.md",
            "hash": ContentHash::of(body).as_str(),
            "bytes": body.len(),
            "sources": [],
        }],
        "lineage": [],
    });

    let reply = multipart(&fx, &s, &manifest.to_string(), &[("../../escaped.md", body)]);
    assert_eq!(reply.status, 400);
    assert!(reply.body.contains("MALFORMED_ARTIFACT_NAME"), "{}", reply.body);
    assert!(!fx._dir.path().join("escaped.md").exists());
}

// ---------------------------------------------------------------------------
// The journal mirror (review R-01)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn the_mirror_takes_only_a_session_the_core_issued_and_writes_inside_its_directory() {
    let fx = start().await;
    let s = health_session(&fx);
    let mirror = fx._dir.path().join("boxes").join("me").join("journal");
    let append = |session: &str| {
        serde_json::json!({ "session": session, "offset": 0, "lines": "{\"forged\":true}\n" }).to_string()
    };

    // Its own session: written where the mirror lives.
    let ok = request(&fx, good(&fx), "POST", "/v1/journal", Some(&s), Some(&append(&s))).unwrap();
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert!(mirror.join(format!("{s}.jsonl")).is_file());

    // A climb out of the directory, and a well-formed id nobody issued.
    for bad in ["../../escaped", "/tmp/escaped", "sess-20260101-deadbeef"] {
        let r = request(&fx, good(&fx), "POST", "/v1/journal", Some(&s), Some(&append(bad))).unwrap();
        assert_eq!(r.status, 401, "{bad}: {}", r.body);
    }
    assert!(!fx._dir.path().join("boxes").join("escaped.jsonl").exists());
    assert!(!fx._dir.path().join("escaped.jsonl").exists());
    let names: Vec<_> = std::fs::read_dir(&mirror).unwrap().flatten().map(|e| e.file_name()).collect();
    assert_eq!(names.len(), 1, "{names:?}");

    // Without a session header at all: refused before the body is looked at.
    let r = request(&fx, good(&fx), "POST", "/v1/journal", None, Some(&append(&s))).unwrap();
    assert_eq!(r.status, 401, "{}", r.body);

    let refused = fx.sink.records().into_iter().filter(|r| r.op == sluse_proto::Op::Journal).count();
    assert_eq!(refused, 4, "every refusal is on the host's record");
}

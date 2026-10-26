// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! M7, Gate Core half, against a local stand-in for Entra and Graph.
//!
//! **What this proves and what it does not.** It proves Gate Core's side of
//! the contract: which sign-ins it believes (D-036: a code redeemed as a
//! public client, its ID token checked), that it binds the box to one person
//! (D-022), that it renews without the guest and without a credential, that
//! URL mode records a decision and not a delivery, and that Graph's answers
//! are recorded as the source's. It proves nothing about Entra itself — the
//! stand-in speaks the documented shapes, and the test run against the demo
//! tenant is where they meet the real ones.
//!
//! Gate Core's router is driven in-process with `tower::ServiceExt::oneshot`;
//! sign-ins go through [`control::sign_in`], as the service's stdin does.
//! mTLS is `tests/mtls.rs`'s claim and is not re-proved here.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use jsonwebtoken::EncodingKey;
use serde_json::{json, Value};
use sluse_gate_core::app::Core;
use sluse_gate_core::audit::MemorySink;
use sluse_gate_core::entra::Entra;
use sluse_gate_core::{control, http, preflight, scope};
use sluse_proto::pipe::HostSignIn;
use sluse_proto::wire::header;
use sluse_proto::{Capability, ContentHash, HostSignInResult, Loaded, Op, Outcome, UserKind};
use tower::ServiceExt;

#[path = "support/entra_mock.rs"]
mod entra_mock;
use entra_mock::{claims, now, rsa, sign, ALICE, BOB, CLIENT, TENANT};

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fx {
    _dir: tempfile::TempDir,
    router: Router,
    core: Arc<Core>,
    sink: Arc<MemorySink>,
    stand_in: entra_mock::Running,
}

async fn fx() -> Fx {
    fx_with(json!(["In-Scope"])).await
}

/// The fixture with the SharePoint source's scope as given.
async fn fx_with(scope: Value) -> Fx {
    let mut source = entra_mock::sharepoint_source();
    source["scope"] = scope;
    fx_sources(json!([source])).await
}

/// The fixture with these sources.
async fn fx_sources(sources: Value) -> Fx {
    let stand_in = entra_mock::start().await;

    let dir = tempfile::tempdir().unwrap();
    let config = json!({
        "schemaVersion": 3,
        "sources": sources,
        "volume": { "admissions": 25, "windowSeconds": 60 },
        "entra": entra_mock::entra_block()
    });
    let device = json!({
        "boxId": "box-spo-test",
        "environment": "demo",
        "maxReadBytes": 64,
        "gate": {
            "listen": "127.0.0.1:7580", "url": "https://127.0.0.1:7580",
            "certPath": "certs/core.pem", "keyPath": "certs/core.key",
            "clientCaPath": "certs/client-ca.pem",
            "certPin": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "endpoint": { "clientCertPath": "c.pem", "clientKeyPath": "c.key", "consoleListen": "127.0.0.1:7582" },
        "artifacts": "artifacts", "workspace": "workspace", "journalDir": "journal",
        "audit": { "sink": "jsonl", "path": "audit/core.jsonl" }
    });
    let path = dir.path().join("demo.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    std::fs::write(sluse_proto::config::device_path(&path), serde_json::to_vec_pretty(&device).unwrap()).unwrap();
    let loaded: Loaded = sluse_proto::config::load(&path).unwrap();
    let compiled = scope::compile(&loaded).unwrap();
    let posture = preflight::run(&loaded, preflight::CertCheck::Ok { pin: ContentHash::of(b"x") });
    let base = stand_in.base.clone();
    let entra = Entra::new(loaded.config.entra.as_ref().unwrap(), &base, &format!("{base}/v1.0")).unwrap();
    let sink = Arc::new(MemorySink::new());
    let core = Arc::new(Core::new(loaded, compiled, sink.clone(), posture).with_entra(Some(entra)));

    Fx { _dir: dir, router: http::router(core.clone()), core, sink, stand_in }
}

impl Fx {
    fn alice(&self) -> HostSignIn {
        self.stand_in.alice()
    }

    fn bob(&self) -> HostSignIn {
        self.stand_in.code(&claims(BOB, "bob@contoso.example"))
    }

    /// A sign-in from the host, as the service's stdin hands it over.
    async fn sign_in(&self, s: HostSignIn) -> HostSignInResult {
        control::sign_in(&self.core, &s).await
    }

    async fn call(&self, method: Method, route: &str, session: Option<&str>, body: Value) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(route).header("content-type", "application/json");
        if let Some(s) = session {
            req = req.header(header::SESSION, s);
        }
        let body = if body.is_null() { Body::empty() } else { Body::from(serde_json::to_vec(&body).unwrap()) };
        let res = self.router.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec();
        (status, headers, bytes)
    }

    async fn session(&self) -> String {
        let (_, _, body) = self.call(Method::GET, "/v1/health", None, Value::Null).await;
        let v: Value = serde_json::from_slice(&body).unwrap();
        v["sessionId"].as_str().unwrap().to_owned()
    }

    async fn read(&self, session: &str, path: &str, verb: &str) -> (StatusCode, HeaderMap, Value) {
        let (s, h, b) = self.call(Method::POST, "/v1/read", Some(session), json!({ "path": path, "verb": verb })).await;
        (s, h, serde_json::from_slice(&b).unwrap_or(Value::Null))
    }

    fn faults(&self) -> Vec<String> {
        self.stand_in.faults()
    }

    fn sign_ins(&self) -> Vec<sluse_proto::AuditRecord> {
        self.sink.records().into_iter().filter(|r| r.op == Op::Signin).collect()
    }

    fn redemptions(&self) -> usize {
        self.stand_in.mock.redemptions.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_read_streams_the_file_and_the_record_names_the_user_and_the_hash() {
    let fx = fx().await;
    assert_eq!(fx.sign_in(fx.alice()).await.error, None);
    let s = fx.session().await;
    let (status, h, body) =
        fx.call(Method::POST, "/v1/read", Some(&s), json!({ "path": "spo/in-scope/a.txt", "verb": "read" })).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(&body[..], b"alpha", "the file, not an address (D-046)");
    assert!(h.get(header::CAPABILITY).is_none(), "absent is bytes");
    assert_eq!(h.get(header::SIZE).unwrap(), "5");
    assert!(fx.faults().is_empty(), "{:?}", fx.faults());
    // Nothing of ours reaches the download host: no session, no token.
    let seen = fx.stand_in.mock.download_headers.lock().unwrap().clone();
    for name in [header::SESSION, "authorization", "cookie"] {
        assert!(seen[0].get(name).is_none(), "the download carried {name}");
    }

    let recs = fx.sink.records();
    let rec = recs.iter().find(|r| r.op == Op::Read).expect("a read record");
    assert_eq!(rec.outcome, Outcome::Admitted);
    assert_eq!(rec.capability, Capability::Bytes);
    assert_eq!(rec.user.kind, UserKind::Entra);
    assert_eq!(rec.user.name, "alice@contoso.example");
    // A delivery, measured on the trusted side.
    assert_eq!(rec.hash.as_ref(), Some(&ContentHash::of(b"alpha")));
    assert_eq!(rec.bytes, Some(5));
    assert_eq!(rec.admission_id.as_ref().unwrap().as_str(), h.get(header::ADMISSION_ID).unwrap());
    assert_eq!(rec.scope.as_deref(), Some("spo/In-Scope"));
    // The library's address and the file's path, not Graph's webUrl, which
    // for an Office file is the viewer's (L1, 2026-10-07).
    assert_eq!(rec.path_resolved.as_deref(), Some("https://contoso.sharepoint.com/sites/tender/Documents/in-scope/a.txt"));
}

/// SharePoint answers any case; a read or fetch must use the file's own, so
/// the box keeps one copy under one name (L1, 2026-10-07).
#[tokio::test]
async fn a_file_named_in_another_case_is_refused_with_its_spelling() {
    let fx = fx().await;
    fx.sign_in(fx.alice()).await;
    let s = fx.session().await;
    let (st, _, body) = fx.read(&s, "spo/in-scope/mixed.txt", "fetch").await;
    assert_eq!(st, StatusCode::BAD_REQUEST, "{body}");
    assert!(body.to_string().contains("spo/in-scope/Mixed.txt"), "{body}");
    let (st, _, _) = fx.read(&s, "spo/in-scope/Mixed.txt", "fetch").await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn an_unbound_box_is_sign_in_required() {
    let fx = fx().await;
    let s = fx.session().await;
    let (status, _, body) = fx.read(&s, "spo/in-scope/a.txt", "read").await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "SIGN_IN_REQUIRED");
    assert!(body["message"].as_str().unwrap_or_default().contains("Sluse window") || body.to_string().contains("Sluse window"), "{body}");
    assert_eq!(fx.stand_in.mock.graph_calls.load(Ordering::SeqCst), 0, "Graph was asked with no user");
    let rec = fx.sink.records().into_iter().find(|r| r.op == Op::Read).unwrap();
    assert_eq!(rec.outcome, Outcome::Refused);
    assert_eq!(rec.user.kind, UserKind::OsProcess, "no user was proven, so none is named");
}

/// D-036: a header that once carried a token is not a way in now.
#[tokio::test]
async fn a_token_on_a_request_binds_nothing() {
    let fx = fx().await;
    let s = fx.session().await;
    let id = sign(&claims(ALICE, "alice@contoso.example"), "entra-1", &fx.stand_in.entra_key);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/v1/read")
        .header("content-type", "application/json")
        .header(header::SESSION, &s)
        .header("x-sluse-user-token", id)
        .body(Body::from(json!({ "path": "spo/in-scope/a.txt", "verb": "read" }).to_string()))
        .unwrap();
    let res = fx.router.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    assert!(fx.core.entra.as_ref().unwrap().binding().is_none());
    // And there is no sign-in route to post one to.
    let (st, _, _) = fx.call(Method::POST, "/v1/sign-in", Some(&s), Value::Null).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_bound_box_refuses_another_users_sign_in() {
    let fx = fx().await;
    assert_eq!(fx.sign_in(fx.alice()).await.error, None);
    let s = fx.session().await;
    assert_eq!(fx.read(&s, "spo/in-scope/a.txt", "read").await.0, StatusCode::OK);

    let refused = fx.sign_in(fx.bob()).await;
    assert!(refused.error.as_deref().unwrap().contains("alice@contoso.example"), "{refused:?}");
    assert_eq!(fx.read(&s, "spo/in-scope/a.txt", "fetch").await.0, StatusCode::OK, "Alice's binding stands");

    // Every record on the bound box names Alice, Bob's refusal included.
    for r in fx.sink.records() {
        assert_eq!(r.user.name, "alice@contoso.example", "{:?}", r.op);
    }
}

#[tokio::test]
async fn id_tokens_the_core_must_not_believe() {
    let fx = fx().await;
    let stranger = EncodingKey::from_rsa_pem(rsa().serialize_pem().as_bytes()).unwrap();
    let base = claims(ALICE, "alice@contoso.example");
    let with = |k: &str, v: Value| {
        let mut c = base.clone();
        c[k] = v;
        c
    };
    let entra = |c: &Value| sign(c, "entra-1", &fx.stand_in.entra_key);
    let cases: Vec<(&str, HostSignIn, &str)> = vec![
        ("another app's audience", fx.stand_in.code(&with("aud", json!("00000000-0000-0000-0000-000000000000"))), "audience"),
        ("a v1 issuer", fx.stand_in.code(&with("iss", json!(format!("https://sts.windows.net/{TENANT}/")))), "issuer"),
        ("another tenant's issuer", fx.stand_in.code(&with("iss", json!("https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/v2.0"))), "issuer"),
        ("wrong tenant claim", fx.stand_in.code(&with("tid", json!("00000000-0000-0000-0000-000000000000"))), "tenant"),
        ("another sign-in's nonce", fx.stand_in.code(&with("nonce", json!("someone else's"))), "nonce"),
        ("no oid", fx.stand_in.code(&with("oid", Value::Null)), "oid"),
        ("signed by a stranger under Entra's kid", fx.stand_in.code_signed(&base, |c| sign(c, "entra-1", &stranger)), "signature"),
        ("a kid Entra does not publish", fx.stand_in.code_signed(&base, |c| sign(c, "made-up", &stranger)), "made-up"),
        ("expired", fx.stand_in.code_signed(&with("exp", json!(now() - 3600)), entra), "expired"),
    ];
    for (why, code, said) in cases {
        let r = fx.sign_in(code).await;
        let e = r.error.unwrap_or_else(|| panic!("{why}: accepted"));
        assert!(e.to_lowercase().contains(said), "{why}: {e}");
    }
    // A code used twice, or a verifier that is not its own.
    let mut wrong = fx.alice();
    wrong.verifier = "not-the-verifier".into();
    assert!(fx.sign_in(wrong).await.error.is_some());
    let once = fx.alice();
    assert_eq!(fx.sign_in(once.clone()).await.error, None);
    fx.core.entra.as_ref().unwrap().unbind();
    assert!(fx.sign_in(once).await.error.is_some(), "a code redeemed twice");

    assert!(fx.faults().is_empty(), "{:?}", fx.faults());
    let refused = fx.sign_ins().iter().filter(|r| r.outcome == Outcome::Refused).count();
    assert_eq!(refused, 11, "every refusal is on the record");
}

#[tokio::test]
async fn a_listing_is_scoped_by_sluse_and_trimmed_by_sharepoint() {
    let fx = fx().await;
    fx.sign_in(fx.alice()).await;
    let s = fx.session().await;
    let list = |path: &'static str, audience: &'static str| {
        let (fx, s) = (&fx, s.clone());
        async move {
            let (st, _, b) = fx.call(Method::POST, "/v1/list", Some(&s), json!({ "path": path, "audience": audience })).await;
            (st, serde_json::from_slice::<Value>(&b).unwrap())
        }
    };
    let names = |v: &Value| -> Vec<String> {
        v["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap().to_owned()).collect()
    };

    // The agent sees the way to its scope and nothing beside it (D-008).
    let (st, root) = list("spo", "agent").await;
    assert_eq!(st, StatusCode::OK, "{root}");
    assert_eq!(names(&root), ["in-scope"]);

    // Case-insensitive, as SharePoint is, and `denied.txt` is simply absent.
    let (_, inside) = list("spo/IN-SCOPE", "agent").await;
    assert_eq!(names(&inside), ["a.txt", "b.txt", "big.bin", "deeper"]);

    // The greyed listing is not served outside LOCAL, because the box cannot
    // be told apart from a person (D-033 point 1); nor is the host's audit
    // tail (point 3).
    let (st, user) = list("spo", "user").await;
    assert_eq!(user["code"], "AUDIENCE_NOT_SERVED", "{st} {user}");
    let (_, _, tail) = fx.call(Method::GET, "/v1/audit/tail?limit=5", Some(&s), Value::Null).await;
    assert!(String::from_utf8_lossy(&tail).contains("AUDIENCE_NOT_SERVED"), "{}", String::from_utf8_lossy(&tail));

    // The agent cannot list outside, and the refusal is Sluse's, before Graph:
    // told as a path that is not there, recorded as what it was (D-033 point 2).
    let before = fx.stand_in.mock.graph_calls.load(Ordering::SeqCst);
    let (st, body) = list("spo/out", "agent").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
    assert_eq!(body["code"], "NOT_FOUND");
    assert_eq!(fx.stand_in.mock.graph_calls.load(Ordering::SeqCst), before, "Graph was asked about out-of-scope");
    let records = fx.sink.records();
    let recorded = records.iter().filter_map(|r| r.reason.clone()).collect::<Vec<_>>();
    assert!(recorded.contains(&"OUT_OF_SCOPE".to_owned()), "{recorded:?}");
    // Refusals, not errors, and the tail under its own op (D-045 point 2).
    let audience: Vec<_> = records.iter().filter(|r| r.reason.as_deref() == Some("AUDIENCE_NOT_SERVED")).collect();
    assert!(audience.iter().all(|r| r.outcome == sluse_proto::Outcome::Refused), "{audience:?}");
    assert!(audience.iter().any(|r| r.op == sluse_proto::Op::Tail), "{audience:?}");
    // Both refused requests above are on the host's record too.
    assert_eq!(recorded.iter().filter(|r| *r == "AUDIENCE_NOT_SERVED").count(), 2, "{recorded:?}");
}

#[tokio::test]
async fn graph_answers_are_recorded_as_the_source_said_them() {
    let fx = fx().await;
    fx.sign_in(fx.alice()).await;
    let s = fx.session().await;

    let (st, _, b) = fx.read(&s, "spo/in-scope/denied.txt", "read").await;
    assert_eq!((st, b["code"].as_str()), (StatusCode::FORBIDDEN, Some("ACCESS_DENIED")));
    let (st, _, b) = fx.read(&s, "spo/in-scope/missing.txt", "read").await;
    assert_eq!((st, b["code"].as_str()), (StatusCode::NOT_FOUND, Some("NOT_FOUND")));
    let (st, _, b) = fx.read(&s, "spo/in-scope/throttled.txt", "read").await;
    assert_eq!((st, b["code"].as_str()), (StatusCode::BAD_GATEWAY, Some("SOURCE_UNAVAILABLE")));
    let (st, _, b) = fx.read(&s, "spo/in-scope/deeper", "read").await;
    assert_eq!((st, b["code"].as_str()), (StatusCode::CONFLICT, Some("NOT_A_FILE")));

    let recs = fx.sink.records();
    let denied = recs.iter().find(|r| r.path_requested.ends_with("denied.txt")).unwrap();
    assert!(denied.detail.as_deref().unwrap().contains("accessDenied"), "{:?}", denied.detail);
    let throttled = recs.iter().find(|r| r.path_requested.ends_with("throttled.txt")).unwrap();
    // Recorded, not retried, and the record says how long SharePoint asked for.
    assert!(throttled.detail.as_deref().unwrap().contains("retry after 7"), "{:?}", throttled.detail);
}

#[tokio::test]
async fn the_read_cap_applies_from_graphs_size_and_fetch_is_uncapped_by_default() {
    let fx = fx().await;
    fx.sign_in(fx.alice()).await;
    let s = fx.session().await;
    let (st, _, b) = fx.read(&s, "spo/in-scope/big.bin", "read").await;
    assert_eq!((st, b["code"].as_str()), (StatusCode::PAYLOAD_TOO_LARGE, Some("TOO_LARGE")));
    let (st, h, _) = fx.read(&s, "spo/in-scope/big.bin", "fetch").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(h.get(header::SIZE).unwrap(), "300000");
}

/// A download address is fetched over https, as Graph is; only a stand-in
/// Graph over plain http serves plain downloads.
#[test]
fn a_download_is_https_when_graph_is() {
    let cfg = serde_json::from_value(entra_mock::entra_block()).unwrap();
    let real = Entra::new(&cfg, "https://login.example", "https://graph.example/v1.0").unwrap();
    assert!(real.may_download("https://tenant.sharepoint.com/_layouts/15/download.aspx?tempauth=x"));
    assert!(!real.may_download("http://tenant.sharepoint.com/x"));
    let stand_in = Entra::new(&cfg, "http://127.0.0.1:1", "http://127.0.0.1:1/v1.0").unwrap();
    assert!(stand_in.may_download("http://127.0.0.1:1/download/a"));
}

/// Graph's listed size is promised, not measured: a labelled Office file
/// comes down larger (L1, 2026-10-01). What arrives is what is checked and
/// recorded.
#[tokio::test]
async fn a_download_larger_than_listed_is_delivered_and_recorded_as_it_arrived() {
    let fx = fx().await;
    fx.sign_in(fx.alice()).await;
    let s = fx.session().await;
    let body: &[u8] = b"alpha, with the document's properties written in";
    let (st, h, b) =
        fx.call(Method::POST, "/v1/read", Some(&s), json!({ "path": "spo/in-scope/grown.docx", "verb": "read" })).await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(&b[..], body);
    assert_eq!(h.get(header::SIZE).unwrap(), &body.len().to_string());
    let rec = fx.sink.records().into_iter().find(|r| r.op == Op::Read).unwrap();
    assert_eq!(rec.bytes, Some(body.len() as u64));
}

#[tokio::test]
async fn stat_hashes_what_it_downloads_and_takes_the_quick_path_on_a_matching_pin() {
    let fx = fx().await;
    fx.sign_in(fx.alice()).await;
    let s = fx.session().await;
    let stat = |pinned: Value| {
        let (fx, s) = (&fx, s.clone());
        async move {
            let mut body = json!({ "path": "spo/in-scope/b.txt" });
            if !pinned.is_null() {
                body["pinned"] = pinned;
            }
            let (st, _, b) = fx.call(Method::POST, "/v1/stat", Some(&s), body).await;
            (st, serde_json::from_slice::<Value>(&b).unwrap())
        }
    };
    let (st, full) = stat(Value::Null).await;
    assert_eq!(st, StatusCode::OK, "{full}");
    assert_eq!(full["hash"], ContentHash::of(b"bravo!").as_str());

    let pin = json!({ "hash": ContentHash::of(b"something else").as_str(), "size": 6, "modified": "2026-09-20T10:00:00Z" });
    let (_, quick) = stat(pin.clone()).await;
    assert_eq!(quick["matchesPinned"], true);
    assert_eq!(quick["hash"], pin["hash"], "the quick path returns the pin, it does not re-read");
}

/// "Leave it running" (D-034 point 5): renewal as Gate Core, with no user
/// and, since D-036, with no credential either.
#[tokio::test]
async fn an_expiring_graph_token_is_renewed_without_the_user() {
    let fx = fx().await;
    // Every Graph token is already inside the renewal margin when issued.
    fx.stand_in.mock.expires_in.store(1, Ordering::SeqCst);
    fx.sign_in(fx.alice()).await;
    let s = fx.session().await;
    assert_eq!(fx.read(&s, "spo/in-scope/a.txt", "read").await.0, StatusCode::OK);
    assert_eq!(fx.read(&s, "spo/in-scope/a.txt", "read").await.0, StatusCode::OK);
    assert!(fx.stand_in.mock.renewals.load(Ordering::SeqCst) >= 2, "the refresh token was never used");
    assert_eq!(fx.redemptions(), 1);
    assert!(fx.faults().is_empty(), "no assertion, no secret: {:?}", fx.faults());
}

/// D-071 slice 2: another resource's token from the same sign-in, as the
/// same person, held beside Graph's and not mistaken for it; the rotated
/// refresh token is the one used next.
#[tokio::test]
async fn another_resource_gets_its_own_token_from_the_same_refresh_token() {
    let fx = fx().await;
    fx.sign_in(fx.alice()).await;
    let entra = fx.core.entra.clone().unwrap();
    let mcp = "api://crm-mcp/Mcp.Read";

    let first = entra.acting_for_scope("crm", mcp).await.unwrap();
    assert!(first.access.starts_with("for-api://crm-mcp/Mcp.Read-"), "{}", first.access);
    assert_eq!(first.bound.identity.oid, entra.binding().unwrap().identity.oid, "as the same person");
    // Held: a second ask does not go to Entra.
    let again = entra.acting_for_scope("crm", mcp).await.unwrap();
    assert_eq!(again.access, first.access);
    assert_eq!(fx.stand_in.mock.renewals.load(Ordering::SeqCst), 1);
    assert_eq!(*fx.stand_in.mock.renewal_scopes.lock().unwrap(), vec![format!("{mcp} offline_access")]);

    // Graph's is still the sign-in's, and SharePoint reads with it.
    let graph = entra.acting_for("spo").await.unwrap();
    assert!(graph.access.starts_with("graph-"), "{}", graph.access);
    let s = fx.session().await;
    assert_eq!(fx.read(&s, "spo/in-scope/a.txt", "read").await.0, StatusCode::OK);

    // Graph's renewal uses the refresh token the last renewal rotated in.
    fx.stand_in.mock.expires_in.store(1, Ordering::SeqCst);
    entra.acting_for_scope("other", "api://other/.default").await.unwrap();
    fx.stand_in.mock.expires_in.store(3600, Ordering::SeqCst);
    let before = fx.stand_in.mock.renewals.load(Ordering::SeqCst);
    let other = entra.acting_for_scope("other", "api://other/.default").await.unwrap();
    assert!(other.access.starts_with("for-api://other/.default-"));
    assert_eq!(fx.stand_in.mock.renewals.load(Ordering::SeqCst), before + 1, "a stale token is renewed");
    let sent = fx.stand_in.mock.renewal_refresh.lock().unwrap().clone();
    let rotated = |i: usize| format!("{}-r{}", sent[i], i + 1);
    for i in 1..sent.len() {
        assert_eq!(sent[i], rotated(i - 1), "each renewal sends the refresh token the one before rotated in: {sent:?}");
    }
    assert!(fx.faults().is_empty(), "{:?}", fx.faults());
}

/// D-022: the console's process and the MCP process are two core sessions,
/// and one sign-in on the host acts for both.
#[tokio::test]
async fn one_sign_in_acts_for_every_session_of_the_box() {
    let fx = fx().await;
    let console = fx.session().await;
    let mcp = fx.session().await;
    assert_ne!(console, mcp);
    fx.sign_in(fx.alice()).await;

    for s in [&console, &mcp] {
        let (status, _, body) = fx.read(s, "spo/in-scope/a.txt", "read").await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    let recs = fx.sink.records();
    assert!(recs.iter().any(|r| r.session_id.as_str() == mcp));
    for r in recs {
        assert_eq!(r.user.name, "alice@contoso.example", "{:?} on {}", r.op, r.session_id);
    }
}

/// D-022: unbinding is the user's, from the console. After it the box acts for
/// nobody, and the next sign-in may be someone else's.
#[tokio::test]
async fn sign_out_unbinds_the_box_and_says_who_it_was() {
    let fx = fx().await;
    let s = fx.session().await;
    let sign_out = || async {
        let (st, _, b) = fx.call(Method::POST, "/v1/sign-out", Some(&s), Value::Null).await;
        (st, serde_json::from_slice::<Value>(&b).unwrap())
    };
    fx.sign_in(fx.alice()).await;
    assert_eq!(fx.read(&s, "spo/in-scope/a.txt", "read").await.0, StatusCode::OK);

    let (st, out) = sign_out().await;
    assert_eq!(st, StatusCode::OK, "{out}");
    assert_eq!(out["user"]["name"], "alice@contoso.example");
    // The record goes before the binding, so it names who signed out.
    let rec = fx.sink.records().into_iter().find(|r| r.op == Op::Signout).expect("a sign-out record");
    assert_eq!((rec.user.kind, rec.user.name.as_str()), (UserKind::Entra, "alice@contoso.example"));
    assert_eq!(rec.outcome, Outcome::Admitted);

    // Nobody is bound now: no read, and the refusal names nobody.
    let (st, _, body) = fx.read(&s, "spo/in-scope/a.txt", "read").await;
    assert_eq!((st, body["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("SIGN_IN_REQUIRED")));
    assert_eq!(fx.sink.records().last().unwrap().user.kind, UserKind::OsProcess);

    // Signing out again is not an error, and says nobody was signed in.
    let (st, again) = sign_out().await;
    assert_eq!((st, &again["user"]), (StatusCode::OK, &Value::Null));

    // The box is free for the next person.
    assert_eq!(fx.sign_in(fx.bob()).await.error, None);
    assert_eq!(fx.read(&s, "spo/in-scope/a.txt", "read").await.0, StatusCode::OK);
    assert_eq!(fx.sink.records().last().unwrap().user.name, "bob@contoso.example");
}

/// The host's sign-in is recorded, and `/v1/status` gives the service its
/// answer by number. The guest's view no longer says where to sign in.
#[tokio::test]
async fn the_host_sign_in_is_recorded_and_answered_in_status() {
    let fx = fx().await;
    let console = fx.session().await;
    let code = fx.alice();
    let seq = code.seq;
    assert_eq!(fx.sign_in(code).await, HostSignInResult { seq, error: None });

    let ins = fx.sign_ins();
    assert_eq!(ins.len(), 1, "{ins:?}");
    assert_eq!((ins[0].outcome, ins[0].user.name.as_str()), (Outcome::Admitted, "alice@contoso.example"));
    assert!(ins[0].reason.as_deref().unwrap().contains("on the host"), "{:?}", ins[0].reason);
    assert_eq!(ins[0].session_id.as_str(), control::HOST_SESSION);

    let (_, _, b) = fx.call(Method::GET, "/v1/status", None, Value::Null).await;
    let status: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(status["signedIn"]["name"], "alice@contoso.example");
    assert_eq!(status["hostSignIn"]["seq"], seq);
    assert!(status["hostSignIn"].get("error").is_none(), "{status}");

    let (_, _, b) = fx.call(Method::GET, "/v1/config-view", Some(&console), Value::Null).await;
    let view: Value = serde_json::from_slice(&b).unwrap();
    assert!(view.get("signIn").is_none(), "{view}");

    // Again, the same person: recorded as again, still one binding.
    fx.sign_in(fx.alice()).await;
    assert!(fx.sign_ins()[1].reason.as_deref().unwrap().contains("again"), "{:?}", fx.sign_ins());
    assert!(fx.faults().is_empty(), "{:?}", fx.faults());

    // The status counts each source's window (Q36), and says a sign-out in
    // the box until the next sign-in (Q7).
    assert_eq!(status["volume"][0]["files"], 0, "{status}");
    assert!(status.get("signedOut").is_none(), "{status}");
    fx.call(Method::POST, "/v1/sign-out", Some(&console), Value::Null).await;
    let (_, _, b) = fx.call(Method::GET, "/v1/status", None, Value::Null).await;
    let status: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(status["signedOut"], true, "{status}");
    fx.sign_in(fx.alice()).await;
    let (_, _, b) = fx.call(Method::GET, "/v1/status", None, Value::Null).await;
    let status: Value = serde_json::from_slice(&b).unwrap();
    assert!(status.get("signedOut").is_none(), "{status}");
    let _ = CLIENT;
}

/// The control channel itself: one line per sign-in, and a line that is not
/// one is skipped, not fatal.
#[tokio::test]
async fn the_control_channel_reads_sign_ins_line_by_line() {
    let fx = fx().await;
    let line = serde_json::to_string(&fx.alice()).unwrap();
    let input = format!("not json\n{line}\n");
    control::run(fx.core.clone(), input.as_bytes()).await;
    assert_eq!(fx.core.entra.as_ref().unwrap().user().unwrap().name, "alice@contoso.example");
}

/// D-022: a refresh token that dies mid-run answers `SIGN_IN_REQUIRED`, and the
/// same person signing in again on the host brings the box back.
#[tokio::test]
async fn signing_in_again_revives_a_box_whose_refresh_token_died() {
    let fx = fx().await;
    let mcp = fx.session().await;
    // The stand-in revokes this user's refresh token, and every Graph token is
    // stale on arrival, so the first read after sign-in has to renew.
    let carol = || fx.stand_in.code(&claims("revoked", "carol@contoso.example"));
    fx.stand_in.mock.expires_in.store(1, Ordering::SeqCst);
    assert_eq!(fx.sign_in(carol()).await.error, None);

    let (st, _, body) = fx.read(&mcp, "spo/in-scope/a.txt", "read").await;
    assert_eq!((st, body["code"].as_str()), (StatusCode::UNAUTHORIZED, Some("SIGN_IN_REQUIRED")));

    fx.stand_in.mock.expires_in.store(3600, Ordering::SeqCst);
    assert_eq!(fx.sign_in(carol()).await.error, None);
    let (st, _, body) = fx.read(&mcp, "spo/in-scope/a.txt", "read").await;
    assert_eq!(st, StatusCode::OK, "{body}");
}

/// D-038 point 6: each scope root is looked up as the user at sign-in, and
/// one that is not there for them is a `scope` record, raised, once per
/// sign-in. One that is there writes nothing.
#[tokio::test]
async fn a_missing_scope_root_is_recorded_at_sign_in() {
    let fx = fx_with(json!(["In-Scope", "Gone-Folder"])).await;
    assert_eq!(fx.sign_in(fx.alice()).await.error, None, "a missing root does not stop the sign-in");
    let raised: Vec<_> = fx.sink.records().into_iter().filter(|r| r.op == Op::Scope).collect();
    assert_eq!(raised.len(), 1, "{raised:?}");
    assert_eq!(raised[0].outcome, Outcome::Raised);
    assert_eq!(raised[0].path_requested, "spo/Gone-Folder");
    assert_eq!(raised[0].user.name, "alice@contoso.example");
    let said = raised[0].detail.as_deref().unwrap();
    assert!(said.contains("may also mean this user cannot open it"), "{said}");
    assert_eq!(sluse_gate_core::audit::event_id(Op::Scope, Outcome::Raised), 1303);
}

/// A restarted endpoint asks whether its session is still held, and a
/// session that aged out is an answer, not a refusal in the Sluse log
/// (L1, 2026-10-07: three 701s at every reopen).
#[tokio::test]
async fn status_says_whether_a_session_is_held_without_a_record() {
    let fx = fx().await;
    let s = fx.session().await;
    let held = |b: Vec<u8>| serde_json::from_slice::<Value>(&b).unwrap()["sessionHeld"].clone();
    let (_, _, b) = fx.call(Method::GET, "/v1/status", Some(&s), Value::Null).await;
    assert_eq!(held(b), json!(true));
    let (_, _, b) = fx.call(Method::GET, "/v1/status", Some("sess-20260101-00000000"), Value::Null).await;
    assert_eq!(held(b), json!(false));
    let (_, _, b) = fx.call(Method::GET, "/v1/status", None, Value::Null).await;
    assert_eq!(held(b), Value::Null);
    assert!(fx.sink.records().is_empty(), "{:?}", fx.sink.records());
}

// ---------------------------------------------------------------------------
// The user's OneDrive `Sluse` folder (D-054)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn onedrive_reads_the_sluse_folder_and_refuses_a_shortcut_in_it() {
    let fx = fx_sources(json!([entra_mock::onedrive_source()])).await;
    assert_eq!(fx.sign_in(fx.alice()).await.error, None);
    // The sign-in's scope check found the folder (D-038 point 6).
    assert!(!fx.sink.records().iter().any(|r| r.reason.as_deref() == Some("SCOPE_MISSING")));
    let s = fx.session().await;

    // The path is the folder's; Graph's `Sluse/` is not the agent's to name,
    // and its spelling check does not trip on it.
    let (status, _, body) =
        fx.call(Method::POST, "/v1/read", Some(&s), json!({ "path": "od/note.txt", "verb": "read" })).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(&body[..], b"alpha");
    let recs = fx.sink.records();
    let rec = recs.iter().find(|r| r.op == Op::Read && r.outcome == Outcome::Admitted).unwrap();
    assert_eq!(rec.path_resolved.as_deref(), Some("OneDrive/Sluse/note.txt"));
    assert_eq!(rec.user.name, "alice@contoso.example");

    // The shortcut: absent from the agent's listing, refused by name.
    let (status, _, body) =
        fx.call(Method::POST, "/v1/list", Some(&s), json!({ "path": "od", "audience": "agent" })).await;
    assert_eq!(status, StatusCode::OK);
    let listed: Value = serde_json::from_slice(&body).unwrap();
    let names: Vec<&str> = listed["entries"].as_array().unwrap().iter().map(|e| e["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["note.txt"], "{listed}");
    let (status, _, _) = fx.read(&s, "od/Tender.docx", "fetch").await;
    assert_ne!(status, StatusCode::OK);
    let refused = fx.sink.records().into_iter().find(|r| r.path_requested == "od/Tender.docx").unwrap();
    assert_eq!(refused.reason.as_deref(), Some("OUT_OF_SCOPE"));
}

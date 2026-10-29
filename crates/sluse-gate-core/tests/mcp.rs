// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! `mcp` sources (D-071 slice 4), Gate Core's half: an MCP server over HTTP,
//! rmcp's own, in this process, which takes only the person's token for its
//! scope; Entra is the local stand-in. Both pinned versions, each with its
//! own handshake and no probe.
//!
//! **What this proves and what it does not.** That Core lists only the tools
//! the config allows, without the arguments it pins; calls only those, as the
//! person, with the pins set over the box's; records each call as a fetch is
//! recorded; and refuses or names what it cannot do. Nothing about a real
//! server or Entra's answer to a real scope: that is the test run against
//! the demo tenant (`prototype/next-run.md`).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::Router;
use serde_json::{json, Value};
use sluse_gate_core::app::Core;
use sluse_gate_core::audit::MemorySink;
use sluse_gate_core::entra::Entra;
use sluse_gate_core::{control, http, preflight, scope};
use sluse_proto::wire::header;
use sluse_proto::{Capability, ContentHash, Loaded, Op, Outcome, SourceKind, ToolsResponse};
use tower::ServiceExt;

#[path = "support/entra_mock.rs"]
mod entra_mock;

#[path = "support/crm.rs"]
mod crm;
use crm::{crm, Calls, SCOPE};

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fx {
    _dir: tempfile::TempDir,
    router: Router,
    core: Arc<Core>,
    sink: Arc<MemorySink>,
    stand_in: entra_mock::Running,
    calls: Calls,
    tokens: Arc<Mutex<Vec<String>>>,
    clipboard: Arc<Mutex<Vec<Value>>>,
}

async fn fx(protocol: &str) -> Fx {
    fx_scoped(protocol, SCOPE).await
}

/// With the scope Core asks Entra for as given.
async fn fx_scoped(protocol: &str, entra_scope: &str) -> Fx {
    let stand_in = entra_mock::start().await;
    let (url, calls, tokens) = crm().await;
    let dir = tempfile::tempdir().unwrap();
    let config = json!({
        "schemaVersion": 3,
        "sources": [{
            "name": "crm",
            "kind": { "type": "mcp", "address": {
                "url": "https://crm.example.com/mcp", "entraScope": entra_scope, "protocol": protocol,
                "pins": { "search_accounts": { "region": "EU" } }
            } },
            "scope": ["get_account", "search_accounts"],
            "sensitivity": 3
        }],
        "volume": { "admissions": 25, "windowSeconds": 60 },
        "entra": entra_mock::entra_block()
    });
    let device = json!({
        "boxId": "box-mcp-test", "environment": "demo",
        "gate": {
            "listen": "127.0.0.1:7580", "url": "https://127.0.0.1:7580",
            "certPath": "certs/core.pem", "keyPath": "certs/core.key", "clientCaPath": "certs/client-ca.pem",
            "certPin": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        },
        "endpoint": { "clientCertPath": "c.pem", "clientKeyPath": "c.key", "consoleListen": "127.0.0.1:7582" },
        "artifacts": "artifacts", "workspace": "workspace", "journalDir": "journal",
        "audit": { "sink": "jsonl", "path": "audit/core.jsonl" }
    });
    let path = dir.path().join("demo.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
    std::fs::write(sluse_proto::config::device_path(&path), serde_json::to_vec_pretty(&device).unwrap()).unwrap();
    let mut loaded: Loaded = sluse_proto::config::load(&path).unwrap();
    // The loader holds the address to https; the test server is plain HTTP
    // on loopback, so the address is set after it.
    if let SourceKind::Mcp { url: u, .. } = &mut loaded.config.sources[0].kind {
        *u = url;
    }
    let compiled = scope::compile(&loaded).unwrap();
    let posture = preflight::run(&loaded, preflight::CertCheck::Ok { pin: ContentHash::of(b"x") });
    let base = stand_in.base.clone();
    let entra = Entra::new(loaded.config.entra.as_ref().unwrap(), &base, &format!("{base}/v1.0")).unwrap();
    let sink = Arc::new(MemorySink::new());
    let clipboard = Arc::new(Mutex::new(Vec::new()));
    let clip = clipboard.clone();
    let core = Arc::new(
        Core::new(loaded, compiled, sink.clone(), posture)
            .with_entra(Some(entra))
            .with_clipboard(Box::new(move |v| clip.lock().unwrap().push(v.clone()))),
    );
    Fx { _dir: dir, router: http::router(core.clone()), core, sink, stand_in, calls, tokens, clipboard }
}

impl Fx {
    async fn send(&self, method: Method, route: &str, session: Option<&str>, body: Value) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut req = Request::builder().method(method).uri(route).header("content-type", "application/json");
        if let Some(s) = session {
            req = req.header(header::SESSION, s);
        }
        let body = if body.is_null() { Body::empty() } else { Body::from(serde_json::to_vec(&body).unwrap()) };
        let res = self.router.clone().oneshot(req.body(body).unwrap()).await.unwrap();
        let (status, headers) = (res.status(), res.headers().clone());
        (status, headers, axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec())
    }

    async fn session(&self) -> String {
        let (_, _, body) = self.send(Method::GET, "/v1/health", None, Value::Null).await;
        serde_json::from_slice::<Value>(&body).unwrap()["sessionId"].as_str().unwrap().to_owned()
    }

    async fn tools(&self, s: &str) -> ToolsResponse {
        let (status, _, body) = self.send(Method::GET, "/v1/tools", Some(s), Value::Null).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        serde_json::from_slice(&body).unwrap()
    }

    async fn call(&self, s: &str, tool: &str, arguments: Value) -> (StatusCode, HeaderMap, Vec<u8>) {
        self.send(Method::POST, "/v1/call", Some(s), json!({ "tool": tool, "arguments": arguments })).await
    }

    fn records(&self, op: Op) -> Vec<sluse_proto::AuditRecord> {
        self.sink.records().into_iter().filter(|r| r.op == op).collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

async fn lists_and_calls_as_the_person(protocol: &str) {
    let fx = fx(protocol).await;
    assert_eq!(control::sign_in(&fx.core, &fx.stand_in.alice()).await.error, None);
    let s = fx.session().await;

    // Only the allowed tools, named as a call names them; the pinned argument
    // neither offered nor required.
    let listed = fx.tools(&s).await;
    let names: Vec<&str> = listed.tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["crm/get_account", "crm/search_accounts"], "delete_account is not on the list");
    let search = &listed.tools[1];
    assert!(search.input_schema["properties"].get("region").is_none(), "{}", search.input_schema);
    assert_eq!(search.input_schema["required"], json!(["q"]));
    assert!(listed.unavailable.is_empty());

    // A call: the pin over the box's value, the result admitted like a fetch.
    let (status, headers, body) = fx.call(&s, "crm/search_accounts", json!({ "q": "Contoso", "region": "US" })).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let result: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(result["content"][0]["text"], r#"search_accounts with {"q":"Contoso","region":"EU"}"#);
    assert_eq!(fx.calls.lock().unwrap().last().unwrap().1, json!({ "q": "Contoso", "region": "EU" }), "the server saw the pin");
    let admission = headers.get(header::ADMISSION_ID).unwrap().to_str().unwrap().to_owned();
    assert_eq!(headers.get(header::SIZE).unwrap().to_str().unwrap(), body.len().to_string());

    let rec = fx.records(Op::Call).pop().unwrap();
    assert_eq!(rec.outcome, Outcome::Admitted);
    assert_eq!(rec.capability, Capability::Bytes);
    assert_eq!(rec.path_requested, "crm/search_accounts");
    assert!(rec.path_resolved.as_deref().unwrap().ends_with("/mcp#search_accounts"));
    assert_eq!(rec.scope.as_deref(), Some("crm/search_accounts"));
    assert_eq!(rec.hash, Some(ContentHash::of(&body)), "the hash of what the box received");
    assert_eq!(rec.admission_id.unwrap().as_str(), admission);
    assert_eq!(rec.user.kind, sluse_proto::UserKind::Entra, "as the person");

    // Every request to the server carried the person's token for its scope.
    let tokens = fx.tokens.lock().unwrap().clone();
    assert!(!tokens.is_empty() && tokens.iter().all(|t| t.starts_with(&format!("Bearer for-{SCOPE}-"))), "{tokens:?}");
    assert!(fx.stand_in.faults().is_empty(), "{:?}", fx.stand_in.faults());
}

#[tokio::test]
async fn the_legacy_handshake_lists_and_calls_as_the_person() {
    lists_and_calls_as_the_person("2025-11-25").await;
}

#[tokio::test]
async fn the_stateless_version_lists_and_calls_as_the_person() {
    lists_and_calls_as_the_person("2026-07-28").await;
}

/// D-076: clipboard text the window carried, from the service on the
/// control channel, is one record each with the box and the person, and is
/// neither a sign-in nor a sign-in window.
#[tokio::test]
async fn a_clipboard_transfer_on_the_control_channel_is_one_record() {
    let fx = fx("2025-11-25").await;
    let line = r#"{"direction":"out","bytes":5,"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824","head":"hello","by":"S-1-12-1-1"}"#;
    control::run(fx.core.clone(), format!("{line}\nnot json\n").as_bytes()).await;
    let recs = fx.clipboard.lock().unwrap().clone();
    assert_eq!(recs.len(), 1, "{recs:?}");
    let r = &recs[0];
    assert_eq!((r["op"].as_str(), r["direction"].as_str(), r["head"].as_str(), r["by"].as_str()), (Some("clipboard"), Some("out"), Some("hello"), Some("S-1-12-1-1")));
    assert_eq!(r["bytes"], 5);
    assert!(r["boxId"].is_string() && r["configVersion"].is_string(), "{r}");
    assert!(fx.core.window.until().is_none(), "no window opened");
    assert!(fx.sink.records().is_empty(), "no sign-in attempted");
}

/// The config's list decides, not the server's: a tool the server has and
/// the config does not allow is never called, and the box is told it does
/// not exist.
#[tokio::test]
async fn a_tool_not_allowed_is_refused_and_never_called() {
    let fx = fx("2025-11-25").await;
    control::sign_in(&fx.core, &fx.stand_in.alice()).await;
    let s = fx.session().await;
    let (status, _, body) = fx.call(&s, "crm/delete_account", json!({ "id": "1" })).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "blinded: {}", String::from_utf8_lossy(&body));
    assert!(fx.calls.lock().unwrap().is_empty(), "the server was never asked");
    let rec = fx.records(Op::Call).pop().unwrap();
    assert_eq!((rec.outcome, rec.reason.as_deref()), (Outcome::Refused, Some("OUT_OF_SCOPE")));
    assert!(fx.tokens.lock().unwrap().is_empty(), "no token was even sent");

    for bad in ["nosuch/get_account", "get_account"] {
        let (status, _, _) = fx.call(&s, bad, json!({})).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{bad}");
    }
}

/// Unbound, there is no one to call as; and a server that refuses the token
/// is a refusal with the server's word in the record, its tools named as
/// unavailable, not a fault that hides them.
#[tokio::test]
async fn no_sign_in_no_call_and_a_refused_token_is_recorded() {
    let fx = fx("2025-11-25").await;
    let s = fx.session().await;
    let (status, _, _) = fx.call(&s, "crm/get_account", json!({ "id": "1" })).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(fx.records(Op::Call).pop().unwrap().reason.as_deref(), Some("SIGN_IN_REQUIRED"));

    // A token Entra gives, for a scope this server does not take.
    let fx = fx_scoped("2025-11-25", "api://elsewhere/Other.Read").await;
    control::sign_in(&fx.core, &fx.stand_in.alice()).await;
    let s = fx.session().await;
    let listed = fx.tools(&s).await;
    assert!(listed.tools.is_empty());
    assert_eq!(listed.unavailable[0].source, "crm");
    assert_eq!(listed.unavailable[0].reason, "ACCESS_DENIED", "{:?}", fx.records(Op::Tools).pop().unwrap().detail);
    assert_eq!(fx.records(Op::Tools).pop().unwrap().reason.as_deref(), Some("ACCESS_DENIED"));
    let (status, _, _) = fx.call(&s, "crm/get_account", json!({ "id": "1" })).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(fx.calls.lock().unwrap().is_empty());
}

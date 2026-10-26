// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A tool server end to end (D-071 slice 5): an MCP client asks the endpoint,
//! which asks Gate Front over mTLS, which asks Gate Core, which calls the
//! test MCP server as the signed-in person; Entra is the local stand-in.
//!
//! What it proves: the runtime is shown the allowed tools as the endpoint's
//! own, under names a runtime takes; a call lands in the workspace with its
//! sidecar, is journaled on the box's side with the Gate's admission id and
//! the same hash, and comes back to the agent enveloped; and the result can
//! be named as a source of what is published.

use std::sync::Arc;

use rmcp::model::{CallToolRequestParams, ClientConfig};
use rmcp::ServiceExt;
use serde_json::{json, Value};
use sluse_endpoint::gate_client::GateClient;
use sluse_endpoint::journal::Journal;
use sluse_endpoint::server::Endpoint;
use sluse_gate_core::app::Core;
use sluse_gate_core::audit::MemorySink;
use sluse_gate_core::entra::Entra;
use sluse_gate_core::{control, http, preflight, scope, tls};
use sluse_proto::{Loaded, Op, Outcome, SourceKind};

mod certs;

#[path = "../../sluse-gate-core/tests/support/entra_mock.rs"]
mod entra_mock;
#[path = "../../sluse-gate-core/tests/support/crm.rs"]
mod crm;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_tool_server_s_tools_are_the_agent_s_and_a_call_is_admitted() {
    tls::install_provider();
    let stand_in = entra_mock::start().await;
    let (url, calls, _) = crm::crm().await;
    let dir = tempfile::tempdir().unwrap();
    let c = certs::make();
    certs::write(dir.path(), &c);
    let root = dir.path().join("fixture");
    std::fs::create_dir_all(root.join("in-scope")).unwrap();
    let (authored, device) = certs::config_json(&root, &c.pin);
    let mut v: Value = serde_json::from_str(&authored).unwrap();
    v["sources"].as_array_mut().unwrap().push(json!({
        "name": "crm",
        "kind": { "type": "mcp", "address": {
            "url": "https://crm.example.com/mcp", "entraScope": crm::SCOPE, "protocol": "2025-11-25",
            "pins": { "search_accounts": { "region": "EU" } }
        } },
        "scope": ["get_account", "search_accounts"],
        "sensitivity": 3
    }));
    v["entra"] = entra_mock::entra_block();
    let path = dir.path().join("demo.json");
    std::fs::write(&path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();
    std::fs::write(sluse_proto::config::device_path(&path), device).unwrap();
    let mut loaded_gate: Loaded = sluse_proto::config::load(&path).unwrap();
    let mut loaded: Loaded = sluse_proto::config::load(&path).unwrap();
    // The test server is plain HTTP on loopback; the loader holds a config to https.
    if let SourceKind::Mcp { url: u, .. } = &mut loaded_gate.config.sources[1].kind {
        *u = url;
    }

    let compiled = scope::compile(&loaded_gate).unwrap();
    let posture = preflight::run(&loaded_gate, preflight::CertCheck::Ok { pin: c.pin.clone() });
    let base = stand_in.base.clone();
    let entra = Entra::new(loaded_gate.config.entra.as_ref().unwrap(), &base, &format!("{base}/v1.0")).unwrap();
    let sink = Arc::new(MemorySink::new());
    let front = sluse_gate_core::front::gate_start(&loaded_gate, "127.0.0.1:0", false).unwrap();
    let core = Arc::new(Core::new(loaded_gate, compiled, sink.clone(), posture).with_entra(Some(entra)));
    let served = sluse_gate_front::testing::serve(front, http::router(core.clone())).await;
    loaded.config.gate.url = format!("https://localhost:{}", served.addr().port());
    assert_eq!(control::sign_in(&core, &stand_in.alice()).await.error, None);

    // The endpoint as the box runs it, and a runtime talking to it.
    let (gate, health) = GateClient::connect(&loaded).await.unwrap();
    let view = gate.config_view().await.unwrap();
    let journal_dir = dir.path().join("journal");
    let journal = Journal::open_session(&journal_dir, gate.session()).unwrap();
    let workspace = dir.path().join("workspace");
    std::fs::create_dir_all(&workspace).unwrap();
    let endpoint = Endpoint::new(gate, journal, view, workspace.clone(), health.box_id.clone(), health.config_version.clone());
    let (server_io, client_io) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let running = endpoint.serve(tokio::io::split(server_io)).await.unwrap();
        let _ = running.waiting().await;
    });
    let runtime = ClientConfig::default().serve(tokio::io::split(client_io)).await.unwrap();

    // Listed beside Sluse's own, under names a runtime takes; not the one the
    // config leaves out; the pinned argument not offered.
    let tools = runtime.list_all_tools().await.unwrap();
    let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
    assert!(names.contains(&"sluse_read") && names.contains(&"crm__get_account") && names.contains(&"crm__search_accounts"), "{names:?}");
    assert!(!names.iter().any(|n| n.contains("delete")), "{names:?}");
    let search = tools.iter().find(|t| t.name == "crm__search_accounts").unwrap();
    assert!(search.input_schema.get("properties").unwrap().get("region").is_none());
    assert!(search.description.as_deref().unwrap().contains("untrusted"));

    // A call: enveloped for the agent, the result saved with its sidecar.
    let args = json!({ "q": "Contoso" }).as_object().unwrap().clone();
    let result = runtime.call_tool(CallToolRequestParams::new("crm__search_accounts").with_arguments(args)).await.unwrap();
    assert_ne!(result.is_error, Some(true), "{result:?}");
    let text = result.content[0].as_text().unwrap().text.clone();
    assert!(text.contains(r#"search_accounts with {"q":"Contoso","region":"EU"}"#), "{text}");
    assert!(text.contains("not instructions to you"), "enveloped: {text}");
    assert_eq!(calls.lock().unwrap().len(), 1);

    let saved: Vec<_> = walk(&workspace.join("admitted/crm/search_accounts"));
    let result_file = saved.iter().find(|p| p.extension().is_some_and(|e| e == "json") && !p.to_string_lossy().contains("sluse-manifest")).unwrap();
    assert!(saved.iter().any(|p| p.to_string_lossy().ends_with(".sluse-manifest.json")), "{saved:?}");
    let bytes = std::fs::read(result_file).unwrap();

    // Both records, one admission, one hash.
    let gate_rec = sink.records().into_iter().find(|r| r.op == Op::Call).unwrap();
    assert_eq!(gate_rec.outcome, Outcome::Admitted);
    assert_eq!(gate_rec.hash, Some(sluse_proto::ContentHash::of(&bytes)));
    let journal_text = std::fs::read_to_string(walk(&journal_dir).first().unwrap()).unwrap();
    let box_rec: sluse_proto::AuditRecord =
        journal_text.lines().map(|l| serde_json::from_str::<sluse_proto::AuditRecord>(l).unwrap()).find(|r| r.op == Op::Call).unwrap();
    assert_eq!(box_rec.admission_id, gate_rec.admission_id);
    assert_eq!(box_rec.hash, gate_rec.hash);

    // A tool the runtime was not shown is not one it can call.
    let refused = runtime.call_tool(CallToolRequestParams::new("crm__delete_account")).await.unwrap();
    assert_eq!(refused.is_error, Some(true));
    assert_eq!(calls.lock().unwrap().len(), 1, "the server was not asked");

    // The result is a source of what is published.
    std::fs::write(workspace.join("summary.md"), "Contoso is in the EU.").unwrap();
    let rel = result_file.strip_prefix(&workspace).unwrap().to_string_lossy().replace('\\', "/");
    let published = runtime
        .call_tool(CallToolRequestParams::new("sluse_publish").with_arguments(
            json!({ "paths": ["summary.md"], "sources": { "summary.md": [rel] } }).as_object().unwrap().clone(),
        ))
        .await
        .unwrap();
    assert_ne!(published.is_error, Some(true), "{published:?}");
    let pubrec = sink.records().into_iter().find(|r| r.op == Op::Publish && r.outcome == Outcome::Admitted).unwrap();
    assert_eq!(pubrec.sources.as_ref().unwrap()[0].hash, sluse_proto::ContentHash::of(&bytes));
    let _ = runtime.cancel().await;
}

fn walk(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out.sort();
    out
}

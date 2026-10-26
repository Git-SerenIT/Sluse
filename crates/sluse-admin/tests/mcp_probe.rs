// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Sluse Admin's probe of an MCP server (D-071 slice 6), against the test
//! server Gate Core's tests use: the version it settles on is the one a box
//! then calls with, and the tools are listed with the server's own hint.

use sluse_proto::McpProtocol;

#[path = "../../sluse-gate-core/tests/support/crm.rs"]
mod crm;

fn token() -> String {
    format!("for-{}-1", crm::SCOPE)
}

#[tokio::test]
async fn a_server_that_speaks_both_is_pinned_to_the_newer() {
    let (url, _, tokens) = crm::crm_with(false).await;
    let p = sluse_admin::mcp::probe(&reqwest::Client::new(), &url, &token()).await.unwrap();
    assert_eq!(p.protocol, McpProtocol::V2026_07_28);
    let names: Vec<&str> = p.tools.iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["get_account", "search_accounts", "delete_account"], "every tool, for the admin to pick from");
    assert!(p.tools[1].input_schema["properties"].get("region").is_some());
    assert!(tokens.lock().unwrap().iter().all(|t| t == &format!("Bearer {}", token())));
}

#[tokio::test]
async fn a_server_on_the_older_version_is_pinned_to_it() {
    let (url, _, _) = crm::crm_with(true).await;
    let p = sluse_admin::mcp::probe(&reqwest::Client::new(), &url, &token()).await.unwrap();
    assert_eq!(p.protocol, McpProtocol::V2025_11_25);
    assert_eq!(p.tools.len(), 3);
}

#[tokio::test]
async fn a_token_the_server_refuses_is_said() {
    let (url, _, _) = crm::crm_with(false).await;
    let e = sluse_admin::mcp::probe(&reqwest::Client::new(), &url, "for-api://other/X-1").await.unwrap_err();
    assert!(e.contains("401"), "{e}");
}

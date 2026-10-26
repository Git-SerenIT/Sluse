// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! An MCP server over HTTP for the `mcp` source's tests (D-071): rmcp's own,
//! a CRM's three tools, `delete_account` among them, which no test config
//! allows. It takes only a token the Entra stand-in issued for [`SCOPE`].
//! Included by path by Gate Core's tests and the endpoint's.

#![allow(dead_code)]

use std::future::Future;
use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use axum::Router;
use rmcp::model::{
    CallToolRequestParams, CallToolResult, ContentBlock, ErrorData, ListToolsResult, PaginatedRequestParams, ServerCapabilities,
    ServerConfig, Tool,
};
use rmcp::service::{MaybeSendFuture, RequestContext, RoleServer};
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use rmcp::ServerHandler;
use serde_json::{json, Value};

pub const SCOPE: &str = "api://crm-mcp/Mcp.Read";

/// What the server was asked: each call's tool and arguments.
pub type Calls = Arc<Mutex<Vec<(String, Value)>>>;

#[derive(Clone)]
struct Crm {
    calls: Calls,
    /// Speaks only 2025-11-25's handshake, as most deployed servers do.
    legacy: bool,
}

fn schema(props: Value, required: &[&str]) -> Arc<serde_json::Map<String, Value>> {
    Arc::new(json!({ "type": "object", "properties": props, "required": required }).as_object().unwrap().clone())
}

impl ServerHandler for Crm {
    fn supported_protocol_versions(&self) -> std::borrow::Cow<'static, [rmcp::model::ProtocolVersion]> {
        use rmcp::model::ProtocolVersion;
        if self.legacy {
            std::borrow::Cow::Borrowed(&[ProtocolVersion::V_2025_11_25])
        } else {
            std::borrow::Cow::Borrowed(ProtocolVersion::known_up_to(&ProtocolVersion::LATEST))
        }
    }

    fn get_info(&self) -> ServerConfig {
        let mut info = ServerConfig::default();
        info.capabilities = ServerCapabilities::builder().enable_tools().build();
        info
    }

    fn list_tools(
        &self,
        _: Option<PaginatedRequestParams>,
        _: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + MaybeSendFuture + '_ {
        std::future::ready(Ok(ListToolsResult::with_all_items(vec![
            Tool::new("get_account", "One account by id.", schema(json!({ "id": { "type": "string" } }), &["id"])),
            Tool::new(
                "search_accounts",
                "Accounts by name, in a region.",
                schema(json!({ "q": { "type": "string" }, "region": { "type": "string" } }), &["q", "region"]),
            ),
            Tool::new("delete_account", "Deletes an account.", schema(json!({ "id": { "type": "string" } }), &["id"])),
        ])))
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<rmcp::model::CallToolResponse, ErrorData>> + MaybeSendFuture + '_ {
        let args = Value::Object(request.arguments.clone().unwrap_or_default());
        self.calls.lock().unwrap().push((request.name.to_string(), args.clone()));
        let text = format!("{} with {args}", request.name);
        std::future::ready(Ok(CallToolResult::success(vec![ContentBlock::text(text)]).into()))
    }
}

/// The server at `http://127.0.0.1:<port>/mcp`, refusing any request whose
/// token is not one the stand-in issued for [`SCOPE`].
pub async fn crm() -> (String, Calls, Arc<Mutex<Vec<String>>>) {
    crm_with(false).await
}

/// The server, speaking only 2025-11-25 when `legacy`.
pub async fn crm_with(legacy: bool) -> (String, Calls, Arc<Mutex<Vec<String>>>) {
    let calls: Calls = Default::default();
    let tokens: Arc<Mutex<Vec<String>>> = Default::default();
    let c = calls.clone();
    let service = StreamableHttpService::new(move || Ok(Crm { calls: c.clone(), legacy }), LocalSessionManager::default().into(), StreamableHttpServerConfig::default());
    let seen = tokens.clone();
    let app = Router::new().nest_service("/mcp", service).layer(axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let seen = seen.clone();
            async move {
                let auth = req.headers().get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("").to_owned();
                seen.lock().unwrap().push(auth.clone());
                if !auth.starts_with(&format!("Bearer for-{SCOPE}-")) {
                    return axum::response::IntoResponse::into_response(StatusCode::UNAUTHORIZED);
                }
                next.run(req).await
            }
        },
    ));
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move { axum::serve(l, app).await });
    (format!("http://127.0.0.1:{port}/mcp"), calls, tokens)
}


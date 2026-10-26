// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! `mcp` sources: Gate Core as an MCP client, as the signed-in person
//! (D-071 slice 4).
//!
//! A server elsewhere, over HTTP, that takes an Entra token: never one run
//! on the host. For each request Gate Core
//!
//! 1. **decides**: the source is an `mcp` one, the tool is in its `scope`
//!    (the config's list, never the server's word), and the arguments the
//!    config pins are set over whatever the box sent;
//! 2. **asks Entra** for the server's delegated scope with the person's
//!    refresh token ([`crate::entra::Entra::acting_for_scope`]), so the
//!    server sees the person and Conditional Access applies;
//! 3. **calls** with the MCP version the config pins: 2025-11-25's
//!    `initialize`, or 2026-07-28 without it. Never a probe and a fallback,
//!    where the reported faults are (`docs/research/2026-10-26-mcp-transport.md`);
//! 4. **records** the call as a fetch is recorded: the result as JSON is the
//!    bytes the box receives, hashed on the way past, recorded once with the
//!    admission id, counted by the volume window, in the session's lineage
//!    ([`crate::http::admitted`]).
//!
//! Gate Core parses the MCP framing of the calls it makes, which rmcp does;
//! what a result says is for the endpoint and the agent, enveloped there.
//!
//! **Limits.** "As the person" holds as far as the server: one that reads its
//! own systems with a service account answers with what that account sees.
//! A tool's `readOnlyHint` is the server's claim; the config's list is the
//! control. A tool's description and schema are the server's text, shown to
//! the agent as they come.
//!
//! ponytail: a connection per request, with its handshake. Hold one per
//! source and token if the latency shows.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::body::Bytes;
use axum::response::Response;
use rmcp::model::{CallToolRequestParams, ClientCapabilities, ClientConfig, Implementation, ProtocolVersion};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt, RoleClient, RunningService};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use sluse_proto::wire::{CallRequest, ToolSourceUnavailable, ToolView, ToolsResponse};
use sluse_proto::{Capability, McpProtocol, Op, SessionId, SluseError, SourceKind};

use crate::app::Core;
use crate::http::{ApiError, ApiResult};
use crate::scope::{request_form, CompiledSource};

/// The most one result may be when no `maxFetchBytes` is set: a result is
/// held whole in memory on both sides, as a delivery is.
const RESULT_LIMIT: u64 = 64 * 1024 * 1024;

/// One client for every server: bounded waits, and **no redirect**, so a
/// call goes to the address the config names, which the loader holds to
/// https, and nowhere else with the person's token.
fn http() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_default()
    })
}

/// An `mcp` source's address, from its compiled form.
struct Server<'a> {
    source: &'a CompiledSource,
    url: &'a str,
    entra_scope: &'a str,
    protocol: McpProtocol,
    pins: Option<&'a serde_json::Map<String, serde_json::Value>>,
}

impl<'a> Server<'a> {
    fn of(source: &'a CompiledSource, tool: Option<&str>) -> Option<Self> {
        let SourceKind::Mcp { url, entra_scope, protocol, pins } = &source.kind else { return None };
        Some(Server { source, url, entra_scope, protocol: *protocol, pins: tool.and_then(|t| pins.get(t)) })
    }

    fn name(&self) -> &str {
        self.source.name.as_str()
    }

    fn unavailable(&self, detail: impl std::fmt::Display) -> SluseError {
        SluseError::SourceUnavailable { source_name: self.name().to_owned(), detail: detail.to_string() }
    }

    /// The person's token for this server, and a client that has done the
    /// pinned handshake.
    async fn connect(&self, core: &Core) -> Result<RunningService<RoleClient, ClientConfig>, SluseError> {
        let entra = core.entra.as_ref().ok_or_else(|| SluseError::SignInRequired {
            detail: "this box's config has no entra block, so there is no one to call the server as".into(),
        })?;
        let token = entra.acting_for_scope(self.name(), self.entra_scope).await?.access;
        let config = StreamableHttpClientTransportConfig::with_uri(self.url.to_owned()).auth_header(token);
        let transport = StreamableHttpClientTransport::with_client(http().clone(), config);
        let (info, mode) = match self.protocol {
            McpProtocol::V2025_11_25 => (client_info(ProtocolVersion::V_2025_11_25), ClientLifecycleMode::Initialize),
            McpProtocol::V2026_07_28 => (
                client_info(ProtocolVersion::V_2026_07_28),
                ClientLifecycleMode::Discover { preferred_versions: vec![ProtocolVersion::V_2026_07_28] },
            ),
        };
        info.serve_with_lifecycle(transport, mode).await.map_err(|e| {
            if e.is_authorization_required() || refused(&e) {
                SluseError::AccessDenied {
                    raw: self.name().to_owned(),
                    detail: format!("the server refused the person's token: {e}"),
                }
            } else {
                self.unavailable(format!("the MCP {} handshake: {e}", self.protocol.as_str()))
            }
        })
    }
}

/// A 401 or 403 from the server. rmcp names one only when it carries the
/// `WWW-Authenticate` challenge MCP requires; one without it comes back as an
/// unexpected response whose text holds the status, and a server that leaves
/// the header out is still refusing the person, not down.
///
/// ponytail: matched on rmcp 3.7's text, `HTTP 401 `; a structured status
/// when rmcp gives one.
fn refused(e: &(dyn std::error::Error + 'static)) -> bool {
    let mut next = Some(e);
    while let Some(err) = next {
        let text = err.to_string();
        if text.contains("HTTP 401 ") || text.contains("HTTP 403 ") {
            return true;
        }
        next = err.source();
    }
    false
}

fn client_info(version: ProtocolVersion) -> ClientConfig {
    let mut me = Implementation::default();
    me.name = "sluse-gate-core".into();
    me.version = crate::VERSION.into();
    ClientConfig::new(ClientCapabilities::default(), me).with_protocol_version(version)
}

/// `GET /v1/tools`: every `mcp` source's allowed tools, as its server lists
/// them now. A server that cannot be asked is recorded and named, and the
/// others are listed.
pub(crate) async fn tools(core: &Arc<Core>, session: &SessionId) -> ToolsResponse {
    let mut out = ToolsResponse { tools: Vec::new(), unavailable: Vec::new() };
    for source in core.compiled.sources.iter().filter(|s| !s.tools.is_empty()) {
        let Some(server) = Server::of(source, None) else { continue };
        let listed = async {
            let client = server.connect(core).await?;
            let listed = client.list_all_tools().await.map_err(|e| server.unavailable(format!("tools/list: {e}")));
            let _ = client.cancel().await;
            listed
        }
        .await;
        match listed {
            Ok(listed) => {
                core.answered(&source.name);
                out.tools.extend(listed.into_iter().filter(|t| source.tools.iter().any(|a| a == t.name.as_ref())).map(|t| {
                    let pins = match &source.kind {
                        SourceKind::Mcp { pins, .. } => pins.get(t.name.as_ref()),
                        _ => None,
                    };
                    ToolView {
                        name: request_form(source.name.as_str(), &t.name),
                        description: t.description.map(|d| d.into_owned()),
                        input_schema: without_pins(serde_json::Value::Object((*t.input_schema).clone()), pins),
                    }
                }));
            }
            Err(e) => {
                let e = core.refuse(core.record(session, Op::Tools, source.name.as_str()), e);
                out.unavailable.push(ToolSourceUnavailable { source: source.name.to_string(), reason: e.reason_code().to_owned() });
            }
        }
    }
    out
}

/// A tool's input schema without the arguments the config pins: the agent
/// is not offered what it cannot set.
fn without_pins(mut schema: serde_json::Value, pins: Option<&serde_json::Map<String, serde_json::Value>>) -> serde_json::Value {
    let Some(pins) = pins else { return schema };
    if let Some(props) = schema.get_mut("properties").and_then(|p| p.as_object_mut()) {
        props.retain(|k, _| !pins.contains_key(k));
    }
    if let Some(req) = schema.get_mut("required").and_then(|r| r.as_array_mut()) {
        req.retain(|k| !k.as_str().is_some_and(|k| pins.contains_key(k)));
    }
    schema
}

/// `POST /v1/call`: one call, decided here, made as the person, its result
/// admitted like a fetch.
pub(crate) async fn call(core: &Arc<Core>, session: SessionId, req: CallRequest) -> ApiResult<Response> {
    let rec = || core.record(&session, Op::Call, &req.tool).with_capability(Capability::Bytes);
    let refuse = |r, e| ApiError(core.refuse(r, e));

    let Some((source_name, tool)) = req.tool.split_once('/') else {
        return Err(refuse(rec(), SluseError::UnknownSource { raw: req.tool.clone() }));
    };
    let Some(index) = core.compiled.sources.iter().position(|s| s.name.as_str() == source_name) else {
        return Err(refuse(rec(), SluseError::UnknownSource { raw: req.tool.clone() }));
    };
    let source = core.source(index);
    let Some(server) = Server::of(source, Some(tool)) else {
        let e = SluseError::UnsupportedSourceKind { source_name: source_name.to_owned(), kind: source.kind.type_name().to_owned() };
        return Err(refuse(rec(), e));
    };
    let resolved = format!("{}#{tool}", server.url);
    let located = || {
        let mut r = rec();
        r.path_resolved = Some(resolved.clone());
        r
    };
    // The config's list, never the server's: a tool not on it does not exist
    // for the agent (D-008's blinders; the box is told NOT_FOUND).
    if !source.tools.iter().any(|t| t == tool) {
        let e = SluseError::OutOfScope {
            raw: req.tool.clone(),
            resolved: resolved.clone(),
            source_name: source_name.to_owned(),
            scopes: source.scope_request_forms(),
        };
        return Err(refuse(located(), e));
    }
    let located = || {
        let mut r = located();
        r.scope = Some(request_form(source_name, tool));
        r
    };

    let mut arguments = req.arguments.clone();
    for (k, v) in server.pins.into_iter().flatten() {
        arguments.insert(k.clone(), v.clone());
    }
    let client = server.connect(core).await.map_err(|e| refuse(located(), e))?;
    let result = client
        .call_tool(CallToolRequestParams::new(tool.to_owned()).with_arguments(arguments))
        .await
        .map_err(|e| server.unavailable(format!("tools/call: {e}")));
    let _ = client.cancel().await;
    let result = result.map_err(|e| refuse(located(), e))?;
    core.answered(&source.name);

    // What the box receives, and so what both ends hash.
    let bytes = serde_json::to_vec(&result).map_err(|e| refuse(located(), SluseError::Internal { message: e.to_string() }))?;
    let size = bytes.len() as u64;
    let limit = core.max_fetch_bytes().unwrap_or(RESULT_LIMIT);
    if size > limit {
        return Err(refuse(located(), SluseError::TooLarge { raw: req.tool.clone(), size, limit }));
    }
    let body = Once(Some(Bytes::from(bytes)));
    Ok(crate::http::admitted(core, located(), session, source.name.clone(), body, size, &resolved))
}

/// One chunk as a stream, for [`crate::http::admitted`].
struct Once(Option<Bytes>);

impl futures_core::Stream for Once {
    type Item = Result<Bytes, std::io::Error>;
    fn poll_next(mut self: std::pin::Pin<&mut Self>, _: &mut std::task::Context<'_>) -> std::task::Poll<Option<Self::Item>> {
        std::task::Poll::Ready(self.0.take().map(Ok))
    }
}

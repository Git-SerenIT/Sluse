// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! An MCP server as a source, set up (D-071 slice 6).
//!
//! Three steps, in the order the setup UI takes them:
//!
//! 1. [`require`]: the server's app in this tenant, found from the
//!    `entraScope` the admin names (`api://crm-mcp/Mcp.Read`, an app id with
//!    a scope, or a resource URL with one), and its delegated scope added to
//!    Sluse Gate's registration beside Graph's. A vendor's app with no
//!    service principal here yet gets one, as Graph's would.
//! 2. [`consented`]: whether a tenant-wide grant covers that scope. The admin
//!    grants it in the portal, as Graph's (`consent.rs`): Sluse Admin asks no
//!    right to write grants.
//! 3. [`probe`]: the server asked once, with a token Sluse Gate got for the
//!    scope as the admin, which is also the proof the grant works: which MCP
//!    version it speaks (the one probe there is, so a box's call never
//!    probes, D-071 point 6) and its tools, with each one's `readOnlyHint`,
//!    shown as the server's claim.

use std::time::Duration;

use rmcp::model::{ClientCapabilities, ClientConfig, Implementation, ProtocolVersion};
use rmcp::service::{ClientLifecycleMode, ClientServiceExt};
use rmcp::transport::streamable_http_client::StreamableHttpClientTransportConfig;
use rmcp::transport::StreamableHttpClientTransport;
use serde::Serialize;
use serde_json::{json, Value};
use sluse_proto::McpProtocol;

use crate::graph::Graph;

/// The server's app in this tenant, and the scope Sluse Gate asks it for.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Resource {
    pub app_id: String,
    pub service_principal: String,
    pub name: String,
    pub scope: String,
    pub scope_id: String,
}

/// `entraScope` as its resource and its scope's value. `/.default` is not
/// one scope, and a scope Sluse Gate is granted has to be named.
pub fn split_scope(entra_scope: &str) -> Result<(&str, &str), String> {
    let (resource, value) = entra_scope
        .trim()
        .rsplit_once('/')
        .filter(|(r, v)| !r.is_empty() && !v.is_empty())
        .ok_or_else(|| format!("\"{entra_scope}\" is not a resource and a scope, such as api://crm-mcp/Mcp.Read"))?;
    if value == ".default" {
        return Err("name the delegated scope the server takes, such as Mcp.Read or user_impersonation, not .default".into());
    }
    Ok((resource, value))
}

fn is_guid(s: &str) -> bool {
    s.len() == 36 && s.bytes().enumerate().all(|(i, c)| if [8, 13, 18, 23].contains(&i) { c == b'-' } else { c.is_ascii_hexdigit() })
}

/// Find the server's app and its scope in this tenant.
pub async fn resource(g: &Graph, entra_scope: &str) -> Result<Resource, String> {
    let (resource, value) = split_scope(entra_scope)?;
    let found = if is_guid(resource) {
        // A vendor's multi-tenant app may have no service principal here yet.
        g.service_principal(resource, &mut Vec::new()).await?
    } else {
        g.list(format!("/servicePrincipals?$filter=servicePrincipalNames/any(n:n eq '{resource}')"))
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| format!("no app in this tenant answers to {resource}; check the scope's spelling, or use the app's id"))?
    };
    let scope_id = found["oauth2PermissionScopes"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|s| s["value"] == value)
        .and_then(|s| s["id"].as_str())
        .ok_or_else(|| format!("{} has no delegated scope {value}", found["displayName"].as_str().unwrap_or(resource)))?
        .to_owned();
    Ok(Resource {
        app_id: found["appId"].as_str().unwrap_or_default().to_owned(),
        service_principal: found["id"].as_str().unwrap_or_default().to_owned(),
        name: found["displayName"].as_str().unwrap_or(resource).to_owned(),
        scope: value.to_owned(),
        scope_id,
    })
}

/// The scope on Sluse Gate's registration, beside Graph's. True when it was
/// added now; nothing else in the registration changes.
pub async fn require(g: &Graph, entra_scope: &str) -> Result<(Resource, bool), String> {
    let r = resource(g, entra_scope).await?;
    let gate = g.find_app(crate::setup::GATE_NAME).await?.ok_or("Sluse's app is not registered yet; set up the tenant first")?;
    let id = gate["id"].as_str().ok_or("Sluse's app has no id")?;
    let mut required = gate["requiredResourceAccess"].as_array().cloned().unwrap_or_default();
    let wanted = json!({ "id": r.scope_id, "type": "Scope" });
    let added = match required.iter_mut().find(|e| e["resourceAppId"] == r.app_id.as_str()) {
        Some(e) if e["resourceAccess"].as_array().is_some_and(|a| a.contains(&wanted)) => false,
        Some(e) => {
            if let Some(a) = e["resourceAccess"].as_array_mut() {
                a.push(wanted);
            } else {
                e["resourceAccess"] = json!([wanted]);
            }
            true
        }
        None => {
            required.push(json!({ "resourceAppId": r.app_id, "resourceAccess": [wanted] }));
            true
        }
    };
    if added {
        g.call(reqwest::Method::PATCH, format!("/applications/{id}"), Some(json!({ "requiredResourceAccess": required }))).await?;
    }
    Ok((r, added))
}

/// Whether a tenant-wide grant gives Sluse Gate's service principal `sp`
/// this resource's scope.
pub async fn consented(g: &Graph, sp: &str, r: &Resource) -> Result<bool, String> {
    let grants = g
        .list(format!("/oauth2PermissionGrants?$filter=clientId eq '{sp}' and consentType eq 'AllPrincipals'"))
        .await?;
    Ok(grants
        .iter()
        .filter(|x| x["resourceId"] == r.service_principal.as_str())
        .any(|x| x["scope"].as_str().unwrap_or_default().split(' ').any(|s| s == r.scope)))
}

/// What the server answered.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Probe {
    pub protocol: McpProtocol,
    pub tools: Vec<ProbedTool>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbedTool {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
    /// The server's `readOnlyHint`: its claim, shown, never relied on.
    pub read_only: Option<bool>,
}

/// Ask the server with a token for its scope: 2026-07-28 first, then the
/// older handshake, each on its own, so a server that answers the new one's
/// discovery but speaks only the old version is still found. The version it
/// answered is the one the config pins. One that speaks neither is refused
/// with both answers.
pub async fn probe(http: &reqwest::Client, url: &str, token: &str) -> Result<Probe, String> {
    let modern = connect(http, url, token, McpProtocol::V2026_07_28).await;
    let (client, protocol) = match modern {
        Ok(c) => (c, McpProtocol::V2026_07_28),
        Err(new) => match connect(http, url, token, McpProtocol::V2025_11_25).await {
            Ok(c) => (c, McpProtocol::V2025_11_25),
            Err(old) => return Err(format!("{url}: as 2026-07-28: {new}; as 2025-11-25: {old}")),
        },
    };
    let tools = client.list_all_tools().await.map_err(|e| format!("tools/list: {e}"));
    let _ = client.cancel().await;
    let tools = tools?
        .into_iter()
        .map(|t| ProbedTool {
            name: t.name.to_string(),
            description: t.description.map(|d| d.into_owned()),
            input_schema: Value::Object((*t.input_schema).clone()),
            read_only: t.annotations.and_then(|a| a.read_only_hint),
        })
        .collect();
    Ok(Probe { protocol, tools })
}

/// One handshake, as a box's Gate Core would make it for that version.
async fn connect(
    http: &reqwest::Client,
    url: &str,
    token: &str,
    protocol: McpProtocol,
) -> Result<rmcp::service::RunningService<rmcp::service::RoleClient, ClientConfig>, String> {
    let config = StreamableHttpClientTransportConfig::with_uri(url.to_owned()).auth_header(token.to_owned());
    let transport = StreamableHttpClientTransport::with_client(http.clone(), config);
    let mut me = Implementation::default();
    me.name = "sluse-admin".into();
    me.version = sluse_proto::VERSION.into();
    let (version, mode) = match protocol {
        McpProtocol::V2026_07_28 => (
            ProtocolVersion::V_2026_07_28,
            ClientLifecycleMode::Discover { preferred_versions: vec![ProtocolVersion::V_2026_07_28] },
        ),
        McpProtocol::V2025_11_25 => (ProtocolVersion::V_2025_11_25, ClientLifecycleMode::Initialize),
    };
    let info = ClientConfig::new(ClientCapabilities::default(), me).with_protocol_version(version);
    tokio::time::timeout(Duration::from_secs(20), info.serve_with_lifecycle(transport, mode))
        .await
        .map_err(|_| "no answer in 20 s".to_owned())?
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_is_a_resource_and_a_named_scope() {
        assert_eq!(split_scope("api://crm-mcp/Mcp.Read").unwrap(), ("api://crm-mcp", "Mcp.Read"));
        assert_eq!(
            split_scope("499b84ac-1321-427f-aa17-267ca6975798/user_impersonation").unwrap(),
            ("499b84ac-1321-427f-aa17-267ca6975798", "user_impersonation")
        );
        assert_eq!(split_scope("https://crm.example.com/Mcp.Read").unwrap(), ("https://crm.example.com", "Mcp.Read"));
        assert!(split_scope("api://crm-mcp/.default").unwrap_err().contains("name the delegated scope"));
        assert!(split_scope("Mcp.Read").is_err());
    }

    #[tokio::test]
    async fn the_scope_is_added_beside_graph_s_once_and_consent_is_per_resource() {
        let (base, t) = crate::stand_in::start().await;
        let g = crate::stand_in::graph(&base);
        let reg = crate::setup::register(&g).await.unwrap();
        t.lock().unwrap().sps.push(json!({
            "id": "sp-crm", "appId": "11111111-0000-4000-8000-000000000001", "displayName": "CRM MCP",
            "servicePrincipalNames": ["api://crm-mcp"],
            "oauth2PermissionScopes": [{ "value": "Mcp.Read", "id": "scope-read" }, { "value": "Mcp.Write", "id": "scope-write" }]
        }));

        let (r, added) = require(&g, "api://crm-mcp/Mcp.Read").await.unwrap();
        assert!(added);
        assert_eq!((r.service_principal.as_str(), r.scope_id.as_str(), r.name.as_str()), ("sp-crm", "scope-read", "CRM MCP"));
        assert!(!require(&g, "api://crm-mcp/Mcp.Read").await.unwrap().1, "once");
        let app = t.lock().unwrap().apps[0].clone();
        let required = app["requiredResourceAccess"].as_array().unwrap();
        assert_eq!(required.len(), 2, "Graph's and the server's: {required:?}");
        assert_eq!(required[1]["resourceAccess"], json!([{ "id": "scope-read", "type": "Scope" }]));

        // Running setup again keeps it (it used to replace the list).
        crate::setup::register(&g).await.unwrap();
        assert_eq!(t.lock().unwrap().apps[0]["requiredResourceAccess"].as_array().unwrap().len(), 2);

        assert!(!consented(&g, &reg.service_principal, &r).await.unwrap());
        // Graph's grant does not count for the server's scope.
        t.lock().unwrap().grants.push(json!({ "clientId": reg.service_principal, "consentType": "AllPrincipals", "resourceId": "graph-sp", "scope": "Mcp.Read" }));
        assert!(!consented(&g, &reg.service_principal, &r).await.unwrap());
        t.lock().unwrap().grants.push(json!({ "clientId": reg.service_principal, "consentType": "AllPrincipals", "resourceId": "sp-crm", "scope": "Mcp.Read" }));
        assert!(consented(&g, &reg.service_principal, &r).await.unwrap());

        assert!(require(&g, "api://crm-mcp/Mcp.Delete").await.unwrap_err().contains("no delegated scope Mcp.Delete"));
        assert!(require(&g, "api://nothing/Read").await.unwrap_err().contains("no app in this tenant"));
    }
}

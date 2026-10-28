// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A stand-in for Entra's sign-in and Microsoft Graph, as far as setup uses
//! them: a tenant held in memory, seeded by each test. It speaks the
//! documented shapes and proves nothing about Graph itself.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::{Method, Uri};
use axum::Json;
use serde_json::{json, Value};

pub const TENANT: &str = "11111111-2222-3333-4444-555555555555";

#[derive(Default)]
pub struct Tenant {
    pub apps: Vec<Value>,
    /// Service principals: `id`, `appId`, `appRoleAssignmentRequired`.
    pub sps: Vec<Value>,
    /// `appRoleAssignedTo` per service principal id.
    pub assigned: HashMap<String, Vec<Value>>,
    /// Admin consent grants: `clientId`, `consentType`, `scope`.
    pub grants: Vec<Value>,
    /// The signed-in admin's directory roles, by template id.
    pub roles: Vec<String>,
    /// Groups: `id`, `displayName`, `resourceProvisioningOptions`, and
    /// `devices` (a count, the stand-in's own).
    pub groups: Vec<Value>,
    pub polls: u32,
    /// Authorization codes the stand-in redeems, with their verifier.
    pub codes: HashMap<String, String>,
    /// Intune: the Win32 apps, as posted and patched.
    pub mobile_apps: Vec<Value>,
    /// Content files: their state and how often each was asked about.
    pub files: HashMap<String, Value>,
    /// Azure storage: uploaded blocks, and the blob once its list is put.
    pub blocks: HashMap<String, Vec<u8>>,
    pub blobs: HashMap<String, Vec<u8>>,
    /// Whether any request to storage carried a bearer token.
    pub bearer_to_storage: bool,
    pub relationships: HashMap<String, Value>,
    pub assignments: HashMap<String, Value>,
    /// Users per group, for the Intune assignment's warning.
    pub group_users: HashMap<String, u32>,
    /// Intune's commit fails, as `commitFileFailed`.
    pub fail_commit: bool,
    /// Where the stand-in is, for the SAS URLs it hands out.
    pub base: String,
    /// `/policies/authorizationPolicy`; none answers 403, as without
    /// `Policy.Read.All`.
    pub authorization_policy: Option<Value>,
    /// Conditional Access's policies; none answers 403, as without P1.
    pub ca_policies: Option<Vec<Value>>,
}

/// Entra and Graph, just as far as setup uses them.
async fn fake(
    State(t): State<Arc<Mutex<Tenant>>>,
    method: Method,
    uri: Uri,
    headers: axum::http::HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    raw: axum::body::Bytes,
) -> Result<Json<Value>, axum::http::StatusCode> {
    // The sign-in posts forms; Graph takes JSON.
    let body: Option<Value> = serde_json::from_slice(&raw).ok();
    let form: HashMap<String, String> = url_form(&raw);
    let mut t = t.lock().unwrap();
    if uri.path().starts_with("/blob/") && headers.contains_key("authorization") {
        t.bearer_to_storage = true;
    }
    // Intune's calls go to beta; the stand-in serves both the same way.
    let path = uri.path().replacen("/beta/", "/v1.0/", 1);
    let filter = |field: &str| {
        q.get("$filter").and_then(|f| f.strip_prefix(&format!("{field} eq '"))?.split('\'').next().map(str::to_owned))
    };
    let token = || {
        let claims = crate::setup::base64(json!({ "tid": TENANT }).to_string().as_bytes())
            .replace('+', "-")
            .replace('/', "_")
            .replace('=', "");
        json!({ "access_token": format!("h.{claims}.s") })
    };
    Ok(Json(match (method.as_str(), path.as_str()) {
        ("POST", "/organizations/oauth2/v2.0/devicecode") => {
            json!({ "device_code": "d", "message": "open the page", "interval": 0 })
        }
        ("POST", "/organizations/oauth2/v2.0/token") if form.get("grant_type").map(String::as_str) == Some("authorization_code") => {
            let code = form.get("code").cloned().unwrap_or_default();
            match t.codes.remove(&code) {
                Some(v) if form.get("code_verifier") == Some(&v) => token(),
                _ => json!({ "error": "invalid_grant", "error_description": "AADSTS70008: stand-in" }),
            }
        }
        ("POST", "/organizations/oauth2/v2.0/token") => {
            t.polls += 1;
            if t.polls < 2 { json!({ "error": "authorization_pending" }) } else { token() }
        }
        ("GET", p) if p.starts_with("/v1.0/servicePrincipals(appId=") => {
            let scopes: Vec<Value> = ["Files.Read.All", "Sites.Read.All", "offline_access", "openid", "profile"]
                .iter()
                .enumerate()
                .map(|(i, v)| json!({ "value": v, "id": format!("graph-scope-{i}") }))
                .collect();
            json!({ "id": "graph-sp", "oauth2PermissionScopes": scopes })
        }
        ("GET", "/v1.0/applications") => {
            let name = filter("displayName").unwrap();
            json!({ "value": t.apps.iter().filter(|a| a["displayName"] == name.as_str()).cloned().collect::<Vec<_>>() })
        }
        ("POST", "/v1.0/applications") => {
            let n = t.apps.len();
            let mut a = body.unwrap();
            a["id"] = json!(format!("object-{n}"));
            a["appId"] = json!(format!("{n:08}-0000-4000-8000-000000000000"));
            t.apps.push(a.clone());
            a
        }
        // An application's owners and credentials (review R-10), before the
        // application's own routes, which would take these paths too.
        ("GET", p) if p.starts_with("/v1.0/applications/") && (p.ends_with("/owners") || p.ends_with("/federatedIdentityCredentials")) => {
            let (id, what) = p.trim_start_matches("/v1.0/applications/").split_once('/').unwrap();
            let a = t.apps.iter().find(|a| a["id"] == id).unwrap();
            json!({ "value": a[what].as_array().cloned().unwrap_or_default() })
        }
        ("DELETE", p) if p.starts_with("/v1.0/applications/") && (p.contains("/owners/") || p.contains("/federatedIdentityCredentials/")) => {
            let mut parts = p.trim_start_matches("/v1.0/applications/").split('/');
            let (id, what, item) = (parts.next().unwrap(), parts.next().unwrap(), parts.next().unwrap());
            let a = t.apps.iter_mut().find(|a| a["id"] == id).unwrap();
            if let Some(list) = a[what].as_array_mut() {
                list.retain(|x| x["id"] != item);
            }
            Value::Null
        }
        ("POST", p) if p.starts_with("/v1.0/applications/") && p.ends_with("/removePassword") => {
            let id = p.trim_start_matches("/v1.0/applications/").trim_end_matches("/removePassword");
            let key = body.unwrap()["keyId"].clone();
            let a = t.apps.iter_mut().find(|a| a["id"] == id).unwrap();
            if let Some(list) = a["passwordCredentials"].as_array_mut() {
                list.retain(|x| x["keyId"] != key);
            }
            Value::Null
        }
        ("DELETE", p) if p.starts_with("/v1.0/applications/") => {
            let id = p.trim_start_matches("/v1.0/applications/");
            t.apps.retain(|a| a["id"] != id);
            Value::Null
        }
        ("PATCH", p) if p.starts_with("/v1.0/applications/") => {
            let id = p.trim_start_matches("/v1.0/applications/");
            let a = t.apps.iter_mut().find(|a| a["id"] == id).unwrap();
            for (k, v) in body.unwrap().as_object().unwrap() {
                a[k] = v.clone();
            }
            Value::Null
        }
        ("GET", "/v1.0/servicePrincipals") => {
            // By app id, or by a name the app answers to (D-071).
            let f = q.get("$filter").cloned().unwrap_or_default();
            if let Some(prefix) = f.strip_prefix("startswith(displayName,'").and_then(|r| r.strip_suffix("')")) {
                json!({ "value": t.sps.iter().filter(|s| s["displayName"].as_str().is_some_and(|n| n.starts_with(prefix))).cloned().collect::<Vec<_>>() })
            } else if let Some(name) = f.strip_prefix("servicePrincipalNames/any(n:n eq '").and_then(|r| r.strip_suffix("')")) {
                json!({ "value": t.sps.iter().filter(|s| s["servicePrincipalNames"].as_array().is_some_and(|n| n.iter().any(|x| x == name))).cloned().collect::<Vec<_>>() })
            } else {
                let app = filter("appId").unwrap();
                json!({ "value": t.sps.iter().filter(|s| s["appId"] == app.as_str()).cloned().collect::<Vec<_>>() })
            }
        }
        ("POST", "/v1.0/servicePrincipals") => {
            let b = body.unwrap();
            let app = b["appId"].as_str().unwrap().to_owned();
            let enabled = b["accountEnabled"].as_bool().unwrap_or(true);
            let sp = json!({ "id": format!("sp-{app}"), "appId": app, "appRoleAssignmentRequired": false, "accountEnabled": enabled });
            t.sps.push(sp.clone());
            sp
        }
        ("GET", p) if p.starts_with("/v1.0/servicePrincipals/") && p.ends_with("/appRoleAssignedTo") => {
            let id = p.trim_start_matches("/v1.0/servicePrincipals/").trim_end_matches("/appRoleAssignedTo");
            json!({ "value": t.assigned.get(id).cloned().unwrap_or_default() })
        }
        ("POST", p) if p.starts_with("/v1.0/servicePrincipals/") && p.ends_with("/appRoleAssignedTo") => {
            let id = p.trim_start_matches("/v1.0/servicePrincipals/").trim_end_matches("/appRoleAssignedTo").to_owned();
            let mut a = body.unwrap();
            let name = t.groups.iter().find(|g| g["id"] == a["principalId"]).map(|g| g["displayName"].clone());
            let n = t.assigned.values().map(Vec::len).sum::<usize>();
            a["id"] = json!(format!("assignment-{n}"));
            a["principalType"] = json!("Group");
            a["principalDisplayName"] = name.unwrap_or(Value::Null);
            a["createdDateTime"] = json!("2026-10-03T09:00:00Z");
            t.assigned.entry(id).or_default().push(a.clone());
            a
        }
        ("DELETE", p) if p.starts_with("/v1.0/servicePrincipals/") && p.contains("/appRoleAssignedTo/") => {
            let (id, item) = p.trim_start_matches("/v1.0/servicePrincipals/").split_once("/appRoleAssignedTo/").unwrap();
            if let Some(list) = t.assigned.get_mut(id) {
                list.retain(|a| a["id"] != item);
            }
            Value::Null
        }
        ("GET", p) if p.starts_with("/v1.0/servicePrincipals/") => {
            let id = p.trim_start_matches("/v1.0/servicePrincipals/");
            t.sps.iter().find(|s| s["id"] == id).cloned().unwrap_or(Value::Null)
        }
        ("PATCH", p) if p.starts_with("/v1.0/servicePrincipals/") => {
            let id = p.trim_start_matches("/v1.0/servicePrincipals/");
            let sp = t.sps.iter_mut().find(|s| s["id"] == id).unwrap();
            for (k, v) in body.unwrap().as_object().unwrap() {
                sp[k] = v.clone();
            }
            Value::Null
        }
        ("GET", "/v1.0/oauth2PermissionGrants") => {
            let client = filter("clientId").unwrap();
            let all = q.get("$filter").is_some_and(|f| f.contains("consentType eq 'AllPrincipals'"));
            json!({ "value": t.grants.iter()
                .filter(|g| g["clientId"] == client.as_str() && (!all || g["consentType"] == "AllPrincipals"))
                .cloned().collect::<Vec<_>>() })
        }
        ("GET", "/v1.0/identity/conditionalAccess/policies") => match &t.ca_policies {
            Some(p) => json!({ "value": p }),
            None => return Err(axum::http::StatusCode::FORBIDDEN),
        },
        ("GET", "/v1.0/policies/authorizationPolicy") => match &t.authorization_policy {
            Some(p) => p.clone(),
            None => return Err(axum::http::StatusCode::FORBIDDEN),
        },
        ("GET", "/v1.0/me") => json!({ "userPrincipalName": "admin@contoso.dk" }),
        ("GET", "/v1.0/organization") => json!({ "value": [{ "displayName": "Contoso" }] }),
        ("GET", "/v1.0/me/memberOf/microsoft.graph.directoryRole") => {
            json!({ "value": t.roles.iter().map(|r| json!({ "roleTemplateId": r, "displayName": format!("role {r}") })).collect::<Vec<_>>() })
        }
        ("GET", "/v1.0/groups") => {
            let f = q.get("$filter").cloned().unwrap_or_default();
            let found: Vec<Value> = match f.strip_prefix("startswith(displayName,'") {
                Some(rest) => {
                    let prefix = rest.split('\'').next().unwrap_or_default().to_lowercase();
                    t.groups.iter().filter(|g| g["displayName"].as_str().unwrap_or_default().to_lowercase().starts_with(&prefix)).cloned().collect()
                }
                // The Teams filter.
                None => t.groups.iter()
                    .filter(|g| g["resourceProvisioningOptions"].as_array().is_some_and(|o| o.iter().any(|x| x == "Team")))
                    .cloned().collect(),
            };
            json!({ "value": found })
        }
        ("GET", p) if p.starts_with("/v1.0/groups/") => {
            let rest = p.trim_start_matches("/v1.0/groups/");
            let (id, what) = rest.split_once('/').unwrap_or((rest, ""));
            if what == "members/microsoft.graph.user" {
                let n = t.group_users.get(id).copied().unwrap_or(0);
                return Ok(Json(json!({ "value": (0..n.min(1)).map(|i| json!({ "id": format!("user-{i}") })).collect::<Vec<_>>() })));
            }
            let g = t.groups.iter().find(|g| g["id"] == id).cloned();
            match (g, what) {
                (Some(g), "") => g,
                (Some(g), "members/microsoft.graph.device") => {
                    let n = g["devices"].as_u64().unwrap_or(0);
                    json!({ "value": (0..n.min(1)).map(|i| json!({ "id": format!("device-{i}") })).collect::<Vec<_>>() })
                }
                (Some(g), "sites/root") if g["site"] == "none" => Value::Null,
                (Some(g), "sites/root") if g["site"] == "forbidden" => return Err(axum::http::StatusCode::FORBIDDEN),
                (Some(g), "sites/root") => json!({ "id": format!("site-{}", g["id"].as_str().unwrap()), "displayName": g["displayName"], "webUrl": format!("https://contoso.sharepoint.com/sites/{}", g["displayName"].as_str().unwrap()) }),
                _ => Value::Null,
            }
        }
        ("GET", "/v1.0/sites") => {
            let search = q.get("search").cloned().unwrap_or_default();
            let all = [
                json!({ "id": "site-tender", "displayName": "Tender", "webUrl": "https://contoso.sharepoint.com/sites/tender" }),
                json!({ "id": "site-hr", "displayName": "HR", "webUrl": "https://contoso.sharepoint.com/sites/hr" }),
            ];
            let found: Vec<Value> = all
                .into_iter()
                .filter(|s| s["displayName"].as_str().unwrap().to_lowercase().contains(&search.to_lowercase()))
                .collect();
            json!({ "value": found })
        }
        ("GET", p) if p.starts_with("/v1.0/sites/") && p.ends_with("/drives") => {
            json!({ "value": [{ "id": "drive-1", "name": "Documents", "webUrl": "https://contoso.sharepoint.com/sites/tender/Shared%20Documents" }] })
        }
        ("GET", "/v1.0/drives/drive-1/root/children") => json!({ "value": [
            { "id": "f-in", "name": "In-Scope", "folder": { "childCount": 4 }, "parentReference": { "path": "/drive/root:" } },
            { "id": "a-doc", "name": "readme.txt", "file": {}, "size": 3, "parentReference": { "path": "/drive/root:" } },
        ]}),
        ("GET", "/v1.0/drives/drive-1/items/f-in/children") => json!({ "value": [
            { "id": "f-deep", "name": "Deeper", "folder": { "childCount": 0 }, "parentReference": { "path": "/drive/root:/In-Scope" } },
        ]}),
        ("GET", "/v1.0/deviceAppManagement/mobileApps") => json!({ "value": t.mobile_apps.clone() }),
        ("POST", "/v1.0/deviceAppManagement/mobileApps") => {
            let mut a = body.unwrap();
            a["id"] = json!(format!("app-{}", t.mobile_apps.len()));
            t.mobile_apps.push(a.clone());
            a
        }
        ("DELETE", p) if p.starts_with("/v1.0/deviceAppManagement/mobileApps/") => {
            let id = p.rsplit('/').next().unwrap();
            t.mobile_apps.retain(|a| a["id"] != id);
            Value::Null
        }
        ("PATCH", p) if p.starts_with("/v1.0/deviceAppManagement/mobileApps/") => {
            let id = p.rsplit('/').next().unwrap();
            let a = t.mobile_apps.iter_mut().find(|a| a["id"] == id).unwrap();
            for (k, v) in body.unwrap().as_object().unwrap() {
                a[k] = v.clone();
            }
            Value::Null
        }
        ("POST", p) if p.ends_with("/microsoft.graph.win32LobApp/contentVersions") => json!({ "id": "1" }),
        ("POST", p) if p.ends_with("/contentVersions/1/files") => {
            let id = format!("file-{}", t.files.len());
            let f = json!({ "id": id, "uploadState": "azureStorageUriRequestPending", "asked": 0, "request": body.unwrap() });
            t.files.insert(id.clone(), f.clone());
            f
        }
        ("POST", p) if p.ends_with("/commit") => {
            let id = p.trim_end_matches("/commit").rsplit('/').next().unwrap().to_owned();
            let blob = t.blobs.get(&id).cloned().unwrap_or_default();
            let f = t.files.get_mut(&id).unwrap();
            f["commit"] = body.unwrap()["fileEncryptionInfo"].clone();
            f["committedBytes"] = json!(blob.len());
            f["uploadState"] = json!("commitFilePending");
            let failed = t.fail_commit;
            if failed {
                t.files.get_mut(&id).unwrap()["uploadState"] = json!("commitFileFailed");
            }
            Value::Null
        }
        ("GET", p) if p.contains("/contentVersions/1/files/") => {
            let id = p.rsplit('/').next().unwrap().to_owned();
            let base = t.base.clone();
            let f = t.files.get_mut(&id).unwrap();
            // Pending the first time it is asked, then done.
            let asked = f["asked"].as_u64().unwrap() + 1;
            f["asked"] = json!(asked);
            let state = f["uploadState"].as_str().unwrap().to_owned();
            if asked > 1 && state.ends_with("Pending") {
                f["uploadState"] = json!(state.replace("Pending", "Success"));
                f["asked"] = json!(0);
                if state.starts_with("azureStorageUri") {
                    f["azureStorageUri"] = json!(format!("{base}/blob/{id}?sv=stand-in"));
                }
            }
            f.clone()
        }
        ("PUT", p) if p.starts_with("/blob/") => {
            let id = p.trim_start_matches("/blob/").to_owned();
            match q.get("comp").map(String::as_str) {
                Some("block") => {
                    let block = q.get("blockid").cloned().unwrap();
                    t.blocks.insert(format!("{id}/{block}"), raw.to_vec());
                }
                Some("blocklist") => {
                    let list = String::from_utf8_lossy(&raw).into_owned();
                    let mut blob = Vec::new();
                    for part in list.split("<Latest>").skip(1) {
                        let block = part.split("</Latest>").next().unwrap();
                        blob.extend(t.blocks[&format!("{id}/{block}")].clone());
                    }
                    t.blobs.insert(id, blob);
                }
                other => panic!("storage was asked comp={other:?}"),
            }
            Value::Null
        }
        ("POST", p) if p.ends_with("/updateRelationships") => {
            let id = p.trim_end_matches("/updateRelationships").rsplit('/').next().unwrap().to_owned();
            t.relationships.insert(id, body.unwrap());
            Value::Null
        }
        ("POST", p) if p.ends_with("/assign") => {
            let id = p.trim_end_matches("/assign").rsplit('/').next().unwrap().to_owned();
            t.assignments.insert(id, body.unwrap());
            Value::Null
        }
        other => panic!("the stand-in was asked {other:?}"),
    }))
}

fn url_form(raw: &[u8]) -> HashMap<String, String> {
    std::str::from_utf8(raw)
        .unwrap_or("")
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), v.replace('+', " ").replace("%2F", "/").replace("%3A", ":")))
        .collect()
}

/// A running stand-in: its base URL (the authority; `<base>/v1.0` is Graph)
/// and its tenant, to seed and to look at.
pub async fn start() -> (String, Arc<Mutex<Tenant>>) {
    let t = Arc::new(Mutex::new(Tenant::default()));
    // Storage takes 6 MB blocks; axum would refuse anything over 2 MB.
    let app = axum::Router::new().fallback(fake).layer(axum::extract::DefaultBodyLimit::disable()).with_state(t.clone());
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", l.local_addr().unwrap());
    t.lock().unwrap().base = base.clone();
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (base, t)
}

/// Graph against the stand-in, signed in.
pub fn graph(base: &str) -> crate::graph::Graph {
    crate::graph::Graph::new(&reqwest::Client::new(), &format!("{base}/v1.0"), "t".into())
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Microsoft Graph, as the signed-in admin: one token, JSON in and out, and
//! an error that names the call. Tests point `base` at a stand-in.

use std::time::Duration;

use serde_json::{json, Value};

/// Graph as the admin, for setup's steps and the setup UI's pickers.
pub struct Graph {
    http: reqwest::Client,
    base: String,
    token: String,
    /// Each call's limit. Without one, a call Graph never answers left Sluse
    /// Admin's step turning in silence (L1, 2026-10-28).
    pub(crate) timeout: Duration,
}

/// Graph answers in seconds; a minute is a stall, not a slow tenant.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);

/// How many pages of a listing are followed. A tenant with more sites than
/// this is searched, not scrolled.
const MAX_PAGES: usize = 20;

impl Graph {
    /// `base` is `https://graph.microsoft.com/v1.0`, or a test's stand-in.
    pub fn new(http: &reqwest::Client, base: &str, token: String) -> Self {
        Graph { http: http.clone(), base: base.trim_end_matches('/').to_owned(), token, timeout: CALL_TIMEOUT }
    }

    pub(crate) async fn call(&self, method: reqwest::Method, path: String, body: Option<Value>) -> Result<Value, String> {
        let url = if path.starts_with("https://") || path.starts_with("http://") { path.clone() } else { format!("{}{path}", self.base) };
        let mut req = self.http.request(method.clone(), url).bearer_auth(&self.token).timeout(self.timeout);
        if let Some(b) = body {
            req = req.json(&b);
        }
        let stalled = |e: reqwest::Error| {
            if e.is_timeout() {
                format!("{method} {path}: Microsoft Graph did not answer within {} s. Check this PC's network (a VPN or a client such as Global Secure Access can hold Graph's traffic) and try again", self.timeout.as_secs())
            } else {
                format!("{method} {path}: {e}")
            }
        };
        let res = req.send().await.map_err(stalled)?;
        let status = res.status();
        let text = res.text().await.map_err(stalled)?;
        if !status.is_success() {
            return Err(format!("{method} {path}: {status}: {text}"));
        }
        Ok(if text.is_empty() { Value::Null } else { serde_json::from_str(&text).unwrap_or(Value::Null) })
    }

    pub(crate) async fn get(&self, path: String) -> Result<Value, String> {
        self.call(reqwest::Method::GET, path, None).await
    }

    /// Every `value` of a listing, following `@odata.nextLink`.
    pub(crate) async fn list(&self, path: String) -> Result<Vec<Value>, String> {
        let mut out = Vec::new();
        let mut next = Some(path);
        for _ in 0..MAX_PAGES {
            let Some(p) = next.take() else { break };
            let page = self.get(p).await?;
            out.extend(page["value"].as_array().cloned().unwrap_or_default());
            next = page["@odata.nextLink"].as_str().map(str::to_owned);
        }
        Ok(out)
    }

    /// The one application with this display name, if any. Two is an error:
    /// which one to repair is a person's call.
    pub(crate) async fn find_app(&self, name: &str) -> Result<Option<Value>, String> {
        let found = self.list(format!("/applications?$filter=displayName eq '{name}'")).await?;
        match found.len() {
            0 => Ok(None),
            1 => Ok(found.into_iter().next()),
            n => Err(format!(
                "{n} applications are named {name:?} (appId {}); remove the ones that are not Sluse's and run this again",
                found.iter().filter_map(|a| a["appId"].as_str()).collect::<Vec<_>>().join(", ")
            )),
        }
    }

    pub(crate) async fn app(&self, name: &str, created: &mut Vec<String>) -> Result<Value, String> {
        if let Some(a) = self.find_app(name).await? {
            return Ok(a);
        }
        created.push(format!("application {name:?}"));
        self.call(reqwest::Method::POST, "/applications".to_owned(), Some(json!({ "displayName": name, "signInAudience": "AzureADMyOrg" })))
            .await
    }

    /// The application's service principal, made if there is none.
    pub(crate) async fn service_principal(&self, app_id: &str, created: &mut Vec<String>) -> Result<Value, String> {
        let found = self.list(format!("/servicePrincipals?$filter=appId eq '{app_id}'")).await?;
        if let Some(sp) = found.into_iter().next() {
            return Ok(sp);
        }
        created.push(format!("service principal {app_id}"));
        self.call(reqwest::Method::POST, "/servicePrincipals".to_owned(), Some(json!({ "appId": app_id }))).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_call_graph_never_answers_ends_in_an_error_that_says_so() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Accepts and holds the connection, never answering.
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((s, _)) = listener.accept().await {
                held.push(s);
            }
        });
        let mut g = Graph::new(&reqwest::Client::new(), &format!("http://{addr}/v1.0"), "t".into());
        g.timeout = Duration::from_millis(200);
        let e = g.get("/applications".into()).await.unwrap_err();
        assert!(e.starts_with("GET /applications: Microsoft Graph did not answer within"), "{e}");
    }
}

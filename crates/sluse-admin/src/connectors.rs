// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The AI providers' own connectors, checked (D-069 point 1, D-071 slice 7).
//!
//! A provider's cloud connector, Microsoft 365 in Claude or SharePoint in
//! ChatGPT, reads company data from the provider's cloud with the user's
//! delegated grant: around the box and its proxy, where Sluse sees nothing.
//! `GUIDE.md` tells IT to turn them off. This reads, through Graph, whether
//! they are open in the tenant, and **warns; it refuses nothing**. The fix it
//! offers is Microsoft's documented block, the admin's choice: the provider's
//! service principal with sign-in disabled (`accountEnabled = false`), which
//! "prevents all tokens from being issued", made ahead of anyone's consent
//! when the app id is known.
//!
//! **What it can and cannot see.** Claude's two Microsoft 365 apps by their
//! published ids (`docs/research/2026-10-23-open-questions.md`). OpenAI
//! publishes no app id for its connectors' Entra app, so it is found by its
//! name once it is in the tenant, and cannot be blocked before. A user's own
//! custom connector on a personal Claude or ChatGPT account involves no
//! Entra app of the tenant's, and nothing here sees it.

use serde::Serialize;
use serde_json::{json, Value};

use crate::graph::Graph;

/// Anthropic's Microsoft 365 connector: its server and its client, both
/// needed (help.claude.com 12542951, retrieved 2026-10-23).
pub const CLAUDE_APPS: [(&str, &str); 2] = [
    ("07c030f6-5743-41b7-ba00-0a6e85f37c17", "M365 MCP Server for Claude"),
    ("08ad6f98-a4f8-4635-bb8d-f1a3044760f0", "M365 MCP Client for Claude"),
];

/// What OpenAI's connectors' app is called in a tenant: "ChatGPT", verified
/// publisher OpenAI, L.L.C. (help.openai.com 12143177). No app id published.
pub const OPENAI_NAMES: [&str; 2] = ["ChatGPT", "OpenAI"];

/// One provider app, as the tenant has it.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub provider: String,
    pub name: String,
    /// The app id, when known.
    pub app_id: Option<String>,
    /// The service principal; none when the app is not in the tenant.
    pub service_principal: Option<String>,
    /// Users may get tokens for it: no service principal (anyone may
    /// consent and make one), or one with sign-in enabled.
    pub open: bool,
    pub sign_in_enabled: Option<bool>,
    pub assignment_required: Option<bool>,
    /// The scopes an admin granted for everyone.
    pub tenant_scopes: Vec<String>,
    /// How many users consented for themselves.
    pub user_grants: usize,
    /// Sluse Admin can block it now: a known app id, or one in the tenant.
    pub can_block: bool,
}

/// The tenant's user-consent setting.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", tag = "state")]
pub enum UserConsent {
    /// Users cannot consent to apps themselves.
    Off,
    /// Users may consent to apps from verified publishers, for low-risk
    /// permissions.
    VerifiedLowRisk,
    /// Users may consent to any app.
    On,
    /// A policy Sluse does not name, as Entra lists it.
    Other { policies: Vec<String> },
    /// It could not be read (`Policy.Read.All`).
    Unknown { detail: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    pub findings: Vec<Finding>,
    pub user_consent: UserConsent,
}

/// Read the providers' apps and the user-consent setting.
pub async fn check(g: &Graph) -> Result<Report, String> {
    let mut findings = Vec::new();
    for (app_id, name) in CLAUDE_APPS {
        let sp = g.list(format!("/servicePrincipals?$filter=appId eq '{app_id}'")).await?.into_iter().next();
        findings.push(finding(g, "Anthropic", name, Some(app_id), sp.as_ref()).await?);
    }
    let mut seen = Vec::new();
    for prefix in OPENAI_NAMES {
        for sp in g.list(format!("/servicePrincipals?$filter=startswith(displayName,'{prefix}')")).await? {
            let id = sp["id"].as_str().unwrap_or_default().to_owned();
            let publisher = sp["verifiedPublisher"]["displayName"].as_str().unwrap_or_default();
            let named = sp["publisherName"].as_str().unwrap_or_default();
            // Only OpenAI's, not every app whose name starts so.
            if seen.contains(&id) || !(publisher.starts_with("OpenAI") || named.starts_with("OpenAI")) {
                continue;
            }
            seen.push(id);
            let name = sp["displayName"].as_str().unwrap_or("ChatGPT").to_owned();
            let app_id = sp["appId"].as_str().map(str::to_owned);
            findings.push(finding(g, "OpenAI", &name, app_id.as_deref(), Some(&sp)).await?);
        }
    }
    let user_consent = match g.call(reqwest::Method::GET, "/policies/authorizationPolicy".into(), None).await {
        Ok(p) => user_consent(&p),
        Err(e) => UserConsent::Unknown { detail: e },
    };
    Ok(Report { findings, user_consent })
}

async fn finding(g: &Graph, provider: &str, name: &str, app_id: Option<&str>, sp: Option<&Value>) -> Result<Finding, String> {
    let Some(sp) = sp else {
        return Ok(Finding {
            provider: provider.into(),
            name: name.into(),
            app_id: app_id.map(str::to_owned),
            service_principal: None,
            open: true,
            sign_in_enabled: None,
            assignment_required: None,
            tenant_scopes: Vec::new(),
            user_grants: 0,
            can_block: app_id.is_some(),
        });
    };
    let id = sp["id"].as_str().unwrap_or_default();
    let grants = g.list(format!("/oauth2PermissionGrants?$filter=clientId eq '{id}'")).await?;
    let mut tenant_scopes: Vec<String> = grants
        .iter()
        .filter(|x| x["consentType"] == "AllPrincipals")
        .flat_map(|x| x["scope"].as_str().unwrap_or_default().split(' ').filter(|s| !s.is_empty()).map(str::to_owned).collect::<Vec<_>>())
        .collect();
    tenant_scopes.sort();
    tenant_scopes.dedup();
    let enabled = sp["accountEnabled"].as_bool().unwrap_or(true);
    Ok(Finding {
        provider: provider.into(),
        name: name.into(),
        app_id: app_id.map(str::to_owned),
        service_principal: Some(id.to_owned()),
        open: enabled,
        sign_in_enabled: Some(enabled),
        assignment_required: sp["appRoleAssignmentRequired"].as_bool(),
        tenant_scopes,
        user_grants: grants.iter().filter(|x| x["consentType"] == "Principal").count(),
        can_block: enabled,
    })
}

/// What `permissionGrantPoliciesAssigned` says users may consent to.
pub fn user_consent(policy: &Value) -> UserConsent {
    let assigned: Vec<String> = policy["defaultUserRolePermissions"]["permissionGrantPoliciesAssigned"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|p| p.as_str())
        .filter(|p| p.starts_with("ManagePermissionGrantsForSelf."))
        .map(str::to_owned)
        .collect();
    match assigned.as_slice() {
        [] => UserConsent::Off,
        [one] if one.ends_with(".microsoft-user-default-legacy") => UserConsent::On,
        [one] if one.ends_with(".microsoft-user-default-low") => UserConsent::VerifiedLowRisk,
        _ => UserConsent::Other { policies: assigned },
    }
}

/// Turn sign-in off for a provider's app: its service principal disabled,
/// made disabled first when the tenant has none and the app id is known.
/// What was done, for the person to read.
pub async fn block(g: &Graph, app_id: Option<&str>, service_principal: Option<&str>) -> Result<String, String> {
    match (service_principal, app_id) {
        (Some(sp), _) => {
            g.call(reqwest::Method::PATCH, format!("/servicePrincipals/{sp}"), Some(json!({ "accountEnabled": false }))).await?;
            Ok(format!("sign-in turned off for service principal {sp}"))
        }
        (None, Some(app)) => {
            let made = g.call(reqwest::Method::POST, "/servicePrincipals".into(), Some(json!({ "appId": app, "accountEnabled": false }))).await?;
            Ok(format!("service principal {} made for {app}, with sign-in off", made["id"].as_str().unwrap_or("?")))
        }
        (None, None) => Err("nothing to block: neither an app id nor a service principal".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_user_consent_setting_is_read_from_the_assigned_policies() {
        let p = |v: Value| json!({ "defaultUserRolePermissions": { "permissionGrantPoliciesAssigned": v } });
        assert_eq!(user_consent(&p(json!([]))), UserConsent::Off);
        assert_eq!(user_consent(&p(json!(["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"]))), UserConsent::On);
        assert_eq!(user_consent(&p(json!(["ManagePermissionGrantsForSelf.microsoft-user-default-low"]))), UserConsent::VerifiedLowRisk);
        // Owners' consent policies are not users' consent.
        assert_eq!(user_consent(&p(json!(["ManagePermissionGrantsForOwnedResource.x"]))), UserConsent::Off);
        assert!(matches!(user_consent(&p(json!(["ManagePermissionGrantsForSelf.custom"]))), UserConsent::Other { .. }));
    }

    #[tokio::test]
    async fn the_providers_apps_are_found_their_grants_counted_and_blocked_on_request() {
        let (base, t) = crate::stand_in::start().await;
        let g = crate::stand_in::graph(&base);
        {
            let mut t = t.lock().unwrap();
            // The Claude server consented for the tenant; its client absent.
            t.sps.push(json!({ "id": "sp-claude", "appId": CLAUDE_APPS[0].0, "displayName": CLAUDE_APPS[0].1, "accountEnabled": true, "appRoleAssignmentRequired": false }));
            t.grants.push(json!({ "clientId": "sp-claude", "consentType": "AllPrincipals", "resourceId": "graph-sp", "scope": "Files.Read.All Sites.Read.All" }));
            // OpenAI's, two users' own consent; and an app merely named so.
            t.sps.push(json!({ "id": "sp-chatgpt", "appId": "a-chatgpt", "displayName": "ChatGPT", "verifiedPublisher": { "displayName": "OpenAI, L.L.C." }, "accountEnabled": true }));
            t.grants.push(json!({ "clientId": "sp-chatgpt", "consentType": "Principal", "scope": "Files.Read.All" }));
            t.grants.push(json!({ "clientId": "sp-chatgpt", "consentType": "Principal", "scope": "Files.Read.All" }));
            t.sps.push(json!({ "id": "sp-other", "appId": "a-other", "displayName": "ChatGPT helper", "publisherName": "Someone Else", "accountEnabled": true }));
            t.authorization_policy = Some(json!({ "defaultUserRolePermissions": { "permissionGrantPoliciesAssigned": ["ManagePermissionGrantsForSelf.microsoft-user-default-legacy"] } }));
        }
        let r = check(&g).await.unwrap();
        assert_eq!(r.user_consent, UserConsent::On);
        let names: Vec<&str> = r.findings.iter().map(|f| f.name.as_str()).collect();
        assert_eq!(names, [CLAUDE_APPS[0].1, CLAUDE_APPS[1].1, "ChatGPT"], "not the app merely named ChatGPT");
        let server = &r.findings[0];
        assert!(server.open && server.can_block);
        assert_eq!(server.tenant_scopes, ["Files.Read.All", "Sites.Read.All"]);
        let client = &r.findings[1];
        assert!(client.open && client.service_principal.is_none() && client.can_block, "absent: anyone could consent and make it");
        assert_eq!(r.findings[2].user_grants, 2);

        // Blocked: the present one disabled, the absent one made disabled.
        block(&g, server.app_id.as_deref(), server.service_principal.as_deref()).await.unwrap();
        block(&g, client.app_id.as_deref(), None).await.unwrap();
        let r = check(&g).await.unwrap();
        assert!(!r.findings[0].open && r.findings[0].sign_in_enabled == Some(false) && !r.findings[0].can_block);
        assert!(!r.findings[1].open && r.findings[1].service_principal.is_some());
    }

    #[tokio::test]
    async fn an_unreadable_consent_setting_is_said_not_guessed() {
        let (base, _) = crate::stand_in::start().await;
        let r = check(&crate::stand_in::graph(&base)).await.unwrap();
        assert!(matches!(r.user_consent, UserConsent::Unknown { .. }), "{:?}", r.user_consent);
    }
}

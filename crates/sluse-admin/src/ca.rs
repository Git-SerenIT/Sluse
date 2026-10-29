// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Conditional Access behind a Microsoft sign-in in the box (D-075 slice 6).
//!
//! In a sign-in window something in the box could carry the person's
//! Microsoft session out; Entra is what refuses it elsewhere. This reads the
//! tenant's policies and says whether two are there: a compliant device
//! required for company data (Office 365, or Sluse Gate's app, or all
//! apps), and device-code sign-in blocked. **A reading, not a proof:** the
//! policies' users and exclusions are the tenant's, and are named, not
//! evaluated. Warnings only; the admin decides.

use serde::Serialize;
use serde_json::Value;

use crate::graph::Graph;

/// What the tenant's Conditional Access says, as far as D-075 needs.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
// `rename_all` names the variants; the fields need `rename_all_fields`, or the
// page reads `compliantDevice` from a `compliant_device` (since 0.1.9; found
// on jok's tenant, 2026-10-29).
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase", tag = "state")]
pub enum Report {
    /// The policies were read.
    Read {
        /// Enabled policies requiring a compliant (or joined) device for
        /// company data, by name.
        compliant_device: Vec<String>,
        /// The same, in report-only mode: they enforce nothing.
        report_only: Vec<String>,
        /// Enabled policies blocking device-code sign-in, by name.
        device_code_blocked: Vec<String>,
    },
    /// No Conditional Access: the tenant has no Entra ID P1, or the sign-in
    /// lacks `Policy.Read.All`. Entra's words in `detail`.
    Unreadable { detail: String },
}

/// Office 365's group of apps in Conditional Access.
const OFFICE_365: &str = "Office365";

/// Read the policies; `gate_app` is Sluse Gate's app id.
pub async fn check(g: &Graph, gate_app: Option<&str>) -> Report {
    let policies = match g.list("/identity/conditionalAccess/policies".into()).await {
        Ok(p) => p,
        Err(detail) => return Report::Unreadable { detail },
    };
    let (mut compliant_device, mut report_only, mut device_code_blocked) = (Vec::new(), Vec::new(), Vec::new());
    for p in &policies {
        let name = p["displayName"].as_str().unwrap_or("(no name)").to_owned();
        let state = p["state"].as_str().unwrap_or_default();
        let grants: Vec<&str> = p["grantControls"]["builtInControls"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        let apps: Vec<&str> =
            p["conditions"]["applications"]["includeApplications"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        let company_data = apps.iter().any(|a| *a == "All" || *a == OFFICE_365 || Some(*a) == gate_app);
        if company_data && grants.iter().any(|c| *c == "compliantDevice" || *c == "domainJoinedDevice") {
            match state {
                "enabled" => compliant_device.push(name.clone()),
                "enabledForReportingButNotEnforced" => report_only.push(name.clone()),
                _ => {}
            }
        }
        let flows: Vec<&str> = p["conditions"]["authenticationFlows"]["transferMethods"]
            .as_str()
            .map(|s| s.split(',').map(str::trim).collect())
            .unwrap_or_default();
        if state == "enabled" && flows.contains(&"deviceCodeFlow") && grants.contains(&"block") {
            device_code_blocked.push(name);
        }
    }
    Report::Read { compliant_device, report_only, device_code_blocked }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn the_two_policies_are_found_by_what_they_do_and_report_only_is_not_enforcing() {
        let (base, t) = crate::stand_in::start().await;
        let g = crate::stand_in::graph(&base);
        assert!(matches!(check(&g, Some("gate")).await, Report::Unreadable { .. }), "no P1: 403");
        t.lock().unwrap().ca_policies = Some(vec![
            json!({ "displayName": "Compliant for M365", "state": "enabled",
                    "conditions": { "applications": { "includeApplications": ["Office365"] } },
                    "grantControls": { "builtInControls": ["mfa", "compliantDevice"] } }),
            json!({ "displayName": "Trial", "state": "enabledForReportingButNotEnforced",
                    "conditions": { "applications": { "includeApplications": ["gate"] } },
                    "grantControls": { "builtInControls": ["compliantDevice"] } }),
            json!({ "displayName": "MFA only", "state": "enabled",
                    "conditions": { "applications": { "includeApplications": ["All"] } },
                    "grantControls": { "builtInControls": ["mfa"] } }),
            json!({ "displayName": "No device code", "state": "enabled",
                    "conditions": { "applications": { "includeApplications": ["All"] }, "authenticationFlows": { "transferMethods": "deviceCodeFlow,authenticationTransfer" } },
                    "grantControls": { "builtInControls": ["block"] } }),
        ]);
        assert_eq!(
            check(&g, Some("gate")).await,
            Report::Read {
                compliant_device: vec!["Compliant for M365".into()],
                report_only: vec!["Trial".into()],
                device_code_blocked: vec!["No device code".into()],
            }
        );
        t.lock().unwrap().ca_policies = Some(vec![]);
        assert_eq!(check(&g, None).await, Report::Read { compliant_device: vec![], report_only: vec![], device_code_blocked: vec![] });
    }

    /// The shape `ui/shell/src/admin.js`'s `drawCa()` reads.
    #[test]
    fn the_report_is_what_the_page_reads() {
        let r = Report::Read { compliant_device: vec!["a".into()], report_only: vec![], device_code_blocked: vec![] };
        assert_eq!(serde_json::to_value(&r).unwrap(), serde_json::json!({ "state": "read", "compliantDevice": ["a"], "reportOnly": [], "deviceCodeBlocked": [] }));
        let u = Report::Unreadable { detail: "no P1".into() };
        assert_eq!(serde_json::to_value(&u).unwrap(), serde_json::json!({ "state": "unreadable", "detail": "no P1" }));
    }
}

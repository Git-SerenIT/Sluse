// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Who may sign in to Sluse (D-038 point 4): Entra's "Assignment required"
//! on Sluse's service principal, and the group the admin picks assigned to
//! it, so Entra decides, not the box.
//!
//! The group here is people. The Intune assignment (slice 5) is the devices,
//! and documented as a device group: two different groups, usually.

use serde_json::json;

use crate::graph::Graph;

/// The default app role: plain access, for an app that defines none.
const DEFAULT_ACCESS: &str = "00000000-0000-0000-0000-000000000000";

/// What assigning did, and what the admin should know.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Assigned {
    pub changed: Vec<String>,
    pub warnings: Vec<String>,
}

/// Turn "Assignment required" on for the service principal `sp` and assign
/// `group` to it, once. Running it again changes nothing.
pub async fn require(g: &Graph, sp: &str, group: &str) -> Result<Assigned, String> {
    let mut out = Assigned::default();
    let principal = g.get(format!("/servicePrincipals/{sp}?$select=id,appRoleAssignmentRequired")).await?;
    if principal["appRoleAssignmentRequired"] != true {
        g.call(reqwest::Method::PATCH, format!("/servicePrincipals/{sp}"), Some(json!({ "appRoleAssignmentRequired": true })))
            .await?;
        out.changed.push("Turned on Assignment required: only the groups assigned to Sluse's app sign in".into());
    }
    let grp = g.get(format!("/groups/{group}?$select=id,displayName")).await?;
    let name = grp["displayName"].as_str().unwrap_or(group).to_owned();
    // Warnings, not friction (D-038): a group with devices in it is allowed,
    // and the admin is told what it does.
    let devices = g.get(format!("/groups/{group}/members/microsoft.graph.device?$select=id&$top=1")).await?;
    if devices["value"].as_array().is_some_and(|d| !d.is_empty()) {
        out.warnings.push(format!(
            "{name} has devices in it. Entra's assignment admits people, not devices: only the users in {name} can sign in. \
             The devices are Intune's assignment, at Publish."
        ));
    }
    let assigned = g.list(format!("/servicePrincipals/{sp}/appRoleAssignedTo")).await?;
    if !assigned.iter().any(|a| a["principalId"] == group) {
        g.call(
            reqwest::Method::POST,
            format!("/servicePrincipals/{sp}/appRoleAssignedTo"),
            Some(json!({ "principalId": group, "resourceId": sp, "appRoleId": DEFAULT_ACCESS })),
        )
        .await?;
        out.changed.push(format!("{name} may sign in"));
    }
    Ok(out)
}

/// A group assigned to Sluse's app, as Entra holds it (Q46).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Group {
    /// The assignment's id, which [`remove`] takes.
    pub id: String,
    pub group: String,
    pub name: String,
    /// When it was assigned, as Entra says it.
    pub created: Option<String>,
}

/// The groups assigned to the service principal `sp`. Users assigned one
/// by one are not listed: Sluse Admin assigns groups.
pub async fn assigned(g: &Graph, sp: &str) -> Result<Vec<Group>, String> {
    Ok(g.list(format!("/servicePrincipals/{sp}/appRoleAssignedTo"))
        .await?
        .iter()
        .filter(|a| a["principalType"] == "Group")
        .filter_map(|a| {
            Some(Group {
                id: a["id"].as_str()?.to_owned(),
                group: a["principalId"].as_str()?.to_owned(),
                name: a["principalDisplayName"].as_str().unwrap_or_default().to_owned(),
                created: a["createdDateTime"].as_str().map(str::to_owned),
            })
        })
        .collect())
}

/// Remove one assignment. Removing the last is allowed (warnings, not
/// friction): with Assignment required on, no one signs in afterwards.
pub async fn remove(g: &Graph, sp: &str, id: &str) -> Result<(), String> {
    g.call(reqwest::Method::DELETE, format!("/servicePrincipals/{sp}/appRoleAssignedTo/{id}"), None).await.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn assignment_is_required_once_and_a_group_with_devices_is_warned_about() {
        let (base, t) = crate::stand_in::start().await;
        {
            let mut t = t.lock().unwrap();
            t.sps.push(json!({ "id": "sp-1", "appId": "a", "appRoleAssignmentRequired": false }));
            t.groups.push(json!({ "id": "g-1", "displayName": "Sluse pilots", "devices": 0 }));
            t.groups.push(json!({ "id": "g-2", "displayName": "Pilot laptops", "devices": 3 }));
        }
        let g = crate::stand_in::graph(&base);
        let first = require(&g, "sp-1", "g-1").await.unwrap();
        assert_eq!(first.changed.len(), 2, "{first:?}");
        assert!(first.warnings.is_empty());
        assert_eq!(t.lock().unwrap().sps[0]["appRoleAssignmentRequired"], true);
        assert_eq!(require(&g, "sp-1", "g-1").await.unwrap(), Assigned::default(), "again: nothing");

        let devices = require(&g, "sp-1", "g-2").await.unwrap();
        assert_eq!(devices.changed.len(), 1);
        assert!(devices.warnings[0].contains("Pilot laptops"), "{devices:?}");
        assert_eq!(t.lock().unwrap().assigned["sp-1"].len(), 2);

        let listed = assigned(&g, "sp-1").await.unwrap();
        assert_eq!(listed.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(), ["Sluse pilots", "Pilot laptops"]);
        remove(&g, "sp-1", &listed[0].id).await.unwrap();
        assert_eq!(assigned(&g, "sp-1").await.unwrap(), listed[1..]);
    }
}

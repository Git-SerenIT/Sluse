// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Whether admin consent covers Sluse's permissions (D-037), so the UI can
//! wait for it. The admin grants it in the portal: the `/adminconsent` link
//! failed on L1 (2026-09-30), and the portal shows each permission's state.

use std::time::Duration;

use crate::graph::Graph;
use crate::setup::GATE_GRAPH_SCOPES;

/// The scopes of [`GATE_GRAPH_SCOPES`] that no tenant-wide grant to the
/// service principal `sp` covers yet. Empty is consented.
pub async fn missing(g: &Graph, sp: &str) -> Result<Vec<String>, String> {
    let grants = g
        .list(format!("/oauth2PermissionGrants?$filter=clientId eq '{sp}' and consentType eq 'AllPrincipals'"))
        .await?;
    let granted: Vec<&str> = grants.iter().filter_map(|g| g["scope"].as_str()).flat_map(|s| s.split(' ')).collect();
    Ok(GATE_GRAPH_SCOPES.iter().filter(|s| !granted.contains(s)).map(|s| s.to_string()).collect())
}

/// Ask every `every` until consent covers everything, at most `tries` times.
/// The scopes still missing when it gives up.
pub async fn wait(g: &Graph, sp: &str, every: Duration, tries: u32) -> Result<Vec<String>, String> {
    let mut left = missing(g, sp).await?;
    for _ in 1..tries {
        if left.is_empty() {
            break;
        }
        tokio::time::sleep(every).await;
        left = missing(g, sp).await?;
    }
    Ok(left)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn consent_is_whole_or_it_names_what_is_missing() {
        let (base, t) = crate::stand_in::start().await;
        let g = crate::stand_in::graph(&base);
        assert_eq!(missing(&g, "sp-1").await.unwrap().len(), 5);
        // A user's own consent is not the tenant's.
        t.lock().unwrap().grants.push(json!({ "clientId": "sp-1", "consentType": "Principal", "scope": "Files.Read.All Sites.Read.All offline_access openid profile" }));
        assert_eq!(missing(&g, "sp-1").await.unwrap().len(), 5);
        t.lock().unwrap().grants.push(json!({ "clientId": "sp-1", "consentType": "AllPrincipals", "scope": " Files.Read.All openid profile offline_access" }));
        assert_eq!(missing(&g, "sp-1").await.unwrap(), ["Sites.Read.All"]);
        t.lock().unwrap().grants.push(json!({ "clientId": "sp-1", "consentType": "AllPrincipals", "scope": "Sites.Read.All" }));
        assert!(wait(&g, "sp-1", Duration::from_millis(1), 3).await.unwrap().is_empty());
    }
}

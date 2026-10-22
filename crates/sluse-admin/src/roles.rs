// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Which of setup's steps the signed-in account may do (D-037), so the UI
//! says before it starts which steps need someone else.
//!
//! By Entra's built-in roles, matched on their template ids, which are the
//! same in every tenant. Which role may do what is Microsoft's documentation
//! as read on 2026-10-02, **not measured here**: the test run checks it.

use crate::graph::Graph;

pub const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";
pub const APPLICATION_ADMINISTRATOR: &str = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3";
pub const CLOUD_APPLICATION_ADMINISTRATOR: &str = "158c047a-c907-4556-b7ef-446551a6b5f7";
pub const PRIVILEGED_ROLE_ADMINISTRATOR: &str = "e8611ab8-c189-46e8-94e1-60213ab1f814";
pub const INTUNE_ADMINISTRATOR: &str = "3a2c62db-5318-420d-8d74-23affee5d9d5";

/// What the account may do, and the roles it holds by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Roles {
    pub names: Vec<String>,
    /// Make and repair Sluse's registration, and assign its group.
    pub register: bool,
    /// Grant tenant-wide consent for Sluse's delegated Graph permissions.
    pub consent: bool,
    /// Publish to Intune through Graph (D-037 point 2).
    pub publish: bool,
}

impl Roles {
    pub fn from_template_ids(ids: &[&str], names: Vec<String>) -> Self {
        let has = |r: &[&str]| ids.iter().any(|i| r.contains(i));
        let apps = [GLOBAL_ADMINISTRATOR, APPLICATION_ADMINISTRATOR, CLOUD_APPLICATION_ADMINISTRATOR];
        Roles {
            names,
            register: has(&apps),
            consent: has(&[GLOBAL_ADMINISTRATOR, APPLICATION_ADMINISTRATOR, CLOUD_APPLICATION_ADMINISTRATOR, PRIVILEGED_ROLE_ADMINISTRATOR]),
            publish: has(&[GLOBAL_ADMINISTRATOR, INTUNE_ADMINISTRATOR]),
        }
    }

    /// One line per step this account cannot do, saying who can.
    pub fn others_needed(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.register {
            out.push("Making Sluse's app registration needs an Application Administrator, a Cloud Application Administrator or a Global Administrator.".into());
        }
        if !self.consent {
            out.push("Granting admin consent needs one of those roles, or a Privileged Role Administrator.".into());
        }
        if !self.publish {
            out.push("Publishing straight to Intune needs an Intune Administrator or a Global Administrator; the .intunewin file does not.".into());
        }
        out
    }
}

/// The signed-in account's directory roles.
pub async fn of_me(g: &Graph) -> Result<Roles, String> {
    let roles = g.list("/me/memberOf/microsoft.graph.directoryRole?$select=roleTemplateId,displayName".into()).await?;
    let ids: Vec<&str> = roles.iter().filter_map(|r| r["roleTemplateId"].as_str()).collect();
    let names = roles.iter().filter_map(|r| r["displayName"].as_str().map(str::to_owned)).collect();
    Ok(Roles::from_template_ids(&ids, names))
}

/// Whom Sluse Admin acts as (Q43): the account, and the organisation's
/// name, `None` when Graph would not say it (Q80): the top bar then names
/// the tenant by id.
pub async fn whoami(g: &Graph) -> Result<(String, Option<String>), String> {
    let me = g.get("/me?$select=userPrincipalName".into()).await?;
    let account = me["userPrincipalName"].as_str().unwrap_or_default().to_owned();
    let org = g.get("/organization?$select=displayName".into()).await.ok();
    let name = org.and_then(|o| o["value"][0]["displayName"].as_str().map(str::to_owned));
    Ok((account, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn an_intune_administrator_is_told_who_else_is_needed() {
        let (base, t) = crate::stand_in::start().await;
        t.lock().unwrap().roles = vec![INTUNE_ADMINISTRATOR.into()];
        let r = of_me(&crate::stand_in::graph(&base)).await.unwrap();
        assert_eq!((r.register, r.consent, r.publish), (false, false, true));
        assert_eq!(r.others_needed().len(), 2);
        let who = whoami(&crate::stand_in::graph(&base)).await.unwrap();
        assert_eq!(who, ("admin@contoso.dk".into(), Some("Contoso".into())));

        let ga = Roles::from_template_ids(&[GLOBAL_ADMINISTRATOR], vec![]);
        assert!(ga.register && ga.consent && ga.publish && ga.others_needed().is_empty());
        let pra = Roles::from_template_ids(&[PRIVILEGED_ROLE_ADMINISTRATOR], vec![]);
        assert_eq!((pra.register, pra.consent, pra.publish), (false, true, false));
    }
}

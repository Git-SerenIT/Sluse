// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Setup's own sign-in (D-037): interactive, an authorization code with
//! PKCE, in place of the CLI's device code. The window that shows Entra's
//! page is the setup UI's (slice 6), which catches the redirect the way the
//! box's shell does; this builds the request and redeems the code.
//!
//! As Microsoft's own public client for Graph, "Microsoft Graph Command Line
//! Tools", whose registered redirects include `http://localhost`. A tenant
//! that has blocked it passes its own client id.

use serde_json::Value;
use sluse_proto::pipe::SignInRequest;
use sluse_proto::SignInView;

/// Where the code comes back. Never loaded: the window catches it.
pub const REDIRECT: &str = "http://localhost";

/// What setup does as the admin: the registration, the assignment, the
/// directory's roles, the sites for the scope picker, and Intune's apps; and
/// the tenant's user-consent setting, for the providers' connectors (D-071
/// slice 7), which `Directory.Read.All` does not read.
pub const SCOPES: &str = "https://graph.microsoft.com/Application.ReadWrite.All \
https://graph.microsoft.com/AppRoleAssignment.ReadWrite.All \
https://graph.microsoft.com/Directory.Read.All \
https://graph.microsoft.com/Policy.Read.All \
https://graph.microsoft.com/Sites.Read.All \
https://graph.microsoft.com/DeviceManagementApps.ReadWrite.All offline_access openid profile";

/// The request and where it goes. `login` is `https://login.microsoftonline.com`.
pub fn request(login: &str, client_id: &str) -> Result<(SignInRequest, SignInView), String> {
    let view = SignInView {
        authority: format!("{}/organizations", login.trim_end_matches('/')),
        client_id: client_id.to_owned(),
        scope: SCOPES.to_owned(),
    };
    Ok((SignInRequest::with_redirect(REDIRECT)?, view))
}

/// The admin's Graph token for a code the window caught.
pub async fn redeem(http: &reqwest::Client, view: &SignInView, req: &SignInRequest, code: &str) -> Result<String, String> {
    let t: Value = http
        .post(format!("{}/oauth2/v2.0/token", view.authority))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", view.client_id.as_str()),
            ("code", code),
            ("redirect_uri", req.redirect.as_str()),
            ("code_verifier", req.verifier.expose()),
            ("scope", view.scope.as_str()),
        ])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    t["access_token"].as_str().map(str::to_owned).ok_or_else(|| {
        format!("the sign-in did not complete: {}", t["error_description"].as_str().unwrap_or("?").lines().next().unwrap_or("?"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluse_proto::pipe::Caught;

    #[tokio::test]
    async fn a_caught_code_is_redeemed_with_its_verifier_once() {
        let (base, t) = crate::stand_in::start().await;
        let (req, view) = request(&base, crate::setup::GRAPH_CLI_CLIENT).unwrap();
        let url = req.authorize_url(&view, false);
        assert!(url.contains("redirect_uri=http%3A%2F%2Flocalhost&"), "{url}");
        let back = format!("http://localhost/?code=c1&state={}", req.state);
        assert_eq!(req.caught(&back), Some(Caught::Code("c1".into())));
        t.lock().unwrap().codes.insert("c1".into(), req.verifier.expose().to_owned());
        let http = reqwest::Client::new();
        let token = redeem(&http, &view, &req, "c1").await.unwrap();
        assert_eq!(crate::setup::tenant_of(&token).unwrap(), crate::stand_in::TENANT);
        assert!(redeem(&http, &view, &req, "c1").await.unwrap_err().contains("AADSTS70008"), "used once");
    }
}

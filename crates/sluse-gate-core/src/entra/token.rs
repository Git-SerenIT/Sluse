// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The host's sign-in, redeemed (D-036), and the tokens it yields.
//!
//! The shell caught an authorization code on the host and the service handed
//! it over. This redeems it at Entra's token endpoint as a **public client**:
//! the client id, the PKCE verifier, no secret and no assertion. What comes
//! back is checked before it binds anything, in order:
//!
//! 1. **The ID token's signature**, against a key Entra publishes for the
//!    configured tenant, looked up by `kid`. RS256 only: accepting a second
//!    algorithm is how `alg` confusion starts.
//! 2. **Expiry and not-before**, with a minute of leeway for clock skew.
//! 3. **The issuer**, `https://login.microsoftonline.com/<tid>/v2.0`, for this
//!    tenant only, and `tid` again: two checks that must agree.
//! 4. **The audience**: Sluse's client id. An ID token for another app is not
//!    a sign-in to Sluse.
//! 5. **The nonce** the shell put in the request, so a code caught for another
//!    sign-in cannot be replayed into this one.
//!
//! The Graph access token beside it is not Gate Core's to validate: it is
//! Graph's audience, and Graph checks it on every call.
//!
//! **One refresh token, an access token per scope** (D-071 slice 2). The
//! sign-in yields Graph's; another resource's, an MCP server's, is asked for
//! with the same refresh token and the resource's delegated scope, as the
//! same person, and held beside Graph's. Entra is asked by `scope` alone,
//! without RFC 8707's `resource`: its v2 endpoint takes the resource from the
//! scope, and refuses a `resource` that is not exactly the app's ID URI
//! (AADSTS9010010; `docs/research/2026-10-26-mcp-servers-entra.md`).
//!
//! What comes out is an [`Identity`]: the object id, which is what the box is
//! bound on because it never changes, and a UPN for the record, which a
//! person can read.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use sluse_proto::pipe::HostSignIn;
use sluse_proto::SluseError;

use super::{unavailable, Entra};

/// Renew this long before an access token expires.
const RENEW_BEFORE: Duration = Duration::from_secs(300);

/// Graph with the consented delegated permissions: the scope the sign-in's
/// access token is for, and the key it is held under.
pub const GRAPH_SCOPE: &str = "https://graph.microsoft.com/.default";

/// What a source is called on a sign-in's records and errors: there is none.
const SIGN_IN: &str = "entra";

/// How often a `kid` the cache does not know may trigger a refetch. Entra rolls
/// keys rarely and announces them ahead of use, so a miss is normally a forged
/// or foreign token — and a forged token must not be a way to make Gate Core
/// hammer the keys endpoint.
const REFETCH_AFTER: Duration = Duration::from_secs(300);

/// The person a validated token names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Entra's object id for the user. Stable across renames; what a session is
    /// bound on.
    pub oid: String,
    /// The sign-in name, for the record.
    pub upn: String,
    pub tid: String,
    /// The user's on-premises SID, when they are synced from AD and Sluse's
    /// registration asks for the optional claim (D-057): what a domain
    /// account's Windows logon is compared with.
    pub onprem_sid: Option<String>,
}

/// The claims this module reads. Everything else in the token is ignored.
#[derive(Debug, Deserialize)]
struct Claims {
    tid: Option<String>,
    oid: Option<String>,
    nonce: Option<String>,
    preferred_username: Option<String>,
    upn: Option<String>,
    onprem_sid: Option<String>,
}

/// One access token, for one scope.
pub struct Access {
    pub(crate) token: String,
    pub(crate) expires_at: Instant,
}

impl Access {
    pub(crate) fn fresh(&self) -> bool {
        self.expires_at > Instant::now() + RENEW_BEFORE
    }
}

/// What Entra answered: an access token, and a refresh token when it sent one.
pub struct Granted {
    pub(crate) access: Access,
    pub(crate) refresh: Option<String>,
}

/// The tokens held for the bound user: one refresh token, and an access token
/// for each scope asked for so far. Memory only.
pub struct Held {
    pub(crate) refresh: Option<String>,
    pub(crate) access: std::collections::HashMap<String, Access>,
}

impl Held {
    /// From a sign-in's answer, whose access token is Graph's.
    pub(crate) fn signed_in(g: Granted) -> Self {
        Held { refresh: g.refresh, access: [(GRAPH_SCOPE.to_owned(), g.access)].into() }
    }

    /// Keep what a renewal for `scope` answered. Entra may rotate the refresh
    /// token; the newest is kept, and one it did not send keeps the old.
    pub(crate) fn take(&mut self, scope: &str, g: Granted) -> String {
        if g.refresh.is_some() {
            self.refresh = g.refresh;
        }
        let token = g.access.token.clone();
        self.access.insert(scope.to_owned(), g.access);
        token
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    expires_in: u64,
}

#[derive(Deserialize, Default)]
struct TokenErrorBody {
    #[serde(default)]
    error: String,
    #[serde(default)]
    error_description: String,
}

/// Entra's signing keys for the tenant, fetched on first use.
#[derive(Default)]
pub struct KeyCache {
    inner: RwLock<Option<(JwkSet, Instant)>>,
}

impl Entra {
    /// Redeem the host's code, and check the ID token that comes with it.
    pub(crate) async fn redeem_code(&self, s: &HostSignIn) -> Result<(Identity, Granted), SluseError> {
        let (t, id_token) = self
            .token_request(&[
                ("grant_type", "authorization_code"),
                ("client_id", &self.client_id),
                ("code", s.code.expose()),
                ("redirect_uri", &s.redirect_uri),
                ("code_verifier", s.verifier.expose()),
                ("scope", sluse_proto::wire::HOST_SCOPE),
            ], SIGN_IN)
            .await?;
        let id_token = id_token.ok_or_else(|| SluseError::TokenRejected {
            detail: "Entra returned no ID token; the sign-in did not ask for openid".into(),
        })?;
        let who = self.validate_id_token(&id_token, &s.nonce).await?;
        Ok((who, t))
    }

    /// An access token for `scope`, with the refresh token the sign-in
    /// returned. No user involved.
    pub async fn renew(&self, refresh: &str, scope: &str, source: &str) -> Result<Granted, SluseError> {
        let scope = format!("{scope} offline_access");
        self.token_request(&[
            ("grant_type", "refresh_token"),
            ("client_id", &self.client_id),
            ("refresh_token", refresh),
            ("scope", &scope),
        ], source)
        .await
        .map(|(t, _)| t)
    }

    async fn token_request(&self, form: &[(&str, &str)], source: &str) -> Result<(Granted, Option<String>), SluseError> {
        let res = self
            .http
            .post(self.token_endpoint())
            .form(form)
            .send()
            .await
            .map_err(|e| unavailable(source, format!("Entra could not be reached: {}", super::cause(&e))))?;
        let status = res.status();
        if status.is_success() {
            let t: TokenResponse = res
                .json()
                .await
                .map_err(|e| unavailable(source, format!("Entra's token response could not be read: {}", super::cause(&e))))?;
            let held = Granted {
                access: Access { token: t.access_token, expires_at: Instant::now() + Duration::from_secs(t.expires_in) },
                refresh: t.refresh_token,
            };
            return Ok((held, t.id_token));
        }
        let body: TokenErrorBody = res.json().await.unwrap_or_default();
        // The first line of Entra's description carries the AADSTS code, which
        // is the part a person searches for. The rest is a trace id and a
        // timestamp.
        let detail = format!("{}: {}", body.error, body.error_description.lines().next().unwrap_or_default());
        Err(match body.error.as_str() {
            // The user has to do something: sign in again, pass MFA, consent,
            // or use a compliant device. Gate Core cannot answer any of
            // those for them and must not try.
            "invalid_grant" | "interaction_required" | "consent_required" | "login_required" => {
                SluseError::SignInRequired { detail }
            }
            // The registration is wrong. A fault in the deployment, not a
            // decision about this request.
            _ => unavailable(source, format!("Entra refused the token request ({status}): {detail}")),
        })
    }

    /// Check an ID token from the token endpoint (the module's list).
    pub async fn validate_id_token(&self, token: &str, nonce: &str) -> Result<Identity, SluseError> {
        let rejected = |detail: String| SluseError::TokenRejected { detail };

        let header = jsonwebtoken::decode_header(token).map_err(|e| rejected(format!("not a JWT: {e}")))?;
        if header.alg != Algorithm::RS256 {
            return Err(rejected(format!("signed with {:?}; only RS256 is accepted", header.alg)));
        }
        let kid = header.kid.ok_or_else(|| rejected("the token names no signing key".into()))?;
        let key = self.key(&kid, SIGN_IN).await?;

        let mut v = Validation::new(Algorithm::RS256);
        v.leeway = 60;
        v.validate_nbf = true;
        v.set_required_spec_claims(&["exp", "iss", "aud"]);
        v.set_issuer(&[format!("https://login.microsoftonline.com/{}/v2.0", self.tenant)]);
        v.set_audience(std::slice::from_ref(&self.client_id));

        let c = jsonwebtoken::decode::<Claims>(token, &key, &v)
            .map_err(|e| match e.kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => {
                    SluseError::SignInRequired { detail: "the sign-in has expired".into() }
                }
                _ => rejected(e.to_string()),
            })?
            .claims;

        let tid = c.tid.unwrap_or_default().to_ascii_lowercase();
        if tid != self.tenant {
            return Err(rejected(format!("issued for tenant \"{tid}\", not this one")));
        }
        if c.nonce.as_deref() != Some(nonce) {
            return Err(rejected("the ID token's nonce is not this sign-in's".into()));
        }
        let oid = c.oid.filter(|o| !o.is_empty()).ok_or_else(|| rejected("no oid claim".into()))?;
        let upn = c
            .preferred_username
            .or(c.upn)
            .filter(|u| !u.is_empty())
            // Named for what it is rather than left blank: a record that says
            // `entra:` and nothing else reads as a missing field, not a person.
            .unwrap_or_else(|| format!("oid:{oid}"));
        Ok(Identity { oid, upn, tid, onprem_sid: c.onprem_sid.filter(|s| !s.is_empty()) })
    }

    /// The decoding key for `kid`, refetching the key set once if it is not
    /// known and the last fetch is old enough.
    async fn key(&self, kid: &str, source: &str) -> Result<DecodingKey, SluseError> {
        let (known, stale) = {
            let guard = self.keys.inner.read().unwrap_or_else(|p| p.into_inner());
            match guard.as_ref() {
                Some((set, at)) => (set.find(kid).cloned(), at.elapsed() > REFETCH_AFTER),
                None => (None, true),
            }
        };
        let jwk = match known {
            Some(jwk) => jwk,
            None if stale => {
                let set = self.fetch_keys(source).await?;
                let found = set.find(kid).cloned();
                *self.keys.inner.write().unwrap_or_else(|p| p.into_inner()) =
                    Some((set, Instant::now()));
                found.ok_or_else(|| SluseError::TokenRejected {
                    detail: format!("signing key \"{kid}\" is not one Entra publishes for this tenant"),
                })?
            }
            None => {
                return Err(SluseError::TokenRejected {
                    detail: format!("signing key \"{kid}\" is not one Entra publishes for this tenant"),
                })
            }
        };
        DecodingKey::from_jwk(&jwk)
            .map_err(|e| unavailable(source, format!("Entra published a key this build cannot use: {e}")))
    }

    async fn fetch_keys(&self, source: &str) -> Result<JwkSet, SluseError> {
        let res = self
            .http
            .get(self.keys_endpoint())
            .send()
            .await
            .map_err(|e| unavailable(source, format!("Entra's signing keys could not be fetched: {}", super::cause(&e))))?;
        if !res.status().is_success() {
            return Err(unavailable(
                source,
                format!("Entra's keys endpoint answered {}", res.status()),
            ));
        }
        res.json::<JwkSet>()
            .await
            .map_err(|e| unavailable(source, format!("Entra's key set could not be read: {}", super::cause(&e))))
    }
}

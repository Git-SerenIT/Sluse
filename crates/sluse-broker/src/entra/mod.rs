// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Acting as the signed-in user against Microsoft 365. **M7, D-036.**
//!
//! Two parts, one per file, in the order a sign-in meets them:
//!
//! 1. [`token`]: the host's sign-in redeemed. The shell caught an
//!    authorization code on the host (D-036); the service hands it over on
//!    the broker's stdin; this redeems it as a **public client**, with no app
//!    credential anywhere, and checks the ID token it gets back — signature
//!    against Entra's published keys, tenant, audience, nonce. The user's
//!    Graph and refresh tokens stay in this process, in memory, for as long
//!    as the box is bound (invariant 3: no durable credential in the box).
//! 2. [`graph`]: the drive, the item, the children, the download URL.
//!
//! ## The box is bound to one person (D-022)
//!
//! The first sign-in binds the box: from then on every record the broker
//! writes, on every session, names that user as `entra:<upn>`, and a sign-in
//! for anyone else is refused as [`SluseError::TokenRejected`]. Requests from
//! the box carry no token at all: the broker renews the Graph token with the
//! refresh token it holds, as SYSTEM, which is what keeps "Leave it running"
//! working (D-034 point 5). Whether Conditional Access is re-checked on those
//! renewals is D-036's unmeasured consequence.
//!
//! **Unbinding is the user's** ([`Entra::unbind`], the console's sign-out), or
//! happens when the broker stops at box close. Never on a timer (D-022,
//! D-019 point 5). A refresh token that dies leaves the binding in place and
//! answers [`SluseError::SignInRequired`]; the shell's next sign-in for the
//! same `oid` picks it up again, and one for anyone else is still refused.
//!
//! ## What this does not prove until the test run
//!
//! Everything here is tested against a local stand-in for Entra and Graph that
//! speaks the documented wire shapes. Only the tenant answers whether single
//! sign-on is silent, whether the device claim reaches a refresh made as
//! SYSTEM, and whether Conditional Access then refuses it (D-036).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sluse_proto::pipe::HostSignIn;
use sluse_proto::{EntraConfig, Loaded, SluseError, UserRef};

pub mod graph;
pub mod token;

pub use token::Identity;

/// Where Entra is. The production value; tests point it at a local stand-in.
pub const AUTHORITY: &str = "https://login.microsoftonline.com";

/// Where Graph is.
pub const GRAPH: &str = "https://graph.microsoft.com/v1.0";

/// Why the broker's Entra half could not be assembled. A start-up failure.
#[derive(Debug, thiserror::Error)]
pub enum EntraError {
    #[error("the HTTP client for Entra and Graph could not be built: {0}")]
    Client(String),
}

/// The box's bound user, and the Graph token held for them.
///
/// Lives in [`Entra`], so it goes at sign-out or when the broker stops.
/// Nothing here is ever written to disk.
pub struct Bound {
    pub identity: Identity,
    pub user: UserRef,
    /// Why the Windows user is not shown to be this one, if not (D-057):
    /// filesystem sources and publish act as the Windows user while the
    /// record names this one, so they are refused while it is `Some`.
    pub windows_mismatch: Option<String>,
    pub token: tokio::sync::Mutex<token::GraphToken>,
}

/// What [`Entra::acting_for`] hands a route.
pub struct Acted {
    pub bound: Arc<Bound>,
    /// The Graph access token to call with.
    pub access: String,
}

/// The broker's Entra half.
pub struct Entra {
    pub(crate) tenant: String,
    pub(crate) client_id: String,
    pub(crate) authority: String,
    pub(crate) graph: String,
    pub(crate) http: reqwest::Client,
    /// For Graph's download addresses: see [`Entra::new`].
    pub(crate) download: reqwest::Client,
    pub(crate) keys: token::KeyCache,
    /// Drive id per source name, found once. Every user sees the same library
    /// under the same id, so this is not per-user state.
    pub(crate) drives: Mutex<HashMap<String, String>>,
    /// The one person this box acts for, once a token has bound it (D-022).
    bound: Mutex<Option<Arc<Bound>>>,
    /// The last binding's D-057 comparison, kept **past a sign-out**: a box
    /// that signed itself out must not lift the refusal (review R-02). A new
    /// binding replaces it, so a matching person's sign-in clears it.
    mismatch: Mutex<Option<String>>,
}

impl Entra {
    /// Build from the config. `None` when the config has no `entra` block,
    /// which the loader permits only when no source is `sharepoint`.
    pub fn from_loaded(loaded: &Loaded) -> Result<Option<Self>, EntraError> {
        let Some(cfg) = &loaded.config.entra else { return Ok(None) };
        Self::new(cfg, AUTHORITY, GRAPH).map(Some)
    }

    /// Build with explicit endpoints. Tests pass a local stand-in; nothing else
    /// should.
    pub fn new(cfg: &EntraConfig, authority: &str, graph: &str) -> Result<Self, EntraError> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| EntraError::Client(e.to_string()))?;
        // Downloads have no total timeout: a large file takes as long as it
        // takes, and a stalled one is caught by the read timeout (D-046). A
        // redirect is followed only to https, and nothing of ours is sent.
        let download = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::custom(|a| {
                if a.url().scheme() != "https" || a.previous().len() >= 5 { a.stop() } else { a.follow() }
            }))
            .read_timeout(std::time::Duration::from_secs(60))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| EntraError::Client(e.to_string()))?;
        Ok(Self {
            tenant: cfg.tenant_id.to_ascii_lowercase(),
            client_id: cfg.client_id.to_ascii_lowercase(),
            authority: authority.trim_end_matches('/').to_owned(),
            graph: graph.trim_end_matches('/').to_owned(),
            http,
            download,
            keys: token::KeyCache::default(),
            drives: Mutex::new(HashMap::new()),
            bound: Mutex::new(None),
            mismatch: Mutex::new(None),
        })
    }

    /// Who the box is bound to, if anyone.
    pub fn binding(&self) -> Option<Arc<Bound>> {
        self.lock_bound().clone()
    }

    /// Who a record should name: the bound user, or `None` to fall back to the
    /// broker's own identity.
    pub fn user(&self) -> Option<UserRef> {
        self.binding().map(|b| b.user.clone())
    }

    /// Bind the box, **once**. If it is already bound, the existing binding is
    /// returned and the new one discarded: two requests that both arrived
    /// before the first exchange finished must not leave the box acting for
    /// whichever finished last. The caller checks the two name the same person.
    fn bind(&self, fresh: Arc<Bound>) -> Arc<Bound> {
        self.lock_bound().get_or_insert(fresh).clone()
    }

    /// Sign the box's user out: drop the binding and the Graph and refresh
    /// tokens with it. Returns who was bound, for the record. **User-initiated
    /// only** (D-022): nothing in the broker calls this on its own. The D-057
    /// comparison stays ([`Entra::windows_mismatch`]).
    pub fn unbind(&self) -> Option<Arc<Bound>> {
        self.lock_bound().take()
    }

    /// Why the Windows user is not shown to be the last person bound, if not
    /// (D-057). Survives a sign-out; before the first sign-in it is `None`.
    pub fn windows_mismatch(&self) -> Option<String> {
        self.mismatch.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Recovered from a poisoned lock, as the session registry is: the slot
    /// holds no invariant a panic could break.
    fn lock_bound(&self) -> std::sync::MutexGuard<'_, Option<Arc<Bound>>> {
        self.bound.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Sign the box in with the host's sign-in (D-036). **The control
    /// channel's entry point.** Returns the binding and whether this call made
    /// it, so the caller writes one `signin` record per binding.
    ///
    /// The code is redeemed and the ID token checked. On an unbound box that
    /// binds it. On a box bound to the **same** person the new tokens replace
    /// the held ones: this is how a box whose refresh token died comes back.
    /// A sign-in for anyone else is refused, and changes nothing.
    pub async fn redeem(&self, sign_in: &HostSignIn) -> Result<(Arc<Bound>, bool), SluseError> {
        let (who, graph) = self.redeem_code(sign_in).await?;
        match self.binding() {
            Some(existing) => {
                let bound = same_user(existing, &who)?;
                let mut held = bound.token.lock().await;
                let refresh = graph.refresh.clone().or_else(|| held.refresh.take());
                *held = token::GraphToken { refresh, ..graph };
                drop(held);
                Ok((bound, false))
            }
            None => {
                let fresh = Arc::new(Bound {
                    user: UserRef::entra(&who.upn),
                    windows_mismatch: crate::as_user::user_sid().and_then(|sid| match sid {
                        Ok(sid) => crate::identity::windows_mismatch(&sid, &who),
                        Err(e) => Some(e.to_string()),
                    }),
                    identity: who.clone(),
                    token: tokio::sync::Mutex::new(graph),
                });
                let bound = self.bind(fresh.clone());
                let made_it = Arc::ptr_eq(&bound, &fresh);
                if made_it {
                    *self.mismatch.lock().unwrap_or_else(|e| e.into_inner()) = fresh.windows_mismatch.clone();
                }
                Ok((same_user(bound, &who)?, made_it))
            }
        }
    }

    /// The Graph token to act with. **The one entry point the source routes
    /// call.** The box must be bound: requests carry no token (D-036).
    pub async fn acting_for(&self, source: &str) -> Result<Acted, SluseError> {
        let bound = self.binding().ok_or_else(|| SluseError::SignInRequired {
            detail: "this box has no signed-in user; sign in from the Sluse window".into(),
        })?;
        let mut held = bound.token.lock().await;
        if !held.fresh() {
            let refresh = held.refresh.clone().ok_or_else(|| SluseError::SignInRequired {
                detail: "the held sign-in expired and Entra returned nothing to renew it with".into(),
            })?;
            let renewed = self.renew(&refresh, source).await?;
            let refresh = renewed.refresh.clone().or_else(|| held.refresh.take());
            *held = token::GraphToken { refresh, ..renewed };
        }
        let access = held.access.clone();
        drop(held);
        Ok(Acted { bound, access })
    }

    pub(crate) fn token_endpoint(&self) -> String {
        format!("{}/{}/oauth2/v2.0/token", self.authority, self.tenant)
    }

    pub(crate) fn keys_endpoint(&self) -> String {
        format!("{}/{}/discovery/v2.0/keys", self.authority, self.tenant)
    }
}

fn same_user(bound: Arc<Bound>, who: &Identity) -> Result<Arc<Bound>, SluseError> {
    if bound.identity.oid == who.oid {
        Ok(bound)
    } else {
        Err(SluseError::TokenRejected {
            detail: format!(
                "this box acts for {}; a token for {} cannot be used on it",
                bound.identity.upn, who.upn
            ),
        })
    }
}

/// Entra or Graph did not answer. A fault, not a refusal: nothing about the
/// request was decided.
pub(crate) fn unavailable(source: &str, detail: impl std::fmt::Display) -> SluseError {
    SluseError::SourceUnavailable { source_name: source.to_owned(), detail: detail.to_string() }
}

/// A transport error with its whole cause chain: reqwest's own text stops at
/// "error sending request for url (…)", and the cause (DNS, a refused
/// connection, TLS, a timeout) is in its sources (L1, 2026-10-07: a transient
/// renewal failure could not be told from a real one).
///
/// **Without the URL.** reqwest appends ` for url (…)`, and a Graph download
/// URL is pre-authenticated (`tempauth`): in a record and in the box it
/// would be an hour's access to the file with no admission (review R-09).
pub(crate) fn cause(e: &reqwest::Error) -> String {
    let mut out = e.to_string();
    if let Some(url) = e.url() {
        out = out.replace(&format!(" for url ({url})"), "");
    }
    let mut next = std::error::Error::source(e);
    while let Some(s) = next {
        let text = s.to_string();
        if !out.contains(&text) {
            out = format!("{out}: {text}");
        }
        next = s.source();
    }
    out
}

#[cfg(test)]
mod cause_tests {
    #[tokio::test]
    async fn a_refused_connection_says_so() {
        // Nothing listens on a port the OS just gave back.
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
        let e = reqwest::get(format!("http://127.0.0.1:{port}/?tempauth=secret")).await.unwrap_err();
        let text = super::cause(&e);
        assert!(text.starts_with("error sending request"), "{text}");
        assert!(text.contains(": "), "the chain adds the cause: {text}");
        assert!(!text.contains("tempauth") && !text.contains("for url"), "the URL is not in it: {text}");
    }
}

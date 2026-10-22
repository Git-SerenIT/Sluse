// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The service's control channel: the broker's stdin (D-036).
//!
//! One JSON line per message, a [`HostSignIn`] each: the code the shell caught
//! on the host, which the service hands over. **Nothing on the host-only
//! segment can write here**: the pipe's other end is the service's, which
//! started this process, and no route on either listener takes a sign-in.
//!
//! The outcome lands in [`Broker::host_sign_in`] under the message's `seq`,
//! where the service reads it back from `/v1/status`. Every attempt is
//! recorded, a refusal included, under the session `sess-host`.

use std::sync::Arc;

use sluse_proto::pipe::HostSignIn;
use sluse_proto::{HostSignInResult, Op, Outcome, SessionId, SluseError, SourceKind};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

use crate::app::Broker;

/// The session the host's sign-ins are recorded under. Not a minted id, so it
/// cannot collide with one.
pub const HOST_SESSION: &str = "sess-host";

/// Read sign-ins until the service closes the pipe.
pub async fn run<R: AsyncBufRead + Unpin>(broker: Arc<Broker>, input: R) {
    let mut lines = input.lines();
    while let Ok(Some(line)) = lines.next_line().await {
        match serde_json::from_str::<HostSignIn>(&line) {
            Ok(s) => {
                sign_in(&broker, &s).await;
            }
            // Not echoed: a line that does not parse may still hold a code.
            Err(e) => eprintln!("control: a line that is not a sign-in ({e})"),
        }
    }
}

/// Redeem one sign-in, record it, and publish its outcome.
pub async fn sign_in(broker: &Broker, s: &HostSignIn) -> HostSignInResult {
    let session = SessionId::new_unchecked(HOST_SESSION);
    let outcome = match broker.entra.clone() {
        None => Err(SluseError::TokenRejected {
            detail: "this box's config has no entra block, so there is nothing to sign in to".into(),
        }),
        Some(entra) => entra.redeem(s).await,
    };
    let error = match outcome {
        Ok((_, made_it)) => {
            broker.signed_in(&session, if made_it { "on the host" } else { "again on the host" });
            scope_roots(broker, &session).await;
            None
        }
        Err(e) => {
            let e = broker.refuse(broker.record(&session, Op::Signin, "(box)"), e);
            Some(e.to_string())
        }
    };
    if error.is_none() {
        broker.signed_out.store(false, std::sync::atomic::Ordering::Relaxed);
    }
    let result = HostSignInResult { seq: s.seq, error };
    // ponytail: published after the scope check, so the service's answer
    // waits for it; a few Graph calls, one per scope root.
    *broker.host_sign_in.lock().unwrap_or_else(|p| p.into_inner()) = Some(result.clone());
    result
}

/// Each SharePoint scope root, and the user's OneDrive `Sluse` folder
/// (D-054), looked up as the signed-in user (D-038 point 6). One that is not there, or not theirs to open, is a `scope` record,
/// raised: the admin's config names a folder this user cannot reach, and a
/// person reading the Event Log should see it before the agent does.
/// Filesystem roots are checked at the broker's start (`scope::compile`).
async fn scope_roots(broker: &Broker, session: &SessionId) {
    let Some(entra) = broker.entra.clone() else { return };
    for source in &broker.compiled.sources {
        let Some(scopes) = &source.remote else { continue };
        let name = source.name.as_str();
        let Ok(acted) = entra.acting_for(name).await else { return };
        let call = |raw: &'static str| crate::entra::graph::Call { source: name, raw, token: &acted.access };
        let (drive, folder) = match &source.kind {
            SourceKind::Sharepoint { site_url, library } => (entra.drive(&call(""), site_url, library).await, ""),
            // No OneDrive yet (never opened, not provisioned) is missing too.
            SourceKind::Onedrive => (entra.my_drive(&call("")).await, sluse_proto::config::ONEDRIVE_FOLDER),
            _ => continue,
        };
        let drive = match drive {
            Ok(d) => d,
            Err(e) => {
                missing(broker, session, &format!("{name}/"), &acted.bound.user.name, &e);
                continue;
            }
        };
        for scope in scopes {
            let path = format!("{name}/{}", scope.rel);
            let raw = crate::entra::graph::Call { source: name, raw: &path, token: &acted.access };
            let in_drive = [folder, scope.rel.as_str()].iter().filter(|p| !p.is_empty()).copied().collect::<Vec<_>>().join("/");
            if let Err(e) = entra.item(&raw, &drive, &in_drive).await {
                missing(broker, session, &path, &acted.bound.user.name, &e);
            }
        }
    }
}

fn missing(broker: &Broker, session: &SessionId, path: &str, user: &str, e: &SluseError) {
    let why = match e {
        SluseError::NotFound { .. } | SluseError::AccessDenied { .. } => format!(
            "the scope root {path} is not there for {user}; missing may also mean this user cannot open it"
        ),
        other => format!("the scope root {path} could not be checked: {other}"),
    };
    let mut rec = broker.record(session, Op::Scope, path);
    rec.outcome = Outcome::Raised;
    rec.reason = Some("SCOPE_MISSING".into());
    rec.detail = Some(why);
    broker.sink.record(&rec);
}

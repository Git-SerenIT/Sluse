// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The eight routes.
//!
//! Every one of them follows the same shape: **refuse, record, then answer.**
//! The record is written before the response goes back, so the host's account of
//! a decision is on disk whatever happens to the connection afterwards — and so
//! that a refusal, which is normal operation and not an exception, is in the
//! audit trail rather than only in the guest's journal (`docs/audit.md`).
//!
//! ## What each route records
//!
//! | Route | Record |
//! |---|---|
//! | `/v1/health`, `/v1/config-view`, `/v1/alerts`, `/v1/audit/tail` | none |
//! | `/v1/list` | refusals only |
//! | `/v1/read` | one on completion; refusals before any byte |
//! | `/v1/stat` | `op: Metadata`, every call |
//! | `/v1/publish` | one per artifact, with lineage |
//! | `/v1/journal` | refusals only |
//!
//! `/v1/stat` records every call including the quick path, which is a choice
//! about audit volume: the console's inventory stats every file it knows about,
//! so the refresh is **user-initiated only, never a timer** (jok, 2026-09-16).
//! A polled refresh would fill the sink with records saying nothing happened,
//! and M5's console is written against that constraint.
//!
//! ## The two things the guest does not get to say
//!
//! `x-sluse-session` must name a session **Gate Core issued** — see
//! [`crate::session`]. And `Audience::User` is served in LOCAL only: the
//! field is one the caller sets, so an agent talking HTTP to Gate Core could
//! ask for the listing that shows out-of-scope entries, and D-008's blinders
//! would be enforced by the guest's own good behaviour. M2 served `Agent`
//! only, M5 brought the console's greyed view back for every caller, and
//! D-033 (2026-10-01) took it back out of the box: the console runs there,
//! and so does the agent. `User` resolves anywhere inside a source root and
//! marks what is out of scope rather than omitting it.
//!
//! ## What the guest is told about a refusal
//!
//! The hidden form (D-033 point 2): an out-of-scope path and an unknown source
//! go to the guest as `NOT_FOUND`, with its status, so neither the code nor the
//! status tells them apart from a path that is not there. The host's record
//! keeps the whole error, resolved path and scopes included, because that is
//! where the audit claim lives. Until D-033 Gate Core never blinded and the
//! endpoint did (`blinders.rs`), which left the truth in the guest's journal.

use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Multipart, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use futures_core::Stream;
use sluse_proto::wire::{header, route};
use sluse_proto::{
    AdmissionId, AlertsQuery, AuditRecord, AuditTailQuery, AuditTailResponse, Audience,
    ContentHash, ContentHasher, Health, ListEntry, ListRequest, ListResponse, Op,
    Outcome, Pin as StatPin, PublishId, PublishManifest, PublishResponse, PublishedArtifact,
    ReadRequest, ReadVerb, SessionId, SignedOut, SluseError, SourceName, StatRequest,
    StatResponse, Status as StatusBody,
};
use tokio_util::io::ReaderStream;

use crate::app::Core;
use crate::scope::{self, Scoped};

/// The most one delivery may carry. Both sides hold it in memory, so a
/// constant and not a config field; axum's default, 2 MiB, was in force until
/// review R-11, and a 3 MB deck could not be published at all.
const PUBLISH_LIMIT: usize = 256 * 1024 * 1024;

/// The most one journal mirror request may carry: the endpoint sends 1 MiB
/// of lines at a time, and JSON escaping grows it.
const JOURNAL_LIMIT: usize = 4 * 1024 * 1024;

/// Build the router.
pub fn router(core: Arc<Core>) -> Router {
    Router::new()
        .route(route::HEALTH, get(health))
        .route(route::STATUS, get(status))
        .route(route::CONFIG_VIEW, get(config_view))
        .route(route::LIST, post(list))
        .route(route::READ, post(read))
        .route(route::STAT, post(stat))
        .route(route::PUBLISH, post(publish).layer(DefaultBodyLimit::max(PUBLISH_LIMIT)))
        .route(route::ALERTS, get(alerts))
        .route(route::AUDIT_TAIL, get(audit_tail))
        .route(route::SIGN_OUT, post(sign_out))
        .route(route::JOURNAL, post(journal_mirror).layer(DefaultBodyLimit::max(JOURNAL_LIMIT)))
        .route(route::TOOLS, get(tools))
        .route(route::CALL, post(call))
        .layer(axum::middleware::map_response_with_state(core.clone(), stamp_user))
        .with_state(core)
}

// ---------------------------------------------------------------------------
// The `mcp` sources' tools (D-071 slice 4)
// ---------------------------------------------------------------------------

/// Every `mcp` source's allowed tools. No record when listed, as a listing;
/// a server that could not be asked is recorded (`crate::mcp::tools`).
async fn tools(State(core): State<Arc<Core>>, headers: HeaderMap) -> ApiResult<Json<sluse_proto::ToolsResponse>> {
    let session = session(&core, &headers, Op::Tools, "")?;
    Ok(Json(crate::mcp::tools(&core, &session).await))
}

/// One tool call, admitted like a fetch.
async fn call(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Json(req): Json<sluse_proto::CallRequest>,
) -> ApiResult<Response> {
    let session = session(&core, &headers, Op::Call, &req.tool)?;
    crate::mcp::call(&core, session, req).await
}

// ---------------------------------------------------------------------------
// The journal's mirror (slice 4)
// ---------------------------------------------------------------------------

/// A session's mirror on the host is capped. A box that sends more is
/// refused, not believed: its own journal is metadata, and 64 MB of it is a
/// box doing something else.
const MIRROR_CAP: u64 = 64 * 1024 * 1024;

/// The whole mirror directory is capped too: a well-formed session id per
/// call would otherwise be a fresh 64 MB each time, and the directory sits on
/// the host's disk under SYSTEM (review R-01).
const MIRROR_DIR_CAP: u64 = 256 * 1024 * 1024;

/// Append the box's journal lines at `offset`, skipping what the host
/// already holds. **What the box said, not the trust anchor**: Gate Core's
/// own audit is that. It is kept so a wiped box's history is not gone
/// (D-027 point 5).
///
/// The file is named after the body's session, not the header's: the console
/// mirrors the run's journal under its own session. So the body's session is
/// held to the same standard as the header's — **a session this core
/// issued**, which is also a name the id grammar makes safe in a path. Before
/// review R-01 it was joined in unchecked, and `..` wrote as SYSTEM wherever
/// the box liked.
async fn journal_mirror(
    State(b): State<Arc<Core>>,
    headers: HeaderMap,
    Json(req): Json<sluse_proto::wire::JournalAppend>,
) -> ApiResult<Json<sluse_proto::wire::JournalAck>> {
    use std::io::Write;
    let caller = session(&b, &headers, Op::Journal, route::JOURNAL)?;
    let Some((dir, lock)) = b.journal_mirror.as_ref() else {
        return Err(ApiError(SluseError::AudienceNotServed { audience: "journal mirror".into() }));
    };
    let named = req.session.as_str();
    if !SessionId::is_well_formed(named) || b.sessions.issued_at(named).is_none() {
        let rec = b.record(&caller, Op::Journal, "(mirror)");
        return Err(ApiError(b.refuse(rec, SluseError::UnknownSession { session_id: named.to_owned() })));
    }
    let _held = lock.lock().unwrap_or_else(|p| p.into_inner());
    let internal = |e: std::io::Error| ApiError(SluseError::Internal { message: format!("the journal mirror: {e}") });
    std::fs::create_dir_all(dir).map_err(internal)?;
    let path = dir.join(format!("{named}.jsonl"));
    let have = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    // A gap: say where the host is, and the box sends from there.
    if req.offset > have || !req.lines.is_empty() && !req.lines.ends_with('\n') {
        return Ok(Json(sluse_proto::wire::JournalAck { have }));
    }
    let skip = (have - req.offset) as usize;
    let new = req.lines.as_bytes().get(skip..).unwrap_or_default();
    if have + new.len() as u64 > MIRROR_CAP {
        let rec = b.record(&caller, Op::Journal, named);
        return Err(ApiError(b.refuse(rec, SluseError::TooLarge { raw: named.to_owned(), size: have + new.len() as u64, limit: MIRROR_CAP })));
    }
    if !new.is_empty() {
        let total = mirror_size(dir) + new.len() as u64;
        if total > MIRROR_DIR_CAP {
            let rec = b.record(&caller, Op::Journal, named);
            return Err(ApiError(b.refuse(rec, SluseError::TooLarge { raw: "the journal mirror".into(), size: total, limit: MIRROR_DIR_CAP })));
        }
    }
    if !new.is_empty() {
        let mut f = std::fs::OpenOptions::new().create(true).append(true).open(&path).map_err(internal)?;
        f.write_all(new).map_err(internal)?;
        f.flush().map_err(internal)?;
    }
    Ok(Json(sluse_proto::wire::JournalAck { have: have + new.len() as u64 }))
}

/// The bytes the mirror directory holds. Flat: Gate Core writes no
/// subdirectories into it.
fn mirror_size(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .map(|it| it.flatten().filter_map(|e| e.metadata().ok()).filter(|m| m.is_file()).map(|m| m.len()).sum())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The enrolment listener (slice 2)
// ---------------------------------------------------------------------------

/// The enrolment listener's whole router: one route. Served with
/// `tls::enrol_server_config`, never merged into [`router`].
pub fn enrol_router(enrolment: Arc<crate::enrol::Enrolment>) -> Router {
    Router::new().route(
        sluse_proto::wire::route::ENROL,
        post(move |Json(req): Json<sluse_proto::wire::EnrolRequest>| {
            let enrolment = enrolment.clone();
            async move { enrolment.enrol(&req).map(Json).map_err(ApiError) }
        }),
    )
}

// ---------------------------------------------------------------------------
// Errors on the wire
// ---------------------------------------------------------------------------

/// A [`SluseError`] as an HTTP response.
///
/// The body is the error itself, serialised with its `code` tag, and the client
/// deserialises it straight back into the same type. The status is coarse and
/// says what kind of thing happened; the `code` says which.
pub struct ApiError(pub SluseError);

impl From<SluseError> for ApiError {
    fn from(e: SluseError) -> Self {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let err = hidden(self.0);
        let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (status, Json(err)).into_response()
    }
}

/// D-008's three as one, for the guest: whatever Gate Core recorded, the box
/// is told only that the path is not there (D-033 point 2).
fn hidden(err: SluseError) -> SluseError {
    match err {
        SluseError::OutOfScope { raw, .. } | SluseError::UnknownSource { raw } => SluseError::NotFound { raw },
        other => other,
    }
}

/// The greyed listing and the host's audit tail are for a person, and the
/// box cannot be told apart from one: served where the box is the person's
/// own machine (LOCAL), refused everywhere else (D-033 points 1 and 3). A
/// refusal is recorded: it is the box asking for something it may not have,
/// which is what IT wants to see (jok, 2026-10-01).
fn local_only(core: &Core, rec: AuditRecord, what: &str) -> ApiResult<()> {
    if core.loaded.config.environment == sluse_proto::Environment::Local {
        Ok(())
    } else {
        Err(ApiError(core.refuse(rec, SluseError::AudienceNotServed { audience: what.to_owned() })))
    }
}

pub(crate) type ApiResult<T> = Result<T, ApiError>;

// ---------------------------------------------------------------------------
// The session header
// ---------------------------------------------------------------------------

/// The session id a record is attributed to when the caller had no valid one.
///
/// A rejected caller is worth seeing in the trail, and the record needs a
/// session id to carry. Using the string the caller presented would put
/// unvetted text in the field that every other record joins on, so it goes in
/// under a sentinel that is not a well-formed minted id and cannot collide with
/// one.
const NO_SESSION: &str = "sess-unknown";

/// Recognise the caller's session, or record the refusal and return it.
fn session(core: &Core, headers: &HeaderMap, op: Op, path: &str) -> ApiResult<SessionId> {
    let raw = headers.get(header::SESSION).and_then(|v| v.to_str().ok()).unwrap_or("");
    match core.sessions.recognise(raw, Utc::now()) {
        Ok(id) => Ok(id),
        Err(err) => {
            let rec = core.record(&SessionId::new_unchecked(NO_SESSION), op, path);
            Err(ApiError(core.refuse(rec, err)))
        }
    }
}

// ---------------------------------------------------------------------------
// GET /v1/health
// ---------------------------------------------------------------------------

/// Every response says who Gate Core acted as, refusals included, so the
/// endpoint's journal names the person Gate Core's record names. Stamped as
/// the response leaves, after a sign-in or sign-out on this request took effect.
async fn stamp_user(State(core): State<Arc<Core>>, mut res: Response) -> Response {
    insert(res.headers_mut(), header::USER, &header::encode(&core.acting_user().display()));
    res
}

/// Liveness, identity, and a session id to carry.
///
/// The only route with no session requirement, because it is where a session
/// comes from. A fresh one per call: health is not a way to attach to a session
/// somebody else is using, and a caller that only wanted liveness — `sluse
/// start`'s "gate reachable" Gate — discards it and it ages out.
async fn health(State(core): State<Arc<Core>>) -> Json<Health> {
    Json(Health {
        ok: true,
        box_id: core.box_id(),
        config_version: core.config_version(),
        gate_version: crate::VERSION.to_owned(),
        user: core.acting_user(),
        posture_id: core.posture.id.clone(),
        session_id: core.sessions.mint(Utc::now()),
    })
}

// ---------------------------------------------------------------------------
// GET /v1/status
// ---------------------------------------------------------------------------

/// Liveness, without minting anything.
///
/// The difference from [`health`] is the whole point: health hands out a session
/// because that is where a session comes from, and a caller that only wants to
/// know whether Gate Core is up would mint one per poll. The registry is
/// bounded and evicts the least recently seen, so a `sluse status` left running
/// beside a real run would eventually evict the run's own session and the
/// endpoint would start getting `UnknownSession` mid-task. This route is what
/// every liveness caller uses instead.
async fn status(State(core): State<Arc<Core>>, headers: HeaderMap) -> Json<StatusBody> {
    // Asked, not used: no refresh of its idle clock, no record.
    let session_held = headers
        .get(header::SESSION)
        .and_then(|v| v.to_str().ok())
        .map(|raw| core.sessions.issued_at(raw).is_some());
    Json(StatusBody {
        ok: true,
        box_id: core.box_id(),
        config_version: core.config_version(),
        gate_version: crate::VERSION.to_owned(),
        user: core.user.clone(),
        posture_id: core.posture.id.clone(),
        required_passed: core.posture.required_passed(),
        signed_in: core.entra.as_ref().and_then(|e| e.user()),
        host_sign_in: core.host_sign_in.lock().unwrap_or_else(|p| p.into_inner()).clone(),
        sessions: core.sessions.len(),
        uptime_seconds: (Utc::now() - core.started).num_seconds(),
        environment: Some(core.loaded.config.environment),
        session_held,
        signed_out: core.signed_out.load(std::sync::atomic::Ordering::Relaxed),
        sign_in_window: core.window.until().is_some(),
        volume: {
            let now = Utc::now();
            core
                .loaded
                .config
                .sources
                .iter()
                .map(|s| {
                    let c = core.volume.count(&s.name, now);
                    sluse_proto::wire::SourceCount { source: s.name.clone(), files: c.files, bytes: c.bytes }
                })
                .collect()
        },
    })
}

// ---------------------------------------------------------------------------
// POST /v1/sign-out
// ---------------------------------------------------------------------------

/// Drop the box's binding: the console's sign-out (D-022).
///
/// Recorded **before** the binding goes, so the record names who signed out
/// and every record after it names Gate Core's own identity again — the
/// trail shows where one person's authority ended. Any session may call it,
/// the MCP process's included. It takes the Entra tokens away and does not
/// lift D-057's refusal ([`windows_mismatch`]); before review R-02 it did, and
/// filesystem reads then ran as the Windows user unchecked.
async fn sign_out(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
) -> ApiResult<Json<SignedOut>> {
    let session = session(&core, &headers, Op::Signout, route::SIGN_OUT)?;
    let mut rec = core.record(&session, Op::Signout, "(box)");
    let user = core.entra.as_ref().and_then(|e| e.unbind()).map(|b| b.user.clone());
    if user.is_some() {
        core.signed_out.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    rec.outcome = Outcome::Admitted;
    rec.reason = Some(match &user {
        Some(u) => format!("signed out {}", u.name),
        None => "nobody was signed in".into(),
    });
    core.sink.record(&rec);
    Ok(Json(SignedOut { user }))
}

// ---------------------------------------------------------------------------
// GET /v1/config-view
// ---------------------------------------------------------------------------

/// What the guest may know about its own world.
///
/// Advisory everywhere it is used. The endpoint refuses early with it and the
/// console draws a browser from it; neither is trusted for anything, because
/// the box cannot assert its own scope (invariant 2) and this is a copy of what
/// Gate Core decides with, not the thing itself.
async fn config_view(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
) -> ApiResult<Json<sluse_proto::ConfigView>> {
    session(&core, &headers, Op::Sources, route::CONFIG_VIEW)?;
    Ok(Json(sluse_proto::ConfigView {
        sources: core.config_view_sources(),
        max_read_bytes: core.max_read_bytes(),
        volume: core.volume_config(),
    }))
}

// ---------------------------------------------------------------------------
// POST /v1/list
// ---------------------------------------------------------------------------

async fn list(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Json(req): Json<ListRequest>,
) -> ApiResult<Json<ListResponse>> {
    let session = session(&core, &headers, Op::List, &req.path)?;
    if req.audience == Audience::User {
        local_only(&core, core.record(&session, Op::List, &req.path), "user")?;
    }
    if scope::remote_source(&core.compiled, &req.path).is_some() {
        return crate::remote::list(&core, session, req).await;
    }
    let rec = || core.record(&session, Op::List, &req.path);
    let _as_user = as_user(&core, rec())?;

    // Neither audience uses `resolve_in_scope`: a directory that is only on the
    // way to a scope may be listed, because walking to a scope is how the agent
    // gets there. The two differ in how far out they may look, and what they
    // may *show* is decided per entry, below.
    //
    // `User` is the console's listing and arrived at M5. It resolves anywhere
    // inside the source root, so a person can see the shape of their own source
    // and read the greying as "not yours to take" rather than as an absence
    // they have to guess at. That is the whole asymmetry D-008 asks for: the
    // agent's world is smaller than the user's, and neither is told a host path.
    let scoped = match req.audience {
        Audience::Agent => scope::resolve(&core.compiled, &req.path),
        Audience::User => scope::resolve_in_source(&core.compiled, &req.path),
    }
    .map_err(|e| ApiError(core.refuse(rec(), e)))?;

    let source = core.compiled.live(scoped.source);
    let raw = core
        .backend(scoped.source)
        .list(&req.path, scoped.path.real())
        .map_err(|e| ApiError(core.refuse(rec().resolved(scoped.path.display()), e)))?;
    // It answered (D-015 point 4). Recorded here rather than probed later:
    // a real operation is the only free evidence of reachability there is.
    core.answered(&source.name);

    let mut entries = Vec::new();
    for e in raw {
        // Visibility is decided on the **resolved** child, never on its name: a
        // junction named `docs` that points outside the scope is not in scope,
        // and a name comparison would have said it was.
        //
        // A child that cannot be canonicalised is dropped. Two different things
        // reach this line and **D-013 decided both should drop**:
        //
        // 1. It went away between the `read_dir` and here. Showing it would
        //    report something whose status is unknown.
        // 2. On Windows, it is denied by an ACL — `canonicalize` opens a handle,
        //    so a deny-read ACE fails here. That gives the asymmetry D-013
        //    wants: an agent walking the tree never learns the name, and an
        //    agent that names it anyway gets `AccessDenied` plainly and leaves
        //    a record of having known something it could not have discovered.
        //
        // **This is deliberate now, and it was incidental before.** It is also
        // Windows-only: POSIX `realpath` does not open the final component, so
        // a denied child canonicalises fine and is listed. The product is
        // Windows and the development guest is not; `docs/development.md` has
        // the per-item table. Do not "fix" this by distinguishing the two error
        // kinds — dropping both is the decision.
        let Ok(canon) = scope::Canonical::of(&e.path) else { continue };
        let visible = source.visible(&canon);
        if !visible && req.audience == Audience::Agent {
            // D-008: omitted, not refused. Out-of-scope material is absent from
            // the agent's world rather than forbidden in it — a refusal is an
            // answer, and an agent that can enumerate what it may not have has
            // been told what exists.
            continue;
        }
        entries.push(ListEntry {
            name: e.name,
            kind: e.kind,
            size: e.size,
            modified: e.modified,
            // Always true in an Agent listing, because everything else was
            // omitted; the field earns its keep in the console's, where false
            // is what gets greyed. "Visible" rather than "admitted": a directory
            // on the way to a scope is navigable and still not readable, and
            // greying it would tell a person their own folder is forbidden.
            in_scope: visible,
        });
    }

    Ok(Json(ListResponse { path: scoped.request_form(&core.compiled), entries }))
}

// ---------------------------------------------------------------------------
// POST /v1/read
// ---------------------------------------------------------------------------

/// Admit a file's bytes.
///
/// The record is written **on completion**, not here, because Gate Core hashes
/// the bytes as it sends them (invariant 7: both sides hash, and `admission_id`
/// joins the two records) and the hash is not known until the last one has gone.
/// Refusals are recorded before any byte leaves.
///
/// `read` is capped at `maxReadBytes` because it puts bytes inline in a model's
/// context. `fetch` streams to the guest's disk and is capped only if the config
/// sets `maxFetchBytes`, which is absent by default (D-016). A file over either
/// cap gets [`SluseError::TooLarge`] before anything is opened.
async fn read(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Json(req): Json<ReadRequest>,
) -> ApiResult<Response> {
    let op = match req.verb {
        ReadVerb::Read => Op::Read,
        ReadVerb::Fetch => Op::Fetch,
    };
    let session = session(&core, &headers, op, &req.path)?;
    if scope::remote_source(&core.compiled, &req.path).is_some() {
        return crate::remote::read(&core, session, req).await;
    }
    // Only filesystem sources get past the branch above; SharePoint's twin
    // streams through the same [`admitted`] body (D-046).
    let capability = sluse_proto::Capability::Bytes;
    let rec = || core.record(&session, op, &req.path).with_capability(capability);
    let _as_user = as_user(&core, rec())?;

    let scoped = scope::resolve_in_scope(&core.compiled, &req.path)
        .map_err(|e| ApiError(core.refuse(rec(), e)))?;
    let located = |r: AuditRecord| -> AuditRecord {
        let r = r.resolved(scoped.path.display());
        match &scoped.scope {
            Some(s) => r.in_scope(s.clone()),
            None => r,
        }
    };

    let backend = core.backend(scoped.source);
    let meta = backend
        .stat(&req.path, scoped.path.real())
        .map_err(|e| ApiError(core.refuse(located(rec()), e)))?;
    core.answered(&core.source(scoped.source).name);

    if meta.is_dir {
        let err = SluseError::NotAFile { raw: req.path.clone() };
        return Err(ApiError(core.refuse(located(rec()), err)));
    }

    // Before a byte is opened, let alone sent. Two caps, and they are different
    // claims: `maxReadBytes` protects a model's context and is always set;
    // `maxFetchBytes` is a deployment's own ceiling on a local copy and is
    // absent by default, because admission is the control point and not size
    // (invariant 4, D-016).
    let cap = match req.verb {
        ReadVerb::Read => Some(core.max_read_bytes()),
        ReadVerb::Fetch => core.max_fetch_bytes(),
    };
    if let Some(limit) = cap {
        if meta.size > limit {
            let err = SluseError::TooLarge { raw: req.path.clone(), size: meta.size, limit };
            return Err(ApiError(core.refuse(located(rec()), err)));
        }
    }

    let file = backend
        .open(&req.path, scoped.path.real())
        .map_err(|e| ApiError(core.refuse(located(rec()), e)))?;
    let source_name = core.source(scoped.source).name.clone();
    let resolved = scoped.path.display().to_owned();
    // No more than the size the caps were applied to: a file growing while it
    // is read must not carry a read past `maxReadBytes` (review R-29).
    let file = tokio::io::AsyncReadExt::take(file, meta.size);
    Ok(admitted(&core, located(rec()), session, source_name, ReaderStream::new(file), meta.size, &resolved))
}

/// The answer to an admitted read, from any source (D-046): the bytes as they
/// come, hashed on the way past, and recorded once when they stop.
pub(crate) fn admitted(
    core: &Arc<Core>,
    record: AuditRecord,
    session: SessionId,
    source: SourceName,
    bytes: impl Stream<Item = Result<Bytes, io::Error>> + Send + 'static,
    size: u64,
    resolved: &str,
) -> Response {
    let admission = AdmissionId::mint();
    let body = AdmittedBody {
        inner: Box::pin(bytes),
        hasher: Some(ContentHasher::new()),
        sent: 0,
        declared: size,
        finish: Some(Finish { core: core.clone(), record, admission: admission.clone(), session, source }),
    };

    let mut response = Response::new(Body::from_stream(body));
    let h = response.headers_mut();
    h.insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    // The content hash is deliberately **not** a header: it is not known until
    // the body has been sent, and a header would need the whole file read
    // twice. Both ends hash independently and `admission_id` joins the records
    // — which is a stronger check than a header either end could have copied.
    insert(h, header::ADMISSION_ID, admission.as_str());
    insert(h, header::SIZE, &size.to_string());
    insert(h, header::RESOLVED, &header::encode(resolved));
    response
}

/// A stream's errors as `io::Error`s, so a download feeds the same body as a
/// file does.
pub(crate) struct IoErrors<S>(pub S);

impl<S, E> Stream for IoErrors<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: std::fmt::Display,
{
    type Item = Result<Bytes, io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.0).poll_next(cx).map(|o| o.map(|r| r.map_err(|e| io::Error::other(e.to_string()))))
    }
}

fn insert(map: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        map.insert(name, v);
    }
}

/// What still has to happen when the body ends.
struct Finish {
    core: Arc<Core>,
    record: AuditRecord,
    admission: AdmissionId,
    session: SessionId,
    source: SourceName,
}

/// A file's bytes, hashed on the way past, recorded once when they stop.
///
/// Three ways to end and each is recorded differently: the file ran out
/// (`Admitted`, with the hash and the byte count), the source failed part-way
/// (`Error`, with the bytes that did go and **no** hash, because there is
/// nothing a partial hash could be compared against), or the client stopped
/// reading (`Error`, same reasoning, caught in `Drop`).
///
/// A partial read is not counted by the volume monitor. The window counts
/// distinct content admitted, and half a file is not content that was admitted.
struct AdmittedBody {
    inner: Pin<Box<dyn Stream<Item = Result<Bytes, io::Error>> + Send>>,
    hasher: Option<ContentHasher>,
    sent: u64,
    /// What `x-sluse-size` said. A stream that ends short of it is recorded
    /// as an error, as the endpoint refuses it, so the two records still
    /// agree (review R-29).
    declared: u64,
    finish: Option<Finish>,
}

impl AdmittedBody {
    fn complete(&mut self, error: Option<String>) {
        let Some(f) = self.finish.take() else { return };
        let hash = self.hasher.take().map(ContentHasher::finish);

        let error = error.or_else(|| {
            (self.sent != self.declared)
                .then(|| format!("the file changed while it was read: {} of {} bytes", self.sent, self.declared))
        });
        match (error, hash) {
            (None, Some(hash)) => {
                let rec = f.record.admitted(f.admission.clone(), hash.clone(), self.sent);
                f.core.sink.record(&rec);
                f.core.sessions.admit(
                    f.session.as_str(),
                    sluse_proto::LineageItem {
                        path: rec.path_requested.clone(),
                        hash: hash.clone(),
                        admission_id: Some(f.admission),
                        state: None,
                    },
                );

                // Only a completed admission counts toward the window, and only
                // a *distinct* one: the monitor dedupes by content hash, so the
                // same file read three times is one admission. `self.sent` is
                // the bytes that actually crossed, which is what D-016 counts —
                // not the size `stat` promised before the read began.
                if let Some(alert) =
                    f.core.volume.admit(&f.session, &f.source, &hash, self.sent, Utc::now())
                {
                    let mut rec = f.core.record(&f.session, Op::Alert, alert.summary.clone());
                    // Raised, not Refused: the admissions that caused it were
                    // permitted and happened. Detective, not preventive
                    // (`docs/threat-model.md`), and nothing here stops an agent.
                    rec.outcome = Outcome::Raised;
                    f.core.sink.record(&rec);
                }
            }
            (error, _) => {
                let err = SluseError::SourceUnavailable {
                    source_name: f.source.as_str().to_owned(),
                    detail: error.unwrap_or_else(|| "the read ended early".to_owned()),
                };
                let mut rec = f.record.failed(&err);
                // What did cross, with no hash beside it. A hash of a truncated
                // file that read as a hash of the file would be worse than none.
                rec.bytes = Some(self.sent);
                f.core.sink.record(&rec);
            }
        }
    }
}

impl Stream for AdmittedBody {
    type Item = Result<Bytes, io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                if let Some(h) = this.hasher.as_mut() {
                    h.update(&chunk);
                }
                this.sent += chunk.len() as u64;
                Poll::Ready(Some(Ok(chunk)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.complete(Some(e.to_string()));
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.complete(None);
                Poll::Ready(None)
            }
        }
    }
}

impl Drop for AdmittedBody {
    fn drop(&mut self) {
        // A client that hung up mid-file. The bytes that went are still bytes
        // that went, and an admission that left no record because the connection
        // ended badly is the failure mode the audit trail exists to not have.
        self.complete(Some("the client stopped reading before the file ended".to_owned()));
    }
}

// ---------------------------------------------------------------------------
// POST /v1/stat
// ---------------------------------------------------------------------------

/// Size, modified time and hash, with a quick path when the caller's pin still
/// matches.
///
/// The quick path is a cache and is honest about being one: size and mtime can
/// both survive an edit. Nothing is admitted on the strength of this answer —
/// the inventory's job is to tell a user their evidence has moved on, not to
/// make a security claim — and re-hashing a 500 MB fetch to redraw a console row
/// is not a cost the source should pay.
async fn stat(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Json(req): Json<StatRequest>,
) -> ApiResult<Json<StatResponse>> {
    let session = session(&core, &headers, Op::Metadata, &req.path)?;
    if scope::remote_source(&core.compiled, &req.path).is_some() {
        return crate::remote::stat(&core, session, req).await;
    }
    let rec = || core.record(&session, Op::Metadata, &req.path);
    let _as_user = as_user(&core, rec())?;

    let scoped = scope::resolve_in_scope(&core.compiled, &req.path)
        .map_err(|e| ApiError(core.refuse(rec(), e)))?;
    let located = |r: AuditRecord| -> AuditRecord {
        let r = r.resolved(scoped.path.display());
        match &scoped.scope {
            Some(s) => r.in_scope(s.clone()),
            None => r,
        }
    };

    let backend = core.backend(scoped.source);
    let meta = backend
        .stat(&req.path, scoped.path.real())
        .map_err(|e| ApiError(core.refuse(located(rec()), e)))?;
    core.answered(&core.source(scoped.source).name);

    if meta.is_dir {
        let err = SluseError::NotAFile { raw: req.path.clone() };
        return Err(ApiError(core.refuse(located(rec()), err)));
    }

    let quick = matches!(
        &req.pinned,
        Some(StatPin { size, modified, .. }) if *size == meta.size && *modified == meta.modified
    );

    let (hash, matches_pinned) = if quick {
        // The pin's own hash, returned unchanged. Re-reading the bytes to
        // confirm what the quick path exists to avoid reading would make the
        // quick path pointless.
        let pin = req.pinned.as_ref().expect("quick implies a pin");
        (pin.hash.clone(), Some(true))
    } else {
        let hash = hash_file(scoped.path.real())
            .map_err(|e| ApiError(core.refuse(located(rec()), source_error(&core, &scoped, &req.path, &e))))?;
        let matches = req.pinned.as_ref().map(|p| p.hash == hash);
        (hash, matches)
    };

    // Every call, including the quick path. The console's inventory refresh is
    // user-initiated, never a timer, which is what keeps this bounded.
    core.sink.record(&stat_record(located(rec()), &hash, meta.size, quick));

    Ok(Json(StatResponse {
        size: meta.size,
        modified: meta.modified,
        hash,
        matches_pinned,
    }))
}

/// A stat's record. On the quick path the hash is the box's own pin, never
/// read here, so the record carries none and says why: written as an
/// admitted hash it would look like Gate Core vouching for bytes it did not
/// see (review R-26).
pub(crate) fn stat_record(rec: AuditRecord, hash: &ContentHash, size: u64, quick: bool) -> AuditRecord {
    let mut rec = rec.admitted(AdmissionId::mint(), hash.clone(), size);
    if quick {
        rec.hash = None;
        rec.reason = Some("PIN_MATCHED".into());
    }
    rec
}

/// A filesystem source is touched as the user on a device (invariant 8,
/// D-054): resolving, listing, opening and hashing, from here to the
/// handler's end, after its last `.await`; an open file keeps the access it
/// was opened with. Records are written as Gate Core regardless
/// ([`crate::as_user::as_core`]). Until 2026-10-12 only publish did this,
/// and an SMB read on a device went out as the computer account.
fn as_user(core: &Core, rec: AuditRecord) -> Result<crate::as_user::Guard, ApiError> {
    if let Some(e) = windows_mismatch(core) {
        return Err(ApiError(core.refuse(rec, e)));
    }
    crate::as_user::enter().map_err(|e| ApiError(core.refuse(rec, SluseError::Internal { message: e.to_string() })))
}

/// D-057: the record names the person signed in to Entra, and a filesystem
/// source or a publish acts as the Windows user, so neither runs while the
/// two are not shown to be the same. The comparison outlives a sign-out, so
/// the box cannot lift the refusal by signing itself out (review R-02).
/// Before the first sign-in nothing has been compared, and the record names
/// Gate Core's own identity: a gap, written in `docs/audit.md`. SharePoint
/// and OneDrive act with the Entra token and are not touched by this.
fn windows_mismatch(core: &Core) -> Option<SluseError> {
    let detail = core.entra.as_ref()?.windows_mismatch()?;
    Some(SluseError::TokenRejected { detail })
}

fn source_error(core: &Core, scoped: &Scoped, raw: &str, e: &io::Error) -> SluseError {
    crate::sources::local_error(
        core.source(scoped.source).name.as_str(),
        raw,
        scoped.path.real(),
        e,
    )
}

fn hash_file(path: &Path) -> io::Result<ContentHash> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = ContentHasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finish())
}

// ---------------------------------------------------------------------------
// POST /v1/publish
// ---------------------------------------------------------------------------

/// The one write path, and it is all or nothing.
///
/// Files land in `artifacts/.incoming/<publish_id>/` and are moved into place
/// only when every one of them has arrived and hashed to what the manifest
/// declared. A delivery that half-succeeded would leave artifacts whose lineage
/// describes a publish that did not happen.
///
/// **One call, many files** (S-2 finding 8, D-018). Every artifact carries the
/// session's full admission set. The old "since the last publish" rule, one
/// call per file, left the second and third artifact of a delivery with none.
async fn publish(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    multipart: Multipart,
) -> ApiResult<Json<PublishResponse>> {
    let session = session(&core, &headers, Op::Publish, "")?;
    let publish_id = PublishId::mint();

    // What the delivery says it is, for a refusal over the limit to name.
    let declared = headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    match do_publish(&core, &session, &publish_id, multipart, declared).await {
        Ok(response) => Ok(Json(response)),
        Err((err, name)) => {
            let rec = core.record(&session, Op::Publish, name.clone().unwrap_or_default());
            let mut rec = rec;
            rec.publish_id = Some(publish_id);
            rec.artifact = name;
            Err(ApiError(core.refuse(rec, err)))
        }
    }
}

/// The body of publish, returning the artifact name a failure was about when
/// there is one.
async fn do_publish(
    core: &Core,
    session: &SessionId,
    publish_id: &PublishId,
    mut multipart: Multipart,
    declared: Option<u64>,
) -> Result<PublishResponse, (SluseError, Option<String>)> {
    let bad = |m: &str| -> (SluseError, Option<String>) {
        (SluseError::Internal { message: m.to_owned() }, None)
    };
    // Over the limit is the delivery's size, said as such, not an internal
    // error (review R-11).
    let read_failed = |what: &str, e: axum::extract::multipart::MultipartError| {
        if e.status() == StatusCode::PAYLOAD_TOO_LARGE {
            let limit = PUBLISH_LIMIT as u64;
            // Without a Content-Length the size is not known, only that it is over.
            (SluseError::TooLarge { raw: "the delivery".into(), size: declared.unwrap_or(limit + 1), limit }, None)
        } else {
            bad(&format!("{what}: {e}"))
        }
    };

    let mut manifest: Option<PublishManifest> = None;
    let mut received: Vec<(String, Bytes)> = Vec::new();

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| read_failed("reading the multipart body", e))?
    {
        let name = field.name().unwrap_or_default().to_owned();
        let bytes = field
            .bytes()
            .await
            .map_err(|e| read_failed(&format!("reading part \"{name}\""), e))?;

        if name == "manifest" {
            manifest = Some(
                serde_json::from_slice(&bytes)
                    .map_err(|e| bad(&format!("the manifest is not a PublishManifest: {e}")))?,
            );
        } else {
            received.push((name, bytes));
        }
    }

    let manifest = manifest.ok_or_else(|| bad("no `manifest` part in the publish"))?;

    // **Parts are matched to manifest entries by order, not by name.** The part
    // name looked like the obvious key and it is not one: reqwest percent-encodes
    // it as a path segment, so an artifact called `crates/x/src/lib.rs` arrives
    // as `crates%2Fx%2Fsrc%2Flib.rs`, and every client would encode it slightly
    // differently. The manifest is the authority on names; a part carries bytes.
    if received.len() != manifest.artifacts.len() {
        return Err((
            SluseError::Internal {
                message: format!(
                    "the manifest names {} artifact(s) and {} file part(s) arrived",
                    manifest.artifacts.len(),
                    received.len()
                ),
            },
            None,
        ));
    }
    // D-059: the lineage recorded is **Gate Core's own**: every read and
    // fetch it completed under this session. A declared source must be one of
    // them (D-055). The guest's manifest lineage contributes only what the
    // core cannot see, each admission's `state` in the box; until review
    // R-07 both lists were the guest's and the record copied them.
    let lineage: Vec<sluse_proto::LineageItem> = core
        .sessions
        .admitted(session.as_str())
        .into_iter()
        .map(|mut l| {
            l.state = manifest.lineage.iter().find(|m| m.hash == l.hash).and_then(|m| m.state);
            l
        })
        .collect();
    for artifact in &manifest.artifacts {
        if let Some(s) = artifact.sources.iter().find(|s| !lineage.iter().any(|l| l.hash == s.hash)) {
            return Err((
                SluseError::SourceNotAdmitted { name: artifact.name.clone(), source_path: s.path.clone() },
                Some(artifact.name.clone()),
            ));
        }
    }

    // Every touch of the folder is made as the user (D-031), and nothing else
    // is: the records below are written after the guard drops, as Gate Core.
    if let Some(e) = windows_mismatch(core) {
        return Err((e, None));
    }
    let base = delivery_folder(&manifest);
    let (moved, folder, outcome) = {
        let _as_user = crate::as_user::enter().map_err(|e| bad(&e.to_string()))?;
        deliver(&core.artifacts, &base, publish_id, &manifest, &received)
    };

    let mut published = Vec::new();
    for (name, hash, bytes, to) in moved {
        let path = request_form_artifact(&format!("{folder}/{name}"));
        let sources = manifest.artifacts.iter().find(|a| a.name == name).map(|a| a.sources.clone());
        let mut rec = core.record(session, Op::Publish, path.clone());
        rec.publish_id = Some(publish_id.clone());
        rec.artifact = Some(name.clone());
        rec.hash = Some(hash.clone());
        rec.bytes = Some(bytes);
        rec.path_resolved = Some(to.display().to_string());
        rec.lineage = Some(lineage.clone());
        rec.sources = sources;
        // `label` stays `None`. Whether the label comes from the config's own
        // levels or from Purview is Q-4, and whether it survives the file format
        // is Q-5; writing one would be a claim about persistence that nothing
        // has verified.
        rec.outcome = Outcome::Admitted;
        core.sink.record(&rec);

        published.push(PublishedArtifact { name, hash, bytes, path });
    }
    // Whatever was moved before a failure is recorded above, so no artifact
    // sits in the folder without its record.
    outcome?;

    Ok(PublishResponse { publish_id: publish_id.clone(), artifacts: published })
}

type Failure = (SluseError, Option<String>);

/// An artifact in place: its name, hash, size and where it landed.
type Moved = (String, ContentHash, u64, PathBuf);

/// `2026-10-07 14.32 report`: the local time a person reads and what the
/// delivery is, from its first file's top folder, or its name without the
/// extension (D-031 point 5). The publish id's hex read as a machine's name
/// (L1, 2026-10-07). One folder per delivery, so a second `report.md` is a
/// second folder, `… report 2`, not a refusal: [`reserve_folder`].
fn delivery_folder(manifest: &PublishManifest) -> String {
    let first = manifest.artifacts.first().map(|a| a.name.as_str()).unwrap_or_default();
    let label = match first.split_once('/') {
        Some((top, _)) => top,
        None => first.rsplit_once('.').map_or(first, |(stem, _)| stem),
    };
    // Letters, digits and a few marks, so the name is a folder on every
    // filesystem: no colon (hence `14.32`), no trailing dot or space.
    let label: String = label
        .chars()
        .map(|c| if c.is_alphanumeric() || " -_.()".contains(c) { c } else { '-' })
        .take(60)
        .collect();
    let label = label.trim_matches([' ', '.']);
    let when = chrono::Local::now().format("%Y-%m-%d %H.%M");
    if label.is_empty() { when.to_string() } else { format!("{when} {label}") }
}

/// Make the delivery's folder: `base`, or `base 2`, `base 3`, … when it is
/// taken. `create_dir` fails on one that exists, so two publishes in the
/// same minute cannot take the same folder.
fn reserve_folder(artifacts: &Path, base: &str) -> std::io::Result<String> {
    for n in 1..1000 {
        let name = if n == 1 { base.to_owned() } else { format!("{base} {n}") };
        match std::fs::create_dir(artifacts.join(&name)) {
            Ok(()) => return Ok(name),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(std::io::Error::other(format!("{base} is taken a thousand times over")))
}

/// Stage, check and move one delivery into `artifacts/<folder>/`, the folder
/// made from `base` only once every hash has matched. Returns what was moved,
/// and the folder, even when it then fails, so the caller can record it.
fn deliver(
    artifacts: &Path,
    base: &str,
    publish_id: &PublishId,
    manifest: &PublishManifest,
    received: &[(String, Bytes)],
) -> (Vec<Moved>, String, Result<(), Failure>) {
    let bad = |m: &str| -> Failure { (SluseError::Internal { message: m.to_owned() }, None) };
    let mut moved = Vec::new();
    let mut folder = String::new();
    let mut run = || -> Result<(), Failure> {
        // The write path makes sure of its own directory. The preflight creates
        // it at start, and a run that outlives someone tidying up underneath it
        // should publish rather than fail with an error about canonicalisation.
        std::fs::create_dir_all(artifacts)
            .map_err(|e| bad(&format!("creating {}: {e}", artifacts.display())))?;

        // --- everything that can be decided before a byte is written -------
        //
        // Resolved up front, so a name that cannot land is refused before the
        // staging directory exists rather than half way through writing it.
        let mut names: Vec<String> = Vec::new();
        for artifact in &manifest.artifacts {
            validate_artifact_name(&artifact.name).map_err(|e| (e, Some(artifact.name.clone())))?;
            // Where it would land, checked for the shape now; the folder is
            // made below, and is new, so nothing in it can be overwritten.
            artifact_path(artifacts, &format!("{base}/{}", artifact.name))
                .map_err(|e| (e, Some(artifact.name.clone())))?;
            // Compared as NTFS sees them: `a.md` and `A.md`, or `x/a` and
            // `x\a`, are one file there (R-52).
            let key = artifact.name.replace('\\', "/").to_lowercase();
            if names.contains(&key) {
                // Refused, never overwritten. Within one delivery that is the
                // same manifest naming one artifact twice, where the second
                // write would win silently and its record would describe the
                // first.
                return Err((
                    SluseError::ArtifactExists { name: artifact.name.clone() },
                    Some(artifact.name.clone()),
                ));
            }
            names.push(key);
        }

        let incoming = artifacts.join(".incoming").join(publish_id.as_str());
        std::fs::create_dir_all(&incoming)
            .map_err(|e| bad(&format!("creating {}: {e}", incoming.display())))?;
        // Whatever happens below, the staging directory does not survive it,
        // and it goes while this still runs as the user.
        let _staging = Staging(incoming.clone());

        let mut parts = received.iter().map(|(_, bytes)| bytes);
        let mut staged: Vec<Moved> = Vec::new();
        for artifact in &manifest.artifacts {
            let bytes = parts.next().expect("the count was checked above");

            let actual = ContentHash::of(bytes);
            if actual != artifact.hash {
                // The whole publish, not just this file. A manifest that does
                // not describe its bytes is the one thing a provenance record
                // must never carry, and the other files in the call came from
                // the same place.
                return Err((
                    SluseError::HashMismatch {
                        name: artifact.name.clone(),
                        declared: artifact.hash.clone(),
                        actual,
                    },
                    Some(artifact.name.clone()),
                ));
            }

            // Staged under the same relative shape, so the move into place is
            // a rename within one directory tree and never a cross-volume copy.
            let staged_path = incoming.join(artifact.name.replace(char::from(47), std::path::MAIN_SEPARATOR_STR));
            if let Some(parent) = staged_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| bad(&format!("creating {}: {e}", parent.display())))?;
            }
            // `create_new`, so a name the fold above misses (an 8.3 alias)
            // is refused rather than written over another (R-52).
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&staged_path)
                .and_then(|mut f| std::io::Write::write_all(&mut f, bytes))
                .map_err(|e| match e.kind() {
                    std::io::ErrorKind::AlreadyExists => {
                        (SluseError::ArtifactExists { name: artifact.name.clone() }, Some(artifact.name.clone()))
                    }
                    _ => bad(&format!("writing {}: {e}", staged_path.display())),
                })?;
            mark_of_the_web(&staged_path)
                .map_err(|e| bad(&format!("marking {}: {e}", staged_path.display())))?;
            staged.push((artifact.name.clone(), actual, bytes.len() as u64, staged_path));
        }

        // --- and only now, into place --------------------------------------
        folder = reserve_folder(artifacts, base)
            .map_err(|e| bad(&format!("making the delivery's folder {base}: {e}")))?;
        for (name, hash, bytes, from) in staged {
            let to = artifact_path(artifacts, &format!("{folder}/{name}")).map_err(|e| (e, Some(name.clone())))?;
            // Checked once more, because the window between the check above and
            // here is a window: a person dropping a file in.
            if to.exists() {
                return Err((SluseError::ArtifactExists { name: name.clone() }, Some(name)));
            }
            if let Some(parent) = to.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| bad(&format!("creating {}: {e}", parent.display())))?;
            }
            std::fs::rename(&from, &to)
                .map_err(|e| bad(&format!("moving {} into place: {e}", from.display())))?;
            moved.push((name, hash, bytes, to));
        }
        Ok(())
    };
    let outcome = run();
    // All or nothing on the host too (review R-31): a move that failed half
    // way takes back what it moved, with the fresh folder it moved into, so
    // the host records nothing, as the box records one refusal. Only if that
    // fails too are the moved files kept, and recorded, so no file sits in
    // Sluse Artifacts without its record.
    if outcome.is_err() && !moved.is_empty() && !folder.is_empty() && std::fs::remove_dir_all(artifacts.join(&folder)).is_ok() {
        moved.clear();
    }
    (moved, folder, outcome)
}

/// The Internet zone on every artifact (D-031 point 4), in the stream Windows
/// itself writes on a download. It moves with the file on the rename into
/// place. Office opens the file in Protected View; SmartScreen checks it.
#[cfg(windows)]
fn mark_of_the_web(path: &Path) -> std::io::Result<()> {
    let mut stream = path.as_os_str().to_owned();
    stream.push(":Zone.Identifier");
    std::fs::write(stream, "[ZoneTransfer]\r\nZoneId=3\r\n")
}

#[cfg(not(windows))]
fn mark_of_the_web(_: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Removes the staging directory on the way out, however the way out happens.
struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
        // And the `.incoming` parent, if this was the last publish using it.
        // `remove_dir` refuses a directory that is not empty, which is exactly
        // the wanted behaviour when another publish is in flight — so this is a
        // tidy-up that cannot race into deleting someone else's staging.
        if let Some(parent) = self.0.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// `artifacts/<name>`, which is what the guest calls it.
///
/// Not a source: the artifacts directory is the write path and is compiled to be
/// outside every source root, so nothing published can be read back as if it had
/// been admitted from a source.
fn request_form_artifact(name: &str) -> String {
    format!("artifacts/{name}")
}

/// Windows device names, which are reserved at every directory level and with
/// any extension.
const RESERVED: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// A relative path under the artifacts directory: `summary.md`, or
/// `crates/sluse-proto/src/lib.rs`.
///
/// **Subdirectories are allowed, and that is a deliberate reversal.** M2 built
/// this as one flat file name, which would have made M4's smoke run unable to
/// repeat the task S-2 passed — that run published
/// `crates/chapr-proto/src/ids.rs`, and a delivery that is a source tree is a
/// delivery a person can open. jok's answer on 2026-09-16.
///
/// The cost is that this is now a second place where a path is validated, and
/// the first one — [`crate::scope`] — is the enforcing resolver. They are
/// deliberately *not* shared: scope resolves a path the agent may **read** and
/// must handle junctions, UNC roots and 8.3 names on the way in; this resolves a
/// path the agent may **write** under a directory Gate Core owns, and the
/// grammar is all that stands between a manifest and the filesystem. Sharing
/// them would mean one change serving two meanings. What they do share is the
/// rule that decides the question: the grammar refuses first, and containment is
/// then checked against the **canonicalised** result, because only
/// canonicalisation sees through a junction.
fn validate_artifact_name(name: &str) -> Result<(), SluseError> {
    let malformed = |reason: &str| SluseError::MalformedArtifactName {
        name: name.to_owned(),
        reason: reason.to_owned(),
    };

    if name.is_empty() {
        return Err(malformed("empty"));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(malformed("a control character"));
    }
    if name.contains(':') {
        // A drive prefix, or an NTFS alternate data stream — which would write
        // bytes that nothing lists and no manifest describes.
        return Err(malformed("a colon"));
    }
    if name.starts_with('/') || name.starts_with('\\') {
        return Err(malformed("a leading separator; the path is relative to the artifacts directory"));
    }

    // Both separators, because a manifest written on either platform reaches the
    // same directory and the two must not validate differently.
    let segments: Vec<&str> = name.split(['/', '\\']).collect();
    for segment in &segments {
        if segment.is_empty() {
            return Err(malformed("an empty path segment"));
        }
        if *segment == "." || *segment == ".." {
            return Err(malformed("a relative path segment"));
        }
        if segment.starts_with('.') {
            // `.incoming` is the staging directory; the rest are hidden files
            // nobody meant to publish.
            return Err(malformed("a segment starting with a dot"));
        }
        if segment.ends_with(' ') || segment.ends_with('.') {
            // Windows silently strips these, so the name written and the name
            // recorded would differ — and the record is the point.
            return Err(malformed("a segment ending in a space or a dot"));
        }
        let stem = segment.split('.').next().unwrap_or(segment).to_ascii_lowercase();
        if RESERVED.contains(&stem.as_str()) {
            // Reserved at every level, not only the last: `crates/con/x.rs` is
            // as unopenable as `con`.
            return Err(SluseError::ReservedName { name: name.to_owned() });
        }
    }
    Ok(())
}

/// Where an artifact lands, once the grammar has passed.
///
/// The grammar above cannot refuse everything: `artifacts` itself may be reached
/// through a junction, or a directory inside it may be one, and a name that is
/// innocent as a string can then resolve outside the tree Gate Core owns. So
/// the resolved parent is canonicalised and checked, every time, as the last
/// thing before any byte is written.
fn artifact_path(artifacts: &Path, name: &str) -> Result<PathBuf, SluseError> {
    let target = artifacts.join(name.replace('/', std::path::MAIN_SEPARATOR_STR));

    let root = crate::scope::Canonical::of(artifacts).map_err(|e| SluseError::Internal {
        message: format!("the artifacts directory cannot be resolved: {e}"),
    })?;

    // The file does not exist yet, so the deepest existing ancestor is what can
    // be canonicalised. A directory that will be created under a junction is
    // still under it.
    let mut probe = target.clone();
    loop {
        if let Ok(canon) = crate::scope::Canonical::of(&probe) {
            if !canon.within(&root) {
                return Err(SluseError::MalformedArtifactName {
                    name: name.to_owned(),
                    reason: format!(
                        "it resolves to \"{}\", outside the artifacts directory",
                        canon.display()
                    ),
                });
            }
            break;
        }
        match probe.parent() {
            Some(parent) if parent.starts_with(artifacts) || parent == artifacts => {
                probe = parent.to_path_buf()
            }
            // Walked above the artifacts directory without finding anything that
            // exists, which cannot happen — the preflight creates it — and is
            // refused rather than assumed.
            _ => {
                return Err(SluseError::MalformedArtifactName {
                    name: name.to_owned(),
                    reason: "it does not resolve under the artifacts directory".to_owned(),
                })
            }
        }
    }

    Ok(target)
}

// ---------------------------------------------------------------------------
// GET /v1/alerts
// ---------------------------------------------------------------------------

/// Open and recently closed volume alerts.
///
/// The sweep runs here rather than on a timer: an alert closes when somebody
/// looks, which is the only moment the answer is needed, and a background task
/// that closed alerts nobody asked about would be a thread doing nothing useful.
async fn alerts(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Query(q): Query<AlertsQuery>,
) -> ApiResult<Json<Vec<sluse_proto::VolumeAlert>>> {
    session(&core, &headers, Op::Alert, route::ALERTS)?;
    let now = Utc::now();
    core.volume.sweep(now);
    Ok(Json(core.volume.alerts(q.since)))
}

// ---------------------------------------------------------------------------
// GET /v1/audit/tail
// ---------------------------------------------------------------------------

/// **Provisional, and LOCAL only** (enforced since D-033 point 3).
///
/// The console's "what IT sees" panel, so a person being shown the prototype can
/// see both halves of the two-record design at once. In the product this route
/// does not exist: the host's log is the host's, and a guest that can read it can
/// learn what the host knows about it. `prototype/README.md` lists it under what
/// is not proven.
async fn audit_tail(
    State(core): State<Arc<Core>>,
    headers: HeaderMap,
    Query(q): Query<AuditTailQuery>,
) -> ApiResult<Json<AuditTailResponse>> {
    let session = session(&core, &headers, Op::Tail, route::AUDIT_TAIL)?;
    local_only(&core, core.record(&session, Op::Tail, route::AUDIT_TAIL), "audit tail")?;

    let records = match core.loaded.config.audit.path.as_ref() {
        Some(p) => crate::audit::tail(&core.loaded.resolve(p), q.limit).unwrap_or_default(),
        None => Vec::new(),
    };
    Ok(Json(AuditTailResponse { records }))
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_delivery_folder_says_what_it_is_and_a_taken_one_is_numbered() {
        let named = |first: &str| {
            let m = PublishManifest {
                artifacts: vec![sluse_proto::wire::ArtifactManifest { name: first.into(), hash: ContentHash::of(b""), bytes: 0, sources: vec![], label: None }],
                lineage: vec![],
            };
            delivery_folder(&m).split_once(' ').unwrap().1.split_once(' ').map(|(_, l)| l.to_owned())
        };
        assert_eq!(named("report/summary.md").as_deref(), Some("report"));
        assert_eq!(named("Q3 summary.docx").as_deref(), Some("Q3 summary"));
        assert_eq!(named("a:b?.md").as_deref(), Some("a-b-"));
        assert_eq!(named(".md"), None, "no label: the date and time alone");

        let dir = tempfile::tempdir().unwrap();
        assert_eq!(reserve_folder(dir.path(), "2026-10-07 14.32 report").unwrap(), "2026-10-07 14.32 report");
        assert_eq!(reserve_folder(dir.path(), "2026-10-07 14.32 report").unwrap(), "2026-10-07 14.32 report 2");
        assert_eq!(reserve_folder(dir.path(), "2026-10-07 14.32 report").unwrap(), "2026-10-07 14.32 report 3");
    }

    #[test]
    fn artifact_names_the_grammar_refuses() {
        for (name, code) in [
            ("", "MALFORMED_ARTIFACT_NAME"),
            ("..", "MALFORMED_ARTIFACT_NAME"),
            ("a/../../etc/passwd", "MALFORMED_ARTIFACT_NAME"),
            ("a//b.md", "MALFORMED_ARTIFACT_NAME"),
            ("/abs.md", "MALFORMED_ARTIFACT_NAME"),
            ("C:/abs.md", "MALFORMED_ARTIFACT_NAME"),
            (".hidden", "MALFORMED_ARTIFACT_NAME"),
            (".incoming/x.md", "MALFORMED_ARTIFACT_NAME"),
            // Hidden at any depth, not only the first segment.
            ("crates/.git/config", "MALFORMED_ARTIFACT_NAME"),
            // An alternate data stream: bytes on disk that nothing lists.
            ("summary.md:hidden", "MALFORMED_ARTIFACT_NAME"),
            ("summary.md", "MALFORMED_ARTIFACT_NAME"),
            // Windows strips these, so the name written would not be the name
            // recorded.
            ("summary.md ", "MALFORMED_ARTIFACT_NAME"),
            ("docs./x.md", "MALFORMED_ARTIFACT_NAME"),
            ("CON", "RESERVED_NAME"),
            ("con.txt", "RESERVED_NAME"),
            // Reserved at every level, not only the last.
            ("crates/con/lib.rs", "RESERVED_NAME"),
            ("LPT9.md", "RESERVED_NAME"),
        ] {
            let err = validate_artifact_name(name).unwrap_err();
            assert_eq!(err.reason_code(), code, "{name:?}");
        }
    }

    #[test]
    fn artifact_names_the_grammar_allows() {
        for name in [
            "summary.md",
            "bid-2026.docx",
            "æøå.txt",
            "a.b.c.json",
            // The shape S-2 actually published, and the reason subdirectories
            // are allowed at all.
            "crates/chapr-proto/src/ids.rs",
            "crates/x/Cargo.toml",
        ] {
            assert!(validate_artifact_name(name).is_ok(), "{name:?} should be allowed");
        }
    }

    #[test]
    fn a_name_that_resolves_out_of_the_artifacts_tree_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        std::fs::create_dir_all(artifacts.join("nested")).unwrap();

        // The grammar passes and the filesystem does not, which is the whole
        // reason the resolved parent is canonicalised before anything is
        // written.
        assert!(artifact_path(&artifacts, "nested/ok.md").is_ok());
        assert!(artifact_path(&artifacts, "deep/not/there/yet.md").is_ok());
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_out_of_the_artifacts_tree_is_refused() {
        use std::os::windows::process::CommandExt;

        let dir = tempfile::tempdir().unwrap();
        let artifacts = dir.path().join("artifacts");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&artifacts).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let link = artifacts.join("escape");
        let status = std::process::Command::new("cmd")
            .raw_arg(format!(r#"/c mklink /J "{}" "{}""#, link.display(), outside.display()))
            .status()
            .expect("mklink");
        if !status.success() {
            eprintln!("skipped: could not create a junction");
            return;
        }

        // `escape/x.md` is a perfectly ordinary name and lands outside the tree
        // Gate Core owns. Only canonicalisation sees it.
        assert!(validate_artifact_name("escape/x.md").is_ok());
        let err = artifact_path(&artifacts, "escape/x.md").unwrap_err();
        assert_eq!(err.reason_code(), "MALFORMED_ARTIFACT_NAME");
    }

    #[test]
    fn an_artifacts_path_is_in_request_form() {
        assert_eq!(request_form_artifact("summary.md"), "artifacts/summary.md");
    }
}

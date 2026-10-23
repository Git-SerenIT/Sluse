// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The console's loopback API.
//!
//! Every route here answers one question a person has about a run in progress.
//! None of them decides anything: the broker decides, this relays, and where it
//! computes — the inventory's comparison — it is careful about what it will not
//! claim ([`super::inventory`]).
//!
//! ## A second process, one journal
//!
//! `--console` and `--mcp` are mutually exclusive, so the console runs beside
//! the MCP endpoint rather than inside it. They share the run's workspace and
//! its journal file: the endpoint appends, the console reads. So the console
//! **re-reads the journal on every request** instead of holding a snapshot. A
//! console showing a run that has moved on is worse than one that costs a file
//! read, and the run is one agent working, not a request rate worth optimising
//! against.
//!
//! One route writes: `POST /api/inventory/clear`, which is user-initiated and
//! rare. It opens the journal for append, records the clear and closes it.
//!
//! ## What the console never has
//!
//! No credential, no scope opinion, no host path it was not given. It shows
//! `SourceView::address`, which the broker puts there for exactly this purpose
//! and which is the one host path the guest is told (M1's choice, and still on
//! the Known Issues list in `prototype/README.md`).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use sluse_proto::audit::{AuditRecord, Capability, Op, Outcome, UserRef};
use sluse_proto::{Audience, BoxId, ConfigView, ContentHash, SessionId, SluseError};

use super::inventory::{self, InventoryItem, InventoryState};
use crate::broker_client::BrokerClient;
use crate::journal;

/// Everything the console needs to answer, and nothing it could decide with.
pub struct Console {
    pub broker: BrokerClient,
    pub view: ConfigView,
    pub workspace: PathBuf,
    pub journal_dir: PathBuf,
    pub box_id: BoxId,
    pub config_version: ContentHash,
    pub session: SessionId,
    /// Where the console's own HTML, CSS and JavaScript live.
    pub ui_dir: PathBuf,
    /// How much of the journal the host's mirror holds (D-027 point 5).
    pub mirrored: std::sync::atomic::AtomicU64,
    /// The device is LOCAL, the only place the greyed listing and the host's
    /// audit tail are served. Elsewhere the console does not ask, so a refusal
    /// on the host's record is the agent asking (D-045 point 2).
    pub local: bool,
    /// The deployment the box's config belongs to, for the console's foot
    /// ("Finance pilot, revision 5"). Display only.
    pub deployment: Option<sluse_proto::config::Deployment>,
}

/// The run's session: the one the workspace records now, else the console's own.
///
/// Asked on every call, because the run can change session under a running
/// console: after a broker restart the console, started first, found the
/// remembered session gone and took a fresh one, while the MCP process took
/// another and recorded it (S-3 run 2, 2026-09-28). The console's views then
/// read an empty journal for the whole run.
fn run_session(workspace: &std::path::Path, own: &SessionId) -> SessionId {
    crate::session::remembered(workspace).unwrap_or_else(|| own.clone())
}

impl Console {
    fn session_now(&self) -> SessionId {
        run_session(&self.workspace, &self.session)
    }

    /// This run's journal, re-read from disk. See the module note.
    fn records(&self) -> Result<Vec<AuditRecord>, ApiError> {
        let path = journal::session_path(&self.journal_dir, &self.session_now());
        journal::read_records(&path).map_err(|e| {
            ApiError(SluseError::Internal { message: format!("reading the journal: {e}") })
        })
    }

    /// Every session's journal in this workspace, for the inventory and
    /// Clear. The workspace outlives a session and every reopen starts a new
    /// one, so the current session's file alone left earlier copies unlisted
    /// and untouched by Clear (review R-04).
    fn all_records(&self) -> Result<Vec<AuditRecord>, ApiError> {
        journal::read_all(&self.journal_dir).map_err(|e| {
            ApiError(SluseError::Internal { message: format!("reading the journals: {e}") })
        })
    }
}

// ---------------------------------------------------------------------------
// Serving
// ---------------------------------------------------------------------------

pub fn router(state: Arc<Console>) -> Router {
    Router::new()
        .route("/api/state", get(state_))
        .route("/api/sources", get(sources))
        .route("/api/list", get(list))
        .route("/api/journal", get(journal_))
        .route("/api/provenance", get(provenance))
        .route("/api/inventory", get(inventory_))
        .route("/api/inventory/check", post(check))
        .route("/api/inventory/clear", post(clear))
        .route("/api/alerts", get(alerts))
        .route("/api/audit", get(audit))
        .route("/api/sign-out", post(sign_out))
        .route("/api/launch", post(launch))
        // Everything that is not an API route is a file, and an unknown file is
        // a 404 rather than the index: a console that answered every path with
        // its own page would make a typo look like a working screen.
        .fallback(ui)
        .layer(axum::middleware::from_fn(guard))
        .with_state(state)
}

/// Every POST carries this header, which the console's own page sets.
pub const CONSOLE_HEADER: &str = "x-sluse-console";

/// The console is on loopback, and a page open in the kiosk's own browser is
/// on the same machine. Two checks keep such a page from using it:
/// - **The Host must be the console's own name.** A page on a domain it
///   re-pointed at 127.0.0.1 (DNS rebinding) sends its own name.
/// - **A POST must carry [`CONSOLE_HEADER`].** A cross-site page cannot add a
///   header without a CORS preflight, which this server never answers.
///
/// Without these, any page could clear the workspace or sign the user out.
async fn guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let host = req.headers().get(axum::http::header::HOST).and_then(|h| h.to_str().ok()).unwrap_or("");
    let name = host.rsplit_once(':').map_or(host, |(n, _)| n);
    if !matches!(name, "localhost" | "127.0.0.1" | "[::1]") {
        return (StatusCode::MISDIRECTED_REQUEST, "not the console's name").into_response();
    }
    if req.method() == axum::http::Method::POST && !req.headers().contains_key(CONSOLE_HEADER) {
        return (StatusCode::FORBIDDEN, "not from the console's page").into_response();
    }
    next.run(req).await
}

#[derive(serde::Deserialize)]
pub struct LaunchBody {
    pub app: String,
}

/// Open one of the box's apps in the kiosk (D-027 point 3), from a fixed
/// list: the request names an app, never a command.
async fn launch(Json(body): Json<LaunchBody>) -> Response {
    let command = match body.app.as_str() {
        // A login shell, so `~/.local/bin`, where the vendors install, is on
        // the path: `claude` was not found in a plain one (L1, 2026-10-05).
        // Each with its app id, which sway names the tab by (sway.conf, Q5).
        "terminal" => "foot --app-id=sluse-terminal bash -l",
        // The CLIs in their own terminal through `packaging/box/kiosk/cli`,
        // which keeps the window open when one stops with an error. A script,
        // because sway strips the quotes from an `exec` line.
        "claude-code" => "foot --app-id=sluse-claude-code /usr/local/libexec/sluse/cli claude",
        "codex" => "foot --app-id=sluse-codex /usr/local/libexec/sluse/cli codex",
        "vibe" => "foot --app-id=sluse-vibe /usr/local/libexec/sluse/cli vibe",
        "claude-desktop" => "claude-desktop",
        _ => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "code": "UNKNOWN_APP" }))).into_response();
        }
    };
    match sway_exec(command) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({ "code": "NO_DESKTOP", "detail": e })))
            .into_response(),
    }
}

/// `swaymsg exec`, on this user's sway: its socket is the one under
/// `/run/user/<uid>/` this process can read.
fn sway_exec(command: &str) -> Result<(), String> {
    let sock = std::fs::read_dir("/run/user")
        .map_err(|e| e.to_string())?
        .flatten()
        .filter_map(|d| std::fs::read_dir(d.path()).ok())
        .flatten()
        .flatten()
        .map(|e| e.path())
        .find(|p| p.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("sway-ipc.") && n.ends_with(".sock")))
        .ok_or("no sway session for this user")?;
    let status = std::process::Command::new("swaymsg")
        .env("SWAYSOCK", sock)
        .args(["exec", command])
        .stdout(std::process::Stdio::null())
        .status()
        .map_err(|e| format!("swaymsg: {e}"))?;
    if status.success() { Ok(()) } else { Err(format!("swaymsg exited {status}")) }
}

/// The console's own files. See [`super::assets`].
async fn ui(State(c): State<Arc<Console>>, uri: axum::http::Uri) -> Response {
    super::assets::serve_file(&c.ui_dir, uri.path().trim_start_matches('/'))
}

/// Bind and serve until the process ends.
///
/// **Loopback is asserted here, not assumed from the config.** `consoleListen`
/// is a config field and a config is a file someone can edit; binding a console
/// with no authentication to a routable address would put a window into the run
/// on the network. Refused rather than warned about.
pub async fn serve(state: Arc<Console>, addr: SocketAddr) -> Result<(), String> {
    require_loopback(addr)?;
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| format!("{}: {e}", sluse_proto::ports::label(&addr.to_string())))?;
    tracing::info!(%addr, "console serving");
    axum::serve(listener, router(state)).await.map_err(|e| e.to_string())
}

/// Refuse a console address that anything but this machine could reach.
///
/// Its own function so it can be tested without a broker: the rule is the
/// interesting part, not the socket.
pub fn require_loopback(addr: SocketAddr) -> Result<(), String> {
    if addr.ip().is_loopback() {
        return Ok(());
    }
    Err(format!(
        "consoleListen is {addr}, which is not a loopback address. The console has no \
         authentication — M5, and written down as a limitation rather than discovered as one — \
         so it is served on loopback only."
    ))
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A [`SluseError`] on its way out of a console route.
///
/// The console is not the agent, so nothing is blinded here: a person looking
/// at their own run is told what actually happened. The blinding in
/// [`crate::blinders`] is for the model's context, and confusing the two would
/// either lie to the user or leak to the agent.
pub struct ApiError(pub SluseError);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let code = StatusCode::from_u16(self.0.http_status()).unwrap_or(StatusCode::BAD_GATEWAY);
        (code, Json(self.0)).into_response()
    }
}

type ApiResult<T> = Result<T, ApiError>;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunState {
    pub box_id: BoxId,
    pub session: SessionId,
    /// The config the **endpoint** loaded.
    pub config_version: ContentHash,
    pub user: UserRef,
    pub max_read_bytes: u64,
    pub sources: usize,
    /// What the broker says right now, or why it could not be asked. The console
    /// says "not reachable" rather than showing nothing, because a blank panel
    /// reads as "nothing is happening".
    pub broker: BrokerState,
    /// A development device: the console lists what the agents cannot see
    /// and shows the host's record beside the box's (D-033, D-045 point 2).
    pub local: bool,
    pub deployment: Option<sluse_proto::config::Deployment>,
}

// `rename_all_fields` as well as `rename_all`: the first renames the variants,
// the second the fields inside them, and without it this one enum would answer
// in snake_case while every other field on the wire is camelCase.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase", tag = "status")]
pub enum BrokerState {
    Serving {
        posture_id: sluse_proto::PostureId,
        /// The config the **broker** is enforcing from. Shown beside the
        /// endpoint's own so a mismatch is visible rather than inferred: only
        /// the broker's copy decides anything, and a guest running against a
        /// different one is worth seeing immediately.
        config_version: ContentHash,
        sessions: usize,
        /// Who the box is signed in as (D-022). The broker's answer, asked on
        /// every refresh: the page never remembers a sign-in of its own.
        signed_in: Option<UserRef>,
        /// The person signed out in the box (Q7), and nobody since.
        signed_out: bool,
        /// Sluse's count for each source in the volume window (Q36).
        volume: Vec<sluse_proto::wire::SourceCount>,
    },
    Unreachable {
        detail: String,
    },
}

async fn state_(State(c): State<Arc<Console>>) -> Json<RunState> {
    // `status`, not `health`: `/v1/health` mints a session on every call, and a
    // console panel that refreshes would evict a live run's session out of a
    // bounded registry. That is why `/v1/status` exists at all.
    let broker = match c.broker.status_now().await {
        Ok(s) => BrokerState::Serving {
            posture_id: s.posture_id,
            config_version: s.config_version,
            sessions: s.sessions,
            signed_in: s.signed_in,
            signed_out: s.signed_out,
            volume: s.volume,
        },
        Err(e) => BrokerState::Unreachable { detail: e.to_string() },
    };

    Json(RunState {
        box_id: c.box_id.clone(),
        session: c.session_now(),
        config_version: c.config_version.clone(),
        // Who the broker is acting as, as its answer just now said: after a
        // sign-in this is the signed-in person, not the start-up identity.
        user: c.broker.acting_as(),
        max_read_bytes: c.view.max_read_bytes,
        sources: c.view.sources.len(),
        broker,
        local: c.local,
        deployment: c.deployment.clone(),
    })
}

async fn sources(State(c): State<Arc<Console>>) -> Json<ConfigView> {
    Json(c.view.clone())
}

// ---------------------------------------------------------------------------
// Sign-out (D-022). The sign-in is the host's (D-036).
// ---------------------------------------------------------------------------

/// The console's sign-out button. User-initiated only (D-022).
async fn sign_out(State(c): State<Arc<Console>>) -> ApiResult<Json<sluse_proto::SignedOut>> {
    c.broker.sign_out().await.map(Json).map_err(ApiError)
}

// ---------------------------------------------------------------------------
// Browsing
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct ListQuery {
    /// `<source>` or `<source>/<relative path>`.
    pub path: String,
}

/// The console's listing: what the agent sees (D-033 point 1).
///
/// The console runs in the box, and anything in the box can call this route,
/// the agent included, so the greyed [`Audience::User`] listing handed it the
/// names D-008 withholds. The broker now serves `User` in LOCAL only, where
/// there is no box: there the greyed view stays, and everywhere else this
/// asks as [`Audience::Agent`]. A greyed view for a person waits for a
/// surface outside the box.
async fn list(
    State(c): State<Arc<Console>>,
    Query(q): Query<ListQuery>,
) -> ApiResult<Json<sluse_proto::ListResponse>> {
    let audience = if c.local { Audience::User } else { Audience::Agent };
    c.broker.list_as(&q.path, audience).await
    .map(Json)
    .map_err(ApiError)
}

async fn journal_(State(c): State<Arc<Console>>) -> ApiResult<Json<Vec<AuditRecord>>> {
    Ok(Json(c.records()?))
}

/// Every publish this box made, in every session (Q37), newest first, with
/// the sources the agent declared for it and everything admitted in its
/// session (D-055).
///
/// The provenance card comes from the endpoint's journal rather than from the
/// artifact's manifest: the manifest is written into the artifacts zone, which
/// is **on the host**, and the console runs in the guest. The two agree by
/// construction — the endpoint computed the lineage it sent — and where they
/// could not, the host's copy is the record that counts.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Provenance {
    pub session_id: SessionId,
    /// `artifacts/<folder>/<name>`: the folder in Sluse Artifacts (D-031).
    pub path: String,
    /// Why a refused or failed publish was not published, as recorded.
    pub reason: Option<String>,
    pub publish_id: Option<sluse_proto::PublishId>,
    pub artifact: Option<String>,
    pub hash: Option<ContentHash>,
    pub bytes: Option<u64>,
    pub at: DateTime<Utc>,
    pub outcome: Outcome,
    /// `None` on a publish record from before D-055, which declared nothing.
    pub sources: Option<Vec<sluse_proto::LineageItem>>,
    pub lineage: Vec<sluse_proto::LineageItem>,
}

async fn provenance(State(c): State<Arc<Console>>) -> ApiResult<Json<Vec<Provenance>>> {
    let mut out: Vec<Provenance> = c
        .all_records()?
        .into_iter()
        .filter(|r| r.op == Op::Publish)
        .map(|r| Provenance {
            session_id: r.session_id,
            path: r.path_requested,
            reason: r.reason,
            publish_id: r.publish_id,
            artifact: r.artifact,
            hash: r.hash,
            bytes: r.bytes,
            at: r.ts,
            outcome: r.outcome,
            sources: r.sources,
            lineage: r.lineage.unwrap_or_default(),
        })
        .collect();
    // Newest first: a provenance panel is read from the top.
    out.sort_by_key(|p| std::cmp::Reverse(p.at));
    Ok(Json(out))
}

// ---------------------------------------------------------------------------
// Inventory
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryRow {
    #[serde(flatten)]
    pub item: InventoryItem,
    pub state: InventoryState,
    /// When the source was last asked about this row. Absent on every row of an
    /// unrefreshed inventory, and absent on a row whose state nobody verified —
    /// a timestamp beside an unverified state reads as verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<DateTime<Utc>>,
}

/// The inventory without asking the source.
///
/// Every row is `Current`-shaped data with no claim attached: the state is
/// whatever can be known locally, which is [`InventoryState::Missing`] or
/// [`InventoryState::Unknown`]. Refreshing is a separate, deliberate act
/// because it costs an audit record per file on the host.
async fn inventory_(State(c): State<Arc<Console>>) -> ApiResult<Json<Vec<InventoryRow>>> {
    let items = inventory::items_from_journal(&c.all_records()?, &c.workspace);
    Ok(Json(
        items
            .into_iter()
            .map(|item| {
                let state = if item.local_present {
                    InventoryState::Unknown
                } else {
                    InventoryState::Missing
                };
                InventoryRow { item, state, checked_at: None }
            })
            .collect(),
    ))
}

/// Ask the source about one copy, and classify what it says (Q33): the page
/// asks for each in turn and counts the answers, "4 of 10 files asked".
///
/// **User-initiated, never a timer.** `/v1/stat` writes an audit record per
/// call, so a console that polled would fill the host's trail with questions
/// nobody asked; the volume is bounded by what a person clicks
/// (`docs/sluse_prototype.md`, the M2 review). One at a time on purpose:
/// concurrency would turn a click into a burst against the source and into
/// the volume window the broker is counting.
async fn check(State(c): State<Arc<Console>>, Json(q): Json<CheckQuery>) -> ApiResult<Json<InventoryRow>> {
    let item = inventory::items_from_journal(&c.all_records()?, &c.workspace)
        .into_iter()
        .find(|i| i.path == q.path)
        .ok_or_else(|| ApiError(SluseError::NotFound { raw: q.path.clone() }))?;
    let stat = c.broker.stat(&item.path, None).await;
    let state = inventory::classify(&item, stat);
    let checked_at = state.is_answered().then(Utc::now);
    Ok(Json(InventoryRow { item, state, checked_at }))
}

#[derive(serde::Deserialize)]
pub struct CheckQuery {
    pub path: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cleared {
    pub files: usize,
    pub bytes: u64,
    /// What could not be removed, with the reason. Reported rather than
    /// swallowed: a clear that half-worked and said it worked is how a person
    /// comes to believe the workspace is empty when it is not.
    pub failed: Vec<String>,
}

/// Delete the admitted files and record that a person did it.
///
/// The journal is **not** deleted. The record of what was admitted is the audit
/// trail; clearing the workspace removes the copies, not the history, and a
/// clear is itself an [`Op::Clear`] record so the gap in the inventory has an
/// explanation beside it.
async fn clear(State(c): State<Arc<Console>>) -> ApiResult<Json<Cleared>> {
    let items = inventory::items_from_journal(&c.all_records()?, &c.workspace);

    let cleared = remove_admitted(&items);
    // And what a fetch killed mid-stream left: never inventory, never kept.
    crate::workspace::sweep_partial(&c.workspace);

    let session = c.session_now();
    let path = journal::session_path(&c.journal_dir, &session);
    let mut j = crate::Journal::open_session(&c.journal_dir, &session).map_err(|e| {
        ApiError(SluseError::Internal {
            message: format!("opening the journal at {} to record the clear: {e}", path.display()),
        })
    })?;
    j.record(AuditRecord {
        writer: sluse_proto::audit::Writer::Endpoint,
        box_id: c.box_id.clone(),
        user: c.broker.acting_as(),
        config_version: c.config_version.clone(),
        session_id: session.clone(),
        ts: Utc::now(),
        op: Op::Clear,
        // Not a path: a clear is about the workspace, not about one file. The
        // count is in the reason so the record says what happened on its own.
        path_requested: "(workspace)".to_owned(),
        path_resolved: None,
        scope: None,
        capability: Capability::Bytes,
        outcome: if cleared.failed.is_empty() { Outcome::Admitted } else { Outcome::Error },
        reason: Some(format!("cleared {} file(s), {} failed", cleared.files, cleared.failed.len())),
        detail: None,
        hash: None,
        bytes: Some(cleared.bytes),
        admission_id: None,
        publish_id: None,
        artifact: None,
        lineage: None,
        sources: None,
        label: None,
        posture_id: None,
    });
    drop(j);
    journal::mirror(&c.broker, &path, &session, &c.mirrored).await;

    Ok(Json(cleared))
}

/// Delete the admitted copies, and say exactly what happened to each.
///
/// Split out from the route so it can be tested without a broker: deleting
/// files is the part with consequences, and the part a test should hold still.
fn remove_admitted(items: &[InventoryItem]) -> Cleared {
    let mut cleared = Cleared { files: 0, bytes: 0, failed: Vec::new() };
    for item in items {
        if !item.local_present {
            continue;
        }
        match std::fs::remove_file(&item.local) {
            Ok(()) => {
                cleared.files += 1;
                cleared.bytes += item.bytes.unwrap_or(0);
                // The sidecar goes with its file: left behind, it would still
                // name the host path and admission of a copy that is gone.
                let sidecar = crate::manifest::path_for(&item.local);
                match std::fs::remove_file(&sidecar) {
                    Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                        cleared.failed.push(format!("{}: {e}", sidecar.display()));
                    }
                    _ => {}
                }
            }
            // Reported, never swallowed: a clear that half-worked and said it
            // worked is how a person comes to believe the workspace is empty
            // when it is not.
            Err(e) => cleared.failed.push(format!("{}: {e}", item.path)),
        }
    }
    cleared
}

// ---------------------------------------------------------------------------
// Alerts and the audit tail
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct SinceQuery {
    pub since: Option<DateTime<Utc>>,
}

async fn alerts(
    State(c): State<Arc<Console>>,
    Query(q): Query<SinceQuery>,
) -> ApiResult<Json<Vec<sluse_proto::VolumeAlert>>> {
    c.broker.alerts(q.since).await.map(Json).map_err(ApiError)
}

#[derive(serde::Deserialize)]
pub struct LimitQuery {
    pub limit: Option<usize>,
}

/// The **host's** trail, as the broker will show it.
///
/// Deliberately not the guest's journal, which `/api/journal` serves: the two
/// records of one admission are written on opposite sides of the boundary and
/// the console shows both rather than merging them. A merged view would hide
/// exactly the disagreement the join exists to detect (invariant 7).
async fn audit(
    State(c): State<Arc<Console>>,
    Query(q): Query<LimitQuery>,
) -> ApiResult<Json<sluse_proto::AuditTailResponse>> {
    if !c.local {
        return Err(ApiError(SluseError::AudienceNotServed { audience: "audit tail".into() }));
    }
    c.broker.audit_tail(q.limit.unwrap_or(50)).await.map(Json).map_err(ApiError)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn the_console_answers_its_own_page_and_no_other() {
        use tower::ServiceExt;
        let app = || {
            Router::new()
                .route("/api/x", post(|| async { "done" }).get(|| async { "read" }))
                .layer(axum::middleware::from_fn(guard))
        };
        let req = |method: &str, host: &str, header: bool| {
            let mut b = axum::http::Request::builder().method(method).uri("/api/x").header("host", host);
            if header {
                b = b.header(CONSOLE_HEADER, "1");
            }
            b.body(axum::body::Body::empty()).unwrap()
        };
        let status = |r: Response| r.status();
        assert_eq!(status(app().oneshot(req("POST", "localhost:7582", true)).await.unwrap()), StatusCode::OK);
        assert_eq!(status(app().oneshot(req("GET", "127.0.0.1:7582", false)).await.unwrap()), StatusCode::OK);
        // A cross-site form: no header.
        assert_eq!(status(app().oneshot(req("POST", "localhost:7582", false)).await.unwrap()), StatusCode::FORBIDDEN);
        // DNS rebinding: the attacker's own name, even with the header.
        for host in ["evil.example:7582", "localhost.evil.example", ""] {
            assert_eq!(
                status(app().oneshot(req("POST", host, true)).await.unwrap()),
                StatusCode::MISDIRECTED_REQUEST,
                "{host}"
            );
        }
    }

    use super::*;

    #[test]
    fn the_console_reads_whichever_session_the_run_records_now() {
        let ws = tempfile::tempdir().unwrap();
        let own = SessionId::new_unchecked("sess-console-own");
        // No run yet: the console's own.
        assert_eq!(run_session(ws.path(), &own), own);
        // The MCP process attaches after the console started.
        let run = SessionId::new_unchecked("sess-run-b9ba0434");
        crate::session::attach(ws.path(), &run, false, Utc::now()).unwrap();
        assert_eq!(run_session(ws.path(), &own), run);
    }

    #[test]
    fn a_console_address_that_is_not_loopback_is_refused() {
        // The console has no authentication and `consoleListen` is a config
        // field — a file someone can edit. Binding an unauthenticated window
        // into a live run to a routable address is refused here rather than
        // warned about, because the warning would be in a log nobody reads
        // until afterwards.
        for bad in ["0.0.0.0:7582", "192.168.221.50:7582", "[::]:7582"] {
            let err = require_loopback(bad.parse().unwrap()).unwrap_err();
            assert!(err.contains("loopback"), "{bad}: {err}");
        }
        for good in ["127.0.0.1:7582", "[::1]:7582"] {
            require_loopback(good.parse().unwrap())
                .unwrap_or_else(|e| panic!("{good} is loopback: {e}"));
        }
    }

    #[test]
    fn clearing_removes_the_copies_and_reports_what_it_could_not() {
        let dir = tempfile::tempdir().unwrap();
        let present = dir.path().join("here.md");
        std::fs::write(&present, b"body").unwrap();
        let sidecar = crate::manifest::path_for(&present);
        std::fs::write(&sidecar, b"{}").unwrap();

        let item = |path: &str, local: PathBuf, local_present: bool| InventoryItem {
            path: path.to_owned(),
            source: "fixture".to_owned(),
            hash: ContentHash::of(b"body"),
            admission_id: None,
            admitted_at: Utc::now(),
            bytes: Some(4),
            local,
            local_present,
            sidecar: false,
        };

        let cleared = remove_admitted(&[
            item("fixture/in-scope/here.md", present.clone(), true),
            // Already gone: skipped, not counted, not an error. A `Missing` row
            // is not a failure to clear.
            item("fixture/in-scope/gone.md", dir.path().join("gone.md"), false),
            // Claims to be there and is not: that *is* reported, because the
            // difference between the two cases is whether we were surprised.
            item("fixture/in-scope/lying.md", dir.path().join("lying.md"), true),
        ]);

        assert!(!present.exists(), "the admitted copy is gone");
        assert!(!sidecar.exists(), "and its sidecar with it");
        assert_eq!(cleared.files, 1);
        assert_eq!(cleared.bytes, 4);
        assert_eq!(cleared.failed.len(), 1);
        assert!(cleared.failed[0].starts_with("fixture/in-scope/lying.md:"), "{:?}", cleared.failed);
    }
}

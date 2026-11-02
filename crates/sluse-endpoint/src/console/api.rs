// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The console: what it asks and does, as plain calls on [`Console`].
//!
//! The calls are the console's whole surface. The console
//! (`crates/sluse-console`, D-079) makes them in its own process, so there is
//! no port for anything else in the box to call: until 0.3 they were a
//! loopback HTTP API any process in the box could reach, the agent's
//! included. `sluse-endpoint --query` prints three of them as JSON for the
//! acceptance script.
//!
//! Every call here answers one question a person has about a run in progress.
//! None of them decides anything: the Gate decides, this relays, and where it
//! computes — the inventory's comparison — it is careful about what it will not
//! claim ([`super::inventory`]).
//!
//! ## A second process, one journal
//!
//! The console runs beside the MCP endpoint rather than inside it. They share the run's workspace and
//! its journal file: the endpoint appends, the console reads. So the console
//! **re-reads the journal on every request** instead of holding a snapshot. A
//! console showing a run that has moved on is worse than one that costs a file
//! read, and the run is one agent working, not a request rate worth optimising
//! against.
//!
//! One call writes: [`Console::clear`], which is user-initiated and rare. It opens the journal for append, records the clear and closes it.
//!
//! ## What the console never has
//!
//! No credential, no scope opinion, no host path it was not given. It shows
//! `SourceView::address`, which the Gate puts there for exactly this purpose
//! and which is the one host path the guest is told (M1's choice, and still on
//! the Known Issues list in `prototype/README.md`).

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use sluse_proto::audit::{AuditRecord, Capability, Op, Outcome, UserRef};
use sluse_proto::{Audience, BoxId, ConfigView, ContentHash, SessionId, SluseError};

use super::inventory::{self, InventoryItem, InventoryState};
use crate::gate_client::GateClient;
use crate::journal;

/// Everything the console needs to answer, and nothing it could decide with.
pub struct Console {
    pub gate: GateClient,
    pub view: ConfigView,
    pub workspace: PathBuf,
    pub journal_dir: PathBuf,
    pub box_id: BoxId,
    pub config_version: ContentHash,
    pub session: SessionId,
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
/// console: after a Gate restart the console, started first, found the
/// remembered session gone and took a fresh one, while the MCP process took
/// another and recorded it (S-3 run 2, 2026-09-28). The console's views then
/// read an empty journal for the whole run.
fn run_session(workspace: &std::path::Path, own: &SessionId) -> SessionId {
    crate::session::remembered(workspace).unwrap_or_else(|| own.clone())
}

impl Console {
    /// Join the run the config's workspace records, or wait for one.
    ///
    /// **It joins the run rather than starting one.** The journal is per
    /// session and the session belongs to the run, so a console that minted
    /// its own would read an empty file and show a person nothing while their
    /// agent worked. It takes the session the workspace remembers, and only
    /// falls back to a fresh one when there is no run to join yet, which is
    /// still worth showing: the sources and the Gate are worth looking at
    /// before anything has been admitted.
    ///
    /// It does **not** call [`crate::session::attach`]. Recording a session
    /// is the running endpoint's business; a console that wrote there would
    /// claim a run it is only watching.
    pub async fn join(loaded: &sluse_proto::Loaded) -> Result<Console, String> {
        let workspace = loaded.resolve(&loaded.config.workspace);
        let remembered = crate::session::remembered(&workspace);
        let joined = remembered.is_some();
        let (client, health, _) = crate::gate_client::connect_resuming(loaded, remembered).await?;
        if joined {
            tracing::info!(session = %client.session(), "console joined the run's session");
        } else {
            tracing::warn!("no run to join yet; the journal and inventory will be empty until one starts");
        }
        let view = client.config_view().await.map_err(|e| format!("the Gate refused the config view: {e}"))?;
        let local = client.status_now().await.ok().and_then(|s| s.environment) == Some(sluse_proto::Environment::Local);
        Ok(Console {
            session: client.session().clone(),
            gate: client,
            view,
            workspace,
            journal_dir: loaded.resolve(&loaded.config.journal_dir),
            box_id: health.box_id.clone(),
            config_version: health.config_version.clone(),
            mirrored: std::sync::atomic::AtomicU64::new(0),
            local,
            deployment: loaded.config.deployment.clone(),
        })
    }

    fn session_now(&self) -> SessionId {
        run_session(&self.workspace, &self.session)
    }

    /// Every session's journal in this workspace, for the inventory and
    /// Clear. The workspace outlives a session and every reopen starts a new
    /// one, so the current session's file alone left earlier copies unlisted
    /// and untouched by Clear (review R-04).
    fn all_records(&self) -> Result<Vec<AuditRecord>, SluseError> {
        journal::read_all(&self.journal_dir)
            .map_err(|e| SluseError::Internal { message: format!("reading the journals: {e}") })
    }
}

/// Why an app did not open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launch {
    /// Not one of the box's apps: the console names an app, never a command.
    Unknown,
    /// sway could not be asked, with what it said.
    NoDesktop(String),
}

/// Open one of the box's apps in the kiosk (D-027 point 3), from a fixed
/// list: the caller names an app, never a command.
pub fn launch_app(app: &str) -> Result<(), Launch> {
    let command = match app {
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
        "chatgpt" => "/usr/local/libexec/sluse/chatgpt",
        _ => return Err(Launch::Unknown),
    };
    sway_exec(command).map_err(Launch::NoDesktop)
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
    /// What the Gate says right now, or why it could not be asked. The console
    /// says "not reachable" rather than showing nothing, because a blank panel
    /// reads as "nothing is happening".
    pub gate: GateState,
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
pub enum GateState {
    Serving {
        posture_id: sluse_proto::PostureId,
        /// The config the **Gate** is enforcing from. Shown beside the
        /// endpoint's own so a mismatch is visible rather than inferred: only
        /// the Gate's copy decides anything, and a guest running against a
        /// different one is worth seeing immediately.
        config_version: ContentHash,
        sessions: usize,
        /// Who the box is signed in as (D-022). The Gate's answer, asked on
        /// every refresh: the page never remembers a sign-in of its own.
        signed_in: Option<UserRef>,
        /// The person signed out in the box (Q7), and nobody since.
        signed_out: bool,
        /// Sluse's count for each source in the volume window (Q36).
        volume: Vec<sluse_proto::wire::SourceCount>,
        /// A sign-in window is open (D-075): the box's sign-in browser
        /// (`signin-browser`) ends when it closes.
        sign_in_window: bool,
    },
    Unreachable {
        detail: String,
    },
}

impl Console {
    /// The run's state and the Gate's, as the console's header and Work show.
    pub async fn state(&self) -> RunState {
        // `status`, not `health`: `/v1/health` mints a session on every call,
        // and a console that refreshes would evict a live run's session out of
        // a bounded registry. That is why `/v1/status` exists at all.
        let gate = match self.gate.status_now().await {
            Ok(s) => GateState::Serving {
                posture_id: s.posture_id,
                config_version: s.config_version,
                sessions: s.sessions,
                signed_in: s.signed_in,
                signed_out: s.signed_out,
                volume: s.volume,
                sign_in_window: s.sign_in_window,
            },
            Err(e) => GateState::Unreachable { detail: e.to_string() },
        };
        RunState {
            box_id: self.box_id.clone(),
            session: self.session_now(),
            config_version: self.config_version.clone(),
            // Who the Gate is acting as, as its answer just now said: after a
            // sign-in this is the signed-in person, not the start-up identity.
            user: self.gate.acting_as(),
            max_read_bytes: self.view.max_read_bytes,
            sources: self.view.sources.len(),
            gate,
            local: self.local,
            deployment: self.deployment.clone(),
        }
    }

    /// The console's sign-out button. User-initiated only (D-022); the
    /// sign-in is the host's (D-036).
    pub async fn sign_out(&self) -> Result<sluse_proto::SignedOut, SluseError> {
        self.gate.sign_out().await
    }

    /// The console's listing: what the agent sees (D-033 point 1).
    ///
    /// The console runs in the box, and anything in the box could call the
    /// route that served this, the agent included, so the greyed
    /// [`Audience::User`] listing handed it the names D-008 withholds. The Gate
    /// serves `User` in LOCAL only, where there is no box: there the greyed
    /// view stays, and everywhere else this asks as [`Audience::Agent`]. A
    /// greyed view for a person waits for a surface outside the box.
    ///
    /// **A click, never a timer** (D-032): the Gate records every listing.
    pub async fn list(&self, path: &str) -> Result<sluse_proto::ListResponse, SluseError> {
        let audience = if self.local { Audience::User } else { Audience::Agent };
        self.gate.list_as(path, audience).await
    }

    /// This run's journal, re-read from disk. See the module note.
    pub fn journal(&self) -> Result<Vec<AuditRecord>, SluseError> {
        let path = journal::session_path(&self.journal_dir, &self.session_now());
        journal::read_records(&path).map_err(|e| SluseError::Internal { message: format!("reading the journal: {e}") })
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

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

impl Console {
    /// Every publish this box made, in every session, newest first.
    pub fn provenance(&self) -> Result<Vec<Provenance>, SluseError> {
        let mut out: Vec<Provenance> = self
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
        Ok(out)
    }
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

impl Console {
    /// The inventory without asking the source.
    ///
    /// Every row is `Current`-shaped data with no claim attached: the state is
    /// whatever can be known locally, which is [`InventoryState::Missing`] or
    /// [`InventoryState::Unknown`]. Refreshing is a separate, deliberate act
    /// because it costs an audit record per file on the host.
    pub fn inventory(&self) -> Result<Vec<InventoryRow>, SluseError> {
        let items = inventory::items_from_journal(&self.all_records()?, &self.workspace);
        Ok(items
            .into_iter()
            .map(|item| {
                let state = if item.local_present { InventoryState::Unknown } else { InventoryState::Missing };
                InventoryRow { item, state, checked_at: None }
            })
            .collect())
    }

    /// Ask the source about one copy, and classify what it says (Q33): the
    /// console asks for each in turn and counts the answers, "4 of 10 files
    /// asked".
    ///
    /// **User-initiated, never a timer.** `/v1/stat` writes an audit record
    /// per call, so a console that polled would fill the host's trail with
    /// questions nobody asked; the volume is bounded by what a person clicks
    /// (`docs/sluse_prototype.md`, the M2 review). One at a time on purpose:
    /// concurrency would turn a click into a burst against the source and into
    /// the volume window the Gate is counting.
    pub async fn check(&self, path: &str) -> Result<InventoryRow, SluseError> {
        let item = inventory::items_from_journal(&self.all_records()?, &self.workspace)
            .into_iter()
            .find(|i| i.path == path)
            .ok_or_else(|| SluseError::NotFound { raw: path.to_owned() })?;
        let stat = self.gate.stat(&item.path, None).await;
        let state = inventory::classify(&item, stat);
        let checked_at = state.is_answered().then(Utc::now);
        Ok(InventoryRow { item, state, checked_at })
    }

    /// Delete the admitted files and record that a person did it.
    ///
    /// The journal is **not** deleted. The record of what was admitted is the
    /// audit trail; clearing the workspace removes the copies, not the
    /// history, and a clear is itself an [`Op::Clear`] record so the gap in
    /// the inventory has an explanation beside it.
    pub async fn clear(&self) -> Result<Cleared, SluseError> {
        let items = inventory::items_from_journal(&self.all_records()?, &self.workspace);

        let cleared = remove_admitted(&items);
        // And what a fetch killed mid-stream left: never inventory, never kept.
        crate::workspace::sweep_partial(&self.workspace);

        let session = self.session_now();
        let path = journal::session_path(&self.journal_dir, &session);
        let mut j = crate::Journal::open_session(&self.journal_dir, &session).map_err(|e| SluseError::Internal {
            message: format!("opening the journal at {} to record the clear: {e}", path.display()),
        })?;
        j.record(AuditRecord {
            writer: sluse_proto::audit::Writer::Endpoint,
            box_id: self.box_id.clone(),
            user: self.gate.acting_as(),
            config_version: self.config_version.clone(),
            session_id: session.clone(),
            ts: Utc::now(),
            op: Op::Clear,
            // Not a path: a clear is about the workspace, not about one file.
            // The count is in the reason so the record says what happened on
            // its own.
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
        journal::mirror(&self.gate, &path, &session, &self.mirrored).await;

        Ok(cleared)
    }
}

/// Delete the admitted copies, and say exactly what happened to each.
///
/// Split out from the route so it can be tested without a Gate: deleting
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

impl Console {
    pub async fn alerts(&self, since: Option<DateTime<Utc>>) -> Result<Vec<sluse_proto::VolumeAlert>, SluseError> {
        self.gate.alerts(since).await
    }
}

impl Console {
    /// The **host's** trail, as the Gate will show it.
    ///
    /// Deliberately not the guest's journal, which [`Console::journal`]
    /// reads: the two records of one admission are written on opposite sides
    /// of the boundary and the console shows both rather than merging them. A
    /// merged view would hide exactly the disagreement the join exists to
    /// detect (invariant 7).
    pub async fn audit(&self, limit: usize) -> Result<sluse_proto::AuditTailResponse, SluseError> {
        if !self.local {
            return Err(SluseError::AudienceNotServed { audience: "audit tail".into() });
        }
        self.gate.audit_tail(limit).await
    }
}

#[cfg(test)]
mod tests {
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

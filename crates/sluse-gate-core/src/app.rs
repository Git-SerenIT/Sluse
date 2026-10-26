// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Gate Core's state, and the one place a record is written.
//!
//! Everything a route needs hangs off [`Core`], and two methods on it are the
//! reason this type exists rather than a tuple of fields: [`Core::record`]
//! builds an audit record with the fields that are the same on every record
//! already filled in, and [`Core::refuse`] turns an error into a recorded
//! refusal and an HTTP response in one move.
//!
//! **Refuse, record, then answer.** A route that returns an error without going
//! through `refuse` is a route whose refusals are invisible to the host, and a
//! refusal is normal operation that the audit trail is supposed to contain
//! (`docs/audit.md`). The compiler cannot enforce that; the handlers are short
//! enough to read, and they all do it.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};

use sluse_proto::{
    AuditRecord, BoxId, ContentHash, Environment, Loaded, Op, PostureSnapshot, SessionId,
    SluseError, SourceLastSeen, SourceName, SourceView, UserRef, VolumeConfig, Writer,
};

use crate::audit::AuditSink;
use crate::entra::Entra;
use crate::scope::{Compiled, CompiledSource};
use crate::session::SessionRegistry;
use crate::sources::{backend_for, SourceBackend};
use crate::volume::VolumeMonitor;

/// Everything the routes share.
pub struct Core {
    pub loaded: Loaded,
    pub compiled: Compiled,
    /// One per compiled source, in the same order, so [`crate::scope::Scoped`]'s
    /// index addresses both.
    backends: Vec<Box<dyn SourceBackend>>,
    pub sink: Arc<dyn AuditSink>,
    pub volume: VolumeMonitor,
    /// What was last observed about each source answering. **D-015 point 4.**
    pub reachability: Reachability,
    pub sessions: SessionRegistry,
    /// The Entra half, when any source is `sharepoint` (M7). `None` otherwise,
    /// and a remote request against a Gate Core without it is refused as a source
    /// kind this core does not serve.
    pub entra: Option<Arc<Entra>>,
    pub posture: PostureSnapshot,
    /// Who Gate Core is acting as. `os-process:DOMAIN\user` in LOCAL, and
    /// labelled as such: invariant 8 is structural in the product because the
    /// core impersonates the signed-in user, and a LOCAL run proves nothing
    /// about identity (D-010).
    pub user: UserRef,
    /// Where published artifacts land. The single write path.
    pub artifacts: PathBuf,
    /// Where the box's journal is mirrored, when the service asked for it
    /// (`SLUSE_JOURNAL_MIRROR`, D-027 point 5): outside the box's disks, so a
    /// wipe keeps it. One lock for every append.
    pub journal_mirror: Option<(PathBuf, Mutex<()>)>,
    /// When this state was assembled, which is within a millisecond of when the
    /// listener was bound. `/v1/status` reports the difference; nothing decides
    /// anything from it.
    pub started: DateTime<Utc>,
    /// How the last sign-in from the host ended (D-036), for `/v1/status`.
    pub host_sign_in: Mutex<Option<sluse_proto::HostSignInResult>>,
    /// The person signed out in the box and has not signed in since (Q7).
    pub signed_out: std::sync::atomic::AtomicBool,
}

impl Core {
    /// Assemble the state from a loaded config and a compiled scope.
    ///
    /// The posture snapshot is taken by the caller and handed in, because it
    /// needs the TLS configuration's verdict on the certificate pin and that is
    /// built before this.
    pub fn new(
        loaded: Loaded,
        compiled: Compiled,
        sink: Arc<dyn AuditSink>,
        posture: PostureSnapshot,
    ) -> Self {
        let backends = compiled.sources.iter().map(backend_for).collect();
        let volume = VolumeMonitor::new(loaded.config.volume.clone());
        let user = crate::identity::acting_as(loaded.config.environment);
        let artifacts = loaded.resolve(&loaded.config.artifacts);

        Self {
            loaded,
            compiled,
            backends,
            sink,
            volume,
            reachability: Reachability::default(),
            sessions: SessionRegistry::new(),
            entra: None,
            posture,
            user,
            artifacts,
            journal_mirror: None,
            started: Utc::now(),
            host_sign_in: Mutex::new(None),
            signed_out: Default::default(),
        }
    }

    /// Mirror the box's journal into `dir` (D-027 point 5).
    pub fn with_journal_mirror(mut self, dir: Option<PathBuf>) -> Self {
        self.journal_mirror = dir.map(|d| (d, Mutex::new(())));
        self
    }

    /// Attach the Entra half. Built by the caller because it reads the
    /// credential from disk and can fail, which [`Core::new`] cannot.
    pub fn with_entra(mut self, entra: Option<Entra>) -> Self {
        self.entra = entra.map(Arc::new);
        self
    }

    pub fn source(&self, index: usize) -> &CompiledSource {
        &self.compiled.sources[index]
    }

    pub fn backend(&self, index: usize) -> &dyn SourceBackend {
        self.backends[index].as_ref()
    }

    pub fn box_id(&self) -> BoxId {
        self.loaded.config.box_id.clone()
    }

    pub fn config_version(&self) -> ContentHash {
        self.loaded.version.clone()
    }

    pub fn environment(&self) -> Environment {
        self.loaded.config.environment
    }

    pub fn max_read_bytes(&self) -> u64 {
        self.loaded.config.max_read_bytes
    }

    /// The ceiling on one `fetch`, or `None` for no ceiling (D-016).
    pub fn max_fetch_bytes(&self) -> Option<u64> {
        self.loaded.config.max_fetch_bytes
    }

    pub fn volume_config(&self) -> VolumeConfig {
        self.loaded.config.volume.clone()
    }

    /// The sources as the guest may see them.
    ///
    /// Scopes in request form, never host paths: the guest learns a host path
    /// only as the `resolved` value of something it already named (invariant 2).
    /// At start: each filesystem source, or scope entry, that could not be
    /// resolved is a `scope` record, raised (1303), as a SharePoint scope root
    /// missing at sign-in is (D-038 point 6), and the source is shown as not
    /// answering from the first look (review R-22).
    pub fn report_unavailable(&self) {
        let session = SessionId::new_unchecked(crate::control::HOST_SESSION);
        for s in &self.compiled.sources {
            let name = s.name.as_str();
            for why in s.unavailable.iter().chain(&s.dropped) {
                let mut rec = self.record(&session, Op::Scope, format!("{name}/"));
                rec.outcome = sluse_proto::Outcome::Raised;
                rec.reason = Some("SCOPE_MISSING".into());
                rec.detail = Some(why.clone());
                self.sink.record(&rec);
            }
            if s.unavailable.is_some() {
                self.reachability.observed(name, false, Utc::now());
            }
        }
    }

    pub fn config_view_sources(&self) -> Vec<SourceView> {
        self.compiled
            .sources
            .iter()
            .map(|s| {
                let level = self
                    .loaded
                    .config
                    .sensitivity_levels
                    .iter()
                    .find(|l| l.level == s.sensitivity)
                    .map(|l| l.name.clone())
                    .unwrap_or_default();
                SourceView::new(
                    s.name.clone(),
                    &s.kind,
                    s.sensitivity,
                    level,
                    s.scope_request_forms(),
                )
                .seen(self.reachability.last_seen(s.name.as_str()))
            })
            .collect()
    }

    /// Start a record with everything constant already on it.
    ///
    /// `writer`, `box_id`, `user`, `config_version` and `posture_id` are the
    /// same on every record this process writes, and a route that had to set
    /// them itself would eventually set one of them differently.
    /// Who Gate Core acts as right now: the box's signed-in user, else its
    /// own process identity. What every record names, and what every response
    /// tells the endpoint in `x-sluse-user`.
    pub fn acting_user(&self) -> UserRef {
        self.entra.as_ref().and_then(|e| e.user()).unwrap_or_else(|| self.user.clone())
    }

    pub fn record(&self, session: &SessionId, op: Op, path: impl Into<String>) -> AuditRecord {
        // A box bound to a signed-in user writes that user on every record of
        // every session, not only on the SharePoint ones: a person reading the
        // trail sees one name for one box (M7, D-022). Unbound, it is the
        // core's own identity.
        AuditRecord::new(
            Writer::Core,
            self.box_id(),
            self.acting_user(),
            self.config_version(),
            session.clone(),
            op,
            path,
        )
        .with_posture(self.posture.id.clone())
    }

    /// The `signin` record (D-022): one per binding, however it happened, and
    /// one per sign-in at the page. Written after the binding, so it names the
    /// user who now holds the box. `how` says which way it came.
    pub fn signed_in(&self, session: &SessionId, how: &str) {
        let mut rec = self.record(session, Op::Signin, "(box)");
        rec.outcome = sluse_proto::Outcome::Admitted;
        rec.reason = Some(format!("signed in {} {how}", rec.user.name));
        self.sink.record(&rec);
    }

    /// Record a refusal or an error, and return it.
    ///
    /// The record is written before the error goes back, which is the ordering
    /// the audit trail depends on: whatever the guest is told afterwards, and
    /// however the connection ends, the host's account of the decision is
    /// already on disk.
    pub fn refuse(&self, mut rec: AuditRecord, err: SluseError) -> SluseError {
        // D-015 point 4: a source that could not be reached is an observation,
        // and this is the one place every refusal passes through. Only
        // `SourceUnavailable` says anything about the source — an out-of-scope
        // or denied path means the source answered perfectly well.
        if let SluseError::SourceUnavailable { source_name, .. } = &err {
            self.reachability.observed(source_name, false, Utc::now());
        }
        rec = rec.failed(&err);
        self.sink.record(&rec);
        err
    }

    /// The source answered. Called from the routes that got an answer out of a
    /// backend, which is the only evidence of reachability that costs nothing.
    pub fn answered(&self, source: &SourceName) {
        self.reachability.observed(source.as_str(), true, Utc::now());
    }

    /// Write the posture snapshot.
    ///
    /// Its own file beside the audit sink, not a line in it: [`AuditRecord`]
    /// deserialises with `deny_unknown_fields`, so a snapshot in the same JSONL
    /// would be skipped by [`crate::audit::tail`] as an unparseable line rather
    /// than rejected loudly — a record that is there and invisible is worse than
    /// one that is somewhere else.
    pub fn write_posture(&self) -> std::io::Result<Option<PathBuf>> {
        // On a device, the Event Log (1400): beside the records, in the log
        // only SYSTEM writes (D-039 slice 7).
        self.sink.posture(&self.posture)?;
        let Some(audit_path) = self.loaded.config.audit.path.as_ref() else {
            return Ok(None);
        };
        let path = self.loaded.resolve(audit_path);
        let target = path.with_file_name(format!(
            "{}-posture.jsonl",
            path.file_stem().unwrap_or_default().to_string_lossy()
        ));
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut line = serde_json::to_vec(&self.posture)?;
        line.push(b'\n');
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&target)?
            .write_all(&line)?;
        Ok(Some(target))
    }
}

/// What was last observed about each source answering. **D-015 point 4.**
///
/// The 2026-09-22 scored run is the argument for it: the file server's VM
/// powered off, every call failed, and `sluse_sources` went on advertising both
/// trees as available — so the agent had no way to tell "I am asking wrongly"
/// from "the source is gone", and concluded 125 files did not exist.
///
/// **Observed, never probed.** A `sources` call that stat'd every configured
/// share would spend I/O on every one of them to produce an answer that is stale
/// the moment it is returned, and would turn a cheap tool call into a network
/// round trip per source. This records what the last real operation found, with
/// its timestamp, and lets the reader judge how old that is.
#[derive(Debug, Default)]
pub struct Reachability {
    last: Mutex<HashMap<String, SourceLastSeen>>,
}

impl Reachability {
    pub fn observed(&self, source: &str, reachable: bool, at: DateTime<Utc>) {
        let mut last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        match last.get(source) {
            // Keep the newer observation. Tool calls run concurrently (rmcp
            // dispatches them in parallel), so these can arrive out of order.
            Some(prev) if prev.at > at => {}
            _ => {
                last.insert(source.to_owned(), SourceLastSeen { reachable, at });
            }
        }
    }

    pub fn last_seen(&self, source: &str) -> Option<SourceLastSeen> {
        let last = self.last.lock().unwrap_or_else(|p| p.into_inner());
        last.get(source).cloned()
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from the S-2 stub's endpoint/src/journal.rs, with the record type
// replaced by the shared `sluse_proto::AuditRecord`.

//! The endpoint's half of the two-record design.
//!
//! One file per session, one JSON object per line, **one line per tool call
//! whatever the outcome**. It is the guest's account of what it asked for and
//! what it got; the broker's is the host's account of what it decided. They join
//! on `admission_id`, and the scorer asserts the join is one-to-one with equal
//! hashes — which is how invariant 7 is checked rather than asserted.
//!
//! **This is not a trust anchor** (`docs/audit.md`). It is inside the box and
//! anything inside the box can be wrong about itself; it is functional. The
//! record that counts is the broker's.
//!
//! ## Lineage
//!
//! [`Journal::lineage`] returns **every admission in the session, deduped by
//! content hash**, each with its [`AdmissionState`] (D-018, D-055): the fix for
//! S-2 finding 8, where "since the last publish" left the second and third
//! artifact of a delivery with no lineage at all because the first publish
//! consumed it.
//!
//! It over-claims on purpose: it is what was admitted, not what was used. What
//! an artifact was made from is the agent's declaration, and
//! [`Journal::hash_named`] is how a declared source is found among the
//! admissions (D-055).
//!
//! Because the session outlives a restart (see [`crate::session`]), the journal
//! is re-opened and re-read rather than truncated, so lineage spans a reconnect.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use sluse_proto::{AdmissionState, AuditRecord, ContentHash, LineageItem, Op, Outcome, SessionId};

/// One session's journal.
pub struct Journal {
    path: PathBuf,
    file: File,
    records: Vec<AuditRecord>,
}

impl Journal {
    /// Open the journal for a session, loading what is already there.
    ///
    /// Append, never truncate: a restart inside one run rejoins the same file,
    /// and lineage that began before the reconnect is still lineage.
    pub fn open_session(dir: &Path, session: &SessionId) -> std::io::Result<Self> {
        std::fs::create_dir_all(dir)?;
        let path = session_path(dir, session);
        let records = read_records(&path)?;
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file, records })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }

    /// Append a record.
    ///
    /// Flushed every time. A journal that lost its last few lines to a buffer
    /// when the process ended would be missing exactly the records a person
    /// investigating would want.
    /// One `write_all` per line, newline included: two processes append to one
    /// session's file (Claude Code and Claude Desktop), and a line and its
    /// newline written apart could interleave with the other's into one line
    /// neither can parse.
    pub fn append(&mut self, rec: AuditRecord) -> std::io::Result<()> {
        let mut line = serde_json::to_string(&rec).map_err(std::io::Error::other)?;
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.records.push(rec);
        Ok(())
    }

    /// Append, and never fail the operation being recorded.
    ///
    /// Same rule as the broker's sink: an admission that happened stays
    /// happened, and a journal that could not be written is a loss to report,
    /// not a reason to tell the agent its read failed.
    pub fn record(&mut self, rec: AuditRecord) {
        if let Err(e) = self.append(rec) {
            tracing::error!(error = %e, path = %self.path.display(), "journal write failed");
        }
    }

    /// Read the file again: another process on the same session (Claude
    /// Desktop beside Claude Code) may have appended since this one loaded it
    /// (review R-15). What it misses is only an admission still under way in
    /// that other process.
    pub fn reload(&mut self) -> std::io::Result<()> {
        self.records = read_records(&self.path)?;
        Ok(())
    }

    /// Every admission in this session, deduped by content hash, oldest first.
    ///
    /// A `read` and a `fetch` of the same bytes count once, and the path kept is
    /// the one from the first admission of those bytes.
    ///
    /// The state is the strongest any admission of those bytes had: encrypted
    /// over fetched over read.
    pub fn lineage(&self) -> Vec<LineageItem> {
        let mut out: Vec<LineageItem> = Vec::new();
        for (r, hash) in self.admissions() {
            let state = Some(state_of(r));
            if let Some(x) = out.iter_mut().find(|x| &x.hash == hash) {
                x.state = x.state.max(state);
                continue;
            }
            out.push(LineageItem {
                path: r.path_requested.clone(),
                hash: hash.clone(),
                admission_id: r.admission_id.clone(),
                state,
            });
        }
        out
    }

    /// The hash of the **latest** admission made under this path, as the agent
    /// asked for it: `\` and `/` alike, case ignored, as SharePoint and Windows
    /// do. Latest, because a file read, changed at its source and read again is
    /// the second bytes the agent worked from (review R-14).
    pub fn hash_named(&self, path: &str) -> Option<&ContentHash> {
        let want = normal(path);
        self.admissions().filter(|(r, _)| normal(&r.path_requested) == want).last().map(|(_, h)| h)
    }

    fn admissions(&self) -> impl Iterator<Item = (&AuditRecord, &ContentHash)> {
        self.records
            .iter()
            .filter(|r| r.outcome == Outcome::Admitted && matches!(r.op, Op::Read | Op::Fetch))
            .filter_map(|r| r.hash.as_ref().map(|h| (r, h)))
    }
}

fn state_of(r: &AuditRecord) -> AdmissionState {
    let reason = |code: &str| r.reason.as_deref().is_some_and(|x| x.split(';').any(|c| c == code));
    if reason("OFFICE_ENCRYPTED") {
        AdmissionState::Encrypted
    } else if r.op == Op::Fetch {
        AdmissionState::Fetched
    } else if reason("NOT_UTF8_TEXT") || reason("NOT_EXTRACTED") {
        AdmissionState::Unread
    } else {
        AdmissionState::Read
    }
}

fn normal(path: &str) -> String {
    path.trim().replace('\\', "/").trim_start_matches("./").to_lowercase()
}

/// Bring the host's mirror of this session's journal up to date (slice 4,
/// D-027 point 5).
///
/// `cursor` is how much the host was last known to hold. A process starts at
/// 0 and asks the host where it is first, so a restart sends what the host
/// lacks rather than the whole file again; and it sends at most
/// [`MIRROR_CHUNK`] at a time, whole lines only, so a long journal is not one
/// request the broker's body limit refuses forever (review R-12). A failure
/// is logged and changes nothing: the next call catches up, and the operation
/// being recorded never fails for it.
pub async fn mirror(
    broker: &crate::broker_client::BrokerClient,
    path: &Path,
    session: &SessionId,
    cursor: &std::sync::atomic::AtomicU64,
) {
    use std::sync::atomic::Ordering;
    let Ok(bytes) = std::fs::read(path) else { return };
    let Some(end) = bytes.iter().rposition(|&b| b == b'\n').map(|i| i + 1) else { return };
    let mut from = cursor.load(Ordering::SeqCst);
    if from == 0 {
        match send(broker, session, 0, String::new(), cursor).await {
            Some(have) => from = have,
            None => return,
        }
    }
    while from < end as u64 {
        let start = from as usize;
        let window = &bytes[start..end.min(start + MIRROR_CHUNK)];
        // A line longer than a chunk goes alone, whole.
        let stop = match window.iter().rposition(|&b| b == b'\n') {
            Some(i) => start + i + 1,
            None => start + bytes[start..end].iter().position(|&b| b == b'\n').map_or(end - start, |i| i + 1),
        };
        let lines = String::from_utf8_lossy(&bytes[start..stop]).into_owned();
        match send(broker, session, from, lines, cursor).await {
            Some(have) if have != from => from = have,
            _ => return,
        }
    }
}

/// How much one mirror request carries at most, before JSON escaping; the
/// broker takes 4 MiB on the route.
const MIRROR_CHUNK: usize = 1024 * 1024;

/// One mirror request; the host's `have`, stored in `cursor`.
async fn send(
    broker: &crate::broker_client::BrokerClient,
    session: &SessionId,
    offset: u64,
    lines: String,
    cursor: &std::sync::atomic::AtomicU64,
) -> Option<u64> {
    use std::sync::atomic::Ordering;
    let append = sluse_proto::wire::JournalAppend { session: session.clone(), offset, lines };
    match broker.mirror_journal(&append).await {
        Ok(have) => {
            cursor.store(have, Ordering::SeqCst);
            Some(have)
        }
        // A broker with no mirror is not asked again by this process.
        Err(sluse_proto::SluseError::AudienceNotServed { .. }) => {
            cursor.store(u64::MAX, Ordering::SeqCst);
            None
        }
        Err(e) => {
            tracing::warn!(error = %e, "the journal mirror is behind; the next record catches it up");
            None
        }
    }
}

/// Where a session's journal lives.
pub fn session_path(dir: &Path, session: &SessionId) -> PathBuf {
    dir.join(format!("{session}.jsonl"))
}

/// Every `*.jsonl` journal in `dir`, one session's after another. A missing
/// directory is no journals.
pub fn read_all(dir: &Path) -> std::io::Result<Vec<AuditRecord>> {
    let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(it) => it
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "jsonl"))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    files.sort();
    let mut records = Vec::new();
    for f in files {
        records.extend(read_records(&f)?);
    }
    Ok(records)
}

/// Read a journal file without opening it for append.
///
/// **The console is a second process** — `--console` and `--mcp` do not share
/// one — so it reads this file while the MCP endpoint is appending to it. It
/// re-reads per request rather than holding a snapshot, because a console
/// showing a run that has moved on is worse than one that costs a file read.
/// A missing file is an empty journal, not an error: the run may not have
/// admitted anything yet.
pub fn read_records(path: &Path) -> std::io::Result<Vec<AuditRecord>> {
    let mut records = Vec::new();
    if !path.exists() {
        return Ok(records);
    }
    for line in BufReader::new(File::open(path)?).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        match serde_json::from_str::<AuditRecord>(&line) {
            Ok(r) => records.push(r),
            // A torn last line costs one record, not the file. The journal is
            // appended to while it may be read, by another process at that.
            Err(e) => tracing::warn!(error = %e, "journal line skipped; not a record"),
        }
    }
    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluse_proto::{AdmissionId, BoxId, SluseError, UserRef, Writer};

    fn rec(op: Op, path: &str, session: &SessionId) -> AuditRecord {
        AuditRecord::new(
            Writer::Endpoint,
            BoxId::new_unchecked("box-local-test"),
            UserRef::os_process("SERENIT\\jok"),
            ContentHash::of(b"a config"),
            session.clone(),
            op,
            path,
        )
    }

    fn admitted(op: Op, path: &str, body: &[u8], session: &SessionId) -> AuditRecord {
        rec(op, path, session).admitted(
            AdmissionId::mint(),
            ContentHash::of(body),
            body.len() as u64,
        )
    }

    #[test]
    fn a_session_gets_its_own_file_named_for_it() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let j = Journal::open_session(dir.path(), &session).unwrap();
        assert_eq!(
            j.path().file_name().unwrap().to_string_lossy(),
            format!("{session}.jsonl")
        );
    }

    /// Review R-14: read, changed at the source, read again. The declared
    /// source is the second bytes.
    #[test]
    fn a_declared_source_names_the_latest_admission_of_its_path() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let mut j = Journal::open_session(dir.path(), &session).unwrap();
        j.append(admitted(Op::Read, "fixture/brief.docx", b"v1", &session)).unwrap();
        j.append(admitted(Op::Read, "fixture/brief.docx", b"v2", &session)).unwrap();
        assert_eq!(j.hash_named("fixture/brief.docx"), Some(&ContentHash::of(b"v2")));
    }

    /// Review R-15: two processes on one session. What the other appended is
    /// seen after a reload, not before.
    #[test]
    fn a_reload_sees_what_another_process_appended() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let mut code = Journal::open_session(dir.path(), &session).unwrap();
        let mut desktop = Journal::open_session(dir.path(), &session).unwrap();
        code.append(admitted(Op::Fetch, "fixture/brief.docx", b"brief", &session)).unwrap();
        assert_eq!(desktop.hash_named("fixture/brief.docx"), None);
        desktop.reload().unwrap();
        assert_eq!(desktop.hash_named("fixture/brief.docx"), Some(&ContentHash::of(b"brief")));
        assert_eq!(desktop.lineage().len(), 1);
    }

    #[test]
    fn lineage_is_every_admission_in_the_session_deduped_by_hash() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let mut j = Journal::open_session(dir.path(), &session).unwrap();

        j.record(admitted(Op::Read, "fixture/a.md", b"alpha", &session));
        j.record(admitted(Op::Fetch, "fixture/b.md", b"beta", &session));
        // The same bytes under a second path: one admission's worth of lineage.
        j.record(admitted(Op::Fetch, "fixture/a-copy.md", b"alpha", &session));
        // Refusals and listings are not lineage.
        j.record(rec(Op::List, "fixture", &session));
        j.record(
            rec(Op::Read, "fixture/secret.md", &session)
                .failed(&SluseError::NotFound { raw: "fixture/secret.md".into() }),
        );

        let lineage = j.lineage();
        assert_eq!(lineage.len(), 2);
        assert_eq!(lineage[0].path, "fixture/a.md", "the first admission's path is kept");
        assert_eq!(lineage[1].path, "fixture/b.md");
        assert!(lineage.iter().all(|l| l.admission_id.is_some()), "the join key travels");
        assert_eq!(lineage[0].state, Some(AdmissionState::Fetched), "read, then fetched as a-copy");
        assert_eq!(lineage[1].state, Some(AdmissionState::Fetched));
    }

    /// D-055: the file the agent could not read is admitted, and says so.
    #[test]
    fn an_encrypted_admission_is_marked_and_a_declared_name_is_found() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let mut j = Journal::open_session(dir.path(), &session).unwrap();

        j.record(admitted(Op::Read, "fixture/Plan.md", b"plan", &session));
        let mut sealed = admitted(Op::Fetch, "fixture/sealed.docx", b"cipher", &session);
        sealed.reason = Some("MANIFEST_NOT_WRITTEN;OFFICE_ENCRYPTED".into());
        j.record(sealed);
        let mut image = admitted(Op::Read, "fixture/logo.png", b"png", &session);
        image.reason = Some("NOT_UTF8_TEXT".into());
        j.record(image);

        let lineage = j.lineage();
        assert_eq!(lineage[0].state, Some(AdmissionState::Read));
        assert_eq!(lineage[1].state, Some(AdmissionState::Encrypted));
        assert_eq!(lineage[2].state, Some(AdmissionState::Unread), "D-056: admitted, never shown");
        assert_eq!(j.hash_named("fixture\\plan.MD"), Some(&ContentHash::of(b"plan")));
        assert_eq!(j.hash_named("fixture/other.md"), None);
    }

    #[test]
    fn a_publish_does_not_consume_the_lineage_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let mut j = Journal::open_session(dir.path(), &session).unwrap();

        j.record(admitted(Op::Read, "fixture/a.md", b"alpha", &session));
        let mut publish = rec(Op::Publish, "artifacts/one.md", &session);
        publish.artifact = Some("one.md".into());
        j.record(publish);
        j.record(admitted(Op::Read, "fixture/b.md", b"beta", &session));

        // S-2 finding 8: under "since the last publish" this would be one item,
        // and the second delivery would claim to derive from nothing it used.
        assert_eq!(j.lineage().len(), 2);
    }

    #[test]
    fn a_restart_rejoins_the_file_and_keeps_the_lineage() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();

        {
            let mut j = Journal::open_session(dir.path(), &session).unwrap();
            j.record(admitted(Op::Read, "fixture/a.md", b"alpha", &session));
        }

        // A new endpoint process, the same run.
        let mut j = Journal::open_session(dir.path(), &session).unwrap();
        assert_eq!(j.len(), 1, "the file was re-read, not truncated");
        j.record(admitted(Op::Read, "fixture/b.md", b"beta", &session));

        // Which is the whole reason the session survives a restart: a publish
        // after a reconnect carries the sources admitted before it.
        assert_eq!(j.lineage().len(), 2);
    }

    #[test]
    fn a_torn_line_costs_one_record_and_not_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let path = {
            let mut j = Journal::open_session(dir.path(), &session).unwrap();
            j.record(admitted(Op::Read, "fixture/a.md", b"alpha", &session));
            j.path().to_path_buf()
        };

        let intact = std::fs::read_to_string(&path).unwrap();
        std::fs::write(&path, format!("{}{{\"writer\":\"endpoi", intact)).unwrap();

        let j = Journal::open_session(dir.path(), &session).unwrap();
        assert_eq!(j.len(), 1);
        assert_eq!(j.lineage().len(), 1);
    }

    #[test]
    fn a_journal_that_cannot_be_written_does_not_fail_the_operation() {
        let dir = tempfile::tempdir().unwrap();
        let session = SessionId::mint();
        let mut j = Journal::open_session(dir.path(), &session).unwrap();

        // Close the file out from under it by replacing the path with a
        // directory; the append fails and the caller is not stopped.
        std::fs::remove_file(j.path()).unwrap();
        std::fs::create_dir(j.path()).unwrap();
        j.record(admitted(Op::Read, "fixture/a.md", b"alpha", &session));
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// JSONL append, size cap, rotate-once and never-fail-the-caller derived from
// Chaperone crates/chapr-endpoint/src/diag.rs:44-161. D-003 allows reuse, not
// vendoring.

//! Where Gate Core's records go.
//!
//! One trait so the sink is a deployment choice and not a code change: JSONL in
//! the prototype, the Windows Event Log in v1 (`docs/audit.md` — every
//! customer's SIEM agent already collects it, so integration work is zero).
//! [`EventLogSink`] is built on Windows only, with no feature flag: a flag is a
//! second build to keep green, and the platform already decides it.
//!
//! ## The rule this module exists to enforce
//!
//! **A sink may never fail the operation it is recording.** A full disk, a
//! locked file, a directory someone deleted — none of them may turn an admission
//! that happened into an error, and none of them may turn a refusal that was
//! decided into an admission. The record is the thing that is lost, loudly, on
//! Gate Core's own stderr; the decision stands.
//!
//! That is a real trade and it is the right way round, but it does mean the
//! journal is **not a trust anchor** — `docs/audit.md` says so and this is where
//! it becomes true. A record that was never written cannot be missed by reading
//! the file it was not written to. Tamper-evidence is a v1 question about the
//! Event Log, not something this sink provides.
//!
//! ## Volume
//!
//! `docs/audit.md` sets the volume rules: one record per admission, no content,
//! no prompts, no model output, no tokens. Nothing here truncates or samples —
//! a sink that drops records under load is a sink that drops exactly the records
//! a burst would have shown.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sluse_proto::AuditRecord;

/// Rotate at 8 MB. One rotation, to `.1`, then the old `.1` is overwritten.
///
/// Chaperone used 2 MB for diagnostics, which are rare. These are not: a record
/// is roughly 400 bytes and a busy session is thousands of them, so 2 MB would
/// rotate inside a single smoke run and cost the first half of it. 8 MB is about
/// 20 000 records.
const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// A destination for audit records.
pub trait AuditSink: Send + Sync {
    /// Write one record.
    ///
    /// Returns `io::Result` so a caller that genuinely wants to know can ask —
    /// `sluse check` does, at start, to find out whether the sink is writable
    /// before anything depends on it. Every caller on a request path ignores it
    /// and logs, which is what [`AuditSink::record`] does for them.
    fn write(&self, record: &AuditRecord) -> std::io::Result<()>;

    /// The posture snapshot, for a sink that keeps it with the records: the
    /// Event Log's (1400). The JSONL sink keeps it in a file of its own
    /// (`Core::write_posture`), so by default this writes nothing.
    fn posture(&self, _snapshot: &sluse_proto::PostureSnapshot) -> std::io::Result<()> {
        Ok(())
    }

    /// Write one record, best effort. The request path calls this.
    fn record(&self, record: &AuditRecord) {
        // As Gate Core, even inside a read made as the user (D-031, D-054).
        if let Err(e) = crate::as_user::as_core(|| self.write(record)) {
            // This is the one place a lost record is visible. It goes to stderr
            // rather than to the sink, for reasons that should be obvious.
            tracing::error!(
                error = %e,
                op = ?record.op,
                outcome = ?record.outcome,
                path = %record.path_requested,
                "audit record could not be written; the operation is unaffected and the record is lost"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// JSONL
// ---------------------------------------------------------------------------

/// One JSON object per line.
///
/// Line-delimited so it can be grepped, tailed and shipped without a parser, and
/// so a torn final line costs one record rather than the file.
#[derive(Debug)]
pub struct JsonlSink {
    path: PathBuf,
    // Serialises the append. Two threads appending to the same handle can
    // interleave a partial line under a large record, and a torn line in the
    // middle of a file is worse than a slow one: the whole point of the format
    // is that a reader can trust line boundaries.
    lock: Mutex<()>,
}

impl JsonlSink {
    /// Open — or rather, prepare — the sink. Creates the parent directory.
    ///
    /// Does not hold the file open: the audit file is something a person tails,
    /// copies and rotates by hand while Gate Core runs, and a held handle makes
    /// all three awkward on Windows.
    pub fn new(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Self { path, lock: Mutex::new(()) })
    }

    /// The file being written. `sluse status` and the console's audit tail read
    /// it; nothing writes to it but this.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for JsonlSink {
    fn write(&self, record: &AuditRecord) -> std::io::Result<()> {
        // Serialise before taking the lock: a record that will not serialise is
        // a bug in the record, not a reason to hold up a writer.
        let line = serde_json::to_string(record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let _guard = self.lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

        if std::fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0) > MAX_BYTES {
            // Rotate once. A rotation that fails is not a reason to stop
            // recording; the file grows past the cap and someone notices it.
            let _ = std::fs::rename(&self.path, self.path.with_extension("jsonl.1"));
        }

        let mut file = match open_append(&self.path) {
            Ok(f) => f,
            // The directory went away under a running core — someone tidying
            // up, a cleanup script, a redirected profile. Recreated and retried
            // once, because the alternative is a sink that keeps swallowing
            // records for the life of the process, and an audit trail that
            // silently stops is the worst failure this design has. The retry is
            // once: a second failure is a real one and is reported.
            Err(_) => {
                if let Some(parent) = self.path.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                open_append(&self.path)?
            }
        };
        writeln!(file, "{line}")
    }
}

fn open_append(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().create(true).append(true).open(path)
}

// ---------------------------------------------------------------------------
// The Windows Event Log
// ---------------------------------------------------------------------------

/// The event source name. Provisional with every other `sluse` name (Q-7).
pub const EVENT_SOURCE: &str = "Sluse";

/// UTF-16 units per insertion string. `ReportEventW` caps one at 31,839, and an
/// event's total at about 64 KB; 15,000 characters stays under both even if
/// every one were outside the BMP.
pub const EVENT_CHUNK: usize = 15_000;

/// The event id for a record: `100 × op + outcome`, so a SIEM rule can filter
/// on either. `Read` refused is 101; `Signin` admitted is 1000. The table is in
/// `docs/audit.md`, and **the numbers are a contract**: a SIEM rule written
/// against one must not start matching something else. New ops go on the end.
pub fn event_id(op: sluse_proto::Op, outcome: sluse_proto::Outcome) -> u32 {
    use sluse_proto::{Op::*, Outcome::*};
    // Exhaustive on purpose: an op added to the proto without a number here
    // does not compile.
    let op = match op {
        Read => 1,
        Fetch => 2,
        Reread => 3,
        Publish => 4,
        Metadata => 5,
        List => 6,
        Sources => 7,
        Alert => 8,
        Clear => 9,
        Signin => 10,
        Signout => 11,
        // 12 is the egress proxy's (EGRESS_REFUSED).
        Scope => 13,
        // 14 is the posture snapshot's (POSTURE).
        Tail => 15,
        Journal => 16,
        Call => 17,
        Tools => 18,
    };
    let outcome = match outcome {
        Admitted => 0,
        Refused => 1,
        Error => 2,
        Raised => 3,
    };
    100 * op + outcome
}

/// The Sluse log's security descriptor (D-023, D-039 slice 7): SYSTEM may
/// write and clear; Administrators and Event Log Readers may read. So no
/// process but Gate Core's and the proxy's, both SYSTEM, can put a record in
/// it. Not proof against an administrator, who can change this. The device
/// init sets it (`packaging/box/sluse-box.ps1`); a test keeps the two equal.
pub const AUDIT_SDDL: &str = "O:BAG:SYD:(A;;0xf0007;;;SY)(A;;0x1;;;BA)(A;;0x1;;;S-1-5-32-573)";

/// The posture snapshot at Gate Core's start (D-039 slice 7): op 14,
/// written once per start. Information, or Warning when a check failed.
pub const POSTURE: u32 = 1400;

/// The proxy's refusals (M9, D-035): op 12, refused. Not an [`AuditRecord`]:
/// the proxy acts for the box, not as a user, and has no session, so its
/// records carry the box, the config version and who opened the box instead.
/// Next on the end of the table, by the rule above (`docs/audit.md`).
pub const EGRESS_REFUSED: u32 = 1201;

/// A sign-in window (D-075): op 19, opened and closed, each its record. Not
/// an [`AuditRecord`], as the proxy's are not: it names the box, the config,
/// who opened it, until when, and at its close the connections made in it.
pub const SIGN_IN_WINDOW: u32 = 1900;

/// Clipboard text the Sluse window carried (D-076): op 20, one record a
/// transfer, with its direction, size, hash and first 40 characters. Not an
/// [`AuditRecord`]: it is the shell's word, which runs as the person, passed
/// on by the service, who names the account it checked.
pub const CLIPBOARD: u32 = 2000;

/// How loud an event is in Event Viewer. A refusal is a warning, not an error:
/// it is Gate Core working. An error is Gate Core or a source failing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventLevel {
    Information,
    Warning,
    Error,
}

pub fn event_level(outcome: sluse_proto::Outcome) -> EventLevel {
    use sluse_proto::Outcome::*;
    match outcome {
        Admitted => EventLevel::Information,
        Refused | Raised => EventLevel::Warning,
        Error => EventLevel::Error,
    }
}

/// The insertion strings for one record, as one or more events.
///
/// Normally one event with one string: the record's JSON, which is a few
/// hundred bytes. A publish with a long lineage set can pass the per-string
/// cap, and **a record is never truncated** (the module note): it is split
/// over consecutive events, each carrying `"<sha256 of the whole> part i/n"`
/// and one piece. Concatenating the pieces in order gives the JSON back, and
/// the hash says whether it did.
pub fn event_strings(json: &str) -> Vec<Vec<String>> {
    let chars: Vec<char> = json.chars().collect();
    if chars.len() <= EVENT_CHUNK {
        return vec![vec![json.to_owned()]];
    }
    let key = sluse_proto::ContentHash::of(json.as_bytes());
    let pieces: Vec<String> = chars.chunks(EVENT_CHUNK).map(|c| c.iter().collect()).collect();
    let n = pieces.len();
    pieces
        .into_iter()
        .enumerate()
        .map(|(i, p)| vec![format!("{key} part {}/{n}", i + 1), p])
        .collect()
}

#[cfg(windows)]
pub use eventlog::EventLogSink;

#[cfg(windows)]
mod eventlog {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::EventLog::{
        DeregisterEventSource, RegisterEventSourceW, ReportEventW, EVENTLOG_ERROR_TYPE,
        EVENTLOG_INFORMATION_TYPE, EVENTLOG_WARNING_TYPE,
    };

    use super::{event_id, event_level, event_strings, AuditSink, EventLevel, EVENT_SOURCE};
    use sluse_proto::AuditRecord;

    /// Records to the Windows Event Log, under [`EVENT_SOURCE`].
    ///
    /// The source lives in its own log, "Sluse", whose descriptor lets only
    /// SYSTEM write ([`super::AUDIT_SDDL`], D-023): device init creates it
    /// (`packaging/box/sluse-box.ps1`, `Set-SluseLog`). No message file is
    /// registered, so Event Viewer says it cannot find a description for the
    /// id; the record is intact as the event's data and a SIEM agent collects
    /// it. An administrator can still change the descriptor: `docs/audit.md`.
    pub struct EventLogSink {
        handle: HANDLE,
    }

    // SAFETY: an event source handle is an opaque kernel-side reference that
    // Windows lets any thread in the process report through; `ReportEventW`
    // takes no lock the caller must hold. The handle is only closed in `Drop`.
    unsafe impl Send for EventLogSink {}
    unsafe impl Sync for EventLogSink {}

    impl EventLogSink {
        pub fn new() -> std::io::Result<Self> {
            let name = HSTRING::from(EVENT_SOURCE);
            // SAFETY: `name` is null-terminated and outlives the call; a null
            // server means this machine.
            let handle = unsafe { RegisterEventSourceW(PCWSTR::null(), PCWSTR(name.as_ptr())) }
                .map_err(|e| std::io::Error::other(format!("RegisterEventSourceW: {e}")))?;
            Ok(Self { handle })
        }

        /// One record as one or more events, split as [`event_strings`] says.
        pub fn report(&self, id: u32, level: EventLevel, json: &str) -> std::io::Result<()> {
            let kind = match level {
                EventLevel::Information => EVENTLOG_INFORMATION_TYPE,
                EventLevel::Warning => EVENTLOG_WARNING_TYPE,
                EventLevel::Error => EVENTLOG_ERROR_TYPE,
            };
            for strings in event_strings(json) {
                let owned: Vec<HSTRING> = strings.iter().map(HSTRING::from).collect();
                let ptrs: Vec<PCWSTR> = owned.iter().map(|h| PCWSTR(h.as_ptr())).collect();
                // SAFETY: `ptrs` points into `owned`, which outlives the call;
                // no SID and no raw data.
                unsafe { ReportEventW(self.handle, kind, 0, id, None, 0, Some(&ptrs), None) }
                    .map_err(|e| std::io::Error::other(format!("ReportEventW: {e}")))?;
            }
            Ok(())
        }
    }

    impl Drop for EventLogSink {
        fn drop(&mut self) {
            // SAFETY: the handle came from RegisterEventSourceW and is closed once.
            let _ = unsafe { DeregisterEventSource(self.handle) };
        }
    }

    impl AuditSink for EventLogSink {
        fn write(&self, record: &AuditRecord) -> std::io::Result<()> {
            let json = serde_json::to_string(record)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            self.report(event_id(record.op, record.outcome), event_level(record.outcome), &json)
        }

        fn posture(&self, snapshot: &sluse_proto::PostureSnapshot) -> std::io::Result<()> {
            let json = serde_json::to_string(snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let failed = snapshot.checks.iter().any(|c| c.outcome == sluse_proto::CheckOutcome::Fail);
            let (id, level) = if failed { (super::POSTURE + 1, EventLevel::Warning) } else { (super::POSTURE, EventLevel::Information) };
            self.report(id, level, &json)
        }
    }
}

// ---------------------------------------------------------------------------
// Memory, for tests
// ---------------------------------------------------------------------------

/// Keeps records in memory. Tests only; never a deployment option.
#[derive(Debug, Default)]
pub struct MemorySink {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemorySink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

impl AuditSink for MemorySink {
    fn write(&self, record: &AuditRecord) -> std::io::Result<()> {
        self.records.lock().unwrap_or_else(|p| p.into_inner()).push(record.clone());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Reading back
// ---------------------------------------------------------------------------

/// The last `limit` records in a JSONL file, oldest first.
///
/// For `GET /v1/audit/tail`, which is **provisional and LOCAL only**: the
/// console's "what IT sees" panel, so a person being shown the prototype can see
/// both halves of the two-record design at once. In the product the host's log
/// is the host's, and a guest that can read it learns what the host knows about
/// it.
///
/// A line that will not parse is skipped rather than failing the read: a torn
/// last line is the expected state of a file being appended to while it is read.
pub fn tail(path: &Path, limit: usize) -> std::io::Result<Vec<AuditRecord>> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        // No file yet means nothing has been recorded, which is an empty tail
        // and not an error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut records: Vec<AuditRecord> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    if records.len() > limit {
        records.drain(..records.len() - limit);
    }
    Ok(records)
}

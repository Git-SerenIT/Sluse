// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! What the guest has, where it came from, and whether it still matches.
//!
//! The inventory is built from the endpoint's own journal, not from a walk of
//! the workspace. A file on disk with no record behind it is not inventory —
//! it is something the agent made, and the console has no provenance to show
//! for it. Every item here names the admission that authorised it.
//!
//! ## What a state means, and what it does not
//!
//! [`classify`] answers from two facts: whether the local copy is still there,
//! and what the source says now. It **never over-claims**. When the Gate
//! cannot be reached, or the source is unavailable, the answer is
//! [`InventoryState::Unknown`] — not `Stale`, and not `Current`. A console that
//! shows "current" because it failed to ask is worse than one that admits it
//! does not know, and this is the screen a person looks at to decide whether
//! what they are about to send out is still true.
//!
//! ## Refresh is user-initiated
//!
//! Nothing here runs on a timer. `/v1/stat` writes an audit record on every
//! call (`docs/sluse_prototype.md`, the M2 review), so a console that polled
//! would fill the host's trail with questions nobody asked. The volume of stat
//! records is bounded by what a person clicks, deliberately.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sluse_proto::audit::{AuditRecord, Op, Outcome};
use sluse_proto::{AdmissionId, ContentHash, SluseError, StatResponse};

use crate::workspace;

/// One admitted file, as the journal remembers it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InventoryItem {
    /// Request form, `<source>/<relative path>` — what the agent asked for and
    /// what the console shows. Never a host path (invariant 2).
    pub path: String,
    /// The source name, split out so the console can group by it.
    pub source: String,
    /// The hash of the bytes admitted. **The identity**: two names for the same
    /// bytes are one thing, and the console groups on this.
    pub hash: ContentHash,
    /// The admission this came from, so a person can find the Gate's record.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admission_id: Option<AdmissionId>,
    pub admitted_at: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// Where it landed in the workspace. Inside the guest, so showing it tells
    /// the guest nothing it does not already know.
    pub local: PathBuf,
    /// Whether that file is still there. Answered by looking, not remembered.
    pub local_present: bool,
    /// Whether the sidecar beside it names this admission (D-019 point 3), so a
    /// re-read through `sluse_read` comes back with its provenance. False means
    /// the re-read says `NO_PROVENANCE`. Not evidence either way: the sidecar is
    /// guest-writable (`manifest.rs`).
    pub sidecar: bool,
}

/// What the source says about an item now, against what was admitted then.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InventoryState {
    /// The source still has these bytes. The only state that licenses "this is
    /// what the source says".
    Current,
    /// The source has the file and it has changed since it was admitted. The
    /// local copy is not wrong, it is *old*, and that is a different thing to
    /// tell someone about to publish.
    Stale,
    /// The source will not answer for it any more: gone, renamed, out of scope,
    /// or the user's own permissions now refuse it. The local copy outlives its
    /// authority.
    Orphaned,
    /// Nobody could be asked. Not a claim about the file — a claim about the
    /// question.
    Unknown,
    /// The admitted copy is no longer in the workspace. The record stands; the
    /// file the agent was given does not.
    Missing,
}

impl InventoryState {
    /// Whether this state was reached by asking the source and getting an
    /// answer. The console greys the refresh time on the others, because a
    /// timestamp beside a state nobody verified reads as verification.
    pub fn is_answered(self) -> bool {
        matches!(self, Self::Current | Self::Stale | Self::Orphaned)
    }
}

/// Every file the journal says was admitted into this workspace.
///
/// Built from [`Op::Fetch`] admissions only: a `read` returns bytes inline and
/// leaves nothing on disk, so it has no local copy to be current or missing. A
/// re-fetch of the same path replaces the earlier entry, because the later
/// admission is the one the file on disk came from.
///
/// A copy admitted before the last Clear and no longer on disk is left out:
/// the Clear removed it, and the records span every session the workspace has
/// had (review R-04), so without this every cleared file would stay listed as
/// missing for good. One still on disk stays, whatever the Clear said.
pub fn items_from_journal(records: &[AuditRecord], workspace_dir: &Path) -> Vec<InventoryItem> {
    let last_clear = records.iter().filter(|r| r.op == Op::Clear).map(|r| r.ts).max();
    // Keyed by request path, so a second fetch of the same file supersedes the
    // first rather than appearing twice with two hashes. Ordered, so the console
    // and the tests see the same list twice running.
    let mut by_path: BTreeMap<String, InventoryItem> = BTreeMap::new();

    for r in records {
        if r.op != Op::Fetch || r.outcome != Outcome::Admitted {
            continue;
        }
        // An admission with no hash is not inventory: without it there is
        // nothing to compare the source against, and a row that can only ever
        // say Unknown is a row that teaches a person to ignore the column.
        let Some(hash) = r.hash.clone() else { continue };

        let Some((source, rel)) = split_request(&r.path_requested) else { continue };
        let local = workspace::admitted_path(workspace_dir, &source, rel);

        let sidecar = crate::manifest::read(&local)
            .is_some_and(|m| r.admission_id.as_ref() == Some(&m.admission_id));
        let item = InventoryItem {
            sidecar,
            path: r.path_requested.clone(),
            source: source.as_str().to_owned(),
            hash,
            admission_id: r.admission_id.clone(),
            admitted_at: r.ts,
            bytes: r.bytes,
            local_present: local.is_file(),
            local,
        };
        match by_path.get(&item.path) {
            // Keep the later admission. Equal timestamps keep the later record,
            // which is the one further down an append-only journal.
            Some(existing) if existing.admitted_at > item.admitted_at => {}
            _ => {
                by_path.insert(item.path.clone(), item);
            }
        }
    }

    by_path
        .into_values()
        .filter(|i| i.local_present || last_clear.is_none_or(|c| i.admitted_at > c))
        .collect()
}

/// What to show for one item, given what the source just said.
///
/// The `stat` argument is the answer to `POST /v1/stat` for [`InventoryItem::path`].
/// Everything this function will not claim is deliberate; see the module note.
pub fn classify(item: &InventoryItem, stat: Result<StatResponse, SluseError>) -> InventoryState {
    // Asked before the source is: whatever the source says, the file the agent
    // was handed is not there, and that is the thing a person needs to see.
    if !item.local_present {
        return InventoryState::Missing;
    }

    match stat {
        Ok(s) => {
            if s.hash == item.hash {
                InventoryState::Current
            } else {
                InventoryState::Stale
            }
        }
        // The source answered, and the answer is that this is no longer yours to
        // have. `AccessDenied` belongs here rather than under `Unknown` for the
        // reason M3 decided to tell it plainly: it is the user's own permissions
        // answering, which is a fact about the file and not a failure to ask.
        Err(
            SluseError::AccessDenied { .. }
            | SluseError::NotFound { .. }
            | SluseError::UnknownSource { .. }
            | SluseError::OutOfScope { .. },
        ) => InventoryState::Orphaned,

        // Nobody was reached, or the source could not answer. Never `Stale`:
        // "changed" and "unanswered" look the same from here and only one of
        // them is a reason to stop.
        Err(_) => InventoryState::Unknown,
    }
}

/// `<source>/<rest>`, with the source parsed as a [`SourceName`].
///
/// [`SourceName`]: sluse_proto::SourceName
fn split_request(request: &str) -> Option<(sluse_proto::SourceName, &str)> {
    let (source, rel) = request.split_once(['/', '\\'])?;
    let source = sluse_proto::SourceName::parse(source)?;
    Some((source, rel))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluse_proto::audit::{Capability, UserKind, UserRef, Writer};
    use sluse_proto::{BoxId, SessionId};

    fn record(path: &str, op: Op, outcome: Outcome, hash: Option<&str>) -> AuditRecord {
        AuditRecord {
            writer: Writer::Endpoint,
            box_id: BoxId::new_unchecked("box"),
            user: UserRef { kind: UserKind::OsProcess, name: "tester".into() },
            config_version: ContentHash::of(b"config"),
            session_id: SessionId::new_unchecked("s".repeat(32)),
            ts: DateTime::parse_from_rfc3339("2026-09-18T10:00:00Z").unwrap().into(),
            op,
            path_requested: path.to_owned(),
            path_resolved: None,
            scope: None,
            capability: Capability::Bytes,
            outcome,
            reason: None,
            detail: None,
            hash: hash.map(|h| ContentHash::of(h.as_bytes())),
            bytes: Some(4),
            admission_id: None,
            publish_id: None,
            artifact: None,
            lineage: None,
            sources: None,
            label: None,
            posture_id: None,
        }
    }

    /// A workspace with `admitted/fixture/in-scope/note.md` actually on disk.
    fn workspace_with_note() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let p = workspace::admitted_path(
            dir.path(),
            &sluse_proto::SourceName::new_unchecked("fixture"),
            "in-scope/note.md",
        );
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, b"body").unwrap();
        dir
    }

    /// Review R-04: a copy from an earlier session is still inventory, and a
    /// copy a Clear removed is not listed again as missing.
    #[test]
    fn a_clear_takes_what_it_removed_off_the_list_and_nothing_else() {
        let ws = workspace_with_note();
        let at = |s: &str| -> DateTime<Utc> { DateTime::parse_from_rfc3339(s).unwrap().into() };
        let mut gone = record("fixture/in-scope/gone.md", Op::Fetch, Outcome::Admitted, Some("gone"));
        gone.ts = at("2026-09-17T10:00:00Z");
        let mut clear = record("(workspace)", Op::Clear, Outcome::Admitted, None);
        clear.ts = at("2026-09-17T11:00:00Z");
        let mut note = record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("body"));
        note.ts = at("2026-09-17T09:00:00Z");
        let mut later = record("fixture/in-scope/later.md", Op::Fetch, Outcome::Admitted, Some("later"));
        later.ts = at("2026-09-18T10:00:00Z");

        let items = items_from_journal(&[gone, note, clear, later], ws.path());
        let paths: Vec<_> = items.iter().map(|i| i.path.as_str()).collect();
        // `note.md` predates the clear and is still on disk: the clear did not
        // get it, so it is listed. `later.md` is missing and came after.
        assert_eq!(paths, ["fixture/in-scope/later.md", "fixture/in-scope/note.md"]);
    }

    #[test]
    fn only_admitted_fetches_are_inventory() {
        let ws = workspace_with_note();
        let records = vec![
            record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("body")),
            // A read leaves nothing on disk to be current or missing.
            record("fixture/in-scope/other.md", Op::Read, Outcome::Admitted, Some("x")),
            // A refused fetch admitted nothing.
            record("fixture/elsewhere/secret.txt", Op::Fetch, Outcome::Refused, None),
            // An admission with no hash cannot be compared against anything.
            record("fixture/in-scope/nohash.md", Op::Fetch, Outcome::Admitted, None),
        ];
        let items = items_from_journal(&records, ws.path());
        let paths: Vec<&str> = items.iter().map(|i| i.path.as_str()).collect();
        assert_eq!(paths, vec!["fixture/in-scope/note.md"]);
        assert!(items[0].local_present, "the file is on disk and the item says so");
        assert_eq!(items[0].source, "fixture");
        assert!(!items[0].sidecar, "no sidecar was written");
    }

    #[test]
    fn a_sidecar_counts_only_when_it_names_this_admission() {
        let ws = workspace_with_note();
        let mut rec = record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("body"));
        rec.admission_id = Some(sluse_proto::AdmissionId::mint());
        let local = workspace::admitted_path(
            ws.path(),
            &sluse_proto::SourceName::new_unchecked("fixture"),
            "in-scope/note.md",
        );
        let manifest = |admission_id| crate::manifest::Manifest {
            admitted_from: "fixture/in-scope/note.md".to_owned(),
            source: sluse_proto::SourceName::new_unchecked("fixture"),
            resolved: "C:\\fixture\\in-scope\\note.md".to_owned(),
            admission_id,
            hash: ContentHash::of(b"body"),
            bytes: 4,
            session_id: sluse_proto::SessionId::mint(),
            config_version: ContentHash::of(b"config"),
            admitted_at: rec.ts,
            sensitivity: 2,
            sensitivity_name: "Internal".to_owned(),
        };

        // Left over from an earlier admission of the same path: not this one's.
        crate::manifest::write(&local, &manifest(sluse_proto::AdmissionId::mint())).unwrap();
        assert!(!items_from_journal(std::slice::from_ref(&rec), ws.path())[0].sidecar);

        crate::manifest::write(&local, &manifest(rec.admission_id.clone().unwrap())).unwrap();
        assert!(items_from_journal(std::slice::from_ref(&rec), ws.path())[0].sidecar);
    }

    #[test]
    fn a_refetch_supersedes_the_earlier_admission() {
        let ws = workspace_with_note();
        let mut first =
            record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("old"));
        first.ts = DateTime::parse_from_rfc3339("2026-09-18T09:00:00Z").unwrap().into();
        let second = record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("new"));

        let items = items_from_journal(&[first, second], ws.path());
        assert_eq!(items.len(), 1, "one file is one row however often it was fetched");
        assert_eq!(
            items[0].hash,
            ContentHash::of(b"new"),
            "the file on disk came from the later admission, so that is the hash to compare"
        );
    }

    #[test]
    fn a_hash_match_is_current_and_a_mismatch_is_stale() {
        let ws = workspace_with_note();
        let items = items_from_journal(
            &[record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("body"))],
            ws.path(),
        );
        let item = &items[0];

        let same = StatResponse {
            size: 4,
            modified: Utc::now(),
            hash: ContentHash::of(b"body"),
            matches_pinned: None,
        };
        assert_eq!(classify(item, Ok(same)), InventoryState::Current);

        let changed = StatResponse {
            size: 9,
            modified: Utc::now(),
            hash: ContentHash::of(b"different"),
            matches_pinned: None,
        };
        assert_eq!(classify(item, Ok(changed)), InventoryState::Stale);
    }

    #[test]
    fn a_source_that_refuses_is_orphaned_and_one_that_cannot_answer_is_unknown() {
        let ws = workspace_with_note();
        let items = items_from_journal(
            &[record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("body"))],
            ws.path(),
        );
        let item = &items[0];

        for refusal in [
            SluseError::AccessDenied { raw: item.path.clone(), detail: "ACCESS_DENIED".into() },
            SluseError::NotFound { raw: item.path.clone() },
            SluseError::UnknownSource { raw: item.path.clone() },
            SluseError::OutOfScope {
                raw: item.path.clone(),
                resolved: "/srv/fixture/in-scope/note.md".into(),
                source_name: "fixture".into(),
                scopes: vec!["fixture/in-scope".into()],
            },
        ] {
            assert_eq!(
                classify(item, Err(refusal.clone())),
                InventoryState::Orphaned,
                "{refusal:?} is the source answering, not a failure to ask"
            );
        }

        // The distinction the whole module exists for: not reaching the Gate
        // must never read as "unchanged".
        let unreachable = SluseError::GateUnreachable { detail: "connection refused".into() };
        assert_eq!(classify(item, Err(unreachable)), InventoryState::Unknown);
        assert!(!InventoryState::Unknown.is_answered());
    }

    #[test]
    fn a_deleted_local_copy_is_missing_whatever_the_source_says() {
        let ws = workspace_with_note();
        let items = items_from_journal(
            &[record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("body"))],
            ws.path(),
        );
        std::fs::remove_file(&items[0].local).unwrap();

        // Rebuilt, because `local_present` is answered by looking.
        let items = items_from_journal(
            &[record("fixture/in-scope/note.md", Op::Fetch, Outcome::Admitted, Some("body"))],
            ws.path(),
        );
        assert!(!items[0].local_present);

        let healthy = StatResponse {
            size: 4,
            modified: Utc::now(),
            hash: ContentHash::of(b"body"),
            matches_pinned: None,
        };
        assert_eq!(
            classify(&items[0], Ok(healthy)),
            InventoryState::Missing,
            "the source being fine does not put the file back"
        );
    }
}

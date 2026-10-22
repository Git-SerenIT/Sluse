// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// The name and the shape follow the S-2 stub's publish manifest
// (`spikes/s2-no-local-sources/endpoint/src/server.rs:304`), so a person who has
// read one recognises the other. What it describes is different: that one
// records a delivery, this one records an admission.

//! The sidecar beside every fetched file. **D-019 point 3.**
//!
//! A `fetch` writes `<file>` and `<file>.sluse-manifest.json` together. The
//! sidecar is what makes the first clause of invariant 5 true: a local copy can
//! be re-read through `sluse_read` and come back inside the same untrusted-data
//! envelope it arrived in, naming the source it came from, because the
//! provenance travelled with it instead of living only in a journal the agent
//! would have to be trusted to consult.
//!
//! ## It is not evidence, and nothing here pretends otherwise
//!
//! The sidecar is a file in the guest's own workspace, so anything that can run
//! code in the guest can write, edit or delete it. That is the same standing the
//! journal has — *functional, not a trust anchor* (`docs/audit.md`) — and it is
//! fine, because nothing decides anything from it:
//!
//! - **Publish lineage does not read it.** Lineage comes from the admissions the
//!   journal recorded in this process. A forged sidecar cannot put a source
//!   file's provenance on an artifact.
//! - **The broker never sees it.** No admission, no scope decision and no audit
//!   record on the host depends on a byte of it (invariant 2).
//! - **The worst a forged one achieves** is telling the model that a file the
//!   agent wrote itself is untrusted source material. That is the safe
//!   direction, and it is the direction a missing sidecar already errs in.
//!
//! What it buys is the honest case: material that really was admitted says so
//! when it is read again, and material that was modified afterwards is caught by
//! the hash rather than described as though it were still the admitted bytes.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sluse_proto::{AdmissionId, ContentHash, SessionId, SourceName};

/// Appended to the file's own name, so the pair sorts together and a copy of the
/// directory carries both.
pub const SUFFIX: &str = ".sluse-manifest.json";

/// What was admitted, written beside the file it describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Manifest {
    /// The request-form path this was admitted from: `<source>/<relative path>`.
    /// The path an agent would name to read it from the source again.
    pub admitted_from: String,
    pub source: SourceName,
    /// The host path the broker resolved it to. For a person reading the
    /// workspace later; the agent has no use for it.
    pub resolved: String,
    /// The broker's admission id. The join key, carried here so a file on disk
    /// can be traced to the host record that authorised it.
    pub admission_id: AdmissionId,
    /// The hash of the bytes as admitted. Re-hashing the file says whether it is
    /// still those bytes.
    pub hash: ContentHash,
    pub bytes: u64,
    pub session_id: SessionId,
    pub config_version: ContentHash,
    pub admitted_at: DateTime<Utc>,
    pub sensitivity: u8,
    /// What this deployment calls that level.
    pub sensitivity_name: String,
}

/// Where the sidecar for `file` goes.
pub fn path_for(file: &Path) -> PathBuf {
    let mut name = file.file_name().unwrap_or_default().to_os_string();
    name.push(SUFFIX);
    file.with_file_name(name)
}

/// Whether a name is a sidecar rather than admitted content.
pub fn is_manifest(name: &str) -> bool {
    name.ends_with(SUFFIX)
}

pub fn write(file: &Path, m: &Manifest) -> std::io::Result<PathBuf> {
    let target = path_for(file);
    let mut body = serde_json::to_vec_pretty(m)?;
    body.push(b'\n');
    std::fs::write(&target, body)?;
    Ok(target)
}

/// The sidecar beside `file`, if there is a readable one.
///
/// `None` covers three cases on purpose — no sidecar, an unreadable one, and one
/// that does not parse — because they mean the same thing to the only caller:
/// this file has no provenance Sluse can state, so the envelope must say so
/// rather than guess. A corrupt sidecar in the untrusted zone is not a fault to
/// report; it is an absence.
pub fn read(file: &Path) -> Option<Manifest> {
    let body = std::fs::read(path_for(file)).ok()?;
    serde_json::from_slice(&body).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> Manifest {
        Manifest {
            admitted_from: "fixture/in-scope/docs/note.txt".to_owned(),
            source: SourceName::parse("fixture").unwrap(),
            resolved: r"C:\fixture\in-scope\docs\note.txt".to_owned(),
            admission_id: AdmissionId::mint(),
            hash: ContentHash::of(b"note"),
            bytes: 4,
            session_id: SessionId::mint(),
            config_version: ContentHash::of(b"config"),
            admitted_at: Utc::now(),
            sensitivity: 2,
            sensitivity_name: "Internal".to_owned(),
        }
    }

    #[test]
    fn the_sidecar_sits_beside_the_file_it_describes() {
        let p = path_for(Path::new("/ws/admitted/fixture/docs/note.txt"));
        assert_eq!(p, PathBuf::from("/ws/admitted/fixture/docs/note.txt.sluse-manifest.json"));
        assert!(is_manifest(p.file_name().unwrap().to_str().unwrap()));
        assert!(!is_manifest("note.txt"));
    }

    #[test]
    fn it_round_trips_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note.txt");
        std::fs::write(&file, b"note").unwrap();

        let written = manifest();
        write(&file, &written).unwrap();
        assert_eq!(read(&file), Some(written));
    }

    /// Absent, unparseable and not-JSON are one answer, and it is the answer
    /// that makes the envelope say "no recorded provenance".
    #[test]
    fn a_missing_or_corrupt_sidecar_is_an_absence() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("note.txt");
        std::fs::write(&file, b"note").unwrap();
        assert_eq!(read(&file), None);

        std::fs::write(path_for(&file), b"{ not json").unwrap();
        assert_eq!(read(&file), None);

        // Valid JSON, wrong shape — a hand-edited sidecar, which is exactly
        // what the untrusted zone invites.
        std::fs::write(path_for(&file), br#"{"admittedFrom":"x"}"#).unwrap();
        assert_eq!(read(&file), None);
    }
}

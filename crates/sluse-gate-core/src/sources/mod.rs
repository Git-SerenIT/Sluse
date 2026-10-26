// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Reaching a source.
//!
//! One trait, three implementations, and a deliberate line about what a backend
//! is allowed to decide: **nothing**. By the time a backend is called, the path
//! has been through [`crate::scope`] and is known to be inside a configured
//! scope of a configured source. A backend performs I/O and maps its failures to
//! the error enum. It never consults scope, never compares a path, and never
//! decides whether something may be admitted — if it did, there would be two
//! answers to that question and eventually they would differ.
//!
//! ## Why `smb` is its own implementation and not a flag
//!
//! Local and UNC paths take the same Win32 calls, so the operations are
//! identical and the *failures* are not. A share that is not answering, a
//! credential that has expired, and a file that does not exist are one
//! `io::Error` each to the filesystem and three different things to a person
//! reading the audit trail — and `SourceUnavailable` against `NotFound` is the
//! difference between "the network is down" and "the agent asked for something
//! that is not there". The mapping is the implementation.
//!
//! ## Blocking I/O
//!
//! Every call here is blocking, including [`SourceBackend::open`], which returns
//! an already-open handle rather than a future. An SMB open on a share that has
//! gone away blocks until the redirector gives up, which is seconds. The HTTP
//! layer is responsible for putting these calls on a blocking thread; this
//! module is honest about being blocking rather than wrapping itself in an async
//! signature that hides it.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sluse_proto::{EntryKind, SluseError, SourceKind};

use crate::scope::CompiledSource;

mod local_folder;
mod sharepoint;
mod smb;

pub use local_folder::LocalFolder;
pub use sharepoint::SharePoint;
pub use smb::Smb;
pub(crate) use smb::{classify, Win32};

/// One directory entry, before scope has had an opinion about it.
///
/// Carries the child's own path so the caller can canonicalise it and ask
/// whether it may be shown: a listing's visibility decision is [`crate::scope`]'s
/// and is made on a resolved path, not on a name.
#[derive(Debug, Clone)]
pub struct RawEntry {
    pub name: String,
    pub kind: EntryKind,
    pub size: Option<u64>,
    pub modified: Option<DateTime<Utc>>,
    pub path: PathBuf,
}

/// What a stat returns before the bytes are hashed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Meta {
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub is_dir: bool,
}

/// What Gate Core can do to a source.
///
/// Every call takes both paths: `raw` is the request-form path the caller wrote
/// and `abs` is what it resolved to. The plan's sketch had `abs` alone, and it
/// was wrong — an error has to name the path the *agent* used, or the record and
/// the message both quote a host path that the guest was never told (invariant 2
/// works in the error path too).
pub trait SourceBackend: Send + Sync {
    /// The wire name of this kind, matching the config's `type` tag.
    fn kind(&self) -> &'static str;

    /// List a directory. The entries are unfiltered; scope filters them.
    fn list(&self, raw: &str, abs: &Path) -> Result<Vec<RawEntry>, SluseError>;

    /// Size, modified time and whether it is a directory.
    fn stat(&self, raw: &str, abs: &Path) -> Result<Meta, SluseError>;

    /// Open a file for reading.
    ///
    /// Returns a `tokio::fs::File` so the read route can stream it, but the open
    /// itself is blocking — see the module docs.
    fn open(&self, raw: &str, abs: &Path) -> Result<tokio::fs::File, SluseError>;
}

/// The backend for a compiled source.
pub fn backend_for(source: &CompiledSource) -> Box<dyn SourceBackend> {
    let name = source.name.as_str().to_owned();
    match &source.kind {
        SourceKind::LocalFolder { .. } => Box::new(LocalFolder::new(name)),
        SourceKind::Smb { .. } => Box::new(Smb::new(name)),
        SourceKind::Sharepoint { .. } => Box::new(SharePoint::new(name)),
        SourceKind::Inputs => Box::new(LocalFolder::inputs(name)),
        SourceKind::Onedrive => Box::new(SharePoint::onedrive(name)),
    }
}

// ---------------------------------------------------------------------------
// Shared filesystem operations
// ---------------------------------------------------------------------------

/// The operations `local-folder` and `smb` share, with the error mapping left to
/// the caller. Both call these; neither reimplements them.
pub(crate) mod fsops {
    use super::*;

    pub(crate) fn list(abs: &Path) -> std::io::Result<Vec<RawEntry>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(abs)? {
            let entry = entry?;
            // A single entry that cannot be stat'd — a file deleted between the
            // read_dir and the metadata call, a handle held exclusively — must
            // not fail the listing. It is listed with what is known.
            let meta = entry.metadata().ok();
            let kind = match &meta {
                Some(m) if m.is_dir() => EntryKind::Directory,
                Some(_) => EntryKind::File,
                None => EntryKind::File,
            };
            out.push(RawEntry {
                name: entry.file_name().to_string_lossy().into_owned(),
                kind,
                size: meta.as_ref().filter(|m| m.is_file()).map(|m| m.len()),
                modified: meta.as_ref().and_then(|m| m.modified().ok()).map(DateTime::<Utc>::from),
                path: entry.path(),
            });
        }
        out.sort_by_key(|e| e.name.to_lowercase());
        Ok(out)
    }

    pub(crate) fn stat(abs: &Path) -> std::io::Result<Meta> {
        let m = std::fs::metadata(abs)?;
        Ok(Meta {
            size: m.len(),
            // A filesystem with no modified time is not one Gate Core will meet
            // on Windows; the epoch is a visibly wrong value rather than a
            // plausible one.
            modified: m.modified().map(DateTime::<Utc>::from).unwrap_or_else(|_| DateTime::UNIX_EPOCH),
            is_dir: m.is_dir(),
        })
    }

    pub(crate) fn open(abs: &Path) -> std::io::Result<tokio::fs::File> {
        let file = std::fs::File::open(abs)?;
        Ok(tokio::fs::File::from_std(file))
    }
}

/// Is the storage under this path there at all? **D-015.**
///
/// Windows reports a dead network path as `ERROR_BAD_NETPATH` or
/// `ERROR_BAD_NET_NAME` and Rust decodes both to `io::ErrorKind::NotFound`, so
/// a share that has gone away arrives here indistinguishable from a file that
/// was never there — and D-008 then blinds it into the same "No such path". The
/// first scored run recorded 33 refusals that way while the file server's VM was
/// powered off, and the agent was told 125 files did not exist
/// (`prototype/results/2026-09-22-fetch-on/`).
///
/// A backend is handed an absolute path and never the configured root, so the
/// question it can ask is not "is the root there" — `scope::io_to_error` asks
/// that one, and it is the stronger check — but "is anything above this path
/// there". The first ancestor that exists means the storage is mounted and the
/// file genuinely is not there.
///
/// **This fires on Windows and effectively never on the guest**, and the
/// asymmetry is honest rather than accidental: what has no ancestor is a dead
/// UNC prefix or a disconnected drive letter, and on a POSIX filesystem `/`
/// always exists. The SMB backend catches the same condition earlier and more
/// precisely by Win32 code (`smb::classify`); this is the backstop for a local
/// path and for codes no list covers.
///
/// On the failure path only, so the cost is a handful of `try_exists` calls on a
/// request that has already failed, and nothing at all on the happy path.
pub(crate) fn storage_reachable(abs: &Path) -> bool {
    abs.ancestors().skip(1).any(|a| a.try_exists().unwrap_or(false))
}

/// Map an I/O failure on a local path.
///
/// `raw` is the request-form path, because that is what the record carries and
/// what the agent asked for; the host path never travels in an error message.
pub(crate) fn local_error(source_name: &str, raw: &str, abs: &Path, e: &std::io::Error) -> SluseError {
    match e.kind() {
        std::io::ErrorKind::NotFound if !storage_reachable(abs) => {
            SluseError::SourceUnavailable {
                source_name: source_name.to_owned(),
                detail: format!("nothing along the path exists: {e}"),
            }
        }
        std::io::ErrorKind::NotFound => SluseError::NotFound { raw: raw.to_owned() },
        std::io::ErrorKind::PermissionDenied => {
            SluseError::AccessDenied { raw: raw.to_owned(), detail: e.to_string() }
        }
        std::io::ErrorKind::NotADirectory => SluseError::NotADirectory { raw: raw.to_owned() },
        std::io::ErrorKind::IsADirectory => SluseError::NotAFile { raw: raw.to_owned() },
        _ => SluseError::SourceUnavailable {
            source_name: source_name.to_owned(),
            detail: e.to_string(),
        },
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The source backends.
//!
//! A backend decides nothing — scope has already decided by the time it is
//! called — so what is under test is the I/O and, mostly, the **classification**
//! of failure. `not_found` against `source_unavailable` is the difference
//! between "the agent asked for something that is not there" and "the share is
//! down", and a person reading a rate of the first when it is really the second
//! is being misled by the audit trail.

use std::fs;

use sluse_gate_core::sources::{backend_for, LocalFolder, SharePoint, SourceBackend};
use sluse_proto::{EntryKind, SluseError, SourceKind, SourceName};

fn local() -> LocalFolder {
    LocalFolder::new("fixture".to_owned())
}

fn reason(err: &SluseError) -> &'static str {
    err.reason_code()
}

#[test]
fn a_listing_is_sorted_and_carries_what_the_console_shows() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("zeta")).unwrap();
    fs::write(dir.path().join("Alpha.txt"), b"alpha").unwrap();
    fs::write(dir.path().join("beta.md"), b"beta!").unwrap();

    let entries = local().list("fixture", dir.path()).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
    // Case-insensitive, because a person reading a file browser does not think
    // of `Alpha.txt` as coming after `beta.md`.
    assert_eq!(names, vec!["Alpha.txt", "beta.md", "zeta"]);

    let alpha = &entries[0];
    assert_eq!(alpha.kind, EntryKind::File);
    assert_eq!(alpha.size, Some(5));
    assert!(alpha.modified.is_some());
    // The child's own path travels with it: visibility is decided on a resolved
    // path, never on a name.
    assert!(alpha.path.ends_with("Alpha.txt"));

    let zeta = &entries[2];
    assert_eq!(zeta.kind, EntryKind::Directory);
    assert_eq!(zeta.size, None, "a directory has no size worth reporting");
}

#[test]
fn stat_reports_size_and_kind() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("note.txt"), b"four").unwrap();

    let file = local().stat("fixture/note.txt", &dir.path().join("note.txt")).unwrap();
    assert_eq!(file.size, 4);
    assert!(!file.is_dir);

    let directory = local().stat("fixture", dir.path()).unwrap();
    assert!(directory.is_dir);
}

#[test]
fn open_gives_a_handle_to_the_bytes() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("note.txt"), b"note").unwrap();
    assert!(local().open("fixture/note.txt", &dir.path().join("note.txt")).is_ok());
}

#[test]
fn a_missing_file_is_not_found_and_names_the_request_not_the_host_path() {
    let dir = tempfile::tempdir().unwrap();
    let err = local().stat("fixture/nope.txt", &dir.path().join("nope.txt")).unwrap_err();
    assert_eq!(reason(&err), "NOT_FOUND");
    match err {
        // Invariant 2 holds in the error path too: the guest is told about the
        // path it wrote, never the one Gate Core resolved.
        SluseError::NotFound { raw } => assert_eq!(raw, "fixture/nope.txt"),
        other => panic!("expected NotFound, got {other}"),
    }
}

/// A path with no reachable prefix at all — a disconnected drive letter — is
/// the source being unavailable, not a missing file (D-015).
///
/// **Windows only, deliberately.** What this detects is a dead UNC prefix or an
/// unmapped drive; on a POSIX filesystem `/` always exists, so the branch cannot
/// be reached on the development guest. `docs/development.md` carries the list
/// of these, and CI runs them on every push.
#[test]
#[cfg(windows)]
fn a_path_with_no_reachable_prefix_is_the_source_being_unavailable() {
    let err = local()
        .stat("fixture/nope.txt", std::path::Path::new(r"Z:\no-such-root\nope.txt"))
        .unwrap_err();
    assert_eq!(reason(&err), "SOURCE_UNAVAILABLE");
}

#[test]
fn the_backend_for_a_source_matches_its_kind() {
    use sluse_gate_core::scope::CompiledSource;

    let sharepoint = CompiledSource {
        name: SourceName::parse("tender").unwrap(),
        kind: SourceKind::Sharepoint {
            site_url: "https://contoso.sharepoint.com/sites/tender".into(),
            library: "Documents".into(),
        },
        sensitivity: 3,
        root: None,
        scopes: Vec::new(),
        remote: Some(Vec::new()),
        unavailable: None,
        dropped: Vec::new(),
    };
    assert_eq!(backend_for(&sharepoint).kind(), "sharepoint");
}

/// A sharepoint source is served by `remote.rs` over Graph, never through the
/// filesystem trait. The trait's implementation stays as a refusal, so a caller
/// that reached it by mistake gets an error rather than a filesystem read.
#[test]
fn the_filesystem_backend_never_serves_sharepoint() {
    let dir = tempfile::tempdir().unwrap();
    let backend = SharePoint::new("tender".to_owned());

    for err in [
        backend.list("tender", dir.path()).unwrap_err(),
        backend.stat("tender/bid.docx", dir.path()).unwrap_err(),
        backend.open("tender/bid.docx", dir.path()).unwrap_err(),
    ] {
        assert_eq!(reason(&err), "UNSUPPORTED_SOURCE_KIND");
        // An error, not a refusal: nothing about the request was wrong, the
        // deployment named a source this build cannot serve.
        assert!(!err.is_refusal(), "a source this build cannot serve is not a refusal");
    }
}

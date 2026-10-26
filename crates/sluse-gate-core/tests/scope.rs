// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The scope table.
//!
//! Every row here is a way a path can leave the subtree it was supposed to stay
//! in, or a way two strings for the same directory can fail to compare equal.
//! The cheapest place to find out that a junction escapes a root is here; the
//! most expensive is a customer's audit log.
//!
//! These build a [`Compiled`] directly rather than going through a config file.
//! The loader has its own tests in `sluse-proto`; what is under test here is
//! what happens to a path *after* a config has loaded.

use std::fs;
use std::path::Path;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use sluse_gate_core::scope::{self, Canonical, Compiled, CompiledScope, CompiledSource};
use sluse_proto::{SluseError, SourceKind, SourceName};

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A source rooted at `root` with the given scopes, in request form.
///
/// An empty `scopes` compiles to the whole root, exactly as `compile` does for
/// an empty `scope` array in the config.
fn source(name: &str, root: &Path, scopes: &[&str]) -> CompiledSource {
    let root_canon = Canonical::of(root).expect("root exists");
    let compiled_scopes = if scopes.is_empty() {
        vec![CompiledScope { rel: String::new(), abs: root_canon.clone() }]
    } else {
        scopes
            .iter()
            .map(|rel| {
                let mut p = root_canon.real().to_path_buf();
                for part in rel.split('/') {
                    p.push(part);
                }
                CompiledScope {
                    rel: (*rel).to_owned(),
                    abs: Canonical::of(&p).expect("scope exists"),
                }
            })
            .collect()
    };
    CompiledSource {
        name: SourceName::parse(name).expect("valid source name"),
        kind: SourceKind::LocalFolder { root: root.to_string_lossy().into_owned() },
        sensitivity: 2,
        root: Some(root_canon),
        scopes: compiled_scopes,
        remote: None,
        unavailable: None,
        dropped: Vec::new(),
    }
}

/// A fixture tree:
///
/// ```text
/// <root>/in-scope/docs/note.txt
/// <root>/in-scope/docs/nested/deep.txt
/// <root>/elsewhere/secret.txt
/// ```
fn tree(root: &Path) {
    fs::create_dir_all(root.join("in-scope/docs/nested")).unwrap();
    fs::create_dir_all(root.join("elsewhere")).unwrap();
    fs::write(root.join("in-scope/docs/note.txt"), b"note").unwrap();
    fs::write(root.join("in-scope/docs/nested/deep.txt"), b"deep").unwrap();
    fs::write(root.join("elsewhere/secret.txt"), b"secret").unwrap();
}

fn reason(err: &SluseError) -> &'static str {
    err.reason_code()
}

// ---------------------------------------------------------------------------
// The grammar, decided before the filesystem is touched
// ---------------------------------------------------------------------------

#[test]
fn grammar_refuses_what_the_filesystem_should_never_see() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    // Every one of these is MalformedPath, not NotFound: refusing on the
    // grammar means the request never became a directory probe, so a malformed
    // path cannot be used to learn whether something exists.
    for bad in [
        "",
        "   ",
        "/fixture/in-scope",
        "C:/Windows/System32",
        "c:\\windows",
        "fixture/../../windows",
        "fixture/in-scope/../../elsewhere/secret.txt",
        "fixture/in-scope/./docs",
        "fixture/docs/note.txt:hidden",
        "fixture/in-scope\u{0}/docs",
    ] {
        let err = scope::resolve(&compiled, bad).expect_err(bad);
        assert_eq!(reason(&err), "MALFORMED_PATH", "{bad} should be malformed, got {err}");
    }
}

#[test]
fn backslashes_are_accepted_as_separators() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    // A person pasting a Windows path fragment into a prompt is not an attack,
    // and the agent copies what it is given.
    let scoped = scope::resolve(&compiled, "fixture\\in-scope\\docs\\note.txt").unwrap();
    assert_eq!(scoped.rel, "in-scope/docs/note.txt");
    assert!(scoped.in_scope);
}

#[test]
fn a_root_that_has_gone_away_is_unavailable_rather_than_absent() {
    // **D-015, and the first scored run is why this test exists.** The file
    // server's VM powered off mid-run; every request after that was recorded
    // `NOT_FOUND` and blinded to "No such path", so the agent was told that 125
    // files it had just listed did not exist
    // (`prototype/results/2026-09-22-fetch-on/`). Windows reports a lost network
    // path as ERROR_BAD_NETPATH and Rust decodes it to `ErrorKind::NotFound`, so
    // resolution — which runs before any backend — could not tell the two apart.
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    // The root existed when it was compiled, as it must have for Gate Core to
    // be running at all, and then it went away.
    let root = dir.path().to_path_buf();
    dir.close().unwrap();
    assert!(!root.exists(), "the fixture root is gone");

    let err = scope::resolve(&compiled, "fixture/in-scope/docs/note.txt").unwrap_err();
    assert_eq!(
        err.reason_code(),
        "SOURCE_UNAVAILABLE",
        "an unreachable root is an unanswerable question, not a negative answer"
    );
    match &err {
        SluseError::SourceUnavailable { source_name, detail } => {
            assert_eq!(source_name, "fixture");
            assert!(!detail.is_empty(), "the record's only evidence that this was an outage");
        }
        other => panic!("expected SourceUnavailable, got {other}"),
    }
}

#[test]
fn a_missing_file_under_a_live_root_is_still_absent() {
    // The other half of D-015: the probe must not turn every NotFound into an
    // outage. A root that is there and a file that is not is the ordinary case
    // D-008 blinds, and it has to stay blinded.
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    let err = scope::resolve(&compiled, "fixture/in-scope/docs/nope.txt").unwrap_err();
    assert_eq!(err.reason_code(), "NOT_FOUND");
}

#[test]
fn unknown_source_is_its_own_refusal() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    let err = scope::resolve(&compiled, "sharepoint/anything.docx").unwrap_err();
    assert_eq!(reason(&err), "UNKNOWN_SOURCE");
}

// ---------------------------------------------------------------------------
// Scope, and the difference between absent and forbidden
// ---------------------------------------------------------------------------

#[test]
fn in_scope_file_resolves_and_names_its_scope() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope/docs"])] };

    let scoped = scope::resolve(&compiled, "fixture/in-scope/docs/note.txt").unwrap();
    assert!(scoped.in_scope);
    assert_eq!(scoped.scope.as_deref(), Some("fixture/in-scope/docs"));
    assert_eq!(scoped.rel, "in-scope/docs/note.txt");
    assert!(scoped.path.display().ends_with("note.txt"));
    // The resolved path a record carries never has the verbatim prefix.
    assert!(!scoped.path.display().starts_with(r"\\?\"));
}

#[test]
fn a_directory_on_the_way_to_a_scope_lists_but_does_not_read() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope/docs"])] };

    // D-008: the agent has to be able to walk to what it may have.
    let scoped = scope::resolve(&compiled, "fixture/in-scope").unwrap();
    assert!(!scoped.in_scope);
    assert_eq!(scoped.scope, None);

    // And no further: the same path is refused for a read.
    let err = scope::resolve_in_scope(&compiled, "fixture/in-scope").unwrap_err();
    assert_eq!(reason(&err), "OUT_OF_SCOPE");
}

#[test]
fn out_of_scope_is_refused_and_records_what_it_was() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    let err = scope::resolve(&compiled, "fixture/elsewhere/secret.txt").unwrap_err();
    assert_eq!(reason(&err), "OUT_OF_SCOPE");
    // Gate Core's record keeps the detail the agent never sees: this is the
    // refusal the endpoint turns into "no such path".
    match err {
        SluseError::OutOfScope { resolved, source_name, .. } => {
            assert!(resolved.ends_with("secret.txt"));
            assert_eq!(source_name, "fixture");
        }
        other => panic!("expected OutOfScope, got {other}"),
    }
}

#[test]
fn a_missing_path_and_a_forbidden_one_are_different_events() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    let missing = scope::resolve(&compiled, "fixture/in-scope/nope.txt").unwrap_err();
    let forbidden = scope::resolve(&compiled, "fixture/elsewhere/secret.txt").unwrap_err();
    assert_eq!(reason(&missing), "NOT_FOUND");
    assert_eq!(reason(&forbidden), "OUT_OF_SCOPE");
    // Both become one message at the endpoint. Here they must not.
    assert_ne!(reason(&missing), reason(&forbidden));
}

#[test]
fn empty_scope_means_the_whole_root() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &[])] };

    let scoped = scope::resolve(&compiled, "fixture/elsewhere/secret.txt").unwrap();
    assert!(scoped.in_scope);
    assert_eq!(scoped.scope.as_deref(), Some("fixture"));
}

#[test]
fn several_scopes_each_admit_their_own_subtree() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled =
        Compiled { sources: vec![source("fixture", dir.path(), &["in-scope/docs", "elsewhere"])] };

    let a = scope::resolve(&compiled, "fixture/in-scope/docs/note.txt").unwrap();
    let b = scope::resolve(&compiled, "fixture/elsewhere/secret.txt").unwrap();
    assert_eq!(a.scope.as_deref(), Some("fixture/in-scope/docs"));
    assert_eq!(b.scope.as_deref(), Some("fixture/elsewhere"));
}

// ---------------------------------------------------------------------------
// Containment, where the string comparisons go wrong
// ---------------------------------------------------------------------------

#[test]
#[cfg(windows)]
fn case_differences_do_not_change_what_is_in_scope() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };

    // NTFS is case-insensitive: these are one file. A raw `starts_with` on the
    // configured scope would admit one spelling and refuse the other.
    let a = scope::resolve(&compiled, "fixture/IN-SCOPE/DOCS/NOTE.TXT").unwrap();
    assert!(a.in_scope);
    assert_eq!(a.scope.as_deref(), Some("fixture/in-scope"));
}

#[test]
fn a_sibling_with_a_longer_name_is_not_inside_the_scope() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir_all(dir.path().join("tender")).unwrap();
    fs::create_dir_all(dir.path().join("tender-archive")).unwrap();
    fs::write(dir.path().join("tender/a.txt"), b"a").unwrap();
    fs::write(dir.path().join("tender-archive/b.txt"), b"b").unwrap();
    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["tender"])] };

    // `tender-archive` starts with `tender`. The boundary is a separator, not a
    // prefix — Chaperone met this one as `\\srv\share2` against `\\srv\share`.
    assert!(scope::resolve(&compiled, "fixture/tender/a.txt").unwrap().in_scope);
    let err = scope::resolve(&compiled, "fixture/tender-archive/b.txt").unwrap_err();
    assert_eq!(reason(&err), "OUT_OF_SCOPE");
}

#[test]
#[cfg(windows)]
fn a_junction_out_of_the_root_is_refused() {
    // The check that only exists because canonicalisation happens: an
    // unresolved-path check admits this, and Chaperone has no handling for it
    // at all.
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("payroll.csv"), b"salaries").unwrap();

    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let link = dir.path().join("in-scope").join("escape");
    // `raw_arg`, not `args`: Rust quotes arguments for the usual C runtime
    // parser and `cmd.exe` re-parses the result, which turns a perfectly
    // ordinary path into "Invalid switch". The command line goes across
    // verbatim instead.
    let made = std::process::Command::new("cmd")
        .raw_arg(format!(
            "/c mklink /J \"{}\" \"{}\"",
            link.display(),
            outside.path().display()
        ))
        .output()
        .expect("cmd runs");
    // A junction needs no elevation, but a policy or a filesystem that will not
    // make one must not turn into a green test.
    assert!(
        made.status.success(),
        "could not create a junction, so this check did not run: {}",
        String::from_utf8_lossy(&made.stderr)
    );

    let compiled = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };
    let err = scope::resolve(&compiled, "fixture/in-scope/escape/payroll.csv").unwrap_err();
    assert_eq!(reason(&err), "OUT_OF_SCOPE");
    match err {
        SluseError::OutOfScope { resolved, .. } => {
            // The record shows where it actually went, which is the fact a
            // person needs.
            assert!(resolved.to_lowercase().contains("payroll.csv"));
        }
        other => panic!("expected OutOfScope, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// Listing visibility, which is D-008 in two lines
// ---------------------------------------------------------------------------

#[test]
fn visibility_covers_scopes_and_the_way_to_them_and_nothing_else() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let src = source("fixture", dir.path(), &["in-scope/docs"]);

    let in_scope = Canonical::of(&dir.path().join("in-scope/docs/nested")).unwrap();
    let on_the_way = Canonical::of(&dir.path().join("in-scope")).unwrap();
    let neither = Canonical::of(&dir.path().join("elsewhere")).unwrap();

    assert!(src.visible(&in_scope), "inside a scope");
    assert!(src.visible(&on_the_way), "an ancestor of a scope");
    assert!(!src.visible(&neither), "neither");

    // Visible is not the same as readable.
    assert!(src.admitting_scope(&in_scope).is_some());
    assert!(src.admitting_scope(&on_the_way).is_none());
}

#[test]
fn scope_request_forms_never_leak_a_host_path() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    let src = source("fixture", dir.path(), &["in-scope/docs"]);

    // Invariant 2: the config view tells the guest what its world is called,
    // never where it is.
    assert_eq!(src.scope_request_forms(), vec!["fixture/in-scope/docs".to_owned()]);
}

// ---------------------------------------------------------------------------
// UNC
// ---------------------------------------------------------------------------

/// Ignored by default: it reaches `\\FS01\share` over SMB.
///
/// jok's call at M2 was to build the `smb` backend now and exercise it at M6,
/// when IT has been told. Run it with `cargo test -- --ignored` once
/// `\\FS01\share\sluse-fixture` exists.
#[test]
#[ignore = "reaches the share; M6"]
#[cfg(windows)]
fn unc_root_compares_in_canonical_form() {
    let root = Path::new(r"\\FS01\share\sluse-fixture");
    let canon = Canonical::of(root).expect("share reachable");
    // canonicalize returns \\?\UNC\server\share\...; the display form is the UNC
    // a person would type, and the key is what containment uses.
    assert!(canon.display().starts_with(r"\\FS01") || canon.display().starts_with(r"\\fs01"));
    assert!(!canon.display().starts_with(r"\\?\"));
    assert!(canon.within(&canon));
}

// ---------------------------------------------------------------------------
// The write paths
// ---------------------------------------------------------------------------

/// Build a config whose `artifacts`, `workspace` and `journalDir` are whatever
/// the caller says, with one local-folder source rooted at `root`.
fn config_with_write_paths(
    dir: &Path,
    root: &Path,
    artifacts: &str,
    workspace: &str,
    journal: &str,
) -> sluse_proto::Loaded {
    let authored = format!(
        r#"{{
          "schemaVersion": 3,
          "sources": [{{
            "name": "fixture",
            "kind": {{ "type": "local-folder", "address": {{ "root": {root} }} }},
            "scope": ["in-scope"],
            "sensitivity": 1
          }}],
          "volume": {{ "admissions": 25, "windowSeconds": 60 }}
        }}"#,
        root = serde_json::to_string(root).unwrap(),
    );
    let device = format!(
        r#"{{
          "boxId": "box-local-test",
          "environment": "local",
          "gate": {{
            "listen": "127.0.0.1:7580", "url": "https://127.0.0.1:7580",
            "certPath": "certs/core.pem", "keyPath": "certs/core.key",
            "clientCaPath": "certs/client-ca.pem", "certPin": "{zero}"
          }},
          "endpoint": {{
            "clientCertPath": "certs/endpoint.pem",
            "clientKeyPath": "certs/endpoint.key",
            "consoleListen": "127.0.0.1:7582"
          }},
          "artifacts": {artifacts},
          "workspace": {workspace},
          "journalDir": {journal},
          "audit": {{ "sink": "jsonl", "path": "audit/core.jsonl" }}
        }}"#,
        artifacts = serde_json::to_string(artifacts).unwrap(),
        workspace = serde_json::to_string(workspace).unwrap(),
        journal = serde_json::to_string(journal).unwrap(),
        zero = "0".repeat(64),
    );
    sluse_proto::config::load_from_bytes(authored.as_bytes(), device.as_bytes(), &dir.join("local.json")).unwrap()
}

#[test]
fn write_paths_outside_every_source_compile() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("fixture");
    tree(&root);

    let loaded = config_with_write_paths(dir.path(), &root, "artifacts", "workspace", "journal");
    assert!(scope::compile(&loaded).is_ok());
}

#[test]
fn an_artifacts_directory_inside_a_source_is_a_compile_failure() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("fixture");
    tree(&root);

    // The failure this exists to stop: an agent publishes a file into the
    // artifacts directory, then reads it back as an admitted source file, and
    // the provenance record says it came from the source.
    let inside = root.join("in-scope").join("out");
    let loaded = config_with_write_paths(
        dir.path(),
        &root,
        &inside.to_string_lossy(),
        "workspace",
        "journal",
    );

    let err = scope::compile(&loaded).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("artifacts"), "{text}");
    assert!(text.contains("inside source \"fixture\""), "{text}");
}

#[test]
fn a_write_path_that_does_not_exist_yet_is_still_checked_against_its_parent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("fixture");
    tree(&root);

    // `deep/out` does not exist; `in-scope` does. A directory Gate Core will
    // create inside a source root is still inside it, and canonicalising the
    // nearest existing ancestor is what catches it.
    let not_yet = root.join("in-scope").join("deep").join("out");
    let loaded = config_with_write_paths(
        dir.path(),
        &root,
        "artifacts",
        &not_yet.to_string_lossy(),
        "journal",
    );

    let err = scope::compile(&loaded).unwrap_err();
    assert!(err.to_string().contains("workspace"), "{err}");
}

#[test]
#[cfg(windows)]
fn a_write_path_that_reaches_a_source_through_a_junction_is_caught() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("fixture");
    tree(&root);

    // The reason this check needs the filesystem and cannot live in the loader:
    // `<dir>\artifacts` and `<root>\in-scope` are the same directory, and the
    // two strings do not resemble each other.
    let link = dir.path().join("artifacts");
    let target = root.join("in-scope");
    let status = std::process::Command::new("cmd")
        .raw_arg(format!(r#"/c mklink /J "{}" "{}""#, link.display(), target.display()))
        .status()
        .expect("mklink");
    if !status.success() {
        eprintln!("skipped: could not create a junction");
        return;
    }

    let loaded = config_with_write_paths(dir.path(), &root, "artifacts", "workspace", "journal");
    let err = scope::compile(&loaded).unwrap_err();
    assert!(err.to_string().contains("artifacts"), "{err}");
}

// ---------------------------------------------------------------------------
// Remote sources (M7): lexical, case-folded, bounded by segments
// ---------------------------------------------------------------------------

fn library(scopes: &[&str]) -> sluse_gate_core::scope::Compiled {
    use sluse_gate_core::scope::RemoteScope;
    let remote = if scopes.is_empty() {
        vec![RemoteScope { rel: String::new(), key: String::new() }]
    } else {
        scopes.iter().map(|s| RemoteScope { rel: (*s).to_owned(), key: s.to_lowercase() }).collect()
    };
    sluse_gate_core::scope::Compiled {
        sources: vec![CompiledSource {
            name: SourceName::parse("spo").unwrap(),
            kind: SourceKind::Sharepoint {
                site_url: "https://contoso.sharepoint.com/sites/tender".into(),
                library: "Documents".into(),
            },
            sensitivity: 2,
            root: None,
            scopes: Vec::new(),
            remote: Some(remote),
            unavailable: None,
            dropped: Vec::new(),
        }],
    }
}

#[test]
fn a_remote_scope_is_a_segment_boundary_not_a_string_prefix() {
    use sluse_gate_core::scope::{resolve_remote, resolve_remote_in_scope};
    let c = library(&["Bids/2026"]);

    // In scope, whatever the case: SharePoint's paths are case-insensitive.
    let ok = resolve_remote_in_scope(&c, "spo/bids/2026/offer.docx").unwrap();
    assert_eq!(ok.scope.as_deref(), Some("spo/Bids/2026"));
    assert!(resolve_remote_in_scope(&c, "spo/BIDS/2026").is_ok());

    // `2026-old` starts with `2026` and is a different folder.
    let err = resolve_remote_in_scope(&c, "spo/Bids/2026-old/x.docx").unwrap_err();
    assert_eq!(err.reason_code(), "OUT_OF_SCOPE");

    // On the way to the scope: listable, not readable.
    assert!(resolve_remote(&c, "spo/Bids", true).is_ok());
    assert_eq!(resolve_remote_in_scope(&c, "spo/Bids").unwrap_err().reason_code(), "OUT_OF_SCOPE");

    // The grammar is the filesystem sources' grammar.
    for bad in ["spo/Bids/2026/../../HR", "spo/Bids/./2026", "/spo/Bids", "spo/Bids/2026/a:b"] {
        assert_eq!(resolve_remote_in_scope(&c, bad).unwrap_err().reason_code(), "MALFORMED_PATH", "{bad}");
    }
    // A source that is not there is the same blinded refusal as elsewhere.
    assert_eq!(resolve_remote_in_scope(&c, "other/x").unwrap_err().reason_code(), "UNKNOWN_SOURCE");
}

#[test]
fn an_empty_remote_scope_means_the_whole_library() {
    let c = library(&[]);
    assert!(sluse_gate_core::scope::resolve_remote_in_scope(&c, "spo/anything/at/all.txt").is_ok());
    assert!(sluse_gate_core::scope::resolve_remote_in_scope(&c, "spo").is_ok());
}

// ---------------------------------------------------------------------------
// Sluse Inputs (D-054)
// ---------------------------------------------------------------------------

/// Created at compile, the whole folder in scope, and a link out of it is
/// out of scope by its real path. A Windows junction is the host's to prove.
#[test]
fn sluse_inputs_is_created_at_compile_and_a_link_out_of_it_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("fixture");
    tree(&root);
    let mut loaded = config_with_write_paths(dir.path(), &root, "artifacts", "workspace", "journal");
    loaded.config.sources.push(sluse_proto::SourceConfig {
        name: SourceName::parse("inputs").unwrap(),
        kind: SourceKind::Inputs,
        scope: Vec::new(),
        sensitivity: 1,
    });
    let inputs = dir.path().join("profile").join("Sluse Inputs");

    let compiled = scope::compile_with(&loaded, Some(&inputs)).unwrap();
    assert!(inputs.is_dir(), "created at compile");
    fs::write(inputs.join("mail.docx"), b"attachment").unwrap();
    assert!(scope::resolve_in_scope(&compiled, "inputs/mail.docx").is_ok());

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(root.join("elsewhere"), inputs.join("away")).unwrap();
        let err = scope::resolve_in_scope(&compiled, "inputs/away/secret.txt").unwrap_err();
        assert_eq!(reason(&err), "OUT_OF_SCOPE", "{err}");
    }
    // No profile, no Sluse Inputs: that source is unavailable, the rest serve.
    let without = scope::compile_with(&loaded, None).unwrap();
    assert!(without.source("inputs").unwrap().unavailable.is_some());
    assert_eq!(reason(&scope::resolve_in_scope(&without, "inputs/mail.docx").unwrap_err()), "SOURCE_UNAVAILABLE");
    assert!(scope::resolve_in_scope(&without, "fixture/in-scope/docs/note.txt").is_ok());
}

/// Review R-22: a root that cannot be reached at start (a file server off the
/// VPN) does not stop Gate Core. That source is unavailable; the others
/// serve. A scope entry that cannot be resolved is dropped, and if every one
/// is, the source is unavailable: never widened to its whole root.
#[test]
fn an_unreachable_root_or_scope_makes_its_source_unavailable_not_the_core() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("fixture");
    tree(&root);
    let mut loaded = config_with_write_paths(dir.path(), &root, "artifacts", "workspace", "journal");
    let local = |name: &str, root: &Path, scope: &[&str]| sluse_proto::SourceConfig {
        name: SourceName::parse(name).unwrap(),
        kind: SourceKind::LocalFolder { root: root.to_string_lossy().into_owned() },
        scope: scope.iter().map(|s| (*s).to_owned()).collect(),
        sensitivity: 1,
    };
    loaded.config.sources.push(local("share", &dir.path().join("not-mounted"), &[]));
    loaded.config.sources.push(local("half", &root, &["in-scope", "gone"]));
    loaded.config.sources.push(local("none", &root, &["gone", "also-gone"]));

    let compiled = scope::compile(&loaded).expect("reachability is not validity");
    assert!(compiled.source("share").unwrap().unavailable.is_some());
    assert_eq!(reason(&scope::resolve(&compiled, "share/anything").unwrap_err()), "SOURCE_UNAVAILABLE");

    let half = compiled.source("half").unwrap();
    assert!(half.unavailable.is_none());
    assert_eq!(half.scopes.len(), 1);
    assert_eq!(half.dropped.len(), 1, "{:?}", half.dropped);
    assert!(scope::resolve_in_scope(&compiled, "half/in-scope/docs/note.txt").is_ok());
    assert_eq!(reason(&scope::resolve_in_scope(&compiled, "half/elsewhere/secret.txt").unwrap_err()), "OUT_OF_SCOPE");

    let none = compiled.source("none").unwrap();
    assert!(none.unavailable.is_some() && none.scopes.is_empty());
    assert_eq!(reason(&scope::resolve(&compiled, "none/elsewhere/secret.txt").unwrap_err()), "SOURCE_UNAVAILABLE");

    assert!(scope::resolve_in_scope(&compiled, "fixture/in-scope/docs/note.txt").is_ok());
}

/// Review R-25: on an `smb` source a link below the root is refused, not
/// followed, even one that stays inside the scope; the server would traverse
/// a junction on its own side and canonicalisation would not see it. A local
/// source keeps canonicalisation, which a local link cannot hide from. Here
/// a Unix symlink stands in; the server-side junction is L1's to prove.
#[cfg(unix)]
#[test]
fn a_link_on_a_share_is_refused_and_one_on_a_local_folder_is_resolved() {
    let dir = tempfile::tempdir().unwrap();
    tree(dir.path());
    std::os::unix::fs::symlink(dir.path().join("in-scope/docs/nested"), dir.path().join("in-scope/docs/link")).unwrap();

    let local = Compiled { sources: vec![source("fixture", dir.path(), &["in-scope"])] };
    assert!(scope::resolve_in_scope(&local, "fixture/in-scope/docs/link/deep.txt").is_ok());

    let mut share = source("fixture", dir.path(), &["in-scope"]);
    share.kind = SourceKind::Smb { unc: r"\\fs\share".into() };
    let share = Compiled { sources: vec![share] };
    let err = scope::resolve_in_scope(&share, "fixture/in-scope/docs/link/deep.txt").unwrap_err();
    assert_eq!(reason(&err), "OUT_OF_SCOPE", "{err}");
    assert!(scope::resolve_in_scope(&share, "fixture/in-scope/docs/nested/deep.txt").is_ok());
}

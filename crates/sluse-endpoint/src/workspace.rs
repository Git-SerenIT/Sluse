// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from the S-2 stub's endpoint/src/server.rs:workspace_relative.

//! The guest's own directory.
//!
//! The workspace is where `fetch` puts files and where `publish` reads them
//! from. It is **inside the box** and nothing here is a security boundary: an
//! agent that can run code in the guest can read and write the whole workspace
//! whatever this module says. The checks exist so that a *path the agent names
//! in a tool call* cannot reach outside it by accident or by prompt — which
//! keeps the journal describing what actually happened, and keeps a publish from
//! delivering a file the agent never fetched.
//!
//! The enforcing decision is always the broker's, on the far side of the
//! boundary (invariant 2). This is hygiene.

use std::path::{Component, Path, PathBuf};

use sluse_proto::{ContentHash, SluseError, SourceName};

use crate::manifest::{self, Manifest};

/// Where a fetched file lands: `<workspace>/admitted/<source>/<relative path>`.
///
/// Mirroring the source's shape rather than flattening it, so an agent that
/// fetched `tender/docs/bid.md` finds it at a path it can predict, and so two
/// files of the same name from different sources do not collide.
///
/// Split as the broker splits a request: `/` and `\` alike, empty and `.`
/// segments dropped. Joined whole, `src//x` was an absolute path that left the
/// workspace, and `a\b` a file named with a backslash (review R-30). A `..`
/// never gets here: the broker refuses it before a byte is written.
pub fn admitted_path(workspace: &Path, source: &SourceName, rel: &str) -> PathBuf {
    let mut at = workspace.join("admitted").join(source.as_str());
    for part in rel.split(['/', '\\']).filter(|p| !p.is_empty() && *p != ".") {
        at.push(part);
    }
    at
}

/// What a partial fetch's name ends with.
const PARTIAL: &str = ".sluse-partial";

/// The sibling a fetch streams into until it is whole (review R-13):
/// `.<name>.sluse-partial`, hidden, beside where the copy will land.
pub fn partial_path(destination: &Path) -> PathBuf {
    let name = destination.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    destination.with_file_name(format!(".{name}{PARTIAL}"))
}

/// Remove the partial fetches a killed process left under `admitted/`, and
/// return how many. Clear calls it, not the endpoint's start: a second
/// runtime's fetch may be streaming into one at that moment. Never follows a link out: a partial file is the
/// endpoint's own, and only a plain file is one.
pub fn sweep_partial(workspace: &Path) -> usize {
    fn walk(dir: &Path, removed: &mut usize) {
        let Ok(entries) = std::fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            let path = entry.path();
            if kind.is_dir() {
                walk(&path, removed);
            } else if kind.is_file()
                && entry.file_name().to_string_lossy().ends_with(PARTIAL)
                && std::fs::remove_file(&path).is_ok()
            {
                *removed += 1;
            }
        }
    }
    let mut removed = 0;
    walk(&workspace.join("admitted"), &mut removed);
    removed
}

/// Resolve a path the agent named, relative to the workspace.
///
/// Refuses absolute paths, drive prefixes and `..` before touching the
/// filesystem, then canonicalises and checks containment — because a symlink or
/// a junction inside the workspace makes a path that passed the grammar land
/// somewhere else, and only canonicalisation sees that.
pub fn resolve(workspace: &Path, raw: &str) -> Result<PathBuf, SluseError> {
    let joined = workspace.join(relative(raw)?);
    let canonical = std::fs::canonicalize(&joined)
        .map_err(|_| SluseError::NotFound { raw: raw.to_owned() })?;

    // The workspace itself is canonicalised too: comparing a canonical path
    // against a non-canonical root is how an 8.3 short name or a substituted
    // drive slips through.
    let root = std::fs::canonicalize(workspace).map_err(|e| SluseError::Internal {
        message: format!("the workspace cannot be resolved: {e}"),
    })?;

    if !canonical.starts_with(&root) {
        return Err(SluseError::MalformedPath {
            raw: raw.to_owned(),
            reason: "it resolves outside your workspace".to_owned(),
        });
    }
    Ok(canonical)
}

/// Write a file the agent gave as content into the workspace (D-048 point 1):
/// Claude Desktop's chat makes its files in the provider's sandbox, so it
/// has nothing in the box to name. Refuses the grammar `resolve` refuses, and
/// a path through a link, since the endpoint would write where the link
/// points; [`resolve`] then checks containment as for any other file.
///
/// ponytail: the link check and the write are not atomic; an agent that can
/// race a link into the workspace can already write the box's disk itself.
pub fn write(workspace: &Path, raw: &str, bytes: &[u8]) -> Result<(), SluseError> {
    let at = place(workspace, raw)?;
    std::fs::write(&at, bytes).map_err(|e| SluseError::Internal { message: format!("writing {raw} into the workspace: {e}") })
}

/// Where [`write`] puts `raw`, its folders made: the grammar, and no link on
/// the way (D-048, D-049). Also where a rendered file is written.
pub fn place(workspace: &Path, raw: &str) -> Result<PathBuf, SluseError> {
    let rel = relative(raw)?;
    let mut at = workspace.to_path_buf();
    for c in rel.components() {
        at.push(c);
        if at.symlink_metadata().is_ok_and(|m| m.file_type().is_symlink()) {
            return Err(SluseError::MalformedPath { raw: raw.to_owned(), reason: "it passes through a link".to_owned() });
        }
    }
    if let Some(parent) = at.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| SluseError::Internal { message: format!("making {raw}'s folder in the workspace: {e}") })?;
    }
    Ok(at)
}

/// The grammar of a workspace path, before the filesystem is touched.
fn relative(raw: &str) -> Result<PathBuf, SluseError> {
    let malformed = |reason: &str| SluseError::MalformedPath {
        raw: raw.to_owned(),
        reason: reason.to_owned(),
    };

    if raw.trim().is_empty() {
        return Err(malformed("empty"));
    }
    if raw.chars().any(|c| c.is_control()) {
        return Err(malformed("a control character"));
    }

    // This is a grammar for paths an *agent* names in a tool call, not for the
    // filesystem underneath, so it answers the same way on both platforms
    // (D-011). Two things `std::path` only does on Windows are therefore done
    // by hand: a drive prefix is spelled out, and `\` is a separator rather
    // than a legal filename character. The cost is that a POSIX file genuinely
    // named `a\b.md` is unreachable through this API, which is a shape no
    // fetch ever writes.
    let drive_qualified = {
        let b = raw.as_bytes();
        b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
    };
    let unified = raw.replace('\\', "/");
    let rel = Path::new(&unified);
    if rel.is_absolute() || drive_qualified || unified.starts_with('/') {
        return Err(malformed("absolute; workspace paths are relative to your working directory"));
    }
    for component in rel.components() {
        match component {
            Component::ParentDir => return Err(malformed("a `..` segment")),
            Component::Prefix(_) => return Err(malformed("a drive or UNC prefix")),
            Component::RootDir => return Err(malformed("a root segment")),
            _ => {}
        }
    }

    Ok(rel.to_path_buf())
}

/// What a local read found: the bytes, their hash now, and what the sidecar
/// beside them says they were.
#[derive(Debug)]
pub struct Local {
    pub bytes: Vec<u8>,
    /// The hash of the bytes **as they are now**. Compare it with
    /// `provenance.hash` to learn whether the copy is still what was admitted.
    pub hash: ContentHash,
    pub provenance: Option<Manifest>,
}

/// Read a file out of the workspace, with the same cap a source read has.
///
/// **D-019 point 3**, and the whole of it that can be decided without a journal:
/// resolve the path inside the workspace, refuse a directory, refuse anything
/// over `limit` **from the metadata, before any bytes are loaded** — a fetched
/// 500 MB file must not become 500 MB of context through the side door — then
/// hash what was read and pick up the sidecar if there is one.
///
/// Nothing here is a boundary; see this module's note. The broker is not asked,
/// because the bytes are already inside the box and were admitted once already.
pub fn read_local(workspace: &Path, raw: &str, limit: u64) -> Result<Local, SluseError> {
    let file = resolve(workspace, raw)?;
    let meta = std::fs::metadata(&file)
        // `resolve` canonicalised it, so this is a file that went away in
        // between. Not found, rather than a fault.
        .map_err(|_| SluseError::NotFound { raw: raw.to_owned() })?;
    if meta.is_dir() {
        return Err(SluseError::NotAFile { raw: raw.to_owned() });
    }
    if meta.len() > limit {
        return Err(SluseError::TooLarge { raw: raw.to_owned(), size: meta.len(), limit });
    }
    let bytes = std::fs::read(&file).map_err(|e| SluseError::Internal {
        message: format!("reading {raw}: {e}"),
    })?;
    Ok(Local { hash: ContentHash::of(&bytes), provenance: manifest::read(&file), bytes })
}

/// The name an artifact is published under, when the agent did not give one.
///
/// The workspace-relative path with forward slashes, so `crates/x/src/lib.rs`
/// publishes as itself and the delivery keeps the shape the agent built.
pub fn default_artifact_name(raw: &str) -> String {
    raw.replace('\\', "/").trim_start_matches("./").to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("crates").join("x").join("src")).unwrap();
        std::fs::write(dir.path().join("notes.md"), b"notes").unwrap();
        std::fs::write(dir.path().join("crates/x/src/lib.rs"), b"lib").unwrap();
        dir
    }

    /// Review R-30: every spelling of one request lands on one path, inside.
    #[test]
    fn a_request_lands_where_the_broker_resolved_it_however_it_is_spelled() {
        let ws = Path::new("/ws");
        let source = SourceName::new_unchecked("fixture");
        let want = admitted_path(ws, &source, "docs/bid.md");
        for spelling in ["docs\\bid.md", "docs//bid.md", "/docs/bid.md", "docs/./bid.md"] {
            assert_eq!(admitted_path(ws, &source, spelling), want, "{spelling}");
        }
        assert!(admitted_path(ws, &source, "//etc/passwd").starts_with("/ws/admitted/fixture"));
    }

    /// Review R-13: what a killed fetch left is removed, and nothing else.
    #[test]
    fn a_sweep_removes_partial_fetches_only() {
        let ws = workspace();
        let copy = admitted_path(ws.path(), &SourceName::new_unchecked("fixture"), "docs/bid.md");
        std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
        std::fs::write(&copy, b"whole").unwrap();
        std::fs::write(partial_path(&copy), b"half").unwrap();
        assert_eq!(partial_path(&copy).file_name().unwrap(), ".bid.md.sluse-partial");
        assert_eq!(sweep_partial(ws.path()), 1);
        assert!(copy.is_file() && !partial_path(&copy).exists());
    }

    #[test]
    fn content_is_written_where_it_names_and_not_through_a_link() {
        let ws = workspace();
        write(ws.path(), "out/report.md", b"report").unwrap();
        assert_eq!(std::fs::read(resolve(ws.path(), "out/report.md").unwrap()).unwrap(), b"report");
        assert!(matches!(write(ws.path(), "../escape.md", b"x"), Err(SluseError::MalformedPath { .. })));
        assert!(matches!(write(ws.path(), "/tmp/escape.md", b"x"), Err(SluseError::MalformedPath { .. })));
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink(outside.path(), ws.path().join("away")).unwrap();
            assert!(matches!(write(ws.path(), "away/x.md", b"x"), Err(SluseError::MalformedPath { .. })));
            assert!(!outside.path().join("x.md").exists());
        }
    }

    #[test]
    fn a_relative_path_inside_the_workspace_resolves() {
        let ws = workspace();
        assert!(resolve(ws.path(), "notes.md").is_ok());
        assert!(resolve(ws.path(), "crates/x/src/lib.rs").is_ok());
        // Both separators, because an agent on Windows will write either.
        assert!(resolve(ws.path(), r"crates\x\src\lib.rs").is_ok());
    }

    #[test]
    fn the_grammar_refuses_before_the_filesystem_is_touched() {
        let ws = workspace();
        for raw in [
            "",
            "   ",
            "/etc/passwd",
            r"\windows\system32\config",
            "C:/Windows/notepad.exe",
            "../outside.md",
            "crates/../../outside.md",
            "notes\u{7}.md",
        ] {
            let err = resolve(ws.path(), raw).unwrap_err();
            assert_eq!(err.reason_code(), "MALFORMED_PATH", "{raw:?}");
        }
    }

    #[test]
    fn a_file_that_is_not_there_is_not_found_not_malformed() {
        let ws = workspace();
        let err = resolve(ws.path(), "nothing.md").unwrap_err();
        // The difference matters to the agent: one is a path it should fix, the
        // other is a file it should create.
        assert_eq!(err.reason_code(), "NOT_FOUND");
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_out_of_the_workspace_is_refused() {
        use std::os::windows::process::CommandExt;

        let ws = workspace();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret.md"), b"secret").unwrap();

        let link = ws.path().join("escape");
        let status = std::process::Command::new("cmd")
            .raw_arg(format!(r#"/c mklink /J "{}" "{}""#, link.display(), outside.path().display()))
            .status()
            .expect("mklink");
        if !status.success() {
            eprintln!("skipped: could not create a junction");
            return;
        }

        // The grammar has nothing to object to; canonicalisation does.
        let err = resolve(ws.path(), "escape/secret.md").unwrap_err();
        assert_eq!(err.reason_code(), "MALFORMED_PATH");
    }

    #[test]
    fn a_fetched_file_keeps_the_shape_it_had_in_the_source() {
        let source = SourceName::parse("tender").unwrap();
        let p = admitted_path(Path::new("C:\\ws"), &source, "docs/bid.md");
        assert!(p.ends_with(Path::new("admitted/tender/docs/bid.md")), "{}", p.display());
    }

    /// **D-019 point 3.** The three answers a local read can give about
    /// provenance, and the cap that applies whatever it says.
    #[test]
    fn a_local_read_reports_what_the_sidecar_says_and_obeys_the_cap() {
        let ws = workspace();
        let file = ws.path().join("admitted").join("fixture").join("note.txt");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, b"a note in scope").unwrap();
        let raw = "admitted/fixture/note.txt";

        // No sidecar: readable, hashed, and honest about knowing nothing.
        let local = read_local(ws.path(), raw, 1024).unwrap();
        assert_eq!(local.bytes, b"a note in scope");
        assert_eq!(local.hash, ContentHash::of(b"a note in scope"));
        assert!(local.provenance.is_none());

        // With a sidecar whose hash matches, the copy is still the admitted
        // bytes; after an edit, the same sidecar proves it is not.
        let m = Manifest {
            admitted_from: "fixture/in-scope/docs/note.txt".to_owned(),
            source: SourceName::parse("fixture").unwrap(),
            resolved: r"C:\fixture\in-scope\docs\note.txt".to_owned(),
            admission_id: sluse_proto::AdmissionId::mint(),
            hash: ContentHash::of(b"a note in scope"),
            bytes: 15,
            session_id: sluse_proto::SessionId::mint(),
            config_version: ContentHash::of(b"config"),
            admitted_at: chrono::Utc::now(),
            sensitivity: 2,
            sensitivity_name: "Internal".to_owned(),
        };
        manifest::write(&file, &m).unwrap();
        let local = read_local(ws.path(), raw, 1024).unwrap();
        assert_eq!(local.provenance.as_ref().map(|p| p.hash.clone()), Some(local.hash.clone()));

        std::fs::write(&file, b"a note in scope, edited").unwrap();
        let local = read_local(ws.path(), raw, 1024).unwrap();
        assert_ne!(local.provenance.unwrap().hash, local.hash, "an edit must be visible");

        // The cap is the read cap, and it is judged before the bytes are loaded.
        match read_local(ws.path(), raw, 4) {
            Err(SluseError::TooLarge { size: 23, limit: 4, .. }) => {}
            other => panic!("expected TooLarge, got {other:?}"),
        }

        // A directory is not a read, and nothing outside the workspace is one.
        assert_eq!(
            read_local(ws.path(), "crates", 1024).unwrap_err().reason_code(),
            "NOT_A_FILE"
        );
        assert_eq!(
            read_local(ws.path(), "../outside.md", 1024).unwrap_err().reason_code(),
            "MALFORMED_PATH"
        );
    }

    #[test]
    fn a_default_artifact_name_is_the_path_the_agent_built() {
        assert_eq!(default_artifact_name(r"crates\x\src\lib.rs"), "crates/x/src/lib.rs");
        assert_eq!(default_artifact_name("./summary.md"), "summary.md");
    }
}

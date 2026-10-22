// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Serving the console's own files.
//!
//! **From disk, not embedded.** `include_dir` would bake `ui/console` into the
//! binary at compile time, which means the Rust build fails until the
//! TypeScript has been built — a build-order coupling that buys nothing while
//! the console is a prototype being changed every few minutes. Packaging is
//! M7's problem and the crate already carries `include_dir` for it.
//!
//! **No `tower-http`.** A static handler that has to serve six files is forty
//! lines; a dependency for it is a dependency in the guest's binary, and the
//! guest's dependency list is something a customer's security function reads.
//!
//! The traversal guard is canonicalise-and-contain, the same shape as
//! [`crate::workspace::resolve`] and for the same reason: a symlink under the
//! UI directory makes a path that passed a string check land somewhere else.
//! Nothing secret is under here, so this is hygiene rather than a boundary —
//! but a console that could be talked into serving `/etc/shadow` over loopback
//! would be an embarrassing way to learn the difference.

use std::path::{Path, PathBuf};

use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};

/// Where the console's files live when nothing says otherwise.
///
/// Relative to the working directory, which for the prototype is the repository
/// root. `--ui` overrides it.
pub const DEFAULT_UI_DIR: &str = "ui/console";

/// Serve one file from the UI directory, or 404.
///
/// `path` is the request path with its leading slash removed; empty means the
/// index.
pub fn serve_file(root: &Path, path: &str) -> Response {
    let rel = if path.is_empty() { "index.html" } else { path };

    let Some(file) = resolve(root, rel) else {
        return (StatusCode::NOT_FOUND, "no such file").into_response();
    };
    let Ok(bytes) = std::fs::read(&file) else {
        return (StatusCode::NOT_FOUND, "no such file").into_response();
    };

    ([(header::CONTENT_TYPE, content_type(&file))], bytes).into_response()
}

/// The file a request names, if it is really inside the UI directory.
fn resolve(root: &Path, rel: &str) -> Option<PathBuf> {
    // Refused before the filesystem is touched, so a malformed request cannot
    // become a filesystem question at all.
    if rel.starts_with('/') || rel.contains("..") || rel.contains('\\') {
        return None;
    }
    let root = std::fs::canonicalize(root).ok()?;
    let candidate = std::fs::canonicalize(root.join(rel)).ok()?;
    // Containment after canonicalisation: a symlink is only visible from here.
    candidate.starts_with(&root).then_some(candidate)
}

/// The type to serve a file as.
///
/// An allowlist, and anything else is `application/octet-stream`. A console
/// that guessed `text/html` for an unknown extension would serve whatever
/// landed in its directory as a page.
fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        // The browser loads these as ES modules. It refuses to, on the wrong
        // type, and the error it gives says nothing about the type.
        Some("js") | Some("mjs") => "text/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ui() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), b"<title>console</title>").unwrap();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        std::fs::write(dir.path().join("dist/main.js"), b"export {}").unwrap();
        dir
    }

    #[test]
    fn the_index_is_the_empty_path_and_files_resolve_under_the_root() {
        let ui = ui();
        assert!(resolve(ui.path(), "index.html").is_some());
        assert!(resolve(ui.path(), "dist/main.js").is_some());
        assert!(resolve(ui.path(), "nothing.css").is_none());
    }

    #[test]
    fn nothing_escapes_the_ui_directory() {
        let ui = ui();
        // Outside, and it exists — so a resolve that only checked existence
        // would hand it over.
        let outside = ui.path().parent().unwrap().join("secret.txt");
        std::fs::write(&outside, b"not for the console").unwrap();

        for bad in ["../secret.txt", "dist/../../secret.txt", "/etc/hostname"] {
            assert!(resolve(ui.path(), bad).is_none(), "{bad} must not resolve");
        }

        // A symlink passes every string check and is exactly what
        // canonicalisation is here for.
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, ui.path().join("link.txt")).unwrap();
            assert!(resolve(ui.path(), "link.txt").is_none(), "a symlink out is still out");
        }

        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn a_module_is_served_as_javascript() {
        // The browser refuses to execute an ES module served as anything else,
        // and says so in a message that does not mention the content type.
        assert_eq!(content_type(Path::new("a/main.js")), "text/javascript; charset=utf-8");
        assert_eq!(content_type(Path::new("a/style.css")), "text/css; charset=utf-8");
        assert_eq!(content_type(Path::new("a/thing.exe")), "application/octet-stream");
    }
}

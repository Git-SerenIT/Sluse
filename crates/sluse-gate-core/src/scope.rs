// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from Chaperone crates/chapr-endpoint/src/canon.rs and pathgrammar.rs
// (separator-boundary containment, verbatim-prefix handling) and from
// spikes/s2-no-local-sources/endpoint/src/scope.rs (the request-form grammar
// and the blinders). D-003 allows reuse, not vendoring.

//! Path grammar and scope resolution — **the enforcing copy**.
//!
//! A request is `<source>/<relative path>` with forward slashes and nothing
//! else: no drive letters, no UNC, no `.` or `..`, no absolute anything. The
//! guest cannot name a host path, because the grammar has no way to write one
//! (invariant 2).
//!
//! Resolution ends in exactly one of two places: an absolute path inside an
//! in-scope subtree of a configured source, or a [`SluseError`]. The S-2 spike
//! ran this check inside the endpoint, where it measured the right things and
//! proved nothing; here it is outside the guest, which is the only place it
//! means anything.
//!
//! ## Three refusals the agent cannot tell apart
//!
//! [`SluseError::UnknownSource`], [`SluseError::NotFound`] and
//! [`SluseError::OutOfScope`] are distinct here and collapse to one "no such
//! path" at the endpoint (D-008). The distinction exists for the audit record: a
//! person reading it needs to know whether an agent asked for something that
//! does not exist or something it may not have, and those are not the same
//! event. Keeping the difference on this side and dropping it on that side is
//! the whole of the blinders design.
//!
//! ## Why comparison happens on a folded key
//!
//! Containment cannot be `starts_with` on raw strings. Four things break it, and
//! all four are reachable from a config a customer would write:
//!
//! 1. **Case.** NTFS is case-insensitive; `C:\Tender` and `c:\tender` are one
//!    directory and two strings.
//! 2. **The verbatim prefix.** `std::fs::canonicalize` returns `\\?\C:\x` for a
//!    local path and `\\?\UNC\srv\share\x` for a UNC one. A root canonicalised
//!    the same way compares fine; a root taken from the config verbatim does
//!    not, and the S-2 copy compared exactly those two forms.
//! 3. **Separators**, `/` against `\`.
//! 4. **A prefix that is not a boundary.** `\\srv\share2` starts with
//!    `\\srv\share` and is a different share. Chaperone found this one in
//!    production; the check is a prefix *plus a separator*.
//!
//! So every path that takes part in a comparison — roots, scopes, and whatever
//! a request resolved to — goes through `fold` first, and the comparison is
//! between two folded keys. Unicode normalisation is deliberately **not** done:
//! both sides of every comparison come out of `canonicalize`, which returns the
//! form on disk, so an `æøå` file compares against itself byte for byte. The one
//! place it would matter is a scope typed into the config in a different normal
//! form than the directory was created with, and that fails loudly at compile
//! time rather than quietly at request time.
//!
//! ## Canonicalisation is also the existence check
//!
//! `canonicalize` resolves junctions, symlinks and short (8.3) names, and fails
//! if the path does not exist. That is deliberate: a junction inside a source
//! pointing at `C:\Users` resolves to `C:\Users`, fails containment, and is
//! refused — a check on the unresolved path would have admitted it. Chaperone
//! has no junction handling at all; this is the one place the S-2 copy was
//! already ahead of it, and it is kept.

use std::io;
use std::path::{Path, PathBuf};

use sluse_proto::{Loaded, SluseError, SourceConfig, SourceKind, SourceName};

// ---------------------------------------------------------------------------
// Folded keys
// ---------------------------------------------------------------------------

/// A path that exists, in the three forms Gate Core needs it in.
///
/// Keeping all three together is what stops the wrong one being used: `real` for
/// I/O because it carries the verbatim prefix and therefore the long-path
/// behaviour, `display` for the audit record and the `x-sluse-resolved` header
/// because the prefix teaches a reader nothing, and `key` for every comparison
/// and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Canonical {
    real: PathBuf,
    display: String,
    key: String,
}

impl Canonical {
    /// Canonicalise an existing path.
    pub fn of(path: &Path) -> io::Result<Self> {
        let real = std::fs::canonicalize(path)?;
        let display = strip_verbatim(&real.to_string_lossy());
        let key = fold(&display);
        Ok(Self { real, display, key })
    }

    /// The path to hand to the filesystem.
    pub fn real(&self) -> &Path {
        &self.real
    }

    /// The path to show a person, and to write to an audit record.
    pub fn display(&self) -> &str {
        &self.display
    }

    /// The comparison key. Never shown to anyone: it is lowercased on Windows
    /// and would be read as the file's actual name.
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Is this path inside `other`, or `other` itself?
    ///
    /// The separator is required, so `\\srv\share2` is not inside
    /// `\\srv\share`.
    pub fn within(&self, other: &Canonical) -> bool {
        key_within(&self.key, &other.key)
    }

    /// Is this path an ancestor of `other` — on the way to it?
    ///
    /// The half of a listing D-008 is built on: a directory that leads to
    /// something in scope is shown, so the agent can walk to what it may have,
    /// without being told what else the directory holds.
    pub fn leads_to(&self, other: &Canonical) -> bool {
        key_within(&other.key, &self.key)
    }
}

/// Prefix-plus-separator containment on two already-folded keys.
fn key_within(inner: &str, outer: &str) -> bool {
    inner == outer
        || (inner.len() > outer.len()
            && inner.starts_with(outer)
            && inner.as_bytes()[outer.len()] == b'\\')
}

/// Drop `std::fs::canonicalize`'s verbatim prefix.
///
/// `\\?\C:\x` becomes `C:\x`; `\\?\UNC\srv\share\x` becomes `\\srv\share\x`.
/// The prefix is what makes the path long-path-safe for I/O and is meaningless
/// to a reader, so it survives in `real` and nowhere else.
fn strip_verbatim(s: &str) -> String {
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_owned()
    } else {
        s.to_owned()
    }
}

/// The comparison form: `\` separators, no trailing separator, lowercased where
/// the filesystem is case-insensitive.
///
/// Case folding is `cfg!(windows)` rather than unconditional because a folded
/// key is also what refuses a request, and silently treating two distinct files
/// on a case-sensitive filesystem as one is the kind of helpfulness that ends up
/// in a threat model.
fn fold(s: &str) -> String {
    let unified: String = s.chars().map(|c| if c == '/' { '\\' } else { c }).collect();
    let unified = if cfg!(windows) { unified.to_lowercase() } else { unified };
    let trimmed = unified.trim_end_matches('\\');
    // A drive root folds `C:\` to `c:`, which is still a usable key. An empty
    // string is not: every path would be "inside" it.
    if trimmed.is_empty() {
        unified
    } else {
        trimmed.to_owned()
    }
}

// ---------------------------------------------------------------------------
// Compiled config
// ---------------------------------------------------------------------------

/// The config with every path resolved once, at start.
///
/// Resolution happens here rather than per request for two reasons: a root that
/// has gone away is a start-time failure a person can be told about, and a scope
/// re-canonicalised on every request is a scope that can change underneath a
/// running core without anything being recorded.
#[derive(Debug, Clone)]
pub struct Compiled {
    pub sources: Vec<CompiledSource>,
}

impl Compiled {
    /// Look a source up by name.
    pub fn source(&self, name: &str) -> Option<&CompiledSource> {
        self.sources.iter().find(|s| s.name.as_str() == name)
    }
}

#[derive(Debug, Clone)]
pub struct CompiledSource {
    pub name: SourceName,
    pub kind: SourceKind,
    pub sensitivity: u8,
    /// `None` for a source that is not on a filesystem: `sharepoint`, served
    /// through Graph (M7) with [`Self::remote`] as its scopes.
    pub root: Option<Canonical>,
    /// Never empty for a source with a root: an empty `scope` in the config
    /// means the whole root, and is compiled into exactly that.
    pub scopes: Vec<CompiledScope>,
    /// A `sharepoint` source's scopes, which have no filesystem to be
    /// canonicalised against. `None` for every other kind. See
    /// [`resolve_remote`].
    pub remote: Option<Vec<RemoteScope>>,
    /// Why a filesystem source could not be resolved at start, if it could
    /// not: its root, or every one of its scopes. Such a source has no root
    /// and no scopes, and every request to it is `SOURCE_UNAVAILABLE`
    /// (review R-22). One that cannot be reached does not stop Gate Core,
    /// and SharePoint and OneDrive with it.
    pub unavailable: Option<String>,
    /// Scope entries that could not be resolved at start, each with why,
    /// while others could: dropped, never widened to the root.
    pub dropped: Vec<String>,
}

/// One scope of a remote source, compared by folded key.
#[derive(Debug, Clone)]
pub struct RemoteScope {
    /// As written, normalised to forward slashes. `""` is the whole library.
    pub rel: String,
    /// Case-folded: SharePoint's paths are case-insensitive on every platform,
    /// so unlike [`fold`] this does not depend on where Gate Core runs.
    pub key: String,
}

#[derive(Debug, Clone)]
pub struct CompiledScope {
    /// Request form, relative to the source root, forward slashes. `""` is the
    /// root itself. This is what the config view shows the guest — never the
    /// host path (invariant 2: the guest learns a host path only as the
    /// `resolved` value of something it already named).
    pub rel: String,
    pub abs: Canonical,
}

impl CompiledSource {
    /// Request form of this source's scopes, for the config view.
    pub fn scope_request_forms(&self) -> Vec<String> {
        match &self.remote {
            Some(remote) => remote.iter().map(|s| request_form(self.name.as_str(), &s.rel)).collect(),
            None => self.scopes.iter().map(|s| request_form(self.name.as_str(), &s.rel)).collect(),
        }
    }

    /// The remote twin of [`visible`](Self::visible): in scope, or on the way.
    pub fn remote_visible(&self, key: &str) -> bool {
        self.remote.iter().flatten().any(|s| remote_within(key, &s.key) || remote_within(&s.key, key))
    }

    /// May a directory entry be shown: is it in scope, or on the way to one?
    ///
    /// Used for listings. The `Agent` audience omits everything this returns
    /// false for; the `User` audience shows it with `inScope: false`.
    pub fn visible(&self, child: &Canonical) -> bool {
        self.scopes.iter().any(|s| child.within(&s.abs) || child.leads_to(&s.abs))
    }

    /// Which scope admits this path, if any. `None` means it is only on the way
    /// to one, which is enough to list and not enough to read.
    pub fn admitting_scope(&self, path: &Canonical) -> Option<&CompiledScope> {
        self.scopes.iter().find(|s| path.within(&s.abs))
    }
}

/// Why a config that loaded still cannot be served.
///
/// Separate from [`sluse_proto::ConfigError`] on purpose: that one is everything
/// decidable from the file's own bytes, this one everything that needs the
/// filesystem. Both are failed required checks — invariant 6 — and the split is so that
/// `sluse check` can tell a person whether to fix the file or the machine.
///
/// **Reachability is not validity** (review R-22). A root or a scope that
/// cannot be resolved does not come back as an error from [`compile`]: the
/// source compiles as unavailable ([`CompiledSource::unavailable`]). The two
/// `*Unavailable` variants are kept for what the record says about one.
#[derive(Debug, thiserror::Error)]
pub enum CompileError {
    #[error("source \"{source_name}\": root \"{root}\" cannot be resolved: {detail}")]
    RootUnavailable { source_name: String, root: String, detail: String },

    #[error("source \"{source_name}\": scope \"{scope}\" cannot be resolved: {detail}")]
    ScopeUnavailable { source_name: String, scope: String, detail: String },

    #[error(
        "source \"{source_name}\": scope \"{scope}\" resolves to \"{resolved}\", \
         which is outside the root \"{root}\""
    )]
    ScopeOutsideRoot { source_name: String, scope: String, resolved: String, root: String },

    #[error("source \"{source_name}\": scope \"{scope}\" is not a relative path in request form")]
    ScopeNotRelative { source_name: String, scope: String },

    #[error(
        "`{field}` resolves to \"{resolved}\", which is inside source \"{source_name}\" \
         (root \"{root}\"); it must be outside every source"
    )]
    WritePathInsideSource {
        field: &'static str,
        resolved: String,
        source_name: String,
        root: String,
    },
}

/// Resolve every root and scope in a loaded config, once.
///
/// Then the check that is not about sources at all: **the directories the box
/// writes to must lie outside every source root.** If `artifacts` sat inside a
/// scope, an agent could publish a file and read it back as an admitted source
/// file, and the provenance record would say it came from the source. The same
/// goes for `workspace` and `journalDir`, where a fetch or a journal entry would
/// become readable as source material.
///
/// This is here rather than in the loader because it needs the filesystem: a
/// junction or a substituted drive makes `C:\Sluse-test\artifacts` and
/// `C:\Sluse-test\fixture\in-scope\out` the same directory without the two
/// strings resembling each other, and only canonicalisation says so.
pub fn compile(loaded: &Loaded) -> Result<Compiled, CompileError> {
    compile_with(loaded, crate::as_user::inputs_dir().as_deref())
}

/// [`compile`], with the user's Sluse Inputs given rather than found.
pub fn compile_with(loaded: &Loaded, inputs: Option<&Path>) -> Result<Compiled, CompileError> {
    let mut sources = Vec::with_capacity(loaded.config.sources.len());
    for src in &loaded.config.sources {
        sources.push(compile_source(src, inputs)?);
    }
    let compiled = Compiled { sources };

    for (field, value) in [
        ("artifacts", &loaded.config.artifacts),
        ("workspace", &loaded.config.workspace),
        ("journalDir", &loaded.config.journal_dir),
    ] {
        check_outside_every_source(&compiled, field, &loaded.resolve(value))?;
    }

    Ok(compiled)
}

/// A write path that does not exist yet is fine — it is created at start — so
/// the nearest existing ancestor is what gets compared. A directory that will be
/// created inside a source root is still inside it.
fn check_outside_every_source(
    compiled: &Compiled,
    field: &'static str,
    path: &Path,
) -> Result<(), CompileError> {
    let mut probe = path.to_path_buf();
    let canon = loop {
        match Canonical::of(&probe) {
            Ok(c) => break c,
            Err(_) => match probe.parent() {
                Some(parent) => probe = parent.to_path_buf(),
                // Nothing on the way up exists. Nothing to be inside, then.
                None => return Ok(()),
            },
        }
    };

    for source in &compiled.sources {
        let Some(root) = source.root.as_ref() else { continue };
        if canon.within(root) {
            return Err(CompileError::WritePathInsideSource {
                field,
                resolved: canon.display().to_owned(),
                source_name: source.name.as_str().to_owned(),
                root: root.display().to_owned(),
            });
        }
    }
    Ok(())
}

fn compile_source(src: &SourceConfig, inputs: Option<&Path>) -> Result<CompiledSource, CompileError> {
    let name = src.name.clone();
    let root_path = match &src.kind {
        SourceKind::LocalFolder { root } => Some(PathBuf::from(root)),
        SourceKind::Smb { unc } => Some(PathBuf::from(unc)),
        // Created here, as the user, whose token the start holds over the
        // compile: as the preflight creates Sluse Artifacts (D-031, D-054).
        SourceKind::Inputs => {
            let unavailable = |detail: String| CompileError::RootUnavailable {
                source_name: name.as_str().to_owned(),
                root: crate::as_user::INPUTS.to_owned(),
                detail,
            };
            let made = inputs
                .ok_or_else(|| unavailable("no user profile to find it in".to_owned()))
                .and_then(|dir| {
                    std::fs::create_dir_all(dir).map_err(|e| unavailable(format!("{}: {e}", dir.display())))?;
                    Ok(dir.to_path_buf())
                });
            match made {
                Ok(dir) => Some(dir),
                Err(e) => return Ok(unreachable(src, e.to_string())),
            }
        }
        // No root to canonicalise: the library is reachable only as a signed-in
        // user, and there is none at start. Its scopes are compiled lexically
        // and the source itself answers for existence at request time.
        SourceKind::Sharepoint { .. } | SourceKind::Onedrive => None,
    };

    let Some(root_path) = root_path else {
        let mut remote = Vec::new();
        if src.scope.is_empty() {
            remote.push(RemoteScope { rel: String::new(), key: String::new() });
        }
        for scope in &src.scope {
            let rel = scope_rel(&name, scope)?;
            remote.push(RemoteScope { key: rel.to_lowercase(), rel });
        }
        return Ok(CompiledSource {
            name,
            kind: src.kind.clone(),
            sensitivity: src.sensitivity,
            root: None,
            scopes: Vec::new(),
            remote: Some(remote),
            unavailable: None,
            dropped: Vec::new(),
        });
    };

    let root = match Canonical::of(&root_path) {
        Ok(r) => r,
        Err(e) => {
            let e = CompileError::RootUnavailable {
                source_name: name.as_str().to_owned(),
                root: root_path.to_string_lossy().into_owned(),
                detail: e.to_string(),
            };
            return Ok(unreachable(src, e.to_string()));
        }
    };

    let mut scopes = Vec::new();
    let mut dropped = Vec::new();
    if src.scope.is_empty() {
        scopes.push(CompiledScope { rel: String::new(), abs: root.clone() });
    } else {
        for scope in &src.scope {
            match compile_scope(&name, &root, scope, matches!(src.kind, SourceKind::Smb { .. })) {
                Ok(s) => scopes.push(s),
                // Not there, or not this user's: that entry goes. Every other
                // refusal is the config meaning something it does not say.
                Err(e @ CompileError::ScopeUnavailable { .. }) => dropped.push(e.to_string()),
                Err(e) => return Err(e),
            }
        }
        // Every entry gone is not "the whole root": an empty list would
        // compile to that, and would widen what the admin drew.
        if scopes.is_empty() {
            return Ok(unreachable(src, dropped.join("; ")));
        }
    }

    Ok(CompiledSource {
        name,
        kind: src.kind.clone(),
        sensitivity: src.sensitivity,
        root: Some(root),
        scopes,
        remote: None,
        unavailable: None,
        dropped,
    })
}

/// The first link (symlink, junction, mount point) below `root` on the way
/// down `parts`, if any.
///
/// **For `smb` sources only** (review R-25). Containment rests on
/// canonicalisation, and on a share a junction is traversed by the server:
/// the client may be handed back a path still under the share while the
/// bytes come from wherever the junction points. So on a share a link is
/// refused, not followed. `is_symlink` is true on Windows for name-surrogate
/// reparse points (symlinks, junctions), not for DFS links, which keep
/// working. A local source keeps canonicalisation, which a local junction
/// cannot hide from.
fn link_below(root: &Path, parts: &[impl AsRef<str>]) -> Option<PathBuf> {
    let mut p = root.to_path_buf();
    for part in parts {
        p.push(part.as_ref());
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.file_type().is_symlink()) {
            return Some(p);
        }
    }
    None
}

/// A filesystem source that could not be resolved at start: no root, no
/// scopes, and why. Every request to it is refused as unavailable.
fn unreachable(src: &SourceConfig, why: String) -> CompiledSource {
    CompiledSource {
        name: src.name.clone(),
        kind: src.kind.clone(),
        sensitivity: src.sensitivity,
        root: None,
        scopes: Vec::new(),
        remote: None,
        unavailable: Some(why),
        dropped: Vec::new(),
    }
}

/// A scope entry in request form, or the refusal. Shared by both kinds of
/// source so the grammar cannot drift between them.
fn scope_rel(name: &SourceName, scope: &str) -> Result<String, CompileError> {
    let rel = scope.trim().replace('\\', "/");
    let rel = rel.trim_matches('/').to_owned();
    let bad = rel.is_empty()
        || rel.split('/').any(|p| p.is_empty() || p == "." || p == ".." || p.contains(':'));
    if bad {
        return Err(CompileError::ScopeNotRelative {
            source_name: name.as_str().to_owned(),
            scope: scope.to_owned(),
        });
    }
    Ok(rel)
}

fn compile_scope(
    name: &SourceName,
    root: &Canonical,
    scope: &str,
    smb: bool,
) -> Result<CompiledScope, CompileError> {
    let rel = scope_rel(name, scope)?;
    if smb {
        if let Some(link) = link_below(root.real(), &rel.split('/').collect::<Vec<_>>()) {
            return Err(CompileError::ScopeUnavailable {
                source_name: name.as_str().to_owned(),
                scope: scope.to_owned(),
                detail: format!("{} is a link on the share; links are not followed", link.display()),
            });
        }
    }

    let mut abs_path = root.real().to_path_buf();
    for part in rel.split('/') {
        abs_path.push(part);
    }
    let abs = Canonical::of(&abs_path).map_err(|e| CompileError::ScopeUnavailable {
        source_name: name.as_str().to_owned(),
        scope: scope.to_owned(),
        detail: e.to_string(),
    })?;

    // Belt and braces: the grammar above already excludes `..`, but a junction
    // inside the root can still land the scope outside it, and a scope that
    // escapes its own root is a config that means something other than it says.
    if !abs.within(root) {
        return Err(CompileError::ScopeOutsideRoot {
            source_name: name.as_str().to_owned(),
            scope: scope.to_owned(),
            resolved: abs.display().to_owned(),
            root: root.display().to_owned(),
        });
    }

    Ok(CompiledScope { rel, abs })
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// A request that resolved.
#[derive(Debug, Clone)]
pub struct Scoped {
    /// Index into [`Compiled::sources`].
    pub source: usize,
    /// Relative to the source root, forward slashes, no trailing slash. Empty
    /// for the root itself.
    pub rel: String,
    pub path: Canonical,
    /// True when the path is inside a scope. False when it is only an ancestor
    /// of one, which may be listed and not read.
    pub in_scope: bool,
    /// Request form of the scope that admits it, for the audit record's `scope`
    /// field. `None` when `in_scope` is false.
    pub scope: Option<String>,
}

impl Scoped {
    /// The request in normalised form, for the record.
    pub fn request_form(&self, compiled: &Compiled) -> String {
        request_form(compiled.sources[self.source].name.as_str(), &self.rel)
    }
}

/// Resolve a request-form path against the compiled config.
///
/// Refuses before touching the filesystem for anything the grammar can decide,
/// which keeps a malformed path from becoming a directory probe.
pub fn resolve(compiled: &Compiled, request: &str) -> Result<Scoped, SluseError> {
    resolve_inner(compiled, request, true)
}

/// Resolve anywhere inside the source root, in scope or not.
///
/// [`Audience::User`](sluse_proto::Audience) wants this and nothing else does: a
/// person at the console may see the shape of their own source, greyed where it
/// is out of scope — they are who the scope was drawn for (D-008). **Containment
/// in the root is still enforced.** A junction that leaves the root is not part
/// of this source at any audience, and that refusal is the one worth recording.
///
/// This never admits anything. `read`, `fetch` and `stat` go through
/// [`resolve_in_scope`], which is stricter than both.
pub fn resolve_in_source(compiled: &Compiled, request: &str) -> Result<Scoped, SluseError> {
    resolve_inner(compiled, request, false)
}

/// `require_scope_lineage`: refuse a path that is neither in a scope nor on the
/// way to one. False only for the console's listing.
fn resolve_inner(
    compiled: &Compiled,
    request: &str,
    require_scope_lineage: bool,
) -> Result<Scoped, SluseError> {
    let (source_name, rel_parts) = parse_request(request)?;

    let Some(index) = compiled.sources.iter().position(|s| s.name.as_str() == source_name) else {
        return Err(SluseError::UnknownSource { raw: request.to_owned() });
    };
    let source = &compiled.sources[index];

    if let Some(why) = &source.unavailable {
        return Err(SluseError::SourceUnavailable {
            source_name: source.name.as_str().to_owned(),
            detail: format!("not reachable when Sluse started: {why}"),
        });
    }
    let Some(root) = source.root.as_ref() else {
        return Err(SluseError::UnsupportedSourceKind {
            source_name: source.name.as_str().to_owned(),
            kind: source.kind.type_name().to_owned(),
        });
    };

    let mut candidate = root.real().to_path_buf();
    for part in &rel_parts {
        candidate.push(part);
    }
    if matches!(source.kind, SourceKind::Smb { .. }) {
        if let Some(link) = link_below(root.real(), &rel_parts) {
            return Err(SluseError::OutOfScope {
                raw: request.to_owned(),
                resolved: format!("{} (a link on the share, not followed)", link.display()),
                source_name: source.name.as_str().to_owned(),
                scopes: source.scope_request_forms(),
            });
        }
    }
    let path = Canonical::of(&candidate).map_err(|e| io_to_error(request, source, &e))?;

    // Containment first, scope second. A junction that leaves the root is not
    // "out of scope", it is not part of this source at all, and the record
    // saying so is the difference between a misconfiguration and an attempt.
    if !path.within(root) {
        return Err(out_of_scope(request, &path, source));
    }

    let admitting = source.admitting_scope(&path);
    let leads = source.scopes.iter().any(|s| path.leads_to(&s.abs));
    if require_scope_lineage && admitting.is_none() && !leads {
        return Err(out_of_scope(request, &path, source));
    }

    Ok(Scoped {
        source: index,
        rel: rel_parts.join("/"),
        path,
        in_scope: admitting.is_some(),
        scope: admitting.map(|s| request_form(source.name.as_str(), &s.rel)),
    })
}

/// Resolve, and refuse anything that is only on the way to a scope.
///
/// `read`, `fetch` and `stat` want this; `list` does not, because walking to a
/// scope is how the agent gets there.
pub fn resolve_in_scope(compiled: &Compiled, request: &str) -> Result<Scoped, SluseError> {
    let scoped = resolve(compiled, request)?;
    if !scoped.in_scope {
        return Err(out_of_scope(request, &scoped.path, &compiled.sources[scoped.source]));
    }
    Ok(scoped)
}

fn out_of_scope(request: &str, path: &Canonical, source: &CompiledSource) -> SluseError {
    SluseError::OutOfScope {
        raw: request.to_owned(),
        resolved: path.display().to_owned(),
        source_name: source.name.as_str().to_owned(),
        // The enforcing list, in request form, for the host's record only: it
        // says what the scope *was* at the moment of the refusal, which is the
        // question a person asks when reading one. It does not travel to the
        // agent — the endpoint maps this whole error to "no such path" (D-008).
        scopes: source.scope_request_forms(),
    }
}

/// Split `<source>/<rel>` and refuse everything the grammar forbids.
fn parse_request(request: &str) -> Result<(String, Vec<String>), SluseError> {
    let malformed = |reason: &str| SluseError::MalformedPath {
        raw: request.to_owned(),
        reason: reason.to_owned(),
    };

    let trimmed = request.trim();
    if trimmed.is_empty() {
        return Err(malformed("path is empty; use <source>/<relative path>"));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(malformed("path contains control characters"));
    }
    let unified = trimmed.replace('\\', "/");
    if unified.starts_with('/') {
        return Err(malformed("paths are relative to a source, not absolute"));
    }
    if looks_like_drive(&unified) {
        return Err(malformed("paths name a source, not a drive"));
    }

    let mut parts = unified.split('/').filter(|p| !p.is_empty());
    let source_name = parts.next().unwrap_or_default().to_owned();
    if source_name.is_empty() {
        return Err(malformed("path names no source"));
    }
    let rel_parts: Vec<String> = parts.map(str::to_owned).collect();
    for p in &rel_parts {
        if p == "." || p == ".." {
            return Err(malformed("path may not contain . or .. segments"));
        }
        if p.contains(':') {
            // Refuses `file.txt:stream` as well as a drive letter mid-path: an
            // NTFS alternate data stream is a second set of bytes behind one
            // name, and admitting one under the other's audit record would put a
            // lie in the record.
            return Err(malformed("path segment may not contain a colon"));
        }
    }
    Ok((source_name, rel_parts))
}

fn looks_like_drive(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() >= 2 && b[0].is_ascii_alphabetic() && b[1] == b':'
}

/// Map a filesystem failure to the error the record should carry.
///
/// The three cases are genuinely different events and are recorded as such: a
/// path that is not there, a path the *user* may not have — which is invariant 8
/// working, not a fault — and a source that is not answering.
///
/// **This function got the third case wrong until D-015, and a scored run paid
/// for it.** Resolution happens here, before any backend, so this is the first
/// thing a dead share meets — and `io::ErrorKind` cannot see the difference:
/// Windows reports a lost network path as `ERROR_BAD_NETPATH` or
/// `ERROR_BAD_NET_NAME`, Rust decodes both to `NotFound`, and D-008 then blinds
/// it to the same "No such path" an absent file gets. The file server's VM
/// powered off during the 2026-09-22 run and the agent was told that 125 files
/// it had just been listing did not exist.
///
/// Two answers, in order. The Win32 codes the `smb` backend has classified since
/// M2 — the lists were always right, this caller simply never consulted them —
/// and then a probe of the source root, which is platform-neutral and catches
/// the cases no code list covers (a cifs mount that has gone away answers
/// `ENOENT`, not a Win32 code).
fn io_to_error(request: &str, source: &CompiledSource, e: &io::Error) -> SluseError {
    let unavailable = |detail: String| SluseError::SourceUnavailable {
        source_name: source.name.as_str().to_owned(),
        detail,
    };

    if let Some(class) = crate::sources::classify(e) {
        return match class {
            crate::sources::Win32::Unavailable(code) => unavailable(format!("{e} (win32 {code})")),
            crate::sources::Win32::Refused(code) => SluseError::AccessDenied {
                raw: request.to_owned(),
                detail: format!("{e} (win32 {code})"),
            },
        };
    }

    match e.kind() {
        io::ErrorKind::NotFound => match &source.root {
            // **The root was canonicalised at start-up**, by `compile`, or the
            // core would not be running (invariant 6). So its absence now is a
            // change in the world rather than a fault in the request, and
            // nothing under it can be called absent: an unreachable root means
            // an unanswerable question, not a negative answer.
            Some(root) if !root.real().try_exists().unwrap_or(false) => {
                unavailable(format!("the source root is no longer reachable: {e}"))
            }
            _ => SluseError::NotFound { raw: request.to_owned() },
        },
        io::ErrorKind::PermissionDenied => {
            SluseError::AccessDenied { raw: request.to_owned(), detail: e.to_string() }
        }
        _ => unavailable(e.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Remote sources (M7)
// ---------------------------------------------------------------------------

/// A request against a remote source that resolved. The remote twin of
/// [`Scoped`], with no host path because there is none.
#[derive(Debug, Clone)]
pub struct RemoteScoped {
    pub source: usize,
    /// Relative to the library root as the agent wrote it, forward slashes.
    pub rel: String,
    pub in_scope: bool,
    pub scope: Option<String>,
}

/// The index of the source a request names, **if it is remote**. The routes
/// branch on this before resolving, so a filesystem source never meets the
/// remote resolver and the other way round.
pub fn remote_source(compiled: &Compiled, request: &str) -> Option<usize> {
    let first = request.trim().replace('\\', "/");
    let name = first.split('/').find(|p| !p.is_empty())?;
    compiled.sources.iter().position(|s| s.name.as_str() == name && s.remote.is_some())
}

/// Resolve a request against a remote source's scopes, **lexically**.
///
/// The same grammar as a filesystem source — no `..`, no `.`, no colon, no
/// absolute anything — and then containment on case-folded segments, because
/// there is nothing to canonicalise: SharePoint has no junctions, and a path
/// in a library means what it says. The source answers for existence when the
/// core asks it, as the user; this answers only "may it be asked for".
///
/// `require_scope_lineage` as for [`resolve`]: false only for the console's
/// listing, which may walk anywhere inside the library.
pub fn resolve_remote(
    compiled: &Compiled,
    request: &str,
    require_scope_lineage: bool,
) -> Result<RemoteScoped, SluseError> {
    let (source_name, rel_parts) = parse_request(request)?;
    let Some(index) = compiled.sources.iter().position(|s| s.name.as_str() == source_name) else {
        return Err(SluseError::UnknownSource { raw: request.to_owned() });
    };
    let source = &compiled.sources[index];
    let Some(remote) = source.remote.as_ref() else {
        return Err(SluseError::Internal {
            message: format!("source \"{source_name}\" is not remote and reached the remote resolver"),
        });
    };

    let rel = rel_parts.join("/");
    let key = rel.to_lowercase();
    let admitting = remote.iter().find(|s| remote_within(&key, &s.key));
    let leads = remote.iter().any(|s| remote_within(&s.key, &key));
    if require_scope_lineage && admitting.is_none() && !leads {
        return Err(remote_out_of_scope(request, source));
    }
    Ok(RemoteScoped {
        source: index,
        rel,
        in_scope: admitting.is_some(),
        scope: admitting.map(|s| request_form(source.name.as_str(), &s.rel)),
    })
}

/// Resolve, and refuse anything only on the way to a scope. For `read`,
/// `fetch` and `stat`.
pub fn resolve_remote_in_scope(compiled: &Compiled, request: &str) -> Result<RemoteScoped, SluseError> {
    let scoped = resolve_remote(compiled, request, true)?;
    if !scoped.in_scope {
        return Err(remote_out_of_scope(request, &compiled.sources[scoped.source]));
    }
    Ok(scoped)
}

pub fn remote_out_of_scope(request: &str, source: &CompiledSource) -> SluseError {
    SluseError::OutOfScope {
        raw: request.to_owned(),
        // No host path exists to report. The library address and the request
        // are what a person reading the record needs to find the item.
        resolved: format!("{}/{}", source.kind.address(), request.split_once('/').map_or("", |(_, r)| r)),
        source_name: source.name.as_str().to_owned(),
        scopes: source.scope_request_forms(),
    }
}

/// Is `key` the same as `scope`, or below it? Both folded, both relative, `/`
/// separated. The remote twin of [`key_within`]: a boundary check, not a
/// prefix check, so `in-scope2` is not inside `in-scope`.
fn remote_within(key: &str, scope: &str) -> bool {
    scope.is_empty()
        || key == scope
        || (key.len() > scope.len() && key.starts_with(scope) && key.as_bytes()[scope.len()] == b'/')
}

/// Request form of a source and a relative path.
pub fn request_form(source: &str, rel: &str) -> String {
    if rel.is_empty() {
        source.to_owned()
    } else {
        format!("{source}/{rel}")
    }
}

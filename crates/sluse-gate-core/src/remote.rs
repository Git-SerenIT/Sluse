// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The three routes that touch a source, for a `sharepoint` source. **M7.**
//!
//! Same shape as their filesystem twins in [`crate::http`] — refuse, record,
//! then answer — with three differences, each of them the design rather than a
//! convenience:
//!
//! 1. **Gate Core acts as the signed-in user**, through
//!    [`Entra::acting_for`], and every record on the box names them as
//!    `entra:<upn>`. The sign-in happened on the host (D-036); a request
//!    carries no token. There is no fallback to Gate Core's own identity for
//!    a remote read: no user, no read ([`SluseError::SignInRequired`]).
//! 2. **The bytes come from Graph's download address**, which Gate Core
//!    fetches itself and streams to the box through the same hashing body as a
//!    file (D-046): the record covers authorisation and delivery, and the box
//!    needs no route to SharePoint.
//! 3. **Scope is lexical** ([`scope::resolve_remote`]), and existence is the
//!    source's to answer, as the user, when asked.
//!
//! `stat` downloads and hashes too when the quick path does not apply, for
//! the inventory; it admits nothing to the guest.

use std::sync::Arc;

use axum::response::Response;
use axum::Json;
use sluse_proto::{
    Audience, AuditRecord, Capability, ContentHash, ContentHasher, ListEntry,
    ListRequest, ListResponse, Op, Pin as StatPin, ReadRequest, ReadVerb, SessionId, SluseError,
    SourceKind, StatRequest, StatResponse,
};

use crate::app::Core;
use crate::entra::graph::{Call, Item};
use crate::entra::Entra;
use crate::http::{ApiError, ApiResult};
use crate::scope::{self, RemoteScoped};

/// The user's Graph token for this request, the drive to ask, and the
/// folder in it the source is: none for a library, `Sluse` for OneDrive.
struct Acting {
    entra: Arc<Entra>,
    token: String,
    drive: String,
    folder: &'static str,
}

async fn act(core: &Core, index: usize, raw: &str) -> Result<Acting, SluseError> {
    let source = core.source(index);
    let Some(entra) = core.entra.clone() else {
        // The loader refuses a Graph source without an `entra` block, so this
        // is a Gate Core assembled without one — a test, or a bug.
        return Err(SluseError::UnsupportedSourceKind {
            source_name: source.name.as_str().to_owned(),
            kind: source.kind.type_name().into(),
        });
    };
    let name = source.name.as_str();
    let token = entra.acting_for(name).await?.access;
    let call = Call { source: name, raw, token: &token };
    let (drive, folder) = match &source.kind {
        SourceKind::Sharepoint { site_url, library } => (entra.drive(&call, site_url, library).await?, ""),
        SourceKind::Onedrive => (entra.my_drive(&call).await?, sluse_proto::config::ONEDRIVE_FOLDER),
        other => return Err(SluseError::Internal { message: format!("{} is not a Graph source", other.type_name()) }),
    };
    Ok(Acting { entra, token, drive, folder })
}

impl Acting {
    fn call<'a>(&'a self, core: &'a Core, index: usize, raw: &'a str) -> Call<'a> {
        Call { source: core.source(index).name.as_str(), raw, token: &self.token }
    }

    /// An item by its path in the source, with its `rel` in the source's
    /// terms: the folder taken off the front, whatever case Graph gives it.
    async fn item(&self, call: &Call<'_>, rel: &str) -> Result<Item, SluseError> {
        let in_drive = match (self.folder, rel) {
            ("", rel) => rel.to_owned(),
            (folder, "") => folder.to_owned(),
            (folder, rel) => format!("{folder}/{rel}"),
        };
        let mut item = self.entra.item(call, &self.drive, &in_drive).await?;
        if !self.folder.is_empty() {
            item.rel = item.rel.map(|r| match r.split_once('/') {
                Some((head, tail)) if head.eq_ignore_ascii_case(self.folder) => tail.to_owned(),
                _ if r.eq_ignore_ascii_case(self.folder) => String::new(),
                _ => r,
            });
        }
        Ok(item)
    }
}

/// Where an item is, for a record and for the journal: the library's address
/// and the path, as SharePoint spells it once Graph has answered.
fn located_at(core: &Core, scoped: &RemoteScoped, item: Option<&Item>) -> String {
    let address = core.source(scoped.source).kind.address();
    let rel = item.and_then(|i| i.rel.as_deref()).unwrap_or(&scoped.rel);
    if rel.is_empty() {
        address
    } else {
        format!("{address}/{rel}")
    }
}

/// A read or fetch must name the file as SharePoint spells it. SharePoint
/// answers any case, so `badabing.docx` reached `Badabing.docx` and left the
/// box two copies under two names (L1, 2026-10-07). Scope is case-folded
/// already, so this keeps no file out of reach; it keeps one name per file.
/// Only a difference of case is refused: one of Unicode form is let through.
fn misspelt(raw: &str, scoped: &RemoteScoped, item: &Item) -> Option<SluseError> {
    let true_rel = item.rel.as_deref()?;
    (true_rel != scoped.rel && true_rel.to_lowercase() == scoped.rel.to_lowercase()).then(|| {
        let source = raw.split_once('/').map_or(raw, |(s, _)| s);
        SluseError::MalformedPath {
            raw: raw.to_owned(),
            reason: format!("the file is spelled {source}/{true_rel}; name it so, as sluse_list shows it"),
        }
    })
}

fn locate(r: AuditRecord, at: String, scoped: &RemoteScoped) -> AuditRecord {
    let r = r.resolved(at);
    match &scoped.scope {
        Some(s) => r.in_scope(s.clone()),
        None => r,
    }
}

// ---------------------------------------------------------------------------

pub(crate) async fn list(
    core: &Arc<Core>,
    session: SessionId,
    req: ListRequest,
) -> ApiResult<Json<ListResponse>> {
    let rec = || core.record(&session, Op::List, &req.path);
    let refuse = |r: AuditRecord, e: SluseError| ApiError(core.refuse(r, e));

    // `User` may walk anywhere in the library, greyed where out of scope;
    // `Agent` only in a scope or on the way to one (D-008).
    let scoped = scope::resolve_remote(&core.compiled, &req.path, req.audience == Audience::Agent)
        .map_err(|e| refuse(rec(), e))?;
    let at = located_at(core, &scoped, None);
    let acting = act(core, scoped.source, &req.path)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    let call = acting.call(core, scoped.source, &req.path);

    let folder = acting
        .item(&call, &scoped.rel)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    if folder.shortcut {
        let err = scope::remote_out_of_scope(&req.path, core.source(scoped.source));
        return Err(refuse(locate(rec(), at, &scoped), err));
    }
    if !folder.is_dir {
        let err = SluseError::NotADirectory { raw: req.path.clone() };
        return Err(refuse(locate(rec(), at, &scoped), err));
    }
    let children = acting
        .entra
        .children(&call, &acting.drive, &folder.id)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    let source = core.source(scoped.source);
    core.answered(&source.name);

    let mut entries = Vec::new();
    for child in children {
        let rel = if scoped.rel.is_empty() { child.name.clone() } else { format!("{}/{}", scoped.rel, child.name) };
        // A shortcut points outside the folder: out of scope wherever it sits
        // (D-054), so greyed for the user and absent for the agent.
        let visible = !child.shortcut && source.remote_visible(&rel.to_lowercase());
        if !visible && req.audience == Audience::Agent {
            // D-008: omitted, not refused. And what SharePoint itself hid from
            // this user never arrived at all (D-013, by the source's hand).
            continue;
        }
        entries.push(ListEntry {
            name: child.name,
            kind: if child.is_dir { sluse_proto::EntryKind::Directory } else { sluse_proto::EntryKind::File },
            size: (!child.is_dir).then_some(child.size),
            modified: Some(child.modified),
            in_scope: visible,
        });
    }
    Ok(Json(ListResponse { path: scope::request_form(source.name.as_str(), &scoped.rel), entries }))
}

// ---------------------------------------------------------------------------

pub(crate) async fn read(
    core: &Arc<Core>,
    session: SessionId,
    req: ReadRequest,
) -> ApiResult<Response> {
    let op = match req.verb {
        ReadVerb::Read => Op::Read,
        ReadVerb::Fetch => Op::Fetch,
    };
    let rec = || core.record(&session, op, &req.path).with_capability(Capability::Bytes);
    let refuse = |r: AuditRecord, e: SluseError| ApiError(core.refuse(r, e));

    let scoped =
        scope::resolve_remote_in_scope(&core.compiled, &req.path).map_err(|e| refuse(rec(), e))?;
    let at = located_at(core, &scoped, None);
    let acting = act(core, scoped.source, &req.path)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    let call = acting.call(core, scoped.source, &req.path);
    let item = acting
        .item(&call, &scoped.rel)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    let source_name = core.source(scoped.source).name.clone();
    core.answered(&source_name);
    let at = located_at(core, &scoped, Some(&item));

    if item.shortcut {
        let err = scope::remote_out_of_scope(&req.path, core.source(scoped.source));
        return Err(refuse(locate(rec(), at, &scoped), err));
    }
    if item.is_dir {
        let err = SluseError::NotAFile { raw: req.path.clone() };
        return Err(refuse(locate(rec(), at, &scoped), err));
    }
    if let Some(err) = misspelt(&req.path, &scoped, &item) {
        return Err(refuse(locate(rec(), at, &scoped), err));
    }
    let cap = match req.verb {
        ReadVerb::Read => Some(core.max_read_bytes()),
        ReadVerb::Fetch => core.max_fetch_bytes(),
    };
    if let Some(limit) = cap {
        if item.size > limit {
            let err = SluseError::TooLarge { raw: req.path.clone(), size: item.size, limit };
            return Err(refuse(locate(rec(), at, &scoped), err));
        }
    }
    let Some(url) = item.download_url.clone().filter(|u| acting.entra.may_download(u)) else {
        let err = SluseError::SourceUnavailable {
            source_name: source_name.as_str().to_owned(),
            detail: "Graph returned no https download URL for the item".into(),
        };
        return Err(refuse(locate(rec(), at, &scoped), err));
    };
    let download = acting
        .entra
        .download(&call, &url)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    // The length that comes, not the one Graph listed: a sensitivity label's
    // encryption grows an Office file at download (L1, 2026-10-01; D-045).
    // ponytail: a body without a length is capped by the listed size only.
    let size = download.content_length().unwrap_or(item.size);
    if let Some(limit) = cap.filter(|l| size > *l) {
        let err = SluseError::TooLarge { raw: req.path.clone(), size, limit };
        return Err(refuse(locate(rec(), at, &scoped), err));
    }
    // Recorded when the bytes stop, with their hash, and counted by the
    // volume window then, as a file's are.
    Ok(crate::http::admitted(
        core,
        locate(rec(), at.clone(), &scoped),
        session,
        source_name,
        crate::http::IoErrors(Box::pin(download.bytes_stream())),
        size,
        &at,
    ))
}

// ---------------------------------------------------------------------------

pub(crate) async fn stat(
    core: &Arc<Core>,
    session: SessionId,
    req: StatRequest,
) -> ApiResult<Json<StatResponse>> {
    let rec = || core.record(&session, Op::Metadata, &req.path);
    let refuse = |r: AuditRecord, e: SluseError| ApiError(core.refuse(r, e));

    let scoped =
        scope::resolve_remote_in_scope(&core.compiled, &req.path).map_err(|e| refuse(rec(), e))?;
    let at = located_at(core, &scoped, None);
    let acting = act(core, scoped.source, &req.path)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    let call = acting.call(core, scoped.source, &req.path);
    let item = acting
        .item(&call, &scoped.rel)
        .await
        .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
    core.answered(&core.source(scoped.source).name);
    let at = located_at(core, &scoped, Some(&item));

    if item.shortcut {
        let err = scope::remote_out_of_scope(&req.path, core.source(scoped.source));
        return Err(refuse(locate(rec(), at, &scoped), err));
    }
    if item.is_dir {
        let err = SluseError::NotAFile { raw: req.path.clone() };
        return Err(refuse(locate(rec(), at, &scoped), err));
    }

    let quick = matches!(
        &req.pinned,
        Some(StatPin { size, modified, .. }) if *size == item.size && *modified == item.modified
    );
    let (hash, matches_pinned) = if quick {
        let pin = req.pinned.as_ref().expect("quick implies a pin");
        (pin.hash.clone(), Some(true))
    } else {
        let hash = hash_download(&acting, &call, &item)
            .await
            .map_err(|e| refuse(locate(rec(), at.clone(), &scoped), e))?;
        let matches = req.pinned.as_ref().map(|p| p.hash == hash);
        (hash, matches)
    };

    core.sink.record(&crate::http::stat_record(locate(rec(), at, &scoped), &hash, item.size, quick));
    Ok(Json(StatResponse { size: item.size, modified: item.modified, hash, matches_pinned }))
}

async fn hash_download(acting: &Acting, call: &Call<'_>, item: &Item) -> Result<ContentHash, SluseError> {
    let unavailable = |detail: String| SluseError::SourceUnavailable {
        source_name: call.source.to_owned(),
        detail,
    };
    let url = item
        .download_url
        .as_deref()
        .ok_or_else(|| unavailable("Graph returned no download URL for the item".into()))?;
    let mut res = acting.entra.download(call, url).await?;
    let expected = res.content_length().unwrap_or(item.size);
    let mut hasher = ContentHasher::new();
    let mut seen: u64 = 0;
    while let Some(chunk) =
        res.chunk().await.map_err(|e| unavailable(format!("the download ended early: {}", crate::entra::cause(&e))))?
    {
        hasher.update(&chunk);
        seen += chunk.len() as u64;
    }
    if seen != expected {
        return Err(unavailable(format!("the download ended after {seen} of {expected} bytes")));
    }
    Ok(hasher.finish())
}

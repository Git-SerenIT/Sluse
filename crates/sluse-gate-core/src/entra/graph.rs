// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The few Graph calls a document library needs.
//!
//! A library is a drive. The drive is found once per source from the site URL
//! and the library name in the config, then every path is addressed relative
//! to its root: `/drives/{id}/root:/{path}`. **SharePoint decides what the user
//! may see**: a listing comes back security-trimmed, so an item the user may
//! not read is absent from its parent — D-013's "quiet for the browser" by the
//! source's own hand — and naming it answers 403 or 404, which is the source's
//! answer and is recorded as such.
//!
//! Status mapping, and it is the part worth reading:
//!
//! | Graph | Recorded as |
//! |---|---|
//! | 404 | `NotFound` |
//! | 403 | `AccessDenied`, with Graph's own error code as the detail |
//! | 401 | `SignInRequired`: Graph refused the token Gate Core holds |
//! | 400 | `MalformedPath`: a name SharePoint cannot hold |
//! | 429, 5xx, transport | `SourceUnavailable`, with `Retry-After` when given |
//!
//! Throttling is recorded, not retried. Retrying inside a request would hide a
//! rate limit from the one record that could show it, and S-4 exists to measure
//! throttling rather than to paper over it.

use chrono::{DateTime, Utc};
use serde::Deserialize;
use sluse_proto::SluseError;

use super::{unavailable, Entra};

/// How many pages of a listing to follow. 200 items a page is Graph's default,
/// so this is ten thousand children.
// ponytail: a hard stop, not a cursor; a folder bigger than this lists its
// first 10,000 and says so. Page through when a pilot has one.
const MAX_PAGES: usize = 50;

/// A drive item, reduced to what Gate Core uses.
#[derive(Debug, Clone)]
pub struct Item {
    pub id: String,
    pub name: String,
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub is_dir: bool,
    /// Pre-authenticated and short-lived. Present on files the user may read.
    pub download_url: Option<String>,
    /// Its path in the library as SharePoint spells it, from the parent's
    /// path and its own name; `None` for the root, or where Graph gave no
    /// parent. The `resolved` value's tail, and the spelling a read or fetch
    /// must use. Not `webUrl`: for an Office file that is the Office viewer's
    /// address, not the file (L1, 2026-10-07).
    pub rel: Option<String>,
    /// A shortcut to an item elsewhere ("Add shortcut to My files"): out of
    /// scope wherever it sits, since it points outside the folder (D-054).
    pub shortcut: bool,
}

#[derive(Deserialize)]
struct RawItem {
    id: String,
    name: String,
    #[serde(default)]
    size: u64,
    #[serde(rename = "lastModifiedDateTime")]
    modified: Option<DateTime<Utc>>,
    folder: Option<serde_json::Value>,
    #[serde(rename = "@microsoft.graph.downloadUrl")]
    download_url: Option<String>,
    #[serde(rename = "parentReference")]
    parent: Option<ParentRef>,
    #[serde(rename = "remoteItem")]
    remote: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ParentRef {
    /// `/drives/{id}/root:/folder/sub`, or `/drive/root:` at the top.
    path: Option<String>,
}

impl From<RawItem> for Item {
    fn from(r: RawItem) -> Self {
        // ponytail: decoded whether Graph encoded it or not; a name with a
        // literal `%41` in it would read as `A`.
        let rel = r.parent.and_then(|p| p.path).and_then(|p| {
            let (_, under) = p.split_once("root:")?;
            let under = decode(under);
            let under = under.trim_matches('/');
            Some(if under.is_empty() { r.name.clone() } else { format!("{under}/{}", r.name) })
        });
        Self {
            id: r.id,
            name: r.name,
            size: r.size,
            modified: r.modified.unwrap_or(DateTime::UNIX_EPOCH),
            is_dir: r.folder.is_some(),
            download_url: r.download_url,
            rel,
            shortcut: r.remote.is_some(),
        }
    }
}

#[derive(Deserialize)]
struct Page<T> {
    value: Vec<T>,
    #[serde(rename = "@odata.nextLink")]
    next: Option<String>,
}

#[derive(Deserialize)]
struct Site {
    id: String,
}

#[derive(Deserialize)]
struct Drive {
    id: String,
    name: String,
    #[serde(rename = "webUrl", default)]
    web_url: String,
}

#[derive(Deserialize, Default)]
struct GraphErrorBody {
    #[serde(default)]
    error: GraphError,
}

#[derive(Deserialize, Default)]
struct GraphError {
    #[serde(default)]
    code: String,
    #[serde(default)]
    message: String,
}

/// Where a call came from, so a failure is recorded against the right source
/// and names the path the agent used.
pub struct Call<'a> {
    pub source: &'a str,
    pub raw: &'a str,
    pub token: &'a str,
}

impl Entra {
    /// The drive id for a library, found once and kept.
    pub async fn drive(
        &self,
        call: &Call<'_>,
        site_url: &str,
        library: &str,
    ) -> Result<String, SluseError> {
        if let Some(id) = self.drives.lock().unwrap_or_else(|p| p.into_inner()).get(call.source) {
            return Ok(id.clone());
        }
        let (host, path) = split_site(site_url)
            .ok_or_else(|| unavailable(call.source, format!("\"{site_url}\" is not a site URL")))?;
        // A bare host is the tenant's root site, which Graph serves at
        // `/sites/{host}` (review R-17: the loader and the picker took one and
        // every request on it failed).
        let by = if path.is_empty() { host.to_owned() } else { format!("{host}:{path}") };
        let site: Site = self.get_json(call, &format!("{}/sites/{by}?$select=id", self.graph)).await?;
        let drives: Page<Drive> = self
            .get_json(call, &format!("{}/sites/{}/drives?$select=id,name,webUrl", self.graph, site.id))
            .await?;
        // The display name is "Documents" where the URL says "Shared Documents",
        // and a person writing the config may have copied either.
        let wanted = library.trim().to_lowercase();
        let found = drives.value.into_iter().find(|d| {
            d.name.to_lowercase() == wanted
                || decode(d.web_url.rsplit('/').next().unwrap_or_default()).to_lowercase() == wanted
        });
        let Some(drive) = found else {
            return Err(unavailable(
                call.source,
                format!("the site has no document library named \"{library}\""),
            ));
        };
        self.drives
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(call.source.to_owned(), drive.id.clone());
        Ok(drive.id)
    }

    /// The signed-in user's own OneDrive (D-054), found once and kept: one
    /// core serves one user.
    pub async fn my_drive(&self, call: &Call<'_>) -> Result<String, SluseError> {
        if let Some(id) = self.drives.lock().unwrap_or_else(|p| p.into_inner()).get(call.source) {
            return Ok(id.clone());
        }
        let drive: Drive = self.get_json(call, &format!("{}/me/drive?$select=id,name,webUrl", self.graph)).await?;
        self.drives
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(call.source.to_owned(), drive.id.clone());
        Ok(drive.id)
    }

    /// One item by its path in the library. `rel` empty is the root.
    pub async fn item(&self, call: &Call<'_>, drive: &str, rel: &str) -> Result<Item, SluseError> {
        let url = if rel.is_empty() {
            format!("{}/drives/{drive}/root", self.graph)
        } else {
            format!("{}/drives/{drive}/root:/{}", self.graph, encode_path(rel))
        };
        self.get_json::<RawItem>(call, &url).await.map(Item::from)
    }

    /// The children of a folder, as SharePoint trims them for this user.
    pub async fn children(
        &self,
        call: &Call<'_>,
        drive: &str,
        item_id: &str,
    ) -> Result<Vec<Item>, SluseError> {
        let mut url = Some(format!("{}/drives/{drive}/items/{item_id}/children", self.graph));
        let mut out = Vec::new();
        for _ in 0..MAX_PAGES {
            let Some(next) = url.take() else { break };
            let page: Page<RawItem> = self.get_json(call, &next).await?;
            out.extend(page.value.into_iter().map(Item::from));
            url = page.next;
        }
        out.sort_by_key(|i| i.name.to_lowercase());
        Ok(out)
    }

    /// Whether a download address may be fetched: https, as Graph is. A
    /// stand-in Graph over plain http (the tests') serves plain downloads.
    pub fn may_download(&self, url: &str) -> bool {
        url.starts_with("https://") || !self.graph.starts_with("https://")
    }

    /// Download an item's bytes from Graph's download address: reads and
    /// fetches, streamed to the box (D-046), and `stat`, which hashes them.
    pub async fn download(&self, call: &Call<'_>, url: &str) -> Result<reqwest::Response, SluseError> {
        let res = self
            .download
            .get(url)
            .send()
            .await
            .map_err(|e| unavailable(call.source, format!("the download could not start: {}", super::cause(&e))))?;
        if res.status().is_success() {
            Ok(res)
        } else {
            Err(status_error(call, res).await)
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        call: &Call<'_>,
        url: &str,
    ) -> Result<T, SluseError> {
        let res = self
            .http
            .get(url)
            .bearer_auth(call.token)
            .send()
            .await
            .map_err(|e| unavailable(call.source, format!("Graph could not be reached: {}", super::cause(&e))))?;
        if !res.status().is_success() {
            return Err(status_error(call, res).await);
        }
        res.json::<T>()
            .await
            .map_err(|e| unavailable(call.source, format!("Graph's answer could not be read: {}", super::cause(&e))))
    }
}

async fn status_error(call: &Call<'_>, res: reqwest::Response) -> SluseError {
    let status = res.status().as_u16();
    let retry = res
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(|v| format!(", retry after {v} s"))
        .unwrap_or_default();
    let body: GraphErrorBody = res.json().await.unwrap_or_default();
    let detail = format!("Graph {status} {}: {}", body.error.code, body.error.message);
    match status {
        404 => SluseError::NotFound { raw: call.raw.to_owned() },
        403 => SluseError::AccessDenied { raw: call.raw.to_owned(), detail },
        401 => SluseError::SignInRequired { detail },
        400 => SluseError::MalformedPath { raw: call.raw.to_owned(), reason: detail },
        _ => unavailable(call.source, format!("{detail}{retry}")),
    }
}

/// `https://tenant.sharepoint.com/sites/name` into `("tenant.sharepoint.com",
/// "/sites/name")`, the two halves Graph's site-by-path lookup wants. The
/// root site, a bare host, has an empty path.
fn split_site(site_url: &str) -> Option<(&str, &str)> {
    let rest = site_url.strip_prefix("https://")?.trim_end_matches('/');
    let host = rest.split('/').next().unwrap_or_default();
    (!host.is_empty()).then(|| (host, &rest[host.len()..]))
}

/// Percent-encode each segment of a path, keeping the slashes between them.
///
/// Everything but the RFC 3986 unreserved set is encoded. A `#` or `%` in a
/// SharePoint file name is legal and would otherwise end the URL or be read as
/// an escape; `?` would start a query. The grammar has already refused `..`,
/// `.` and `:` before a path gets here.
pub fn encode_path(rel: &str) -> String {
    rel.split('/').map(encode_segment).collect::<Vec<_>>().join("/")
}

fn encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Undo `%XX` escapes, for comparing a library's URL segment with its name.
fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && i + 2 < b.len()
            && b[i + 1].is_ascii_hexdigit()
            && b[i + 2].is_ascii_hexdigit()
        {
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("0");
            out.push(u8::from_str_radix(hex, 16).unwrap_or(0));
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_site_url_splits_into_host_and_path() {
        assert_eq!(
            split_site("https://contoso.sharepoint.com/sites/purviewtest/"),
            Some(("contoso.sharepoint.com", "/sites/purviewtest"))
        );
        assert_eq!(split_site("https://contoso.sharepoint.com"), Some(("contoso.sharepoint.com", "")));
        assert_eq!(split_site("https://contoso.sharepoint.com/"), Some(("contoso.sharepoint.com", "")));
        assert_eq!(split_site("https://"), None);
        assert_eq!(split_site("http://x/sites/y"), None);
    }

    /// A `#` left unencoded ends the URL at the fragment, and the request then
    /// asks for a different item than the one the agent named.
    #[test]
    fn segments_are_percent_encoded_and_slashes_survive() {
        assert_eq!(encode_path("in-scope/Q3 #2 100%.docx"), "in-scope/Q3%20%232%20100%25.docx");
        assert_eq!(encode_path("æ/ø"), "%C3%A6/%C3%B8");
    }

    #[test]
    fn a_library_url_segment_decodes() {
        assert_eq!(decode("Shared%20Documents"), "Shared Documents");
        assert_eq!(decode("100%"), "100%");
    }
}

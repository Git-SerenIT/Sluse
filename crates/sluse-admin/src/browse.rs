// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The scope picker's tree (D-038 point 6), browsed **as the admin**: sites,
//! Teams as a way in to their sites, document libraries, folders, and file
//! shares. A count per folder where the source gives one cheaply.
//!
//! The tree shows what the admin can open. A user still reaches only what
//! they can open themselves: every read is as the user (invariant 8), and
//! the config only narrows that. A scope is a path, never an id.

use std::path::Path;

use serde::Serialize;
use serde_json::Value;

use crate::graph::Graph;

/// A SharePoint site, or a Team's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub id: String,
    pub name: String,
    /// What the config's `siteUrl` takes.
    pub url: String,
}

/// A document library: what the config's `library` takes is `name`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Library {
    pub id: String,
    pub name: String,
}

/// A folder, with its path as a scope entry takes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Folder {
    /// Graph's item id, to open it; empty for a share.
    pub id: String,
    pub name: String,
    /// Relative to the library or share, forward slashes.
    pub path: String,
    /// What it holds, folders and files, where the source says so cheaply.
    pub count: Option<u64>,
}

fn site(v: &Value) -> Option<Site> {
    Some(Site {
        id: v["id"].as_str()?.to_owned(),
        name: v["displayName"].as_str().or(v["name"].as_str()).unwrap_or_default().to_owned(),
        url: v["webUrl"].as_str()?.to_owned(),
    })
}

/// An Entra group, for who may sign in and which devices Intune installs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub name: String,
}

/// Groups whose name starts with `query`.
pub async fn groups(g: &Graph, query: &str) -> Result<Vec<Group>, String> {
    let q = query.replace('\'', "''");
    let found = g.list(format!("/groups?$filter=startswith(displayName,'{q}')&$select=id,displayName&$top=50")).await?;
    Ok(found
        .iter()
        .filter_map(|v| Some(Group { id: v["id"].as_str()?.to_owned(), name: v["displayName"].as_str()?.to_owned() }))
        .collect())
}

/// Sites whose name matches `query`.
pub async fn sites(g: &Graph, query: &str) -> Result<Vec<Site>, String> {
    let q: String = query.chars().filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-').collect();
    Ok(g.list(format!("/sites?search={q}&$select=id,displayName,webUrl")).await?.iter().filter_map(site).collect())
}

/// A Team the listing left out, and why in words (Q47).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Skipped {
    pub name: String,
    pub reason: String,
}

/// Every Team as its site, one at a time, counted through `tell(read, of)`.
/// A Team is a way in, not a source kind. One Team whose site cannot be
/// read is left out and named, never the end of the listing (Q47).
pub async fn teams(g: &Graph, account: &str, tell: &(dyn Fn(usize, usize) + Sync)) -> Result<(Vec<Site>, Vec<Skipped>), String> {
    let groups = g
        .list("/groups?$filter=resourceProvisioningOptions/Any(x:x eq 'Team')&$select=id,displayName".into())
        .await?;
    let (mut out, mut skipped) = (Vec::new(), Vec::new());
    for (n, grp) in groups.iter().enumerate() {
        tell(n, groups.len());
        let Some(id) = grp["id"].as_str() else { continue };
        let name = grp["displayName"].as_str().unwrap_or(id).to_owned();
        match g.get(format!("/groups/{id}/sites/root?$select=id,displayName,webUrl")).await {
            Ok(v) => match site(&v) {
                Some(s) => out.push(Site { name, ..s }),
                None => skipped.push(Skipped { name, reason: "it has no SharePoint site.".into() }),
            },
            Err(e) if e.contains(": 403") || e.contains(": 401") => {
                skipped.push(Skipped { name, reason: format!("you cannot open its site as {account}.") })
            }
            Err(e) if e.contains(": 404") => skipped.push(Skipped { name, reason: "it has no SharePoint site.".into() }),
            Err(_) => skipped.push(Skipped { name, reason: "its site did not answer.".into() }),
        }
    }
    tell(groups.len(), groups.len());
    Ok((out, skipped))
}

pub async fn libraries(g: &Graph, site_id: &str) -> Result<Vec<Library>, String> {
    let drives = g.list(format!("/sites/{site_id}/drives?$select=id,name")).await?;
    Ok(drives
        .iter()
        .filter_map(|d| Some(Library { id: d["id"].as_str()?.to_owned(), name: d["name"].as_str()?.to_owned() }))
        .collect())
}

/// The folders in a library's folder: its root when `item` is `None`.
pub async fn folders(g: &Graph, drive: &str, item: Option<&str>) -> Result<Vec<Folder>, String> {
    let path = match item {
        None => format!("/drives/{drive}/root/children"),
        Some(id) => format!("/drives/{drive}/items/{id}/children"),
    };
    let children = g.list(format!("{path}?$select=id,name,folder,parentReference")).await?;
    let mut out: Vec<Folder> = children
        .iter()
        .filter(|c| c.get("folder").is_some_and(|f| !f.is_null()))
        .filter_map(|c| {
            let name = c["name"].as_str()?.to_owned();
            // `/drive/root:` or `/drive/root:/A/B`, which is what a scope is
            // relative to.
            let parent = c["parentReference"]["path"].as_str().unwrap_or("/drive/root:");
            let parent = parent.split_once("root:").map_or("", |(_, p)| p).trim_matches('/');
            let path = if parent.is_empty() { name.clone() } else { format!("{parent}/{name}") };
            Some(Folder { id: c["id"].as_str()?.to_owned(), name, path, count: c["folder"]["childCount"].as_u64() })
        })
        .collect();
    out.sort_by_key(|f| f.name.to_lowercase());
    Ok(out)
}

/// The folders in a share's folder, read as the admin: `root` is the share
/// (`\\server\share`), `rel` the folder under it. Counted, which a share
/// gives for the price of a listing.
pub fn share_folders(root: &Path, rel: &str) -> std::io::Result<Vec<Folder>> {
    let dir = if rel.is_empty() { root.to_path_buf() } else { root.join(rel) };
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let path = if rel.is_empty() { name.clone() } else { format!("{}/{name}", rel.trim_end_matches('/')) };
        let count = std::fs::read_dir(entry.path()).ok().map(|d| d.count() as u64);
        out.push(Folder { id: String::new(), name, path, count });
    }
    out.sort_by_key(|f| f.name.to_lowercase());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn sites_teams_libraries_and_folders_as_paths_with_counts() {
        let (base, t) = crate::stand_in::start().await;
        t.lock().unwrap().groups.push(json!({ "id": "g-t", "displayName": "Tender team", "resourceProvisioningOptions": ["Team"] }));
        t.lock().unwrap().groups.push(json!({ "id": "g-x", "displayName": "Just a group", "resourceProvisioningOptions": [] }));
        t.lock().unwrap().groups.push(json!({ "id": "g-old", "displayName": "Old Projects", "resourceProvisioningOptions": ["Team"], "site": "none" }));
        t.lock().unwrap().groups.push(json!({ "id": "g-hr", "displayName": "HR Private", "resourceProvisioningOptions": ["Team"], "site": "forbidden" }));
        let g = crate::stand_in::graph(&base);

        let found = sites(&g, "tend").await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].url, "https://contoso.sharepoint.com/sites/tender");
        let found = groups(&g, "tend").await.unwrap();
        assert_eq!(found, [Group { id: "g-t".into(), name: "Tender team".into() }]);
        let counted = std::sync::Mutex::new(Vec::new());
        let (teams, skipped) = teams(&g, "admin@contoso.dk", &|n, of| counted.lock().unwrap().push((n, of))).await.unwrap();
        assert_eq!(teams.len(), 1, "only the Team whose site answers");
        assert_eq!(teams[0].name, "Tender team");
        assert_eq!(counted.into_inner().unwrap().last(), Some(&(3, 3)));
        assert_eq!(skipped, [
            Skipped { name: "Old Projects".into(), reason: "it has no SharePoint site.".into() },
            Skipped { name: "HR Private".into(), reason: "you cannot open its site as admin@contoso.dk.".into() },
        ]);

        let libs = libraries(&g, "site-tender").await.unwrap();
        assert_eq!(libs[0].name, "Documents");
        let top = folders(&g, &libs[0].id, None).await.unwrap();
        assert_eq!(top, [Folder { id: "f-in".into(), name: "In-Scope".into(), path: "In-Scope".into(), count: Some(4) }]);
        let deeper = folders(&g, "drive-1", Some("f-in")).await.unwrap();
        assert_eq!(deeper[0].path, "In-Scope/Deeper", "a scope is a path");
    }

    #[test]
    fn a_share_lists_its_folders_with_counts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("Tender/2026")).unwrap();
        std::fs::write(dir.path().join("Tender/note.txt"), "x").unwrap();
        std::fs::write(dir.path().join("loose.txt"), "x").unwrap();
        let top = share_folders(dir.path(), "").unwrap();
        assert_eq!(top, [Folder { id: String::new(), name: "Tender".into(), path: "Tender".into(), count: Some(2) }]);
        assert_eq!(share_folders(dir.path(), "Tender").unwrap()[0].path, "Tender/2026");
    }
}

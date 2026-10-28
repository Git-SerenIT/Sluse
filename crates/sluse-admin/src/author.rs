// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The authored file (D-038 point 2), from what the admin chose.
//!
//! **Warnings, not friction.** The admin decides. What the box's own loader
//! refuses is refused here too, by the same code (invariant 6); everything
//! else is allowed, and each choice that carries a risk is named with what
//! it means ([`Warning`]). The setup UI shows them before it publishes.

use std::path::Path;

use serde::Serialize;
use sluse_proto::{Authored, SourceKind};

use crate::catalog::Catalog;

/// One risk the admin chose to take, in words for them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    /// Stable, for the UI to group by: `whole-source`, `uploads`,
    /// `shared-wildcard`, `own-host`, `bundle-trimmed`, `box-memory`,
    /// `egress-log`, `no-byte-alert`.
    pub code: &'static str,
    pub text: String,
    /// The hosts it is about, where a list would crowd the sentence: an
    /// uploads bundle's, shown behind a disclosure.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hosts: Vec<String>,
}

/// An authored file ready to save or publish: its bytes, which are the
/// version, and what the admin should read first.
#[derive(Debug, Clone)]
pub struct Draft {
    pub text: String,
    pub warnings: Vec<Warning>,
}

/// Hosting that many organisations share: a wildcard over one reaches
/// whatever any of them put there.
/// Where Entra issues tokens. Not in any bundle (D-044): with one, the box
/// can turn a sign-in into a SharePoint token. Its static CDNs are not here;
/// they issue nothing.
const MICROSOFT_SIGN_IN: &[&str] =
    &["login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "device.login.microsoftonline.com"];

const SHARED: [&str; 16] = [
    "sharepoint.com", "onmicrosoft.com", "blob.core.windows.net", "azurewebsites.net", "amazonaws.com",
    "cloudfront.net", "googleapis.com", "googleusercontent.com", "appspot.com", "herokuapp.com",
    "github.io", "githubusercontent.com", "vercel.app", "netlify.app", "workers.dev", "pages.dev",
];

/// Write `a` out and check it with the box's own loader. An error is what
/// the box would refuse; a draft carries its warnings.
pub fn author(a: &Authored, catalog: &Catalog) -> Result<Draft, String> {
    let mut text = serde_json::to_string_pretty(a).map_err(|e| e.to_string())?;
    text.push('\n');
    let back = sluse_proto::config::load_authored(text.as_bytes()).map_err(|e| e.to_string())?;
    Ok(Draft { warnings: warnings(&back, catalog), text })
}

pub fn warnings(a: &Authored, catalog: &Catalog) -> Vec<Warning> {
    let mut w = Vec::new();
    let mut say = |code, text: String| w.push(Warning { code, text, hosts: vec![] });
    let mut sharepoint_hosts = Vec::new();
    for s in &a.sources {
        let what = match &s.kind {
            SourceKind::Sharepoint { site_url, library } => {
                if let Some(h) = site_url.strip_prefix("https://").and_then(|r| r.split('/').next()) {
                    sharepoint_hosts.push(h.to_ascii_lowercase());
                }
                format!("the whole library {library}")
            }
            SourceKind::Smb { unc } => format!("the whole share {unc}"),
            SourceKind::LocalFolder { root } => format!("all of {root}"),
            // The whole folder is the point (D-054); what is in it is not
            // the admin's to scope.
            SourceKind::Inputs => {
                say("user-chosen", format!(
                    "{} admits what each user puts in their own Sluse Inputs folder on the device: the user decides what is in it, and Sluse can say only that it came from that device.",
                    s.name
                ));
                continue;
            }
            SourceKind::Onedrive => {
                say("user-chosen", format!(
                    "{} admits what each user puts in the Sluse folder of their own OneDrive: the user decides what is in it.",
                    s.name
                ));
                continue;
            }
            // The loader refuses one with no tools; what remains is the two
            // limits D-071 states: a tool that writes is the admin's to keep
            // out, and the person's identity reaches only as far as the server.
            SourceKind::Mcp { .. } => {
                say("mcp-server-trust", format!(
                    "{} lets the agent call {} tool(s) on this server as each user. Sluse calls only the tools listed, but cannot tell whether a tool changes anything: list only tools that read. The server decides what each call returns; if it reads its own systems with a service account rather than as the user, the agent sees what that account can.",
                    s.name, s.scope.len()
                ));
                continue;
            }
        };
        if s.scope.is_empty() {
            say("whole-source", format!(
                "{} has no scope, so {what} is in reach of the agent, as far as each user can open it.", s.name
            ));
        }
    }
    let egress = a.egress.clone().unwrap_or_default();
    for b in egress.bundles.iter().filter_map(|id| catalog.bundle(id)).filter(|b| b.uploads) {
        say("uploads", format!(
            "{} can also take what the box sends it. Sluse sees which host a connection is for, not what it carries.",
            b.name
        ));
    }
    for b in egress.bundles.iter().filter_map(|id| catalog.bundle(id)) {
        let gone: Vec<&String> = b.hosts.iter().filter(|h| !egress.allow.contains(h)).collect();
        if !gone.is_empty() {
            let gone: Vec<&str> = gone.iter().map(|h| h.as_str()).collect();
            say("bundle-trimmed", format!("{} is ticked without {}, so it may not work.", b.name, gone.join(", ")));
        }
    }
    let from_catalog = catalog.allow(&egress.bundles, &[]);
    for h in &egress.allow {
        if let Some(suffix) = h.strip_prefix("*.") {
            if SHARED.iter().any(|s| suffix == *s || suffix.ends_with(&format!(".{s}"))) {
                say("shared-wildcard", format!(
                    "{h} is a name many organisations share: the box can reach whatever any of them hosts there."
                ));
            }
        }
        if sharepoint_hosts.contains(h) {
            say("sharepoint-host", format!(
                "{h} is your SharePoint, which the box does not need: Sluse brings its files. On the \
                 list, it is a way around the scopes for anything in the box with a token."
            ));
        } else if !from_catalog.contains(h) {
            say("own-host", format!("{h} is your own addition, not from a bundle."));
        }
        if MICROSOFT_SIGN_IN.iter().any(|x| h == x || h.strip_prefix("*.").is_some_and(|s| x.ends_with(&format!(".{s}")))) {
            say("microsoft-sign-in", format!(
                "{h} is Microsoft's sign-in. With it, something in the box can get the user's own SharePoint \
                 token and use it past the scopes and the record of admissions. The AI apps sign in on the \
                 computer instead."
            ));
        }
    }
    if a.box_settings.memory_gb > 6 {
        say("box-memory", format!(
            "A box of {} GB needs a device with about {} GB or more; on a smaller one, Windows gets little.",
            a.box_settings.memory_gb,
            a.box_settings.memory_gb * 2
        ));
    }
    if egress.log.as_ref().is_some_and(|l| l.enabled) {
        say("egress-log", "The egress log keeps every host the box connects to, on each device, under logs.".into());
    }
    if a.volume.bytes.is_none() {
        say("no-byte-alert", "The volume alert counts files only; one large file raises nothing.".into());
    }
    // An uploads bundle's hosts beside its sentence, not in it.
    for x in w.iter_mut().filter(|x| x.code == "uploads") {
        if let Some(b) = egress.bundles.iter().filter_map(|id| catalog.bundle(id)).find(|b| x.text.starts_with(&b.name)) {
            x.hosts = b.hosts.clone();
        }
    }
    w
}

/// A configuration saved earlier, to change and publish again.
pub fn open(path: &Path) -> Result<Authored, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    sluse_proto::config::load_authored(&bytes).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn save(path: &Path, d: &Draft) -> Result<(), String> {
    std::fs::write(path, &d.text).map_err(|e| format!("{}: {e}", path.display()))
}

/// What changed between two configurations, a line each, for the review
/// screen: top-level fields, and the hosts one by one.
pub fn diff(old: &Authored, new: &Authored) -> Vec<String> {
    let mut out = Vec::new();
    let (o, n) = (serde_json::to_value(old).unwrap_or_default(), serde_json::to_value(new).unwrap_or_default());
    for key in ["deployment", "entra", "sources", "maxFetchBytes", "volume", "box", "accounts"] {
        if o.get(key) != n.get(key) {
            out.push(format!("{key} changed"));
        }
    }
    let hosts = |a: &Authored| a.egress.as_ref().map(|e| e.allow.clone()).unwrap_or_default();
    let (oh, nh) = (hosts(old), hosts(new));
    out.extend(nh.iter().filter(|h| !oh.contains(h)).map(|h| format!("the box may now reach {h}")));
    out.extend(oh.iter().filter(|h| !nh.contains(h)).map(|h| format!("the box may no longer reach {h}")));
    let log = |a: &Authored| a.egress.as_ref().and_then(|e| e.log.clone());
    if log(old) != log(new) {
        out.push("the egress log changed".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn authored(v: serde_json::Value) -> Authored {
        serde_json::from_value(v).unwrap()
    }

    fn base() -> serde_json::Value {
        let c = Catalog::shipped();
        json!({
            "schemaVersion": 3,
            "deployment": { "id": "d1", "name": "Pilot", "revision": 1 },
            "entra": { "tenantId": "11111111-2222-3333-4444-555555555555", "clientId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" },
            "sources": [{ "name": "spo", "kind": { "type": "sharepoint", "address": { "siteUrl": "https://contoso.sharepoint.com/sites/t", "library": "Documents" } }, "scope": ["In-Scope"], "sensitivity": 2 }],
            "volume": { "admissions": 25, "windowSeconds": 60, "bytes": 52428800 },
            "egress": { "catalog": 1, "bundles": ["python"], "allow": c.allow(&["python".into()], &[]) },
        })
    }

    #[test]
    fn a_careful_config_has_no_warnings_and_round_trips() {
        let c = Catalog::shipped();
        let d = author(&authored(base()), &c).unwrap();
        assert!(d.warnings.is_empty(), "{:?}", d.warnings);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pilot.json");
        save(&p, &d).unwrap();
        assert!(diff(&open(&p).unwrap(), &authored(base())).is_empty());
    }

    #[test]
    fn what_the_loader_refuses_is_refused_and_the_rest_is_warned_about() {
        let c = Catalog::shipped();
        let mut v = base();
        v["sources"][0]["sensitivity"] = json!(7);
        assert!(author(&authored(v), &c).is_err(), "the box's own rules");

        let mut v = base();
        v["sources"][0]["scope"] = json!([]);
        v["egress"]["bundles"] = json!(["python", "github"]);
        v["egress"]["allow"].as_array_mut().unwrap().extend([json!("*.blob.core.windows.net"), json!("intranet.contoso.com"), json!("login.microsoftonline.com"), json!("contoso.sharepoint.com")]);
        v["box"] = json!({ "memoryGB": 8 });
        v["egress"]["log"] = json!({ "enabled": true, "maxMB": 50 });
        v["volume"].as_object_mut().unwrap().remove("bytes");
        let d = author(&authored(v), &c).expect("allowed");
        let codes: Vec<&str> = d.warnings.iter().map(|w| w.code).collect();
        for code in ["whole-source", "uploads", "bundle-trimmed", "shared-wildcard", "own-host", "microsoft-sign-in", "sharepoint-host", "box-memory", "egress-log", "no-byte-alert"] {
            assert!(codes.contains(&code), "{code} in {codes:?}");
        }
        assert!(d.warnings.iter().any(|w| w.text.contains("intranet.contoso.com")));
    }

    /// The shape `ui/shell/src/admin.js`'s `authored()` sends, field for
    /// field, so the page and the engine cannot drift apart unseen.
    #[test]
    fn the_setup_pages_shape_is_what_the_engine_reads() {
        let page = json!({
            "schemaVersion": 3,
            "deployment": { "id": "6f1c2a9e-0000-4000-8000-000000000000", "name": "Pilot", "revision": 1 },
            "entra": { "tenantId": "11111111-2222-3333-4444-555555555555", "clientId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" },
            "sources": [
                { "name": "tender", "kind": { "type": "sharepoint", "address": { "siteUrl": "https://contoso.sharepoint.com/sites/tender", "library": "Documents" } }, "scope": ["In-Scope", "In-Scope/Deeper"], "sensitivity": 3 },
                { "name": "share", "kind": { "type": "smb", "address": { "unc": "\\\\fs\\share" } }, "scope": [], "sensitivity": 2 }
            ],
            "volume": { "admissions": 25, "windowSeconds": 60, "bytes": 52428800 },
            "maxFetchBytes": 104857600,
            "egress": { "catalog": 1, "bundles": ["box-system", "python"], "allow": ["archive.ubuntu.com", "pypi.org"],
                        "log": { "enabled": true, "maxMB": 50 } },
            "box": { "memoryGB": 6, "homeGB": 80, "copyOut": false },
        });
        let d = author(&authored(page), &Catalog::shipped()).expect("the page's file loads");
        assert!(d.text.contains("\"memoryGB\": 6") && d.text.contains("\"copyOut\": false"));
    }

    #[test]
    fn the_difference_names_hosts_one_by_one() {
        let old = authored(base());
        let mut v = base();
        v["egress"]["allow"].as_array_mut().unwrap().retain(|h| h != "files.pythonhosted.org");
        v["egress"]["allow"].as_array_mut().unwrap().push(json!("intranet.contoso.com"));
        v["volume"]["admissions"] = json!(30);
        v["accounts"] = json!({ "claudeOrganisation": "8f0d2c1e-0000-4000-8000-000000000001" });
        let lines = diff(&old, &authored(v));
        assert!(lines.contains(&"volume changed".to_owned()));
        assert!(lines.contains(&"accounts changed".to_owned()), "D-072's pins are a change: {lines:?}");
        assert!(lines.contains(&"the box may now reach intranet.contoso.com".to_owned()));
        assert!(lines.contains(&"the box may no longer reach files.pythonhosted.org".to_owned()));
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The egress bundles this install ships (D-038 point 5),
//! `config/egress-catalog.json`.
//!
//! **Bundles to choose from, hosts as the truth.** Setup writes the bundles
//! chosen and the catalog's version into the config for display, and every
//! host written out in `egress.allow`, which alone is enforced. A newer
//! catalog is a difference for the admin to republish ([`Catalog::diff`]);
//! nothing here widens a box by itself.

use serde::{Deserialize, Serialize};

/// The catalog as the MSI ships it.
pub const SHIPPED: &str = include_str!("../../../config/egress-catalog.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Catalog {
    pub version: u32,
    #[serde(default)]
    pub about: String,
    pub bundles: Vec<Bundle>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bundle {
    pub id: String,
    pub name: String,
    pub description: String,
    /// On in every config: the box's own system.
    #[serde(default)]
    pub locked: bool,
    /// Ticked in a new configuration.
    #[serde(default)]
    pub default: bool,
    /// Whether these hosts can also take what the box sends them. The proxy
    /// sees a host, never a method (D-035), so each such bundle says so.
    pub uploads: bool,
    pub hosts: Vec<String>,
    /// When the hosts were measured, or `None` for the M9 draft.
    pub measured: Option<String>,
    /// Reached only in a sign-in window the person opens (D-075): its hosts
    /// go to `egress.window`, never to `egress.allow`.
    #[serde(default)]
    pub window: bool,
}

impl Catalog {
    pub fn shipped() -> Catalog {
        serde_json::from_str(SHIPPED).expect("the shipped catalog parses; a test says so")
    }

    pub fn bundle(&self, id: &str) -> Option<&Bundle> {
        self.bundles.iter().find(|b| b.id == id)
    }

    /// The ids ticked in a new configuration.
    pub fn defaults(&self) -> Vec<String> {
        self.bundles.iter().filter(|b| b.default || b.locked).map(|b| b.id.clone()).collect()
    }

    /// Every host for `chosen` (locked bundles always), then `extra` (the
    /// admin's own), each once, in order.
    pub fn allow(&self, chosen: &[String], extra: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        let hosts = self
            .bundles
            .iter()
            .filter(|b| !b.window && (b.locked || chosen.contains(&b.id)))
            .flat_map(|b| b.hosts.iter().cloned())
            .chain(extra.iter().cloned());
        for h in hosts {
            if !out.contains(&h) {
                out.push(h);
            }
        }
        out
    }

    /// The hosts of the window bundles chosen (D-075), each once: the box
    /// reaches them only while the person has a sign-in window open.
    pub fn window(&self, chosen: &[String]) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for h in self.bundles.iter().filter(|b| b.window && chosen.contains(&b.id)).flat_map(|b| &b.hosts) {
            if !out.contains(h) {
                out.push(h.clone());
            }
        }
        out
    }

    /// What `allow` would gain and lose if the chosen bundles were taken
    /// from this catalog again: the difference the admin republishes.
    pub fn diff(&self, allow: &[String], chosen: &[String], extra: &[String]) -> (Vec<String>, Vec<String>) {
        let now = self.allow(chosen, extra);
        let added = now.iter().filter(|h| !allow.contains(h)).cloned().collect();
        let removed = allow.iter().filter(|h| !now.contains(h)).cloned().collect();
        (added, removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shipped_catalog_is_valid_hosts_and_locks_the_box_system() {
        let c = Catalog::shipped();
        assert!(c.version >= 1);
        let all: Vec<String> = c.bundles.iter().flat_map(|b| b.hosts.clone()).collect();
        // Every host passes the box's own egress grammar.
        let cfg = sluse_proto::EgressConfig { allow: all.clone(), ..Default::default() };
        let json = serde_json::json!({ "schemaVersion": 3, "sources": [{ "name": "s", "kind": { "type": "smb", "address": { "unc": "\\\\h\\s" } }, "sensitivity": 1 }],
                                       "volume": { "admissions": 1, "windowSeconds": 1 }, "egress": cfg });
        sluse_proto::config::load_authored(json.to_string().as_bytes()).expect("the catalog's hosts load");
        assert!(c.bundle("box-system").unwrap().locked);
        // D-047: the bundles that take uploads beside the inference channel's
        // start off, ticked by consent.
        assert!(!c.defaults().iter().any(|b| b == "node" || b == "github"), "{:?}", c.defaults());
        // D-036, D-044: no bundle puts Microsoft's sign-in on the list; since
        // D-075 the one that names it is a window, off by default.
        let listed: Vec<&String> = c.bundles.iter().filter(|b| !b.window).flat_map(|b| &b.hosts).collect();
        assert!(!listed.iter().any(|h| h.starts_with("login.") || h.contains("microsoftonline")), "{listed:?}");
        let ms = c.bundles.iter().find(|b| b.window).expect("D-075's window bundle");
        assert!(!ms.default && !ms.locked && ms.hosts.iter().any(|h| h == "login.microsoftonline.com"));
    }

    #[test]
    fn a_window_bundle_never_reaches_the_allow_list() {
        let c = Catalog::shipped();
        let chosen = vec!["microsoft-signin".to_owned()];
        assert!(!c.allow(&chosen, &[]).iter().any(|h| h == "login.microsoftonline.com"));
        assert!(c.window(&chosen).iter().any(|h| h == "login.microsoftonline.com"));
        assert!(c.window(&[]).is_empty(), "not chosen, no window");
    }

    #[test]
    fn locked_bundles_are_always_in_and_the_difference_is_what_changed() {
        let c = Catalog::shipped();
        let none = c.allow(&[], &["intranet.contoso.com".into()]);
        assert!(none.contains(&"archive.ubuntu.com".into()) && none.contains(&"intranet.contoso.com".into()));
        assert!(!none.contains(&"pypi.org".into()));
        let chosen = vec!["python".to_owned()];
        let mut allow = c.allow(&chosen, &[]);
        assert_eq!(c.diff(&allow, &chosen, &[]), (vec![], vec![]));
        allow.retain(|h| h != "files.pythonhosted.org");
        allow.push("old.example.com".into());
        assert_eq!(c.diff(&allow, &chosen, &[]), (vec!["files.pythonhosted.org".into()], vec!["old.example.com".into()]));
    }
}

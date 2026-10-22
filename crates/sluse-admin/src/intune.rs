// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Publishing straight to Intune through Graph (D-037 point 2), for an admin
//! who grants setup Intune's rights; the `.intunewin` file is the other way.
//!
//! **One Win32 app per revision (D-043):** the deployment's package, which
//! carries the MSI, the config and the script, detected by the package
//! version in the registry and assigned, required, to the device group. A
//! new revision supersedes the deployment's last one as an update, which
//! never uninstalls it first.
//!
//! Each upload: the app, a content version, a file entry, Azure storage's
//! SAS URL, the encrypted content in blocks, the commit with the encryption
//! info, then the app pointed at that content version.
//!
//! **The riskiest part of D-039** (slice 5): Graph's beta endpoint, which is
//! where Win32 apps' relationships live, against a stand-in on the guest.
//! Only the demo tenant's Intune proves it.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{json, Value};

use crate::graph::Graph;
use crate::intunewin::Package;
use crate::setup::base64;

/// Azure storage's block size for the upload.
const BLOCK: usize = 6 * 1024 * 1024;

/// The MSI, as `msi::info` read it from the file the admin picked.
#[derive(Debug, Clone)]
pub struct Msi {
    pub product_code: String,
    pub version: String,
}

/// What to publish.
pub struct Publish<'a> {
    /// The package, built by [`crate::intunewin::build`] over the folder
    /// [`crate::setup::write_package`] wrote.
    pub package: &'a Package,
    /// The MSI it carries, for the app's description.
    pub msi: &'a Msi,
    pub deployment: &'a sluse_proto::Deployment,
    /// [`crate::setup::package_version`]: what detection compares.
    pub package_version: &'a str,
    /// The device group the app is assigned to, required.
    pub group: &'a str,
    /// How long to wait between asking Graph about an upload.
    pub poll: Duration,
    /// Set by closing Sluse Admin mid-upload (Q81): the upload stops between
    /// blocks or waits, and the app it made is deleted.
    pub stop: Option<&'a AtomicBool>,
    /// Each step as it happens, for the wait's named steps: `{"step": …}`.
    pub tell: Option<&'a (dyn Fn(Value) + Sync)>,
}

impl Publish<'_> {
    fn tell(&self, v: Value) {
        if let Some(t) = self.tell {
            t(v);
        }
    }
}

fn stopped(stop: Option<&AtomicBool>) -> Result<(), String> {
    match stop {
        Some(s) if s.load(Ordering::Relaxed) => Err("stopped: Sluse Admin was closed during the upload".into()),
        _ => Ok(()),
    }
}

#[derive(Debug, Default)]
pub struct Published {
    pub app: String,
    pub changed: Vec<String>,
    pub warnings: Vec<String>,
}

fn notes_deployment(id: &str) -> String {
    format!("sluse-deployment:{id}")
}

/// Publish the revision as one app, supersede the last and assign it.
pub async fn publish(g: &Graph, http: &reqwest::Client, p: &Publish<'_>) -> Result<Published, String> {
    let mut out = Published::default();
    let apps = g.list("/deviceAppManagement/mobileApps?$filter=isof('microsoft.graph.win32LobApp')".into()).await?;
    let note = |a: &Value| a["notes"].as_str().unwrap_or_default().to_owned();
    let dep_note = notes_deployment(&p.deployment.id);
    // The deployment's last revision, a two-app tenant app (D-037) included.
    let revision = |a: &Value| note(a).rsplit(':').next().and_then(|r| r.parse::<u32>().ok()).unwrap_or(0);
    let last = apps.iter().filter(|a| note(a).starts_with(&format!("{dep_note}:"))).max_by_key(|a| revision(a));
    if let Some(a) = last {
        p.tell(json!({ "step": "found", "revision": revision(a) }));
    }
    let previous = last.and_then(|a| a["id"].as_str().map(str::to_owned));

    let label = if p.deployment.name.is_empty() { p.deployment.id.clone() } else { p.deployment.name.clone() };
    let script = &p.package.setup_file;
    // Sluse apps made by hand, the `.intunewin` route's: nothing on them says
    // which deployment they carry, so they are named, not superseded
    // (D-045 point 4).
    for a in apps.iter().filter(|a| a["setupFilePath"].as_str() == Some(script) && !note(a).starts_with("sluse-deployment:")) {
        out.warnings.push(format!(
            "\"{}\" in Intune runs Sluse's script but was not published from here, so this revision does not \
             supersede it. If it is assigned to the same devices, the two give each device the other's \
             configuration at every check-in: remove its assignment, or supersede it with this app in the Intune admin center.",
            a["displayName"].as_str().unwrap_or("An app")
        ));
    }
    let ps = |extra: &str| format!("powershell.exe -NoProfile -ExecutionPolicy Bypass -File {script}{extra}");
    let body = json!({
        "@odata.type": "#microsoft.graph.win32LobApp",
        "displayName": format!("Sluse: {label}, revision {}", p.deployment.revision),
        "description": format!(
            "Sluse {} with this deployment's configuration. One deployment per device: a device that runs another refuses this one with exit code 2.",
            p.msi.version
        ),
        "publisher": "SerenIT and Prompted",
        "notes": format!("{dep_note}:{}", p.deployment.revision),
        "fileName": "IntunePackage.intunewin",
        "setupFilePath": script,
        "installCommandLine": ps(""),
        "uninstallCommandLine": ps(" -Uninstall"),
        "applicableArchitectures": "x64",
        "minimumSupportedOperatingSystem": { "v10_2004": true },
        "installExperience": { "runAsAccount": "system", "deviceRestartBehavior": "basedOnReturnCode" },
        "returnCodes": return_codes(),
        "rules": [{
            "@odata.type": "#microsoft.graph.win32LobAppRegistryRule",
            "ruleType": "detection",
            "check32BitOn64System": false,
            "keyPath": "HKEY_LOCAL_MACHINE\\SOFTWARE\\Sluse\\Deployment",
            "valueName": "PackageVersion",
            "operationType": "string",
            "operator": "equal",
            "comparisonValue": p.package_version,
        }, {
            // Both rules must hold: Sluse itself, not only the script's value.
            "@odata.type": "#microsoft.graph.win32LobAppFileSystemRule",
            "ruleType": "detection",
            "check32BitOn64System": false,
            "path": crate::setup::DETECT_DIR,
            "fileOrFolderName": crate::setup::DETECT_FILE,
            "operationType": "exists",
            "operator": "notConfigured",
        }],
    });
    let name = body["displayName"].clone();
    let app = g.call(reqwest::Method::POST, "/deviceAppManagement/mobileApps".into(), Some(body)).await?;
    out.app = app["id"].as_str().ok_or("Intune made an app with no id")?.to_owned();
    p.tell(json!({ "step": "made", "app": name }));
    // An app without its content is deleted again (Q53), and the error says
    // whether that worked: a person deletes it in Intune if not.
    if let Err(e) = upload(g, http, &out.app, p).await {
        return Err(match delete_app(g, &out.app).await {
            Ok(()) => format!("{e}\nthe app {} Sluse Admin made was deleted", out.app),
            Err(d) => format!("{e}\nthe app {} Sluse Admin made could not be deleted: {d}", out.app),
        });
    }
    out.changed.push(format!("published: Sluse, {label}, revision {}", p.deployment.revision));

    if let Some(prev) = &previous {
        p.tell(json!({ "step": "superseding" }));
        g.call(
            reqwest::Method::POST,
            format!("/deviceAppManagement/mobileApps/{}/updateRelationships", out.app),
            Some(json!({ "relationships": [{
                "@odata.type": "#microsoft.graph.mobileAppSupersedence",
                "targetId": prev,
                "supersedenceType": "update",
            }] })),
        )
        .await?;
        out.changed.push("superseding: the deployment's previous revision".into());
    }

    // Warnings, not friction (D-038 point 4): a user group is allowed.
    let users = g.get(format!("/groups/{}/members/microsoft.graph.user?$select=id&$top=1", p.group)).await?;
    if users["value"].as_array().is_some_and(|u| !u.is_empty()) {
        out.warnings.push(
            "The group has users in it. Intune installs a Win32 app assigned to users on the devices they sign in \
             to, so a shared device runs the first user's deployment. A device group is the documented choice."
                .into(),
        );
    }
    p.tell(json!({ "step": "assigning" }));
    g.call(
        reqwest::Method::POST,
        format!("/deviceAppManagement/mobileApps/{}/assign", out.app),
        Some(json!({ "mobileAppAssignments": [{
            "@odata.type": "#microsoft.graph.mobileAppAssignment",
            "intent": "required",
            "target": { "@odata.type": "#microsoft.graph.groupAssignmentTarget", "groupId": p.group },
        }] })),
    )
    .await?;
    out.changed.push("assigned: required, to the group".into());
    Ok(out)
}

/// Delete an app Sluse Admin made: after a failed upload, and when the admin
/// asks again because that delete failed (Q53).
pub async fn delete_app(g: &Graph, id: &str) -> Result<(), String> {
    g.call(reqwest::Method::DELETE, format!("/deviceAppManagement/mobileApps/{id}"), None).await.map(|_| ())
}

/// What a package folder Save wrote (D-043) holds: its deployment, the MSI
/// it carries and the package version. Publish reads it, and so does Sluse
/// Admin before publishing a package saved earlier (Q50).
pub fn package_info(package: &std::path::Path) -> Result<(sluse_proto::Deployment, Msi, String), String> {
    let read = |name: &str| std::fs::read(package.join(name)).map_err(|e| format!("the package's {name}: {e}"));
    let a = sluse_proto::config::load_authored(&read("sluse.json")?).map_err(|e| e.to_string())?;
    let deployment = a.deployment.ok_or("the package's config names no deployment")?;
    let meta: Value = serde_json::from_slice(&read("package.json")?).map_err(|e| format!("the package's package.json: {e}"))?;
    let field = |k: &str| meta[k].as_str().map(str::to_owned).ok_or_else(|| format!("the package's package.json has no {k}"));
    let msi = Msi { product_code: field("productCode")?, version: field("msiVersion")? };
    Ok((deployment, msi, field("packageVersion")?))
}

/// The setup UI's publish: a package folder Save wrote, packaged and
/// published as it is.
pub async fn publish_files(
    g: &Graph,
    http: &reqwest::Client,
    package: &std::path::Path,
    group: &str,
    stop: Option<&AtomicBool>,
    tell: Option<&(dyn Fn(Value) + Sync)>,
) -> Result<Published, String> {
    let (deployment, msi, version) = package_info(package)?;
    let pkg = crate::intunewin::build(package, crate::setup::SCRIPT)?;
    let p = Publish { package: &pkg, msi: &msi, deployment: &deployment, package_version: &version, group, poll: Duration::from_secs(2), stop, tell };
    publish(g, http, &p).await
}

fn return_codes() -> Value {
    json!([
        { "returnCode": 0, "type": "success" },
        { "returnCode": 1707, "type": "success" },
        { "returnCode": 3010, "type": "softReboot" },
        { "returnCode": 1641, "type": "hardReboot" },
        { "returnCode": 1618, "type": "retry" },
    ])
}

/// The app's content: a content version, upload, commit, point at it.
async fn upload(g: &Graph, http: &reqwest::Client, id: &str, p: &Publish<'_>) -> Result<(), String> {
    let (pkg, poll) = (p.package, p.poll);
    let base = format!("/deviceAppManagement/mobileApps/{id}/microsoft.graph.win32LobApp/contentVersions");
    let version = g.call(reqwest::Method::POST, base.clone(), Some(json!({}))).await?;
    let v = version["id"].as_str().ok_or("a content version with no id")?.to_owned();
    let files = format!("{base}/{v}/files");
    let file = g
        .call(
            reqwest::Method::POST,
            files.clone(),
            Some(json!({
                "@odata.type": "#microsoft.graph.mobileAppContentFile",
                "name": "IntunePackage.intunewin",
                "size": pkg.unencrypted_size,
                "sizeEncrypted": pkg.encrypted.len(),
                "isDependency": false,
            })),
        )
        .await?;
    let f = file["id"].as_str().ok_or("a content file with no id")?.to_owned();
    let entry = format!("{files}/{f}");
    let sas = wait(g, &entry, "azureStorageUriRequest", poll, p.stop).await?["azureStorageUri"]
        .as_str()
        .ok_or("no storage URL")?
        .to_owned();
    p.tell(json!({ "step": "room" }));
    put_blocks(http, &sas, &pkg.encrypted, p).await?;
    p.tell(json!({ "step": "checking" }));
    g.call(reqwest::Method::POST, format!("{entry}/commit"), Some(json!({ "fileEncryptionInfo": pkg.info }))).await?;
    wait(g, &entry, "commitFile", poll, p.stop).await?;
    g.call(
        reqwest::Method::PATCH,
        format!("/deviceAppManagement/mobileApps/{id}"),
        Some(json!({ "@odata.type": "#microsoft.graph.win32LobApp", "committedContentVersion": v })),
    )
    .await?;
    Ok(())
}

/// Ask about a content file until its `uploadState` says `<step>Success`;
/// `<step>Failed` or `<step>TimedOut` is an error, and so is waiting long.
async fn wait(g: &Graph, entry: &str, step: &str, poll: Duration, stop: Option<&AtomicBool>) -> Result<Value, String> {
    for _ in 0..120 {
        stopped(stop)?;
        let f = g.get(entry.to_owned()).await?;
        let state = f["uploadState"].as_str().unwrap_or_default();
        if state == format!("{step}Success") {
            return Ok(f);
        }
        if state == format!("{step}Failed") || state == format!("{step}TimedOut") {
            return Err(format!("Intune's upload: {state}"));
        }
        tokio::time::sleep(poll).await;
    }
    Err(format!("Intune's upload did not reach {step}Success"))
}

/// The encrypted content to Azure storage's SAS URL, in blocks, then the
/// block list. No Graph token goes there: the SAS is the authority.
async fn put_blocks(http: &reqwest::Client, sas: &str, data: &[u8], p: &Publish<'_>) -> Result<(), String> {
    let mut ids = Vec::new();
    let of = data.len().div_ceil(BLOCK);
    for (n, chunk) in data.chunks(BLOCK).enumerate() {
        stopped(p.stop)?;
        p.tell(json!({ "step": "block", "n": n + 1, "of": of, "bytes": (n * BLOCK + chunk.len()), "total": data.len() }));
        let id = base64(format!("{n:04}").as_bytes());
        let res = http
            .put(format!("{sas}&comp=block&blockid={}", id.replace('=', "%3D")))
            .header("x-ms-blob-type", "BlockBlob")
            .body(chunk.to_vec())
            .send()
            .await
            .map_err(|e| format!("uploading block {n}: {e}"))?;
        if !res.status().is_success() {
            return Err(format!("uploading block {n}: {}", res.status()));
        }
        ids.push(id);
    }
    let list: String = ids.iter().map(|i| format!("<Latest>{i}</Latest>")).collect();
    let res = http
        .put(format!("{sas}&comp=blocklist"))
        .body(format!("<?xml version=\"1.0\" encoding=\"utf-8\"?><BlockList>{list}</BlockList>"))
        .send()
        .await
        .map_err(|e| format!("the block list: {e}"))?;
    if !res.status().is_success() {
        return Err(format!("the block list: {}", res.status()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str) -> (tempfile::TempDir, Package) {
        let dir = tempfile::tempdir().unwrap();
        // Random, so deflate cannot shrink it below three blocks.
        let mut data = vec![0u8; 13 * 1024 * 1024];
        getrandom::fill(&mut data).unwrap();
        std::fs::write(dir.path().join(name), data).unwrap();
        let p = crate::intunewin::build(dir.path(), name).unwrap();
        (dir, p)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn one_app_uploads_in_blocks_and_a_new_revision_supersedes_the_last() {
        let (base, t) = crate::stand_in::start().await;
        t.lock().unwrap().group_users.insert("g-users".into(), 2);
        let http = reqwest::Client::new();
        let g = Graph::new(&http, &format!("{base}/beta"), "t".into());
        let (_d, package) = pkg(crate::setup::SCRIPT);
        let msi = Msi { product_code: "{11111111-2222-3333-4444-555555555555}".into(), version: "0.0.1".into() };
        let mut dep = sluse_proto::Deployment { id: "dep-a".into(), name: "Pilot".into(), revision: 1 };
        fn publish_as<'a>(p: &'a Package, msi: &'a Msi, dep: &'a sluse_proto::Deployment, group: &'a str) -> Publish<'a> {
            Publish { package: p, msi, deployment: dep, package_version: "0.0.1:{x}:abc123", group, poll: Duration::from_millis(1), stop: None, tell: None }
        }

        let first = publish(&g, &http, &publish_as(&package, &msi, &dep, "g-devices")).await.unwrap();
        assert!(first.warnings.is_empty(), "{:?}", first.warnings);
        {
            let t = t.lock().unwrap();
            assert_eq!(t.mobile_apps.len(), 1, "one app, the MSI inside it (D-043)");
            assert!(!t.bearer_to_storage, "the Graph token never goes to storage");
            let app = &t.mobile_apps[0];
            assert_eq!(app["committedContentVersion"], "1", "{app}");
            // The encrypted content, whole, in three 6 MB blocks, and the
            // encryption info Intune decrypts it with.
            let f = &t.files["file-0"];
            assert_eq!(t.blobs["file-0"], package.encrypted);
            assert_eq!(t.blocks.keys().filter(|k| k.starts_with("file-0/")).count(), 3);
            assert_eq!(f["commit"]["mac"], package.info.mac);
            assert_eq!(f["request"]["sizeEncrypted"], package.encrypted.len());
            assert_eq!(app["rules"][0]["valueName"], "PackageVersion");
            assert_eq!(app["rules"][0]["comparisonValue"], "0.0.1:{x}:abc123", "detection by the package's version");
            assert_eq!(app["rules"][1]["@odata.type"], "#microsoft.graph.win32LobAppFileSystemRule");
            assert_eq!((&app["rules"][1]["path"], &app["rules"][1]["fileOrFolderName"]), (&json!(r"%ProgramFiles%\Sluse\bin"), &json!("sluse.exe")), "and Sluse itself");
            assert_eq!(app["installExperience"]["deviceRestartBehavior"], "basedOnReturnCode", "Hyper-V's 3010");
            assert!(app["uninstallCommandLine"].as_str().unwrap().ends_with("-Uninstall"));
            assert!(!t.relationships.contains_key(app["id"].as_str().unwrap()), "nothing to supersede yet");
            assert_eq!(t.assignments[app["id"].as_str().unwrap()]["mobileAppAssignments"][0]["target"]["groupId"], "g-devices");
        }

        // Revision 2: the last revision superseded, a user group warned about,
        // and an app made by hand named, not superseded (L1, 2026-10-05).
        dep.revision = 2;
        t.lock().unwrap().mobile_apps.push(json!({
            "id": "hand", "displayName": "Sluse by hand", "setupFilePath": crate::setup::SCRIPT, "notes": "",
        }));
        let second = publish(&g, &http, &publish_as(&package, &msi, &dep, "g-users")).await.unwrap();
        assert_eq!(second.warnings.len(), 2, "{:?}", second.warnings);
        assert!(second.warnings.iter().any(|w| w.contains("\"Sluse by hand\"")));
        let t = t.lock().unwrap();
        assert_eq!(t.mobile_apps.len(), 3);
        let rel = &t.relationships[&second.app]["relationships"];
        assert_eq!(rel.as_array().unwrap().len(), 1);
        assert_eq!(rel[0]["@odata.type"], "#microsoft.graph.mobileAppSupersedence");
        assert_eq!(rel[0]["targetId"], json!(first.app));
        assert_eq!(rel[0]["supersedenceType"], "update", "never uninstalled first");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_or_stopped_upload_deletes_the_app_it_made() {
        let (base, t) = crate::stand_in::start().await;
        let http = reqwest::Client::new();
        let g = Graph::new(&http, &format!("{base}/beta"), "t".into());
        let (_d, package) = pkg(crate::setup::SCRIPT);
        let msi = Msi { product_code: "{x}".into(), version: "0.0.1".into() };
        let dep = sluse_proto::Deployment { id: "dep-a".into(), name: "Pilot".into(), revision: 1 };
        let steps = std::sync::Mutex::new(Vec::new());
        let tell = |v: Value| steps.lock().unwrap().push(v["step"].as_str().unwrap().to_owned());
        let mut p = Publish { package: &package, msi: &msi, deployment: &dep, package_version: "v", group: "g", poll: Duration::from_millis(1), stop: None, tell: Some(&tell) };

        t.lock().unwrap().fail_commit = true;
        let e = publish(&g, &http, &p).await.unwrap_err();
        assert!(e.contains("commitFileFailed") && e.ends_with("the app app-0 Sluse Admin made was deleted"), "{e}");
        assert!(t.lock().unwrap().mobile_apps.is_empty());
        assert_eq!(steps.lock().unwrap().iter().filter(|s| *s == "block").count(), 3, "{steps:?}");

        let stop = AtomicBool::new(true);
        p.stop = Some(&stop);
        let e = publish(&g, &http, &p).await.unwrap_err();
        assert!(e.starts_with("stopped:") && e.contains("was deleted"), "{e}");
        assert!(t.lock().unwrap().mobile_apps.is_empty());
    }
}

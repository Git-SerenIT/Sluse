// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A tenant, once (D-024 point 2, slice 5): Sluse's registration, the
//! tenant's config and the tenant package. Moved here from the lifecycle's
//! `admin.rs` (D-039 slice 4), which `sluse admin setup` now calls.
//!
//! Signs in to Microsoft Graph by device code, as a tenant administrator,
//! then:
//! 1. finds or makes **one registration, "Sluse Gate", a public client**
//!    (D-036): the host's sign-in redirects to Entra's native-client page,
//!    and it holds Graph's delegated `Files.Read.All`, `Sites.Read.All`,
//!    `offline_access`, `openid` and `profile`. No application permissions,
//!    **no credential**: a certificate an older setup gave it is removed, and
//!    so is the API scope OBO needed;
//! 2. deletes the "Sluse entry" registration an older setup made;
//! 3. makes the service principal;
//! 4. prints where to grant admin consent in the portal;
//! 5. writes the tenant's `sluse.json` and the deployment's package for
//!    Intune: the config, the MSI and one script, one Win32 app (D-043). It
//!    holds no key.
//!
//! **Idempotent.** It finds by name and repairs by `PATCH`, so a rerun
//! changes nothing.
//!
//! The sign-in uses Microsoft's own public client for Graph, "Microsoft Graph
//! Command Line Tools", which is what `Connect-MgGraph` signs in with. A
//! tenant that has blocked it passes `--client-id` for its own.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

use crate::graph::Graph;

/// "Microsoft Graph Command Line Tools", Microsoft's public client.
pub const GRAPH_CLI_CLIENT: &str = "14d82eec-204b-4c2f-b7e8-296a70dab67e";
const GRAPH_APP: &str = "00000003-0000-0000-c000-000000000000";
pub const GATE_NAME: &str = "Sluse Gate";
/// The OBO-era sign-in page's registration, deleted by setup (D-036).
pub const ENTRY_NAME: &str = "Sluse entry";
/// The delegated Graph permissions Sluse's app holds, and so what admin
/// consent must cover ([`crate::consent`]).
pub const GATE_GRAPH_SCOPES: [&str; 5] = ["Files.Read.All", "Sites.Read.All", "offline_access", "openid", "profile"];

pub struct Options {
    pub out: PathBuf,
    /// The MSI the package carries (D-043).
    pub msi: MsiFile,
    pub site: String,
    pub library: String,
    pub source_name: String,
    /// Folders in the library the agent may work in; empty is the whole
    /// library. The acceptance run's fixture had none, so its `out-of-scope`
    /// was readable (L1, 2026-10-01).
    pub scopes: Vec<String>,
    pub client_id: String,
    /// `https://login.microsoftonline.com` and `https://graph.microsoft.com/v1.0`,
    /// or a test's stand-ins.
    pub login: String,
    pub graph: String,
}

pub struct Outcome {
    pub tenant: String,
    pub gate_app: String,
    /// Its service principal's object id: what consent and assignment name.
    pub service_principal: String,
    /// What this run made or removed, for the person to read.
    pub created: Vec<String>,
    pub package: PathBuf,
    /// [`package_version`]: what detection compares.
    pub version: String,
}

/// Sign in by device code and return an access token for Graph. `tell` shows
/// the person what to open and which code to type.
pub async fn sign_in(http: &reqwest::Client, o: &Options, tell: &mut dyn FnMut(&str)) -> Result<String, String> {
    let base = format!("{}/organizations/oauth2/v2.0", o.login.trim_end_matches('/'));
    let scope = "https://graph.microsoft.com/Application.ReadWrite.All";
    let code: Value = http
        .post(format!("{base}/devicecode"))
        .form(&[("client_id", o.client_id.as_str()), ("scope", scope)])
        .send()
        .await
        .map_err(|e| e.to_string())?
        .json()
        .await
        .map_err(|e| e.to_string())?;
    let device = code["device_code"].as_str().ok_or_else(|| format!("no device code: {code}"))?;
    tell(code["message"].as_str().unwrap_or("Sign in at https://microsoft.com/devicelogin"));
    let mut interval = code["interval"].as_u64().unwrap_or(5);
    loop {
        tokio::time::sleep(Duration::from_secs(interval)).await;
        let t: Value = http
            .post(format!("{base}/token"))
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                ("client_id", o.client_id.as_str()),
                ("device_code", device),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())?;
        if let Some(token) = t["access_token"].as_str() {
            return Ok(token.to_owned());
        }
        match t["error"].as_str() {
            Some("authorization_pending") => {}
            Some("slow_down") => interval += 5,
            _ => return Err(format!("the sign-in did not complete: {}", t["error_description"].as_str().unwrap_or("?"))),
        }
    }
}

/// The directory (tenant) id, from the token's own `tid` claim.
pub fn tenant_of(token: &str) -> Result<String, String> {
    let payload = token.split('.').nth(1).ok_or("the token is not a JWT")?;
    let mut b64: String = payload.replace('-', "+").replace('_', "/");
    while !b64.len().is_multiple_of(4) {
        b64.push('=');
    }
    let bytes = base64_decode(&b64).ok_or("the token's payload is not base64")?;
    let claims: Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    claims["tid"].as_str().map(str::to_owned).ok_or_else(|| "the token has no tid".into())
}

/// The script Intune runs, and the MSI beside it, in every package (D-043).
pub const SCRIPT: &str = "Install-Sluse.ps1";
pub const MSI: &str = "Sluse.msi";

/// The app's second detection rule (2026-10-05): the device half's own
/// file, which only the MSI's "Sluse on this computer" puts there. The registry value
/// is the script's, and outlives Sluse removed from Settings > Apps, where
/// Intune would go on seeing it installed and never reinstall it.
pub const DETECT_DIR: &str = r"%ProgramFiles%\Sluse\bin";
pub const DETECT_FILE: &str = "sluse.exe";

/// An MSI to package, and what Windows Installer read from it.
pub struct MsiFile {
    pub path: PathBuf,
    pub info: crate::intune::Msi,
}

impl MsiFile {
    /// Read by Windows Installer: Windows only.
    pub fn read(path: &Path) -> Result<Self, String> {
        Ok(Self { path: path.to_owned(), info: crate::msi::info(path)? })
    }
}

/// What the app's detection compares (D-043): the MSI's version and product
/// code, which every build changes even at one version, and the config's
/// hash. A new Sluse and a new revision are each a new package.
pub fn package_version(msi: &crate::intune::Msi, authored: &[u8]) -> String {
    format!("{}:{}:{}", msi.version, msi.product_code, sluse_proto::ContentHash::of(authored).as_str())
}

/// The CLI's whole run: the registration, then the package.
pub async fn setup(http: &reqwest::Client, token: String, o: &Options) -> Result<Outcome, String> {
    let tenant = tenant_of(&token)?;
    let g = Graph::new(http, &o.graph, token);
    let r = register(&g).await?;
    let config = tenant_config(&tenant, &r.app_id, o)?;
    let version = write_package(&o.out, &config, &o.msi)?;
    Ok(Outcome {
        version,
        tenant,
        gate_app: r.app_id,
        service_principal: r.service_principal,
        created: r.changed,
        package: o.out.clone(),
    })
}

/// Sluse's registration as it now is.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Registered {
    pub app_id: String,
    pub service_principal: String,
    /// What this run made or removed, for the person to read.
    pub changed: Vec<String>,
}

/// Find or make Sluse's registration and its service principal, and remove
/// what an older setup made for OBO. Idempotent (the module's list).
pub async fn register(g: &Graph) -> Result<Registered, String> {
    let mut created = Vec::new();

    // Graph's own delegated scopes, by value, so no GUID is typed here.
    let graph_sp = g
        .call(reqwest::Method::GET, format!("/servicePrincipals(appId='{GRAPH_APP}')?$select=oauth2PermissionScopes"), None)
        .await?;
    let graph_scope = |value: &str| -> Result<String, String> {
        graph_sp["oauth2PermissionScopes"]
            .as_array()
            .and_then(|a| a.iter().find(|s| s["value"] == value))
            .and_then(|s| s["id"].as_str())
            .map(str::to_owned)
            .ok_or_else(|| format!("Graph has no delegated scope {value}"))
    };
    let access = |scopes: &[&str]| -> Result<Value, String> {
        Ok(Value::Array(scopes.iter().map(|s| Ok(json!({ "id": graph_scope(s)?, "type": "Scope" }))).collect::<Result<_, String>>()?))
    };

    let gate = g.app(GATE_NAME, &mut created).await?;
    let gate_id = gate["id"].as_str().ok_or("the Gate application has no id")?.to_owned();
    let gate_app = gate["appId"].as_str().ok_or("the Gate application has no appId")?.to_owned();
    let patch = |id: &str, body: Value| g.call(reqwest::Method::PATCH, format!("/applications/{id}"), Some(body));

    // OBO's API scope goes (D-036). Entra refuses to delete an enabled scope,
    // so an older setup's is disabled first, with its pre-authorisation.
    let scopes = gate["api"]["oauth2PermissionScopes"].as_array().cloned().unwrap_or_default();
    if !scopes.is_empty() {
        let disabled: Vec<Value> = scopes
            .into_iter()
            .map(|mut s| {
                s["isEnabled"] = json!(false);
                s
            })
            .collect();
        patch(&gate_id, json!({ "api": { "oauth2PermissionScopes": disabled, "preAuthorizedApplications": [] } })).await?;
        created.push("removed: the access_as_user scope (OBO)".into());
    }
    if gate["keyCredentials"].as_array().is_some_and(|k| !k.is_empty()) {
        created.push("removed: the certificate credential".into());
    }
    // An app found by its name may have been made by anyone (review R-10):
    // nobody owns it after this, no secret or federated credential signs in
    // as it, and it has no redirect but the native one, before it is
    // consented to for the whole tenant. Every run, so one added later goes
    // at the next. Managing it needs the roles setup asks for, not ownership.
    let at = format!("/applications/{gate_id}");
    for owner in g.list(format!("{at}/owners?$select=id")).await? {
        let Some(id) = owner["id"].as_str() else { continue };
        g.call(reqwest::Method::DELETE, format!("{at}/owners/{id}/$ref"), None).await?;
        created.push(format!("removed: owner {id}"));
    }
    for secret in gate["passwordCredentials"].as_array().cloned().unwrap_or_default() {
        let Some(key) = secret["keyId"].as_str() else { continue };
        g.call(reqwest::Method::POST, format!("{at}/removePassword"), Some(json!({ "keyId": key }))).await?;
        created.push(format!("removed: a client secret ({key})"));
    }
    for fic in g.list(format!("{at}/federatedIdentityCredentials")).await? {
        let Some(id) = fic["id"].as_str() else { continue };
        g.call(reqwest::Method::DELETE, format!("{at}/federatedIdentityCredentials/{id}"), None).await?;
        created.push(format!("removed: a federated credential ({id})"));
    }
    // Graph's, first, and every other resource's the admin added since, kept:
    // an MCP server's delegated scope (D-071). Before, this replaced the
    // list, and running setup again would have dropped them.
    let mut required: Vec<Value> = gate["requiredResourceAccess"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| r["resourceAppId"] != GRAPH_APP)
        .cloned()
        .collect();
    required.insert(0, json!({ "resourceAppId": GRAPH_APP, "resourceAccess": access(&GATE_GRAPH_SCOPES)? }));
    patch(&gate_id, json!({
        "signInAudience": "AzureADMyOrg",
        "web": { "redirectUris": [], "implicitGrantSettings": { "enableIdTokenIssuance": false, "enableAccessTokenIssuance": false } },
        "spa": { "redirectUris": [] },
        "identifierUris": [],
        "api": { "oauth2PermissionScopes": [], "preAuthorizedApplications": [] },
        "isFallbackPublicClient": true,
        "publicClient": { "redirectUris": [sluse_proto::wire::NATIVE_REDIRECT] },
        "keyCredentials": [],
        "requiredResourceAccess": required,
        // D-057: a synced user's AD SID in the ID token, which a domain
        // account's Windows logon is compared with.
        "optionalClaims": { "idToken": [{ "name": "onprem_sid", "essential": false }], "accessToken": [], "saml2Token": [] },
    }))
    .await?;
    let sp = g.service_principal(&gate_app, &mut created).await?;
    let service_principal = sp["id"].as_str().ok_or("the service principal has no id")?.to_owned();

    // The OBO-era sign-in page's registration, made by an older setup.
    if let Some(entry) = g.find_app(ENTRY_NAME).await? {
        let id = entry["id"].as_str().ok_or("the entry application has no id")?;
        g.call(reqwest::Method::DELETE, format!("/applications/{id}"), None).await?;
        created.push(format!("deleted: application {ENTRY_NAME:?}"));
    }

    Ok(Registered { app_id: gate_app, service_principal, changed: created })
}

/// The deployment's package in `out` (D-043), in a folder closed first: the
/// authored file as `sluse.json`, the MSI, `package.json` with what the
/// script needs of the MSI and what detection compares, and the script. An
/// older package's key and script go. The package version.
pub fn write_package(out: &Path, authored: &str, msi: &MsiFile) -> Result<String, String> {
    protect_package(out)?;
    let version = package_version(&msi.info, authored.as_bytes());
    std::fs::write(out.join("sluse.json"), authored).map_err(|e| e.to_string())?;
    if msi.path != out.join(MSI) {
        std::fs::copy(&msi.path, out.join(MSI)).map_err(|e| format!("{}: {e}", msi.path.display()))?;
    }
    let meta = json!({ "productCode": msi.info.product_code, "msiVersion": msi.info.version, "packageVersion": version });
    std::fs::write(out.join("package.json"), format!("{meta:#}\n")).map_err(|e| e.to_string())?;
    std::fs::write(out.join(SCRIPT), INSTALL).map_err(|e| e.to_string())?;
    // What an older package held, which no device needs any more: the key
    // (D-036) and the tenant-only script (D-043).
    let _ = std::fs::remove_dir_all(out.join("entra"));
    let _ = std::fs::remove_file(out.join("Install-SluseTenant.ps1"));
    Ok(version)
}

/// Sluse Admin's Save over a file that already holds another deployment
/// continues that one: its id, and the revision after its own. Found at the
/// test run (2026-10-05): a Save after Sluse Admin was reinstalled, without
/// Open, made a new deployment of the same name, and the device refused it
/// as a second one. The file is the deployment; a new file is a new one.
/// The text to save, and what to tell the admin when it changed.
pub fn continue_deployment(existing: Option<&[u8]>, text: &str) -> Result<(String, Option<String>), String> {
    let Some(old) = existing.and_then(|b| sluse_proto::config::load_authored(b).ok()).and_then(|a| a.deployment) else {
        return Ok((text.to_owned(), None));
    };
    let mut a = sluse_proto::config::load_authored(text.as_bytes()).map_err(|e| e.to_string())?;
    let Some(new) = a.deployment.as_mut() else { return Ok((text.to_owned(), None)) };
    if new.id == old.id {
        return Ok((text.to_owned(), None));
    }
    new.id = old.id.clone();
    new.revision = old.revision + 1;
    let said = format!(
        "This file held the deployment '{}' at revision {}: saved as its revision {}, which devices running it take as an update. Save to a new file to start a new deployment.",
        old.name, old.revision, new.revision
    );
    let mut out = serde_json::to_string_pretty(&a).map_err(|e| e.to_string())?;
    out.push('\n');
    Ok((out, Some(said)))
}

/// A saved configuration's package and `.intunewin`, beside it.
#[derive(Debug)]
pub struct Saved {
    pub package: PathBuf,
    pub intunewin: PathBuf,
    /// [`package_version`]: what detection compares.
    pub version: String,
}

/// Package the authored `text`, saved at `config`, with `msi` (D-043): the
/// folder `<config>.package` and `<config>.intunewin` beside it. Sluse
/// Admin's Save and `sluse admin package` both. Refuses a config the box
/// would refuse, or one that names no deployment.
pub fn save(config: &Path, text: &str, msi: &MsiFile) -> Result<Saved, String> {
    let a = sluse_proto::config::load_authored(text.as_bytes()).map_err(|e| format!("{}: {e}", config.display()))?;
    if a.deployment.is_none() {
        return Err(format!("{} names no deployment; save it from Sluse Admin", config.display()));
    }
    let package = config.with_extension("package");
    let version = write_package(&package, text, msi)?;
    let iw = crate::intunewin::build(&package, SCRIPT)?;
    let intunewin = config.with_extension("intunewin");
    std::fs::write(&intunewin, &iw.intunewin).map_err(|e| format!("{}: {e}", intunewin.display()))?;
    Ok(Saved { package, intunewin, version })
}

/// Close the package folder to everyone but SYSTEM, Administrators and the
/// account running setup, at every run, so a rerun also closes a folder an
/// older setup left open. It holds no key since D-036, but names the
/// tenant's sources and scopes, and a script Intune runs as SYSTEM on every
/// device.
fn protect_package(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(windows)]
    crate::acl::protect_package(dir).map_err(|e| format!("closing {}: {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("closing {}: {e}", dir.display()))?;
    }
    Ok(())
}

/// The tenant's `sluse.json`, the authored file (D-038 point 2), checked by
/// the config's own loader. The device half is each device's service's.
pub fn tenant_config(tenant: &str, gate: &str, o: &Options) -> Result<String, String> {
    // A rerun is the same deployment, published again (D-038 point 4).
    let deployment = std::fs::read(o.out.join("sluse.json"))
        .ok()
        .and_then(|b| sluse_proto::config::load_authored(&b).ok())
        .and_then(|a| a.deployment)
        .map_or_else(|| uuid().map(|id| (id, 1)), |d| Ok((d.id, d.revision + 1)))?;
    let catalog = crate::catalog::Catalog::shipped();
    let c = json!({
        "schemaVersion": sluse_proto::SCHEMA_VERSION,
        "deployment": { "id": deployment.0, "name": "", "revision": deployment.1 },
        "sources": [{
            "name": o.source_name,
            "kind": { "type": "sharepoint", "address": { "siteUrl": o.site, "library": o.library } },
            "scope": o.scopes,
            "sensitivity": 2,
        }],
        "volume": { "admissions": 25, "windowSeconds": 60, "bytes": 52428800 },
        "entra": { "tenantId": tenant, "clientId": gate },
        // The shipped catalog's default bundles. Not the tenant's SharePoint:
        // the Gate brings its files (D-046), and with it on the list a token
        // got in the box would have a way there (D-044).
        "egress": {
            "catalog": catalog.version,
            "bundles": catalog.defaults(),
            "allow": catalog.allow(&catalog.defaults(), &[]),
        },
    });
    let mut text = serde_json::to_string_pretty(&c).map_err(|e| e.to_string())?;
    text.push('\n');
    sluse_proto::config::load_authored(text.as_bytes()).map_err(|e| format!("the config this made does not load: {e}"))?;
    Ok(text)
}

/// The deployment's one Win32 app (D-043): refuses another deployment,
/// installs the MSI unless this build is installed, copies the config in,
/// then the detection value. `-Uninstall` takes all of it off.
const INSTALL: &str = r#"# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# A Sluse deployment's package (D-043): Sluse.msi, this tenant's sluse.json
# and package.json, installed as SYSTEM by Intune as one Win32 app. No key:
# the Gate is a public client (D-036).
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-Sluse.ps1
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File Install-Sluse.ps1 -Uninstall
#
# One deployment per device (D-038 point 4): a package for another deployment
# is refused with exit code 2, naming both, before anything is installed. The
# same deployment replaces. Exit 3010 is the MSI's, when Hyper-V needs the
# restart; Intune does it. Detection is the registry value
# HKLM\SOFTWARE\Sluse\Deployment\PackageVersion equal to package.json's.
#
# -RegistryKey, -Msiexec, -Products and -Device are for the test, which runs
# this against a stand-in registry, msiexec and install.
param(
    [switch]$Uninstall,
    [string]$RegistryKey = 'HKLM:\SOFTWARE\Sluse\Deployment',
    [string]$Msiexec = (Join-Path $env:SystemRoot 'System32\msiexec.exe'),
    [string]$Products = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    # Installed by the MSI's "Sluse on this computer" feature only, never by Sluse Admin.
    [string]$Device = (Join-Path $env:ProgramFiles 'Sluse\bin\sluse.exe')
)
$ErrorActionPreference = 'Stop'
# Intune's agent may start this as a 32-bit process, whose HKLM:\SOFTWARE is
# WOW6432Node: detection, which reads the 64-bit view, would never find the
# value. Run again as 64-bit, with the same arguments and exit code.
if (-not [Environment]::Is64BitProcess -and [Environment]::Is64BitOperatingSystem) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $MyInvocation.MyCommand.Path)
    if ($Uninstall) { $a += '-Uninstall' }
    foreach ($k in 'RegistryKey', 'Msiexec', 'Products', 'Device') {
        if ($PSBoundParameters.ContainsKey($k)) { $a += "-$k", $PSBoundParameters[$k] }
    }
    & (Join-Path $env:SystemRoot 'sysnative\WindowsPowerShell\v1.0\powershell.exe') @a
    exit $LASTEXITCODE
}
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Join-Path $env:ProgramData 'Sluse'
$installed = Join-Path $root 'sluse.json'
$log = Join-Path $env:SystemRoot 'Temp\Sluse-msi.log'
function Deployment($file) {
    try { (Get-Content -Raw -LiteralPath $file | ConvertFrom-Json).deployment } catch { $null }
}
function Msi([string[]]$arguments) {
    (Start-Process -FilePath $Msiexec -ArgumentList $arguments -Wait -PassThru).ExitCode
}
if ($Uninstall) {
    # The deployment's config, its device half, its detection value, then
    # Sluse itself, whose uninstall removes the boxes and the data directory.
    # Sluse Artifacts stay (D-031).
    $code = (Get-ItemProperty -Path $RegistryKey -ErrorAction SilentlyContinue).ProductCode
    Remove-Item $installed, (Join-Path $root 'sluse.device.json') -Force -ErrorAction SilentlyContinue
    Remove-Item $RegistryKey -Recurse -Force -ErrorAction SilentlyContinue
    if (-not $code) { $code = (Get-Content -Raw -LiteralPath (Join-Path $here 'package.json') | ConvertFrom-Json).productCode }
    if (-not (Test-Path -LiteralPath (Join-Path $Products $code))) { exit 0 }
    $r = Msi @('/x', $code, '/qn', '/norestart', '/l*v', "`"$log`"")
    if ($r -eq 1605) { exit 0 }  # not installed after all
    exit $r
}
$package = Join-Path $here 'sluse.json'
$meta = Get-Content -Raw -LiteralPath (Join-Path $here 'package.json') | ConvertFrom-Json
$new = Deployment $package
if (-not $new.id) { throw "$package names no deployment; publish it again from Sluse Admin" }
$old = if (Test-Path -LiteralPath $installed) { Deployment $installed } else { $null }
if ($old.id -and $old.id -ne $new.id) {
    if ($old.name -and $old.name -eq $new.name) {
        # The likelier story when the names match (L1, 2026-10-05), first:
        # bare ids read as version hashes, and the refusal as an update refused.
        [Console]::Error.WriteLine("Same name '$($new.name)', different deployment: the installed one is id " +
            "$($old.id), this package is id $($new.id). It was saved as a new deployment, not as the next " +
            "revision of the installed one. Save it again in Sluse Admin over the installed deployment's " +
            "saved file, which keeps its id. One deployment per device.")
    } else {
        [Console]::Error.WriteLine("This device already runs the Sluse deployment '$($old.name)' (id $($old.id)); " +
            "this package is the deployment '$($new.name)' (id $($new.id)). One deployment per device: " +
            "uninstall the other one first, or take this device out of one of the two groups.")
    }
    exit 2
}
# Sluse itself with "Sluse on this computer", unless this very build is installed with
# it: a new revision with the same MSI changes the config alone. ADDLOCAL
# adds the device half where an admin installed Sluse Admin alone from the
# same build (L1, 2026-10-05). ADDLOCAL also stops MajorUpgrade carrying
# the old build's features over, so Sluse Admin is named when it is there:
# its shortcut's key, which only its feature writes (D-045 point 5).
$msiExit = 0
$have = (Test-Path -LiteralPath (Join-Path $Products $meta.productCode)) -and (Test-Path -LiteralPath $Device)
if (-not $have) {
    $admin = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Sluse\Shortcuts' -ErrorAction SilentlyContinue).SluseAdmin
    $features = if ($admin) { 'Device,Admin' } else { 'Device' }
    $msiExit = Msi @('/i', "`"$(Join-Path $here 'Sluse.msi')`"", "ADDLOCAL=$features", '/qn', '/norestart', '/l*v', "`"$log`"")
    if ($msiExit -ne 0 -and $msiExit -ne 3010) {
        [Console]::Error.WriteLine("Sluse.msi exited $msiExit; its log is $log")
        exit $msiExit
    }
}
New-Item -ItemType Directory -Force $root | Out-Null
Copy-Item $package $root -Force
# The tenant key an older package installed, which nothing reads any more.
Remove-Item (Join-Path $root 'entra') -Recurse -Force -ErrorAction SilentlyContinue
# The same ACL the service takes at its start (winsys::protect_root), in case
# it is not running yet: the folder's whole descriptor replaced from the
# service's own SDDL, so no entry the folder's creator had survives, and its
# children inherit it. Ownership goes first, by SID since the names are
# localised, while this caller still has access. **The folder and the files
# this script writes, never everything under it:** a box's disks carry
# Hyper-V's own grant to the VM's account, which a reset of the whole tree
# removed, and the box no longer started ("Account does not have permission
# to open attachment ... home.vhdx", L1, 2026-10-06). An explicit entry on a
# child survives the folder's new ACL.
icacls $root /setowner '*S-1-5-32-544' /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls $root /setowner exited $LASTEXITCODE" }
$sd = New-Object System.Security.AccessControl.DirectorySecurity
$sd.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)', 'Owner, Access')
[System.IO.Directory]::SetAccessControl($root, $sd)
icacls $installed /setowner '*S-1-5-32-544' /Q | Out-Null
icacls $installed /reset /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls $installed /reset exited $LASTEXITCODE" }
New-Item -Path $RegistryKey -Force | Out-Null
Set-ItemProperty -Path $RegistryKey -Name Id -Value $new.id
Set-ItemProperty -Path $RegistryKey -Name Revision -Value ([int]$new.revision) -Type DWord
Set-ItemProperty -Path $RegistryKey -Name ProductCode -Value $meta.productCode
Set-ItemProperty -Path $RegistryKey -Name ConfigVersion -Value (Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash.ToLowerInvariant()
Set-ItemProperty -Path $RegistryKey -Name PackageVersion -Value $meta.packageVersion
# Before Hyper-V's restart (3010) the service may not come back up; the
# restart starts it with this config either way.
if (Get-Service Sluse -ErrorAction SilentlyContinue) {
    if ($msiExit -eq 3010) { Restart-Service Sluse -ErrorAction SilentlyContinue } else { Restart-Service Sluse }
}
exit $msiExit
"#;

fn uuid() -> Result<String, String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| e.to_string())?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: String = b.iter().map(|x| format!("{x:02x}")).collect();
    Ok(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

/// Standard base64, padded or not; `None` for anything else.
pub(crate) fn base64_decode(s: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let value = |c: u8| -> Option<u32> { TABLE.iter().position(|&t| t == c).map(|i| i as u32) };
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut acc = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            acc |= value(b)? << (18 - 6 * i);
        }
        for i in 0..chunk.len() - 1 {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    Some(out)
}

/// Standard base64, padded.
pub(crate) fn base64(b: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::stand_in::{start as stand_in, TENANT};

    fn options(base: &str, out: &Path) -> Options {
        // An MSI to carry: its bytes are copied, and only Windows reads them.
        let msi = out.with_extension("msi");
        std::fs::write(&msi, b"an MSI").unwrap();
        let info = crate::intune::Msi { product_code: "{11111111-2222-3333-4444-555555555555}".into(), version: "0.0.1".into() };
        Options {
            out: out.to_owned(),
            msi: MsiFile { path: msi, info },
            site: "https://contoso.sharepoint.com/sites/Team".into(),
            library: "Documents".into(),
            source_name: "spo".into(),
            scopes: vec!["in-scope".into()],
            client_id: GRAPH_CLI_CLIENT.into(),
            login: base.to_owned(),
            graph: format!("{base}/v1.0"),
        }
    }

    #[tokio::test]
    async fn setup_makes_the_tenant_once_and_a_rerun_changes_nothing() {
        let (base, t) = stand_in().await;
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tenant");
        let http = reqwest::Client::new();
        let token = sign_in(&http, &options(&base, &out), &mut |_| {}).await.unwrap();
        assert_eq!(tenant_of(&token).unwrap(), TENANT);

        let first = setup(&http, token.clone(), &options(&base, &out)).await.unwrap();
        assert_eq!(first.created.len(), 2, "one application, one service principal: {:?}", first.created);
        let gate = t.lock().unwrap().apps[0].clone();
        // D-036: a public client, the native redirect, no credential, no API.
        assert_eq!(gate["isFallbackPublicClient"], true);
        assert_eq!(gate["publicClient"]["redirectUris"][0], sluse_proto::wire::NATIVE_REDIRECT);
        assert_eq!(gate["keyCredentials"], json!([]));
        assert_eq!(gate["identifierUris"], json!([]));
        assert_eq!(gate["optionalClaims"]["idToken"][0]["name"], "onprem_sid", "D-057");
        assert_eq!(gate["requiredResourceAccess"][0]["resourceAccess"].as_array().unwrap().len(), 5);
        let config = sluse_proto::config::load_authored(&std::fs::read(out.join("sluse.json")).unwrap()).unwrap();
        let entra = config.entra.as_ref().unwrap();
        assert_eq!(entra.client_id, first.gate_app);
        assert_eq!(config.sources[0].scope, ["in-scope"], "--scope reaches the config");
        assert!(config.deployment.is_some(), "setup names the deployment");
        let egress = config.egress.as_ref().expect("setup writes the box's way out");
        assert!(!egress.allows("contoso.sharepoint.com"), "no SharePoint on the box's list (D-046)");
        assert!(egress.allows("api.anthropic.com") && egress.allows("api.openai.com") && egress.allows("pypi.org"));
        assert!(!egress.allows("upload.pypi.org"), "PyPI's upload host stays out (D-026)");
        assert!(out.join(SCRIPT).is_file() && !out.join("entra").exists());
        // One package (D-043): the MSI and what detection compares beside it.
        assert_eq!(std::fs::read(out.join(MSI)).unwrap(), b"an MSI");
        let meta: Value = serde_json::from_slice(&std::fs::read(out.join("package.json")).unwrap()).unwrap();
        let authored = std::fs::read(out.join("sluse.json")).unwrap();
        assert_eq!(meta["packageVersion"], package_version(&options(&base, &out).msi.info, &authored));
        assert_eq!(meta["packageVersion"], first.version);
        #[cfg(unix)]
        let mode = |p: &Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        };
        #[cfg(unix)]
        {
            // The package is closed to everyone but the account running setup.
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(mode(&out), 0o700);
            // And an older setup's open folder is closed by a rerun.
            std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o755)).unwrap();
        }

        // Again: nothing made.
        let second = setup(&http, token, &options(&base, &out)).await.unwrap();
        #[cfg(unix)]
        assert_eq!(mode(&out), 0o700);
        assert!(second.created.is_empty(), "{:?}", second.created);
        assert_eq!(t.lock().unwrap().apps.len(), 1);
    }

    /// Review R-10: an app an employee registered under Sluse's name first.
    /// Adopted, and stripped of everything that let its owner use it: the
    /// owner, the secret, the federated credential, the web redirect.
    #[tokio::test]
    async fn an_app_someone_else_made_under_the_name_is_stripped_before_consent() {
        let (base, t) = stand_in().await;
        t.lock().unwrap().apps.push(json!({
            "id": "object-0", "appId": "00000000-0000-4000-8000-000000000000", "displayName": GATE_NAME,
            "signInAudience": "AzureADMultipleOrgs",
            "owners": [{ "id": "employee" }],
            "passwordCredentials": [{ "keyId": "secret-1" }],
            "federatedIdentityCredentials": [{ "id": "fic-1" }],
            "web": { "redirectUris": ["https://phish.example/cb"] },
        }));
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tenant");
        let http = reqwest::Client::new();
        let token = sign_in(&http, &options(&base, &out), &mut |_| {}).await.unwrap();
        let done = setup(&http, token, &options(&base, &out)).await.unwrap();
        let said = done.created.join("; ");
        assert!(said.contains("owner employee") && said.contains("secret-1") && said.contains("fic-1"), "{said}");
        let t = t.lock().unwrap();
        let app = &t.apps[0];
        assert_eq!(app["owners"], json!([]));
        assert_eq!(app["passwordCredentials"], json!([]));
        assert_eq!(app["federatedIdentityCredentials"], json!([]));
        assert_eq!(app["web"]["redirectUris"], json!([]));
        assert_eq!(app["signInAudience"], "AzureADMyOrg");
    }

    /// A tenant an older setup made: OBO's scope and pre-authorisation, the
    /// certificate, the entry app, and the key in the package. All of it goes.
    #[tokio::test]
    async fn a_rerun_over_an_obo_tenant_removes_the_credential_and_the_entry_app() {
        let (base, t) = stand_in().await;
        {
            let mut t = t.lock().unwrap();
            t.apps.push(json!({
                "id": "object-0", "appId": "00000000-0000-4000-8000-000000000000", "displayName": GATE_NAME,
                "identifierUris": ["api://00000000-0000-4000-8000-000000000000"],
                "api": { "oauth2PermissionScopes": [{ "id": "s", "value": "access_as_user", "isEnabled": true }],
                         "preAuthorizedApplications": [{ "appId": "entry", "delegatedPermissionIds": ["s"] }] },
                "keyCredentials": [{ "customKeyIdentifier": "old" }],
            }));
            t.apps.push(json!({ "id": "object-1", "appId": "entry", "displayName": ENTRY_NAME }));
        }
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("tenant");
        std::fs::create_dir_all(out.join("entra")).unwrap();
        std::fs::write(out.join("entra/entra.key"), "old key").unwrap();
        let http = reqwest::Client::new();
        let token = sign_in(&http, &options(&base, &out), &mut |_| {}).await.unwrap();
        let done = setup(&http, token, &options(&base, &out)).await.unwrap();
        let said = done.created.join("; ");
        assert!(said.contains("access_as_user") && said.contains("certificate") && said.contains(ENTRY_NAME), "{said}");
        let t = t.lock().unwrap();
        assert_eq!(t.apps.len(), 1, "the entry app is deleted");
        assert_eq!(t.apps[0]["keyCredentials"], json!([]));
        assert_eq!(t.apps[0]["api"]["oauth2PermissionScopes"], json!([]));
        assert!(!out.join("entra").exists(), "the old key leaves the package");
    }

    #[test]
    fn a_save_over_a_deployments_file_continues_it_and_a_new_file_is_new() {
        let text = |id: &str, rev: u32| {
            format!(r#"{{"schemaVersion":3,"deployment":{{"id":"{id}","name":"Pilot","revision":{rev}}},"sources":[{{"name":"fixture","kind":{{"type":"local-folder","address":{{"root":"C:\\\\fixture"}}}},"scope":[],"sensitivity":2}}],"volume":{{"admissions":25,"windowSeconds":60}}}}"#)
        };
        let fresh = text("new-id", 1);
        // A new file, or one with no deployment: as it is.
        assert_eq!(continue_deployment(None, &fresh).unwrap(), (fresh.clone(), None));
        // The same deployment, opened and saved: as it is.
        let opened = text("old-id", 4);
        assert_eq!(continue_deployment(Some(text("old-id", 3).as_bytes()), &opened).unwrap(), (opened.clone(), None));
        // Over another deployment's file: that deployment, its next revision.
        let (out, said) = continue_deployment(Some(text("old-id", 3).as_bytes()), &fresh).unwrap();
        let d = sluse_proto::config::load_authored(out.as_bytes()).unwrap().deployment.unwrap();
        assert_eq!((d.id.as_str(), d.revision, d.name.as_str()), ("old-id", 4, "Pilot"));
        assert!(said.unwrap().contains("revision 4"));
    }

    /// `sluse admin package` and Save (D-043), with the config CI's install
    /// job packages: the folder and the `.intunewin` beside the file.
    #[test]
    fn save_packages_a_saved_config_and_refuses_one_without_a_deployment() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("sluse-ci.json");
        let msi = options("http://unused", &dir.path().join("x")).msi;
        let text = r#"{"schemaVersion":3,"deployment":{"id":"ci-dep","name":"CI","revision":1},"sources":[{"name":"fixture","kind":{"type":"local-folder","address":{"root":"C:\\fixture"}},"scope":[],"sensitivity":2}],"volume":{"admissions":25,"windowSeconds":60}}"#;
        let saved = save(&config, text, &msi).unwrap();
        assert_eq!(saved.package, dir.path().join("sluse-ci.package"));
        assert!(saved.intunewin.is_file() && saved.package.join(SCRIPT).is_file() && saved.package.join(MSI).is_file());
        assert_eq!(saved.version, package_version(&msi.info, text.as_bytes()));

        let none = text.replace(r#""deployment":{"id":"ci-dep","name":"CI","revision":1},"#, "");
        assert!(save(&config, &none, &msi).unwrap_err().contains("names no deployment"));
    }

    #[test]
    fn two_applications_of_one_name_is_a_persons_call_and_base64_is_standard() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
        assert_eq!(base64_decode(&base64(b"\x00\xff\x10hello")).unwrap(), b"\x00\xff\x10hello");
        let u = uuid().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
    }

    /// The package folder's ACL, on a folder that inherited something wider
    /// first, as `C:\SluseTenant` did on L1: SYSTEM, Administrators and the
    /// account running setup, on the folder and on a file already in it.
    #[cfg(windows)]
    #[test]
    fn the_package_folder_is_closed_to_everyone_else() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = dir.path().join("tenant");
        std::fs::create_dir(&pkg).unwrap();
        std::fs::write(pkg.join("sluse.json"), "x").unwrap();
        let wide = std::process::Command::new("icacls").arg(&pkg).args(["/grant", "*S-1-5-32-545:(OI)(CI)RX"]).output().unwrap();
        assert!(wide.status.success(), "{}", String::from_utf8_lossy(&wide.stdout));

        protect_package(&pkg).unwrap();

        let sids = |p: &Path| {
            let ps = format!(
                "$s = [Security.Principal.SecurityIdentifier]; \
                 ((Get-Acl -LiteralPath '{}').Access | ForEach-Object {{ $_.IdentityReference.Translate($s).Value }} | Sort-Object -Unique) -join ','",
                p.display()
            );
            let o = std::process::Command::new("powershell.exe").args(["-NoProfile", "-Command", &ps]).env_remove("PSModulePath").output().unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_owned()
        };
        let me = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"])
            .output()
            .unwrap();
        let me = String::from_utf8_lossy(&me.stdout).trim().to_owned();
        let mut want = vec!["S-1-5-18".to_owned(), "S-1-5-32-544".to_owned(), me];
        want.sort();
        want.dedup();
        for p in [pkg.clone(), pkg.join("sluse.json")] {
            let mut got: Vec<String> = sids(&p).split(',').map(str::to_owned).collect();
            got.sort();
            assert_eq!(got, want, "{}", p.display());
        }
    }

    /// The package's script, run for real against a stand-in `ProgramData`,
    /// a registry under HKCU and a stand-in msiexec: it once failed on L1
    /// with `icacls` refusing `/setowner` beside `/grant` (2026-09-30), which
    /// nothing had run. The MSI once, 3010 passed on, a revision without the
    /// MSI, a second deployment refused before the MSI, and uninstalled.
    #[cfg(windows)]
    #[test]
    fn the_package_script_installs_protects_and_refuses_a_second_deployment() {
        let pkg = tempfile::tempdir().unwrap();
        let data = tempfile::tempdir().unwrap();
        let reg = format!("HKCU:\\Software\\SluseTest-{}", std::process::id());
        let products = format!("{reg}-products");
        let config = |id: &str, rev: u32| format!(r#"{{"schemaVersion":3,"deployment":{{"id":"{id}","name":"{id} name","revision":{rev}}}}}"#);
        let code = "{11111111-2222-3333-4444-555555555555}";
        let script = pkg.path().join(SCRIPT);
        std::fs::write(&script, INSTALL).unwrap();
        std::fs::write(pkg.path().join(MSI), "not an MSI").unwrap();
        std::fs::write(pkg.path().join("package.json"), format!(r#"{{"productCode":"{code}","msiVersion":"0.0.1","packageVersion":"v1"}}"#)).unwrap();
        // msiexec, stood in: it records its arguments and exits as told.
        let stub = data.path().join("msiexec.cmd");
        let calls = data.path().join("calls.txt");
        // sluse.exe, which only the "Sluse on this computer" feature installs.
        let device = data.path().join("sluse.exe");
        std::fs::write(&stub, "@echo off\r\necho %*>>\"%~dp0calls.txt\"\r\nexit /b %SLUSE_TEST_MSI_EXIT%\r\n").unwrap();
        let run = |extra: &[&str], msi_exit: &str| {
            std::process::Command::new("powershell.exe")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
                .arg(&script)
                .args(["-RegistryKey", &reg, "-Products", &products, "-Msiexec"])
                .arg(&stub)
                .arg("-Device")
                .arg(&device)
                .args(extra)
                .env("ProgramData", data.path())
                .env("SLUSE_TEST_MSI_EXIT", msi_exit)
                .env_remove("PSModulePath")
                .output()
                .unwrap()
        };
        let ps = |cmd: &str| {
            let o = std::process::Command::new("powershell.exe").args(["-NoProfile", "-Command", cmd]).env_remove("PSModulePath").output().unwrap();
            String::from_utf8_lossy(&o.stdout).trim().to_owned()
        };
        let called = || std::fs::read_to_string(&calls).unwrap_or_default().lines().map(str::to_owned).collect::<Vec<_>>();

        // The first install: the MSI, which asks for Hyper-V's restart.
        std::fs::write(pkg.path().join("sluse.json"), config("dep-a", 1)).unwrap();
        let out = run(&[], "3010");
        assert_eq!(out.status.code(), Some(3010), "{}", String::from_utf8_lossy(&out.stderr));
        assert_eq!(called().len(), 1);
        assert!(called()[0].starts_with("/i ") && called()[0].contains("Sluse.msi"), "{:?}", called());
        assert!(called()[0].contains("ADDLOCAL=Device"), "{:?}", called());
        let installed = data.path().join("Sluse").join("sluse.json");
        let hash = sluse_proto::ContentHash::of(&std::fs::read(&installed).unwrap());
        assert_eq!(ps(&format!("(Get-ItemProperty '{reg}').PackageVersion")), "v1", "detection by the package's version");
        assert_eq!(ps(&format!("(Get-ItemProperty '{reg}').ConfigVersion")), hash.as_str());
        assert_eq!(ps(&format!("(Get-ItemProperty '{reg}').ProductCode")), code);

        // A box's disk, with Hyper-V's kind of grant: an explicit entry for
        // one account, which the folder's ACL does not hold. Hyper-V's is the
        // VM's own; Users (S-1-5-32-545) stands in, since a runner without
        // Hyper-V may not map the VMs' SIDs. An install must leave it, or the
        // box does not start (L1, 2026-10-06).
        let disk = data.path().join("Sluse").join("boxes").join("S-1-5-21-1").join("home.vhdx");
        std::fs::create_dir_all(disk.parent().unwrap()).unwrap();
        std::fs::write(&disk, "a disk").unwrap();
        let grant = std::process::Command::new("icacls").arg(&disk).args(["/grant", "*S-1-5-32-545:(F)"]).output().unwrap();
        assert!(grant.status.success(), "{}", String::from_utf8_lossy(&grant.stdout));
        let vm_grant = || {
            ps(&format!(
                "((Get-Acl -LiteralPath '{}').Access | ForEach-Object {{ $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value }}) -contains 'S-1-5-32-545'",
                disk.display()
            )) == "True"
        };
        assert!(vm_grant(), "the grant is there before");

        // That build is installed now, with the device half: a new revision
        // changes the config alone.
        ps(&format!("New-Item -Path '{products}\\{code}' -Force | Out-Null"));
        std::fs::write(&device, "").unwrap();
        std::fs::write(pkg.path().join("sluse.json"), config("dep-a", 2)).unwrap();
        assert!(run(&[], "0").status.success());
        assert_eq!(called().len(), 1, "no msiexec for the same build");
        assert_eq!(ps(&format!("(Get-ItemProperty '{reg}').Revision")), "2");
        assert!(vm_grant(), "an install keeps the box disk's grant to the VM");

        // The same build with Sluse Admin alone (L1, 2026-10-05): the device
        // half is added.
        std::fs::remove_file(&device).unwrap();
        std::fs::write(pkg.path().join("sluse.json"), config("dep-a", 3)).unwrap();
        assert!(run(&[], "0").status.success());
        assert_eq!(called().len(), 2, "msiexec for the missing device half");
        assert!(called()[1].starts_with("/i ") && called()[1].contains("ADDLOCAL=Device"), "{:?}", called());
        std::fs::write(&device, "").unwrap();

        // Another deployment: refused, both named, nothing installed or changed.
        std::fs::write(pkg.path().join("sluse.json"), config("dep-b", 1)).unwrap();
        let refused = run(&[], "0");
        assert_eq!(refused.status.code(), Some(2));
        let said = String::from_utf8_lossy(&refused.stderr);
        assert!(said.contains("dep-a") && said.contains("dep-b"), "{said}");
        assert!(String::from_utf8_lossy(&std::fs::read(&installed).unwrap()).contains("dep-a"));
        assert_eq!(called().len(), 2);

        // Uninstalled: the file, the detection value, then the MSI by its code.
        assert!(run(&["-Uninstall"], "0").status.success());
        assert!(!installed.exists());
        assert_eq!(called().len(), 3);
        assert!(called()[2].starts_with(&format!("/x {code}")), "{:?}", called());
        ps(&format!("Remove-Item '{products}' -Recurse -Force"));
        assert_eq!(run(&[], "0").status.code(), Some(0), "the other deployment, once the first is gone");
        let _ = ps(&format!("Remove-Item '{reg}' -Recurse -Force"));
        let root = data.path().join("Sluse");
        let key = installed.clone();
        assert!(key.is_file());
        // Only SYSTEM and Administrators, by SID whatever the language: not
        // an empty DACL, which nobody could read, and not the creator's entry
        // (this runner's own account). Owned by Administrators. The pwsh 7
        // step's PSModulePath stops Windows PowerShell loading Get-Acl.
        let ps = format!(
            "$a = Get-Acl -LiteralPath '{}'; $s = [Security.Principal.SecurityIdentifier]; \
             ($a.Access | ForEach-Object {{ $_.IdentityReference.Translate($s).Value }} | Sort-Object -Unique) -join ','; \
             $a.GetOwner($s).Value",
            key.display()
        );
        let run = |cmd: &str, args: &[&std::ffi::OsStr]| {
            let o = std::process::Command::new(cmd).args(args).output().unwrap();
            format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
        };
        let acl = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &ps])
            .env_remove("PSModulePath")
            .output()
            .unwrap();
        let (out, err) = (String::from_utf8_lossy(&acl.stdout), String::from_utf8_lossy(&acl.stderr));
        let lines: Vec<&str> = out.lines().map(str::trim).collect();
        // Everything needed to tell a wrong ACL from a runner that cannot read
        // a right one: whether this token's Administrators is enabled or
        // deny-only decides that.
        assert_eq!(
            lines,
            ["S-1-5-18,S-1-5-32-544", "S-1-5-32-544"],
            "stdout: {out}\nstderr: {err}\nicacls root: {}\nicacls key: {}\nwhoami: {}",
            run("icacls", &[root.as_os_str()]),
            run("icacls", &[key.as_os_str()]),
            run("whoami", &["/groups".as_ref()]).lines().filter(|l| l.contains("S-1-5-32-544") || l.contains("Mandatory")).collect::<Vec<_>>().join("\n"),
        );
    }
}

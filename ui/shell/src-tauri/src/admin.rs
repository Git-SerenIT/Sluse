// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Sluse Admin (D-037, D-039 slice 6): the tenant admin's window, a thin
//! layer over `sluse-admin`. Each command is one step of setup; the page
//! (`admin.js`) is the screens.
//!
//! The admin's Graph token is held here, in memory, for as long as the
//! window is open, and never written anywhere.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::Value;
use sluse_admin::graph::Graph;
use tauri::{Emitter, State};

const LOGIN: &str = "https://login.microsoftonline.com";
const GRAPH: &str = "https://graph.microsoft.com/v1.0";
/// Intune's Win32 apps and their relationships are on beta.
const GRAPH_BETA: &str = "https://graph.microsoft.com/beta";

#[derive(Default)]
pub struct Admin {
    http: sluse_admin::reqwest::Client,
    token: std::sync::Mutex<Option<String>>,
    registered: std::sync::Mutex<Option<sluse_admin::setup::Registered>>,
    /// The account signed in, for "you cannot open its site as …".
    account: std::sync::Mutex<String>,
    /// Signed out in this window: the next sign-in offers Microsoft's
    /// account picker instead of signing the same account in again.
    picked: AtomicBool,
    /// Set by closing during a publish (Q81).
    stop: AtomicBool,
}

/// Unsaved work or a publish under way, as the page says: X then asks.
static GUARD: AtomicBool = AtomicBool::new(false);

impl Admin {
    fn graph(&self, base: &str) -> Result<Graph, String> {
        let token = self.token.lock().unwrap_or_else(|p| p.into_inner()).clone().ok_or("not signed in")?;
        Ok(Graph::new(&self.http, base, token))
    }

    fn sp(&self) -> Result<String, String> {
        self.registered
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .map(|r| r.service_principal.clone())
            .ok_or_else(|| "Sluse's app is not registered yet".into())
    }
}

/// Sign in as the tenant's admin, as Graph Command Line Tools: the tenant
/// id from the token, the account, and the organisation's name when Graph
/// gives it (Q43, Q80). A tenant that blocks that app uses the CLI's
/// `--client-id`.
#[tauri::command]
pub async fn admin_sign_in(app: tauri::AppHandle, admin: State<'_, Admin>) -> Result<Value, String> {
    let (req, view) = sluse_admin::signin::request(LOGIN, sluse_admin::setup::GRAPH_CLI_CLIENT)?;
    let pick = admin.picked.load(Ordering::Relaxed);
    let code = {
        let (req, view) = (req.clone(), view.clone());
        tauri::async_runtime::spawn_blocking(move || crate::sign_in_code(&app, &req, &view, pick))
            .await
            .map_err(|e| e.to_string())??
    };
    let token = sluse_admin::signin::redeem(&admin.http, &view, &req, &code).await?;
    let tenant = sluse_admin::setup::tenant_of(&token)?;
    *admin.token.lock().unwrap_or_else(|p| p.into_inner()) = Some(token);
    let who = admin_whoami(admin).await.unwrap_or_default();
    Ok(serde_json::json!({ "tenant": tenant, "account": who["account"], "tenantName": who["tenantName"] }))
}

/// The account and the organisation's name, again: "Read the name again".
#[tauri::command]
pub async fn admin_whoami(admin: State<'_, Admin>) -> Result<Value, String> {
    let (account, name) = sluse_admin::roles::whoami(&admin.graph(GRAPH)?).await?;
    account.clone_into(&mut admin.account.lock().unwrap_or_else(|p| p.into_inner()));
    Ok(serde_json::json!({ "account": account, "tenantName": name }))
}

/// Drop the token, and the sign-in's profile with it (Q82): the profile at
/// the next start, while its browser holds it open; until then each sign-in
/// opens Microsoft's account picker.
#[tauri::command]
pub fn admin_sign_out(admin: State<'_, Admin>) {
    *admin.token.lock().unwrap_or_else(|p| p.into_inner()) = None;
    *admin.registered.lock().unwrap_or_else(|p| p.into_inner()) = None;
    admin.picked.store(true, Ordering::Relaxed);
    #[cfg(windows)]
    crate::signin::clear_profile();
}

/// "Sign in as someone else" (Q82): no quiet try, Microsoft's account picker.
#[tauri::command]
pub fn admin_pick_account(admin: State<'_, Admin>) {
    admin.picked.store(true, Ordering::Relaxed);
}

/// What the account may do, and who else is needed for the rest.
#[tauri::command]
pub async fn admin_roles(admin: State<'_, Admin>) -> Result<Value, String> {
    let r = sluse_admin::roles::of_me(&admin.graph(GRAPH)?).await?;
    Ok(serde_json::json!({
        "names": r.names, "register": r.register, "consent": r.consent, "publish": r.publish,
        "othersNeeded": r.others_needed(),
    }))
}

#[tauri::command]
pub async fn admin_register(admin: State<'_, Admin>) -> Result<sluse_admin::setup::Registered, String> {
    let r = sluse_admin::setup::register(&admin.graph(GRAPH)?).await?;
    *admin.registered.lock().unwrap_or_else(|p| p.into_inner()) = Some(r.clone());
    Ok(r)
}

/// The scopes admin consent does not cover yet; empty is granted.
#[tauri::command]
pub async fn admin_consent_missing(admin: State<'_, Admin>) -> Result<Vec<String>, String> {
    sluse_admin::consent::missing(&admin.graph(GRAPH)?, &admin.sp()?).await
}

#[tauri::command]
pub async fn admin_groups(admin: State<'_, Admin>, query: String) -> Result<Vec<sluse_admin::browse::Group>, String> {
    sluse_admin::browse::groups(&admin.graph(GRAPH)?, &query).await
}

#[tauri::command]
pub async fn admin_assign(admin: State<'_, Admin>, group: String) -> Result<Value, String> {
    let a = sluse_admin::assign::require(&admin.graph(GRAPH)?, &admin.sp()?, &group).await?;
    Ok(serde_json::json!({ "changed": a.changed, "warnings": a.warnings }))
}

/// The groups assigned to Sluse's app, as Entra holds them (Q46).
#[tauri::command]
pub async fn admin_assigned(admin: State<'_, Admin>) -> Result<Vec<sluse_admin::assign::Group>, String> {
    sluse_admin::assign::assigned(&admin.graph(GRAPH)?, &admin.sp()?).await
}

#[tauri::command]
pub async fn admin_unassign(admin: State<'_, Admin>, id: String) -> Result<(), String> {
    sluse_admin::assign::remove(&admin.graph(GRAPH)?, &admin.sp()?, &id).await
}

#[tauri::command]
pub async fn admin_sites(admin: State<'_, Admin>, query: String) -> Result<Vec<sluse_admin::browse::Site>, String> {
    sluse_admin::browse::sites(&admin.graph(GRAPH)?, &query).await
}

/// Every Team's site, counted to the page as `teams-progress` (Q47), and
/// the Teams left out, each with its reason.
#[tauri::command]
pub async fn admin_teams(app: tauri::AppHandle, admin: State<'_, Admin>) -> Result<Value, String> {
    let account = admin.account.lock().unwrap_or_else(|p| p.into_inner()).clone();
    let tell = |read: usize, of: usize| {
        let _ = app.emit("teams-progress", (read, of));
    };
    let (sites, skipped) = sluse_admin::browse::teams(&admin.graph(GRAPH)?, &account, &tell).await?;
    Ok(serde_json::json!({ "sites": sites, "skipped": skipped }))
}

#[tauri::command]
pub async fn admin_libraries(admin: State<'_, Admin>, site: String) -> Result<Vec<sluse_admin::browse::Library>, String> {
    sluse_admin::browse::libraries(&admin.graph(GRAPH)?, &site).await
}

#[tauri::command]
pub async fn admin_folders(
    admin: State<'_, Admin>,
    drive: String,
    item: Option<String>,
) -> Result<Vec<sluse_admin::browse::Folder>, String> {
    sluse_admin::browse::folders(&admin.graph(GRAPH)?, &drive, item.as_deref()).await
}

#[tauri::command]
pub fn admin_share_folders(root: String, rel: String) -> Result<Vec<sluse_admin::browse::Folder>, String> {
    sluse_admin::browse::share_folders(std::path::Path::new(&root), &rel).map_err(|e| format!("{root}: {e}"))
}

#[tauri::command]
pub fn admin_catalog() -> sluse_admin::catalog::Catalog {
    sluse_admin::catalog::Catalog::shipped()
}

/// The page's choices as the authored file: its text, or why the box would
/// refuse it, and the warnings.
#[tauri::command]
pub fn admin_author(authored: Value) -> Result<Value, String> {
    let a: sluse_proto::Authored = serde_json::from_value(authored).map_err(|e| e.to_string())?;
    let d = sluse_admin::author::author(&a, &sluse_admin::catalog::Catalog::shipped())?;
    Ok(serde_json::json!({ "text": d.text, "warnings": d.warnings }))
}

#[tauri::command]
pub fn admin_open(path: PathBuf) -> Result<sluse_proto::Authored, String> {
    sluse_admin::author::open(&path)
}

#[tauri::command]
pub fn admin_diff(old: Value, new: Value) -> Result<Vec<String>, String> {
    let parse = |v: Value| serde_json::from_value::<sluse_proto::Authored>(v).map_err(|e| e.to_string());
    Ok(sluse_admin::author::diff(&parse(old)?, &parse(new)?))
}

/// Save the authored file, write the deployment's package beside it with
/// `msi` in it, and wrap the package as one `.intunewin` (D-043; D-037
/// point 2's file route). The paths and what the app's settings need.
#[tauri::command]
pub async fn admin_save(config: PathBuf, text: String, msi: PathBuf) -> Result<Value, String> {
    // Reading and encrypting the MSI takes seconds: off the main thread.
    tauri::async_runtime::spawn_blocking(move || -> Result<Value, String> {
        let msi = sluse_admin::setup::MsiFile::read(&msi)?;
        let (text, continued) = sluse_admin::setup::continue_deployment(std::fs::read(&config).ok().as_deref(), &text)?;
        // The package first: if it cannot be written, the configuration
        // file is left as it was.
        let s = sluse_admin::setup::save(&config, &text, &msi)?;
        std::fs::write(&config, &text).map_err(|e| format!("{}: {e}", config.display()))?;
        Ok(serde_json::json!({
            "config": config, "package": s.package, "intunewin": s.intunewin, "script": sluse_admin::setup::SCRIPT,
            "packageVersion": s.version, "msiVersion": msi.info.version, "text": text, "continued": continued,
        }))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// The MSI the admin picked, as Windows Installer reads it.
#[tauri::command]
pub async fn admin_msi(path: PathBuf) -> Result<Value, String> {
    let m = tauri::async_runtime::spawn_blocking(move || sluse_admin::setup::MsiFile::read(&path)).await.map_err(|e| e.to_string())??;
    Ok(serde_json::json!({ "path": m.path, "version": m.info.version, "productCode": m.info.product_code }))
}

/// Sluse's app's API permissions in the Azure portal, in the browser. The
/// address is made here, from an application id, never taken from the page.
/// An MCP server as a source (D-071 slice 6), step 1: its scope on Sluse's
/// registration beside Graph's, and whether admin consent covers it yet.
#[tauri::command]
pub async fn admin_mcp_require(admin: State<'_, Admin>, scope: String) -> Result<Value, String> {
    let g = admin.graph(GRAPH)?;
    let (resource, added) = sluse_admin::mcp::require(&g, &scope).await?;
    let consented = sluse_admin::mcp::consented(&g, &admin.sp()?, &resource).await?;
    Ok(serde_json::json!({ "resource": resource, "added": added, "consented": consented }))
}

/// Step 2, again after the admin granted it in the portal.
#[tauri::command]
pub async fn admin_mcp_consented(admin: State<'_, Admin>, scope: String) -> Result<bool, String> {
    let g = admin.graph(GRAPH)?;
    let resource = sluse_admin::mcp::resource(&g, &scope).await?;
    sluse_admin::mcp::consented(&g, &admin.sp()?, &resource).await
}

/// Step 3: the server asked once, with a token Sluse's own app (`client`)
/// gets for the scope as the admin, which is the token a box's Gate Core
/// will ask for as each user. Its version and its tools.
#[tauri::command]
pub async fn admin_mcp_probe(
    app: tauri::AppHandle,
    admin: State<'_, Admin>,
    url: String,
    scope: String,
    client: String,
) -> Result<sluse_admin::mcp::Probe, String> {
    let token = admin.token.lock().unwrap_or_else(|p| p.into_inner()).clone().ok_or("not signed in")?;
    let tenant = sluse_admin::setup::tenant_of(&token)?;
    let req = sluse_proto::pipe::SignInRequest::with_redirect(sluse_proto::wire::NATIVE_REDIRECT)?;
    let view = sluse_proto::SignInView {
        authority: format!("{LOGIN}/{tenant}"),
        client_id: client,
        scope: format!("{scope} offline_access openid profile"),
    };
    let code = {
        let (req, view) = (req.clone(), view.clone());
        tauri::async_runtime::spawn_blocking(move || crate::sign_in_code(&app, &req, &view, false))
            .await
            .map_err(|e| e.to_string())??
    };
    let server_token = sluse_admin::signin::redeem(&admin.http, &view, &req, &code).await?;
    sluse_admin::mcp::probe(&admin.http, &url, &server_token).await
}

/// The AI providers' own connectors in the tenant (D-071 slice 7).
#[tauri::command]
pub async fn admin_connectors(admin: State<'_, Admin>) -> Result<sluse_admin::connectors::Report, String> {
    sluse_admin::connectors::check(&admin.graph(GRAPH)?).await
}

/// Turn sign-in off for one provider's app, the admin's choice. Only an app
/// the check just found: the page names it, this makes sure it is one.
#[tauri::command]
pub async fn admin_connector_block(admin: State<'_, Admin>, app_id: Option<String>, service_principal: Option<String>) -> Result<String, String> {
    let g = admin.graph(GRAPH)?;
    let report = sluse_admin::connectors::check(&g).await?;
    let found = report
        .findings
        .iter()
        .find(|f| f.can_block && f.app_id == app_id && f.service_principal == service_principal)
        .ok_or("that is not one of the providers' apps the check found")?;
    sluse_admin::connectors::block(&g, found.app_id.as_deref(), found.service_principal.as_deref()).await
}

#[tauri::command]
pub fn admin_open_portal(app_id: String) -> Result<(), String> {
    if app_id.len() != 36 || !app_id.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
        return Err("not an application id".into());
    }
    std::process::Command::new("explorer.exe")
        .arg(format!("https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/{app_id}"))
        .spawn()
        .map(drop)
        .map_err(|e| format!("the browser: {e}"))
}

/// The admin said to close, after the page asked.
#[tauri::command]
pub fn admin_close(window: tauri::Window) {
    GUARD.store(false, Ordering::Relaxed);
    let _ = window.destroy();
}

/// What a package folder holds, before it is published (Q50).
#[tauri::command]
pub fn admin_package(package: PathBuf) -> Result<Value, String> {
    let (d, msi, _) = sluse_admin::intune::package_info(&package)?;
    Ok(serde_json::json!({ "deployment": d, "msiVersion": msi.version }))
}

/// Publish straight to Intune (D-037 point 2): a saved package folder, one
/// app (D-043), to `group`. Each step goes to the page as `publish-step`.
#[tauri::command]
pub async fn admin_publish(app: tauri::AppHandle, admin: State<'_, Admin>, package: PathBuf, group: String) -> Result<Value, String> {
    let g = admin.graph(GRAPH_BETA)?;
    admin.stop.store(false, Ordering::Relaxed);
    let tell = |v: Value| {
        let _ = app.emit("publish-step", v);
    };
    let p = sluse_admin::intune::publish_files(&g, &admin.http, &package, &group, Some(&admin.stop), Some(&tell)).await?;
    Ok(serde_json::json!({ "app": p.app, "changed": p.changed, "warnings": p.warnings }))
}

/// Closing during a publish (Q81): the upload stops and deletes its app.
#[tauri::command]
pub fn admin_stop_publish(admin: State<'_, Admin>) {
    admin.stop.store(true, Ordering::Relaxed);
}

/// "Try deleting it again", after a failed upload's delete failed (Q53).
#[tauri::command]
pub async fn admin_delete_app(admin: State<'_, Admin>, id: String) -> Result<(), String> {
    sluse_admin::intune::delete_app(&admin.graph(GRAPH_BETA)?, &id).await
}

/// The page says whether X has work to lose.
#[tauri::command]
pub fn admin_guard(on: bool) {
    GUARD.store(on, Ordering::Relaxed);
}

/// X with work to lose: the page asks, with Goes and Stays (D-034 point 5),
/// and closes the window itself once the admin says so.
pub fn close_requested(window: &tauri::Window, event: &tauri::WindowEvent) {
    if let tauri::WindowEvent::CloseRequested { api, .. } = event {
        if GUARD.load(Ordering::Relaxed) {
            api.prevent_close();
            let _ = window.emit("close-requested", ());
        }
    }
}

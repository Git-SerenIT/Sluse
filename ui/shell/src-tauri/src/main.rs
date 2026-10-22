// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The Sluse host shell (D-025): the shortcut opens this window, the window
//! asks the service to open the user's box, and then shows the box.
//!
//! **No file channel, by construction.** The viewer is noVNC, which has none;
//! dropping a file on the window is switched off (`dragDropEnabled`); the
//! clipboard carries text only, both ways, which is the documented channel
//! (D-025 point 3). That is a host-side guarantee: nothing in the box can
//! turn it on.
//!
//! Closing the window asks first (D-034 point 5): close the box, or leave it
//! and its sign-in running, which S-8 1b showed a reconnect finds. "Close the
//! box" stops both, says "Closed", and then ends the window.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod admin;
mod edges;
mod pipe;
#[cfg(windows)]
mod signin;

use pipe::Failure;
use serde::Serialize;
use sluse_proto::pipe::{BoxState, HostSignIn, Phase, PipeEvent, PipeRequest, Theme, VNC_USER};
use tauri::{Emitter, Manager};

#[derive(Serialize)]
struct Ready {
    vnc: String,
    username: &'static str,
    password: String,
    /// A newer base exists; a reset would give this box it (D-026 point 1:
    /// offered, never applied).
    update: bool,
    /// The device's last base build failed, in words for the user.
    problem: Option<String>,
    /// Text may be copied out of the box (D-038 point 7).
    copy_out: bool,
    /// The config changed since this box last opened (D-038 point 4).
    config_changed: bool,
    /// Which parts: `sources`, `egress`, `settings` (D-045 point 3).
    config_changes: Vec<String>,
    /// The config admits the user's Sluse Inputs (D-054).
    inputs: bool,
    /// The config reads the user's OneDrive `Sluse` folder (D-054).
    onedrive: bool,
    /// The config has file shares, read as the Windows user (Q8).
    shares: bool,
}

/// What the bar and Copy details say around the box (Q8, Q24, Q30), asked
/// at each open: who Sluse reads as, and what IT needs to find this box.
#[derive(Serialize)]
struct Facts {
    version: String,
    device: String,
    windows_user: String,
    /// The keyboard layout's language when the box has no layout for it
    /// and types US English instead (Q30); empty where Windows does not
    /// name it.
    keyboard_fallback: Option<String>,
    /// The config has an `entra` block: Sluse reads as the work account.
    entra: bool,
    /// Who the running box is signed in as.
    user: Option<String>,
    signed_out: bool,
    vm: Option<String>,
    dir: Option<String>,
}

#[tauri::command(async)]
fn facts(app: tauri::AppHandle) -> Facts {
    let env = |k| std::env::var(k).unwrap_or_default();
    let (entra, user, signed_out, vm, dir) = match pipe::ask(&PipeRequest::Status, |_| {}) {
        Ok(PipeEvent::State { sign_in, user, signed_out, vm, dir, .. }) => (sign_in.is_some(), user, signed_out, vm, dir),
        _ => (false, None, false, None, None),
    };
    Facts {
        version: app.package_info().version.to_string(),
        device: env("COMPUTERNAME"),
        windows_user: format!("{}\\{}", env("USERDOMAIN"), env("USERNAME")),
        keyboard_fallback: pipe::keyboard_fallback(),
        entra,
        user,
        signed_out,
        vm,
        dir,
    }
}

/// Microsoft's sign-in window, brought forward when the main window says
/// it is waiting for it (Q18): it may have opened behind.
#[tauri::command]
fn show_sign_in(app: tauri::AppHandle) {
    for (label, w) in app.webview_windows() {
        if label.starts_with("signin-") && w.is_visible().unwrap_or(false) {
            let _ = w.unminimize();
            let _ = w.set_focus();
        }
    }
}

/// What the main window shows, as the page says: the box on screen
/// (`RUNNING`), a build under way (`BUILDING`), or anything else. A second
/// X closes the box with the window while it is on screen (Q29), and during
/// a build quits into the tray, where the build's progress goes on (Q26).
static WINDOW: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
const RUNNING: u8 = 1;
const BUILDING: u8 = 2;

#[tauri::command]
fn window_state(state: String) {
    let s = match state.as_str() {
        "running" => RUNNING,
        "building" => BUILDING,
        _ => 0,
    };
    WINDOW.store(s, std::sync::atomic::Ordering::SeqCst);
}

/// Quit during an open (Q26, Q75): the service is told to leave the box
/// closed. During a build the window goes and the process stays in the
/// tray until the build is done; otherwise the process ends.
#[tauri::command]
fn quit_open(app: tauri::AppHandle, building: bool) {
    pipe::tell(&PipeRequest::Quit);
    if building {
        edges::leave(app);
    } else {
        app.exit(0);
    }
}

/// The host's sign-in (D-036), when the tenant's config has an `entra`
/// block: `None` when it has none, or when the sign-in did not work, in
/// which case the box opens unbound and [`keep_signed_in`] tries again,
/// silently. The one sign-in of an open that may ask the person (Q22).
/// A box still running from before needs none while it is signed in, and
/// gets none after a sign-out in it, which holds until it is closed (Q7).
fn host_sign_in(app: &tauri::AppHandle) -> Option<HostSignIn> {
    let PipeEvent::State { state, sign_in: Some(view), signed_in, signed_out, .. } = pipe::ask(&PipeRequest::Status, |_| {}).ok()?
    else {
        return None;
    };
    if state == BoxState::Running && (signed_out || signed_in == Some(true)) {
        return None;
    }
    sign_in(app, &view, true, true).map_err(|e| eprintln!("sign-in: {e}")).ok()
}

#[cfg(windows)]
fn sign_in(app: &tauri::AppHandle, view: &sluse_proto::SignInView, may_ask: bool, steps: bool) -> Result<HostSignIn, String> {
    signin::sign_in(app, view, may_ask, steps)
}

#[cfg(not(windows))]
fn sign_in(_: &tauri::AppHandle, _: &sluse_proto::SignInView, _: bool, _: bool) -> Result<HostSignIn, String> {
    Err("the host's sign-in is Windows only".into())
}

/// Sluse Admin's sign-in: the same window, its own request (D-037); `pick`
/// after a sign-out, so another account can sign in.
#[cfg(windows)]
fn sign_in_code(
    app: &tauri::AppHandle,
    req: &sluse_proto::pipe::SignInRequest,
    view: &sluse_proto::SignInView,
    pick: bool,
) -> Result<String, String> {
    signin::catch_code(app, req, view, true, true, Some(pick))
}

#[cfg(not(windows))]
fn sign_in_code(_: &tauri::AppHandle, _: &sluse_proto::pipe::SignInRequest, _: &sluse_proto::SignInView, _: bool) -> Result<String, String> {
    Err("the sign-in is Windows only".into())
}

/// `timezone` is the page's IANA name (`Intl`), which Windows itself does not
/// name; the box's clock follows it. `theme` is the one in use in this
/// window, Follow Windows resolved here (Q70).
#[tauri::command(async)]
fn open_box(app: tauri::AppHandle, timezone: Option<String>, theme: Option<Theme>) -> Result<Ready, Failure> {
    let req = PipeRequest::Open { keyboard: pipe::keyboard(), timezone, sign_in: host_sign_in(&app), theme };
    match pipe::ask(&req, |e| {
        let _ = app.emit("progress", e);
    })? {
        PipeEvent::Ready { vnc, password, update, problem, copy_out, config_changed, config_changes, inputs, onedrive, shares } => Ok(Ready {
            vnc,
            username: VNC_USER,
            password: password.expose().to_owned(),
            update,
            problem,
            copy_out,
            config_changed,
            config_changes,
            inputs,
            onedrive,
            shares,
        }),
        other => Err(Failure::from_event(other)),
    }
}

/// Asked by the page once the box is open and every minute after (D-036):
/// if the box's broker holds no sign-in, sign in **silently** and hand it
/// over. `may_ask` on the first ask after an open: an open's sign-in grown
/// too old during a build leaves the box unbound, and Microsoft's page is
/// shown then rather than leaving the box without a sign-in (D-066,
/// amending Q22). Never as the wait's steps: the box is on screen. A
/// sign-out is `signedOut` and is not undone (Q7). The user now signed in,
/// if this did.
#[tauri::command(async)]
fn keep_signed_in(app: tauri::AppHandle, may_ask: Option<bool>) -> Result<Option<String>, Failure> {
    let PipeEvent::State { sign_in: Some(view), signed_in: Some(false), signed_out, .. } = pipe::ask(&PipeRequest::Status, |_| {})?
    else {
        return Ok(None);
    };
    if signed_out {
        return Err(Failure::new("signedOut", "signed out in the box; Sluse signs it in again at the next open"));
    }
    let s = sign_in(&app, &view, may_ask.unwrap_or(false), false).map_err(|e| Failure::new("signIn", e))?;
    match pipe::ask(&PipeRequest::SignIn { sign_in: s }, |_| {})? {
        PipeEvent::SignedIn { user } => Ok(Some(user)),
        other => Err(Failure::from_event(other)),
    }
}

/// One line of this window's own log, `%LOCALAPPDATA%\Sluse\logs\shell.log`:
/// what the window did and when, which nothing else on disk records (L1,
/// 2026-10-21: 12 minutes after the box was ready, unaccounted for; D-066).
/// The page stamps it. Best effort; one older file kept at 1 MB.
#[tauri::command]
fn shell_log(line: String) {
    use std::io::Write;
    let Some(local) = std::env::var_os("LOCALAPPDATA") else { return };
    let dir = std::path::Path::new(&local).join("Sluse").join("logs");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("shell.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() > 1 << 20) {
        let _ = std::fs::rename(&path, dir.join("shell.1.log"));
    }
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let _ = writeln!(f, "{}", line.replace(['\r', '\n'], " "));
    }
}

/// The bar's Sign out (D-064): Sluse stops reading as the person, until the
/// next open (Q7).
#[tauri::command(async)]
fn sign_out() -> Result<(), Failure> {
    match pipe::ask(&PipeRequest::SignOut, |_| {})? {
        PipeEvent::Done => Ok(()),
        other => Err(Failure::from_event(other)),
    }
}

/// The theme changed while the box is open (Q70): the box takes it at once.
/// Busy during an open; the page sends it again once the box is up.
#[tauri::command(async)]
fn set_theme(theme: Theme) -> Result<(), Failure> {
    match pipe::ask(&PipeRequest::Theme { theme }, |_| {})? {
        PipeEvent::Done => Ok(()),
        other => Err(Failure::from_event(other)),
    }
}

/// The wait over the box until its console answers (Q9), the shell's last
/// step: asks the service every second, says the step once it has to wait,
/// with its last time and limit, and fails as `console` past the limit. The
/// box is running then; the page offers to close it.
#[tauri::command(async)]
fn wait_for_console(app: tauri::AppHandle) -> Result<(), Failure> {
    let started = std::time::Instant::now();
    let mut said = false;
    loop {
        match pipe::ask(&PipeRequest::Console, |_| {})? {
            PipeEvent::Console { answered: true, .. } => return Ok(()),
            PipeEvent::Console { answered: false, last_s, limit_s } => {
                if !said {
                    let step = PipeEvent::Progress {
                        step: "Waiting for your box's console".into(),
                        phase: Some(Phase::Console),
                        pct: None,
                        last_s,
                        limit_s: Some(limit_s),
                        plan: vec![],
                    };
                    let _ = app.emit("progress", step);
                    said = true;
                }
                if started.elapsed().as_secs() >= limit_s {
                    return Err(Failure::new("console", format!("the box's console did not answer within {limit_s} s")));
                }
            }
            other => return Err(Failure::from_event(other)),
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

/// The page says "Closed" for a moment, then asks to [`quit`] (D-034 point 6).
#[tauri::command(async)]
fn close_box(app: tauri::AppHandle) -> Result<(), Failure> {
    match pipe::ask(&PipeRequest::Close, |e| {
        let _ = app.emit("progress", e);
    })? {
        PipeEvent::Closed => Ok(()),
        other => Err(Failure::from_event(other)),
    }
}

#[tauri::command]
fn quit(app: tauri::AppHandle) {
    app.exit(0);
}

/// "Reset the system, keep my files" (`wipe: false`) or "Wipe the box"
/// (`wipe: true`), for this user's own box. The page asks first; this does.
#[tauri::command(async)]
fn reset_box(app: tauri::AppHandle, wipe: bool) -> Result<(), Failure> {
    let req = if wipe { PipeRequest::Wipe { sid: None } } else { PipeRequest::Reset { sid: None } };
    match pipe::ask(&req, |e| {
        let _ = app.emit("progress", e);
    })? {
        PipeEvent::Closed => Ok(()),
        other => Err(Failure::from_event(other)),
    }
}

/// Explorer on the user's Sluse Artifacts (D-031) or Sluse Inputs (D-054),
/// made first if it is not there yet. The shell runs as the user, so this is
/// theirs to make. The same folders the broker uses as them, under
/// `%USERPROFILE%`.
#[tauri::command(async)]
fn open_folder(which: String) -> Result<(), String> {
    let name = match which.as_str() {
        "artifacts" => "Sluse Artifacts",
        "inputs" => "Sluse Inputs",
        _ => return Err(format!("no such folder: {which}")),
    };
    let profile = std::env::var_os("USERPROFILE").ok_or("no USERPROFILE in this session")?;
    let dir = std::path::Path::new(&profile).join(name);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    std::process::Command::new("explorer.exe").arg(&dir).spawn().map(drop).map_err(|e| format!("Explorer: {e}"))
}

/// The user's OneDrive `Sluse` folder (D-054): `present`, `missing`, or
/// `no-client` where no OneDrive sync client is signed in on this computer.
/// With `create`, a missing one is made, in the synced OneDrive folder, as
/// the user: the user's click is the approval, and the broker, which only
/// reads, never holds a scope that writes (D-054). The sync client takes it
/// to the drive's root.
#[tauri::command(async)]
fn onedrive_folder(create: bool) -> Result<&'static str, String> {
    let Some(root) = std::env::var_os("OneDriveCommercial").map(std::path::PathBuf::from).filter(|r| r.is_dir()) else {
        return Ok("no-client");
    };
    let dir = root.join(sluse_proto::config::ONEDRIVE_FOLDER);
    if dir.is_dir() {
        return Ok("present");
    }
    if !create {
        return Ok("missing");
    }
    std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    Ok("present")
}

/// OneDrive on the web, for a computer with no sync client.
#[tauri::command(async)]
fn open_onedrive_web() -> Result<(), String> {
    std::process::Command::new("explorer.exe")
        .arg("https://www.microsoft365.com/onedrive")
        .spawn()
        .map(drop)
        .map_err(|e| format!("the browser: {e}"))
}

/// F5, Ctrl+R and the other browser keys belong to the box, not to this
/// window: WebView2 took them and reloaded the shell, which dropped the
/// screen's secret and started a new open (L1, 2026-09-30).
#[cfg(windows)]
fn box_keys(app: &tauri::App) {
    use tauri::Manager;
    use webview2_com::Microsoft::Web::WebView2::Win32::ICoreWebView2Settings3;
    use windows::core::Interface;
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.with_webview(|wv| unsafe {
            if let Ok(s) = wv.controller().CoreWebView2().and_then(|c| c.Settings()).and_then(|s| s.cast::<ICoreWebView2Settings3>()) {
                let _ = s.SetAreBrowserAcceleratorKeysEnabled(false);
            }
        });
    }
}

#[cfg(not(windows))]
fn box_keys(_: &tauri::App) {}

/// Whether another Sluse window is already open in this Windows session; if
/// so, that window is brought forward. A named mutex in the session's own
/// namespace (`Local\`), so two users on one device each have their own.
/// Never closed: the process holds it for as long as it lives. Clicking
/// Sluse twice used to open two windows, both asking to open the box.
#[cfg(windows)]
fn already_open(admin: bool) -> bool {
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
    use windows::Win32::System::Threading::CreateMutexW;
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE};
    // One of each per session: Sluse Admin beside the box is fine.
    let (mutex, title) = if admin { ("Local\\SluseAdmin", ADMIN_TITLE) } else { ("Local\\SluseShell", "Sluse") };
    let created = unsafe { CreateMutexW(None, true, &HSTRING::from(mutex)) };
    if created.is_err() || unsafe { GetLastError() } != ERROR_ALREADY_EXISTS {
        return false;
    }
    if let Ok(window) = unsafe { FindWindowW(PCWSTR::null(), &HSTRING::from(title)) } {
        unsafe {
            let _ = ShowWindow(window, SW_RESTORE);
            let _ = SetForegroundWindow(window);
        }
    }
    true
}

#[cfg(not(windows))]
fn already_open(_: bool) -> bool {
    false
}

const ADMIN_TITLE: &str = "Sluse Admin";

/// The window opens at 1600 x 932 inside where that fits, and to the work
/// area where it does not (Q25); it never goes below 960 x 600 inside
/// (`tauri.conf.json`). The box renders at whatever space it gets (Q34).
fn fit_to_screen(w: &tauri::WebviewWindow) {
    let (Ok(Some(screen)), Ok(outer)) = (w.current_monitor(), w.outer_size()) else { return };
    let area = screen.work_area().size;
    if outer.width > area.width || outer.height > area.height {
        let _ = w.maximize();
    }
}

/// `sluse-shell.exe --admin` is Sluse Admin (D-039 point 1); the shortcut the
/// MSI's Admin feature installs runs it.
fn admin_mode() -> bool {
    std::env::args().any(|a| a == "--admin")
}

/// When the window's X was last pressed, in ms since the epoch, for
/// [`close_requested`].
static LAST_CLOSE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// The X asks the page, which knows whether a box is open, what to do
/// (D-034 point 5). **A second X within 5 s always closes**, so a page that
/// does not answer can never keep the window open; with the box on screen
/// it closes the box too (Q29). Mid-wait it is Quit: the service finishes
/// a build and leaves the box closed (Q26, Q75).
fn close_requested(window: &tauri::Window, event: &tauri::WindowEvent) {
    use std::sync::atomic::Ordering;
    let tauri::WindowEvent::CloseRequested { api, .. } = event else { return };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    if now.saturating_sub(LAST_CLOSE.swap(now, Ordering::SeqCst)) < 5_000 {
        match WINDOW.load(Ordering::SeqCst) {
            RUNNING => pipe::tell(&PipeRequest::Close),
            BUILDING => {
                pipe::tell(&PipeRequest::Quit);
                api.prevent_close();
                let _ = window.hide();
                let _ = window.emit("quit-build", ());
            }
            _ => pipe::tell(&PipeRequest::Quit),
        }
        return;
    }
    api.prevent_close();
    let _ = window.emit("close-requested", ());
}

fn main() {
    let admin = admin_mode();
    // A `sluse:` link (a notification's button): the folder needs no window;
    // open and close go to the window already running, or start one.
    match edges::link() {
        Some(Some("artifacts")) => {
            let _ = open_folder("artifacts".into());
            return;
        }
        Some(Some(verb)) if edges::signal(verb) => return,
        Some(None) => return,
        _ => {}
    }
    if already_open(admin) {
        return;
    }
    #[cfg(windows)]
    edges::toast::identity();
    tauri::Builder::default()
        .on_window_event(move |w, e| {
            // The box's window asks; Sluse Admin asks only with work to lose.
            if w.label() == "main" {
                close_requested(w, e);
            } else if w.label() == "admin" {
                admin::close_requested(w, e);
            }
        })
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .manage(admin::Admin::default())
        .setup(move |app| {
            if admin {
                tauri::WebviewWindowBuilder::new(app, "admin", tauri::WebviewUrl::App("admin.html".into()))
                    .title(ADMIN_TITLE)
                    .inner_size(1200.0, 860.0)
                    .drag_and_drop(false)
                    .build()?;
            } else {
                // `create: false` in tauri.conf.json, so one process is one window.
                let w = tauri::WebviewWindowBuilder::from_config(app.handle(), &app.config().app.windows[0])?.build()?;
                fit_to_screen(&w);
                box_keys(app);
                edges::listen(app.handle());
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            open_box,
            facts,
            show_sign_in,
            window_state,
            quit_open,
            edges::taskbar,
            edges::tray,
            edges::leave,
            edges::notify,
            edges::withdraw,
            keep_signed_in,
            shell_log,
            sign_out,
            set_theme,
            wait_for_console,
            close_box,
            quit,
            reset_box,
            open_folder,
            onedrive_folder,
            open_onedrive_web,
            admin::admin_sign_in,
            admin::admin_roles,
            admin::admin_register,
            admin::admin_consent_missing,
            admin::admin_groups,
            admin::admin_assign,
            admin::admin_sites,
            admin::admin_teams,
            admin::admin_libraries,
            admin::admin_folders,
            admin::admin_share_folders,
            admin::admin_catalog,
            admin::admin_author,
            admin::admin_open,
            admin::admin_diff,
            admin::admin_save,
            admin::admin_publish,
            admin::admin_whoami,
            admin::admin_sign_out,
            admin::admin_pick_account,
            admin::admin_assigned,
            admin::admin_unassign,
            admin::admin_package,
            admin::admin_stop_publish,
            admin::admin_delete_app,
            admin::admin_guard,
            admin::admin_msi,
            admin::admin_open_portal,
            admin::admin_close
        ])
        .run(tauri::generate_context!())
        .expect("the Sluse window");
}

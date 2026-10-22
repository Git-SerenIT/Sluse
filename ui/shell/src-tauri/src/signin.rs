// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The sign-in on the host (D-036): a window of its own, on Entra's page,
//! signed in from the person's Windows sign-in where the device allows it.
//!
//! The window is WebView2 with `AllowSingleSignOnUsingOSPrimaryAccount`, which
//! Tauri's own environment leaves off, so it gets an environment of its own
//! with its own data folder. It has no IPC: no capability names it, and it
//! only ever shows Microsoft's pages. Its one job is to catch the redirect to
//! [`NATIVE_REDIRECT`](sluse_proto::wire::NATIVE_REDIRECT) before it loads and
//! read the code from it. **The code goes to the service, and the broker
//! redeems it**, so the person's tokens never pass through this process.
//!
//! A silent attempt comes first, hidden, with `prompt=none`; only if Entra
//! says the person is needed does the window show, without it. A silent
//! attempt that ends on a page instead of the redirect counts as needing the
//! person, so that page (an AADSTS error, say) is shown, not waited out.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use sluse_proto::pipe::{Caught, HostSignIn, Phase, PipeEvent, SignInRequest};
use sluse_proto::SignInView;
use tauri::webview::PageLoadEvent;
use tauri::{AppHandle, Emitter, WebviewUrl, WebviewWindowBuilder, WindowEvent};
use webview2_com::Microsoft::Web::WebView2::Win32::{
    CreateCoreWebView2EnvironmentWithOptions, ICoreWebView2Environment, ICoreWebView2EnvironmentOptions,
};
use webview2_com::{CoreWebView2EnvironmentOptions, CreateCoreWebView2EnvironmentCompletedHandler};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Foundation::{E_POINTER, E_UNEXPECTED};

/// A label per attempt: `destroy` returns before Tauri lets go of the old
/// window's label, so the shown attempt right after a silent one cannot
/// reuse it ("a webview with label 'signin' already exists").
static ATTEMPT: AtomicU32 = AtomicU32::new(0);

/// How long a silent attempt may take before it counts as failed: Entra
/// answers a `prompt=none` request at once, or not at all.
const SILENT: Duration = Duration::from_secs(30);
/// How long the person has to finish the page.
const INTERACTIVE: Duration = Duration::from_secs(600);

/// One sign-in window at a time.
static SIGNING: Mutex<()> = Mutex::new(());

/// Carried from the main thread, where it is made, to the builder, which
/// hands it back to the main thread to use.
/// ponytail: `unsafe impl` for a COM pointer that is only ever used on the
/// thread that made it; drop it if webview2-com marks the interface `Send`.
struct Env(ICoreWebView2Environment);
unsafe impl Send for Env {}
unsafe impl Sync for Env {}

static ENV: OnceLock<Env> = OnceLock::new();

/// The open's sign-in as a step of the main window's wait, with this
/// file's limits (Q21): only for the open's own sign-in (Q22), never one
/// while the box is on screen, which would put the wait back over it
/// (D-066). In Sluse Admin's process there is no main window, and nothing
/// hears it.
fn say(app: &AppHandle, steps: bool, step: &str, limit: Duration) {
    if steps {
        let step = PipeEvent::Progress {
            step: step.into(),
            phase: Some(Phase::SignIn),
            pct: None,
            last_s: None,
            limit_s: Some(limit.as_secs()),
            plan: vec![],
        };
        let _ = app.emit_to("main", "progress", step);
    }
}

/// Sign in, silently if the device lets it, else with the window shown when
/// `may_ask`; `steps`: as steps of the main window's wait. The hand-over for
/// the service, or why not.
pub fn sign_in(app: &AppHandle, view: &SignInView, may_ask: bool, steps: bool) -> Result<HostSignIn, String> {
    let req = SignInRequest::new()?;
    say(app, steps, "Signing you in to Microsoft", SILENT);
    catch_code(app, &req, view, may_ask, steps, None).map(|code| req.host_sign_in(code))
}

/// The code for `req`: silently first, then with the window shown when
/// `may_ask`. Sluse Admin's sign-in uses this too, with its own request and
/// `admin` set: its own title, and when `Some(true)`, after a sign-out, no
/// silent try and Microsoft's account picker, so another account can sign in.
pub fn catch_code(
    app: &AppHandle,
    req: &SignInRequest,
    view: &SignInView,
    may_ask: bool,
    steps: bool,
    admin: Option<bool>,
) -> Result<String, String> {
    let _one = SIGNING.lock().unwrap_or_else(|p| p.into_inner());
    let first = if admin == Some(true) { Caught::NeedsUser } else { attempt(app, req, view, true, admin)? };
    match first {
        Caught::Code(code) => Ok(code),
        Caught::NeedsUser if may_ask => match {
            say(app, steps, "Sign in to Microsoft in the other window", INTERACTIVE);
            // The main window offers to bring this one forward while it waits (Q18).
            // To whichever window this process has: the box's, or Sluse Admin's.
            let _ = app.emit("signin-window", true);
            let got = attempt(app, req, view, false, admin);
            let _ = app.emit("signin-window", false);
            got?
        } {
            Caught::Code(code) => Ok(code),
            Caught::NeedsUser => Err("the sign-in was not finished".into()),
            Caught::Failed(e) => Err(e),
        },
        Caught::NeedsUser => Err("the sign-in needs you; it is asked at the next open".into()),
        Caught::Failed(e) => Err(e),
    }
}

fn attempt(app: &AppHandle, req: &SignInRequest, view: &SignInView, silent: bool, admin: Option<bool>) -> Result<Caught, String> {
    let env = environment(app)?;
    let mut url = req.authorize_url(view, silent);
    if admin == Some(true) {
        url.push_str("&prompt=select_account");
    }
    let url = url.parse().map_err(|e| format!("the sign-in address: {e}"))?;
    let (tx, rx) = mpsc::channel::<Caught>();
    let on_redirect = tx.clone();
    let on_page = tx.clone();
    let mine = req.clone();
    let label = format!("signin-{}", ATTEMPT.fetch_add(1, Ordering::Relaxed));
    let window = WebviewWindowBuilder::new(app, &label, WebviewUrl::External(url))
        .title(if admin.is_some() { "Sign in to Microsoft for Sluse Admin" } else { "Sign in to Sluse" })
        .inner_size(480.0, 640.0)
        .center()
        .visible(!silent)
        .focused(!silent)
        .with_environment(env)
        // Every navigation is looked at; the redirect is caught and never loads.
        .on_navigation(move |u| match mine.caught(u.as_str()) {
            Some(c) => {
                let _ = on_redirect.send(c);
                false
            }
            None => true,
        })
        // A `prompt=none` answer is a redirect, never a page. A page that
        // finished loading is Entra wanting the person; a caught redirect
        // has already sent its answer, and the first answer wins.
        .on_page_load(move |_, p| {
            if silent && p.event() == PageLoadEvent::Finished {
                let _ = on_page.send(Caught::NeedsUser);
            }
        })
        .build()
        .map_err(|e| format!("the sign-in window: {e}"))?;
    window.on_window_event(move |e| {
        if matches!(e, WindowEvent::Destroyed) {
            let _ = tx.send(Caught::Failed("the sign-in window was closed".into()));
        }
    });
    let got = rx.recv_timeout(if silent { SILENT } else { INTERACTIVE });
    let _ = window.destroy();
    got.or_else(|_| Ok(Caught::Failed("Microsoft's sign-in did not answer".into())))
}

/// The sign-in's browser profile: the box's, or Sluse Admin's own, so that
/// clearing the admin's never signs the person out of their box.
fn profile() -> Result<std::path::PathBuf, String> {
    let local = std::env::var_os("LOCALAPPDATA").ok_or("no LOCALAPPDATA in this session")?;
    Ok(std::path::Path::new(&local).join("Sluse").join(if crate::admin_mode() { "admin-signin" } else { "signin" }))
}

/// Sluse Admin's Sign out (Q82): the profile, with what Microsoft's page
/// remembers, goes at Sluse Admin's next start. Until then each sign-in in
/// this window opens Microsoft's account picker.
pub fn clear_profile() {
    if let Ok(dir) = profile() {
        let _ = std::fs::write(dir.with_extension("clear"), b"");
    }
}

/// The sign-in's own WebView2 environment, made once, on the main thread.
fn environment(app: &AppHandle) -> Result<ICoreWebView2Environment, String> {
    if let Some(e) = ENV.get() {
        return Ok(e.0.clone());
    }
    let dir = profile()?;
    // Sluse Admin's Sign out asked for its profile to go (Q82). Cleared here,
    // before the environment holds the folder open.
    let marker = dir.with_extension("clear");
    if marker.exists() {
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_file(&marker);
    }
    let (tx, rx) = mpsc::channel();
    app.run_on_main_thread(move || {
        let _ = tx.send(make_environment(&dir).map(Env));
    })
    .map_err(|e| format!("the sign-in's browser: {e}"))?;
    let env = rx.recv().map_err(|_| "the sign-in's browser was not made".to_owned())??;
    let _ = ENV.set(env);
    Ok(ENV.get().expect("set above").0.clone())
}

fn make_environment(dir: &std::path::Path) -> Result<ICoreWebView2Environment, String> {
    let options = CoreWebView2EnvironmentOptions::default();
    // The device's own sign-in, the Primary Refresh Token's: single sign-on,
    // and the device's claim for Conditional Access (D-036).
    unsafe { options.set_allow_single_sign_on_using_os_primary_account(true) };
    let (tx, rx) = mpsc::channel();
    let handler = CreateCoreWebView2EnvironmentCompletedHandler::create(Box::new(move |code, env| {
        let made = code.and_then(|()| env.ok_or_else(|| windows::core::Error::from(E_POINTER)));
        tx.send(made).map_err(|_| windows::core::Error::from(E_UNEXPECTED))
    }));
    unsafe {
        CreateCoreWebView2EnvironmentWithOptions(
            PCWSTR::null(),
            &HSTRING::from(dir.as_os_str()),
            &ICoreWebView2EnvironmentOptions::from(options),
            &handler,
        )
    }
    .map_err(|e| format!("WebView2: {e}"))?;
    webview2_com::wait_with_pump(rx).map_err(|e| format!("WebView2: {e:?}"))?.map_err(|e| format!("WebView2: {e}"))
}

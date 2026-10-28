// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Windows' edges around the Sluse window (Q11, D-062): the taskbar
//! button's progress, the tray icon and its menu, Sluse's notifications,
//! and the `sluse:` link their buttons use.
//!
//! The page decides what each says, in its words; this file puts it where
//! Windows shows it. The tray icon is there exactly while a box or a build
//! runs for the person whose Sluse process this is (Q71): a process of
//! their own, so nobody else signed in sees it.
//!
//! **The `sluse:` link** (jok, 2026-10-20) takes three verbs and nothing
//! else: `open`, `close` (the window on its own Close confirm, Q85) and
//! `artifacts`. Any page or program can follow it; each verb only shows
//! Sluse's window or a folder, and closing still asks.

use serde::Deserialize;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::window::ProgressBarState;
use tauri::menu::IsMenuItem;
use tauri::{AppHandle, Emitter, Manager, Wry};

pub use sluse_proto::pipe::LINK_VERBS as VERBS;

/// The verb a `sluse:` link on the command line asks for: `Some(None)` for
/// a link that is not one of [`VERBS`], which is ignored.
pub fn link() -> Option<Option<&'static str>> {
    std::env::args().skip(1).find(|a| a.to_ascii_lowercase().starts_with("sluse:")).map(|a| sluse_proto::pipe::link_verb(&a))
}

/// The taskbar button's bar (Q11): the step's percentage during a build,
/// Windows' moving bar where there is none, the error state when a build
/// stopped, none otherwise. It belongs to the window, so it goes with it.
#[tauri::command]
pub fn taskbar(window: tauri::WebviewWindow, state: ProgressBarState) {
    let _ = window.set_progress_bar(state);
}

/// What the tray says, from the page: the tooltip, the status lines at the
/// menu's top, whether Sluse Inputs is offered and whether the box can be
/// closed (not while only a build runs).
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrayState {
    tip: String,
    lines: Vec<String>,
    inputs: bool,
    can_close: bool,
}

const TRAY: &str = "sluse";

/// The tray icon, made, changed or removed (`None`).
#[tauri::command]
pub fn tray(app: AppHandle, state: Option<TrayState>) -> Result<(), String> {
    let Some(s) = state else {
        app.remove_tray_by_id(TRAY);
        return Ok(());
    };
    let e = |e: tauri::Error| e.to_string();
    let lines: Vec<MenuItem<Wry>> =
        s.lines.iter().enumerate().map(|(i, l)| MenuItem::with_id(&app, format!("line{i}"), l, false, None::<&str>)).collect::<Result<_, _>>().map_err(e)?;
    let sep = PredefinedMenuItem::separator(&app).map_err(e)?;
    let sep2 = PredefinedMenuItem::separator(&app).map_err(e)?;
    let open = MenuItem::with_id(&app, "open", "Open Sluse", true, None::<&str>).map_err(e)?;
    let artifacts = MenuItem::with_id(&app, "artifacts", "Sluse Artifacts", true, None::<&str>).map_err(e)?;
    let inputs = MenuItem::with_id(&app, "inputs", "Sluse Inputs", true, None::<&str>).map_err(e)?;
    let close = MenuItem::with_id(&app, "close", "Close the box…", s.can_close, None::<&str>).map_err(e)?;
    let mut items: Vec<&dyn IsMenuItem<Wry>> = lines.iter().map(|l| l as &dyn IsMenuItem<Wry>).collect();
    items.extend([&sep as &dyn IsMenuItem<Wry>, &open, &artifacts]);
    if s.inputs {
        items.push(&inputs);
    }
    items.extend([&sep2 as &dyn IsMenuItem<Wry>, &close]);
    let menu = Menu::with_items(&app, &items).map_err(e)?;
    if let Some(t) = app.tray_by_id(TRAY) {
        t.set_menu(Some(menu)).map_err(e)?;
        t.set_tooltip(Some(&s.tip)).map_err(e)?;
        return Ok(());
    }
    let mut b = TrayIconBuilder::with_id(TRAY).tooltip(&s.tip).menu(&menu).show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        b = b.icon(icon.clone());
    }
    b.on_menu_event(|app, ev| match ev.id().as_ref() {
        "open" => show(app),
        "close" => ask_close(app),
        which @ ("artifacts" | "inputs") => {
            let _ = crate::open_folder(which.to_owned());
        }
        _ => {}
    })
    // A click on the icon is Open Sluse, as the bold item would be.
    .on_tray_icon_event(|tray, ev| {
        if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = ev {
            show(tray.app_handle());
        }
    })
    .build(&app)
    .map(drop)
    .map_err(e)
}

/// The Sluse window, shown and in front: from the tray, a notification or
/// a second launch.
pub fn show(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Close the box from the tray or a notification: the window comes forward
/// on its own Close confirm (Q85), never Windows' message box.
pub fn ask_close(app: &AppHandle) {
    crate::note("window: Close asked from the tray or a notification");
    show(app);
    let _ = app.emit_to("main", "tray-close", ());
}

/// Leave the box running: the window goes, the process stays in the tray,
/// reading as the person until the box is closed (D-034 point 5).
#[tauri::command]
pub fn leave(app: AppHandle) {
    crate::note("window: left running, in the tray");
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
}

/// One of Sluse's notifications (Q11): `tag` names it, so it can be
/// withdrawn once it is no longer true (Q86). Buttons are `(label, verb)`,
/// each verb one of [`VERBS`]; a click on the notification opens Sluse.
/// Problems stay out of notifications; the window says them.
#[tauri::command]
pub fn notify(tag: String, title: String, text: String, buttons: Vec<(String, String)>) -> Result<(), String> {
    if let Some((_, v)) = buttons.iter().find(|(_, v)| !VERBS.contains(&v.as_str())) {
        return Err(format!("not a Sluse link: {v}"));
    }
    #[cfg(windows)]
    {
        let esc = |t: &str| t.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        let actions: String = buttons
            .iter()
            .map(|(l, v)| format!(r#"<action content="{}" activationType="protocol" arguments="sluse:{v}"/>"#, esc(l)))
            .collect();
        let xml = format!(
            r#"<toast launch="sluse:open" activationType="protocol"><visual><binding template="ToastGeneric"><text>{}</text><text>{}</text></binding></visual><actions>{actions}</actions></toast>"#,
            esc(&title),
            esc(&text)
        );
        toast::show(&tag, &xml).map_err(|e| format!("the notification: {e}"))
    }
    #[cfg(not(windows))]
    {
        let _ = (tag, title, text);
        Ok(())
    }
}

/// Withdraw notifications that are no longer true (Q86), by tag.
#[tauri::command]
pub fn withdraw(tags: Vec<String>) {
    #[cfg(windows)]
    for t in tags {
        let _ = toast::withdraw(&t);
    }
    #[cfg(not(windows))]
    let _ = tags;
}

/// Hand a `sluse:` verb to the Sluse window already running in this
/// session: `false` when none runs.
pub fn signal(verb: &str) -> bool {
    #[cfg(windows)]
    {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenEventW, SetEvent, EVENT_MODIFY_STATE};
        let Ok(h) = (unsafe { OpenEventW(EVENT_MODIFY_STATE, false, &HSTRING::from(event_name(verb))) }) else {
            return false;
        };
        let ok = unsafe { SetEvent(h) }.is_ok();
        unsafe {
            let _ = CloseHandle(h);
        }
        ok
    }
    #[cfg(not(windows))]
    {
        let _ = verb;
        false
    }
}

/// Listen for verbs from a second launch: `open` shows the window, `close`
/// shows it on its Close confirm. Named events in the session's own
/// namespace, so another person's link never reaches this window.
pub fn listen(app: &AppHandle) {
    #[cfg(windows)]
    for verb in ["open", "close"] {
        use windows::core::HSTRING;
        use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
        use windows::Win32::System::Threading::{CreateEventW, WaitForSingleObject, INFINITE};
        let Ok(h) = (unsafe { CreateEventW(None, false, false, &HSTRING::from(event_name(verb))) }) else { continue };
        // The handle crosses to the thread as a number; it is never closed.
        let raw = h.0 as isize;
        let app = app.clone();
        std::thread::spawn(move || loop {
            if unsafe { WaitForSingleObject(HANDLE(raw as *mut _), INFINITE) } != WAIT_OBJECT_0 {
                return;
            }
            if verb == "close" { ask_close(&app) } else { show(&app) }
        });
    }
    #[cfg(not(windows))]
    let _ = app;
}

#[cfg(windows)]
fn event_name(verb: &str) -> String {
    format!("Local\\SluseShell-{verb}")
}

/// Windows' toasts, as an app with no package: the Start shortcut carries
/// [`AUMID`] (the MSI sets it), and so does this process.
#[cfg(windows)]
pub mod toast {
    use windows::core::HSTRING;
    use windows::Data::Xml::Dom::XmlDocument;
    use windows::UI::Notifications::{ToastNotification, ToastNotificationManager};

    pub const AUMID: &str = "SerenIT.Sluse";
    const GROUP: &str = "sluse";

    /// This process's identity, so its notifications are Sluse's.
    pub fn identity() {
        let _ = unsafe { windows::Win32::UI::Shell::SetCurrentProcessExplicitAppUserModelID(&HSTRING::from(AUMID)) };
    }

    pub fn show(tag: &str, xml: &str) -> windows::core::Result<()> {
        let doc = XmlDocument::new()?;
        doc.LoadXml(&HSTRING::from(xml))?;
        let toast = ToastNotification::CreateToastNotification(&doc)?;
        toast.SetTag(&HSTRING::from(tag))?;
        toast.SetGroup(&HSTRING::from(GROUP))?;
        ToastNotificationManager::CreateToastNotifierWithId(&HSTRING::from(AUMID))?.Show(&toast)
    }

    pub fn withdraw(tag: &str) -> windows::core::Result<()> {
        ToastNotificationManager::History()?.RemoveGroupedTagWithId(&HSTRING::from(tag), &HSTRING::from(GROUP), &HSTRING::from(AUMID))
    }
}

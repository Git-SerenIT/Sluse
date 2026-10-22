// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The shell's side of the service's pipe (`sluse_proto::pipe`).
//!
//! Two checks before anything the service says is believed:
//! - **The server is SYSTEM.** A process that created `\\.\pipe\sluse` before
//!   the service could otherwise hand the shell its own VNC address, and the
//!   user would type their Microsoft password into its screen.
//! - **The screen is on the host-only segment** (`192.168.77.0/24`).
//!
//! The pipe is opened at identification level, so the service can learn who
//! is asking and cannot act as them.

use std::io::{BufRead, BufReader, Write};

use serde::Serialize;
use sluse_proto::pipe::{PipeEvent, PipeRequest};

/// What went wrong, for the page to explain (D-034 point 4): a
/// [`sluse_proto::pipe::PipeFailure`] code from the service, or one of the
/// shell's own: `service` (the pipe could not be used: not running, not
/// SYSTEM's, an answer it cannot read) and `screen` (the box's screen was not
/// on the host-only segment, so it was not shown). `message` is the detail,
/// for "Details" and "Copy for IT", never the headline.
#[derive(Debug, Serialize)]
pub struct Failure {
    pub code: String,
    pub message: String,
}

impl Failure {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Failure { code: code.to_owned(), message: message.into() }
    }

    /// The service's own failure, with its code as the wire spells it.
    pub fn from_event(e: PipeEvent) -> Self {
        match e {
            PipeEvent::Failed { code, message } => {
                let code = serde_json::to_value(code).ok().and_then(|v| v.as_str().map(str::to_owned));
                Failure { code: code.unwrap_or_else(|| "unknown".into()), message }
            }
            // `Debug`, and safe to show: the VNC password is a `Secret`.
            other => Failure::new("service", format!("the Sluse service answered {other:?}")),
        }
    }
}

/// Ask the service, reporting each progress event whole (its step, phase,
/// percentage, last time and limit, D-034), and return the final event.
pub fn ask(req: &PipeRequest, mut progress: impl FnMut(&PipeEvent)) -> Result<PipeEvent, Failure> {
    let service = |m: String| Failure::new("service", m);
    let mut pipe = connect().map_err(service)?;
    let mut line = serde_json::to_vec(req).map_err(|e| service(e.to_string()))?;
    line.push(b'\n');
    pipe.write_all(&line).map_err(|e| service(format!("the Sluse service: {e}")))?;
    for line in BufReader::new(pipe).lines() {
        let line = line.map_err(|e| service(format!("the Sluse service: {e}")))?;
        // Not echoed: a line that does not parse may be a `Ready` from a
        // newer service, password and all (D-033 point 5).
        let event: PipeEvent = serde_json::from_str(&line)
            .map_err(|e| service(format!("the Sluse service sent an answer this shell cannot read: {e}")))?;
        match event {
            PipeEvent::Progress { .. } => progress(&event),
            PipeEvent::Ready { ref vnc, .. } => {
                sluse_proto::pipe::vnc_on_segment(vnc).map_err(|m| Failure::new("screen", m))?;
                return Ok(event);
            }
            other => return Ok(other),
        }
    }
    Err(service("the Sluse service closed the pipe without an answer".into()))
}

#[cfg(windows)]
fn connect() -> Result<std::fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{LocalFree, HANDLE, HLOCAL};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };
    use windows::Win32::Storage::FileSystem::{SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};

    // FILE_GENERIC_READ | FILE_WRITE_DATA: the service's pipe DACL grants no
    // more (`sluse-lifecycle` `winsys::PIPE_SDDL`, review R-06).
    let pipe = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(0x0012_008b)
        .security_qos_flags(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0)
        .open(sluse_proto::pipe::PIPE_NAME)
        .map_err(|e| format!("The Sluse service is not running ({e}). Ask your administrator."))?;

    // The pipe's owner, read from the handle we hold (READ_CONTROL). Not the
    // server process's token: a standard user may not open SYSTEM's, which
    // refused every open on L1 (2026-09-30). A pipe a standard user squatted
    // first is theirs; only SYSTEM, or an administrator running the service
    // in the foreground, makes one owned by SYSTEM or Administrators.
    let not_system = || "the pipe is not the Sluse service's: its owner is not SYSTEM".to_owned();
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let got = unsafe {
        GetSecurityInfo(
            HANDLE(pipe.as_raw_handle()),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&raw mut owner),
            None,
            None,
            None,
            Some(&raw mut sd),
        )
    };
    if got.is_err() {
        return Err(not_system());
    }
    let trusted = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid).as_bool() || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
    };
    unsafe { LocalFree(Some(HLOCAL(sd.0))) };
    if !trusted {
        return Err(not_system());
    }
    Ok(pipe)
}

#[cfg(not(windows))]
fn connect() -> Result<std::fs::File, String> {
    Err("the Sluse shell runs on Windows".into())
}

/// The xkb layout for the user's Windows keyboard, `us` if the table lacks it.
pub fn keyboard() -> String {
    klid().as_deref().and_then(sluse_proto::pipe::xkb_layout).unwrap_or("us").to_owned()
}

/// When the box has no layout for the user's keyboard and types US English
/// instead (Q30): the layout's language, in English, for the notice that
/// says so, or empty where Windows does not name it. `None` when the box
/// has the layout.
pub fn keyboard_fallback() -> Option<String> {
    let klid = klid()?;
    if sluse_proto::pipe::xkb_layout(&klid).is_some() {
        return None;
    }
    #[cfg(windows)]
    {
        use windows::Win32::Globalization::{GetLocaleInfoW, LOCALE_SENGLISHLANGUAGENAME};
        // The layout id's low word is its language.
        let lang = klid.get(4..).and_then(|l| u32::from_str_radix(l, 16).ok());
        let mut buf = [0u16; 85];
        let n = lang.map_or(0, |l| unsafe { GetLocaleInfoW(l, LOCALE_SENGLISHLANGUAGENAME, Some(&mut buf)) });
        Some(if n > 1 { String::from_utf16_lossy(&buf[..n as usize - 1]) } else { String::new() })
    }
    #[cfg(not(windows))]
    Some(String::new())
}

/// The Windows keyboard layout id, `00000406` say.
fn klid() -> Option<String> {
    #[cfg(windows)]
    {
        let mut name = [0u16; 9];
        unsafe { windows::Win32::UI::Input::KeyboardAndMouse::GetKeyboardLayoutNameW(&mut name) }
            .ok()
            .map(|_| String::from_utf16_lossy(&name[..8]))
    }
    #[cfg(not(windows))]
    None
}

/// Send a request and do not wait for its answer: the window's second X,
/// which closes the window at once and the box behind it (Q29). The service
/// carries on with a request whose asker has gone.
pub fn tell(req: &PipeRequest) {
    let Ok(mut pipe) = connect() else { return };
    if let Ok(mut line) = serde_json::to_vec(req) {
        line.push(b'\n');
        let _ = pipe.write_all(&line);
    }
}

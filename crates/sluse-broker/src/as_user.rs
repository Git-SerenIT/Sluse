// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Writing as the user (D-031).
//!
//! On a device the service hands the broker the signed-in user's token, as an
//! inherited handle named by `SLUSE_USER_TOKEN`. Sluse Artifacts is then that
//! user's own `%USERPROFILE%\Sluse Artifacts`, and every touch of it is made
//! **as the user**, never as SYSTEM: a SYSTEM writer in a folder the user
//! controls follows the user's junctions wherever they point. Invariant 8 says
//! the broker acts as the user; this is that, for the one write path.
//!
//! In LOCAL there is no token, the broker is already the user, the config's
//! `artifacts` is used as written, and [`enter`] does nothing.
//!
//! The token is process-wide on purpose: one broker serves one box for one
//! user (`sluse-lifecycle`'s service).

use std::io;
use std::path::PathBuf;

/// The variable the service names the inherited token handle in.
pub const ENV: &str = "SLUSE_USER_TOKEN";

/// The folder's name under the user's profile (D-031 point 1).
pub const FOLDER: &str = "Sluse Artifacts";

/// Sluse Inputs' name under the user's profile (D-054).
pub const INPUTS: &str = "Sluse Inputs";

static PROFILE: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

/// Take the token the service handed over, if it did, and return where that
/// user's Sluse Artifacts is. `None` when there is no token (LOCAL, tests).
pub fn adopt() -> io::Result<Option<PathBuf>> {
    let Some(value) = std::env::var_os(ENV) else { return Ok(None) };
    let value = value.to_string_lossy().parse::<usize>().map_err(|e| io::Error::other(format!("{ENV}: {e}")))?;
    let profile = imp::adopt(value)?;
    let _ = PROFILE.set(profile.clone());
    Ok(Some(profile.join(FOLDER)))
}

/// Where the user's Sluse Inputs is: under the profile of the token adopted,
/// or, in LOCAL, where the broker is the user, under its own.
pub fn inputs_dir() -> Option<PathBuf> {
    let home = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    PROFILE.get().cloned().or_else(|| std::env::var_os(home).map(PathBuf::from)).map(|p| p.join(INPUTS))
}

/// Act as the user on this thread until the guard drops; a no-op without a
/// token. **Never hold it across an `.await`**: impersonation is per thread,
/// and the task may resume on another one. The guard is not `Send`, so in an
/// axum handler, whose future must be, holding it across one does not compile.
pub fn enter() -> io::Result<Guard> {
    let active = imp::enter()?;
    ACTIVE.set(active);
    Ok(Guard(active, std::marker::PhantomData))
}

thread_local! {
    static ACTIVE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `f` as the broker, SYSTEM, on a thread that may be acting as the user:
/// the audit sink writes its records through this, since the Sluse log takes
/// SYSTEM's writes only (D-023) and a source read refused mid-way is recorded
/// while the read's guard is held.
pub fn as_broker<T>(f: impl FnOnce() -> T) -> T {
    if !ACTIVE.get() {
        return f();
    }
    imp::revert();
    let out = f();
    // Back as the user, or not at all: carrying on as SYSTEM would make the
    // rest of the read the one this module exists to prevent.
    if imp::enter().is_err() {
        std::process::abort();
    }
    out
}

/// The user's token, as a raw handle, for a question about the user (the
/// preflight's `user-not-local-admin`). `None` without one.
pub fn token() -> Option<usize> {
    imp::token()
}

/// The Windows user's SID, `S-1-…`, from the token the service handed over:
/// what the sign-in is compared with (D-057). `None` without a token (LOCAL,
/// tests).
pub fn user_sid() -> Option<io::Result<String>> {
    imp::user_sid()
}

/// Reverts to the broker's own identity on drop. Not `Send`, on purpose:
///
/// ```compile_fail
/// fn send<T: Send>(_: T) {}
/// send(sluse_broker::as_user::enter().unwrap());
/// ```
#[must_use]
pub struct Guard(bool, std::marker::PhantomData<*const ()>);

impl Drop for Guard {
    fn drop(&mut self) {
        if self.0 {
            imp::revert();
            ACTIVE.set(false);
        }
    }
}

#[cfg(windows)]
mod imp {
    use std::io;
    use std::path::PathBuf;
    use std::sync::OnceLock;
    use windows::core::PWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{ImpersonateLoggedOnUser, RevertToSelf};
    use windows::Win32::UI::Shell::GetUserProfileDirectoryW;

    static TOKEN: OnceLock<usize> = OnceLock::new();

    fn handle(value: usize) -> HANDLE {
        HANDLE(value as *mut core::ffi::c_void)
    }

    pub fn adopt(value: usize) -> io::Result<PathBuf> {
        let mut buf = vec![0u16; 512];
        let mut len = buf.len() as u32;
        unsafe { GetUserProfileDirectoryW(handle(value), Some(PWSTR(buf.as_mut_ptr())), &mut len) }
            .map_err(|e| io::Error::other(format!("the user's profile, from the token the service handed over: {e}")))?;
        let profile = PathBuf::from(String::from_utf16_lossy(&buf[..len.saturating_sub(1) as usize]));
        TOKEN.set(value).map_err(|_| io::Error::other("the user's token was adopted twice"))?;
        Ok(profile)
    }

    pub fn token() -> Option<usize> {
        TOKEN.get().copied()
    }

    pub fn user_sid() -> Option<io::Result<String>> {
        use windows::Win32::Foundation::{LocalFree, HLOCAL};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_USER};
        let value = *TOKEN.get()?;
        // ponytail: 256 bytes; a TOKEN_USER is its SID (68 at most) and a pointer.
        let mut buf = vec![0u8; 256];
        let mut len = 0u32;
        Some((|| {
            unsafe { GetTokenInformation(handle(value), TokenUser, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut len) }
                .map_err(|e| io::Error::other(format!("the Windows user's SID: {e}")))?;
            let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
            let mut s = PWSTR::null();
            unsafe { ConvertSidToStringSidW(user.User.Sid, &mut s) }.map_err(io::Error::other)?;
            let out = unsafe { s.to_string() }.map_err(io::Error::other);
            unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
            out
        })())
    }

    /// Whether the thread now acts as the user: false without a token.
    pub fn enter() -> io::Result<bool> {
        let Some(&value) = TOKEN.get() else { return Ok(false) };
        unsafe { ImpersonateLoggedOnUser(handle(value)) }
            .map_err(|e| io::Error::other(format!("acting as the user: {e}")))?;
        Ok(true)
    }

    pub fn revert() {
        // A thread left as the user would write the next Event Log record as
        // them. Nothing sensible continues from that.
        if unsafe { RevertToSelf() }.is_err() {
            std::process::abort();
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use std::io;
    use std::path::PathBuf;

    pub fn adopt(_: usize) -> io::Result<PathBuf> {
        Err(io::Error::other(format!("{} is a Windows handle; this broker is not on Windows", super::ENV)))
    }

    pub fn token() -> Option<usize> {
        None
    }

    pub fn user_sid() -> Option<io::Result<String>> {
        None
    }

    pub fn enter() -> io::Result<bool> {
        Ok(false)
    }

    pub fn revert() {}
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The tenant package folder's ACL, on Windows.
//!
//! ponytail: `Sd`, `set_acl`, `token_sid` and `sid_string` are copies of the
//! lifecycle's `winsys.rs`, which keeps its own for the pipe and the data
//! directory; a shared Windows crate when a third user appears.

use std::io;
use std::path::Path;

use windows::core::{HSTRING, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SetNamedSecurityInfoW,
    SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, TokenUser, ACL,
    DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

struct Sd(PSECURITY_DESCRIPTOR);

impl Sd {
    fn from_sddl(sddl: &str) -> io::Result<Self> {
        let mut sd = PSECURITY_DESCRIPTOR::default();
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                &HSTRING::from(sddl),
                SDDL_REVISION_1,
                &mut sd,
                None,
            )
        }
        .map_err(io::Error::other)?;
        Ok(Sd(sd))
    }
}

impl Drop for Sd {
    fn drop(&mut self) {
        unsafe { LocalFree(Some(HLOCAL(self.0 .0))) };
    }
}

/// The tenant package folder (`admin setup --out`): SYSTEM, Administrators
/// and the account running setup, protected from inheritance, applied to
/// what is already in it. Under `C:\` it would otherwise inherit
/// `Users:(RX)`, so anyone reads the tenant's broker key, and `Authenticated
/// Users:(M)`, so anyone edits `Install-Sluse.ps1`, which Intune runs as
/// SYSTEM on every device (found on L1, 2026-09-30). The owner is left alone:
/// it is the account that made the folder.
pub fn protect_package(dir: &Path) -> io::Result<()> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.map_err(io::Error::other)?;
    let me = token_sid(token);
    unsafe { CloseHandle(token) }.ok();
    set_acl(dir, &format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{})", me?), false)
}

/// `sddl`'s DACL, protected, on `path`, and its owner too when `owner`.
fn set_acl(path: &Path, sddl: &str, owner: bool) -> io::Result<()> {
    let sd = Sd::from_sddl(sddl)?;
    let mut sd_owner = PSID::default();
    let mut defaulted = false.into();
    if owner {
        unsafe { GetSecurityDescriptorOwner(sd.0, &mut sd_owner, &mut defaulted) }.map_err(io::Error::other)?;
    }
    let mut present = false.into();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) }
        .map_err(io::Error::other)?;
    let path = HSTRING::from(path.as_os_str());
    let what = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let (what, sd_owner) = if owner { (what | OWNER_SECURITY_INFORMATION, Some(sd_owner)) } else { (what, None) };
    unsafe { SetNamedSecurityInfoW(&path, SE_FILE_OBJECT, what, sd_owner, None, Some(dacl), None) }
    .ok()
    .map_err(io::Error::other)
}

fn token_sid(token: HANDLE) -> io::Result<String> {
    let mut buf = vec![0u8; 256];
    let mut len = 0u32;
    unsafe { GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut len) }
        .map_err(io::Error::other)?;
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    sid_string(user.User.Sid)
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut s = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut s) }.map_err(io::Error::other)?;
    let out = unsafe { s.to_string() }.map_err(io::Error::other);
    unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
    out
}

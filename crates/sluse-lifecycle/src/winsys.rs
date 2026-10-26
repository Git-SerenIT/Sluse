// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The Win32 half of the service: the pipe, who is on the other end of it,
//! the Gate's job object, and the data directory's ACL.
//!
//! Every `unsafe` block here is a plain Win32 call with its handles owned by
//! this module. None of it runs on the development guest (D-011), and none of
//! it is verified by the guest's suite.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;

use windows::core::{HSTRING, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, ERROR_PIPE_CONNECTED, HANDLE, HANDLE_FLAG_INHERIT, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::{
    CheckTokenMembership, CreateWellKnownSid, WinBuiltinAdministratorsSid, SECURITY_MAX_SID_SIZE,
    GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation, RevertToSelf,
    TokenUser, ACL, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientSessionId, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::RemoteDesktop::WTSQueryUserToken;
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};

/// SYSTEM has everything; interactive users and elevated administrators may
/// read and write. Nobody else, and nothing from the network
/// (`PIPE_REJECT_REMOTE_CLIENTS`). Administrators, because a service logon or
/// an admin's tooling is not interactive, and an administrator can already do
/// everything the pipe offers.
///
/// **Read and write without `FILE_CREATE_PIPE_INSTANCE`.** `0x12019b` is
/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE` less `FILE_APPEND_DATA` (0x4),
/// which on a pipe is the right to create another instance of it. With `GW`
/// any interactive user could add instances owned by SYSTEM, pass the shell's
/// owner check, and be handed another user's sign-in code (review R-06).
/// Clients open with [`PIPE_CLIENT_ACCESS`], within this.
const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;0x12019b;;;IU)(A;;0x12019b;;;BA)";

/// What a pipe client asks for: `FILE_GENERIC_READ | FILE_WRITE_DATA`. Asking
/// for `GENERIC_WRITE`, which `OpenOptions::write` does, would be refused by
/// [`PIPE_SDDL`].
pub const PIPE_CLIENT_ACCESS: u32 = 0x0012_008b;

/// The data directory: owned by Administrators, SYSTEM and Administrators
/// only, inherited by everything under it. `ProgramData`'s default ACL lets
/// any user create a folder there, so a folder a user made first would be
/// theirs, config and all.
const ROOT_SDDL: &str = "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

/// A security descriptor from SDDL, freed on drop.
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

/// Accept connections on `name` for ever, handing each to `handle` on its own
/// thread. Fails if another process already owns the name
/// (`FILE_FLAG_FIRST_PIPE_INSTANCE`), rather than serving beside a squatter.
///
/// **The name always has a listening instance of ours.** The next instance is
/// created before a connected one is handed off, and a failed connect is
/// retried on the same instance. Until review R-06 a failed connect closed the
/// only instance, which freed the name for anyone to take.
pub fn serve_pipe(name: &str, handle: impl Fn(File) + Send + Sync + 'static) -> io::Result<()> {
    let sd = Sd::from_sddl(PIPE_SDDL)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0 .0,
        bInheritHandle: false.into(),
    };
    let handle = std::sync::Arc::new(handle);
    let wide = HSTRING::from(name);
    let create = |first: bool| -> io::Result<HANDLE> {
        let mode = if first { PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE } else { PIPE_ACCESS_DUPLEX };
        let pipe = unsafe {
            CreateNamedPipeW(
                &wide,
                mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                4096,
                4096,
                0,
                Some(&sa),
            )
        };
        if pipe.is_invalid() {
            return Err(io::Error::last_os_error());
        }
        Ok(pipe)
    };
    let mut pipe = create(true)?;
    loop {
        // A client that connected between create and connect is connected.
        if let Err(e) = unsafe { ConnectNamedPipe(pipe, None) } {
            if e.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                // A client that left before it was served: reset this
                // instance and listen on it again, never giving up the name.
                unsafe { DisconnectNamedPipe(pipe) }.ok();
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            }
        }
        let next = create(false)?;
        let conn = unsafe { File::from_raw_handle(pipe.0) };
        let handle = handle.clone();
        std::thread::spawn(move || handle(conn));
        pipe = next;
    }
}

/// Who is on the other end of `conn`: their SID, and whether their token
/// holds Administrators **enabled**, which means elevated: a UAC-filtered
/// token holds it deny-only.
///
/// By impersonation, not by the client's pid, which can exit and be reused.
/// Windows allows it only after the server has read from the pipe, so the
/// caller reads the request first.
pub fn client_identity(conn: &File) -> io::Result<crate::service::Caller> {
    let pipe = HANDLE(conn.as_raw_handle());
    let mut session = 0u32;
    unsafe { GetNamedPipeClientSessionId(pipe, &mut session) }.map_err(io::Error::other)?;
    unsafe { ImpersonateNamedPipeClient(pipe) }.map_err(io::Error::other)?;
    let mut token = HANDLE::default();
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
    // Back to SYSTEM before anything else can go wrong.
    unsafe { RevertToSelf() }.map_err(io::Error::other)?;
    opened.map_err(io::Error::other)?;

    let result = (|| {
        let sid = token_sid(token)?;

        let mut admins = [0u8; SECURITY_MAX_SID_SIZE as usize];
        let mut size = admins.len() as u32;
        unsafe { CreateWellKnownSid(WinBuiltinAdministratorsSid, None, Some(PSID(admins.as_mut_ptr().cast())), &mut size) }
            .map_err(io::Error::other)?;
        let mut member = false.into();
        unsafe { CheckTokenMembership(Some(token), PSID(admins.as_mut_ptr().cast()), &mut member) }
            .map_err(io::Error::other)?;
        Ok(crate::service::Caller { sid, admin: member.as_bool(), session })
    })();
    unsafe { CloseHandle(token) }.ok();
    result
}

fn token_sid(token: HANDLE) -> io::Result<String> {
    let mut buf = vec![0u8; 256];
    let mut len = 0u32;
    unsafe { GetTokenInformation(token, TokenUser, Some(buf.as_mut_ptr().cast()), buf.len() as u32, &mut len) }
        .map_err(io::Error::other)?;
    let user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    sid_string(user.User.Sid)
}

/// The signed-in user's own token, for the Gate to write Sluse Artifacts as
/// them (D-031), and **inheritable**, because that is how it reaches the Gate.
///
/// From the caller's logon session, because the pipe cannot give it: the shell
/// opens the pipe at identification level, so the service learns who is asking
/// and cannot act as them through it. SYSTEM can take any session's token
/// (`WTSQueryUserToken`) whatever the pipe says; that is SYSTEM's, not a grant
/// from the shell. Refused when the session's user is not the caller, such as
/// a shell started with `runas` as someone else: their box's artifacts would
/// land in the wrong profile.
///
/// ponytail: inheritable from here until the caller drops it after the spawn,
/// so a child another thread spawns meanwhile (a Hyper-V call) inherits it too.
/// That child is SYSTEM already and gains nothing; a handle list per spawn
/// (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) closes it if it ever matters.
pub fn session_token(session: u32, sid: &str) -> io::Result<OwnedHandle> {
    let mut raw = HANDLE::default();
    unsafe { WTSQueryUserToken(session, &mut raw) }
        .map_err(|e| io::Error::other(format!("the token of session {session}: {e}")))?;
    let token = unsafe { OwnedHandle::from_raw_handle(raw.0) };
    let owner = token_sid(raw)?;
    if owner != sid {
        return Err(io::Error::other(format!("session {session} is signed in as {owner}, and the box is {sid}'s")));
    }
    unsafe { SetHandleInformation(raw, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }.map_err(io::Error::other)?;
    Ok(token)
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut s = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut s) }.map_err(io::Error::other)?;
    let out = unsafe { s.to_string() }.map_err(io::Error::other);
    unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
    out
}

/// A job that kills everything in it when the service's last handle to it
/// closes, which is when the service exits for any reason. So a Gate never
/// outlives the service that started it and holds the port against the next.
pub struct KillOnClose(HANDLE);

// The handle is only ever used to assign a process and to be closed.
unsafe impl Send for KillOnClose {}
unsafe impl Sync for KillOnClose {}

impl KillOnClose {
    pub fn new() -> io::Result<Self> {
        let job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }.map_err(io::Error::other)?;
        let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        }
        .map_err(io::Error::other)?;
        Ok(KillOnClose(job))
    }

    pub fn assign(&self, child: &std::process::Child) -> io::Result<()> {
        let process = HANDLE(child.as_raw_handle());
        unsafe { AssignProcessToJobObject(self.0, process) }.map_err(io::Error::other)
    }
}

impl Drop for KillOnClose {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) }.ok();
    }
}

/// Take the data directory: owner Administrators, SYSTEM and Administrators
/// only, protected from inheritance; then everything under it
/// ([`reclaim_tree`]).
///
/// `ponytail:` the MSI creates the directory right (slice 5); this closes the
/// gap before it exists, and on a machine where someone made the folder first.
pub fn protect_root(root: &Path) -> io::Result<()> {
    std::fs::create_dir_all(root)?;
    set_acl(root, ROOT_SDDL, true, true)?;
    reclaim_tree(root);
    Ok(())
}

/// What a standard user made under the data directory before Sluse did is
/// taken back (review R-05). The root's ACL alone left a child's own ACEs and
/// owner in place: a user who made `certs\` first, with an inheritable ACE of
/// their own, could read the client CA's key once SYSTEM wrote it.
///
/// - **A link** (junction, symlink) anywhere is removed, never followed.
/// - **`certs\` and `images\`** are SYSTEM's own material: if anything in one
///   is owned by anyone but SYSTEM or Administrators, the folder is removed,
///   and the service makes it again (the certificates at the next open, the
///   base in the background). A planted CA or base is the attack, not a file
///   to repair.
/// - **Everything else** gets owner Administrators where its owner was
///   anyone else, and loses every ACE whose trustee is not on
///   [`crate::console::admins_only`]'s list, inheriting the root's again.
///   Not a reset of the tree: a VM's own ACE on its disks stays, and a reset
///   removed it on L1 (2026-10-06).
///
/// An elevated administrator's own files (`sluse box adopt`) may be owned by
/// that user rather than the group; elsewhere they are re-owned, not removed.
fn reclaim_tree(root: &Path) {
    for own in ["certs", "images"] {
        let dir = root.join(own);
        if dir.exists() && !trusted_tree(&dir) {
            let gone = std::fs::remove_dir_all(&dir);
            crate::service::note(format_args!("{}: made by someone else; removed ({gone:?})", dir.display()));
        }
    }
    reclaim_dir(root);
}

fn reclaim_dir(dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if let Err(e) = reclaim(&path) {
            crate::service::note(format_args!("{}: not taken back: {e}", path.display()));
        }
    }
}

/// `FILE_ATTRIBUTE_REPARSE_POINT` and `FILE_ATTRIBUTE_DIRECTORY`.
const REPARSE: u32 = 0x400;
const DIRECTORY: u32 = 0x10;

fn attributes(path: &Path) -> io::Result<u32> {
    use std::os::windows::fs::MetadataExt;
    Ok(std::fs::symlink_metadata(path)?.file_attributes())
}

fn reclaim(path: &Path) -> io::Result<()> {
    let attrs = attributes(path)?;
    if attrs & REPARSE != 0 {
        crate::service::note(format_args!("{}: a link in the data directory; removed", path.display()));
        return if attrs & DIRECTORY != 0 { std::fs::remove_dir(path) } else { std::fs::remove_file(path) };
    }
    let (trusted, dacl) = owner_and_dacl(path)?;
    let wanted = crate::console::admins_only(&dacl);
    if !trusted || wanted != dacl {
        set_acl(path, &format!("O:BA{wanted}"), !trusted, false)?;
    }
    if attrs & DIRECTORY != 0 {
        reclaim_dir(path);
    }
    Ok(())
}

/// Whether nothing under `dir`, itself included, is a link or owned by
/// anyone but SYSTEM or Administrators.
fn trusted_tree(dir: &Path) -> bool {
    let ok = |p: &Path| attributes(p).is_ok_and(|a| a & REPARSE == 0) && owner_and_dacl(p).is_ok_and(|(t, _)| t);
    if !ok(dir) {
        return false;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return false };
    entries.flatten().all(|e| {
        let p = e.path();
        if attributes(&p).is_ok_and(|a| a & DIRECTORY != 0 && a & REPARSE == 0) { trusted_tree(&p) } else { ok(&p) }
    })
}

/// Whether `path`'s owner is SYSTEM or Administrators, and its DACL in SDDL.
fn owner_and_dacl(path: &Path) -> io::Result<(bool, String)> {
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
    };
    use windows::Win32::Security::{IsWellKnownSid, WinLocalSystemSid};
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let wide = HSTRING::from(path.as_os_str());
    unsafe {
        GetNamedSecurityInfoW(
            &wide,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut sd,
        )
    }
    .ok()
    .map_err(io::Error::other)?;
    let held = Sd(sd);
    let trusted = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid).as_bool() || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
    };
    let mut s = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(held.0, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut s, None)
    }
    .map_err(io::Error::other)?;
    let sddl = unsafe { s.to_string() }.map_err(io::Error::other);
    unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
    Ok((trusted, sddl?))
}

/// `sddl`'s DACL on `path`, and its owner too when `owner`. `protect`: the
/// DACL stands alone, as the root's does; otherwise it inherits the parent's
/// as well.
fn set_acl(path: &Path, sddl: &str, owner: bool, protect: bool) -> io::Result<()> {
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
    let what = DACL_SECURITY_INFORMATION
        | if protect { PROTECTED_DACL_SECURITY_INFORMATION } else { UNPROTECTED_DACL_SECURITY_INFORMATION };
    let (what, sd_owner) = if owner { (what | OWNER_SECURITY_INFORMATION, Some(sd_owner)) } else { (what, None) };
    unsafe { SetNamedSecurityInfoW(&path, SE_FILE_OBJECT, what, sd_owner, None, Some(dacl), None) }
    .ok()
    .map_err(io::Error::other)
}

/// Under the SCM a service has no stderr, and what it writes is lost: point
/// it at `path`, appended. Started from a console, it keeps the console.
/// `std` looks the handle up at every write, so `eprintln!` follows.
pub fn stderr_to_file_if_none(path: &Path) -> io::Result<()> {
    use std::os::windows::io::IntoRawHandle;
    use windows::Win32::System::Console::{GetStdHandle, SetStdHandle, STD_ERROR_HANDLE};
    if unsafe { GetStdHandle(STD_ERROR_HANDLE) }.is_ok_and(|h| !h.is_invalid() && !h.0.is_null()) {
        return Ok(());
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let f = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
    unsafe { SetStdHandle(STD_ERROR_HANDLE, HANDLE(f.into_raw_handle())) }.map_err(io::Error::other)
}

/// Rewrite the DACL of the pipe `f` is open on to `console::admins_only` of
/// itself (D-030 point 4). Needs `f` opened with `WRITE_DAC`.
pub fn pipe_admins_only(f: &File) -> io::Result<()> {
    use windows::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SetSecurityInfo, SE_KERNEL_OBJECT,
    };
    let h = HANDLE(f.as_raw_handle());
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe { GetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, None, None, None, None, Some(&mut sd)) }
        .ok()
        .map_err(io::Error::other)?;
    let current = Sd(sd);
    let mut s = PWSTR::null();
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(current.0, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut s, None)
    }
    .map_err(io::Error::other)?;
    let sddl = unsafe { s.to_string() }.map_err(io::Error::other);
    unsafe { LocalFree(Some(HLOCAL(s.0.cast()))) };
    let sddl = sddl?;
    let wanted = crate::console::admins_only(&sddl);
    if wanted == sddl {
        return Ok(());
    }
    let sd = Sd::from_sddl(&wanted)?;
    let mut present = false.into();
    let mut defaulted = false.into();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) }.map_err(io::Error::other)?;
    unsafe { SetSecurityInfo(h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, None, None, Some(dacl), None) }
        .ok()
        .map_err(io::Error::other)
}

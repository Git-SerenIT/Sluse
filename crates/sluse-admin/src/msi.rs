// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! An MSI's product code and version, read from its Property table, for the
//! MSI app's detection rule in Intune (D-037 point 2). Windows Installer's
//! own API; setup runs on Windows.

use crate::intune::Msi;

#[cfg(windows)]
pub fn info(path: &std::path::Path) -> Result<Msi, String> {
    use windows::core::HSTRING;
    use windows::Win32::System::ApplicationInstallationAndServicing::{
        MsiCloseHandle, MsiDatabaseOpenViewW, MsiOpenDatabaseW, MsiRecordGetStringW, MsiViewExecute, MsiViewFetch,
        MSIDBOPEN_READONLY, MSIHANDLE,
    };
    const OK: u32 = 0;

    /// Closed when it goes, whatever returns first.
    struct Handle(MSIHANDLE);
    impl Drop for Handle {
        fn drop(&mut self) {
            if self.0 .0 != 0 {
                unsafe { MsiCloseHandle(self.0) };
            }
        }
    }

    let mut db = Handle(MSIHANDLE(0));
    let r = unsafe { MsiOpenDatabaseW(&HSTRING::from(path.as_os_str()), MSIDBOPEN_READONLY, &mut db.0) };
    if r != OK {
        return Err(format!("{} is not an MSI Windows Installer can open (error {r})", path.display()));
    }
    let property = |name: &str| -> Result<String, String> {
        let mut view = Handle(MSIHANDLE(0));
        let q = HSTRING::from(format!("SELECT `Value` FROM `Property` WHERE `Property`='{name}'"));
        let r = unsafe { MsiDatabaseOpenViewW(db.0, &q, &mut view.0) };
        if r != OK || unsafe { MsiViewExecute(view.0, MSIHANDLE(0)) } != OK {
            return Err(format!("{}: the Property table (error {r})", path.display()));
        }
        let mut rec = Handle(MSIHANDLE(0));
        if unsafe { MsiViewFetch(view.0, &mut rec.0) } != OK {
            return Err(format!("{} has no {name}", path.display()));
        }
        let mut buf = vec![0u16; 256];
        let mut len = buf.len() as u32;
        let r = unsafe { MsiRecordGetStringW(rec.0, 1, Some(windows::core::PWSTR(buf.as_mut_ptr())), Some(&mut len as *mut u32)) };
        if r != OK {
            return Err(format!("{}: {name} (error {r})", path.display()));
        }
        Ok(String::from_utf16_lossy(&buf[..len as usize]))
    };
    Ok(Msi { product_code: property("ProductCode")?, version: property("ProductVersion")? })
}

#[cfg(not(windows))]
pub fn info(path: &std::path::Path) -> Result<Msi, String> {
    Err(format!("reading {} needs Windows Installer, which is Windows only", path.display()))
}

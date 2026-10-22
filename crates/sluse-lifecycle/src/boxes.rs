// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Which box is whose: `%ProgramData%\Sluse\boxes\<sid>\box.json`, one box
//! per Windows user (D-027 design point 3).
//!
//! Written by `sluse box adopt` for a box that already exists (slice 1), and
//! by the image build later (slice 3). Read by the service, which learns the
//! SID from the pipe and never from a request.

use std::io;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BoxRecord {
    /// The Hyper-V VM's name.
    pub vm: String,
    /// The box's address on the host-only segment.
    pub address: Ipv4Addr,
    /// The base its system disk stands on, as a file name in `images\`.
    /// `None` for a box that was adopted, not made (slice 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// The work account its Hyper-V notes name (Q67), once a sign-in said
    /// who; `None` while they name the Windows account.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub named: Option<String>,
}

/// `%ProgramData%\Sluse`, the service's data directory. SYSTEM and
/// Administrators only (`winsys::protect_root`).
pub fn data_root() -> PathBuf {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Sluse")
}

/// Whether `s` is a SID string. It becomes a directory name.
pub fn valid_sid(s: &str) -> bool {
    s.len() <= 184
        && s.strip_prefix("S-1-")
            .is_some_and(|rest| rest.split('-').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())))
}

/// A VM name the Hyper-V script will take (it checks the same).
pub fn valid_vm(s: &str) -> bool {
    (1..=64).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
}

fn path(root: &Path, sid: &str) -> io::Result<PathBuf> {
    if !valid_sid(sid) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not a SID: {sid:?}")));
    }
    Ok(root.join("boxes").join(sid).join("box.json"))
}

pub fn load(root: &Path, sid: &str) -> io::Result<Option<BoxRecord>> {
    match std::fs::read(path(root, sid)?) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(io::Error::other),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn save(root: &Path, sid: &str, rec: &BoxRecord) -> io::Result<PathBuf> {
    if !valid_vm(&rec.vm) {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not a VM name: {:?}", rec.vm)));
    }
    let p = path(root, sid)?;
    std::fs::create_dir_all(p.parent().expect("has a parent"))?;
    std::fs::write(&p, serde_json::to_vec_pretty(rec).map_err(io::Error::other)?)?;
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_round_trips_under_its_sid_and_nothing_else_is_a_sid() {
        let dir = tempfile::tempdir().unwrap();
        let sid = "S-1-12-1-1234567-890-12345-6789";
        assert_eq!(load(dir.path(), sid).unwrap(), None);
        let rec = BoxRecord { vm: "sluse-box".into(), address: Ipv4Addr::new(192, 168, 77, 10), base: None, named: None };
        save(dir.path(), sid, &rec).unwrap();
        assert_eq!(load(dir.path(), sid).unwrap(), Some(rec.clone()));
        for bad in ["", "S-1-", "S-1-5-..", r"S-1-5\..\x", "S-1-5-18-", "x-1-5-18"] {
            assert!(!valid_sid(bad), "{bad:?}");
            assert!(load(dir.path(), bad).is_err());
        }
        let bad_vm = BoxRecord { vm: "a'b".into(), ..rec };
        assert!(save(dir.path(), sid, &bad_vm).is_err());
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Error classification derived from Chaperone crates/chapr-endpoint/src/mount.rs
// and its share-availability handling. D-003 allows reuse, not vendoring.

//! An SMB share, addressed by UNC.
//!
//! The operations are the local ones — a UNC path is a path to Win32. What is
//! different, and what this file is for, is that a share can be *absent* in ways
//! a local directory cannot, and those have to be told apart in the record:
//!
//! - The agent asked for a file that is not there. **`NotFound`.** Ordinary.
//! - The user may not have it. **`AccessDenied`.** Invariant 8 working, not a
//!   fault: the broker acts as the user and the share said no.
//! - The server is not answering, the session was dropped, the credential has
//!   expired. **`SourceUnavailable`.** Nothing about the request was wrong and
//!   the same request may succeed in a minute.
//!
//! Collapsing the third into the first would tell a person that a file they can
//! see in Explorer does not exist, and a rate of `not_found` that is really a
//! flapping share is a metric that lies. The Win32 error codes are matched
//! explicitly because `io::ErrorKind` does not distinguish them.
//!
//! **Built now, exercised at M6** (jok's call at M2): every M2 test runs against
//! local temp trees, and the UNC test is `#[ignore]`d until
//! `\\FS01\share\sluse-fixture` exists and IT has been told.

use std::path::Path;

use sluse_proto::SluseError;

use super::{fsops, local_error, Meta, RawEntry, SourceBackend};

/// Which of the two lists a failure falls in, if either.
///
/// Returned rather than matched inline because **scope resolution needs the
/// same answer** and used not to have it: `scope::io_to_error` ran before any
/// backend and classified on `io::ErrorKind` alone, so a dead share became
/// `NotFound` and was blinded (D-015). The lists were always right; only this
/// caller was missing.
pub(crate) enum Win32 {
    Unavailable(i32),
    Refused(i32),
}

pub(crate) fn classify(e: &std::io::Error) -> Option<Win32> {
    match e.raw_os_error() {
        Some(code) if UNAVAILABLE.contains(&code) => Some(Win32::Unavailable(code)),
        Some(code) if REFUSED.contains(&code) => Some(Win32::Refused(code)),
        _ => None,
    }
}

/// Win32 codes that mean the share, not the file, is the problem.
///
/// From winerror.h. Listed rather than ranged: a range would quietly acquire
/// meanings as Windows adds codes, and this list is the difference between two
/// audit outcomes.
const UNAVAILABLE: &[i32] = &[
    51,   // ERROR_REM_NOT_LIST — the remote computer is not available
    52,   // ERROR_DUP_NAME
    53,   // ERROR_BAD_NETPATH — the network path was not found
    54,   // ERROR_NETWORK_BUSY
    55,   // ERROR_DEV_NOT_EXIST — the share is no longer available
    59,   // ERROR_UNEXP_NET_ERR
    64,   // ERROR_NETNAME_DELETED — the session was dropped underneath us
    67,   // ERROR_BAD_NET_NAME — no such share
    1231, // ERROR_NETWORK_UNREACHABLE
    1232, // ERROR_HOST_UNREACHABLE
    1311, // ERROR_NO_LOGON_SERVERS
];

/// Win32 codes that mean the user was refused, which is not an error.
const REFUSED: &[i32] = &[
    1326, // ERROR_LOGON_FAILURE — the stored credential no longer works
    1327, // ERROR_ACCOUNT_RESTRICTION
    1331, // ERROR_ACCOUNT_DISABLED
    1907, // ERROR_PASSWORD_MUST_CHANGE
    1909, // ERROR_ACCOUNT_LOCKED_OUT
];

#[derive(Debug)]
pub struct Smb {
    source_name: String,
}

impl Smb {
    pub fn new(source_name: String) -> Self {
        Self { source_name }
    }

    fn err(&self, raw: &str, abs: &Path, e: &std::io::Error) -> SluseError {
        match classify(e) {
            Some(Win32::Unavailable(code)) => SluseError::SourceUnavailable {
                source_name: self.source_name.clone(),
                detail: format!("{e} (win32 {code})"),
            },
            Some(Win32::Refused(code)) => SluseError::AccessDenied {
                raw: raw.to_owned(),
                detail: format!("{e} (win32 {code})"),
            },
            // Everything else classifies exactly as a local path would.
            None => local_error(&self.source_name, raw, abs, e),
        }
    }
}

impl SourceBackend for Smb {
    fn kind(&self) -> &'static str {
        "smb"
    }

    fn list(&self, raw: &str, abs: &Path) -> Result<Vec<RawEntry>, SluseError> {
        fsops::list(abs).map_err(|e| self.err(raw, abs, &e))
    }

    fn stat(&self, raw: &str, abs: &Path) -> Result<Meta, SluseError> {
        fsops::stat(abs).map_err(|e| self.err(raw, abs, &e))
    }

    fn open(&self, raw: &str, abs: &Path) -> Result<tokio::fs::File, SluseError> {
        fsops::open(abs).map_err(|e| self.err(raw, abs, &e))
    }
}

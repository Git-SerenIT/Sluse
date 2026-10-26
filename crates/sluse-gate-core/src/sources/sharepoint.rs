// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A SharePoint document library, **as the filesystem trait sees it: not at
//! all.**
//!
//! Since M7 a `sharepoint` source is served by [`crate::remote`], over Graph and
//! as the signed-in user, and the routes branch to it before any backend is
//! consulted. This implementation remains so that [`super::backend_for`] stays
//! total and a caller that reached the trait by mistake gets
//! [`SluseError::UnsupportedSourceKind`] — an error, not a refusal — rather than
//! a filesystem read against a path that is a URL.

use std::path::Path;

use sluse_proto::SluseError;

use super::{Meta, RawEntry, SourceBackend};

#[derive(Debug)]
pub struct SharePoint {
    source_name: String,
    kind: &'static str,
}

impl SharePoint {
    pub fn new(source_name: String) -> Self {
        Self { source_name, kind: "sharepoint" }
    }

    /// The user's OneDrive `Sluse` folder (D-054), served by the same route.
    pub fn onedrive(source_name: String) -> Self {
        Self { source_name, kind: "onedrive" }
    }

    fn unsupported(&self) -> SluseError {
        SluseError::UnsupportedSourceKind {
            source_name: self.source_name.clone(),
            kind: self.kind.to_owned(),
        }
    }
}

impl SourceBackend for SharePoint {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn list(&self, _raw: &str, _abs: &Path) -> Result<Vec<RawEntry>, SluseError> {
        Err(self.unsupported())
    }

    fn stat(&self, _raw: &str, _abs: &Path) -> Result<Meta, SluseError> {
        Err(self.unsupported())
    }

    fn open(&self, _raw: &str, _abs: &Path) -> Result<tokio::fs::File, SluseError> {
        Err(self.unsupported())
    }
}

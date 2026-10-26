// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A directory on the machine Gate Core runs on.
//!
//! **The LOCAL fixture, and nothing a customer would deploy.** It exists so the
//! prototype can be exercised without a share; its presence in a real config
//! would mean Gate Core and the data are on the same machine, which is the
//! arrangement Sluse exists to replace. `docs/config.md` says so, and this
//! comment is here because the file is the easiest one in the crate to copy.

use std::path::Path;

use sluse_proto::SluseError;

use super::{fsops, local_error, Meta, RawEntry, SourceBackend};

#[derive(Debug)]
pub struct LocalFolder {
    source_name: String,
    kind: &'static str,
}

impl LocalFolder {
    pub fn new(source_name: String) -> Self {
        Self { source_name, kind: "local-folder" }
    }

    /// The user's Sluse Inputs (D-054): a directory on the device, read the
    /// same way, and the one local folder a customer does deploy.
    pub fn inputs(source_name: String) -> Self {
        Self { source_name, kind: "inputs" }
    }
}

impl SourceBackend for LocalFolder {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn list(&self, raw: &str, abs: &Path) -> Result<Vec<RawEntry>, SluseError> {
        fsops::list(abs).map_err(|e| local_error(&self.source_name, raw, abs, &e))
    }

    fn stat(&self, raw: &str, abs: &Path) -> Result<Meta, SluseError> {
        fsops::stat(abs).map_err(|e| local_error(&self.source_name, raw, abs, &e))
    }

    fn open(&self, raw: &str, abs: &Path) -> Result<tokio::fs::File, SluseError> {
        fsops::open(abs).map_err(|e| local_error(&self.source_name, raw, abs, &e))
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! `sluse-gate-front`: started by its parent with the channel as its stdin and
//! stdout (D-071). It takes no arguments and reads no file: it asks its parent
//! what to run, runs it, and stops when its parent goes. **Nothing else may
//! write to stdout**; what it says goes to stderr, its log.

use std::process::ExitCode;

fn main() -> ExitCode {
    sluse_gate_front::tls::install_provider();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async {
        let io = tokio::io::join(tokio::io::stdin(), tokio::io::stdout());
        let (parent, connection) = match sluse_gate_front::ipc::connect(io).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        };
        let connection = tokio::spawn(connection);
        let start = match parent.start().await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("{e}");
                return ExitCode::from(1);
            }
        };
        tokio::select! {
            r = sluse_gate_front::run(start, parent) => {
                eprintln!("stopped: {}", r.err().unwrap_or_else(|| "a listener ended".into()));
                ExitCode::from(1)
            }
            _ = connection => {
                // The parent is gone, and Front with it.
                ExitCode::SUCCESS
            }
        }
    })
}

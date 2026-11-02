// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The box's console, drawn by this program rather than a browser (D-079).
//!
//! It makes the console's calls ([`sluse_endpoint::console::Console`]) in its
//! own process: there is no port for anything else in the box to call. The
//! look and the frame are 0.3's slice 2; the pages are slice 3
//! (`docs/sluse_prototype.md`).
//!
//! It starts with the kiosk, before the box has enrolled, so it waits: it
//! joins the run once the config is there and the Gate answers, and joins
//! again when the config changes, which is a new enrolment.

#[cfg(target_os = "linux")]
mod app;
#[cfg(target_os = "linux")]
mod icons;
#[cfg(target_os = "linux")]
mod look;
#[cfg(target_os = "linux")]
mod pages;
#[cfg(target_os = "linux")]
mod widgets;
#[cfg(target_os = "linux")]
mod words;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    // First, as in the endpoint: with two crypto providers linked, rustls
    // refuses to guess which is the default and panics on the first handshake.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "sluse_console=info,sluse_endpoint=info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match app::run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sluse-console: {e}");
            std::process::ExitCode::from(1)
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("sluse-console draws in the box, which is Linux; there is no console here.");
    std::process::ExitCode::from(2)
}

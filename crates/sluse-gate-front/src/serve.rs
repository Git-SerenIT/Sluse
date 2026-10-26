// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from Chaperone chapr-coord/src/main.rs:406-453 (explicit bind before
// ready, then serve over the bound listener).

//! Binding and serving.
//!
//! **The socket is bound before anything is told the Gate is up.** The order
//! matters: `sluse start` and the service check the Gate is reachable straight
//! after starting Gate Core, which starts Front, and a Front that announced
//! readiness and then failed to bind would be reported as a failure with no
//! useful reason, or worse, raced into passing. Binding first means
//! "listening" is a fact by the time it is claimed, and an address in use is
//! an error at the moment it can still be explained.
//!
//! It also gives the ephemeral-port case for free. A test binds `127.0.0.1:0`
//! and reads back the port the OS chose — which is why [`bind`] takes the
//! address as an argument rather than reading `gate.listen` itself. The config
//! loader refuses port 0 in a config, correctly: a config with port 0 would
//! produce a Gate the endpoint's `gate.url` cannot name.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;

use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use axum_server::Handle;
use rustls::ServerConfig;

/// Bind a listener, and say what was actually bound.
///
/// `addr` is a `host:port` string. Pass `127.0.0.1:0` for an ephemeral port and
/// read the real one off the returned listener.
pub fn bind(addr: &str) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(addr)?;
    // Non-blocking is what tokio's accept loop needs; `from_tcp_rustls` sets it
    // too, and setting it here means a caller inspecting the listener between
    // bind and serve sees the same socket the server will.
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// A listener that is serving.
pub struct Running {
    pub addr: SocketAddr,
    handle: Handle<SocketAddr>,
}

impl Running {
    /// Stop accepting and let open connections finish.
    ///
    /// A read in flight is an admission in flight: cutting it mid-body would
    /// produce the truncated-read record for a shutdown rather than for a
    /// failure, which is a worse lie than taking the extra second.
    pub fn shutdown(&self) {
        self.handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
    }

    /// Stop now, without waiting.
    pub fn shutdown_now(&self) {
        self.handle.shutdown();
    }
}

/// Serve on an already-bound listener until shutdown.
///
/// Returns the [`Running`] handle and the task's join handle. The listener is
/// consumed, so there is no window in which something else could bind the same
/// port.
pub fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    router: Router,
) -> std::io::Result<(Running, tokio::task::JoinHandle<std::io::Result<()>>)> {
    let addr = listener.local_addr()?;
    let handle = Handle::new();

    let server = axum_server::from_tcp_rustls(listener, RustlsConfig::from_config(tls))?
        .handle(handle.clone());

    let task = tokio::spawn(async move { server.serve(router.into_make_service()).await });

    Ok((Running { addr, handle }, task))
}

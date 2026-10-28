// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Sluse Gate Front (D-071): everything the box can reach, without privilege
//! and without a token. One per box, started by its parent, Gate Core for an
//! open or the service for a base build, as LocalService on Windows. It
//! terminates the box's TLS, parses what the box sends, and runs the egress
//! proxy; it asks its parent for everything else (`sluse_proto::gate`).

pub mod ipc;
pub mod proxy;
pub mod relay;
pub mod serve;
pub mod testing;
pub mod tls;

use std::sync::Arc;

use sluse_proto::gate::{Claim, FrontStart};

use crate::ipc::Parent;

/// Bind what `start` names and serve until a listener fails. Every bind is
/// made before any serves, so a port in use fails the start at once.
pub async fn run(start: FrontStart, parent: Parent) -> Result<(), String> {
    let mut tasks = tokio::task::JoinSet::new();

    // The proxy's port first: once the Gate's answers, which is what the
    // service waits for, the box's way out is there too.
    let proxy_listener = match &start.proxy {
        Some(p) => Some(tokio::net::TcpListener::bind(&p.listen).await.map_err(|e| format!("{}: {e}", sluse_proto::ports::label(&p.listen)))?),
        None => None,
    };

    if let Some(g) = &start.gate {
        let pin = tls::LeafPin::default();
        let l = serve::bind(&g.listen).map_err(|e| format!("{}: {e}", sluse_proto::ports::label(&g.listen)))?;
        let (running, task) = serve::serve(l, tls::gate_config(g, pin.clone())?, relay::router(parent.clone())).map_err(|e| e.to_string())?;
        eprintln!("the Gate on https://{} (mTLS required)", running.addr);
        tasks.spawn(async move { task.await.map_err(|e| e.to_string()).and_then(|r| r.map_err(|e| e.to_string())) });
        if let Some(addr) = &g.enrol_listen {
            let l = serve::bind(addr).map_err(|e| format!("{}: {e}", sluse_proto::ports::label(addr)))?;
            let (running, task) = serve::serve(l, tls::enrol_config(g)?, relay::enrol_router(parent.clone(), pin)).map_err(|e| e.to_string())?;
            eprintln!("enrolment on https://{} (one route, no client certificate)", running.addr);
            tasks.spawn(async move { task.await.map_err(|e| e.to_string()).and_then(|r| r.map_err(|e| e.to_string())) });
        }
    }

    if let (Some(p), Some(listener)) = (start.proxy, proxy_listener) {
        let (to, refusals) = (parent.clone(), parent.clone());
        let connection: Box<dyn Fn(&serde_json::Value) + Send + Sync> = if p.log_connections {
            Box::new(move |v| to.claim(Claim::Connection(v.clone())))
        } else {
            Box::new(|_| {})
        };
        let records = proxy::Records { connection, refusal: Box::new(move |v| refusals.claim(Claim::EgressRefused(v.clone()))) };
        eprintln!("egress proxy on {}: {} allowed hosts", p.listen, p.allow.allow.len());
        let mut proxy = proxy::Proxy::new(p.allow, p.about, records);
        proxy.public_only = p.public_only;
        // A window host is the parent's to allow (D-075); a base build's
        // parent has no window, and answers no.
        let ask = parent.clone();
        proxy.window = Some(Box::new(move |host| {
            let ask = ask.clone();
            Box::pin(async move { ask.window(host).await })
        }));
        let proxy = Arc::new(proxy);
        tasks.spawn(async move { proxy.serve(listener).await.map_err(|e| format!("egress proxy: {e}")) });
    }

    match tasks.join_next().await {
        Some(Ok(r)) => r,
        Some(Err(e)) => Err(e.to_string()),
        None => Err("nothing to serve".to_owned()),
    }
}

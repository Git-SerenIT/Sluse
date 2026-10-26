// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A Front and a parent's router in one process, for tests: the channel is an
//! in-memory duplex, the relay and TLS are the real ones. Gate Core's tests
//! and the endpoint's run a real Core behind it, so what they prove goes
//! through Front as the product does.

use std::net::SocketAddr;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use sluse_proto::gate::FrontGate;

use crate::{ipc, relay, serve, tls};

/// What a test talks to.
pub struct Served {
    pub gate: serve::Running,
    /// Enrolment's listener, when `g.enrol_listen` named one.
    pub enrol: Option<serve::Running>,
}

impl Served {
    pub fn addr(&self) -> SocketAddr {
        self.gate.addr
    }
}

/// Serve `router` as Front's parent and `g` as Front. Bind `127.0.0.1:0` in
/// `g.listen` (and `g.enrol_listen`) for an ephemeral port.
pub async fn serve(g: FrontGate, router: axum::Router) -> Served {
    tls::install_provider();
    let (parent_side, front_side) = tokio::io::duplex(1 << 20);
    tokio::spawn(async move {
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(parent_side), TowerToHyperService::new(router))
            .await;
    });
    let (parent, connection) = ipc::connect(front_side).await.expect("the channel");
    tokio::spawn(connection);
    let pin = tls::LeafPin::default();
    let l = serve::bind(&g.listen).expect("bind the Gate");
    let (gate, _) = serve::serve(l, tls::gate_config(&g, pin.clone()).expect("the Gate's TLS"), relay::router(parent.clone()))
        .expect("serve the Gate");
    let enrol = g.enrol_listen.as_deref().map(|addr| {
        let l = serve::bind(addr).expect("bind enrolment");
        serve::serve(l, tls::enrol_config(&g).expect("enrolment's TLS"), relay::enrol_router(parent.clone(), pin.clone()))
            .expect("serve enrolment")
            .0
    });
    Served { gate, enrol }
}

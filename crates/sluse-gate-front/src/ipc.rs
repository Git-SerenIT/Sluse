// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Front's side of the channel to its parent (D-071, `sluse_proto::gate`):
//! HTTP/2 over its stdin and stdout, Front the client.

use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::client::conn::http2::SendRequest;
use hyper_util::rt::{TokioExecutor, TokioIo};
use sluse_proto::gate::{route, Claim, FrontStart};
use tokio::io::{AsyncRead, AsyncWrite};

/// The authority on every request to the parent. Only the path is read.
const AUTHORITY: &str = "http://gate";

/// The parent, Gate Core or the service. Cheap to clone.
#[derive(Clone)]
pub struct Parent {
    sender: SendRequest<Body>,
}

/// Connect over `io`. The second half runs the connection and ends when the
/// parent goes, and Front with it.
pub async fn connect<IO>(io: IO) -> Result<(Parent, impl std::future::Future<Output = ()>), String>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
        .await
        .map_err(|e| format!("the channel to Gate Core: {e}"))?;
    Ok((Parent { sender }, async move {
        if let Err(e) = conn.await {
            eprintln!("the channel to Gate Core: {e}");
        }
    }))
}

impl Parent {
    /// Send one request. `path_and_query` is `/v1/…` or `/front/…`.
    pub async fn send(&self, mut req: Request<Body>) -> Result<Response<Incoming>, String> {
        let pq = req.uri().path_and_query().map_or("/", |p| p.as_str()).to_owned();
        *req.uri_mut() = format!("{AUTHORITY}{pq}").parse().map_err(|e| format!("{pq}: {e}"))?;
        let mut sender = self.sender.clone();
        sender.ready().await.map_err(|e| format!("Gate Core: {e}"))?;
        sender.send_request(req).await.map_err(|e| format!("Gate Core: {e}"))
    }

    /// What Front runs on. Asked once, first.
    pub async fn start(&self) -> Result<FrontStart, String> {
        let req = Request::builder().method(Method::GET).uri(route::START).body(Body::empty()).map_err(|e| e.to_string())?;
        let res = self.send(req).await?;
        let status = res.status();
        let bytes = res.into_body().collect().await.map_err(|e| e.to_string())?.to_bytes();
        if status != StatusCode::OK {
            return Err(format!("Gate Core answered {status}: {}", String::from_utf8_lossy(&bytes)));
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("Front's start from Gate Core: {e}"))
    }

    /// Tell the parent what Front saw. Not waited on: a connection is not held
    /// up by its own record, and a parent that is gone takes Front with it.
    pub fn claim(&self, claim: Claim) {
        let me = self.clone();
        tokio::spawn(async move {
            let body = match serde_json::to_vec(&claim) {
                Ok(b) => b,
                Err(_) => return,
            };
            let req = Request::builder()
                .method(Method::POST)
                .uri(route::CLAIM)
                .header("content-type", "application/json")
                .body(Body::from(body));
            if let Ok(req) = req {
                if let Err(e) = me.send(req).await {
                    eprintln!("a claim did not reach Gate Core: {e}");
                }
            }
        });
    }
}

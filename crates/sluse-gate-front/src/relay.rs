// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The box's routes, parsed here and asked of Gate Core (D-071).
//!
//! **What Front does with a request:** only the routes the box has; a JSON
//! body parsed into its type, as Core would, and sent on as Front wrote it
//! again, so what reaches Core is a request Front could read; a query parsed
//! the same way and passed on; the session header and the content type, and no
//! other header. A request that does not parse is refused here, with the
//! rejection Core's own extractor gave before the split. **Core decides
//! everything else** (scope, sessions, records) and its answer comes back as
//! it was sent.
//!
//! ponytail: a publish's multipart body is passed on as a stream under the
//! size cap and parsed by Core, as before the split. Parse it here and send
//! Core the manifest and the files apart when publish next changes.

use axum::body::Body;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{HeaderMap, Method, Request, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sluse_proto::wire::{header, route, EnrolRequest, EnrolResponse, JournalAppend};
use sluse_proto::{AlertsQuery, AuditTailQuery, CallRequest, ListRequest, ReadRequest, SluseError, StatRequest};

use crate::ipc::Parent;
use crate::tls::LeafPin;

/// The most one delivery may carry (review R-11): both sides hold it.
const PUBLISH_LIMIT: usize = 256 * 1024 * 1024;
/// The most one journal mirror request may carry.
const JOURNAL_LIMIT: usize = 4 * 1024 * 1024;

/// The Gate's routes, for the box's endpoint and console.
pub fn router(parent: Parent) -> Router {
    Router::new()
        .route(route::HEALTH, get(bare))
        .route(route::STATUS, get(bare))
        .route(route::CONFIG_VIEW, get(bare))
        .route(route::SIGN_OUT, post(bare))
        .route(route::ALERTS, get(query::<AlertsQuery>))
        .route(route::AUDIT_TAIL, get(query::<AuditTailQuery>))
        .route(route::LIST, post(json::<ListRequest>))
        .route(route::READ, post(json::<ReadRequest>))
        .route(route::STAT, post(json::<StatRequest>))
        .route(route::JOURNAL, post(json::<JournalAppend>).layer(DefaultBodyLimit::max(JOURNAL_LIMIT)))
        .route(route::PUBLISH, post(publish).layer(DefaultBodyLimit::max(PUBLISH_LIMIT)))
        .route(route::TOOLS, get(bare))
        .route(route::CALL, post(json::<CallRequest>))
        .with_state(parent)
}

/// Enrolment's one route. Core checks the token and issues the leaf; Front
/// pins the leaf Core's answer carries.
pub fn enrol_router(parent: Parent, pin: LeafPin) -> Router {
    Router::new().route(route::ENROL, post(enrol)).with_state((parent, pin))
}

/// A request with no body to parse.
async fn bare(State(p): State<Parent>, method: Method, uri: Uri, headers: HeaderMap) -> Response {
    ask(&p, method, &uri, &headers, Body::empty()).await
}

/// A query, parsed and passed on as the box wrote it.
async fn query<Q: DeserializeOwned + Send>(State(p): State<Parent>, uri: Uri, headers: HeaderMap, Query(_): Query<Q>) -> Response {
    ask(&p, Method::GET, &uri, &headers, Body::empty()).await
}

/// A JSON body, parsed and written again.
async fn json<T: DeserializeOwned + Serialize + Send>(
    State(p): State<Parent>,
    uri: Uri,
    headers: HeaderMap,
    Json(body): Json<T>,
) -> Response {
    match serde_json::to_vec(&body) {
        Ok(b) => ask(&p, Method::POST, &uri, &headers, Body::from(b)).await,
        Err(e) => internal(&e.to_string()),
    }
}

async fn publish(State(p): State<Parent>, uri: Uri, headers: HeaderMap, body: Body) -> Response {
    // The cap holds on the stream: DefaultBodyLimit only bounds extractors.
    let body = Body::new(http_body_util::Limited::new(body, PUBLISH_LIMIT));
    ask(&p, Method::POST, &uri, &headers, body).await
}

async fn enrol(State((p, pin)): State<(Parent, LeafPin)>, uri: Uri, headers: HeaderMap, Json(req): Json<EnrolRequest>) -> Response {
    let body = match serde_json::to_vec(&req) {
        Ok(b) => b,
        Err(e) => return internal(&e.to_string()),
    };
    let res = match send(&p, Method::POST, &uri, &headers, Body::from(body)).await {
        Ok(r) => r,
        Err(r) => return *r,
    };
    let (parts, body) = res.into_parts();
    let bytes = match body.collect().await {
        Ok(b) => b.to_bytes(),
        Err(e) => return unreachable_core(&e.to_string()),
    };
    if parts.status == StatusCode::OK {
        // Core's answer is the decision; Front applies it. A second leaf for
        // the same open is not taken (D-058).
        if let Some(leaf) = serde_json::from_slice::<EnrolResponse>(&bytes).ok().and_then(|r| crate::tls::leaf(&r.cert_pem).ok()) {
            let _ = pin.set(leaf);
        }
    }
    Response::from_parts(parts, Body::from(bytes))
}

/// Ask Core and answer the box with what Core said.
async fn ask(p: &Parent, method: Method, uri: &Uri, headers: &HeaderMap, body: Body) -> Response {
    match send(p, method, uri, headers, body).await {
        Ok(r) => r.map(Body::new),
        Err(r) => *r,
    }
}

async fn send(
    p: &Parent,
    method: Method,
    uri: &Uri,
    headers: &HeaderMap,
    body: Body,
) -> Result<axum::http::Response<hyper::body::Incoming>, Box<Response>> {
    let pq = uri.path_and_query().map_or(uri.path(), |p| p.as_str());
    let mut req = Request::builder().method(method).uri(pq);
    for name in [header::SESSION, "content-type"] {
        if let Some(v) = headers.get(name) {
            req = req.header(name, v);
        }
    }
    let req = req.body(body).map_err(|e| Box::new(internal(&e.to_string())))?;
    p.send(req).await.map_err(|e| Box::new(unreachable_core(&e)))
}

fn unreachable_core(detail: &str) -> Response {
    let e = SluseError::GateUnreachable { detail: detail.to_owned() };
    (StatusCode::SERVICE_UNAVAILABLE, Json(e)).into_response()
}

fn internal(detail: &str) -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, detail.to_owned()).into_response()
}

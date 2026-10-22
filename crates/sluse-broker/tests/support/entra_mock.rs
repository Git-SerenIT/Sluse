// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A local stand-in for Entra and Graph, shared by the broker's and the
//! endpoint's M7 tests. Included by `#[path]`, not a crate: it is test code for
//! two test suites, and a crate for it would be scaffolding.
//!
//! It speaks the documented wire shapes and checks what Entra would check of
//! the broker as a public client (D-036) — the client id, the code, its PKCE
//! verifier and redirect, and that **no client assertion** is sent — and it
//! proves nothing about Entra itself. The test run against the demo tenant
//! does that.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use jsonwebtoken::jwk::{Jwk, JwkSet};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{json, Value};

pub const TENANT: &str = "11111111-2222-3333-4444-555555555555";
pub const CLIENT: &str = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
pub const ALICE: &str = "0a11ce00-0000-0000-0000-000000000001";
pub const BOB: &str = "0b0b0000-0000-0000-0000-000000000002";

// ---------------------------------------------------------------------------
// The stand-in
// ---------------------------------------------------------------------------

/// A code the stand-in issued: the ID token it redeems for, and the verifier
/// it must come with.
pub struct Issued {
    pub id_token: String,
    pub oid: String,
    pub verifier: String,
}

pub struct Mock {
    pub base: Mutex<String>,
    pub jwks: JwkSet,
    /// Codes not yet redeemed. One use each, as Entra's.
    pub codes: Mutex<HashMap<String, Issued>>,
    pub redemptions: AtomicUsize,
    pub renewals: AtomicUsize,
    pub graph_calls: AtomicUsize,
    /// What the token endpoint says a Graph token lives for.
    pub expires_in: AtomicU64,
    /// Every problem the stand-in found with a token request. Must stay empty.
    pub faults: Mutex<Vec<String>>,
    /// The request headers every download arrived with.
    pub download_headers: Mutex<Vec<HeaderMap>>,
}

pub fn now() -> u64 {
    jsonwebtoken::get_current_timestamp()
}

fn form(body: &[u8]) -> HashMap<String, String> {
    let decode = |s: &str| {
        let s = s.replace('+', " ");
        let b = s.as_bytes();
        let mut out = Vec::new();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap());
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    };
    std::str::from_utf8(body)
        .unwrap()
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (decode(k), decode(v)))
        .collect()
}

fn percent_decode(s: &str) -> String {
    form(format!("x={}", s.replace('+', "%2B")).as_bytes()).remove("x").unwrap_or_default()
}

fn item(id: &str, name: &str, size: u64, folder: bool, download: Option<String>) -> Value {
    let mut v = json!({
        "id": id, "name": name, "size": size,
        "lastModifiedDateTime": "2026-09-20T10:00:00Z",
        "webUrl": format!("https://contoso.sharepoint.com/sites/tender/Shared%20Documents/{name}"),
        "cTag": format!("ctag-{id}"),
    });
    if folder {
        v["folder"] = json!({ "childCount": 1 });
    } else {
        v["file"] = json!({});
    }
    if let Some(d) = download {
        v["@microsoft.graph.downloadUrl"] = json!(d);
    }
    v
}

impl Mock {
    fn items(&self) -> Vec<(&'static str, Value)> {
        vec![
            ("", item("root", "root", 0, true, None)),
            ("in-scope", item("f-in", "in-scope", 0, true, None)),
            ("in-scope/a.txt", item("i-a", "a.txt", 5, false, Some(self.download("a")))),
            ("in-scope/b.txt", item("i-b", "b.txt", 6, false, Some(self.download("b")))),
            ("in-scope/big.bin", item("i-big", "big.bin", 300_000, false, Some(self.download("big")))),
            // Not listed, only named: an Office file that downloads larger
            // than Graph lists it (L1, 2026-10-01), and one whose download
            // host refuses after the grant.
            ("in-scope/grown.docx", item("i-g", "grown.docx", 5, false, Some(self.download("grown")))),
            ("in-scope/gone.txt", item("i-x", "gone.txt", 5, false, Some(self.download("gone")))),
            // Spelled with a capital; SharePoint answers any case for it.
            ("in-scope/mixed.txt", item("i-m", "Mixed.txt", 5, false, Some(self.download("a")))),
            ("in-scope/deeper", item("f-deep", "deeper", 0, true, None)),
            ("out", item("f-out", "out", 0, true, None)),
            ("out/secret.txt", item("i-s", "secret.txt", 6, false, Some("https://download.example/s".into()))),
        ]
        .into_iter()
        .map(|(p, mut v)| {
            // Graph's parent path, from the drive's root.
            if !p.is_empty() {
                let parent = p.rsplit_once('/').map_or("", |(d, _)| d);
                v["parentReference"] = json!({ "path": format!("/drives/drive-1/root:/{parent}").trim_end_matches('/') });
            }
            (p, v)
        })
        .collect()
    }

    /// Where an item downloads from: the stand-in itself, over plain http as
    /// its Graph is, which the broker allows only then (`may_download`).
    fn download(&self, name: &str) -> String {
        format!("{}/download/{name}?tempauth=x", self.base.lock().unwrap())
    }

    fn children(&self, id: &str) -> Vec<Value> {
        let names: &[&str] = match id {
            "root" => &["in-scope", "out"],
            // `denied.txt` exists and is absent: SharePoint trims it for this
            // user, which is D-013's quiet listing done by the source.
            "f-in" => &["in-scope/a.txt", "in-scope/b.txt", "in-scope/big.bin", "in-scope/deeper"],
            _ => &[],
        };
        let items = self.items();
        names.iter().map(|n| items.iter().find(|(p, _)| p == n).unwrap().1.clone()).collect()
    }
}

pub async fn mock(
    State(m): State<Arc<Mock>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path().to_owned();
    let json_ok = |v: Value| (StatusCode::OK, axum::Json(v)).into_response();
    let graph_err = |s: StatusCode, code: &str| {
        (s, axum::Json(json!({ "error": { "code": code, "message": "stand-in" } }))).into_response()
    };

    if path == format!("/{TENANT}/discovery/v2.0/keys") {
        return json_ok(serde_json::to_value(&m.jwks).unwrap());
    }
    if path == format!("/{TENANT}/oauth2/v2.0/token") && method == Method::POST {
        return token_endpoint(&m, &form(&body));
    }
    if path == "/download/b" {
        return (StatusCode::OK, "bravo!").into_response();
    }
    if path == "/download/grown" {
        return (StatusCode::OK, "alpha, with the document's properties written in").into_response();
    }
    if path == "/download/big" {
        return (StatusCode::OK, vec![b'x'; 300_000]).into_response();
    }
    if path == "/download/gone" {
        return StatusCode::NOT_FOUND.into_response();
    }
    if path == "/download/a" {
        m.download_headers.lock().unwrap().push(headers.clone());
        return (StatusCode::OK, "alpha").into_response();
    }

    let Some(graph) = path.strip_prefix("/v1.0/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    m.graph_calls.fetch_add(1, Ordering::SeqCst);
    let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !auth.starts_with("Bearer graph-") {
        return graph_err(StatusCode::UNAUTHORIZED, "InvalidAuthenticationToken");
    }

    let graph = percent_decode(graph);
    if graph == "sites/contoso.sharepoint.com:/sites/tender" {
        return json_ok(json!({ "id": "site-1" }));
    }
    if graph == "sites/site-1/drives" {
        return json_ok(json!({ "value": [
            { "id": "drive-9", "name": "Site Assets", "webUrl": "https://contoso.sharepoint.com/sites/tender/SiteAssets" },
            { "id": "drive-1", "name": "Documents", "webUrl": "https://contoso.sharepoint.com/sites/tender/Shared%20Documents" }
        ]}));
    }
    // The user's own OneDrive (D-054): a `Sluse` folder with a file and a
    // shortcut in it, and a file beside the folder.
    if graph == "me/drive" {
        return json_ok(json!({ "id": "drive-me", "name": "OneDrive", "webUrl": "https://contoso-my.sharepoint.com/personal/alice" }));
    }
    if let Some(rest) = graph.strip_prefix("drives/drive-me/") {
        let note = {
            let mut v = item("o-n", "note.txt", 5, false, Some(m.download("a")));
            v["parentReference"] = json!({ "path": "/drives/drive-me/root:/Sluse" });
            v
        };
        let shortcut = {
            let mut v = item("o-s", "Tender.docx", 0, false, None);
            v["parentReference"] = json!({ "path": "/drives/drive-me/root:/Sluse" });
            v["remoteItem"] = json!({ "id": "i-s", "parentReference": { "driveId": "drive-1" } });
            v
        };
        let mut folder = item("o-f", "Sluse", 0, true, None);
        folder["parentReference"] = json!({ "path": "/drives/drive-me/root:" });
        return match rest.to_lowercase().as_str() {
            "root:/sluse" => json_ok(folder),
            "root:/sluse/note.txt" => json_ok(note),
            "root:/sluse/tender.docx" => json_ok(shortcut),
            "items/o-f/children" => json_ok(json!({ "value": [note, shortcut] })),
            _ => graph_err(StatusCode::NOT_FOUND, "itemNotFound"),
        };
    }
    if let Some(rest) = graph.strip_prefix("drives/drive-1/items/") {
        let id = rest.trim_end_matches("/children");
        return json_ok(json!({ "value": m.children(id) }));
    }
    let rel = if graph == "drives/drive-1/root" {
        Some(String::new())
    } else {
        graph.strip_prefix("drives/drive-1/root:/").map(|r| r.to_lowercase())
    };
    let Some(rel) = rel else { return graph_err(StatusCode::BAD_REQUEST, "invalidRequest") };
    if rel == "in-scope/denied.txt" {
        return graph_err(StatusCode::FORBIDDEN, "accessDenied");
    }
    if rel == "in-scope/throttled.txt" {
        let mut r = graph_err(StatusCode::TOO_MANY_REQUESTS, "activityLimitReached");
        r.headers_mut().insert("retry-after", "7".parse().unwrap());
        return r;
    }
    match m.items().into_iter().find(|(p, _)| *p == rel) {
        Some((_, v)) => json_ok(v),
        None => graph_err(StatusCode::NOT_FOUND, "itemNotFound"),
    }
}

fn token_endpoint(m: &Mock, f: &HashMap<String, String>) -> Response {
    let fault = |why: String| {
        m.faults.lock().unwrap().push(why);
        (StatusCode::UNAUTHORIZED, axum::Json(json!({ "error": "invalid_client", "error_description": "AADSTS700027: stand-in" })))
            .into_response()
    };
    let invalid_grant = |why: &str| {
        (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": "invalid_grant", "error_description": format!("AADSTS70008: {why}") })))
            .into_response()
    };
    // A public client (D-036): its id, and no credential of any kind.
    if f.get("client_id").map(String::as_str) != Some(CLIENT) {
        return fault(format!("client_id {:?}", f.get("client_id")));
    }
    if f.contains_key("client_assertion") || f.contains_key("client_secret") {
        return fault("a public client sent a credential".into());
    }

    let expires_in = m.expires_in.load(Ordering::SeqCst);
    match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            m.redemptions.fetch_add(1, Ordering::SeqCst);
            if f.get("redirect_uri").map(String::as_str) != Some(sluse_proto::wire::NATIVE_REDIRECT) {
                return fault(format!("redirect_uri {:?}", f.get("redirect_uri")));
            }
            if !f.get("scope").is_some_and(|s| s.split(' ').any(|x| x == "openid")) {
                return fault(format!("scope {:?} has no openid", f.get("scope")));
            }
            let Some(issued) = m.codes.lock().unwrap().remove(f.get("code").map(String::as_str).unwrap_or_default()) else {
                return invalid_grant("the code is not one this stand-in issued, or was used");
            };
            if f.get("code_verifier") != Some(&issued.verifier) {
                return invalid_grant("the PKCE verifier does not match");
            }
            axum::Json(json!({
                "token_type": "Bearer",
                "id_token": issued.id_token,
                "access_token": format!("graph-{}-{}", issued.oid, now()),
                "refresh_token": format!("refresh-{}", issued.oid),
                "expires_in": expires_in,
            }))
            .into_response()
        }
        Some("refresh_token") => {
            m.renewals.fetch_add(1, Ordering::SeqCst);
            let r = f.get("refresh_token").cloned().unwrap_or_default();
            if r == "refresh-revoked" {
                return (StatusCode::BAD_REQUEST, axum::Json(json!({ "error": "invalid_grant", "error_description": "AADSTS50173: revoked" })))
                    .into_response();
            }
            axum::Json(json!({
                "token_type": "Bearer",
                "access_token": format!("graph-renewed-{}", now()),
                "expires_in": expires_in,
            }))
            .into_response()
        }
        other => fault(format!("grant_type {other:?}")),
    }
}

// ---------------------------------------------------------------------------
// Standing it up
// ---------------------------------------------------------------------------

/// A running stand-in, and what a test needs to use it.
pub struct Running {
    pub mock: Arc<Mock>,
    /// `http://127.0.0.1:<port>`: the authority, and `<base>/v1.0` is Graph.
    pub base: String,
    /// Signs ID tokens as Entra would.
    pub entra_key: EncodingKey,
}

pub fn rsa() -> rcgen::KeyPair {
    rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("RSA keygen under aws-lc-rs")
}

pub async fn start() -> Running {
    let entra_kp = rsa();
    let entra_key = EncodingKey::from_rsa_pem(entra_kp.serialize_pem().as_bytes()).unwrap();
    let mut jwk = Jwk::from_encoding_key(&entra_key, Algorithm::RS256).unwrap();
    jwk.common.key_id = Some("entra-1".into());
    let jwks = JwkSet { keys: vec![jwk] };

    let mock = Arc::new(Mock {
        base: Mutex::new(String::new()),
        jwks,
        codes: Mutex::new(HashMap::new()),
        redemptions: AtomicUsize::new(0),
        renewals: AtomicUsize::new(0),
        graph_calls: AtomicUsize::new(0),
        expires_in: AtomicU64::new(3600),
        faults: Mutex::new(Vec::new()),
        download_headers: Mutex::new(Vec::new()),
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    *mock.base.lock().unwrap() = base.clone();
    let app = app(mock.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    Running { mock, base, entra_key }
}

/// The stand-in as a router, for a test that serves it a second time over TLS.
pub fn app(mock: Arc<Mock>) -> Router {
    Router::new().fallback(mock_handler).with_state(mock)
}

async fn mock_handler(
    state: State<Arc<Mock>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    mock(state, method, uri, headers, body).await
}

/// An ID token's claims from the v2 endpoint, for Sluse's registration. The
/// nonce is filled in when a code is issued for it.
pub fn claims(oid: &str, upn: &str) -> Value {
    json!({
        "aud": CLIENT,
        "iss": format!("https://login.microsoftonline.com/{TENANT}/v2.0"),
        "tid": TENANT, "oid": oid, "preferred_username": upn, "ver": "2.0",
        "iat": now() - 10, "nbf": now() - 10, "exp": now() + 3600,
    })
}

pub fn sign(claims: &Value, kid: &str, key: &EncodingKey) -> String {
    let mut h = Header::new(Algorithm::RS256);
    h.kid = Some(kid.into());
    jsonwebtoken::encode(&h, claims, key).unwrap()
}

static NEXT: AtomicUsize = AtomicUsize::new(0);

impl Running {
    /// What the shell would have caught for these claims (D-036): a code the
    /// stand-in redeems for an ID token signed by Entra's key.
    pub fn code(&self, claims: &Value) -> sluse_proto::pipe::HostSignIn {
        self.code_signed(claims, |c| sign(c, "entra-1", &self.entra_key))
    }

    /// The same, with the ID token signed however the test says. The nonce
    /// is put in the claims unless they already name one.
    pub fn code_signed(&self, claims: &Value, signer: impl Fn(&Value) -> String) -> sluse_proto::pipe::HostSignIn {
        let n = NEXT.fetch_add(1, Ordering::SeqCst);
        let nonce = format!("nonce-{n}");
        let mut c = claims.clone();
        if c.get("nonce").is_none() {
            c["nonce"] = json!(nonce);
        }
        let (code, verifier) = (format!("code-{n}"), format!("verifier-{n}"));
        let oid = c["oid"].as_str().unwrap_or_default().to_owned();
        self.mock.codes.lock().unwrap().insert(code.clone(), Issued { id_token: signer(&c), oid, verifier: verifier.clone() });
        sluse_proto::pipe::HostSignIn {
            seq: n as u64,
            code: code.into(),
            verifier: verifier.into(),
            redirect_uri: sluse_proto::wire::NATIVE_REDIRECT.into(),
            nonce,
        }
    }

    pub fn alice(&self) -> sluse_proto::pipe::HostSignIn {
        self.code(&claims(ALICE, "alice@contoso.example"))
    }

    pub fn faults(&self) -> Vec<String> {
        self.mock.faults.lock().unwrap().clone()
    }
}

/// The source and the `entra` block a config needs to use the stand-in.
pub fn sharepoint_source() -> Value {
    json!({
        "name": "spo",
        "kind": { "type": "sharepoint", "address": { "siteUrl": "https://contoso.sharepoint.com/sites/tender", "library": "Documents" } },
        "scope": ["In-Scope"],
        "sensitivity": 2
    })
}

pub fn onedrive_source() -> Value {
    json!({ "name": "od", "kind": { "type": "onedrive" }, "sensitivity": 2 })
}

pub fn entra_block() -> Value {
    json!({ "tenantId": TENANT, "clientId": CLIENT })
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from Chaperone chapr-endpoint/src/coord_client.rs:40-171, 393-500
// (timeouts, one `authed()` chokepoint, transport_cause, typed error from the
// body). The pinned verifier is new: Chaperone's endpoint trusts a CA.

//! Talking to the broker.
//!
//! **The guest trusts exactly one certificate, by its hash, and no CA at all.**
//! [`PinnedVerifier`] compares the leaf the broker presents against the
//! `broker.certPin` in the config and accepts nothing else — not a different
//! certificate from the same CA, not a public root, not the operating system's
//! store. A guest with a root store is a guest that can be talked into trusting
//! a broker that is not the broker, and the way to not have that problem is to
//! not have a root store.
//!
//! ## The one call that keeps it that way
//!
//! [`ClientBuilder::use_preconfigured_tls`](reqwest::ClientBuilder::use_preconfigured_tls)
//! is **load-bearing and not a convenience.** reqwest 0.13's `rustls` feature,
//! given no explicit roots, installs `rustls-platform-verifier` — the OS root
//! store. Handing it a finished [`rustls::ClientConfig`] skips that path
//! entirely. Every client in this crate is built by [`build_client`] for exactly
//! that reason; there is no second place a client is constructed.
//!
//! ## Errors survive the round trip
//!
//! The broker answers a refusal with the [`SluseError`] itself, serialised under
//! its `code` tag. This deserialises it straight back into the same type, so a
//! refusal arrives as a value rather than as prose to be re-parsed — and the
//! blinders in [`crate::server`] then decide what the *agent* is told, which is
//! narrower. Everything this returns is what the broker said.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use reqwest::Client;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use sluse_proto::wire::{header, route};
use sluse_proto::{
    AdmissionId, AuditTailResponse, Audience, ConfigView, ContentHash, ContentHasher, Health,
    LineageItem, ListRequest, ListResponse, Loaded, Pin, PublishManifest, PublishResponse,
    ReadRequest, ReadVerb, SessionId, SignedOut, SluseError, StatRequest, StatResponse,
    Status, UserRef, VolumeAlert,
};
use sluse_proto::audit::Capability;
use tokio::io::AsyncWriteExt;

/// How long a request may take before the endpoint gives up.
///
/// Generous, because an SMB open on a share that has gone away blocks until the
/// redirector gives up and that is seconds — and a timeout shorter than the
/// source's own is a timeout that reports the wrong thing.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// The connect timeout, which is short: the broker is on the same machine in
/// LOCAL and one hop away in the product. Failing to connect is not something to
/// wait two minutes to find out.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// The verifier
// ---------------------------------------------------------------------------

/// Accepts one certificate: the one whose DER hashes to the configured pin.
///
/// Not a CA check, not a hostname check, not an expiry check — a hash
/// comparison, and a deliberate one. The broker's certificate is generated on
/// the machine that uses it and is in no chain a public root would recognise, so
/// "is this signed by someone I trust" has no useful answer here; "is this the
/// exact certificate the config names" has a complete one.
///
/// What that gives up is said plainly: an expired pinned certificate is still
/// accepted, and a revoked one has nowhere to be revoked. Both follow from
/// pinning a leaf rather than trusting an issuer, and both are the right trade
/// for a transport where the two ends are configured together — but neither is
/// a property this prototype may claim, and `prototype/README.md` says so.
#[derive(Debug)]
pub struct PinnedVerifier {
    pin: ContentHash,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl PinnedVerifier {
    pub fn new(pin: ContentHash) -> Self {
        Self { pin, provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()) }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let presented = ContentHash::of(end_entity.as_ref());
        if presented == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            // The message names both hashes, because a person comparing them by
            // eye is the point and one alone would not say which end to fix.
            Err(rustls::Error::General(format!(
                "certificate pin mismatch: expected {}, the broker presented {}",
                self.pin.short(),
                presented.short()
            )))
        }
    }

    // The signature checks stay real. Pinning says *which* certificate is the
    // broker's; it does not excuse the handshake from proving the peer holds the
    // matching private key, and skipping these would make the pin worthless
    // against anyone who could copy a public certificate.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

// ---------------------------------------------------------------------------
// The client
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("reading {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("{path} contains no {what}")]
    Empty { path: String, what: &'static str },
    #[error("building the TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
    #[error("building the HTTP client: {0}")]
    Http(String),
}

/// What an admission brought back, besides the value.
///
/// The endpoint hashes the bytes it received, independently of the broker
/// hashing the bytes it sent (invariant 7). The hash is deliberately **not** on
/// the wire — it is not known until the body has been sent, and a header would
/// need the file read twice — so the two records are joined by `admission_id`
/// and the scorer asserts the hashes match. That is a stronger check than a
/// header either end could have copied from the other.
#[derive(Debug, Clone)]
pub struct Admitted<T> {
    pub value: T,
    pub hash: ContentHash,
    pub bytes: u64,
    pub admission_id: AdmissionId,
    /// The host path, as the broker resolved it. The one host path the guest is
    /// told, and only for a path it already named, so the two records line up.
    pub resolved: String,
    /// How the bytes came: through the broker, for every source since D-046.
    /// The journal records it; journals from before then may say `url`, where
    /// this side was the only one that saw the bytes.
    pub capability: Capability,
}

/// The endpoint's one way to reach the broker.
#[derive(Debug)]
pub struct BrokerClient {
    http: Client,
    base: String,
    session: SessionId,
    /// See [`BrokerClient::acting_as`].
    acting: std::sync::Mutex<UserRef>,
}

/// Build the TLS configuration and the HTTP client.
///
/// Separate from [`BrokerClient::connect`] so the integration test can assert
/// the pin is enforced without a session, and so there is exactly one place in
/// this crate where a client is constructed.
pub fn build_client(loaded: &Loaded) -> Result<Client, ClientError> {
    let cert_path = loaded.resolve(&loaded.config.endpoint.client_cert_path);
    let key_path = loaded.resolve(&loaded.config.endpoint.client_key_path);

    let certs = read_certs(&cert_path)?;
    let key = read_key(&key_path)?;

    let tls = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(
            loaded.config.broker.cert_pin.clone(),
        )))
        .with_client_auth_cert(certs, key)?;

    Client::builder()
        // The load-bearing call. Without it reqwest 0.13 builds its own rustls
        // configuration around `rustls-platform-verifier`, which is the OS root
        // store, and the pin above would never be consulted.
        .use_preconfigured_tls(tls)
        // The broker is on the segment, never behind the box's egress proxy
        // (M9), whatever the box's environment says.
        .no_proxy()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|e| ClientError::Http(e.to_string()))
}

/// Enrol this box (slice 2): the enrolment listener, pinned to the same leaf
/// as the mTLS one, with no client certificate, because the box has none yet.
/// The one call in this crate made without one.
pub async fn enrol(
    url: &str,
    pin: ContentHash,
    req: &sluse_proto::wire::EnrolRequest,
) -> Result<sluse_proto::wire::EnrolResponse, SluseError> {
    let tls = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedVerifier::new(pin)))
        .with_no_client_auth();
    let client = Client::builder()
        .use_preconfigured_tls(tls)
        .no_proxy()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()
        .map_err(|e| SluseError::Internal { message: e.to_string() })?;
    let res = client
        .post(format!("{}{}", url.trim_end_matches('/'), sluse_proto::wire::route::ENROL))
        .json(req)
        .send()
        .await
        .map_err(transport_cause)?;
    json_or_error(res).await
}

/// Ask a broker whether it is serving, without taking a session from it.
///
/// A free function rather than a [`BrokerClient`] method because it needs no
/// session — that is the entire reason `/v1/status` exists. `sluse status` and
/// the "broker reachable" gate call this, and so does the console. Calling
/// `/v1/health` for the same answer would mint a session per poll and evict live
/// ones out of a registry that holds a bounded number.
///
/// It builds the guest's own client, pin and all. A host-side probe that trusted
/// anything the guest does not would be answering a different question from the
/// one the endpoint asks a moment later.
pub async fn status(loaded: &Loaded) -> Result<Status, SluseError> {
    let http = build_client(loaded).map_err(|e| SluseError::BrokerUnreachable {
        detail: format!("the client could not be built: {e}"),
    })?;
    let base = loaded.config.broker.url.trim_end_matches('/');
    let res = http
        .get(format!("{base}{}", route::STATUS))
        .send()
        .await
        .map_err(transport_cause)?;
    json_or_error(res).await
}

impl BrokerClient {
    /// Build the client and take a session from the broker.
    ///
    /// The session id comes back from `/v1/health`; the guest does not choose
    /// it. See [`crate::session`] for what happens across a restart.
    pub async fn connect(loaded: &Loaded) -> Result<(Self, Health), SluseError> {
        let http = build_client(loaded).map_err(|e| SluseError::BrokerUnreachable {
            detail: format!("the client could not be built: {e}"),
        })?;
        let base = loaded.config.broker.url.trim_end_matches('/').to_owned();

        // A placeholder session, because health is the one route that does not
        // need one and is where a real one comes from.
        let mut client = Self {
            http,
            base,
            session: SessionId::new_unchecked("sess-pending"),
            acting: std::sync::Mutex::new(UserRef::os_process("")),
        };
        let health = client.health().await?;
        *client.acting.lock().unwrap_or_else(|p| p.into_inner()) = health.user.clone();
        client.session = health.session_id.clone();
        Ok((client, health))
    }

    /// Resume with a session the broker issued earlier.
    ///
    /// Used when a run's session id survives an endpoint restart. If the broker
    /// has since forgotten it, the first call answers `UnknownSession` and the
    /// caller starts a new one rather than carrying on silently.
    pub fn with_session(mut self, session: SessionId) -> Self {
        self.session = session;
        self
    }

    pub fn session(&self) -> &SessionId {
        &self.session
    }

    /// Who the broker last said it acted as (`x-sluse-user`), and so the user
    /// the guest's journal names (D-022). From `/v1/health` until the first
    /// response says otherwise.
    pub fn acting_as(&self) -> UserRef {
        self.acting.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    /// Every call to the broker goes through here, so every response updates
    /// [`acting_as`](Self::acting_as). A broker older than the header sends
    /// none, and the last known value stands.
    ///
    /// ponytail: one value for the whole client, so two calls racing a
    /// sign-in can each see the other's answer; per-call users if that matters.
    async fn send(&self, req: reqwest::RequestBuilder) -> Result<reqwest::Response, SluseError> {
        let res = req.send().await.map_err(transport_cause)?;
        let said = res.headers().get(header::USER).and_then(|v| v.to_str().ok());
        if let Some(user) = said.and_then(|v| UserRef::parse_display(&header::decode(v))) {
            *self.acting.lock().unwrap_or_else(|p| p.into_inner()) = user;
        }
        Ok(res)
    }

    fn url(&self, route: &str) -> String {
        format!("{}{route}", self.base)
    }

    /// Every request goes through here, so the session header cannot be
    /// forgotten on a route added later.
    fn authed(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        req.header(header::SESSION, self.session.as_str())
    }

    // ---- the routes ------------------------------------------------------

    pub async fn health(&self) -> Result<Health, SluseError> {
        let req = self
            .http
            .get(self.url(route::HEALTH));
        let res = self.send(req).await?;
        json_or_error(res).await
    }

    pub async fn config_view(&self) -> Result<ConfigView, SluseError> {
        let req = self
            .authed(self.http.get(self.url(route::CONFIG_VIEW)));
        let res = self.send(req).await?;
        json_or_error(res).await
    }

    pub async fn list(&self, path: &str) -> Result<ListResponse, SluseError> {
        // `Agent` always on this method, and it is the only one the MCP tool
        // handlers can reach. Asking for `User` from the agent's side would be
        // the guest deciding what it may see (invariant 2).
        self.list_as(path, Audience::Agent).await
    }

    /// List for a named audience. **The console's route, and nothing else's.**
    ///
    /// Separate from [`list`](Self::list) rather than a parameter on it, so that
    /// every call site in `server.rs` — the MCP surface the agent drives — is
    /// spelled `list` and gets `Agent` without choosing it. The audience is not
    /// a permission the broker grants; it is a question the console asks and the
    /// agent's tools cannot phrase.
    pub async fn list_as(
        &self,
        path: &str,
        audience: Audience,
    ) -> Result<ListResponse, SluseError> {
        let req = self
            .authed(self.http.post(self.url(route::LIST)))
            .json(&ListRequest { path: path.to_owned(), audience });
        let res = self.send(req).await?;
        json_or_error(res).await
    }

    /// Offer the host journal lines from `offset` (D-027 point 5), and learn
    /// how much it now holds.
    pub async fn mirror_journal(&self, append: &sluse_proto::wire::JournalAppend) -> Result<u64, SluseError> {
        let req = self.authed(self.http.post(self.url(route::JOURNAL))).json(append);
        let res = self.send(req).await?;
        json_or_error::<sluse_proto::wire::JournalAck>(res).await.map(|a| a.have)
    }

    /// Sign the box out (D-022). User-initiated: the console's button.
    pub async fn sign_out(&self) -> Result<SignedOut, SluseError> {
        let req = self
            .authed(self.http.post(self.url(route::SIGN_OUT)));
        let res = self.send(req).await?;
        json_or_error(res).await
    }

    /// `/v1/status` on this client's connection.
    ///
    /// The free [`status`] function answers the same question from a `Loaded`,
    /// for `sluse status` and the start-up gate. This one is for a caller that
    /// already holds a client — the console, refreshing its own panel — and it
    /// is `status` rather than `health` for the reason that route exists:
    /// `/v1/health` mints a session per call, and a panel that refreshed would
    /// evict a live run's session out of a bounded registry.
    pub async fn status_now(&self) -> Result<Status, SluseError> {
        let res = self.send(self.http.get(self.url(route::STATUS))).await?;
        json_or_error(res).await
    }

    /// Whether the broker still holds this client's session: a question on
    /// the status route, so a session that aged out is not a refusal in the
    /// Sluse log (L1, 2026-10-07).
    pub async fn session_held(&self) -> Result<bool, SluseError> {
        let res = self.send(self.authed(self.http.get(self.url(route::STATUS)))).await?;
        Ok(json_or_error::<Status>(res).await?.session_held.unwrap_or(false))
    }

    /// Read a file's bytes into memory, for the envelope.
    ///
    /// The cap is the broker's; this does not check it first. A second opinion
    /// about size would be a second answer, and the broker's record has to be
    /// the complete one.
    pub async fn read(&self, path: &str) -> Result<Admitted<Vec<u8>>, ReadFailed> {
        let (headers, mut stream) = self.open_read(path, ReadVerb::Read).await?;
        let failed = |e| ReadFailed::after(e, &headers);
        // The broker's cap was applied to the size it declared; the buffer is
        // sized from the same number, so an oversized declaration is refused
        // before it is allocated for.
        let mut buf = Vec::with_capacity(headers.size.unwrap_or(0).min(64 * 1024 * 1024) as usize);
        let mut hasher = ContentHasher::new();

        while let Some(chunk) = stream.chunk().await.map_err(|e| failed(transport_cause(e)))? {
            hasher.update(&chunk);
            buf.extend_from_slice(&chunk);
        }

        let hash = hasher.finish();
        check_length(path, buf.len() as u64, &headers).map_err(failed)?;
        Ok(Admitted {
            bytes: buf.len() as u64,
            value: buf,
            hash,
            admission_id: headers.admission_id,
            resolved: headers.resolved,
            capability: headers.capability,
        })
    }

    /// Stream a file into the workspace, hashing on the way past.
    ///
    /// Never held whole in memory: a 500 MB fetch is the case this exists for.
    ///
    /// **Into a partial file beside the destination, renamed over it only
    /// when the stream is whole** (review R-13). A failure, a cancelled call
    /// or a short stream removes the partial file, so the workspace never
    /// holds bytes the journal does not describe, and a failed re-fetch
    /// leaves the earlier copy and its sidecar as they were. A process killed
    /// mid-stream leaves the partial file; [`crate::workspace::sweep_partial`]
    /// removes those.
    pub async fn fetch_to_file(
        &self,
        path: &str,
        destination: &Path,
    ) -> Result<Admitted<std::path::PathBuf>, ReadFailed> {
        let (headers, mut stream) = self.open_read(path, ReadVerb::Fetch).await?;
        let failed = |e| ReadFailed::after(e, &headers);

        if let Some(parent) = destination.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                failed(SluseError::Internal { message: format!("preparing the workspace for {path}: {e}") })
            })?;
        }
        let partial = crate::workspace::partial_path(destination);
        let guard = Partial(Some(partial.clone()));
        let mut file = tokio::fs::File::create(&partial).await.map_err(|e| {
            failed(SluseError::Internal { message: format!("creating {}: {e}", partial.display()) })
        })?;

        let mut hasher = ContentHasher::new();
        let mut written: u64 = 0;
        while let Some(chunk) = stream.chunk().await.map_err(|e| failed(transport_cause(e)))? {
            hasher.update(&chunk);
            written += chunk.len() as u64;
            file.write_all(&chunk).await.map_err(|e| {
                failed(SluseError::Internal { message: format!("writing {}: {e}", destination.display()) })
            })?;
        }
        file.flush().await.map_err(|e| {
            failed(SluseError::Internal { message: format!("flushing {}: {e}", destination.display()) })
        })?;
        drop(file);

        // Checked before the rename: a short stream must not become the copy
        // the agent is handed as though it were the source.
        check_length(path, written, &headers).map_err(failed)?;
        tokio::fs::rename(&partial, destination).await.map_err(|e| {
            failed(SluseError::Internal { message: format!("moving {} into place: {e}", destination.display()) })
        })?;
        guard.keep();

        Ok(Admitted {
            value: destination.to_path_buf(),
            hash: hasher.finish(),
            bytes: written,
            admission_id: headers.admission_id,
            resolved: headers.resolved,
            capability: headers.capability,
        })
    }

    async fn open_read(
        &self,
        path: &str,
        verb: ReadVerb,
    ) -> Result<(ReadHeaders, reqwest::Response), ReadFailed> {
        let req = self
            .authed(self.http.post(self.url(route::READ)))
            .json(&ReadRequest { path: path.to_owned(), verb });
        let res = self.send(req).await?;

        if !res.status().is_success() {
            return Err(error_from(res).await.into());
        }
        Ok((read_headers(&res)?, res))
    }

    pub async fn stat(
        &self,
        path: &str,
        pinned: Option<Pin>,
    ) -> Result<StatResponse, SluseError> {
        let req = self
            .authed(self.http.post(self.url(route::STAT)))
            .json(&StatRequest { path: path.to_owned(), pinned });
        let res = self.send(req).await?;
        json_or_error(res).await
    }

    /// Publish a delivery: one call, many files, all or nothing.
    ///
    /// Each entry is `(name, bytes, declared sources)`; the name may carry
    /// subdirectories.
    pub async fn publish(
        &self,
        files: &[(String, Vec<u8>, Vec<LineageItem>)],
        lineage: Vec<LineageItem>,
    ) -> Result<PublishResponse, SluseError> {
        let manifest = PublishManifest {
            artifacts: files
                .iter()
                .map(|(name, bytes, sources)| sluse_proto::ArtifactManifest {
                    name: name.clone(),
                    hash: ContentHash::of(bytes),
                    bytes: bytes.len() as u64,
                    sources: sources.clone(),
                    // Q-4 and Q-5 are open. Writing a label would be a claim
                    // about persistence that nothing has verified.
                    label: None,
                })
                .collect(),
            lineage,
        };

        let manifest_json = serde_json::to_vec(&manifest).map_err(|e| SluseError::Internal {
            message: format!("serialising the manifest: {e}"),
        })?;

        // The manifest part first, so the broker has the whole delivery's shape
        // before a byte of any file.
        let mut form = reqwest::multipart::Form::new().part(
            "manifest",
            reqwest::multipart::Part::bytes(manifest_json).mime_str("application/json").map_err(
                |e| SluseError::Internal { message: format!("building the manifest part: {e}") },
            )?,
        );
        for (name, bytes, _) in files {
            form = form.part(
                name.clone(),
                reqwest::multipart::Part::bytes(bytes.clone()).file_name(name.clone()),
            );
        }

        let req = self
            .authed(self.http.post(self.url(route::PUBLISH)))
            .multipart(form);
        let res = self.send(req).await?;
        json_or_error(res).await
    }

    pub async fn alerts(
        &self,
        since: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Vec<VolumeAlert>, SluseError> {
        let mut req = self.http.get(self.url(route::ALERTS));
        if let Some(since) = since {
            req = req.query(&[("since", since.to_rfc3339())]);
        }
        let res = self.send(self.authed(req)).await?;
        json_or_error(res).await
    }

    pub async fn audit_tail(&self, limit: usize) -> Result<AuditTailResponse, SluseError> {
        let req = self
            .authed(self.http.get(self.url(route::AUDIT_TAIL)))
            .query(&[("limit", limit.to_string())]);
        let res = self.send(req).await?;
        json_or_error(res).await
    }
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

/// A read or fetch that failed, with the admission id when the broker had
/// already authorised it: the endpoint's error record then joins the broker's
/// `Authorised` one. Derefs to the error.
#[derive(Debug)]
pub struct ReadFailed {
    pub error: SluseError,
    pub admission_id: Option<AdmissionId>,
}

impl ReadFailed {
    fn after(error: SluseError, headers: &ReadHeaders) -> Self {
        ReadFailed { error, admission_id: Some(headers.admission_id.clone()) }
    }
}

impl From<SluseError> for ReadFailed {
    fn from(error: SluseError) -> Self {
        ReadFailed { error, admission_id: None }
    }
}

impl std::ops::Deref for ReadFailed {
    type Target = SluseError;
    fn deref(&self) -> &SluseError {
        &self.error
    }
}

struct ReadHeaders {
    admission_id: AdmissionId,
    /// The length the body must have, as the broker said it.
    size: Option<u64>,
    resolved: String,
    capability: Capability,
}

fn read_headers(res: &reqwest::Response) -> Result<ReadHeaders, SluseError> {
    let get = |name: &str| -> Option<String> {
        res.headers().get(name).and_then(|v| v.to_str().ok()).map(|s| s.to_owned())
    };
    let missing = |name: &str| SluseError::Internal {
        message: format!("the broker answered a read without the {name} header"),
    };

    Ok(ReadHeaders {
        admission_id: AdmissionId::new_unchecked(
            get(header::ADMISSION_ID).ok_or_else(|| missing(header::ADMISSION_ID))?,
        ),
        size: Some(get(header::SIZE).and_then(|s| s.parse().ok()).ok_or_else(|| missing(header::SIZE))?),
        resolved: get(header::RESOLVED).map(|r| header::decode(&r)).unwrap_or_default(),
        // Absent is bytes: every broker before M7 answers without it.
        capability: match get(header::CAPABILITY).as_deref() {
            None | Some("bytes") => Capability::Bytes,
            // A download address instead of the file, from a broker older than
            // D-046; this build takes the bytes from the broker only.
            Some("url") => {
                return Err(SluseError::Internal {
                    message: "the broker answered with a download address, which this build no longer takes".into(),
                })
            }
            Some(other) => {
                return Err(SluseError::Internal {
                    message: format!("the broker answered with capability \"{other}\", which this build does not know"),
                })
            }
        },
    })
}

/// A body that stopped early is an error, not a short file.
///
/// The broker records a truncated read as an `Error` with the bytes that did
/// cross and no hash; this is the other half of that, and it is what keeps the
/// agent from being handed half a document as though it were the whole one.
fn check_length(path: &str, received: u64, headers: &ReadHeaders) -> Result<(), SluseError> {
    let Some(expected) = headers.size.filter(|&n| n != received) else { return Ok(()) };
    Err(SluseError::SourceUnavailable {
        source_name: path.split('/').next().unwrap_or(path).to_owned(),
        detail: format!("the read ended after {received} of {expected} bytes; the file was not delivered whole"),
    })
}

async fn json_or_error<T: serde::de::DeserializeOwned>(
    res: reqwest::Response,
) -> Result<T, SluseError> {
    if !res.status().is_success() {
        return Err(error_from(res).await);
    }
    res.json::<T>().await.map_err(|e| SluseError::Internal {
        message: format!("the broker's answer could not be read: {e}"),
    })
}

/// Turn a failure response back into the error the broker raised.
///
/// The body *is* a `SluseError`, so it deserialises straight back into one and
/// the loop closes: what the broker decided is what the endpoint holds.
async fn error_from(res: reqwest::Response) -> SluseError {
    let status = res.status();
    let body = res.text().await.unwrap_or_default();
    match serde_json::from_str::<SluseError>(&body) {
        Ok(err) => err,
        // A failure that is not a `SluseError` is not something to guess about:
        // a proxy, a crash, a version skew. It is reported as what it is.
        Err(_) => SluseError::Internal {
            message: format!("the broker answered {status} with a body this build cannot read"),
        },
    }
}

/// The innermost error in a chain: "certificate pin mismatch" rather than
/// "error sending request".
fn innermost(e: &reqwest::Error) -> String {
    let mut source: Option<&dyn std::error::Error> = Some(e);
    let mut last = e.to_string();
    while let Some(s) = source {
        last = s.to_string();
        source = s.source();
    }
    last
}

/// Every transport failure is the same thing to the agent: the broker could not
/// be reached, and the tool call fails closed (Q-2, provisional).
fn transport_cause(e: reqwest::Error) -> SluseError {
    let detail = innermost(&e);
    if detail.contains("certificate pin mismatch") {
        return SluseError::BrokerUnreachable {
            detail: format!("the broker is not the pinned one: {detail}"),
        };
    }
    SluseError::BrokerUnreachable { detail }
}

// ---------------------------------------------------------------------------

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, ClientError> {
    use rustls::pki_types::pem::PemObject;
    let pem = std::fs::read(path)
        .map_err(|source| ClientError::Read { path: path.display().to_string(), source })?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ClientError::Empty { path: path.display().to_string(), what: "certificate" })?;
    if certs.is_empty() {
        return Err(ClientError::Empty {
            path: path.display().to_string(),
            what: "certificate",
        });
    }
    Ok(certs)
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, ClientError> {
    use rustls::pki_types::pem::PemObject;
    let pem = std::fs::read(path)
        .map_err(|source| ClientError::Read { path: path.display().to_string(), source })?;
    PrivateKeyDer::from_pem_slice(&pem)
        .map_err(|_| ClientError::Empty { path: path.display().to_string(), what: "private key" })
}

/// A partial fetch, removed when dropped unless kept: every early return and
/// a cancelled future alike.
struct Partial(Option<std::path::PathBuf>);

impl Partial {
    fn keep(mut self) {
        self.0 = None;
    }
}

impl Drop for Partial {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            let _ = std::fs::remove_file(p);
        }
    }
}

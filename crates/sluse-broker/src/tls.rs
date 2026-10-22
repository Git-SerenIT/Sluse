// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from Chaperone chapr-coord/src/main.rs:406-453 (axum-server + rustls
// serve, explicit bind before ready, install_default). The client verifier is
// new: Chaperone's coordinator does not require a client certificate.

//! The mTLS server configuration.
//!
//! **mTLS is mandatory, in the literal sense**: the broker's client verifier
//! requires a certificate from the configured CA, so a connection without one
//! does not complete a handshake and no route is reached. There is no
//! unauthenticated path to compare against — not a route that checks and
//! refuses, but a socket that never becomes an HTTP connection.
//!
//! The two ends trust each other by different means and both are deliberate.
//! The broker trusts **a CA**, because it must accept a client certificate that
//! can be reissued without the broker being reconfigured. The endpoint trusts
//! **one leaf, by hash**, and no CA bundle at all: a root store in the guest
//! would be a way for something inside the box to be talked into trusting a
//! broker that is not the broker. The asymmetry is the point.
//!
//! ## One crypto provider
//!
//! [`install_provider`] is the first statement of `main` and of every test that
//! starts a listener. axum-server brings `aws-lc-rs` and reqwest could bring
//! `ring`; with both linked, rustls refuses to guess which is the process
//! default and panics on the first handshake. Chaperone met this. The workspace
//! pins one provider in `Cargo.toml` — including through rcgen, whose default
//! backend is `ring` and which is configured here not to use it — and this
//! function makes the choice explicit at runtime as well.

use std::io;
use std::path::Path;
use std::sync::{Arc, OnceLock};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme};
use sluse_proto::{BrokerConfig, ContentHash, Loaded};

use crate::preflight::CertCheck;

#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    #[error("reading {path}: {source}")]
    Read { path: String, source: io::Error },
    #[error("{path} contains no {what}")]
    Empty { path: String, what: &'static str },
    #[error("building the client verifier from {path}: {source}")]
    Verifier { path: String, source: rustls::server::VerifierBuilderError },
    #[error("building the TLS configuration: {0}")]
    Rustls(#[from] rustls::Error),
}

/// Install `aws-lc-rs` as the process-wide crypto provider.
///
/// Idempotent and quiet about it: a second call in the same process — a test
/// that starts two brokers — finds one already installed, which is the
/// state it wanted.
pub fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A loaded server configuration and what the preflight should record about it.
pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    /// What the broker's own leaf hashes to, and whether that is the pin the
    /// config names. Handed to [`crate::preflight::run`] rather than re-derived
    /// there: two answers to the same question eventually differ.
    pub check: CertCheck,
}

/// Build the server configuration from the config's `broker` section.
///
/// A pin that does not match the certificate on disk is **not** an error here.
/// It is a gate failure, which is a different thing: the broker has a usable
/// certificate and the guest has been told to expect another one, so the
/// condition to report is "this box will not start and here is why", with both
/// hashes in the detail, rather than an I/O error that names neither.
pub fn server_config(loaded: &Loaded) -> Result<ServerTls, TlsError> {
    server_config_pinned(loaded, None)
}

/// The one leaf this broker issued at enrolment (D-058), filled by
/// [`crate::enrol::Enrolment`] when the box enrols and empty until then.
pub type LeafPin = Arc<OnceLock<CertificateDer<'static>>>;

/// [`server_config`], and with a [`LeafPin`] a client must present **that**
/// leaf, not merely one the client CA signed. The CA is one per device and a
/// leaf lives 30 days, so without the pin a leaf copied out of one user's box
/// reached the broker serving the next user's (review R-03). Until the box
/// has enrolled, only the device's own leaf passes: the service's.
pub fn server_config_pinned(loaded: &Loaded, pin: Option<LeafPin>) -> Result<ServerTls, TlsError> {
    let broker: &BrokerConfig = &loaded.config.broker;

    let cert_path = loaded.resolve(&broker.cert_path);
    let key_path = loaded.resolve(&broker.key_path);
    let ca_path = loaded.resolve(&broker.client_ca_path);

    let certs = read_certs(&cert_path)?;
    let key = read_key(&key_path)?;

    // The leaf is the first certificate in the file, by convention and by the
    // TLS wire format: the chain is ordered leaf first.
    let presented = ContentHash::of(certs[0].as_ref());
    let check = if presented == broker.cert_pin {
        CertCheck::Ok { pin: presented.clone() }
    } else {
        CertCheck::PinMismatch { expected: broker.cert_pin.clone(), presented }
    };

    let mut roots = RootCertStore::empty();
    for cert in read_certs(&ca_path)? {
        roots.add(cert).map_err(TlsError::Rustls)?;
    }

    // `builder` and not `builder_with_...allow_unauthenticated`: an anonymous
    // client is refused at the handshake. The optional variant exists and is the
    // wrong one — it would put the decision in a middleware, where a route added
    // later could miss it.
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|source| TlsError::Verifier { path: ca_path.display().to_string(), source })?;
    let verifier: Arc<dyn ClientCertVerifier> = match pin {
        None => verifier,
        // The device's own leaf passes too: the service asks the broker it
        // started with it, and it never leaves the host's `certs\`, which is
        // SYSTEM's and Administrators' only (D-058 point 4). Without one, only
        // the box's.
        Some(pin) => Arc::new(Pinned {
            inner: verifier,
            pin,
            host: read_certs(&loaded.resolve(&loaded.config.endpoint.client_cert_path))
                .ok()
                .and_then(|c| c.into_iter().next()),
        }),
    };

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    // HTTP/1.1 and h2, in the order the server prefers them.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(ServerTls { config: Arc::new(config), check })
}

/// The CA's verdict, and then the pin's: everything else is the CA verifier's.
/// `host` is the device's own leaf, the service's.
#[derive(Debug)]
struct Pinned {
    inner: Arc<dyn ClientCertVerifier>,
    pin: LeafPin,
    host: Option<CertificateDer<'static>>,
}

impl ClientCertVerifier for Pinned {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;
        let is = |leaf: Option<&CertificateDer<'_>>| leaf.is_some_and(|l| l.as_ref() == end_entity.as_ref());
        if is(self.pin.get()) || is(self.host.as_ref()) {
            Ok(verified)
        } else {
            // rustls tells the client this as the alert `AccessDenied`.
            Err(rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// The enrolment listener's configuration: the same leaf, and **no client
/// certificate asked for**, because a box enrolling has none yet. Its router
/// has one route (`http::enrol_router`); the mTLS listener is built by
/// [`server_config`] and is unchanged.
pub fn enrol_server_config(loaded: &Loaded) -> Result<Arc<ServerConfig>, TlsError> {
    let broker: &BrokerConfig = &loaded.config.broker;
    let certs = read_certs(&loaded.resolve(&broker.cert_path))?;
    let key = read_key(&loaded.resolve(&broker.key_path))?;
    let mut config = ServerConfig::builder().with_no_client_auth().with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

fn read_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let pem = read(path)?;
    let certs: Vec<_> = rustls::pki_types::pem::PemObject::pem_slice_iter(pem.as_slice())
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|_| TlsError::Empty { path: path.display().to_string(), what: "certificate" })?;
    if certs.is_empty() {
        return Err(TlsError::Empty { path: path.display().to_string(), what: "certificate" });
    }
    Ok(certs)
}

fn read_key(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let pem = read(path)?;
    <PrivateKeyDer<'static> as rustls::pki_types::pem::PemObject>::from_pem_slice(pem.as_slice())
        .map_err(|_| TlsError::Empty { path: path.display().to_string(), what: "private key" })
}

fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|source| TlsError::Read {
        path: path.display().to_string(),
        source,
    })
}

/// Turn an I/O failure on the certificate files into the preflight's language.
///
/// Called when [`server_config`] failed outright: there is no TLS configuration,
/// so there is no listener, and the useful output is a gate failure naming the
/// file rather than a stack of wrapped errors.
pub fn missing(e: &TlsError) -> CertCheck {
    CertCheck::Missing { detail: e.to_string() }
}

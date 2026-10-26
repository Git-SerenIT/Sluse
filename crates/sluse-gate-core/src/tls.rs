// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from Chaperone chapr-coord/src/main.rs:406-453 (axum-server + rustls
// serve, explicit bind before ready, install_default). The client verifier is
// new: Chaperone's coordinator does not require a client certificate.

//! The mTLS server configuration.
//!
//! **mTLS is mandatory, in the literal sense**: Gate Core's client verifier
//! requires a certificate from the configured CA, so a connection without one
//! does not complete a handshake and no route is reached. There is no
//! unauthenticated path to compare against — not a route that checks and
//! refuses, but a socket that never becomes an HTTP connection.
//!
//! The two ends trust each other by different means and both are deliberate.
//! Gate Core trusts **a CA**, because it must accept a client certificate that
//! can be reissued without Gate Core being reconfigured. The endpoint trusts
//! **one leaf, by hash**, and no CA bundle at all: a root store in the guest
//! would be a way for something inside the box to be talked into trusting a
//! core that is not Gate Core. The asymmetry is the point.
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
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use sluse_proto::{GateConfig, ContentHash, Loaded};

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
/// that starts two cores — finds one already installed, which is the
/// state it wanted.
pub fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A loaded server configuration and what the preflight should record about it.
pub struct ServerTls {
    pub config: Arc<ServerConfig>,
    /// What Gate Core's own leaf hashes to, and whether that is the pin the
    /// config names. Handed to [`crate::preflight::run`] rather than re-derived
    /// there: two answers to the same question eventually differ.
    pub check: CertCheck,
}

/// Build the server configuration from the config's `core` section.
///
/// A pin that does not match the certificate on disk is **not** an error here.
/// It is a failed required check, which is a different thing: Gate Core has a usable
/// certificate and the guest has been told to expect another one, so the
/// condition to report is "this box will not start and here is why", with both
/// hashes in the detail, rather than an I/O error that names neither.
pub fn server_config(loaded: &Loaded) -> Result<ServerTls, TlsError> {
    let core: &GateConfig = &loaded.config.gate;

    let cert_path = loaded.resolve(&core.cert_path);
    let key_path = loaded.resolve(&core.key_path);
    let ca_path = loaded.resolve(&core.client_ca_path);

    let certs = read_certs(&cert_path)?;
    let key = read_key(&key_path)?;

    // The leaf is the first certificate in the file, by convention and by the
    // TLS wire format: the chain is ordered leaf first.
    let presented = ContentHash::of(certs[0].as_ref());
    let check = if presented == core.cert_pin {
        CertCheck::Ok { pin: presented.clone() }
    } else {
        CertCheck::PinMismatch { expected: core.cert_pin.clone(), presented }
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

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    // HTTP/1.1 and h2, in the order the server prefers them.
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(ServerTls { config: Arc::new(config), check })
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
/// so there is no listener, and the useful output is a failed required check naming the
/// file rather than a stack of wrapped errors.
pub fn missing(e: &TlsError) -> CertCheck {
    CertCheck::Missing { detail: e.to_string() }
}

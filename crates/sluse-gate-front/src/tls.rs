// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The box's TLS, terminated here (D-071): mutual TLS on the Gate's port, a
//! server certificate only on enrolment's. Everything comes from
//! [`FrontGate`], which Gate Core read; Front reads no file.
//!
//! **Pinned** (D-058): once the box has enrolled, only the leaf issued to it is
//! accepted, and the device's own, which the service's checks use (point 4).
//! Before it enrols, only the device's own. Gate Core issues the leaf; Front
//! learns it from Core's answer to the enrolment it relays.

use std::sync::{Arc, OnceLock};

use rustls::client::danger::HandshakeSignatureValid;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::WebPkiClientVerifier;
use rustls::{DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig, SignatureScheme};
use sluse_proto::gate::FrontGate;

/// Install aws-lc-rs as rustls's provider, once.
pub fn install_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// The leaf enrolment issued, once it has.
pub type LeafPin = Arc<OnceLock<CertificateDer<'static>>>;

fn certs(pem: &str, what: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("{what}: {e}"))?;
    if certs.is_empty() {
        return Err(format!("{what}: no certificate"));
    }
    Ok(certs)
}

/// The first certificate in `pem`, for a pin.
pub fn leaf(pem: &str) -> Result<CertificateDer<'static>, String> {
    certs(pem, "the leaf").map(|mut c| c.remove(0))
}

/// The Gate's port: mutual TLS, pinned when the start says so.
pub fn gate_config(g: &FrontGate, pin: LeafPin) -> Result<Arc<ServerConfig>, String> {
    let mut roots = RootCertStore::empty();
    for c in certs(&g.client_ca_pem, "the client CA")? {
        roots.add(c).map_err(|e| format!("the client CA: {e}"))?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots)).build().map_err(|e| format!("the client verifier: {e}"))?;
    let verifier: Arc<dyn ClientCertVerifier> = if g.pinned {
        let host = g.host_leaf_pem.as_deref().map(leaf).transpose()?;
        Arc::new(Pinned { inner: verifier, pin, host })
    } else {
        verifier
    };
    let key = PrivateKeyDer::from_pem_slice(g.key_pem.as_bytes()).map_err(|e| format!("the Gate's key: {e}"))?;
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(&g.cert_pem, "the Gate's certificate")?, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Enrolment's port: the same certificate, no client certificate (the box
/// has none yet; its one-use token is the check, made by Gate Core).
pub fn enrol_config(g: &FrontGate) -> Result<Arc<ServerConfig>, String> {
    let key = PrivateKeyDer::from_pem_slice(g.key_pem.as_bytes()).map_err(|e| format!("the Gate's key: {e}"))?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs(&g.cert_pem, "the Gate's certificate")?, key)
        .map_err(|e| e.to_string())?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// The CA's check, and then the pin.
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

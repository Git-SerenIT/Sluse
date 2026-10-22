// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Development certificates and a config, for the integration test.
//!
//! Generated in-process rather than by shelling out to `sluse devcert` — a test
//! that spawns a binary proves less and flakes more — but with the same rcgen
//! calls, so a change that broke the chain would break this.

use sluse_proto::ContentHash;

pub struct Certs {
    pub ca_pem: String,
    pub ca_key_pem: String,
    pub broker_cert_pem: String,
    pub broker_key_pem: String,
    pub endpoint_cert_pem: String,
    pub endpoint_key_pem: String,
    /// A second client leaf from the same CA: one copied out of another
    /// user's box, to an open's broker (D-058).
    pub other_cert_pem: String,
    pub other_key_pem: String,
    pub pin: ContentHash,
}

pub fn make() -> Certs {
    use rcgen::{CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, Issuer, KeyPair};

    let dn = |cn: &str| {
        let mut d = DistinguishedName::new();
        d.push(DnType::CommonName, cn);
        d
    };

    // The broker's own CA parameters, so the enrolment test's leaves chain
    // exactly as a real run's do.
    let ca_key = KeyPair::generate().unwrap();
    let ca_params = sluse_broker::enrol::ca_params();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let broker_key = KeyPair::generate().unwrap();
    let mut broker_params =
        CertificateParams::new(vec!["localhost".to_owned(), "127.0.0.1".to_owned()]).unwrap();
    broker_params.distinguished_name = dn("sluse-broker");
    broker_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let broker_cert = broker_params.signed_by(&broker_key, &issuer).unwrap();
    let pin = ContentHash::of(broker_cert.der());

    let endpoint_key = KeyPair::generate().unwrap();
    let mut endpoint_params = CertificateParams::new(vec!["sluse-endpoint".to_owned()]).unwrap();
    endpoint_params.distinguished_name = dn("sluse-endpoint");
    endpoint_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let endpoint_cert = endpoint_params.signed_by(&endpoint_key, &issuer).unwrap();
    let other_key = KeyPair::generate().unwrap();
    let other_cert = endpoint_params.signed_by(&other_key, &issuer).unwrap();

    Certs {
        ca_pem,
        ca_key_pem,
        broker_cert_pem: broker_cert.pem(),
        broker_key_pem: broker_key.serialize_pem(),
        endpoint_cert_pem: endpoint_cert.pem(),
        endpoint_key_pem: endpoint_key.serialize_pem(),
        other_cert_pem: other_cert.pem(),
        other_key_pem: other_key.serialize_pem(),
        pin,
    }
}

pub fn write(dir: &std::path::Path, c: &Certs) {
    std::fs::create_dir_all(dir.join("certs")).unwrap();
    for (name, body) in [
        ("client-ca.pem", &c.ca_pem),
        ("client-ca.key", &c.ca_key_pem),
        ("broker.pem", &c.broker_cert_pem),
        ("broker.key", &c.broker_key_pem),
        ("endpoint.pem", &c.endpoint_cert_pem),
        ("endpoint.key", &c.endpoint_key_pem),
        ("other.pem", &c.other_cert_pem),
        ("other.key", &c.other_key_pem),
    ] {
        std::fs::write(dir.join("certs").join(name), body).unwrap();
    }
}

/// A LOCAL config over `root`, with a low read cap and a low volume threshold so
/// the tests can reach both without moving much data: the authored file at
/// `path` and its device half beside it.
#[allow(dead_code)] // url_mode writes its own, from config_json
pub fn write_config(path: &std::path::Path, root: &std::path::Path, pin: &ContentHash) {
    let (authored, device) = config_json(root, pin);
    std::fs::write(path, authored).unwrap();
    std::fs::write(sluse_proto::config::device_path(path), device).unwrap();
}

/// The two halves [`write_config`] writes.
pub fn config_json(root: &std::path::Path, pin: &ContentHash) -> (String, String) {
    let authored = format!(
        r#"{{
          "schemaVersion": 3,
          "sources": [{{
            "name": "fixture",
            "kind": {{ "type": "local-folder", "address": {{ "root": {root} }} }},
            "scope": ["in-scope"],
            "sensitivity": 2
          }}],
          "volume": {{ "admissions": 3, "windowSeconds": 60 }}
        }}"#,
        root = serde_json::to_string(root).unwrap(),
    );
    let device = format!(
        r#"{{
          "boxId": "box-local-test",
          "environment": "local",
          "maxReadBytes": 4096,
          "broker": {{
            "listen": "127.0.0.1:7580",
            "url": "https://127.0.0.1:7580",
            "certPath": "certs/broker.pem",
            "keyPath": "certs/broker.key",
            "clientCaPath": "certs/client-ca.pem",
            "certPin": "{pin}"
          }},
          "endpoint": {{
            "clientCertPath": "certs/endpoint.pem",
            "clientKeyPath": "certs/endpoint.key",
            "consoleListen": "127.0.0.1:7582"
          }},
          "artifacts": "artifacts",
          "workspace": "workspace",
          "journalDir": "journal",
          "audit": {{ "sink": "jsonl", "path": "audit/broker.jsonl" }}
        }}"#,
        pin = pin.as_str(),
    );
    (authored, device)
}

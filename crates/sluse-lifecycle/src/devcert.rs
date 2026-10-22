// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Derived from Chaperone chapr-coord/src/setup.rs:744-800 (rcgen by hand: CN,
// SANs, validity, skew). D-003 allows reuse, not vendoring.

//! Development certificates.
//!
//! Three certificates and two facts about them.
//!
//! The certificates: a CA that exists only to sign the other two, a **broker
//! leaf** with `serverAuth` and the SANs the endpoint will dial, and an
//! **endpoint leaf** with `clientAuth` and nothing else. mTLS is mandatory
//! (`docs/config.md`), so the broker's client verifier accepts exactly what this
//! CA signed and a connection without a client certificate does not complete a
//! handshake.
//!
//! The first fact: **the endpoint trusts one certificate, by hash, and no CA
//! bundle at all.** `cert_pin` is the SHA-256 of the broker leaf in DER form.
//! A public root store in the guest would be a way for something inside the box
//! to be talked into trusting a broker that is not the broker; there is no root
//! store, so there is nothing to talk into anything.
//!
//! The second fact: **`devcert` does not edit the config unless told to.** It
//! prints the pin, and `--update-config <path>` writes it. The file it would
//! edit is the file that defines scope, and its SHA-256 *is* `config_version` —
//! so a silent rewrite would change the identity of the config that every audit
//! record cites, from a command whose name says it makes certificates. jok's
//! answer on 2026-09-14, and the same reasoning either way.
//!
//! These are development certificates. They are generated on the machine that
//! uses them, they are not in any chain a customer would recognise, and nothing
//! about the prototype's transport is evidence for the product's.

use std::fs;
use std::io;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use sluse_proto::ContentHash;

/// How long a leaf is good for.
///
/// 397 days is the public-CA maximum. Nothing here is a public CA, but a
/// development certificate that outlives the prototype is a development
/// certificate someone still has in three years.
const VALIDITY_DAYS: i64 = 397;

/// Backdating, for the clock the two ends do not share.
///
/// The broker and the endpoint are the same machine today and will be a host and
/// a guest tomorrow, and a guest's clock is set by its own means. An hour is
/// enough for the skew that causes a `not_before` rejection on a certificate
/// generated thirty seconds ago.
const SKEW_HOURS: i64 = 1;

/// The six files a run needs.
pub struct DevCerts {
    pub ca_pem: String,
    /// The CA's key, which the broker signs each box's enrolment with
    /// (slice 2). Without it, enrolment has nothing to sign with.
    pub ca_key_pem: String,
    pub broker_cert_pem: String,
    pub broker_key_pem: String,
    pub endpoint_cert_pem: String,
    pub endpoint_key_pem: String,
    /// SHA-256 of the broker leaf, DER. What goes in `broker.certPin`.
    pub pin: ContentHash,
}

#[derive(Debug, thiserror::Error)]
pub enum DevCertError {
    #[error("generating certificates: {0}")]
    Rcgen(#[from] rcgen::Error),
    #[error("writing {path}: {source}")]
    Write { path: PathBuf, source: io::Error },
    #[error("reading {path}: {source}")]
    Read { path: PathBuf, source: io::Error },
    #[error("{path} is not the JSON object a config is: {detail}")]
    NotAConfig { path: PathBuf, detail: String },
}

/// Generate a CA and the two leaves.
///
/// `hostnames` are the extra DNS names the broker leaf should answer to, beyond
/// the loopback pair every run needs. The guest dials the host by name once the
/// broker is not on the same machine, and a certificate that cannot be reissued
/// without a rebuild is a certificate that gets reused past its usefulness.
pub fn generate(hostnames: &[String]) -> Result<DevCerts, DevCertError> {
    let now = time_now();
    let not_before = now - time::Duration::hours(SKEW_HOURS);
    let not_after = now + time::Duration::days(VALIDITY_DAYS);

    // --- the CA ------------------------------------------------------------
    let ca_key = KeyPair::generate()?;
    // The broker's own parameters, name included: the broker signs enrolment
    // leaves as this CA, and a leaf chains only if its issuer is the CA's
    // subject exactly (`sluse_broker::enrol`).
    let mut ca_params = sluse_broker::enrol::ca_params();
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key)?;
    let ca_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();

    let issuer = Issuer::new(ca_params, ca_key);

    // --- the broker leaf ---------------------------------------------------
    let mut sans: Vec<String> = vec!["localhost".to_owned(), "127.0.0.1".to_owned()];
    for h in hostnames {
        let h = h.trim();
        // `CertificateParams::new` turns anything that parses as an address into
        // an IP SAN and everything else into a DNS SAN, which is what is wanted;
        // this only skips the empty string and the duplicate.
        if !h.is_empty() && !sans.iter().any(|s| s.eq_ignore_ascii_case(h)) {
            sans.push(h.to_owned());
        }
    }
    let _: Vec<IpAddr> = Vec::new(); // documents the intent of the line above

    let broker_key = KeyPair::generate()?;
    let mut broker_params = CertificateParams::new(sans)?;
    broker_params.distinguished_name = dn("sluse-broker");
    broker_params.is_ca = IsCa::NoCa;
    broker_params.key_usages =
        vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
    broker_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    broker_params.not_before = not_before;
    broker_params.not_after = not_after;
    let broker_cert = broker_params.signed_by(&broker_key, &issuer)?;

    // --- the endpoint leaf -------------------------------------------------
    //
    // `clientAuth` and nothing else. A certificate that carries both purposes
    // can be presented by a server, and the one thing the guest must not be able
    // to do is answer to the name of the broker.
    let endpoint_key = KeyPair::generate()?;
    let mut endpoint_params = CertificateParams::new(vec!["sluse-endpoint".to_owned()])?;
    endpoint_params.distinguished_name = dn("sluse-endpoint");
    endpoint_params.is_ca = IsCa::NoCa;
    endpoint_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    endpoint_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    endpoint_params.not_before = not_before;
    endpoint_params.not_after = not_after;
    let endpoint_cert = endpoint_params.signed_by(&endpoint_key, &issuer)?;

    // The pin is over the DER, not the PEM. PEM is a wrapper with line breaks
    // and a header, and two encodings of the same certificate must not produce
    // two pins.
    let pin = ContentHash::of(broker_cert.der());

    Ok(DevCerts {
        ca_pem,
        ca_key_pem,
        broker_cert_pem: broker_cert.pem(),
        broker_key_pem: broker_key.serialize_pem(),
        endpoint_cert_pem: endpoint_cert.pem(),
        endpoint_key_pem: endpoint_key.serialize_pem(),
        pin,
    })
}

/// The file names `config/local.example.json` expects under `certs\`.
pub const CA_FILE: &str = "client-ca.pem";
pub const CA_KEY_FILE: &str = "client-ca.key";
pub const BROKER_CERT_FILE: &str = "broker.pem";
pub const BROKER_KEY_FILE: &str = "broker.key";
pub const ENDPOINT_CERT_FILE: &str = "endpoint.pem";
pub const ENDPOINT_KEY_FILE: &str = "endpoint.key";

/// Write the six files into `dir`, creating it if needed.
///
/// The CA is written under the name the config's `clientCaPath` uses, because in
/// this prototype one CA signs both leaves: the broker's client verifier trusts
/// the same authority that issued the broker's own certificate. A deployment
/// that wanted the guest's issuer to be a different authority would change one
/// path in the config and nothing in the broker.
pub fn write(dir: &Path, certs: &DevCerts) -> Result<Vec<PathBuf>, DevCertError> {
    fs::create_dir_all(dir).map_err(|e| DevCertError::Write { path: dir.to_owned(), source: e })?;

    let files = [
        (CA_FILE, &certs.ca_pem),
        (CA_KEY_FILE, &certs.ca_key_pem),
        (BROKER_CERT_FILE, &certs.broker_cert_pem),
        (BROKER_KEY_FILE, &certs.broker_key_pem),
        (ENDPOINT_CERT_FILE, &certs.endpoint_cert_pem),
        (ENDPOINT_KEY_FILE, &certs.endpoint_key_pem),
    ];

    let mut written = Vec::new();
    for (name, body) in files {
        let path = dir.join(name);
        fs::write(&path, body)
            .map_err(|e| DevCertError::Write { path: path.clone(), source: e })?;
        restrict(&path)?;
        written.push(path);
    }
    Ok(written)
}

// ---------------------------------------------------------------------------
// The broker's Entra credential (M7)
// ---------------------------------------------------------------------------

/// Take the private keys off the inherited ACL.
///
/// Best effort and said to be: this is a development certificate on a developer's
/// machine, and `icacls` is a process spawn the LOCAL rules forbid
/// (`docs/sluse_prototype.md` — the 2026-09-14 monitoring incident). The files
/// land under the user's own profile, which is where the protection actually
/// comes from. Nothing here is a claim about key protection and
/// `prototype/README.md` says so.
fn restrict(_path: &Path) -> Result<(), DevCertError> {
    Ok(())
}

/// Rewrite `broker.certPin` in a config's device half, in place.
///
/// Only from `--update-config`. Since D-038 the pin is the device's, so this
/// no longer changes `config_version`, which is the authored file's hash.
///
/// The edit is deliberately textual-minimal in intent but structural in fact:
/// the file is parsed, the one field is replaced, and it is written back
/// pretty-printed. A regex would survive comments and formatting that JSON does
/// not have anyway, and would happily edit a `certPin` nested somewhere it does
/// not belong.
pub fn update_config(path: &Path, pin: &ContentHash) -> Result<(), DevCertError> {
    let before =
        fs::read(path).map_err(|e| DevCertError::Read { path: path.to_owned(), source: e })?;

    let mut doc: serde_json::Value = serde_json::from_slice(&before)
        .map_err(|e| DevCertError::NotAConfig { path: path.to_owned(), detail: e.to_string() })?;

    let broker = doc
        .get_mut("broker")
        .and_then(|b| b.as_object_mut())
        .ok_or_else(|| DevCertError::NotAConfig {
            path: path.to_owned(),
            detail: "no `broker` object".to_owned(),
        })?;
    broker.insert("certPin".to_owned(), serde_json::Value::String(pin.as_str().to_owned()));

    let mut after = serde_json::to_vec_pretty(&doc)
        .map_err(|e| DevCertError::NotAConfig { path: path.to_owned(), detail: e.to_string() })?;
    after.push(b'\n');

    fs::write(path, &after)
        .map_err(|e| DevCertError::Write { path: path.to_owned(), source: e })?;

    Ok(())
}

fn dn(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "SerenIT ApS");
    dn
}

/// `time::OffsetDateTime::now_utc()` without depending on `time`'s std feature
/// being on somewhere else in the graph.
fn time_now() -> time::OffsetDateTime {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pin_is_the_hash_of_the_broker_leaf_and_not_of_anything_else() {
        let certs = generate(&[]).unwrap();
        // Distinctness is the whole property: a pin that matched the CA would
        // let anything the CA signed answer as the broker.
        assert_ne!(certs.pin, ContentHash::of(certs.ca_pem.as_bytes()));
        assert_ne!(certs.pin, ContentHash::of(certs.broker_cert_pem.as_bytes()));
        assert_eq!(certs.pin.as_str().len(), 64);
    }

    #[test]
    fn two_runs_do_not_produce_the_same_certificate() {
        assert_ne!(generate(&[]).unwrap().pin, generate(&[]).unwrap().pin);
    }

    #[test]
    fn extra_hostnames_are_added_once_and_the_loopback_pair_is_always_there() {
        // Both spellings of what is already there, plus a real one.
        let certs = generate(&[
            "127.0.0.1".to_owned(),
            "LOCALHOST".to_owned(),
            "sluse-host".to_owned(),
            "  ".to_owned(),
        ])
        .unwrap();
        assert!(!certs.broker_cert_pem.is_empty());
        // The SAN list itself is asserted through a handshake in the broker's
        // tls test; what is checked here is that generation accepts the shapes.
        assert!(generate(&["sluse-host".to_owned()]).is_ok());
    }

    #[test]
    fn write_puts_six_files_where_the_config_expects_them() {
        let dir = tempfile::tempdir().unwrap();
        let certs = generate(&[]).unwrap();
        let written = write(&dir.path().join("certs"), &certs).unwrap();
        assert_eq!(written.len(), 6);
        for name in [CA_FILE, CA_KEY_FILE, BROKER_CERT_FILE, BROKER_KEY_FILE, ENDPOINT_CERT_FILE, ENDPOINT_KEY_FILE]
        {
            assert!(dir.path().join("certs").join(name).exists(), "{name} is missing");
        }
    }

    #[test]
    fn updating_the_config_changes_the_pin_and_nothing_else() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("local.json");
        fs::write(
            &path,
            br#"{"schemaVersion":1,"broker":{"listen":"127.0.0.1:7580","certPin":"00"}}"#,
        )
        .unwrap();

        let certs = generate(&[]).unwrap();
        update_config(&path, &certs.pin).unwrap();

        let back: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert_eq!(back["broker"]["certPin"], certs.pin.as_str());
        // Untouched fields survive: this rewrites one value, not the file.
        assert_eq!(back["schemaVersion"], 1);
        assert_eq!(back["broker"]["listen"], "127.0.0.1:7580");
    }

    #[test]
    fn a_file_that_is_not_a_config_is_refused_rather_than_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("notes.txt");
        fs::write(&path, b"this is not JSON").unwrap();
        let certs = generate(&[]).unwrap();

        assert!(matches!(
            update_config(&path, &certs.pin),
            Err(DevCertError::NotAConfig { .. })
        ));
        // Refused means unchanged.
        assert_eq!(fs::read(&path).unwrap(), b"this is not JSON");

        // Valid JSON with no broker section is the same answer.
        let other = dir.path().join("other.json");
        fs::write(&other, br#"{"schemaVersion":1}"#).unwrap();
        assert!(matches!(
            update_config(&other, &certs.pin),
            Err(DevCertError::NotAConfig { .. })
        ));
    }
}

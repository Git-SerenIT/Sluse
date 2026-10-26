// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Enrolment: how a box gets its identity with no file crossing (slice 2,
//! D-024 point 7, D-027 design points 4 and 5).
//!
//! The service starts Gate Core with the **hash** of a single-use token and
//! writes the token itself into the box's KVP pool. The box makes its own key
//! pair, sends the public half and the token to the enrolment listener, and is
//! given a client certificate signed by the client CA, plus Gate Core's
//! config file byte for byte. The private key never leaves the box.
//!
//! **What the token is and is not.** It proves the caller read this open's
//! KVP pool, which only the box's root and the host can. It does not make the
//! box trustworthy: a box is untrusted by design, and an enrolled one is
//! served under the same scope as any other (invariant 2). What the leaf buys
//! is that the mTLS listener keeps refusing anything that did not enrol.
//!
//! **The CA's name is fixed** ([`ca_params`]). A leaf's issuer must be the
//! CA's subject, and reading that back from the CA certificate would take an
//! X.509 parser this crate does not otherwise need. So the one function that
//! makes the CA is the one that names it, and `sluse devcert` calls it.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, PublicKeyData, SignatureAlgorithm, PKCS_ECDSA_P256_SHA256,
};
use sluse_proto::wire::{EnrolRequest, EnrolResponse};
use sluse_proto::{ContentHash, Loaded, SluseError};

/// How long a box's leaf is valid. The box enrols again at every start from
/// off, so this only has to outlast a box left running: a month of that.
pub const LEAF_DAYS: i64 = 30;

/// The client CA's parameters, name included. Every CA that signs endpoint
/// leaves is made from these, or its leaves will not chain.
pub fn ca_params() -> CertificateParams {
    let mut p = CertificateParams::default();
    p.distinguished_name = name("Sluse development CA");
    // Path length 0: this CA signs leaves and cannot mint another CA.
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    p
}

pub fn name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(DnType::OrganizationName, "SerenIT ApS");
    dn
}

/// The CA's private key sits beside its certificate: `client-ca.pem`, then
/// `client-ca.key`.
pub fn ca_key_path(client_ca: &Path) -> PathBuf {
    client_ca.with_extension("key")
}

/// Now, as `time` wants it, without depending on `time`'s std feature.
pub fn now() -> time::OffsetDateTime {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    time::OffsetDateTime::from_unix_timestamp(secs).unwrap_or(time::OffsetDateTime::UNIX_EPOCH)
}

pub struct Enrolment {
    issuer: Issuer<'static, KeyPair>,
    config: String,
    device: String,
    box_id: String,
    /// `None` once used. One token, one enrolment, so one leaf: Gate Front
    /// pins the one Core's answer carries (D-058, D-071).
    token: Mutex<Option<ContentHash>>,
}

impl Enrolment {
    /// From Gate Core's own config: the CA beside `core.clientCaPath`, and
    /// the config's two files as they are on disk, refused if either has
    /// changed since Gate Core loaded it.
    pub fn load(loaded: &Loaded, token: ContentHash) -> Result<Self, String> {
        let ca = loaded.resolve(&loaded.config.gate.client_ca_path);
        let key_path = ca_key_path(&ca);
        let key = std::fs::read_to_string(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
        let ca_pem = std::fs::read_to_string(&ca).map_err(|e| format!("{}: {e}", ca.display()))?;
        let read = |path: &std::path::Path, version: &ContentHash| {
            let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            if ContentHash::of(&bytes) != *version {
                return Err(format!("{} changed after Gate Core loaded it", path.display()));
            }
            String::from_utf8(bytes).map_err(|_| format!("{} is not UTF-8", path.display()))
        };
        let config = read(&loaded.file, &loaded.version)?;
        let device = read(&sluse_proto::config::device_path(&loaded.file), &loaded.device_version)?;
        Self::new(&key, &ca_pem, config, device, loaded.config.box_id.to_string(), token)
    }

    pub fn new(
        ca_key_pem: &str,
        ca_pem: &str,
        config: String,
        device: String,
        box_id: String,
        token: ContentHash,
    ) -> Result<Self, String> {
        let key = KeyPair::from_pem(ca_key_pem).map_err(|e| format!("the client CA's key: {e}"))?;
        // A key that is not the CA's would sign leaves nothing trusts, and the
        // box would fail at its first mTLS call with no hint why.
        let der = rustls::pki_types::pem::PemObject::from_pem_slice(ca_pem.as_bytes())
            .map(|c: rustls::pki_types::CertificateDer<'static>| c.to_vec())
            .map_err(|_| "the client CA certificate is not PEM".to_owned())?;
        if !der.windows(key.public_key_raw().len()).any(|w| w == key.public_key_raw()) {
            return Err("the client CA's key is not the key of the client CA's certificate".into());
        }
        Ok(Enrolment { issuer: Issuer::new(ca_params(), key), config, device, box_id, token: Mutex::new(Some(token)) })
    }

    pub fn enrol(&self, req: &EnrolRequest) -> Result<EnrolResponse, SluseError> {
        let refuse = |detail: &str| SluseError::EnrolmentRefused { detail: detail.to_owned() };
        let point = unhex(&req.public_key)
            .filter(|p| p.len() == 65 && p[0] == 0x04)
            .ok_or_else(|| refuse("the key is not an uncompressed P-256 point"))?;
        {
            let mut token = self.token.lock().unwrap_or_else(|p| p.into_inner());
            match token.as_ref() {
                None => return Err(refuse("this open's token is already used")),
                Some(expected) if *expected != ContentHash::of(req.token.as_bytes()) => {
                    return Err(refuse("not this open's token"));
                }
                Some(_) => *token = None,
            }
        }
        let mut p = CertificateParams::new(vec!["sluse-endpoint".to_owned()])
            .map_err(|e| SluseError::Internal { message: e.to_string() })?;
        p.distinguished_name = name(&self.box_id);
        p.is_ca = IsCa::NoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        // `clientAuth` only: the box must never be able to answer as a server.
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let now = now();
        p.not_before = now - time::Duration::hours(1);
        p.not_after = now + time::Duration::days(LEAF_DAYS);
        // ponytail: the point is not checked to be on the curve; a bad one only
        // yields a leaf the box itself cannot use.
        let cert = p
            .signed_by(&P256(&point), &self.issuer)
            .map_err(|e| SluseError::Internal { message: e.to_string() })?;
        eprintln!("enrolled box {:?} as {}", printable(&req.hostname), self.box_id);
        Ok(EnrolResponse { cert_pem: cert.pem(), config: self.config.clone(), device: self.device.clone() })
    }
}

struct P256<'a>(&'a [u8]);

impl PublicKeyData for P256<'_> {
    fn der_bytes(&self) -> &[u8] {
        self.0
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ECDSA_P256_SHA256
    }
}

pub fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len()).step_by(2).map(|i| s.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok())).collect()
}

/// A name from the box goes into a log line: short, and nothing that is not
/// a hostname character.
fn printable(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.').take(64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ca() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let cert = ca_params().self_signed(&key).unwrap();
        (key.serialize_pem(), cert.pem())
    }

    fn request(token: &str) -> EnrolRequest {
        let key = KeyPair::generate().unwrap();
        let public_key = key.public_key_raw().iter().map(|b| format!("{b:02x}")).collect();
        EnrolRequest { token: token.into(), public_key, hostname: "box\n; evil".into() }
    }

    #[test]
    fn a_token_works_once_and_a_wrong_one_not_at_all() {
        let (key, pem) = ca();
        let e = Enrolment::new(&key, &pem, "{}".into(), "{}".into(), "box-a".into(), ContentHash::of(b"right")).unwrap();
        let wrong = e.enrol(&request("wrong")).unwrap_err();
        assert_eq!(wrong.reason_code(), "ENROLMENT_REFUSED");
        let ok = e.enrol(&request("right")).unwrap();
        assert!(ok.cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert_eq!(ok.config, "{}");
        let again = e.enrol(&request("right")).unwrap_err();
        assert!(again.to_string().contains("already used"), "{again}");
    }

    #[test]
    fn a_wrong_token_does_not_use_up_the_right_one() {
        let (key, pem) = ca();
        let e = Enrolment::new(&key, &pem, "{}".into(), "{}".into(), "box-a".into(), ContentHash::of(b"right")).unwrap();
        for _ in 0..3 {
            assert!(e.enrol(&request("guess")).is_err());
        }
        assert!(e.enrol(&request("right")).is_ok());
    }

    #[test]
    fn a_key_that_is_not_a_p256_point_is_refused_before_the_token_is_spent() {
        let (key, pem) = ca();
        let e = Enrolment::new(&key, &pem, "{}".into(), "{}".into(), "box-a".into(), ContentHash::of(b"t")).unwrap();
        for bad in ["", "zz", &"04".repeat(64), &format!("05{}", "00".repeat(64))] {
            let r = EnrolRequest { public_key: bad.to_owned(), ..request("t") };
            assert!(e.enrol(&r).is_err(), "{bad:.8}");
        }
        assert!(e.enrol(&request("t")).is_ok(), "the token survived the bad keys");
    }

    #[test]
    fn a_ca_key_that_is_not_the_cas_is_refused_at_load() {
        let (_, pem) = ca();
        let (other_key, _) = ca();
        let err = Enrolment::new(&other_key, &pem, "{}".into(), "{}".into(), "b".into(), ContentHash::of(b"t")).err().unwrap();
        assert!(err.contains("not the key"), "{err}");
    }

    #[test]
    fn hex_round_trips_and_refuses_what_is_not_hex() {
        assert_eq!(unhex("00ff10"), Some(vec![0, 255, 16]));
        assert_eq!(unhex("0"), None);
        assert_eq!(unhex("gg"), None);
        assert_eq!(unhex("é0"), None);
        assert_eq!(printable("box\n; evil"), "boxevil");
    }
}

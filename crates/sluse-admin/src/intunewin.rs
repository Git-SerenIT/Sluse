// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! An `.intunewin`, written by our own code (D-039 point 2), in the shape
//! Microsoft's Win32 Content Prep Tool writes:
//!
//! - the source folder zipped, then encrypted with AES-256-CBC (PKCS#7)
//!   under a random key and IV, and an HMAC-SHA256 under a second random key
//!   over the IV and the ciphertext. The encrypted file is
//!   `HMAC (32 bytes) ‖ IV (16) ‖ ciphertext`;
//! - `Detection.xml`, naming the setup file and carrying the keys, the MAC
//!   and the SHA-256 of the unencrypted zip, which Intune needs to decrypt it
//!   on the device;
//! - both in an outer zip, at `IntuneWinPackage/Contents/IntunePackage.intunewin`
//!   and `IntuneWinPackage/Metadata/Detection.xml`.
//!
//! **Built from the documented and observed shape, not checked by Intune
//! yet**: the demo tenant's upload is where it is (`next-run.md`). The keys
//! are in `Detection.xml` in clear, as in Microsoft's own, so the file is no
//! more secret than the folder it holds.
//!
//! ponytail: everything in memory; the MSI is a few hundred MB at most.
//! Stream it if that changes.

use std::path::Path;

use aws_lc_rs::cipher::{EncryptionContext, PaddedBlockEncryptingKey, UnboundCipherKey, AES_256};
use aws_lc_rs::{digest, hmac};

use crate::setup::base64;
use crate::zip;

pub const CONTENT: &str = "IntuneWinPackage/Contents/IntunePackage.intunewin";
pub const DETECTION: &str = "IntuneWinPackage/Metadata/Detection.xml";

/// What Intune needs to decrypt the content: Graph's `fileEncryptionInfo`,
/// and `Detection.xml`'s `EncryptionInfo`, all base64.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionInfo {
    pub encryption_key: String,
    pub mac_key: String,
    pub initialization_vector: String,
    pub mac: String,
    pub profile_identifier: String,
    pub file_digest: String,
    pub file_digest_algorithm: String,
}

/// A built package: the `.intunewin` to save, and its parts, for Graph's
/// upload, which takes the encrypted content and the info separately.
pub struct Package {
    pub intunewin: Vec<u8>,
    pub encrypted: Vec<u8>,
    pub info: EncryptionInfo,
    pub unencrypted_size: u64,
    pub setup_file: String,
}

/// Package every file under `source`, with `setup_file` (a file in it) as
/// what Intune runs.
pub fn build(source: &Path, setup_file: &str) -> Result<Package, String> {
    if !source.join(setup_file).is_file() {
        return Err(format!("{} has no {setup_file}", source.display()));
    }
    let mut files = Vec::new();
    collect(source, source, &mut files)?;
    let entries: Vec<zip::Entry<'_>> =
        files.iter().map(|(name, data)| zip::Entry { name, data, deflate: true }).collect();
    let inner = zip::write(&entries)?;
    let (encrypted, info) = encrypt(&inner)?;
    let xml = detection_xml(setup_file, inner.len() as u64, &info);
    let intunewin = zip::write(&[
        zip::Entry { name: CONTENT, data: &encrypted, deflate: false },
        zip::Entry { name: DETECTION, data: xml.as_bytes(), deflate: true },
    ])?;
    Ok(Package { intunewin, encrypted, info, unencrypted_size: inner.len() as u64, setup_file: setup_file.to_owned() })
}

fn collect(root: &Path, dir: &Path, out: &mut Vec<(String, Vec<u8>)>) -> Result<(), String> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let path = e.path();
        if path.is_dir() {
            collect(root, &path, out)?;
        } else {
            let name = path.strip_prefix(root).map_err(|e| e.to_string())?.to_string_lossy().replace('\\', "/");
            out.push((name, std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?));
        }
    }
    Ok(())
}

fn random<const N: usize>() -> Result<[u8; N], String> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|e| format!("no randomness: {e}"))?;
    Ok(b)
}

fn encrypt(plain: &[u8]) -> Result<(Vec<u8>, EncryptionInfo), String> {
    let (key, mac_key, iv) = (random::<32>()?, random::<32>()?, random::<16>()?);
    let cbc = PaddedBlockEncryptingKey::cbc_pkcs7(UnboundCipherKey::new(&AES_256, &key).map_err(|_| "an AES key")?)
        .map_err(|_| "an AES-CBC key")?;
    let mut body = plain.to_vec();
    cbc.less_safe_encrypt(&mut body, EncryptionContext::Iv128(iv.into())).map_err(|_| "encrypting")?;
    let mut signed = Vec::with_capacity(16 + body.len());
    signed.extend_from_slice(&iv);
    signed.extend_from_slice(&body);
    let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &mac_key), &signed);
    let mut file = Vec::with_capacity(32 + signed.len());
    file.extend_from_slice(mac.as_ref());
    file.extend_from_slice(&signed);
    let info = EncryptionInfo {
        encryption_key: base64(&key),
        mac_key: base64(&mac_key),
        initialization_vector: base64(&iv),
        mac: base64(mac.as_ref()),
        profile_identifier: "ProfileVersion1".into(),
        file_digest: base64(digest::digest(&digest::SHA256, plain).as_ref()),
        file_digest_algorithm: "SHA256".into(),
    };
    Ok((file, info))
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

fn detection_xml(setup_file: &str, size: u64, i: &EncryptionInfo) -> String {
    let setup = xml_escape(setup_file);
    format!(
        r#"<ApplicationInfo xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ToolVersion="1.8.6.0">
  <Name>{setup}</Name>
  <UnencryptedContentSize>{size}</UnencryptedContentSize>
  <FileName>IntunePackage.intunewin</FileName>
  <SetupFile>{setup}</SetupFile>
  <EncryptionInfo>
    <EncryptionKey>{}</EncryptionKey>
    <MacKey>{}</MacKey>
    <InitializationVector>{}</InitializationVector>
    <Mac>{}</Mac>
    <ProfileIdentifier>ProfileVersion1</ProfileIdentifier>
    <FileDigest>{}</FileDigest>
    <FileDigestAlgorithm>SHA256</FileDigestAlgorithm>
  </EncryptionInfo>
</ApplicationInfo>
"#,
        i.encryption_key, i.mac_key, i.initialization_vector, i.mac, i.file_digest
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::cipher::{DecryptionContext, PaddedBlockDecryptingKey};

    fn unbase64(s: &str) -> Vec<u8> {
        crate::setup::base64_decode(s).unwrap()
    }

    fn between<'a>(xml: &'a str, tag: &str) -> &'a str {
        let open = format!("<{tag}>");
        let start = xml.find(&open).unwrap() + open.len();
        &xml[start..start + xml[start..].find("</").unwrap()]
    }

    /// Intune's side, as far as it is documented: read Detection.xml, check
    /// the MAC, decrypt, check the digest, unzip.
    #[test]
    fn what_is_packaged_decrypts_with_what_detection_xml_says() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Install-Sluse.ps1"), "Write-Host hi").unwrap();
        std::fs::write(dir.path().join("sluse.json"), "{}").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub").join("x.txt"), "x").unwrap();
        let p = build(dir.path(), "Install-Sluse.ps1").unwrap();

        let outer = zip::read(&p.intunewin).unwrap();
        let names: Vec<&str> = outer.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, [CONTENT, DETECTION]);
        let xml = String::from_utf8(outer[1].1.clone()).unwrap();
        assert_eq!(between(&xml, "SetupFile"), "Install-Sluse.ps1");
        assert_eq!(between(&xml, "Mac"), p.info.mac);
        let content = &outer[0].1;
        assert_eq!(*content, p.encrypted);

        let (mac, signed) = content.split_at(32);
        let key = hmac::Key::new(hmac::HMAC_SHA256, &unbase64(between(&xml, "MacKey")));
        hmac::verify(&key, signed, mac).expect("the MAC is over IV and ciphertext");
        let (iv, body) = signed.split_at(16);
        assert_eq!(iv, unbase64(between(&xml, "InitializationVector")));
        let aes = UnboundCipherKey::new(&AES_256, &unbase64(between(&xml, "EncryptionKey"))).unwrap();
        let mut buf = body.to_vec();
        let plain = PaddedBlockDecryptingKey::cbc_pkcs7(aes)
            .unwrap()
            .decrypt(&mut buf, DecryptionContext::Iv128(<[u8; 16]>::try_from(iv).unwrap().into()))
            .unwrap()
            .to_vec();
        assert_eq!(plain.len() as u64, p.unencrypted_size);
        assert_eq!(between(&xml, "UnencryptedContentSize"), p.unencrypted_size.to_string());
        assert_eq!(base64(digest::digest(&digest::SHA256, &plain).as_ref()), between(&xml, "FileDigest"));
        let inner = zip::read(&plain).unwrap();
        let inner: Vec<&str> = inner.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(inner, ["Install-Sluse.ps1", "sluse.json", "sub/x.txt"]);

        // Every build has its own keys.
        assert_ne!(build(dir.path(), "Install-Sluse.ps1").unwrap().info.encryption_key, p.info.encryption_key);
        assert!(build(dir.path(), "missing.ps1").is_err());
    }
}

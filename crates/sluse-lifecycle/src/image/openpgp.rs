// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Canonical's signature on `SHA256SUMS`, checked against one pinned key.
//!
//! The image is the box's whole operating system, so its checksum list is a
//! trust boundary: HTTPS says the bytes came from Canonical's host, and the
//! signature says Canonical's image builder made the list, whatever happened
//! to the host.
//!
//! **Exactly one shape is accepted**, the one Canonical publishes:
//! - a v4 detached signature, armored;
//! - class 0x00 (binary);
//! - RSA with SHA-512;
//! - made by the key pinned here.
//!
//! That is about eighty lines on the `aws-lc-rs` already in the graph, not an
//! OpenPGP library. Anything else is refused by name, so a change on
//! Canonical's side shows up as a clear failure, not a silent pass.
//!
//! The key is Ubuntu's own `ubuntu-cloudimage-keyring`, "UEC Image Automatic
//! Signing Key <cdimage@ubuntu.com>": the public-key packet, embedded, and
//! checked against its fingerprint at every use.

use aws_lc_rs::digest;
use aws_lc_rs::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA512};

const KEY_PACKET: &[u8] = include_bytes!("canonical-cloudimage.pgp");
pub const FINGERPRINT: &str = "D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81";

/// Verify `signature` (armored) over `data`.
pub fn verify(data: &[u8], armored: &str) -> Result<(), String> {
    let (n, e) = pinned_key()?;
    let sig = dearmor(armored)?;
    let (tag, body) = packet(&sig)?;
    if tag != 2 {
        return Err(format!("the signature file holds packet type {tag}, not a signature"));
    }
    // version, class, key algorithm, hash algorithm, hashed length.
    if body.len() < 6 {
        return Err("the signature packet is truncated".into());
    }
    let (version, class, algo, hash) = (body[0], body[1], body[2], body[3]);
    if (version, class, algo, hash) != (4, 0x00, 1, 10) {
        return Err(format!(
            "an unexpected signature: version {version}, class {class:#04x}, key algorithm {algo}, hash {hash} \
             (Canonical's is 4, 0x00, RSA, SHA-512)"
        ));
    }
    let hashed_len = u16::from_be_bytes([body[4], body[5]]) as usize;
    let hashed_end = 6 + hashed_len;
    let unhashed_len = be16(body, hashed_end)? as usize;
    let mpi_at = hashed_end + 2 + unhashed_len + 2; // skip the 16-bit hash prefix
    let (s, _) = mpi(body, mpi_at)?;

    // RFC 4880 5.2.4: the data, the signature's own hashed part, and a
    // trailer that says how long that part was.
    let mut message = Vec::with_capacity(data.len() + hashed_end + 6);
    message.extend_from_slice(data);
    message.extend_from_slice(&body[..hashed_end]);
    message.extend_from_slice(&[0x04, 0xFF]);
    message.extend_from_slice(&(hashed_end as u32).to_be_bytes());

    // The MPI drops leading zero bytes; RSA verification wants the full width.
    let mut padded = vec![0u8; n.len().saturating_sub(s.len())];
    padded.extend_from_slice(s);
    RsaPublicKeyComponents { n, e }
        .verify(&RSA_PKCS1_2048_8192_SHA512, &message, &padded)
        .map_err(|_| format!("the signature does not verify against Canonical's key {FINGERPRINT}"))
}

/// The embedded key's modulus and exponent, refused unless the packet is the
/// one whose fingerprint is pinned.
fn pinned_key() -> Result<(&'static [u8], &'static [u8]), String> {
    let (tag, body) = packet(KEY_PACKET)?;
    let fpr = {
        let mut v = vec![0x99];
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, &v)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<String>()
    };
    if tag != 6 || body.first() != Some(&4) || body.get(5) != Some(&1) || fpr != FINGERPRINT {
        return Err("the embedded key is not Canonical's pinned key".into());
    }
    let (n, at) = mpi(body, 6)?;
    let (e, _) = mpi(body, at)?;
    Ok((n, e))
}

/// One OpenPGP packet: its tag and body. Old and new header formats.
fn packet(b: &[u8]) -> Result<(u8, &[u8]), String> {
    let short = || "the OpenPGP packet is truncated".to_owned();
    let ctb = *b.first().ok_or_else(short)?;
    if ctb & 0x80 == 0 {
        return Err("not an OpenPGP packet".into());
    }
    let (tag, len, head) = if ctb & 0x40 == 0 {
        let tag = (ctb >> 2) & 0x0F;
        match ctb & 3 {
            0 => (tag, *b.get(1).ok_or_else(short)? as usize, 2),
            1 => (tag, be16(b, 1)? as usize, 3),
            2 => (tag, u32::from_be_bytes(b.get(1..5).ok_or_else(short)?.try_into().unwrap()) as usize, 5),
            _ => return Err("an indeterminate-length packet".into()),
        }
    } else {
        let tag = ctb & 0x3F;
        match *b.get(1).ok_or_else(short)? {
            l @ 0..=191 => (tag, l as usize, 2),
            l @ 192..=223 => (tag, ((l as usize - 192) << 8) + *b.get(2).ok_or_else(short)? as usize + 192, 3),
            255 => (tag, u32::from_be_bytes(b.get(2..6).ok_or_else(short)?.try_into().unwrap()) as usize, 6),
            _ => return Err("a partial-length packet".into()),
        }
    };
    b.get(head..head + len).map(|body| (tag, body)).ok_or_else(short)
}

fn be16(b: &[u8], at: usize) -> Result<u16, String> {
    b.get(at..at + 2).map(|x| u16::from_be_bytes([x[0], x[1]])).ok_or_else(|| "the OpenPGP packet is truncated".into())
}

/// A multiprecision integer at `at`, and where the next field starts.
fn mpi(b: &[u8], at: usize) -> Result<(&[u8], usize), String> {
    let len = (be16(b, at)? as usize).div_ceil(8);
    b.get(at + 2..at + 2 + len).map(|v| (v, at + 2 + len)).ok_or_else(|| "the OpenPGP packet is truncated".into())
}

/// The body between the armor lines, without the `=` checksum line.
fn dearmor(s: &str) -> Result<Vec<u8>, String> {
    let start = s.find("-----BEGIN PGP SIGNATURE-----").ok_or("not an armored signature")?;
    // Searched after BEGIN: this runs before the signature is checked, and a
    // reversed armor would otherwise panic on the slice (R-54).
    let end = start + s[start..].find("-----END PGP SIGNATURE-----").ok_or("not an armored signature")?;
    let inner = &s[start..end];
    // The header block ends at the first blank line.
    let body = inner.split_once("\n\n").or_else(|| inner.split_once("\r\n\r\n")).ok_or("no armor body")?.1;
    let b64: String = body.lines().filter(|l| !l.starts_with('=')).collect::<String>().split_whitespace().collect();
    crate::run::base64_decode(&b64).ok_or_else(|| "the armor is not base64".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SUMS: &[u8] = include_bytes!("testdata/SHA256SUMS");
    const SIG: &str = include_str!("testdata/SHA256SUMS.gpg");

    #[test]
    fn an_end_line_before_the_begin_line_is_refused_not_a_panic() {
        assert!(dearmor("-----END PGP SIGNATURE-----\n-----BEGIN PGP SIGNATURE-----\n\nAAAA\n").is_err());
    }

    #[test]
    fn canonicals_signature_on_a_real_sha256sums_verifies() {
        verify(SUMS, SIG).unwrap();
    }

    #[test]
    fn one_changed_byte_in_the_list_or_the_signature_fails() {
        let mut sums = SUMS.to_vec();
        sums[10] ^= 1;
        assert!(verify(&sums, SIG).is_err());
        // A different image hash on the one line that matters.
        let forged = String::from_utf8(SUMS.to_vec()).unwrap().replacen("88", "89", 1);
        assert!(verify(forged.as_bytes(), SIG).is_err());
        let mut sig = SIG.to_owned();
        let i = sig.find("\n\n").unwrap() + 40;
        sig.replace_range(i..i + 1, if &sig[i..i + 1] == "A" { "B" } else { "A" });
        assert!(verify(SUMS, &sig).is_err());
        assert!(verify(SUMS, "not armor").is_err());
    }

    #[test]
    fn the_embedded_key_is_the_pinned_one() {
        let (n, e) = pinned_key().unwrap();
        assert_eq!(n.len(), 512, "RSA-4096");
        assert_eq!(e, [1, 0, 1]);
    }
}

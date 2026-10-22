// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The content hash: SHA-256, lowercase hex, 64 characters.
//!
//! One type for three jobs, deliberately:
//!
//! 1. **The hash of admitted or published bytes** (`docs/audit.md`, Fields).
//! 2. **`config_version`**, the hash of the config file as loaded, so an audit
//!    record can always be tied to the exact scope in force (`docs/config.md`,
//!    Rules).
//! 3. **The certificate pin**, the hash of the broker's leaf in DER form
//!    (`docs/sluse_prototype.md`, Preflight).
//!
//! SHA-256 rather than Chaperone's BLAKE3. Chaperone's hash is an internal change
//! detector and nothing outside the system reads it; Sluse's hash is shown to a
//! customer's security function and is the thing a lineage claim rests on, so it
//! is the algorithm their tooling and their policies already name.
//!
//! Invariant 7: the endpoint hashes received bytes regardless of capability type.
//! That is why [`ContentHasher`] exists beside [`ContentHash::of`] — a 500 MB
//! fetch is hashed as it streams, never buffered to be hashed whole.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

/// A SHA-256 digest in lowercase hex. On the wire it is a bare string.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(transparent)]
pub struct ContentHash(String);

impl ContentHash {
    /// Length of a SHA-256 digest in bytes.
    pub const DIGEST_LEN: usize = 32;
    /// Length of its hex encoding.
    pub const HEX_LEN: usize = Self::DIGEST_LEN * 2;

    /// Hash a complete slice. The only correct way to mint a hash from bytes
    /// you already hold; use [`ContentHasher`] for bytes you are streaming.
    pub fn of(bytes: &[u8]) -> Self {
        ContentHash(hex(&Sha256::digest(bytes)))
    }

    /// Wrap an already-computed digest without re-hashing.
    ///
    /// For values read back off the wire or out of a journal. Returns `None`
    /// unless `hex` is exactly [`Self::HEX_LEN`] **lowercase** hex characters,
    /// so a truncated or upper-cased value cannot masquerade as a real hash and
    /// then fail to match a hash that is byte-for-byte the same content.
    pub fn from_hex(hex: impl Into<String>) -> Option<Self> {
        let hex = hex.into();
        let valid = hex.len() == Self::HEX_LEN
            && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        valid.then_some(ContentHash(hex))
    }

    /// The hash as its hex string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first 12 characters, for a console column or a log line where the
    /// full 64 would push everything else off the screen. **Never** for
    /// comparison, and never written to an audit record: a short hash is a
    /// display convenience and the moment it is compared it is a weaker claim
    /// than the one the record makes.
    pub fn short(&self) -> &str {
        // `get`, not indexing: a value off the wire is not checked to be 64
        // characters, and a display helper must not panic (review R-34).
        self.0.get(..12).unwrap_or(&self.0)
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// Not derived: show that this is a hash, but keep the full hex so a log line can
// be grepped against a journal.
impl fmt::Debug for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentHash({})", self.0)
    }
}

/// Hashes bytes as they arrive. Feed it every chunk, then [`finish`].
///
/// [`finish`]: ContentHasher::finish
#[derive(Default, Clone)]
pub struct ContentHasher(Sha256);

impl ContentHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finish(self) -> ContentHash {
        ContentHash(hex(&self.0.finalize()))
    }
}

impl fmt::Debug for ContentHasher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ContentHasher(..)")
    }
}

fn hex(digest: &[u8]) -> String {
    use fmt::Write as _;
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector() {
        // The SHA-256 of the empty string, which is the one digest worth
        // hard-coding: it catches a wrong algorithm and a wrong encoding at once.
        assert_eq!(
            ContentHash::of(b"").as_str(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn streaming_equals_whole() {
        let bytes: Vec<u8> = (0..=255u8).cycle().take(100_000).collect();
        let mut h = ContentHasher::new();
        for chunk in bytes.chunks(7919) {
            h.update(chunk);
        }
        assert_eq!(h.finish(), ContentHash::of(&bytes));
    }

    #[test]
    fn from_hex_refuses_what_is_not_a_hash() {
        let good = ContentHash::of(b"x");
        assert_eq!(ContentHash::from_hex(good.as_str()), Some(good.clone()));
        // Truncated, which is what `short()` produces.
        assert_eq!(ContentHash::from_hex(good.short()), None);
        // Upper case: the same digest, a different string, and it would fail
        // every comparison in the system.
        assert_eq!(ContentHash::from_hex(good.as_str().to_uppercase()), None);
        assert_eq!(ContentHash::from_hex("zz".repeat(32)), None);
        assert_eq!(ContentHash::from_hex(""), None);
    }

    #[test]
    fn wire_form_is_a_bare_string() {
        let h = ContentHash::of(b"hello");
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.starts_with('"'), "{json}");
        assert_eq!(serde_json::from_str::<ContentHash>(&json).unwrap(), h);
    }
}

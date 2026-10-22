// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Typed identifier newtypes, and the one grammar they all share.
//!
//! Thin wrappers around `String`, but distinct *types*: the compiler will not
//! let an [`AdmissionId`] be passed where a [`PublishId`] is expected. That
//! mix-up is otherwise invisible until it joins two audit records that have
//! nothing to do with each other, and the join is the thing the audit design
//! rests on (`docs/sluse_prototype.md`, Wire contract: "`admission_id` joins the
//! two records").
//!
//! All are `#[serde(transparent)]`, so on the wire each is a bare string.
//!
//! ## Minting, and why it lives in a contract crate
//!
//! This crate is otherwise pure data. [`SessionId::mint`] and its siblings read
//! the clock and the OS random source, which is a departure, and a deliberate
//! one: the broker mints admission, publish and posture ids while the endpoint
//! mints session ids, and a grammar implemented twice is a grammar that drifts.
//! One implementation, one test.
//!
//! The shape is `<prefix>-<yyyymmdd>-<8 lowercase hex>`. The date is there for a
//! person reading a journal directory or a log line, not for correctness; the
//! 32 random bits are what make it unique. It is not a UUID because these are
//! read aloud and typed into a console filter.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Generate a transparent `String` newtype with the common accessors.
macro_rules! string_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, schemars::JsonSchema,
        )]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Wrap a raw string. Named `_unchecked` because this type performs
            /// no validation of its own — see the type's docs for what the
            /// caller must guarantee.
            pub fn new_unchecked(s: impl Into<String>) -> Self {
                $name(s.into())
            }

            /// Borrow the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume into the owned string.
            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }
    };
}

/// Add `mint()` to a newtype, with the shared grammar and a prefix.
macro_rules! minted {
    ($name:ident, $prefix:literal) => {
        impl $name {
            /// The prefix every value of this type carries.
            pub const PREFIX: &'static str = $prefix;

            /// Mint a fresh id: `<prefix>-<yyyymmdd>-<8 hex>`, UTC.
            pub fn mint() -> Self {
                $name(crate::ids::mint_with_prefix($prefix))
            }

            /// Whether a string has this type's shape. Used when a value
            /// arrives from outside — a header, a query parameter, a journal
            /// line — and nowhere else.
            pub fn is_well_formed(s: &str) -> bool {
                crate::ids::well_formed(s, $prefix)
            }
        }
    };
}

string_newtype! {
    /// Which box. From the config, carried on every audit record
    /// (`docs/audit.md`, Fields). Not minted: a human or the platform names it.
    BoxId
}

string_newtype! {
    /// One agent session, from the entry surface. Scopes the endpoint's journal
    /// file and, with the source, the volume window.
    SessionId
}
minted!(SessionId, "sess");

string_newtype! {
    /// One admission: one file, admitted once, by one `read` or `fetch`.
    ///
    /// **The join key.** The broker mints it when it admits bytes and returns it
    /// in the `x-sluse-admission-id` header; the endpoint records the same value
    /// beside its own hash of the bytes it received. Two records, two writers,
    /// one id, and the scorer asserts the join is 1:1 with equal hashes. That is
    /// how invariant 7 is checked rather than asserted.
    AdmissionId
}
minted!(AdmissionId, "adm");

string_newtype! {
    /// One `publish` call, which may carry several artifacts. Each artifact gets
    /// its own audit record; all of them carry this id.
    PublishId
}
minted!(PublishId, "pub");

string_newtype! {
    /// One preflight run: the gate and posture results as they were at broker
    /// start. Every broker record carries it, so "what was this machine like
    /// when that file was admitted" is answerable after the fact
    /// (`docs/sluse_prototype.md`, Preflight).
    PostureId
}
minted!(PostureId, "post");

string_newtype! {
    /// A source's name in the config, which is also the first segment of every
    /// request path. Validate with [`SourceName::parse`]; `new_unchecked` is for
    /// values the loader has already accepted.
    SourceName
}

impl SourceName {
    /// Maximum length. Long enough to be descriptive, short enough that a
    /// request path stays readable in an audit record.
    pub const MAX_LEN: usize = 64;

    /// Accept a name, or reject it.
    ///
    /// One to 64 characters, ASCII letters, digits, hyphen and underscore. No
    /// dot, no space, no separator, no case rule. The grammar is narrow on
    /// purpose: a source name is the first segment of every request path, so
    /// anything the path grammar would otherwise have to think about later — a
    /// dot that looks like a traversal, a backslash, a colon that looks like a
    /// drive letter — is excluded here, where the error message can still say
    /// plainly what is wrong with the config.
    ///
    /// The dot is additionally excluded because an MCP tool name cannot contain
    /// one (S-2 finding 1), and the two grammars should not diverge.
    pub fn parse(s: &str) -> Option<Self> {
        let ok = !s.is_empty()
            && s.len() <= Self::MAX_LEN
            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        ok.then(|| SourceName(s.to_owned()))
    }
}

fn mint_with_prefix(prefix: &str) -> String {
    let mut random = [0u8; 4];
    // Failing here means the OS random source is unavailable, which on Windows
    // means something is badly wrong with the process. Nothing useful can be
    // done with a predictable id, so this is one of the few honest panics.
    getrandom::fill(&mut random).expect("OS random source unavailable");
    let date = chrono::Utc::now().format("%Y%m%d");
    let mut hex = String::with_capacity(8);
    for b in random {
        use fmt::Write as _;
        let _ = write!(hex, "{b:02x}");
    }
    format!("{prefix}-{date}-{hex}")
}

fn well_formed(s: &str, prefix: &str) -> bool {
    let Some(rest) = s.strip_prefix(prefix).and_then(|r| r.strip_prefix('-')) else {
        return false;
    };
    let Some((date, hex)) = rest.split_once('-') else {
        return false;
    };
    date.len() == 8
        && date.bytes().all(|b| b.is_ascii_digit())
        && hex.len() == 8
        && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minted_ids_have_their_own_shape() {
        assert!(SessionId::is_well_formed(SessionId::mint().as_str()));
        assert!(AdmissionId::is_well_formed(AdmissionId::mint().as_str()));
        assert!(PublishId::is_well_formed(PublishId::mint().as_str()));
        assert!(PostureId::is_well_formed(PostureId::mint().as_str()));

        // And not each other's: a publish id is not a session id.
        assert!(!SessionId::is_well_formed(PublishId::mint().as_str()));
        // The near miss, explicitly: a prefix test that forgot the hyphen would
        // accept anything starting with the letters.
        assert!(!PostureId::is_well_formed("postXYZ-20260914-deadbeef"));
    }

    #[test]
    fn minted_ids_differ() {
        let a = AdmissionId::mint();
        let b = AdmissionId::mint();
        assert_ne!(a, b, "two admissions in the same millisecond must not collide");
    }

    #[test]
    fn well_formed_rejects_the_shapes_that_nearly_pass() {
        assert!(!SessionId::is_well_formed("sess-20260914"));
        assert!(!SessionId::is_well_formed("sess-2026914-deadbeef"));
        assert!(!SessionId::is_well_formed("sess-20260914-DEADBEEF"));
        assert!(!SessionId::is_well_formed("sess-20260914-deadbee"));
        assert!(!SessionId::is_well_formed(""));
    }

    #[test]
    fn source_name_grammar() {
        let sixty_four = "a".repeat(64);
        for ok in ["tender", "Tender_2026", "a", "x-y_z9", sixty_four.as_str()] {
            assert!(SourceName::parse(ok).is_some(), "{ok} should be accepted");
        }
        let sixty_five = "a".repeat(65);
        for bad in [
            "",
            sixty_five.as_str(),
            "has space",
            "has.dot", // S-2 finding 1: not legal in an MCP tool name
            "has/slash",
            r"has\backslash",
            "has:colon",
            "æøå",
            "..",
        ] {
            assert!(SourceName::parse(bad).is_none(), "{bad} should be refused");
        }
    }

    #[test]
    fn wire_form_is_a_bare_string() {
        let s = SessionId::mint();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, format!("\"{s}\""));
        assert_eq!(serde_json::from_str::<SessionId>(&json).unwrap(), s);
    }
}

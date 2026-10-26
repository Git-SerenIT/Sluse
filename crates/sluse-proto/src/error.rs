// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! [`SluseError`] — every way an operation can fail, as one closed enum.
//!
//! The crown jewel of the contract, and the rule that comes with it: **add the
//! failure mode to the enum first.** A new refusal that arrives as a string is a
//! refusal the endpoint cannot map, the console cannot render and the audit
//! record cannot categorise, and by the time anyone notices, three call sites
//! have invented three phrasings for it.
//!
//! ## On the wire
//!
//! Serialised with `#[serde(tag = "code")]` and SCREAMING_SNAKE_CASE names, so a
//! refusal body is a flat object whose `code` is machine-readable and whose
//! other fields are the specifics:
//!
//! ```json
//! { "code": "OUT_OF_SCOPE", "raw": "tender/hr/salaries.xlsx", "resolved": "…" }
//! { "code": "TOO_LARGE", "raw": "tender/big.bin", "size": 9000000, "limit": 262144 }
//! ```
//!
//! The endpoint deserialises straight back into this type, so an error survives
//! the round trip as a value rather than as prose to be re-parsed.
//!
//! ## What the agent is told is not this
//!
//! These are the *Gate's* reasons, and they are complete because the Gate's
//! audit record must be complete. What reaches the agent is narrower: D-008
//! makes scope blinders rather than a fence, so the endpoint maps
//! [`UnknownSource`], [`OutOfScope`] and [`NotFound`] to one indistinguishable
//! "no such path". Distinguishing them for the agent would turn a refusal into
//! an oracle for what exists. See `crates/sluse-endpoint` (M3).
//!
//! [`UnknownSource`]: SluseError::UnknownSource
//! [`OutOfScope`]: SluseError::OutOfScope
//! [`NotFound`]: SluseError::NotFound
//!
//! ## Formatting paths
//!
//! Every path in a message is formatted plainly, with literal quotes, never
//! `{x:?}`. Debug-formatting doubles every backslash, so a Windows path shows as
//! `Z:\\payroll` beside a root shown as `\\srv\share`, and these messages exist
//! precisely so a person can compare paths by eye (Chaperone I-021).

use crate::hash::ContentHash;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Every way a Sluse operation can fail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Error)]
#[serde(tag = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SluseError {
    // ---- The request was not well formed ---------------------------------
    /// The path could not be parsed as `<source>/<relative path>`, or it
    /// contained something the grammar refuses outright.
    ///
    /// The one error the endpoint may raise **without** asking the Gate: a
    /// path that cannot be parsed cannot be audited meaningfully by the Gate
    /// either, and forwarding it would only put unparseable strings in the host
    /// log. It is journaled in the guest.
    #[error("malformed path \"{raw}\": {reason}")]
    MalformedPath { raw: String, reason: String },

    /// The first segment names no source in the config.
    ///
    /// Carries what was asked for and nothing else. Listing the sources that do
    /// exist would answer, in a refusal, the question D-008 exists to leave
    /// unanswered.
    #[error("no such path: \"{raw}\"")]
    UnknownSource { raw: String },

    // ---- The request was well formed and refused -------------------------
    /// Inside a known source, outside every scope the config admits.
    ///
    /// `scopes` is the enforcing list as the Gate holds it, for the host's
    /// audit record. It does not travel to the agent.
    #[error("\"{raw}\" resolves to \"{resolved}\", which is outside the scope of source \"{source_name}\"")]
    OutOfScope {
        raw: String,
        resolved: String,
        source_name: String,
        scopes: Vec<String>,
    },

    /// Nothing at that path.
    #[error("no such path: \"{raw}\"")]
    NotFound { raw: String },

    /// A directory where a file was needed.
    #[error("\"{raw}\" is a directory, not a file")]
    NotAFile { raw: String },

    /// A file where a directory was needed.
    #[error("\"{raw}\" is a file, not a directory")]
    NotADirectory { raw: String },

    /// **The source refused.** In scope, and the user may not read it.
    ///
    /// Distinct from [`OutOfScope`](SluseError::OutOfScope) because they mean
    /// opposite things about the design: out of scope is Sluse doing its job,
    /// access denied is the source's own ACL having the final say against the
    /// user's identity (`docs/config.md`, What enforces what). Conflating them
    /// would let a permission problem read as a configuration problem for as
    /// long as it took someone to check the ACL.
    #[error("access denied to \"{raw}\": the source refused this user{}", detail_clause(detail))]
    AccessDenied { raw: String, detail: String },

    /// Over the cap for the verb that was used.
    ///
    /// `maxReadBytes` for a `read`, which returns bytes inline, and
    /// `maxFetchBytes` for a `fetch` — which is absent by default, so a `read`
    /// refused this way normally has a way forward and a `fetch` refused this
    /// way was refused by a number someone chose. The message names the limit
    /// rather than the remedy, because since D-019 only the config knows
    /// whether there is one.
    #[error("\"{raw}\" is {size} bytes, over the {limit}-byte limit for this verb")]
    TooLarge { raw: String, size: u64, limit: u64 },

    // ---- The source or the box could not answer --------------------------
    /// The source was unreachable, timed out, or returned something
    /// unintelligible. Transport, not policy.
    ///
    /// Kept apart from every refusal above because the inventory depends on the
    /// difference: a file the Gate cannot reach is `Unknown`, never
    /// `Orphaned`. Reporting a network blip as a deleted file would have the
    /// console tell a user their evidence is gone.
    #[error("source \"{source_name}\" is unavailable: {detail}")]
    SourceUnavailable { source_name: String, detail: String },

    /// A source kind the config accepts but this build does not serve.
    ///
    /// Since M7 every kind the loader takes is served, so this is now a Gate
    /// reached by a path that cannot serve the kind (a `sharepoint` source at
    /// a filesystem backend, or a Gate built without Entra): an error, so
    /// nothing silently behaves as if it worked.
    #[error("source \"{source_name}\" is of kind \"{kind}\", which this build does not serve")]
    UnsupportedSourceKind { source_name: String, kind: String },

    // ---- The caller is not who it needs to be ----------------------------
    /// The `x-sluse-session` header named a session the Gate did not issue.
    ///
    /// **The Gate mints session ids and the guest carries them**, rather than
    /// the other way round, so records and a journal name a run the Gate
    /// knows. The volume window no longer keys on it (D-060): `/v1/health`
    /// mints freely, so a session was a threshold the box could reset.
    ///
    /// jok's answer on 2026-09-16, and the reason `/v1/health` returns a session
    /// id at all.
    #[error("session \"{session_id}\" was not issued by this gate; call /v1/health for one")]
    UnknownSession { session_id: String },

    /// A listing audience this build does not serve.
    ///
    /// `Audience::User` shows out-of-scope entries greyed rather than absent,
    /// and it is a field the caller sets — so an agent that speaks HTTP to the
    /// Gate directly could ask for it and enumerate everything D-008 exists to
    /// keep out of its world. Both the MCP surface and the console present the
    /// same client certificate, so the Gate cannot tell them apart.
    ///
    /// **M5 serves both**, and the decision this variant was waiting for was
    /// taken then: the Gate still cannot tell the console from the agent, so
    /// `User` is not a privilege the Gate grants a caller — it is a listing
    /// the console asks for and the MCP surface never does. The endpoint's tool
    /// handlers send `Agent` and nothing in `sluse-endpoint::server` can be made
    /// to send anything else; an agent that speaks HTTP past the endpoint is
    /// already outside what the guest boundary claims to stop (invariant 2, and
    /// `docs/threat-model.md` on what the box does not prevent).
    ///
    /// Kept rather than deleted: a future audience that *is* refused will want
    /// this code, and the wire has a name for the refusal already.
    #[error("this build serves only the `agent` audience; `{audience}` is not available")]
    AudienceNotServed { audience: String },

    /// A `sharepoint` source was asked for and there is no signed-in user to
    /// act as, or the one there was can no longer be renewed without them.
    ///
    /// **The remedy is a person, not a retry**: sign in again at the console.
    /// Also what Entra's `interaction_required` becomes — MFA, a Conditional
    /// Access policy, consent — because the Gate cannot answer any of those
    /// on the user's behalf and must not try.
    #[error("no signed-in user to act as: {detail}. Sign in again at the console")]
    SignInRequired { detail: String },

    /// A user token was presented and is not one the Gate accepts: bad
    /// signature, wrong tenant, wrong audience, wrong client, or a different
    /// user from the one this session is bound to.
    ///
    /// Distinct from [`SignInRequired`](SluseError::SignInRequired) because the
    /// two mean different things in the record. An expired sign-in is ordinary;
    /// a token for another audience or another user, presented by something in
    /// the guest, is worth a person's attention.
    #[error("the user token was refused: {detail}")]
    TokenRejected { detail: String },

    /// A box asked to enrol and was refused: a token that is not this open's,
    /// one already used, or a key that is not a P-256 point (slice 2,
    /// D-024 point 7). Worth a person's attention when it repeats: something
    /// on the segment is guessing.
    #[error("enrolment refused: {detail}")]
    EnrolmentRefused { detail: String },

    // ---- Publish ---------------------------------------------------------
    /// An artifact of that name is already published.
    ///
    /// Refused, never overwritten. Artifacts are the single write path and the
    /// thing provenance is claimed about; a silent overwrite would break the
    /// tie between a name, its lineage and its bytes.
    #[error("artifact \"{name}\" already exists; publish under a different name")]
    ArtifactExists { name: String },

    /// A name Windows or the layout reserves.
    #[error("artifact name \"{name}\" is reserved and cannot be used")]
    ReservedName { name: String },

    /// A name that is not a single legal file name.
    #[error("malformed artifact name \"{name}\": {reason}")]
    MalformedArtifactName { name: String, reason: String },

    /// The bytes received do not hash to what the manifest declared.
    ///
    /// The publish is refused whole (all or nothing), because a manifest that
    /// does not describe its bytes is the one thing a provenance record must
    /// never carry.
    #[error("artifact \"{name}\": manifest declares {declared}, received bytes hash to {actual}")]
    HashMismatch {
        name: String,
        declared: ContentHash,
        actual: ContentHash,
    },

    /// A declared source that is not an admission of the session (D-055).
    ///
    /// Refused whole, as a hash mismatch is: a source on record that never
    /// entered the box would be the one false thing a provenance record says.
    #[error("artifact \"{name}\": the declared source \"{source_path}\" was not admitted in this session")]
    SourceNotAdmitted { name: String, source_path: String },

    // ---- Client-side: raised in the guest, never received from the Gate --
    /// The Gate could not be reached at all.
    ///
    /// Fail closed: the tool call fails and is journaled as an error. Whether
    /// a cached check window should soften this is Q-2, still open; the
    /// prototype does not cache (`docs/sluse_prototype.md`, Provisional).
    #[error("the Gate is unreachable: {detail}")]
    GateUnreachable { detail: String },

    /// The Gate's certificate is not the pinned one.
    ///
    /// The handshake is abandoned. The endpoint trusts one leaf and no CA
    /// bundle, so this is either a misconfiguration or something standing where
    /// the Gate should be; neither is a condition to retry through.
    #[error("the Gate presented certificate {presented}, not the pinned {expected}")]
    CertificatePinMismatch {
        expected: ContentHash,
        presented: ContentHash,
    },

    // ---- Everything else -------------------------------------------------
    /// A bug, or a condition with no better name yet. If one of these turns out
    /// to be a real, repeatable failure mode, it gets its own variant.
    #[error("internal error: {message}")]
    Internal { message: String },
}

/// Convenience alias for fallible operations.
pub type Result<T> = std::result::Result<T, SluseError>;

impl SluseError {
    /// The `code` this variant carries on the wire.
    ///
    /// The same string serde writes for the `tag`, and a test asserts they
    /// cannot drift. Use it for the audit record's `reason` and for anything
    /// that switches on a failure; never match on the message text, which is
    /// written for people and is rewritten when it reads badly.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::MalformedPath { .. } => "MALFORMED_PATH",
            Self::UnknownSource { .. } => "UNKNOWN_SOURCE",
            Self::OutOfScope { .. } => "OUT_OF_SCOPE",
            Self::NotFound { .. } => "NOT_FOUND",
            Self::NotAFile { .. } => "NOT_A_FILE",
            Self::NotADirectory { .. } => "NOT_A_DIRECTORY",
            Self::AccessDenied { .. } => "ACCESS_DENIED",
            Self::TooLarge { .. } => "TOO_LARGE",
            Self::SourceUnavailable { .. } => "SOURCE_UNAVAILABLE",
            Self::UnsupportedSourceKind { .. } => "UNSUPPORTED_SOURCE_KIND",
            Self::UnknownSession { .. } => "UNKNOWN_SESSION",
            Self::AudienceNotServed { .. } => "AUDIENCE_NOT_SERVED",
            Self::SignInRequired { .. } => "SIGN_IN_REQUIRED",
            Self::TokenRejected { .. } => "TOKEN_REJECTED",
            Self::EnrolmentRefused { .. } => "ENROLMENT_REFUSED",
            Self::ArtifactExists { .. } => "ARTIFACT_EXISTS",
            Self::ReservedName { .. } => "RESERVED_NAME",
            Self::MalformedArtifactName { .. } => "MALFORMED_ARTIFACT_NAME",
            Self::HashMismatch { .. } => "HASH_MISMATCH",
            Self::SourceNotAdmitted { .. } => "SOURCE_NOT_ADMITTED",
            Self::GateUnreachable { .. } => "GATE_UNREACHABLE",
            Self::CertificatePinMismatch { .. } => "CERTIFICATE_PIN_MISMATCH",
            Self::Internal { .. } => "INTERNAL",
        }
    }

    /// The HTTP status the Gate answers with.
    ///
    /// The mapping is deliberately coarse and says what kind of thing happened,
    /// not which variant: 400 the request was malformed, 403 policy refused it,
    /// 404 it is not there, 409 the target is not in the required state, 413 too
    /// big, 422 the body contradicts itself, 501 not served by this build, 502
    /// the source failed, 500 a bug.
    ///
    /// A client must still read the `code`. The status exists so that a proxy,
    /// a log or a person skimming can tell a refusal from a fault without
    /// parsing the body.
    pub fn http_status(&self) -> u16 {
        match self {
            Self::MalformedPath { .. }
            | Self::ReservedName { .. }
            | Self::MalformedArtifactName { .. } => 400,

            Self::OutOfScope { .. }
            | Self::AccessDenied { .. }
            | Self::EnrolmentRefused { .. }
            | Self::AudienceNotServed { .. } => 403,

            Self::UnknownSource { .. } | Self::NotFound { .. } => 404,

            Self::NotAFile { .. } | Self::NotADirectory { .. } | Self::ArtifactExists { .. } => 409,

            Self::TooLarge { .. } => 413,
            Self::HashMismatch { .. } | Self::SourceNotAdmitted { .. } => 422,
            Self::UnsupportedSourceKind { .. } => 501,

            // 401, not 403: the caller has not identified a session the Gate
            // knows, and the remedy is to get one rather than to ask for less.
            Self::UnknownSession { .. }
            | Self::SignInRequired { .. }
            | Self::TokenRejected { .. } => 401,
            Self::SourceUnavailable { .. } => 502,

            // Raised inside the guest and never sent by the Gate. A status is
            // given anyway so the mapping is total and so these can share one
            // rendering path in the console.
            Self::GateUnreachable { .. } | Self::CertificatePinMismatch { .. } => 503,

            Self::Internal { .. } => 500,
        }
    }

    /// Whether this is a refusal (a decision the system made about this
    /// request) rather than an error (something that went wrong).
    ///
    /// The audit record's `outcome` turns on this, and the two must not be
    /// conflated: refusals are the control working and are expected in normal
    /// use; errors are faults and someone should look at a rate of them.
    ///
    /// [`UnsupportedSourceKind`](Self::UnsupportedSourceKind) sits on the error
    /// side, which is worth saying because it looks like a refusal. Nothing
    /// about the request was wrong and no policy decided against it: the
    /// deployment names a source this build cannot serve, which is a fault in
    /// the config or in the build, and a rate of it means somebody should look.
    ///
    /// [`AudienceNotServed`](Self::AudienceNotServed) does not (D-045 point 2):
    /// the console stops asking outside LOCAL, so what is still refused is the
    /// agent asking for what D-033 keeps from the box. Nor does
    /// [`UnknownSession`](Self::UnknownSession): a session
    /// the Gate never issued is a caller asking for something it has not been
    /// given, which is a decision the Gate made about the request.
    pub fn is_refusal(&self) -> bool {
        !matches!(
            self,
            Self::UnsupportedSourceKind { .. }
                | Self::SourceUnavailable { .. }
                | Self::GateUnreachable { .. }
                | Self::CertificatePinMismatch { .. }
                | Self::Internal { .. }
        )
    }
}

/// The optional detail clause on [`SluseError::AccessDenied`].
///
/// A free function because `thiserror`'s format attribute cannot branch, and the
/// branch is real: a source that explains itself should be quoted, and one that
/// says nothing should not produce a message ending in a dangling colon.
fn detail_clause(detail: &str) -> String {
    if detail.trim().is_empty() {
        String::new()
    } else {
        format!(": {detail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// One of every variant. The exhaustive `match` in `reason_code` means a
    /// new variant will not compile until it is added there; this list is what
    /// makes it show up in the round-trip and status tests too.
    fn one_of_each() -> Vec<SluseError> {
        let h = ContentHash::of(b"a");
        let h2 = ContentHash::of(b"b");
        vec![
            SluseError::MalformedPath { raw: "..".into(), reason: "traversal".into() },
            SluseError::UnknownSource { raw: "nope/x".into() },
            SluseError::OutOfScope {
                raw: "tender/hr/pay.xlsx".into(),
                resolved: r"C:\src\hr\pay.xlsx".into(),
                source_name: "tender".into(),
                scopes: vec![r"C:\src\bids".into()],
            },
            SluseError::NotFound { raw: "tender/gone.md".into() },
            SluseError::NotAFile { raw: "tender/dir".into() },
            SluseError::NotADirectory { raw: "tender/a.md".into() },
            SluseError::AccessDenied { raw: "tender/r/x".into(), detail: "ACCESS_DENIED".into() },
            SluseError::TooLarge { raw: "tender/big.bin".into(), size: 9_000_000, limit: 262_144 },
            SluseError::SourceUnavailable { source_name: "share".into(), detail: "timed out".into() },
            SluseError::UnsupportedSourceKind {
                source_name: "spo".into(),
                kind: "sharepoint".into(),
            },
            SluseError::UnknownSession { session_id: "sess-20260916-deadbeef".into() },
            SluseError::AudienceNotServed { audience: "user".into() },
            SluseError::SignInRequired { detail: "no token presented".into() },
            SluseError::TokenRejected { detail: "wrong audience".into() },
            SluseError::EnrolmentRefused { detail: "a token already used".into() },
            SluseError::ArtifactExists { name: "summary.md".into() },
            SluseError::ReservedName { name: "CON".into() },
            SluseError::MalformedArtifactName {
                name: "a/b".into(),
                reason: "not a single file name".into(),
            },
            SluseError::HashMismatch {
                name: "summary.md".into(),
                declared: h.clone(),
                actual: h2.clone(),
            },
            SluseError::SourceNotAdmitted { name: "summary.md".into(), source_path: "tender/x.md".into() },
            SluseError::GateUnreachable { detail: "connection refused".into() },
            SluseError::CertificatePinMismatch { expected: h, presented: h2 },
            SluseError::Internal { message: "bug".into() },
        ]
    }

    #[test]
    fn every_variant_round_trips_through_json() {
        for e in one_of_each() {
            let json = serde_json::to_string(&e).expect("serialise");
            let back: SluseError = serde_json::from_str(&json).expect(&json);
            assert_eq!(e, back, "round trip changed the value: {json}");
        }
    }

    #[test]
    fn the_tag_serde_writes_is_the_reason_code() {
        for e in one_of_each() {
            let v: Value = serde_json::to_value(&e).unwrap();
            let tag = v.get("code").and_then(Value::as_str).expect("a code field");
            assert_eq!(
                tag,
                e.reason_code(),
                "serde tag and reason_code() disagree for {e:?}"
            );
        }
    }

    #[test]
    fn reason_codes_are_unique() {
        let all = one_of_each();
        let mut codes: Vec<&str> = all.iter().map(|e| e.reason_code()).collect();
        let before = codes.len();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(before, codes.len(), "two variants share a code");
    }

    #[test]
    fn statuses_are_in_range_and_refusals_are_not_five_hundreds() {
        for e in one_of_each() {
            let s = e.http_status();
            assert!((400..=599).contains(&s), "{e:?} maps to {s}");
            if e.is_refusal() {
                assert!(s < 500, "{e:?} is a refusal but maps to {s}");
            }
        }
    }

    #[test]
    fn paths_are_printed_plainly_not_debug_escaped() {
        let e = SluseError::OutOfScope {
            raw: r"Z:\payroll\q3.xlsx".into(),
            resolved: r"\\FS01\share\payroll\q3.xlsx".into(),
            source_name: "share".into(),
            scopes: vec![],
        };
        let msg = e.to_string();
        assert!(msg.contains(r"Z:\payroll\q3.xlsx"), "{msg}");
        assert!(!msg.contains(r"\\\\FS01"), "backslashes were doubled: {msg}");
    }

    #[test]
    fn access_denied_without_detail_has_no_dangling_colon() {
        let e = SluseError::AccessDenied { raw: "s/x".into(), detail: "  ".into() };
        assert!(e.to_string().ends_with("refused this user"), "{e}");
    }
}

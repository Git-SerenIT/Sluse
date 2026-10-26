// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! What the agent is told, which is narrower than what happened.
//!
//! **D-008.** Out-of-scope material is *absent* from the agent's world, not
//! forbidden in it. A refusal is an answer: an agent that can tell "that is out
//! of scope" from "that does not exist" can enumerate what exists by asking, and
//! a refusal that distinguishes them is an oracle with a polite tone.
//!
//! So three of the Gate's refusals collapse into one indistinguishable "no
//! such path":
//!
//! | The Gate decided | The agent is told |
//! |---|---|
//! | `UnknownSource` — no source of that name | no such path |
//! | `OutOfScope` — a real path, outside every scope | no such path |
//! | `NotFound` — inside scope, nothing there | no such path |
//!
//! The Gate's own record keeps all three, with the resolved host path and the
//! enforcing scope list. **Nothing is hidden from the user; the agent is the one
//! wearing the blinders.**
//!
//! ## `AccessDenied` is not blinded, and that is a decision
//!
//! `AccessDenied` means the path is inside a scope the config advertises and the
//! *source's own ACL* refused the signed-in user. The agent is told plainly.
//!
//! The argument for blinding it is that it confirms a file exists. The argument
//! against, which won: the config view already told the agent that directory is
//! in its world, so the existence of files there is not news — and an agent that
//! cannot tell "you may never have this" from "that is not there" retries, which
//! wastes the run and fills the audit trail with refusals that mean nothing. It
//! is also the one refusal a *person* most needs to see, since it is their own
//! permissions answering, and M5's inventory maps it to `Orphaned` on that
//! basis. jok's answer on 2026-09-16.
//!
//! ## Everything else passes through
//!
//! `TooLarge`, `NotAFile`, `SourceUnavailable`,
//! `UnsupportedSourceKind` and the rest say what they are, because each names a
//! condition the agent can do something about and none of them says whether a
//! file the agent has not already named exists.

use sluse_proto::SluseError;

/// What the agent gets: a message, and whether it was a refusal or a fault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Told {
    pub message: String,
    /// `true` when the system decided against this request; `false` when
    /// something went wrong. The journal's outcome follows it.
    pub refused: bool,
}

/// The one message the three blinded refusals share.
///
/// Identical text, identical shape, no hint of which one it was. If these ever
/// diverge — even in punctuation — the blinder is gone and an agent can tell
/// them apart by string comparison.
const NO_SUCH_PATH: &str = "No such path";

/// Translate a Gate refusal into what the agent is told.
pub fn tell(err: &SluseError, raw: &str) -> Told {
    let refused = err.is_refusal();
    let message = match err {
        // --- the blinded three ---------------------------------------------
        SluseError::UnknownSource { .. }
        | SluseError::OutOfScope { .. }
        | SluseError::NotFound { .. } => {
            format!("{NO_SUCH_PATH}: {raw}. Call sluse_sources to see what you can reach.")
        }

        // --- told plainly, on purpose ---------------------------------------
        // "this path", not "this file". The refusal is deliberately identical
        // whatever the verb, so that it says nothing about the target — and
        // "file" was the one word that did, wrongly. The prober run addressed a
        // directory, got told about a file, and reported that it could conclude
        // nothing from the message: "either the Gate's message is generic
        // boilerplate, or sealed is not a directory at all" (jok, 2026-09-22,
        // `prototype/results/2026-09-22-prober/`).
        SluseError::AccessDenied { .. } => format!(
            "The source refused {raw} for your user. It is inside a path you may work with, \
             and your account does not have permission to open this path. Do not retry it; \
             report it to the user if it matters to the task."
        ),

        SluseError::MalformedPath { reason, .. } => {
            format!("{raw} is not a usable path: {reason}.")
        }
        SluseError::NotAFile { .. } => format!("{raw} is a directory. Use sluse_list."),
        SluseError::NotADirectory { .. } => format!("{raw} is a file. Use sluse_read."),
        // **It does not promise that fetch is uncapped.** It used to, and D-016
        // made that a lie in any deployment that sets `maxFetchBytes`: the same
        // error now comes back for either verb, and the message cannot tell
        // which cap it hit without being told. "the cap" is true of both.
        SluseError::TooLarge { size, limit, .. } => format!(
            "{raw} is {size} bytes and the cap is {limit}. It is refused rather than \
             truncated. If this was a read, sluse_fetch may still be allowed to take it; \
             if it was a fetch, nothing will."
        ),
        SluseError::SourceUnavailable { source_name, .. } => format!(
            "The source \"{source_name}\" could not be reached, so {raw} was not delivered. \
             This is a fault, not a refusal; the file may well be there."
        ),
        SluseError::UnsupportedSourceKind { source_name, kind } => format!(
            "The source \"{source_name}\" is of kind \"{kind}\", which this build does not \
             serve. Nothing about your request was wrong."
        ),

        // --- identity (M7) ----------------------------------------------------
        // Both say what to do, and neither says anything about the file: the
        // refusal happened before the source was asked.
        SluseError::SignInRequired { .. } => format!(
            "{raw} is in a source that is read as the signed-in user, and there is no \
             signed-in user right now. Ask the user to sign in at the Sluse console, \
             then try again. Nothing was admitted."
        ),
        // Detail withheld: why a token was refused is for the host's record,
        // and a message that explained it would be a way to refine a forgery.
        SluseError::TokenRejected { .. } => format!(
            "The sign-in presented for {raw} was refused, and nothing was admitted. \
             Ask the user to sign in again at the Sluse console."
        ),
        // Only the box's own enrolment service meets this, never a tool call;
        // mapped so the match stays total.
        SluseError::EnrolmentRefused { .. } => format!(
            "This box could not get its identity from the Gate, so {raw} was not admitted. \
             Ask the user to close the box and open it again."
        ),

        // --- publish ---------------------------------------------------------
        SluseError::ArtifactExists { name } => format!(
            "An artifact named {name} was already published. Artifacts are never overwritten; \
             publish under a different name."
        ),
        SluseError::ReservedName { name } => {
            format!("{name} is a reserved name and cannot be used for an artifact.")
        }
        SluseError::MalformedArtifactName { name, reason } => {
            format!("{name} is not a usable artifact name: {reason}.")
        }
        SluseError::HashMismatch { name, .. } => format!(
            "The bytes received for {name} do not match what was declared, so the whole \
             delivery was refused. Nothing was published."
        ),
        SluseError::SourceNotAdmitted { name, source_path } => format!(
            "{source_path}, declared as a source of {name}, was not admitted in this session, so \
             nothing was published. Name a source as you read or fetched it (`<source>/<path>`), \
             or by its unchanged fetched copy in your workspace; a file you made is not a source."
        ),

        // --- the transport ----------------------------------------------------
        SluseError::GateUnreachable { detail } => format!(
            "The Gate could not be reached, so nothing was admitted: {detail}. \
             This fails closed by design; there is no local copy to fall back to."
        ),
        SluseError::CertificatePinMismatch { .. } => {
            "The Gate did not present the expected certificate; nothing was admitted.".to_owned()
        }

        // The agent gets no detail here on purpose: an internal message can
        // carry a host path or a library's idea of context, and neither belongs
        // on this side of the boundary. The journal has it.
        SluseError::Internal { .. } => {
            format!("Something went wrong handling {raw}. It has been recorded.")
        }

        // Neither of these should reach an agent: the endpoint holds the
        // session and always asks for the `agent` audience. Handled rather than
        // unwrapped, because "should not happen" is how a panic gets written.
        SluseError::UnknownSession { .. } => {
            "The session ended. Ask the user to restart the Sluse endpoint.".to_owned()
        }
        SluseError::AudienceNotServed { .. } => {
            format!("Something went wrong handling {raw}. It has been recorded.")
        }
    };

    Told { message, refused }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out_of_scope(raw: &str) -> SluseError {
        SluseError::OutOfScope {
            raw: raw.to_owned(),
            resolved: "C:\\Sluse-test\\fixture\\elsewhere\\secret.txt".into(),
            source_name: "fixture".into(),
            scopes: vec!["fixture/in-scope".into()],
        }
    }

    #[test]
    fn the_three_blinded_refusals_are_indistinguishable() {
        let raw = "fixture/elsewhere/secret.txt";
        let told: Vec<String> = [
            SluseError::UnknownSource { raw: raw.into() },
            out_of_scope(raw),
            SluseError::NotFound { raw: raw.into() },
        ]
        .iter()
        .map(|e| tell(e, raw).message)
        .collect();

        // Byte-identical. A difference in punctuation would be enough to tell
        // them apart, and telling them apart is the whole thing D-008 forbids.
        assert_eq!(told[0], told[1]);
        assert_eq!(told[1], told[2]);
        assert!(told[0].starts_with("No such path"));
    }

    #[test]
    fn nothing_the_gate_knew_survives_into_the_blinded_message() {
        let raw = "fixture/elsewhere/secret.txt";
        let message = tell(&out_of_scope(raw), raw).message;

        // The Gate's record keeps the host path and the enforcing scope list.
        // Neither may cross the boundary in a refusal the agent can read.
        assert!(!message.contains("C:\\"), "{message}");
        assert!(!message.contains("in-scope"), "{message}");
        assert!(!message.to_lowercase().contains("scope"), "{message}");
    }

    #[test]
    fn access_denied_is_told_plainly_and_says_not_to_retry() {
        let raw = "fixture/in-scope/restricted/salaries.xlsx";
        let told = tell(
            &SluseError::AccessDenied { raw: raw.into(), detail: "ACCESS_DENIED".into() },
            raw,
        );
        assert!(told.refused);
        // Distinct from the blinded message: the agent must be able to tell
        // "never" from "not there", or it retries.
        assert!(!told.message.starts_with("No such path"));
        assert!(told.message.contains("Do not retry"));
        assert!(told.message.contains(raw));

        // **It says "path", not "file".** The message is identical whatever the
        // verb, so it must not assert what the target is — and the prober run
        // met it on a *directory*, was told about a file, and reported that it
        // could conclude nothing from the message (jok, 2026-09-22).
        assert!(
            !told.message.contains("this file"),
            "the refusal must not claim a type it does not know: {}",
            told.message
        );
    }

    #[test]
    fn a_fault_is_not_a_refusal_and_says_so() {
        let told = tell(
            &SluseError::SourceUnavailable {
                source_name: "share".into(),
                detail: "the network is down".into(),
            },
            "share/docs/a.md",
        );
        assert!(!told.refused, "a source that is down is a fault, not a decision");
        assert!(told.message.contains("fault, not a refusal"));
        // And it does not leak the transport detail, which can name a host.
        assert!(!told.message.contains("the network is down"));
    }

    #[test]
    fn an_internal_error_tells_the_agent_nothing_it_could_act_on() {
        let told = tell(
            &SluseError::Internal { message: "C:\\Sluse-test\\secret panicked".into() },
            "fixture/a.md",
        );
        assert!(!told.refused);
        assert!(!told.message.contains("C:\\"));
        assert!(told.message.contains("recorded"));
    }

    #[test]
    fn every_variant_produces_a_message_and_none_is_empty() {
        // The compiler already forces the match to be total; this asserts the
        // arms actually say something, which it cannot.
        let cases = [
            SluseError::MalformedPath { raw: "..".into(), reason: "a `..` segment".into() },
            SluseError::NotAFile { raw: "f/d".into() },
            SluseError::NotADirectory { raw: "f/a.md".into() },
            SluseError::TooLarge { raw: "f/big".into(), size: 900, limit: 100 },
            SluseError::UnsupportedSourceKind {
                source_name: "tender".into(),
                kind: "sharepoint".into(),
            },
            SluseError::ArtifactExists { name: "s.md".into() },
            SluseError::ReservedName { name: "CON".into() },
            SluseError::MalformedArtifactName { name: "..".into(), reason: "a segment".into() },
            SluseError::HashMismatch {
                name: "s.md".into(),
                declared: sluse_proto::ContentHash::of(b"a"),
                actual: sluse_proto::ContentHash::of(b"b"),
            },
            SluseError::SourceNotAdmitted { name: "s.md".into(), source_path: "f/x.md".into() },
            SluseError::GateUnreachable { detail: "connection refused".into() },
            SluseError::CertificatePinMismatch {
                expected: sluse_proto::ContentHash::of(b"a"),
                presented: sluse_proto::ContentHash::of(b"b"),
            },
            SluseError::UnknownSession { session_id: "sess-x".into() },
            SluseError::AudienceNotServed { audience: "user".into() },
        ];
        for err in &cases {
            let told = tell(err, "fixture/a.md");
            assert!(!told.message.trim().is_empty(), "{}", err.reason_code());
            assert_eq!(told.refused, err.is_refusal(), "{}", err.reason_code());
        }
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The audit record: one shape, written by two writers.
//!
//! The Gate writes to the host's sink (`docs/audit.md`: the Windows Event Log
//! in v1, JSONL in the prototype). The endpoint writes to a per-session journal
//! in the guest. **They use the same type**, and that is the design, not a
//! convenience: invariant 7 says audit is uniform even when transport is not,
//! and two record shapes would let the two sides drift until a comparison
//! between them stopped meaning anything.
//!
//! The comparison is the point. Each admission carries an [`AdmissionId`] minted
//! by the Gate and echoed by the endpoint, so the two records join 1:1 and the
//! hashes on either side of the boundary can be checked against each other
//! rather than assumed equal.
//!
//! ## Weight
//!
//! The two writers are not equally trustworthy and the design says so. The
//! Gate runs outside the guest, so its record is evidence. The endpoint's
//! journal runs inside the untrusted zone: it is **functional, not a trust
//! anchor** (`docs/audit.md`). It exists so lineage can be computed and so the
//! console has something to show — not so a claim can rest on it. The [`writer`]
//! field is on every record because a reader must never have to guess which
//! kind they are holding.
//!
//! [`writer`]: AuditRecord::writer
//!
//! ## Never
//!
//! File content. Prompt text. Model output. Tokens. There is no field for any of
//! them and none should be added; an audit trail that quotes the data it governs
//! is a second copy of that data with weaker handling.

use crate::hash::ContentHash;
use crate::ids::{AdmissionId, BoxId, PostureId, PublishId, SessionId};
use crate::error::SluseError;
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Which side wrote this record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Writer {
    /// On the host, outside the guest. Evidence.
    Core,
    /// In the guest. Functional, not a trust anchor.
    Endpoint,
}

/// Who the operation was performed as.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UserRef {
    pub kind: UserKind,
    /// `DOMAIN\user` for an OS process, a UPN for Entra.
    pub name: String,
}

impl UserRef {
    /// The LOCAL identity: the OS account the Gate process runs as.
    pub fn os_process(name: impl Into<String>) -> Self {
        Self { kind: UserKind::OsProcess, name: name.into() }
    }

    /// The identity from a validated token.
    pub fn entra(upn: impl Into<String>) -> Self {
        Self { kind: UserKind::Entra, name: upn.into() }
    }

    /// A label a person can read without having to know the field names, and
    /// which cannot be mistaken for the other kind.
    pub fn display(&self) -> String {
        match self.kind {
            UserKind::OsProcess => format!("os-process:{}", self.name),
            UserKind::Entra => format!("entra:{}", self.name),
        }
    }

    /// The inverse of [`display`](Self::display), for the `x-sluse-user` header.
    pub fn parse_display(s: &str) -> Option<Self> {
        if let Some(name) = s.strip_prefix("entra:") {
            Some(Self::entra(name))
        } else {
            s.strip_prefix("os-process:").map(Self::os_process)
        }
    }
}

/// What kind of identity the `user` field holds.
///
/// The distinction is load-bearing and is why this is not a bare string.
/// `docs/audit.md` claims an **authenticated user**, meaning the subject of a
/// token the Gate validated — a claim that only holds once the entry surface
/// performs Entra sign-in and S-3 has passed. In LOCAL there is no token and no
/// sign-in, so the field carries the OS account and says so. Recording that as
/// if it were the same thing would make the audit design's central claim a
/// fiction (spec §14) in exactly the environment where nobody would notice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum UserKind {
    /// The OS account of the process. **Not an authenticated user.** LOCAL only.
    OsProcess,
    /// The subject of a validated Entra token.
    Entra,
}

/// What was attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    /// Admission of bytes, returned inline and enveloped.
    Read,
    /// Admission of bytes, streamed to the workspace.
    Fetch,
    /// A local file in the workspace, read back through the endpoint. **D-019.**
    ///
    /// **Not an admission**: nothing crossed the boundary, the Gate was never
    /// asked, and there is no record of it on the host — so it carries no
    /// `admission_id` and the scorer's 1:1 join is untouched. What it carries is
    /// [`lineage`](AuditRecord::lineage): the admission the copy came from, when
    /// the sidecar beside it says so.
    ///
    /// It exists because a local re-read used to be invisible. An agent that
    /// fetched a file and read it again with its own tools left nothing behind
    /// anywhere; routing that read through `sluse_read` makes it an event with a
    /// record. A read the agent does with `cat` still leaves nothing, and that
    /// is the known channel D-019 point 4 documents beside the clipboard.
    Reread,
    /// One artifact written to the artifacts zone.
    Publish,
    /// A stat: size, modified time, hash. What the inventory is built from.
    Metadata,
    /// A directory listing.
    List,
    /// The config view: which sources exist and what is in scope.
    Sources,
    /// A volume alert opening. Not an operation a caller asked for; the Gate
    /// raises it.
    Alert,
    /// The user cleared the workspace inventory. User-initiated only, never
    /// automatic.
    Clear,
    /// The box was bound to a signed-in user (D-022): at the sign-in page,
    /// or by the first token on a read. As important as the sign-out, and
    /// written for the same reason: the trail shows where authority began.
    Signin,
    /// The user signed the box out: the Gate dropped its binding and the
    /// tokens it held (D-022). User-initiated only, never on a timer.
    Signout,
    /// A scope root checked at sign-in, as the user, was not there
    /// (D-038 point 6). Raised, not refused: nothing was asked for. Missing
    /// may also mean this user cannot open it.
    Scope,
    /// The host's audit tail, asked for (D-033 point 3). Served in LOCAL
    /// only; elsewhere its refusal is the record (D-045 point 2).
    Tail,
    /// The box's journal mirrored to the host (D-027 point 5). Recorded only
    /// when refused: a session the Gate did not issue, or a mirror over its
    /// cap (review R-01).
    Journal,
    /// A tool call to an `mcp` source (D-071): admitted like a fetch, with
    /// the hash of the result the box received.
    Call,
    /// The tools of the `mcp` sources, listed (D-071). Recorded when refused,
    /// or when a server could not be asked.
    Tools,
}

/// How the bytes were delivered, or would have been.
///
/// The asymmetry this field records is in `docs/audit.md`: in bytes mode the
/// Gate authorises **and delivers**, so its record covers both. In URL mode it
/// hands over a per-item capability and records **a decision, not a delivery** —
/// what arrived is known only to the endpoint's journal, inside the untrusted
/// zone. A reader who cannot see which mode was in play cannot know which of
/// those two things the record in front of them means.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    /// The Gate was on the data path.
    Bytes,
    /// The Gate issued a pre-authenticated URL. M7.
    Url,
}

/// How it ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// It happened.
    Admitted,
    /// The system decided against it. **Normal operation**, not a fault: a
    /// refusal is the control doing its job.
    Refused,
    /// Something went wrong. A rate of these is worth someone's attention in a
    /// way that a rate of refusals is not.
    Error,
    /// An alert was raised. Only ever on [`Op::Alert`].
    Raised,
}

/// What became of an admission in the box, as the journal recorded it
/// (D-055 point 2, D-056 point 1). One per hash: encrypted over fetched over
/// unread over read, since the same bytes read and fetched are one entry and
/// an encrypted one was readable by neither verb.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AdmissionState {
    /// Returned through `sluse_read`, enveloped, and not fetched.
    Read,
    /// Admitted through `sluse_read` and not shown: not text, or its text
    /// could not be extracted (`NOT_UTF8_TEXT`, `NOT_EXTRACTED`).
    Unread,
    /// Written to the workspace by `sluse_fetch`.
    Fetched,
    /// Arrived encrypted (`OFFICE_ENCRYPTED`): nothing in the box can read it.
    Encrypted,
}

/// One admission named on a publish: in its declared `sources`, one the agent
/// says the artifact used, and in its `lineage`, one of everything admitted in
/// the session (D-055). On a [`Op::Reread`], the admission the copy came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LineageItem {
    /// The path as it was requested, including the source name.
    pub path: String,
    /// The hash of the bytes admitted. The identity that matters: the same
    /// bytes read twice under two names are one lineage entry.
    pub hash: ContentHash,
    /// The admission this came from, so a lineage entry can be traced back to
    /// the Gate record that authorised it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_id: Option<AdmissionId>,
    /// What became of it in the box; on a publish's `lineage` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<AdmissionState>,
}

/// One audit record.
///
/// Fields follow `docs/audit.md`. Everything optional is optional because it is
/// genuinely absent for some operations, not because it is sometimes
/// inconvenient to fill in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditRecord {
    pub writer: Writer,
    pub box_id: BoxId,
    /// Who this was done as. See [`UserKind`] for why this is not a string.
    pub user: UserRef,
    /// The hash of the config in force, so the record can be tied to the exact
    /// scope that admitted it.
    pub config_version: ContentHash,
    pub session_id: SessionId,
    /// UTC, with offset.
    pub ts: DateTime<Utc>,
    pub op: Op,
    /// The path as the caller wrote it.
    pub path_requested: String,
    /// What it resolved to, when that differs. Present on the Gate's records
    /// for anything it resolved; absent on the endpoint's, which never resolves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_resolved: Option<String>,
    /// Which configured scope admitted it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    pub capability: Capability,
    pub outcome: Outcome,
    /// Why, when refused or errored. A [`SluseError::reason_code`], never prose:
    /// messages are written for people and get rewritten.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// What the *source* said, when it said anything: the OS or Win32 error
    /// behind an `ACCESS_DENIED` or a `SOURCE_UNAVAILABLE`. **D-015.**
    ///
    /// Not prose for a reader and not shown to the agent — the message the agent
    /// gets is identical whatever this says. It is here because the error types
    /// have carried it all along and the record dropped it, which left a refusal
    /// nobody could investigate: the prober run's two `ACCESS_DENIED` records
    /// carried a reason code and nothing else, and the scored run's outage
    /// carried no evidence of being one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The hash of the bytes admitted or published.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<ContentHash>,
    /// How many bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    /// The join key between the Gate's record and the endpoint's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_id: Option<AdmissionId>,
    /// Which publish call, on a publish record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub publish_id: Option<PublishId>,
    /// The artifact's name, on a publish record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    /// On a publish record, **everything admitted in the session**, deduped by
    /// hash, each with its state: deterministic, and an over-claim on purpose
    /// (D-018, renamed by D-055). On a [`Op::Reread`], the one admission the
    /// local copy came from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lineage: Option<Vec<LineageItem>>,
    /// On a publish record, the sources the agent declared for this artifact,
    /// each an admission of the session; empty when it declared none (D-055).
    /// The agent's word: checked to have been admitted, not to have been used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sources: Option<Vec<LineageItem>>,
    /// The sensitivity label applied, where one was. `None` everywhere until
    /// Q-4 and Q-5 are settled; the prototype writes `null` in every manifest
    /// rather than inventing a label it cannot honour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Which preflight snapshot was in force. Gate records only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture_id: Option<PostureId>,
}

impl AuditRecord {
    /// A record with everything mandatory filled in and everything optional
    /// empty. Start here and set what applies.
    ///
    /// The timestamp is taken now, at construction, which is the moment the
    /// record describes rather than the moment it reaches a sink.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        writer: Writer,
        box_id: BoxId,
        user: UserRef,
        config_version: ContentHash,
        session_id: SessionId,
        op: Op,
        path_requested: impl Into<String>,
    ) -> Self {
        Self {
            writer,
            box_id,
            user,
            config_version,
            session_id,
            ts: Utc::now(),
            op,
            path_requested: path_requested.into(),
            path_resolved: None,
            scope: None,
            capability: Capability::Bytes,
            outcome: Outcome::Admitted,
            reason: None,
            detail: None,
            hash: None,
            bytes: None,
            admission_id: None,
            publish_id: None,
            artifact: None,
            lineage: None,
            sources: None,
            label: None,
            posture_id: None,
        }
    }

    /// Mark this record as a refusal or an error, taking both the outcome and
    /// the reason code from the error itself.
    ///
    /// One call, so the two can never disagree — which they would, eventually,
    /// if each call site chose an outcome and a code separately.
    pub fn failed(mut self, err: &SluseError) -> Self {
        self.outcome = if err.is_refusal() { Outcome::Refused } else { Outcome::Error };
        self.reason = Some(err.reason_code().to_owned());

        // What the agent is not told.
        //
        // D-008 collapses `UnknownSource`, `OutOfScope` and `NotFound` into one
        // byte-identical "No such path" for the guest, so the difference between
        // "you asked for something that is not there" and "you went looking
        // outside your scope" survives in exactly one place: this record. A
        // refusal that does not carry the resolved path and the enforcing scopes
        // is a refusal nobody can investigate — which is most of what the host
        // half of the two-record design is for.
        //
        // `SluseError::OutOfScope` has carried both since M1 and its own
        // documentation says they are "for the host's audit record". Until M4
        // they were dropped here.
        if let SluseError::OutOfScope { resolved, scopes, .. } = err {
            self.path_resolved = Some(resolved.clone());
            if !scopes.is_empty() {
                self.scope = Some(scopes.join("; "));
            }
        }

        // D-015 point 3: carry whatever the error already holds.
        //
        // `AccessDenied` and `SourceUnavailable` have had a `detail` since M1 and
        // it never reached a record, so a denied path recorded a reason code and
        // nothing else — nothing to investigate, and no way to tell a targeted
        // refusal from a flapping share. A denied path has no *resolved* path to
        // record, because canonicalisation is exactly what the ACL refused, so
        // this is the only evidence there is.
        //
        // `NotFound` deliberately gains nothing here. It carries no detail, and
        // D-015 point 1 is why it does not need one: the case that made an OS
        // error worth having on a `NOT_FOUND` — an outage arriving as an absence
        // — is now classified as `SOURCE_UNAVAILABLE` before it reaches this
        // point. Adding a field for an event that can no longer land in it would
        // be paperwork.
        match err {
            SluseError::AccessDenied { detail, .. }
            | SluseError::SourceUnavailable { detail, .. }
                if !detail.trim().is_empty() =>
            {
                self.detail = Some(detail.clone());
            }
            _ => {}
        }
        self
    }

    /// Record the bytes that crossed, and the admission that authorised them.
    pub fn admitted(mut self, id: AdmissionId, hash: ContentHash, bytes: u64) -> Self {
        self.outcome = Outcome::Admitted;
        self.admission_id = Some(id);
        self.hash = Some(hash);
        self.bytes = Some(bytes);
        self
    }

    /// Record an admission the Gate **authorised and did not deliver**: URL
    /// mode (M7). No hash and no byte count, because the Gate never saw the
    /// bytes, and a number here would read as a measurement it did not make.
    /// The endpoint's record, joined on the admission id, carries both.
    pub fn authorised(mut self, id: AdmissionId) -> Self {
        self.outcome = Outcome::Admitted;
        self.admission_id = Some(id);
        self.capability = Capability::Url;
        self
    }

    pub fn resolved(mut self, resolved: impl Into<String>) -> Self {
        self.path_resolved = Some(resolved.into());
        self
    }

    pub fn in_scope(mut self, scope: impl Into<String>) -> Self {
        self.scope = Some(scope.into());
        self
    }

    /// The admission a failure happened after, when there was one: a URL-mode
    /// download that failed, after the Gate had authorised it.
    pub fn with_admission_id(mut self, admission_id: Option<AdmissionId>) -> Self {
        self.admission_id = admission_id;
        self
    }

    pub fn with_capability(mut self, capability: Capability) -> Self {
        self.capability = capability;
        self
    }

    pub fn with_posture(mut self, posture_id: PostureId) -> Self {
        self.posture_id = Some(posture_id);
        self
    }
}

// ---------------------------------------------------------------------------
// Preflight
// ---------------------------------------------------------------------------

/// Which list a check belongs to.
///
/// The split is provisional and is the open question behind it: whether "the
/// user is not a local administrator" is **required** (the box refuses to start)
/// or **posture** (recorded, and someone decides what it means) is under
/// discussion and is not settled by writing this type
/// (`docs/sluse_prototype.md`, Provisional design points).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum CheckList {
    /// A `Fail` here stops the box. No override. The preflight's required
    /// checks; "the gate" before D-071 named the Gate.
    Required,
    /// Recorded on every audit record via the snapshot id. Never blocks.
    Posture,
}

/// How a check came out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum CheckOutcome {
    Pass,
    Fail,
    /// The check does not apply in this environment. LOCAL has no hypervisor
    /// guest, no host-only segment and no enforcing proxy, and saying so is
    /// more useful than a `Pass` that would overstate the machine.
    NotApplicable,
    /// The check applies and could not be answered. Distinct from `Fail`
    /// because the difference is the whole reason the field exists: an unknown
    /// reported as a pass is a claim nobody made, and an unknown reported as a
    /// failure stops a box for no reason.
    Unknown,
}

/// One preflight check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Check {
    /// A stable identifier, e.g. `config-valid`, `user-not-local-admin`.
    pub name: String,
    pub list: CheckList,
    pub outcome: CheckOutcome,
    /// What was found: a registry value, an OS build, the reason for a failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// The preflight result as it was at Gate start.
///
/// Written once, as its own record; every audit record the Gate writes then
/// carries [`PostureSnapshot::id`]. That is what makes "what was this machine
/// like when that file was admitted" answerable months later, without storing
/// the same twenty fields on every line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PostureSnapshot {
    pub id: PostureId,
    pub ts: DateTime<Utc>,
    pub box_id: BoxId,
    pub config_version: ContentHash,
    /// LOCAL or DEMO. A snapshot without it could be read as saying more about
    /// the machine than it does (D-010).
    pub environment: crate::config::Environment,
    pub checks: Vec<Check>,
}

impl PostureSnapshot {
    /// Whether the box may start: no required check failed.
    ///
    /// `NotApplicable` and `Unknown` pass. That is a deliberate looseness in
    /// the Gate and it is the reason the posture list exists beside it: the
    /// things LOCAL cannot answer are recorded as unanswered rather than
    /// waved through silently.
    pub fn required_passed(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|c| c.list == CheckList::Required && c.outcome == CheckOutcome::Fail)
    }

    /// The required checks that failed, for the message that refuses to start.
    pub fn gate_failures(&self) -> impl Iterator<Item = &Check> {
        self.checks
            .iter()
            .filter(|c| c.list == CheckList::Required && c.outcome == CheckOutcome::Fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(op: Op) -> AuditRecord {
        AuditRecord::new(
            Writer::Core,
            BoxId::new_unchecked("box-local-01"),
            UserRef::os_process(r"SERENIT\jok"),
            ContentHash::of(b"config"),
            SessionId::mint(),
            op,
            "tender/docs/brief.md",
        )
    }

    #[test]
    fn a_record_round_trips() {
        let r = record(Op::Read)
            .resolved(r"C:\Sluse-test\fixture\in-scope\docs\brief.md")
            .in_scope("in-scope/docs")
            .admitted(AdmissionId::mint(), ContentHash::of(b"bytes"), 5);
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<AuditRecord>(&json).unwrap(), r);
    }

    #[test]
    fn absent_fields_are_absent_from_the_json_not_null() {
        let json = serde_json::to_value(record(Op::List)).unwrap();
        assert!(json.get("lineage").is_none());
        assert!(json.get("label").is_none());
        assert!(json.get("pathResolved").is_none());
        // And the mandatory ones are there.
        assert_eq!(json["writer"], "core");
        assert_eq!(json["op"], "list");
        assert_eq!(json["capability"], "bytes");
    }

    /// The outcome and the reason code come from one place, so they cannot
    /// disagree: a refusal is never recorded as an error and vice versa.
    /// The blinded refusal keeps, on the host, exactly what the guest is not
    /// told. Without this the two-record design records that something was
    /// refused and not what was reached for, and D-008 becomes untraceable.
    #[test]
    fn a_blinded_refusal_keeps_the_resolved_path_and_the_enforcing_scopes() {
        let refusal = SluseError::OutOfScope {
            raw: "tender/hr/pay.xlsx".into(),
            resolved: r"C:srchrpay.xlsx".into(),
            source_name: "tender".into(),
            scopes: vec![r"C:srcids".into(), r"C:srcpublic".into()],
        };
        let r = record(Op::Read).failed(&refusal);

        assert_eq!(r.outcome, Outcome::Refused);
        assert_eq!(r.reason.as_deref(), Some("OUT_OF_SCOPE"));
        assert_eq!(
            r.path_resolved.as_deref(),
            Some(r"C:srchrpay.xlsx"),
            "the host must keep where the request actually pointed"
        );
        assert_eq!(
            r.scope.as_deref(),
            Some(r"C:srcids; C:srcpublic"),
            "and which scopes were enforcing when it refused"
        );

        // The other two blinded refusals carry nothing to keep, and must not
        // invent it: `UnknownSource` deliberately holds only what was asked for.
        let unknown = SluseError::UnknownSource { raw: "nope/x".into() };
        let r = record(Op::Read).failed(&unknown);
        assert_eq!(r.reason.as_deref(), Some("UNKNOWN_SOURCE"));
        assert!(r.path_resolved.is_none());
        assert!(r.scope.is_none());
    }
    #[test]
    fn a_refusal_carries_what_the_source_said() {
        // D-015 point 3. `AccessDenied` and `SourceUnavailable` have carried a
        // `detail` since M1 and it never reached a record, so the prober run's
        // two ACCESS_DENIED records held a reason code and nothing else. A
        // denied path has no *resolved* path either — canonicalisation is what
        // the ACL refused — so this is the only evidence there is.
        let denied = SluseError::AccessDenied {
            raw: "fixture/restricted/sealed".into(),
            detail: "Access is denied. (os error 5)".into(),
        };
        let r = record(Op::List).failed(&denied);
        assert_eq!(r.reason.as_deref(), Some("ACCESS_DENIED"));
        assert_eq!(r.detail.as_deref(), Some("Access is denied. (os error 5)"));

        let gone = SluseError::SourceUnavailable {
            source_name: "fixture".into(),
            detail: "the source root is no longer reachable".into(),
        };
        assert!(record(Op::Read).failed(&gone).detail.is_some());

        // And a blinded refusal gains nothing: `NotFound` carries no detail, and
        // after D-015 point 1 the event that made one worth having — an outage
        // arriving as an absence — no longer lands here.
        let absent = SluseError::NotFound { raw: "fixture/nope.txt".into() };
        assert_eq!(record(Op::Read).failed(&absent).detail, None);
    }

    #[test]
    fn failed_takes_both_outcome_and_reason_from_the_error() {
        let refusal = SluseError::OutOfScope {
            raw: "tender/hr/pay.xlsx".into(),
            resolved: r"C:\x\hr\pay.xlsx".into(),
            source_name: "tender".into(),
            scopes: vec![],
        };
        let r = record(Op::Read).failed(&refusal);
        assert_eq!(r.outcome, Outcome::Refused);
        assert_eq!(r.reason.as_deref(), Some("OUT_OF_SCOPE"));

        let fault = SluseError::SourceUnavailable {
            source_name: "share".into(),
            detail: "timed out".into(),
        };
        let r = record(Op::Read).failed(&fault);
        assert_eq!(r.outcome, Outcome::Error);
        assert_eq!(r.reason.as_deref(), Some("SOURCE_UNAVAILABLE"));
    }

    #[test]
    fn user_kinds_are_distinguishable_in_the_record() {
        assert_eq!(UserRef::os_process(r"SERENIT\jok").display(), r"os-process:SERENIT\jok");
        assert_eq!(UserRef::entra("adele@contoso.dk").display(), "entra:adele@contoso.dk");

        let json = serde_json::to_value(UserRef::os_process("x")).unwrap();
        assert_eq!(json["kind"], "osProcess");
    }

    fn check(name: &str, list: CheckList, outcome: CheckOutcome) -> Check {
        Check { name: name.into(), list, outcome, detail: None }
    }

    #[test]
    fn the_gate_fails_only_on_a_gate_fail() {
        let mut snap = PostureSnapshot {
            id: PostureId::mint(),
            ts: Utc::now(),
            box_id: BoxId::new_unchecked("b"),
            config_version: ContentHash::of(b"c"),
            environment: crate::config::Environment::Local,
            checks: vec![
                check("config-valid", CheckList::Required, CheckOutcome::Pass),
                check("hypervisor-guest", CheckList::Required, CheckOutcome::NotApplicable),
                check("enhanced-session-disabled", CheckList::Posture, CheckOutcome::Unknown),
                // Posture never blocks, even failing.
                check("user-not-local-admin", CheckList::Posture, CheckOutcome::Fail),
            ],
        };
        assert!(snap.required_passed(), "posture must not block");
        assert_eq!(snap.gate_failures().count(), 0);

        snap.checks.push(check("certs-present", CheckList::Required, CheckOutcome::Fail));
        assert!(!snap.required_passed());
        assert_eq!(snap.gate_failures().count(), 1);
    }

    #[test]
    fn a_snapshot_round_trips() {
        let snap = PostureSnapshot {
            id: PostureId::mint(),
            ts: Utc::now(),
            box_id: BoxId::new_unchecked("b"),
            config_version: ContentHash::of(b"c"),
            environment: crate::config::Environment::Local,
            checks: vec![check("config-valid", CheckList::Required, CheckOutcome::Pass)],
        };
        let json = serde_json::to_string(&snap).unwrap();
        assert_eq!(serde_json::from_str::<PostureSnapshot>(&json).unwrap(), snap);
    }
}

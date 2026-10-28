// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The endpoint-to-gate wire contract: HTTP and JSON over mTLS.
//!
//! One direction only. The endpoint, in the guest, calls the Gate, on the
//! host; the Gate never calls the guest. That is what makes invariant 2 —
//! *the box cannot assert its own scope* — structural rather than a matter of
//! the guest behaving: scope is decided on the far side of a connection the
//! guest opens and cannot answer.
//!
//! mTLS is mandatory, not a hardening option. The endpoint proves it is the
//! endpoint with a client certificate; the Gate proves it is the Gate with a
//! leaf the endpoint has pinned by hash and no CA bundle at all.
//!
//! ## Why the content hash is not on the wire for reads
//!
//! A `read` or `fetch` answers with a byte stream and a few headers. The hash of
//! those bytes is not among them: it would have to be a trailer, which reqwest
//! 0.12 and 0.13 do not surface, or a header, which would mean the Gate read
//! the whole file before sending any of it — and a 500 MB fetch would then be
//! buffered in the one process that must never be a bottleneck.
//!
//! So both sides hash independently, as invariant 7 requires anyway, and the
//! [`ADMISSION_ID`] header joins the two records. The scorer asserts the join is
//! 1:1 and the hashes match. An assumption became a check, which is the better
//! trade.
//!
//! [`ADMISSION_ID`]: header::ADMISSION_ID

use crate::audit::{AuditRecord, Capability, LineageItem};
use crate::config::{SourceKind, VolumeConfig};
use crate::hash::ContentHash;
use crate::ids::{AdmissionId, BoxId, PostureId, PublishId, SessionId, SourceName};
use chrono::{DateTime, Utc};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Route paths. Versioned from the first line: the endpoint ships inside a guest
/// image and the Gate is installed on the host, so the two are updated
/// separately and will not always be the same age.
/// **Responses accept fields they do not know; requests do not** (review
/// R-48, D-071 slice 9). The Gate is updated with the MSI and a box's
/// endpoint with its base, so a newer Gate's answer may carry a field an
/// older box has never heard of, and refusing it would stop every box not
/// yet reset. A request is the box's word, parsed by Gate Front: strict.
pub mod route {
    pub const HEALTH: &str = "/v1/health";
    pub const STATUS: &str = "/v1/status";
    pub const CONFIG_VIEW: &str = "/v1/config-view";
    pub const LIST: &str = "/v1/list";
    pub const READ: &str = "/v1/read";
    pub const STAT: &str = "/v1/stat";
    pub const PUBLISH: &str = "/v1/publish";
    pub const ALERTS: &str = "/v1/alerts";
    pub const AUDIT_TAIL: &str = "/v1/audit/tail";
    pub const SIGN_OUT: &str = "/v1/sign-out";
    /// On the enrolment listener only ([`super::ENROL_PORT`]), never on the
    /// mTLS one.
    pub const ENROL: &str = "/v1/enrol";
    /// The box's journal, mirrored to the host (D-027 point 5).
    pub const JOURNAL: &str = "/v1/journal";
    /// The tools of the config's `mcp` sources the agent may call (D-071).
    pub const TOOLS: &str = "/v1/tools";
    /// One tool call, admitted like a fetch (D-071).
    pub const CALL: &str = "/v1/call";
}

/// The enrolment listener's port, on the Gate's own host. Server TLS with the
/// Gate's pinned leaf, **no client certificate**, and one route (D-027 design
/// point 4). The mTLS listener is not touched: there is no route there that
/// takes a client without a certificate.
pub const ENROL_PORT: u16 = crate::ports::ENROL;

/// Header names, as constants, because a typo in one of these is a silent
/// authorisation change rather than a compile error.
pub mod header {
    /// The session every request belongs to. Required on every route but health.
    pub const SESSION: &str = "x-sluse-session";

    /// The admission id, on a read or fetch response. The join key.
    pub const ADMISSION_ID: &str = "x-sluse-admission-id";

    /// Size in bytes of the body that follows.
    pub const SIZE: &str = "x-sluse-size";

    /// What the requested path resolved to, for the endpoint's journal.
    pub const RESOLVED: &str = "x-sluse-resolved";

    /// `bytes` or `url`, on a read or fetch response. **M7.**
    ///
    /// Absent means `bytes`. `url` was a pre-authenticated download address
    /// in the body instead of the file, from M7 until D-046 put SharePoint in
    /// bytes mode; this build refuses one.
    pub const CAPABILITY: &str = "x-sluse-capability";

    /// Who the Gate acted as for this response: [`UserRef::display`], on
    /// every response it sends. The endpoint's journal records this, not the
    /// identity it saw at start-up, so the guest's record of an admission names
    /// the same person as the Gate's once the box is signed in (D-022).
    ///
    /// [`UserRef::display`]: crate::UserRef::display
    pub const USER: &str = "x-sluse-user";

    /// A header value for any string. Header values are visible ASCII, and a
    /// UPN or a host path need not be: `æ`, a space. Bytes outside `!`..`~`,
    /// and `%` itself, become `%XX`. [`RESOLVED`] and [`USER`] are sent this way.
    pub fn encode(value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        for b in value.bytes() {
            if (0x21..=0x7e).contains(&b) && b != b'%' {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{b:02X}"));
            }
        }
        out
    }

    /// The inverse of [`encode`]. A malformed escape is kept as written, and
    /// bytes that are not UTF-8 are replaced rather than refused: this is a
    /// label for a record, and a partly wrong label beats a missing one.
    pub fn decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let hex = bytes.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
            match (bytes[i], hex.and_then(|h| u8::from_str_radix(h, 16).ok())) {
                (b'%', Some(b)) => {
                    out.push(b);
                    i += 3;
                }
                (b, _) => {
                    out.push(b);
                    i += 1;
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }
}

// ---------------------------------------------------------------------------
// GET /v1/health
// ---------------------------------------------------------------------------

/// What the Gate says about itself. The only route that needs no session.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Health {
    pub ok: bool,
    pub box_id: BoxId,
    /// The hash of the config the Gate loaded. The endpoint compares it with
    /// its own copy's hash: a guest running against a different config than the
    /// host is enforcing is a condition worth seeing immediately, even though
    /// only the Gate's copy decides anything.
    pub config_version: ContentHash,
    /// The Gate binary's version.
    pub gate_version: String,
    /// Who the Gate is acting as: the box's signed-in user, else its own
    /// process identity. Can change after this answer; `x-sluse-user` on
    /// every response is the current one.
    pub user: crate::audit::UserRef,
    /// The preflight snapshot in force.
    pub posture_id: PostureId,
    /// **A session id the Gate minted, for the caller to carry from here on.**
    ///
    /// The guest does not choose this. It ties records and a journal to one
    /// run; it is not what the volume window counts by, which is the source
    /// alone (D-060), because a box can mint as many as it likes. Every other
    /// route requires
    /// [`headers::SESSION`], and the Gate refuses one it did not issue with
    /// [`SluseError::UnknownSession`](crate::SluseError::UnknownSession).
    ///
    /// A fresh one per call, so health is not a way to reattach to somebody
    /// else's session. A caller that only wants liveness — `sluse check`'s
    /// "gate reachable" Gate — discards it, and it ages out unused.
    pub session_id: SessionId,
}

// ---------------------------------------------------------------------------
// GET /v1/status
// ---------------------------------------------------------------------------

/// Liveness without a session.
///
/// Everything [`Health`] reports except the session id, and that omission is
/// the whole reason the route exists. `/v1/health` mints on every call because
/// it is where a session comes from; anything that only wants to know whether
/// the Gate is serving — `sluse status`, the "gate reachable" Gate, the
/// console's state panel — would mint one per call and evict live sessions out
/// of a registry that holds a bounded number of them. A liveness probe that
/// costs another caller its session is a probe that breaks the thing it is
/// checking.
///
/// Behind the same mTLS listener as every other route: a caller still presents
/// a client certificate, so this is not an unauthenticated liveness endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub ok: bool,
    pub box_id: BoxId,
    /// The hash of the config the Gate loaded.
    pub config_version: ContentHash,
    /// The Gate binary's version.
    pub gate_version: String,
    /// Who the Gate is acting as.
    pub user: crate::audit::UserRef,
    /// The preflight snapshot in force.
    pub posture_id: PostureId,
    /// Whether every required check passed. Always true on a serving Gate — it
    /// refuses to start otherwise — and reported anyway, so a reader does not
    /// have to already know that in order to trust the answer.
    pub required_passed: bool,
    /// Who the box is signed in as (D-022), or `None`. Asked by the console
    /// on every refresh, so the person sees whose authority the box is using.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_in: Option<crate::audit::UserRef>,
    /// How the last sign-in from the host ended (D-036), for the service,
    /// which handed it over and waits for this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_sign_in: Option<HostSignInResult>,
    /// How many sessions the Gate is holding. Not a count of users:
    /// `/v1/health` mints one per call, so this is closer to "how many times
    /// has something asked for a session recently".
    pub sessions: usize,
    /// Seconds since the listener was bound.
    pub uptime_seconds: i64,
    /// The device's environment, so the console asks for the greyed listing
    /// and the host's audit tail only where they are served, in LOCAL
    /// (D-033, D-045 point 2). Absent from an older gate: taken as not LOCAL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<crate::Environment>,
    /// Whether the Gate still holds the session in the request's
    /// [`headers::SESSION`]; absent when none was sent. How a restarted
    /// endpoint asks to resume its run without a refused request in the
    /// Sluse log for a session that only aged out (L1, 2026-10-07).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_held: Option<bool>,
    /// The person signed out in the box (Q7), and nobody has signed in since:
    /// not the same as never signed in, or a sign-in that lapsed.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub signed_out: bool,
    /// What each source let in during the volume window now (Q36, D-060):
    /// the counts the alert is raised from, so the console's meters and the
    /// alert agree. Absent from an older Gate.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volume: Vec<SourceCount>,
    /// A sign-in window the person opened is open now (D-075): the box's
    /// sign-in browser lives until it closes. Absent: none open.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub sign_in_window: bool,
}

/// One source's count in the volume window (Q36).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceCount {
    pub source: SourceName,
    /// Distinct files, as the alert counts them.
    pub files: u32,
    pub bytes: u64,
}

/// The outcome of the sign-in with this `seq`: `error` is `None` when it
/// bound the box (or renewed the binding of the same person).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HostSignInResult {
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ---------------------------------------------------------------------------
// POST /v1/sign-out
// ---------------------------------------------------------------------------

/// What a sign-out did. **D-022**: the box's binding is dropped, and with it
/// the Graph and refresh tokens the Gate held.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SignedOut {
    /// Who was signed out, or `None` when nobody was signed in. Not an error:
    /// signing out twice ends in the same state as once.
    pub user: Option<crate::audit::UserRef>,
}

// ---------------------------------------------------------------------------
// POST /v1/enrol (slice 2, D-024 point 7)
// ---------------------------------------------------------------------------

/// A box asking for its identity. The token came over KVP for this open and
/// works once; the key pair was made in the box and its private half never
/// leaves it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrolRequest {
    pub token: String,
    /// The raw P-256 public key, uncompressed (65 bytes), as lowercase hex.
    pub public_key: String,
    /// The box's own name, for the Gate's log. Not trusted for anything.
    pub hostname: String,
}

/// What the box is given: its client certificate, signed by the Gate's
/// client CA, and **the Gate's two config files, byte for byte**, so that
/// the box's `config_version` is the Gate's.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrolResponse {
    pub cert_pem: String,
    /// The authored file.
    pub config: String,
    /// The device's half.
    pub device: String,
}

// ---------------------------------------------------------------------------
// POST /v1/journal (slice 4, D-027 point 5)
// ---------------------------------------------------------------------------

/// Lines of a session's journal, from byte `offset` of the box's file. The
/// host appends what it does not already have, so sending again is harmless,
/// and answers with how much it now holds.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalAppend {
    pub session: SessionId,
    pub offset: u64,
    /// Whole lines only: the text ends with a newline.
    pub lines: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JournalAck {
    /// The length of the host's copy, which is where the box sends from next.
    pub have: u64,
}

// ---------------------------------------------------------------------------
// GET /v1/config-view
// ---------------------------------------------------------------------------

/// The parts of the config the guest may know.
///
/// Advisory everywhere it is used: the endpoint refuses early with it and the
/// console draws a file browser from it, and neither is trusted for anything
/// (`docs/config.md`, What enforces what). It exists so the agent is not made to
/// discover its world by trial and error, which would fill the audit trail with
/// refusals that mean nothing.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigView {
    pub sources: Vec<SourceView>,
    pub max_read_bytes: u64,
    pub volume: VolumeConfig,
}

/// Where the host's sign-in redirects (D-036): Entra's own page for native
/// clients, which the shell catches before it loads. Registered on Sluse's
/// app as a public-client redirect.
pub const NATIVE_REDIRECT: &str = "https://login.microsoftonline.com/common/oauth2/nativeclient";

/// What the host's sign-in asks for: an ID token for the binding, a refresh
/// token, and Graph with the app's consented delegated permissions.
pub const HOST_SCOPE: &str = "openid profile offline_access https://graph.microsoft.com/.default";

/// What the host's sign-in needs to ask Entra for a code (D-036). None of it
/// is secret: identifiers the tenant already publishes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SignInView {
    /// `https://login.microsoftonline.com/<tenant>`.
    pub authority: String,
    /// Sluse's registration, a public client.
    pub client_id: String,
    /// [`HOST_SCOPE`].
    pub scope: String,
}

impl SignInView {
    pub fn for_entra(e: &crate::EntraConfig) -> Self {
        SignInView {
            authority: format!("https://login.microsoftonline.com/{}", e.tenant_id),
            client_id: e.client_id.clone(),
            scope: HOST_SCOPE.to_owned(),
        }
    }
}

/// One source, as the guest sees it.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceView {
    pub name: SourceName,
    /// `local-folder`, `smb`, `sharepoint`.
    pub kind: String,
    /// Where it is, for the console to show a person. The agent has no use for
    /// it: every path it writes starts with the source name, and
    /// `sluse_sources` does not show it. **It does reach the guest:** the
    /// console's API on localhost serves it, so the agent can learn a share's
    /// UNC path or the SharePoint site's URL. Accepted as a known channel
    /// (D-056 point 2): it names a place, and grants no way to it.
    pub address: String,
    pub sensitivity: u8,
    pub sensitivity_name: String,
    /// The scopes **in request form** — `tender/in-scope/docs`, not
    /// `C:\Sluse-test\fixture\in-scope\docs`.
    ///
    /// No host path in scope form: the guest learns a resolved path only as
    /// the `resolved` value on a path it already named, where it is needed for
    /// the journal to line up with the Gate's record. The source's own
    /// location is in `address`, which is not a path the guest can use.
    pub scopes: Vec<String>,
    /// Whether this source answered the last time anything asked it, and when.
    /// `None` until something has. **D-015 point 4.**
    ///
    /// Reported, never probed: a `sources` call that stat'd every configured
    /// share would buy I/O against each of them to answer a question that is
    /// stale the moment it is answered. This is the last *observation*, with its
    /// timestamp, so a reader can see how old it is.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<SourceLastSeen>,
}

/// The last thing observed about a source's reachability.
///
/// No detail and no error string: the agent gets a state and a time, and the
/// reason lives in the audit record's `detail` (D-015 point 3), on the host side
/// where it belongs.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SourceLastSeen {
    /// Did it answer?
    pub reachable: bool,
    /// When that was observed.
    pub at: DateTime<Utc>,
}

impl SourceView {
    /// Build a view from a config source. Kept here so the Gate cannot
    /// accidentally publish the address of a source under a field the guest
    /// treats as a path.
    pub fn new(
        name: SourceName,
        kind: &SourceKind,
        sensitivity: u8,
        sensitivity_name: impl Into<String>,
        scopes: Vec<String>,
    ) -> Self {
        Self {
            name,
            kind: kind.type_name().to_owned(),
            address: kind.address(),
            sensitivity,
            sensitivity_name: sensitivity_name.into(),
            scopes,
            last_seen: None,
        }
    }

    /// Attach the last observation of this source's reachability (D-015 p4).
    pub fn seen(mut self, last_seen: Option<SourceLastSeen>) -> Self {
        self.last_seen = last_seen;
        self
    }
}

// ---------------------------------------------------------------------------
// POST /v1/list
// ---------------------------------------------------------------------------

/// Who the listing is for. **The whole of D-008 is in this enum.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Audience {
    /// The agent. Entries that are neither in scope nor on the way to something
    /// in scope are **omitted**: out-of-scope files are absent from the agent's
    /// world, not refused in it. A refusal is an answer, and an agent that can
    /// enumerate what it may not have has been told what exists.
    Agent,
    /// A person at the console. Everything is listed, with `inScope: false` on
    /// what is not. The user may see the shape of their own sources; they are
    /// who the scope was drawn for.
    User,
}

// ---------------------------------------------------------------------------
// GET /v1/tools, POST /v1/call (D-071)
// ---------------------------------------------------------------------------

/// The tools the agent may call: each `mcp` source's, as its server lists
/// them, only those the config allows, without the arguments it pins.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolsResponse {
    pub tools: Vec<ToolView>,
    /// Sources whose server could not be asked, each with the reason code.
    /// Their tools are absent, not refused: a server back up lists again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<ToolSourceUnavailable>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolView {
    /// `<source>/<tool>`, as a call names it.
    pub name: String,
    /// The server's description, which is the server's text and not Sluse's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The server's JSON Schema for the arguments, pinned ones removed.
    pub input_schema: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ToolSourceUnavailable {
    pub source: String,
    pub reason: String,
}

/// One call. The answer is the tool's result as JSON, admitted like a fetch:
/// [`header::ADMISSION_ID`], [`header::SIZE`] and [`header::RESOLVED`] as a
/// read's, the hash in both records.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CallRequest {
    /// `<source>/<tool>`.
    pub tool: String,
    #[serde(default)]
    pub arguments: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ListRequest {
    /// `<source>/<relative path>`, or just `<source>` for its root.
    pub path: String,
    pub audience: Audience,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    /// The path listed, echoed back.
    pub path: String,
    pub entries: Vec<ListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ListEntry {
    pub name: String,
    pub kind: EntryKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modified: Option<DateTime<Utc>>,
    /// Always `true` in an [`Audience::Agent`] listing, because anything else
    /// was omitted. Meaningful only to the console.
    pub in_scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Directory,
}

// ---------------------------------------------------------------------------
// POST /v1/read
// ---------------------------------------------------------------------------

/// Which of the two read verbs (`docs/dataflow.md`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ReadVerb {
    /// Bytes inline, capped at `maxReadBytes`, delivered to the model inside an
    /// envelope that marks them as untrusted data.
    Read,
    /// Bytes streamed to the workspace as a file. **Invariant 5's stated
    /// limit**: once a file is on local disk, a later local re-read carries no
    /// envelope, and the docs say so rather than implying otherwise.
    Fetch,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ReadRequest {
    pub path: String,
    pub verb: ReadVerb,
}

/// What a successful read returns *besides* the body: the header values, parsed.
///
/// The body itself is `application/octet-stream` and is streamed, so it is not
/// part of this type — this is the metadata the endpoint needs to journal what
/// it received and to join its record to the Gate's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadHeaders {
    pub admission_id: AdmissionId,
    pub size: u64,
    pub resolved: String,
}

// ---------------------------------------------------------------------------
// POST /v1/stat
// ---------------------------------------------------------------------------

/// What the workspace inventory pinned when a file was admitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Pin {
    pub hash: ContentHash,
    pub size: u64,
    pub modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct StatRequest {
    pub path: String,
    /// What the caller believes about the file.
    ///
    /// When size and modified time still match, the Gate answers from
    /// metadata alone and returns the pinned hash with `matchesPinned: true`
    /// rather than re-reading the bytes. The inventory stats every file it
    /// knows about, and re-hashing a 500 MB fetch to redraw a console row is
    /// not a cost the source should pay.
    ///
    /// It is a cache, and it is honest about being one: size and mtime can both
    /// be preserved across an edit. The inventory's job is to tell a user their
    /// evidence has moved on, not to make a security claim — nothing is
    /// admitted on the strength of this answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pinned: Option<Pin>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StatResponse {
    pub size: u64,
    pub modified: DateTime<Utc>,
    pub hash: ContentHash,
    /// Present only when the request carried a pin. `Some(true)` means the quick
    /// path was taken or the hash matched; `Some(false)` means the file has
    /// changed since it was admitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matches_pinned: Option<bool>,
}

// ---------------------------------------------------------------------------
// POST /v1/publish
// ---------------------------------------------------------------------------

/// The manifest part of a publish, sent before the file parts.
///
/// **One call, many files.** The alternative — a call per file — is what left
/// the second and third artifact of a delivery with no lineage under the "since
/// the last publish" rule, because the first publish consumed it (S-2 finding 8,
/// Q-12). A delivery is one act and is recorded as one.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct PublishManifest {
    pub artifacts: Vec<ArtifactManifest>,
    /// **The endpoint's view of the session's admissions**, deduped by content
    /// hash, each with its state, computed from its journal (D-018). The
    /// Gate does not record this list: it records its own admissions of the
    /// session and takes only each entry's `state` from here, and refuses a
    /// declared source it did not admit itself (D-059, review R-07).
    pub lineage: Vec<LineageItem>,
}

/// One artifact in a publish.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ArtifactManifest {
    /// A single file name. No directory separators, no reserved name.
    pub name: String,
    /// What the endpoint hashed before sending. The Gate re-hashes what it
    /// received and refuses the whole publish on a mismatch: a manifest that
    /// does not describe its bytes is the one thing a provenance record must
    /// never carry.
    pub hash: ContentHash,
    pub bytes: u64,
    /// The admissions the agent declared it used for this artifact, checked by
    /// the endpoint against its journal; empty is a declaration (D-055).
    pub sources: Vec<LineageItem>,
    /// The sensitivity label to apply.
    ///
    /// `None` in everything the prototype writes. Whether the label comes from
    /// the config's own levels or from Purview is Q-4, and whether it survives
    /// the file format is Q-5; until both are settled, writing a label would be
    /// a claim about persistence that nothing has verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublishResponse {
    pub publish_id: PublishId,
    pub artifacts: Vec<PublishedArtifact>,
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PublishedArtifact {
    pub name: String,
    pub hash: ContentHash,
    pub bytes: u64,
    /// Where it landed, in request form.
    pub path: String,
}

// ---------------------------------------------------------------------------
// GET /v1/alerts
// ---------------------------------------------------------------------------

/// A bulk-admission alert.
///
/// **Detective, not preventive.** The admissions that raised it were permitted
/// and happened; the alert says a person should look (`docs/threat-model.md`).
/// Nothing about this stops an agent, and the docs must not suggest it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VolumeAlert {
    pub source: SourceName,
    pub session_id: SessionId,
    /// Distinct content hashes admitted inside the window.
    pub count: u32,
    /// Bytes admitted inside the window, summed over those distinct hashes.
    /// **D-016**: an alert says which threshold tripped in its summary, and
    /// carries both numbers either way, because one large file and forty small
    /// ones are different events and a console showing only a file count cannot
    /// tell them apart.
    #[serde(default)]
    pub bytes: u64,
    pub window_seconds: u32,
    pub opened_at: DateTime<Utc>,
    /// When the count fell back below the threshold. `None` while open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,
    /// A human summary, e.g. `tender/ (27 files, 60 s)`. Also the
    /// `pathRequested` of the `Alert` audit record.
    pub summary: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AlertsQuery {
    /// Only alerts opened after this instant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// GET /v1/audit/tail
// ---------------------------------------------------------------------------

/// **Provisional, and LOCAL only.**
///
/// The console's "what IT sees" panel: the last N records from the host's sink,
/// so a person being shown the prototype can see both halves of the two-record
/// design at once. In the product this route does not exist — the host's log is
/// the host's, and a guest that can read it can learn what the host knows about
/// it. `docs/audit.md` keeps the two-record model; this is a demonstration
/// affordance and `prototype/README.md` lists it under what is not proven.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditTailQuery {
    #[serde(default = "default_tail_limit")]
    pub limit: usize,
}

fn default_tail_limit() -> usize {
    200
}

impl Default for AuditTailQuery {
    fn default() -> Self {
        Self { limit: default_tail_limit() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AuditTailResponse {
    pub records: Vec<AuditRecord>,
}

// ---------------------------------------------------------------------------

/// The capability a source kind produces, whichever verb asked.
///
/// **The source decides, not the verb**, and since D-046 every source is
/// bytes mode: the Gate reads as the user and streams, so its record covers
/// authorisation and delivery both. `sharepoint` was URL mode from M7, on the
/// spec's ground that the Gate would be the bottleneck; since the egress
/// proxy (D-035) a URL-mode download crossed a host process anyway, and URL
/// mode put the tenant's SharePoint host on every box's list (D-044). The
/// verb still decides the cap and where the bytes land.
pub fn capability_for(kind: &SourceKind) -> Capability {
    match kind {
        // Every kind since D-046: the Gate on the data path, SharePoint
        // included, so the trusted side records the delivery and its hash and
        // the box needs no route to the source.
        SourceKind::LocalFolder { .. }
        | SourceKind::Smb { .. }
        | SourceKind::Sharepoint { .. }
        | SourceKind::Inputs
        | SourceKind::Onedrive
        // A tool's answer passes through Gate Core too (D-071).
        | SourceKind::Mcp { .. } => Capability::Bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review R-48: a newer Gate's answer reaches an older box; a request
    /// with a field the Gate does not know is still refused.
    #[test]
    fn a_response_takes_a_field_it_does_not_know_and_a_request_does_not() {
        let entry = serde_json::json!({ "name": "a.md", "kind": "file", "inScope": true, "addedLater": true });
        assert!(serde_json::from_value::<ListEntry>(entry).is_ok());
        let req = serde_json::json!({ "path": "fs/a.md", "audience": "agent", "addedLater": true });
        assert!(serde_json::from_value::<ListRequest>(req).is_err());
    }

    #[test]
    fn a_header_value_carries_any_name_and_comes_back_unchanged() {
        for v in [
            r"C:\Sluse-test\fixture\in-scope\odd\blåbærgrød.txt",
            "entra:adele@contoso.onmicrosoft.com",
            r"os-process:DEMO\Søren Ærø",
            "100% plain",
        ] {
            let enc = header::encode(v);
            assert!(enc.bytes().all(|b| (0x21..=0x7e).contains(&b)), "{enc} is not a header value");
            assert_eq!(header::decode(&enc), v);
        }
        // Plain ASCII passes through as written, so an older Gate's raw value
        // still reads correctly.
        assert_eq!(header::encode("spo/in-scope/a.txt"), "spo/in-scope/a.txt");
        assert_eq!(header::decode("bad%zz%4"), "bad%zz%4");

        let u = crate::UserRef::entra("adele@contoso.onmicrosoft.com");
        assert_eq!(crate::UserRef::parse_display(&u.display()), Some(u));
        let o = crate::UserRef::os_process(r"CONTOSO\adele");
        assert_eq!(crate::UserRef::parse_display(&o.display()), Some(o));
        assert_eq!(crate::UserRef::parse_display("someone"), None);
    }

    #[test]
    fn audience_is_two_words_on_the_wire() {
        assert_eq!(serde_json::to_string(&Audience::Agent).unwrap(), "\"agent\"");
        assert_eq!(serde_json::to_string(&Audience::User).unwrap(), "\"user\"");
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        // A misspelled verb field must fail rather than default to `read`.
        let bad = r#"{"path":"tender/a.md","verbb":"fetch"}"#;
        assert!(serde_json::from_str::<ReadRequest>(bad).is_err());
    }

    #[test]
    fn stat_without_a_pin_is_valid() {
        let r: StatRequest = serde_json::from_str(r#"{"path":"tender/a.md"}"#).unwrap();
        assert!(r.pinned.is_none());
    }

    #[test]
    fn a_manifest_round_trips_with_lineage() {
        let brief = LineageItem {
            path: "tender/docs/brief.md".into(),
            hash: ContentHash::of(b"in"),
            admission_id: Some(AdmissionId::mint()),
            state: Some(crate::AdmissionState::Read),
        };
        let m = PublishManifest {
            artifacts: vec![ArtifactManifest {
                name: "summary.md".into(),
                hash: ContentHash::of(b"out"),
                bytes: 3,
                sources: vec![brief.clone()],
                label: None,
            }],
            lineage: vec![brief],
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: PublishManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.artifacts[0].name, "summary.md");
        assert_eq!(back.artifacts[0].sources, back.lineage);
        assert!(json.contains(r#""state":"read""#));
        assert_eq!(back.lineage.len(), 1);
        // The label is absent, not null: the prototype applies none (Q-4, Q-5).
        assert!(!json.contains("label"));
    }

    #[test]
    fn scopes_travel_in_request_form() {
        let v = SourceView::new(
            SourceName::parse("tender").unwrap(),
            &SourceKind::LocalFolder { root: r"C:\Sluse-test\fixture".into() },
            2,
            "Internal",
            vec!["tender/in-scope/docs".into()],
        );
        assert_eq!(v.kind, "local-folder");
        assert!(v.scopes.iter().all(|s| !s.contains('\\')), "a host path leaked into scopes");
    }

    #[test]
    fn audit_tail_limit_has_a_default() {
        let q: AuditTailQuery = serde_json::from_str("{}").unwrap();
        assert_eq!(q.limit, 200);
    }

    #[test]
    fn the_source_kind_decides_the_capability() {
        let local = SourceKind::LocalFolder { root: "C:\\x".into() };
        let smb = SourceKind::Smb { unc: "\\\\srv\\share".into() };
        let spo = SourceKind::Sharepoint { site_url: "https://t.sharepoint.com/sites/s".into(), library: "Documents".into() };
        assert_eq!(capability_for(&local), Capability::Bytes);
        assert_eq!(capability_for(&smb), Capability::Bytes);
        assert_eq!(capability_for(&spo), Capability::Bytes, "D-046");
    }
}

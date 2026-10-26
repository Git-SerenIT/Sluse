// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The config: the authored file and its device half, their types, the loader,
//! and the rules it fails on.
//!
//! **The schema is the product boundary** (`docs/config.md`): the box consumes
//! this file under Apache-2.0, and the platform — proprietary, and not built —
//! will one day emit it. In v1 a human or a consultant writes it. That is why
//! these types live in the contract crate rather than in the Gate: the Gate,
//! the lifecycle CLI and the endpoint all read the same file, and a field one of
//! them understands differently is a scope disagreement.
//!
//! ## Invariant 6, which is the whole design of this module
//!
//! *Config absent, invalid or of an unknown schema version means nothing runs.*
//! There is no partial load, no default that stands in for a missing source, no
//! warning-and-continue. Every `ConfigError` below is a reason the box does not
//! start.
//!
//! ## What the loader checks, and what it deliberately does not
//!
//! It checks everything that can be decided **from the file alone**: the schema
//! version, the field shapes, the source-name grammar, duplicate names, scope
//! strings that would escape their root, an `smb` address that is not a UNC
//! path, a sensitivity a source claims that is not defined.
//!
//! It does **not** touch the filesystem. It does not canonicalise a root, check
//! that a scope exists, or read a certificate. Three reasons:
//!
//! 1. Those answers are platform-specific and change between the host and the
//!    guest, and this crate is shared by both. Canonicalisation of a UNC path,
//!    junction handling and `\\?\` prefixes belong in the Gate (M2).
//! 2. They are not stable. A scope that exists at load can be gone a second
//!    later, so a check here would buy a guarantee it cannot keep — and the
//!    Gate re-validates on every request regardless, because that is the only
//!    check that holds (`docs/config.md`, What enforces what).
//! 3. The preflight checks is the place where "can this machine actually run
//!    this" is answered, and it reports as a list a person reads
//!    (`docs/deployment.md`).
//!
//! So a config that loads is well formed, not proven workable. The loader says
//! only the first thing, and says it completely.
//!
//! ## The version is the hash
//!
//! [`Loaded::version`] is the **full** SHA-256 of the authored file's bytes as
//! read. Every audit record carries it, so a record can always be tied to the
//! exact scope in force when it was written (`docs/config.md`, Rules). Not a
//! version field a human maintains: the point is that it cannot be edited
//! without changing. The device half beside it ([`Device`], D-038) is not part
//! of it, so every device of a deployment cites the same version.

use crate::hash::ContentHash;
use crate::ids::{BoxId, SourceName};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// The only schema version this build understands.
///
/// **3 since D-038**, which split the file in two: the authored file the
/// admin publishes, whose hash is the version, and the device's half the
/// service writes beside it. A schema 2 file mixed the two, so every device
/// cited its own version; it is refused by name
/// ([`ConfigError::SupersededSchema`]), as D-019 refused schema 1.
pub const SCHEMA_VERSION: u32 = 3;

/// Default for `maxReadBytes`: 256 KiB.
///
/// The cap on a `read`, which returns bytes inline to the model. Chosen as a
/// round number that comfortably holds the documents the S-1 scenario uses and
/// comfortably refuses a source file dump. It is not a security boundary —
/// `maxFetchBytes` is absent by default and admission is the control point
/// (invariant 4) — it is a guard against one tool result filling a context
/// window. Fixed by the product since D-038 point 7: it sits in the device's
/// half, which the admin does not author.
pub const DEFAULT_MAX_READ_BYTES: u64 = 256 * 1024;

/// The four sensitivity levels, fixed (D-038 point 3). Native, not Purview:
/// mapping them to labels is the Platform's, or Q-4's.
pub const SENSITIVITY_LEVELS: [(u8, &str); 4] =
    [(1, "Public"), (2, "Internal"), (3, "Confidential"), (4, "Highly confidential")];

/// The name of the device's half beside an authored file: `sluse.json` has
/// `sluse.device.json`.
pub fn device_path(authored: &Path) -> PathBuf {
    let stem = authored.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    authored.with_file_name(format!("{stem}.device.json"))
}

// ---------------------------------------------------------------------------
// The two files
// ---------------------------------------------------------------------------

/// The authored file: what the admin decided (D-038 point 2). Identity,
/// policy and settings, and nothing about one device. **Its hash is
/// `config_version`**, so every device of a deployment cites the same one.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Authored {
    /// Checked before anything else, and refused if unknown. A file from a
    /// newer platform must stop an older box rather than be half-understood.
    pub schema_version: u32,

    /// Which deployment this file is, for the install's refusal of a second
    /// one (D-038 point 4). Setup always writes it; a hand-written LOCAL file
    /// may leave it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment: Option<Deployment>,

    /// The sources, in the order the console shows them. At least one.
    pub sources: Vec<SourceConfig>,

    /// The ceiling on one `fetch`, or `None` for no ceiling. **D-016.**
    ///
    /// Defaults to absent, deliberately. Admission is the control point and not
    /// size (invariant 4), and `fetch` exists so an agent can have a file it
    /// will process with local tools — a default cap would break that for a
    /// number nobody has measured. A deployment that wants a ceiling says so,
    /// and then `SluseError::TooLarge` refuses above it exactly as `read` does.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_fetch_bytes: Option<u64>,

    /// When to raise a bulk-admission alert.
    pub volume: VolumeConfig,

    /// The tenant and Sluse's app registration. **Required when any source is
    /// `sharepoint`**, and absent otherwise. No credential: the Gate is a
    /// public client (D-036).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entra: Option<EntraConfig>,

    /// Where the box may connect out to, through the host's proxy (M9,
    /// D-035). **Absent means nowhere**: a box whose config has no list
    /// reaches the Gate and nothing else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressConfig>,

    /// The box's size and the copy-out switch (D-038 point 7).
    #[serde(default, rename = "box")]
    pub box_settings: BoxSettings,
}

/// The device's half: what the service writes for this device (D-038 point
/// 2). Not part of the version.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Device {
    /// Which box this is. Carried on every audit record.
    pub box_id: BoxId,

    /// Which environment this box runs in. Drives `not_applicable` rows in
    /// the preflight report and is stamped on every result file, so a LOCAL
    /// result cannot be read as saying something about identity or the guest
    /// boundary (D-010). A fact about how the box was made, so the device's.
    pub environment: Environment,

    /// Inline-read cap in bytes. Fixed by the product; tests lower it.
    #[serde(default = "default_max_read_bytes")]
    pub max_read_bytes: u64,

    /// Where the Gate listens and what certificate it presents.
    pub gate: GateConfig,

    /// What the endpoint presents, and where the console listens.
    pub endpoint: EndpointConfig,

    /// Where published artifacts land. The single write path. On a device the
    /// Gate writes to the signed-in user's `%USERPROFILE%\Sluse Artifacts`
    /// instead, as that user (D-031); this path is used where there is no user
    /// token, as in LOCAL.
    pub artifacts: String,

    /// The agent's working directory inside the box.
    pub workspace: String,

    /// Where the endpoint writes its per-session journal files.
    pub journal_dir: String,

    /// Where the Gate writes audit records.
    pub audit: AuditConfig,
}

/// Which deployment an authored file belongs to.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Deployment {
    /// Setup makes it once and keeps it. Letters, digits, `-` and `_`: it is
    /// compared by the install script and written to the registry.
    pub id: String,
    /// What the admin calls it. Display only.
    #[serde(default)]
    pub name: String,
    /// Counts publishes, from 1. Display only: the hash is the version.
    pub revision: u32,
}

/// The box's size and the copy-out switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BoxSettings {
    /// The box's memory. Setup offers 4, 6 or 8.
    #[serde(rename = "memoryGB", default = "default_memory_gb")]
    pub memory_gb: u32,
    /// The home disk. Setup offers 40, 80 or 120. Grows an existing box,
    /// never shrinks it.
    #[serde(rename = "homeGB", default = "default_home_gb")]
    pub home_gb: u32,
    /// Copying out of the box through the clipboard. It stops copy and paste
    /// out, not retyping or photographing the screen.
    #[serde(default = "default_true")]
    pub copy_out: bool,
}

impl Default for BoxSettings {
    fn default() -> Self {
        Self { memory_gb: default_memory_gb(), home_gb: default_home_gb(), copy_out: true }
    }
}

fn default_memory_gb() -> u32 {
    6 // D-045 point 7
}
fn default_home_gb() -> u32 {
    40
}
fn default_true() -> bool {
    true
}

/// The two halves joined: what every component reads. Built by the loader,
/// never deserialised, so the call sites read one struct as before schema 3.
#[derive(Debug, Clone)]
pub struct Config {
    pub schema_version: u32,
    pub deployment: Option<Deployment>,
    pub box_id: BoxId,
    pub environment: Environment,
    pub sources: Vec<SourceConfig>,
    /// [`SENSITIVITY_LEVELS`], always.
    pub sensitivity_levels: Vec<SensitivityLevel>,
    pub max_read_bytes: u64,
    pub max_fetch_bytes: Option<u64>,
    pub volume: VolumeConfig,
    pub gate: GateConfig,
    pub endpoint: EndpointConfig,
    pub artifacts: String,
    pub workspace: String,
    pub journal_dir: String,
    pub audit: AuditConfig,
    pub entra: Option<EntraConfig>,
    pub egress: Option<EgressConfig>,
    pub box_settings: BoxSettings,
}

impl Config {
    fn join(a: Authored, d: Device) -> Self {
        Config {
            schema_version: a.schema_version,
            deployment: a.deployment,
            box_id: d.box_id,
            environment: d.environment,
            sources: a.sources,
            sensitivity_levels: SENSITIVITY_LEVELS
                .iter()
                .map(|&(level, name)| SensitivityLevel { level, name: name.to_owned() })
                .collect(),
            max_read_bytes: d.max_read_bytes,
            max_fetch_bytes: a.max_fetch_bytes,
            volume: a.volume,
            gate: d.gate,
            endpoint: d.endpoint,
            artifacts: d.artifacts,
            workspace: d.workspace,
            journal_dir: d.journal_dir,
            audit: d.audit,
            entra: a.entra,
            egress: a.egress,
            box_settings: a.box_settings,
        }
    }
}

/// The box's way out: host names, nothing else (D-035). The proxy sees the
/// host a connection is for, never its method or path, so a host that takes
/// uploads is a way out for whatever the box sends it (`threat-model.md`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressConfig {
    /// `host.example.com` for that host alone, `*.example.com` for every
    /// name under it but not `example.com` itself. Lowercase, no scheme, port,
    /// path or address: an address is refused, because the list names whom
    /// the box talks to, and a name's addresses change. **The only part that
    /// is enforced** (D-038 point 5).
    pub allow: Vec<String>,
    /// The bundles setup's catalog offered and the admin chose. Display only:
    /// `allow` is written out in full.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bundles: Vec<String>,
    /// The catalog version the bundles came from. A device that ships a newer
    /// one says so in posture; it never widens `allow` by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalog: Option<u32>,
    /// The per-connection log, `egress.jsonl`. Off when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<EgressLog>,
}

/// The per-connection egress log (D-038 point 7). Refusals reach the Event
/// Log whether or not it is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EgressLog {
    pub enabled: bool,
    /// The size at which it rolls over, keeping one older file.
    #[serde(rename = "maxMB")]
    pub max_mb: u32,
}

impl EgressConfig {
    /// Whether `host` is on the list. `host` as a client sent it: case and a
    /// trailing dot are ignored.
    pub fn allows(&self, host: &str) -> bool {
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        self.allow.iter().any(|e| match e.strip_prefix("*.") {
            Some(suffix) => host.len() > suffix.len() + 1
                && host.ends_with(suffix)
                && host.as_bytes()[host.len() - suffix.len() - 1] == b'.',
            None => *e == host,
        })
    }
}

/// A host name as `egress.allow` takes it: labels of `a-z`, `0-9` and `-`,
/// at least one dot, not all digits (so not an IPv4 address).
fn valid_egress_entry(e: &str) -> bool {
    let name = e.strip_prefix("*.").unwrap_or(e);
    let labels: Vec<&str> = name.split('.').collect();
    name.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        && !labels.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()))
}

/// Sluse's app registration in Entra. **No credential** (D-036): the Gate
/// is a public client, the user signs in on the host, and the Gate holds
/// the user's tokens in memory.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EntraConfig {
    /// The directory (tenant) id, a GUID. Tokens from any other tenant are
    /// refused, whatever else about them is right.
    pub tenant_id: String,
    /// The registration's application (client) id: the ID token's audience.
    pub client_id: String,
}

/// Which environment a config describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Environment {
    /// One laptop, an OS identity, a fixture folder and a mapped share. Proves
    /// functionality, UI, usability and NTFS semantics; proves nothing about
    /// identity or the guest boundary (D-010).
    Local,
    /// A demo-tenant workstation with a real signed-in user.
    Demo,
}

/// One source: what it is called, where it is, and how much of it is in scope.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceConfig {
    /// The name the agent uses as the first segment of every path.
    pub name: SourceName,

    /// What kind of source, and its address.
    pub kind: SourceKind,

    /// Paths relative to the source's root. **Only these, and the directories
    /// on the way to them, exist from the agent's side** (D-008: blinders, not
    /// a fence). Empty means the whole root is in scope.
    #[serde(default)]
    pub scope: Vec<String>,

    /// Which of the configured sensitivity levels applies to this source.
    pub sensitivity: u8,
}

/// The kinds of source, and the address each one needs.
///
/// Adjacently tagged: `{"type": "smb", "address": {"unc": "\\\\host\\share"}}`.
/// The shape follows `docs/config.md`, which names the two parts "type" and
/// "address", and it keeps `deny_unknown_fields` working — serde cannot enforce
/// that alongside a flattened field, and silently accepting a mistyped key in a
/// file that defines scope is exactly the failure invariant 6 exists to stop.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    content = "address",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SourceKind {
    /// A directory on the machine the Gate runs on. The LOCAL fixture, and
    /// nothing a customer would deploy.
    LocalFolder {
        /// Absolute path to the root.
        root: String,
    },
    /// An SMB share, addressed by UNC. Never a mapped drive letter: a letter is
    /// per-session state of whoever mapped it, and the Gate runs as SYSTEM,
    /// where it means something different or nothing at all.
    Smb {
        /// `\\server\share`, optionally with a path below it.
        unc: String,
    },
    /// A SharePoint document library, reached with the user's own token.
    /// Needs [`Authored::entra`] (M7).
    ///
    /// Scope entries are paths inside the library, and are compared
    /// case-insensitively: SharePoint's own paths are.
    Sharepoint {
        /// `https://tenant.sharepoint.com/sites/name`.
        site_url: String,
        /// The document library's name.
        library: String,
    },
    /// The user's own `%USERPROFILE%\Sluse Inputs` (D-054): files the user
    /// puts there to be admitted. Per user, so no address: the Gate finds it
    /// from the user's profile and creates it as them at start, as it does
    /// Sluse Artifacts. Its contents are the user's choice, not the admin's,
    /// and its provenance is the user's device: off unless the admin adds it.
    Inputs,
    /// The `Sluse` folder at the root of the signed-in user's own OneDrive
    /// (D-054), reached with their token as a library is. Per user, so no
    /// address. The user makes the folder and decides what is in it; the
    /// Gate only reads. A shortcut in it is out of scope. Needs
    /// [`Authored::entra`].
    Onedrive,
}

/// The OneDrive folder an `onedrive` source reads (D-054).
pub const ONEDRIVE_FOLDER: &str = "Sluse";

impl SourceKind {
    /// The wire name, matching the `type` tag and the audit record.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::LocalFolder { .. } => "local-folder",
            Self::Smb { .. } => "smb",
            Self::Sharepoint { .. } => "sharepoint",
            Self::Inputs => "inputs",
            Self::Onedrive => "onedrive",
        }
    }

    /// The address as one string, for display and for an audit record.
    pub fn address(&self) -> String {
        match self {
            Self::LocalFolder { root } => root.clone(),
            Self::Smb { unc } => unc.clone(),
            Self::Sharepoint { site_url, library } => format!("{site_url}/{library}"),
            Self::Inputs => r"%USERPROFILE%\Sluse Inputs".to_owned(),
            Self::Onedrive => format!("OneDrive/{ONEDRIVE_FOLDER}"),
        }
    }
}

/// One sensitivity level.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SensitivityLevel {
    /// 1 is the least sensitive. Levels must be distinct.
    pub level: u8,
    /// What this deployment calls it. Shown in the console and written to the
    /// publish manifest as `label` when Q-4 resolves; today it is a name.
    pub name: String,
}

/// Bulk-admission alerting.
///
/// Detective, not preventive: the alert is raised and the admission proceeds
/// (`docs/threat-model.md`). Semantics are provisional — count of *distinct
/// content hashes* per session per source in a sliding window — and are one of
/// the things `docs/config.md` lists as unspecified.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct VolumeConfig {
    /// How many distinct files in the window before an alert is raised.
    ///
    /// S-2 finding 7 sets the floor on a sane value: a first `fetch` of a Rust
    /// crate was 12 files in 13 seconds, and that is ordinary work rather than
    /// an incident. A threshold below it would alert on every session start.
    pub admissions: u32,
    /// The sliding window, in seconds.
    pub window_seconds: u32,
    /// How many bytes in the same window before an alert is raised. **D-016.**
    ///
    /// `None` means bytes are not watched: a hand-written config that leaves it
    /// out, and every config written before 2026-09-22. Sluse Admin writes 50 MB
    /// beside its 25 files in 60 s, so an authored deployment watches bytes.
    ///
    /// Counting files alone measured the wrong thing, and the first scored run
    /// showed it: one `fetch` moved a 500 MB file, 582 MB crossed in the
    /// session, and the single alert that was raised described a *rate of 25
    /// files* that had nothing to do with either number. Bytes are summed over
    /// **distinct content hashes**, the same dedupe `admissions` uses, so one
    /// file read twice is one file's worth of bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}

/// Where the Gate listens and what it presents.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct GateConfig {
    /// Socket address to bind, e.g. `127.0.0.1:7580`.
    pub listen: String,
    /// The base URL the endpoint dials, e.g. `https://127.0.0.1:7580`.
    pub url: String,
    /// Gate leaf certificate (PEM).
    pub cert_path: String,
    /// Its private key (PEM).
    pub key_path: String,
    /// The CA whose certificates the Gate accepts from clients. mTLS is
    /// mandatory: a client without one does not complete a handshake.
    pub client_ca_path: String,
    /// SHA-256 of the Gate's leaf certificate in DER form.
    ///
    /// The endpoint trusts this one certificate and no CA bundle at all. A
    /// public root store here would be a way for something in the guest to be
    /// talked into trusting a Gate that is not the Gate.
    pub cert_pin: ContentHash,
}

/// What the endpoint presents, and where the console listens.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EndpointConfig {
    /// Endpoint client certificate (PEM), signed by the Gate's client CA.
    pub client_cert_path: String,
    /// Its private key (PEM).
    pub client_key_path: String,
    /// Where the console's loopback API listens, e.g. `127.0.0.1:7582`.
    ///
    /// Loopback and unauthenticated in LOCAL, which is a limitation and is
    /// written down as one in `prototype/README.md` rather than glossed.
    pub console_listen: String,
}

/// Where audit records go.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AuditConfig {
    /// Which sink.
    pub sink: AuditSinkKind,
    /// The JSONL file, when `sink` is `jsonl`. Ignored by the Event Log sink.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// The audit sinks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum AuditSinkKind {
    /// One JSON object per line. The prototype's sink, and readable without a
    /// SIEM.
    Jsonl,
    /// The Windows Event Log. **v1's sink** (`docs/audit.md`): every customer's
    /// SIEM agent already collects it, so integration work is zero. Windows
    /// only; elsewhere the Gate refuses to start with it.
    Eventlog,
}

fn default_max_read_bytes() -> u64 {
    DEFAULT_MAX_READ_BYTES
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

/// A config that loaded, with the things derived from loading it.
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The two files, joined.
    pub config: Config,
    /// The full SHA-256 of the authored file's bytes. This is `config_version`.
    pub version: ContentHash,
    /// The full SHA-256 of the device's half, so a reader can tell it changed.
    pub device_version: ContentHash,
    /// The authored file, as it was named.
    pub file: PathBuf,
    /// The directory relative paths in the file resolve against: the file's own
    /// directory. A config is moved as a unit with the tree it describes, and a
    /// path relative to the current working directory would mean something
    /// different depending on who started the process.
    pub base: PathBuf,
}

impl Loaded {
    /// Find a source by name.
    pub fn source(&self, name: &str) -> Option<&SourceConfig> {
        self.config.sources.iter().find(|s| s.name.as_str() == name)
    }

    /// Resolve one of the file's path fields against [`Loaded::base`].
    pub fn resolve(&self, p: &str) -> PathBuf {
        let p = Path::new(p);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            self.base.join(p)
        }
    }

    /// The sensitivity level a source claims. Present for every source: the
    /// loader refuses a config where one is not.
    pub fn sensitivity_of(&self, source: &SourceConfig) -> &SensitivityLevel {
        self.config
            .sensitivity_levels
            .iter()
            .find(|l| l.level == source.sensitivity)
            .expect("load() refuses a source whose sensitivity is not defined")
    }
}

/// Every reason a config does not load, and therefore every reason the box does
/// not start.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("config file cannot be read: {0}")]
    Unreadable(String),

    #[error("config is not valid JSON: {0}")]
    NotJson(String),

    #[error("config has no numeric schemaVersion")]
    NoSchemaVersion,

    #[error("config schemaVersion {found} is unknown; this build understands {expected}")]
    UnknownSchema { found: u64, expected: u32 },

    /// A schema this build once understood.
    ///
    /// Its own variant because "unknown version" sends a reader hunting for a
    /// typo, and the file has none: it is a correct old config. Refused, not
    /// half-understood (invariant 6).
    ///
    /// - **1 (D-019):** `fetch` is always available now, so the field has
    ///   nothing left to say and is not accepted-and-ignored.
    /// - **2 (D-038):** the device's plumbing was in the admin's file, and the
    ///   Entra block carried a certificate D-036 removed.
    #[error("{}", superseded(*found))]
    SupersededSchema { found: u64 },

    #[error("config does not match schema {SCHEMA_VERSION}: {0}")]
    Invalid(String),

    #[error("the device's half: {0}")]
    InvalidDevice(String),

    #[error("deployment.{field}: {reason}")]
    BadDeployment { field: &'static str, reason: &'static str },

    #[error("box.{field} is 0")]
    ZeroBox { field: &'static str },

    #[error("egress.log.maxMB is 0 while the log is on")]
    ZeroEgressLog,

    #[error("config defines no sources; a box with no sources can admit nothing")]
    NoSources,

    #[error("source name \"{0}\" is used twice")]
    DuplicateSource(String),

    #[error("source \"{source_name}\": scope entry \"{path}\" is not usable: {reason}")]
    BadScope { source_name: String, path: String, reason: String },

    #[error("source \"{source_name}\": address \"{unc}\" is not a UNC path; an smb source must be \\\\server\\share, never a mapped drive letter")]
    SmbNotUnc { source_name: String, unc: String },

    #[error("source \"{source_name}\": root \"{root}\" must be an absolute path")]
    RootNotAbsolute { source_name: String, root: String },

    #[error("source \"{source_name}\": site URL \"{url}\" must be an https:// URL")]
    SiteUrlNotHttps { source_name: String, url: String },

    #[error("source \"{source_name}\" claims sensitivity {level}; the levels are 1 to 4")]
    UnknownSensitivity { source_name: String, level: u8 },

    #[error("{field} \"{value}\" is not a host:port address: {reason}")]
    BadAddress { field: &'static str, value: String, reason: String },

    #[error("audit sink is jsonl but no path is configured")]
    JsonlWithoutPath,

    #[error("egress.allow: \"{0}\" is not a host name; write host.example.com or *.example.com, lowercase, with no scheme, port, path or address")]
    BadEgressHost(String),

    #[error("maxReadBytes is {0}; it must be at least 1")]
    ZeroMaxRead(u64),

    #[error("volume.{field} is 0; a threshold of 0 would alert on every admission")]
    ZeroVolume { field: &'static str },

    /// Present and zero, which would refuse every fetch. Absent means no cap.
    #[error("maxFetchBytes is 0, which would refuse every fetch; omit it for no cap")]
    ZeroMaxFetch,

    /// A `sharepoint` source and nothing to reach it with. The source is read as
    /// the signed-in user, which needs Sluse's registration; without it every
    /// request would fail at the first read rather than at start, where a
    /// person can be told why.
    #[error("source \"{source_name}\" reads through Microsoft Graph (sharepoint or onedrive), which needs an \"entra\" block naming Sluse's registration")]
    EntraMissing { source_name: String },

    #[error("entra.{field} \"{value}\" is not a GUID")]
    NotAGuid { field: &'static str, value: String },
}

fn superseded(found: u64) -> String {
    match found {
        1 => format!("config is schemaVersion 1, which this build no longer accepts: `fetch` was removed and fetch is now always available. Delete the \"fetch\" field and set \"schemaVersion\": {SCHEMA_VERSION}"),
        _ => format!("config is schemaVersion {found}, which this build no longer accepts: since schema {SCHEMA_VERSION} the admin's file holds only what the admin decides, and the device's half is written by the service. Publish the configuration again from Sluse Admin"),
    }
}

/// Read, hash, and validate a config: the authored file at `path` and the
/// device's half beside it ([`device_path`]).
///
/// The order matters and is the point of the function: **version, then shape,
/// then semantics.** An unknown version is reported as an unknown version, not
/// as a pile of unrecognised fields — which is what a newer platform's file
/// would look like if the shape were checked first, and it would send whoever
/// reads the error hunting for a typo that is not there.
pub fn load(path: &Path) -> Result<Loaded, ConfigError> {
    let read = |p: &Path| std::fs::read(p).map_err(|e| ConfigError::Unreadable(format!("{}: {e}", p.display())));
    let authored = read(path)?;
    let device = read(&device_path(path))?;
    load_from_bytes(&authored, &device, path)
}

/// The loader, with the bytes already in hand.
///
/// Split out so tests and the schema example do not need a file, and so the
/// Gate can hash exactly the bytes it validated rather than re-reading a file
/// that may have changed in between.
pub fn load_from_bytes(authored: &[u8], device: &[u8], path: &Path) -> Result<Loaded, ConfigError> {
    let a = load_authored(authored)?;
    let d: Device = serde_json::from_slice(device).map_err(|e| ConfigError::InvalidDevice(e.to_string()))?;
    validate_device(&d)?;

    let base = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);

    Ok(Loaded {
        config: Config::join(a, d),
        version: ContentHash::of(authored),
        device_version: ContentHash::of(device),
        file: path.to_path_buf(),
        base,
    })
}

/// The authored file alone: what setup validates before it publishes, with
/// the same checks the box applies (D-038 point 2).
pub fn load_authored(bytes: &[u8]) -> Result<Authored, ConfigError> {
    // 1. Version, from a shallow parse.
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| ConfigError::NotJson(e.to_string()))?;
    let found = value
        .get("schemaVersion")
        .and_then(serde_json::Value::as_u64)
        .ok_or(ConfigError::NoSchemaVersion)?;
    if (1..u64::from(SCHEMA_VERSION)).contains(&found) {
        return Err(ConfigError::SupersededSchema { found });
    }
    if found != u64::from(SCHEMA_VERSION) {
        return Err(ConfigError::UnknownSchema { found, expected: SCHEMA_VERSION });
    }

    // 2. Shape.
    // From the bytes, not from `value`: a `Value` keeps the last of two equal
    // keys, and `"scope": [...]` then `"scope": []` would enforce the whole
    // root. The struct refuses a duplicate field (review R-35).
    let a: Authored = serde_json::from_slice(bytes).map_err(|e| ConfigError::Invalid(e.to_string()))?;

    // 3. Semantics.
    validate(&a)?;
    Ok(a)
}

/// Everything decidable from the authored file alone. No filesystem, no network.
fn validate(c: &Authored) -> Result<(), ConfigError> {
    if let Some(d) = &c.deployment {
        if d.id.is_empty() || !d.id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(ConfigError::BadDeployment { field: "id", reason: "letters, digits, - and _ only, and not empty" });
        }
        if d.revision == 0 {
            return Err(ConfigError::BadDeployment { field: "revision", reason: "it counts from 1" });
        }
    }
    if c.box_settings.memory_gb == 0 {
        return Err(ConfigError::ZeroBox { field: "memoryGB" });
    }
    if c.box_settings.home_gb == 0 {
        return Err(ConfigError::ZeroBox { field: "homeGB" });
    }
    if c.egress.as_ref().and_then(|e| e.log.as_ref()).is_some_and(|l| l.enabled && l.max_mb == 0) {
        return Err(ConfigError::ZeroEgressLog);
    }
    if c.volume.admissions == 0 {
        return Err(ConfigError::ZeroVolume { field: "admissions" });
    }
    if c.volume.window_seconds == 0 {
        return Err(ConfigError::ZeroVolume { field: "windowSeconds" });
    }
    // Present-and-zero is a config that alerts on everything or refuses
    // everything; absent is the default and means "not watched" / "no cap".
    if c.volume.bytes == Some(0) {
        return Err(ConfigError::ZeroVolume { field: "bytes" });
    }
    if c.max_fetch_bytes == Some(0) {
        return Err(ConfigError::ZeroMaxFetch);
    }

    if c.sources.is_empty() {
        return Err(ConfigError::NoSources);
    }
    let mut seen = BTreeSet::new();
    for s in &c.sources {
        // The name grammar is enforced by `SourceName`'s own deserialiser via
        // the schema; re-check it here so a `new_unchecked` value from a test
        // or a future caller cannot slip past.
        if SourceName::parse(s.name.as_str()).is_none() {
            return Err(ConfigError::Invalid(format!(
                "source name \"{}\" must be 1 to {} characters of ASCII letters, digits, hyphen or underscore",
                s.name,
                SourceName::MAX_LEN
            )));
        }
        if !seen.insert(s.name.as_str()) {
            return Err(ConfigError::DuplicateSource(s.name.to_string()));
        }
        validate_address(s)?;
        for entry in &s.scope {
            validate_scope_entry(s.name.as_str(), entry)?;
        }
        if !SENSITIVITY_LEVELS.iter().any(|&(l, _)| l == s.sensitivity) {
            return Err(ConfigError::UnknownSensitivity {
                source_name: s.name.to_string(),
                level: s.sensitivity,
            });
        }
    }

    if let Some(entra) = &c.entra {
        for (field, value) in [("tenantId", &entra.tenant_id), ("clientId", &entra.client_id)] {
            if !is_guid(value) {
                return Err(ConfigError::NotAGuid { field, value: value.clone() });
            }
        }
    } else if let Some(s) =
        c.sources.iter().find(|s| matches!(s.kind, SourceKind::Sharepoint { .. } | SourceKind::Onedrive))
    {
        return Err(ConfigError::EntraMissing { source_name: s.name.to_string() });
    }

    if let Some(bad) = c.egress.iter().flat_map(|e| &e.allow).find(|e| !valid_egress_entry(e)) {
        return Err(ConfigError::BadEgressHost(bad.clone()));
    }

    Ok(())
}

/// The device's half. The service writes it, but a hand-edited one is still
/// refused rather than half-understood.
fn validate_device(c: &Device) -> Result<(), ConfigError> {
    if c.max_read_bytes == 0 {
        return Err(ConfigError::ZeroMaxRead(c.max_read_bytes));
    }
    // A hash in shape, or the preflight's report panics where it shortens it
    // (review R-34).
    if ContentHash::from_hex(c.gate.cert_pin.as_str()).is_none() {
        return Err(ConfigError::InvalidDevice(format!(
            "gate.certPin {:?} is not a SHA-256 in lowercase hex",
            c.gate.cert_pin.as_str()
        )));
    }
    validate_socket_addr("gate.listen", &c.gate.listen)?;
    refuse_wildcard("gate.listen", &c.gate.listen)?;
    validate_socket_addr("endpoint.consoleListen", &c.endpoint.console_listen)?;

    if c.audit.sink == AuditSinkKind::Jsonl && c.audit.path.is_none() {
        return Err(ConfigError::JsonlWithoutPath);
    }
    Ok(())
}

fn validate_address(s: &SourceConfig) -> Result<(), ConfigError> {
    let name = s.name.to_string();
    match &s.kind {
        SourceKind::LocalFolder { root } => {
            // Absolute in the shape Windows means by it: a drive-qualified path
            // or a UNC. `\fixture` is "root of the current drive", which is
            // whichever drive the process happens to be on.
            let drive_qualified = {
                let b = root.as_bytes();
                b.len() >= 3
                    && b[0].is_ascii_alphabetic()
                    && b[1] == b':'
                    && (b[2] == b'\\' || b[2] == b'/')
            };
            // A POSIX absolute root off Windows, same asymmetry as `scope::fold`
            // and for the same reason: each platform is judged in the shape it
            // actually has. The development guest (D-011) has no drives, and
            // refusing `/srv/fixture` there leaves `sluse start` unable to name
            // a source on the machine the build now happens on. `\fixture` is
            // still refused everywhere — a backslash root is not a POSIX path.
            let posix_absolute = !cfg!(windows) && root.starts_with('/');
            if !(drive_qualified || is_unc(root) || posix_absolute) {
                return Err(ConfigError::RootNotAbsolute { source_name: name, root: root.clone() });
            }
        }
        SourceKind::Smb { unc } => {
            if !is_unc(unc) {
                return Err(ConfigError::SmbNotUnc { source_name: name, unc: unc.clone() });
            }
        }
        SourceKind::Sharepoint { site_url, .. } => {
            if !site_url.starts_with("https://") {
                return Err(ConfigError::SiteUrlNotHttps { source_name: name, url: site_url.clone() });
            }
        }
        SourceKind::Inputs | SourceKind::Onedrive => {}
    }
    Ok(())
}

/// `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, hex. A tenant or client id that is
/// not one is a copy-paste error, and the place to find that is here rather
/// than in a token exchange that fails with a message about something else.
fn is_guid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            _ => c.is_ascii_hexdigit(),
        })
}

/// `\\server\share`, with both parts present.
fn is_unc(s: &str) -> bool {
    let Some(rest) = s.strip_prefix(r"\\") else {
        return false;
    };
    let mut parts = rest.split('\\').filter(|p| !p.is_empty());
    parts.next().is_some() && parts.next().is_some()
}

/// A scope entry is a path *relative to its source's root*.
///
/// Refused: anything absolute, anything drive-qualified, anything with a `..`
/// component, and the empty string. This is not the enforcing check — the Gate
/// canonicalises and re-checks on every request, because only a check made
/// outside the guest against the resolved path holds. It is the check that stops
/// an unworkable config from ever reaching the Gate, where the same mistake
/// would surface as a refusal on a file a user expected to be able to read.
fn validate_scope_entry(source: &str, entry: &str) -> Result<(), ConfigError> {
    let bad = |reason: &str| ConfigError::BadScope {
        source_name: source.to_owned(),
        path: entry.to_owned(),
        reason: reason.to_owned(),
    };

    if entry.trim().is_empty() {
        return Err(bad("it is empty; omit the scope list entirely to mean the whole root"));
    }
    if entry.starts_with('/') || entry.starts_with('\\') {
        return Err(bad("it is absolute; scope entries are relative to the source root"));
    }
    if entry.as_bytes().get(1) == Some(&b':') {
        return Err(bad("it names a drive; scope entries are relative to the source root"));
    }
    if entry.split(['/', '\\']).any(|c| c == "..") {
        return Err(bad("it contains a \"..\" component, which would leave the source root"));
    }
    Ok(())
}

/// `host:port`, with a port that parses. Not resolved: the Gate binds it and
/// reports the real failure if it cannot.
fn validate_socket_addr(field: &'static str, value: &str) -> Result<(), ConfigError> {
    let bad = |reason: &str| ConfigError::BadAddress {
        field,
        value: value.to_owned(),
        reason: reason.to_owned(),
    };
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(bad("no port"));
    };
    if host.is_empty() {
        return Err(bad("no host"));
    }
    match port.parse::<u16>() {
        Ok(0) => Err(bad("port 0")),
        Ok(_) => Ok(()),
        Err(e) => Err(bad(&e.to_string())),
    }
}

/// The Gate binds one address, never every interface (M8). On the host it is
/// the host-only segment's address; `0.0.0.0` would also put the Gate on the
/// laptop's Wi-Fi. mTLS would still refuse a stranger, but a listener nobody
/// needs on that network is surface for nothing. The console has its own,
/// stricter rule: loopback only (`require_loopback` in the endpoint).
fn refuse_wildcard(field: &'static str, value: &str) -> Result<(), ConfigError> {
    let host = value.rsplit_once(':').map_or(value, |(h, _)| h);
    let host = host.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_unspecified() => Err(ConfigError::BadAddress {
            field,
            value: value.to_owned(),
            reason: "it is every interface; bind the one the guest dials, the host-only segment's address".to_owned(),
        }),
        // A number the resolver reads as an address (`0`, `127.1`, `0x0`)
        // without being one written whole: `0` binds every interface
        // (review R-36). A name is a name and is left to resolve.
        Err(_) if host.bytes().any(|b| b.is_ascii_digit())
            && host.split('.').all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_hexdigit() || b == b'x' || b == b'X')) =>
        {
            Err(ConfigError::BadAddress {
                field,
                value: value.to_owned(),
                reason: "it is a number, not a whole IP address; write the address in full".to_owned(),
            })
        }
        _ => Ok(()),
    }
}

/// The JSON Schema for [`Authored`], pretty-printed with a trailing newline.
///
/// One function so the example that writes `config/schema.json` and the test
/// that checks it has not drifted produce byte-identical output. Two call sites
/// formatting the same schema slightly differently would make the currency test
/// fail for a reason that has nothing to do with the schema.
pub fn schema_json() -> String {
    pretty(schemars::schema_for!(Authored))
}

/// The JSON Schema for [`Device`], for `config/device.schema.json`.
pub fn device_schema_json() -> String {
    pretty(schemars::schema_for!(Device))
}

fn pretty(schema: schemars::Schema) -> String {
    let mut s = serde_json::to_string_pretty(&schema).expect("a schema serialises");
    s.push('\n');
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal valid config, both halves in one value, so each test can
    /// corrupt one thing and assert on what that one thing produces.
    /// [`split`] parts it into the two files.
    fn valid_json() -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 3,
            "boxId": "box-local-01",
            "environment": "local",
            "sources": [{
                "name": "tender",
                "kind": { "type": "local-folder", "address": { "root": "C:\\Sluse-test\\fixture" } },
                "scope": ["in-scope/docs", "in-scope/office"],
                "sensitivity": 2
            }],
            "volume": { "admissions": 25, "windowSeconds": 60 },
            "gate": {
                "listen": "127.0.0.1:7580",
                "url": "https://127.0.0.1:7580",
                "certPath": "certs/gate.pem",
                "keyPath": "certs/gate.key",
                "clientCaPath": "certs/client-ca.pem",
                "certPin": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            },
            "endpoint": {
                "clientCertPath": "certs/endpoint.pem",
                "clientKeyPath": "certs/endpoint.key",
                "consoleListen": "127.0.0.1:7582"
            },
            "artifacts": "artifacts",
            "workspace": "workspace",
            "journalDir": "journal",
            "audit": { "sink": "jsonl", "path": "audit/gate.jsonl" }
        })
    }

    /// The directory the test loader pretends the config was read from, and an
    /// absolute path somewhere else, both in the running platform's shape.
    /// `base` comes from `Path::parent`, and `C:\cfg\sluse.json` has no parent
    /// off Windows — the loader is fine, the fixture was Windows-only (D-011).
    fn cfg_dir() -> &'static str {
        if cfg!(windows) {
            "C:\\cfg"
        } else {
            "/cfg"
        }
    }

    fn elsewhere() -> &'static str {
        if cfg!(windows) {
            "D:\\elsewhere"
        } else {
            "/elsewhere"
        }
    }

    const DEVICE_KEYS: [&str; 9] =
        ["boxId", "environment", "maxReadBytes", "gate", "endpoint", "artifacts", "workspace", "journalDir", "audit"];

    /// The authored file's bytes and the device's half's, from one value.
    fn split(mut v: serde_json::Value) -> (String, String) {
        let mut device = serde_json::Map::new();
        for k in DEVICE_KEYS {
            if let Some(x) = v.as_object_mut().unwrap().remove(k) {
                device.insert(k.to_owned(), x);
            }
        }
        (v.to_string(), serde_json::Value::Object(device).to_string())
    }

    fn load_value(v: serde_json::Value) -> Result<Loaded, ConfigError> {
        let (a, d) = split(v);
        load_from_bytes(a.as_bytes(), d.as_bytes(), &Path::new(cfg_dir()).join("sluse.json"))
    }

    #[test]
    fn the_example_loads() {
        let loaded = load_value(valid_json()).expect("should load");
        assert_eq!(loaded.config.sources.len(), 1);
        assert_eq!(loaded.config.max_read_bytes, DEFAULT_MAX_READ_BYTES);
        assert_eq!(loaded.base, Path::new(cfg_dir()));
    }

    #[test]
    fn version_is_the_full_hash_of_the_authored_bytes() {
        let (a, d) = split(valid_json());
        let loaded = load_from_bytes(a.as_bytes(), d.as_bytes(), Path::new("x.json")).unwrap();
        assert_eq!(loaded.version, ContentHash::of(a.as_bytes()));
        assert_eq!(loaded.version.as_str().len(), ContentHash::HEX_LEN);
        assert_eq!(loaded.device_version, ContentHash::of(d.as_bytes()));
    }

    #[test]
    fn one_changed_authored_byte_changes_the_version() {
        let a = load_value(valid_json()).unwrap();
        let mut v = valid_json();
        v["volume"]["admissions"] = serde_json::json!(26);
        let b = load_value(v).unwrap();
        assert_ne!(a.version, b.version);
    }

    /// D-038 point 2: the device's half is not part of the version, so every
    /// device of a deployment cites the same one.
    #[test]
    fn two_devices_with_different_pins_cite_one_version() {
        let a = load_value(valid_json()).unwrap();
        let mut v = valid_json();
        v["gate"]["certPin"] = serde_json::json!("0".repeat(64));
        v["boxId"] = serde_json::json!("box-other");
        let b = load_value(v).unwrap();
        assert_eq!(a.version, b.version);
        assert_ne!(a.device_version, b.device_version);
    }

    #[test]
    fn a_device_field_in_the_authored_file_is_refused() {
        let (a, d) = split(valid_json());
        let mut a: serde_json::Value = serde_json::from_str(&a).unwrap();
        a["boxId"] = serde_json::json!("box-x");
        let e = load_from_bytes(a.to_string().as_bytes(), d.as_bytes(), Path::new("x"));
        assert!(matches!(e, Err(ConfigError::Invalid(_))), "{e:?}");
    }

    #[test]
    fn the_device_half_sits_beside_the_authored_file() {
        assert_eq!(device_path(Path::new("/d/sluse.json")), Path::new("/d/sluse.device.json"));
    }

    /// The ordering rule, and the reason this module checks the version with a
    /// shallow parse before deserialising the whole file.
    #[test]
    fn unknown_version_is_reported_before_unknown_fields() {
        let mut v = valid_json();
        v["schemaVersion"] = serde_json::json!(4);
        v["somethingFromTheFuture"] = serde_json::json!(true);
        match load_value(v) {
            Err(ConfigError::UnknownSchema { found: 4, expected: 3 }) => {}
            other => panic!("expected UnknownSchema, got {other:?}"),
        }
    }

    /// D-019: a v1 file is a correct config for a choice that no longer exists,
    /// and the field it carries decided what an agent could do. Refused, with
    /// its own error, and **not** accepted with `fetch` ignored.
    #[test]
    fn a_schema_1_config_is_refused_by_name() {
        let mut v = valid_json();
        v["schemaVersion"] = serde_json::json!(1);
        v["fetch"] = serde_json::json!(false);
        match load_value(v) {
            Err(e @ ConfigError::SupersededSchema { found: 1 }) => {
                let said = e.to_string();
                assert!(said.contains("fetch"), "names the field that went: {said}");
                assert!(said.contains("schemaVersion\": 3"), "says what to set: {said}");
            }
            other => panic!("expected SupersededSchema, got {other:?}"),
        }
    }

    /// D-038: a schema 2 file is refused by name, and says where the new one
    /// comes from.
    #[test]
    fn a_schema_2_config_is_refused_by_name() {
        let mut v = valid_json();
        v["schemaVersion"] = serde_json::json!(2);
        match load_value(v) {
            Err(e @ ConfigError::SupersededSchema { found: 2 }) => {
                assert!(e.to_string().contains("Sluse Admin"), "{e}");
            }
            other => panic!("expected SupersededSchema, got {other:?}"),
        }
    }

    #[test]
    fn deployment_box_and_egress_log_are_checked() {
        let mut v = valid_json();
        v["deployment"] = serde_json::json!({ "id": "4f1c-aa_01", "name": "Pilot", "revision": 2 });
        v["box"] = serde_json::json!({ "memoryGB": 8, "homeGB": 120, "copyOut": false });
        v["egress"] = serde_json::json!({ "allow": ["pypi.org"], "bundles": ["python"], "catalog": 1,
                                          "log": { "enabled": true, "maxMB": 50 } });
        let c = load_value(v).expect("loads").config;
        assert_eq!(c.deployment.unwrap().revision, 2);
        assert_eq!(c.box_settings, BoxSettings { memory_gb: 8, home_gb: 120, copy_out: false });

        // Absent box is the defaults.
        assert_eq!(load_value(valid_json()).unwrap().config.box_settings, BoxSettings::default());

        for (key, value) in [
            ("deployment", serde_json::json!({ "id": "has space", "revision": 1 })),
            ("deployment", serde_json::json!({ "id": "a", "revision": 0 })),
            ("box", serde_json::json!({ "memoryGB": 0 })),
            ("egress", serde_json::json!({ "allow": [], "log": { "enabled": true, "maxMB": 0 } })),
        ] {
            let mut v = valid_json();
            v[key] = value.clone();
            assert!(load_value(v).is_err(), "{key} {value} is refused");
        }
    }

    #[test]
    fn a_missing_version_is_its_own_error() {
        let mut v = valid_json();
        v.as_object_mut().unwrap().remove("schemaVersion");
        assert!(matches!(load_value(v), Err(ConfigError::NoSchemaVersion)));
    }

    #[test]
    fn an_unknown_field_is_refused() {
        let mut v = valid_json();
        v["fecth"] = serde_json::json!(true); // the typo that matters
        assert!(matches!(load_value(v), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn not_json_at_all() {
        let e = load_from_bytes(b"{ not json", b"{}", Path::new("x"));
        assert!(matches!(e, Err(ConfigError::NotJson(_))));
    }

    #[test]
    fn duplicate_source_names() {
        let mut v = valid_json();
        let s = v["sources"][0].clone();
        v["sources"] = serde_json::json!([s.clone(), s]);
        assert!(matches!(load_value(v), Err(ConfigError::DuplicateSource(n)) if n == "tender"));
    }

    #[test]
    fn no_sources_at_all() {
        let mut v = valid_json();
        v["sources"] = serde_json::json!([]);
        assert!(matches!(load_value(v), Err(ConfigError::NoSources)));
    }

    #[test]
    fn source_name_grammar_is_enforced() {
        let mut v = valid_json();
        v["sources"][0]["name"] = serde_json::json!("has.dot");
        assert!(matches!(load_value(v), Err(ConfigError::Invalid(_))));
    }

    #[test]
    fn scope_entries_that_would_leave_the_root() {
        for entry in ["../elsewhere", "in-scope/../../etc", r"\absolute", "/absolute", "D:\\other", "  "] {
            let mut v = valid_json();
            v["sources"][0]["scope"] = serde_json::json!([entry]);
            match load_value(v) {
                Err(ConfigError::BadScope { .. }) => {}
                other => panic!("{entry:?} should be a BadScope, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_dotdot_inside_a_name_is_not_a_traversal() {
        // "..notes" is a legal file name and must not be refused as traversal.
        let mut v = valid_json();
        v["sources"][0]["scope"] = serde_json::json!(["in-scope/..notes"]);
        assert!(load_value(v).is_ok());
    }

    #[test]
    fn empty_scope_means_the_whole_root() {
        let mut v = valid_json();
        v["sources"][0].as_object_mut().unwrap().remove("scope");
        let loaded = load_value(v).expect("should load");
        assert!(loaded.config.sources[0].scope.is_empty());
    }

    #[test]
    fn smb_must_be_unc_not_a_drive_letter() {
        let mut v = valid_json();
        v["sources"][0]["kind"] =
            serde_json::json!({ "type": "smb", "address": { "unc": "Z:\\share" } });
        assert!(matches!(load_value(v), Err(ConfigError::SmbNotUnc { .. })));

        let mut v = valid_json();
        v["sources"][0]["kind"] =
            serde_json::json!({ "type": "smb", "address": { "unc": "\\\\FS01\\share" } });
        assert!(load_value(v).is_ok());

        // A server with no share is not a source.
        let mut v = valid_json();
        v["sources"][0]["kind"] =
            serde_json::json!({ "type": "smb", "address": { "unc": "\\\\FS01" } });
        assert!(matches!(load_value(v), Err(ConfigError::SmbNotUnc { .. })));
    }

    #[test]
    fn local_folder_root_must_be_absolute() {
        let mut v = valid_json();
        v["sources"][0]["kind"] =
            serde_json::json!({ "type": "local-folder", "address": { "root": "fixture" } });
        assert!(matches!(load_value(v), Err(ConfigError::RootNotAbsolute { .. })));

        // "\fixture" is root-of-the-current-drive, which is not a location.
        let mut v = valid_json();
        v["sources"][0]["kind"] =
            serde_json::json!({ "type": "local-folder", "address": { "root": "\\fixture" } });
        assert!(matches!(load_value(v), Err(ConfigError::RootNotAbsolute { .. })));
    }

    /// The guest has no drives (D-011). A POSIX absolute root is a location
    /// there and nowhere else, so the acceptance is `cfg`-gated, not widened.
    #[test]
    #[cfg(not(windows))]
    fn local_folder_root_may_be_posix_absolute_off_windows() {
        let mut v = valid_json();
        v["sources"][0]["kind"] =
            serde_json::json!({ "type": "local-folder", "address": { "root": "/srv/fixture" } });
        assert!(load_value(v).is_ok());
    }

    #[test]
    fn egress_names_hosts_and_wildcards_only_and_matches_them() {
        let mut v = valid_json();
        v["egress"] = serde_json::json!({ "allow": ["pypi.org", "*.snapcraftcontent.com"] });
        let egress = load_value(v).expect("the loader accepts it").config.egress.unwrap();
        assert!(egress.allows("pypi.org"));
        assert!(egress.allows("PyPI.org."), "case and a trailing dot are a client's");
        assert!(!egress.allows("upload.pypi.org"), "a plain entry is that host alone");
        assert!(!egress.allows("evilpypi.org"));
        assert!(egress.allows("a.b.snapcraftcontent.com"));
        assert!(!egress.allows("snapcraftcontent.com"), "a wildcard is the names under it");
        assert!(!egress.allows("xsnapcraftcontent.com"));
        for bad in ["https://pypi.org", "pypi.org:443", "pypi.org/simple", "PyPI.org", "1.2.3.4", "[::1]", "localhost", "*", "*.com.", "a..b", "-a.b", ""] {
            let mut v = valid_json();
            v["egress"] = serde_json::json!({ "allow": [bad] });
            assert!(matches!(load_value(v), Err(ConfigError::BadEgressHost(_))), "{bad:?} is refused");
        }
        // Absent is nowhere, and an older file means what it meant.
        assert!(load_value(valid_json()).unwrap().config.egress.is_none());
    }

    fn entra_json() -> serde_json::Value {
        serde_json::json!({
            "tenantId": "11111111-2222-3333-4444-555555555555",
            "clientId": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        })
    }

    fn sharepoint_source(v: &mut serde_json::Value) {
        v["sources"][0]["kind"] = serde_json::json!({
            "type": "sharepoint",
            "address": { "siteUrl": "https://contoso.sharepoint.com/sites/purviewtest", "library": "Documents" }
        });
    }

    #[test]
    fn sharepoint_loads_with_an_entra_block() {
        let mut v = valid_json();
        sharepoint_source(&mut v);
        v["entra"] = entra_json();
        let loaded = load_value(v).expect("the loader accepts it");
        assert_eq!(loaded.config.sources[0].kind.type_name(), "sharepoint");
        assert!(loaded.config.entra.is_some());
    }

    /// Refused at start rather than at the first read: without the Gate's
    /// registration there is no way to act as the user, and that is a reason
    /// the box does not run (invariant 6).
    #[test]
    fn sharepoint_without_entra_is_refused() {
        let mut v = valid_json();
        sharepoint_source(&mut v);
        assert!(matches!(load_value(v), Err(ConfigError::EntraMissing { .. })));
    }

    /// D-036: no credential, so a file that names one is not half-understood.
    #[test]
    fn an_entra_credential_is_refused() {
        for field in ["certificatePath", "keyPath", "entryClientId"] {
            let mut v = valid_json();
            v["entra"] = entra_json();
            v["entra"][field] = serde_json::json!("x");
            assert!(matches!(load_value(v), Err(ConfigError::Invalid(_))), "{field}");
        }
    }

    #[test]
    fn entra_ids_must_be_guids() {
        for field in ["tenantId", "clientId"] {
            let mut v = valid_json();
            v["entra"] = entra_json();
            v["entra"][field] = serde_json::json!("contoso.onmicrosoft.com");
            assert!(
                matches!(load_value(v), Err(ConfigError::NotAGuid { .. })),
                "{field} accepted a non-GUID"
            );
        }
    }

    /// Additive: a file without the block is the file it always was.
    #[test]
    fn entra_is_optional_without_sharepoint() {
        let loaded = load_value(valid_json()).unwrap();
        assert!(loaded.config.entra.is_none());
    }

    #[test]
    fn sharepoint_site_url_must_be_https() {
        let mut v = valid_json();
        v["sources"][0]["kind"] = serde_json::json!({
            "type": "sharepoint",
            "address": { "siteUrl": "http://contoso.sharepoint.com/sites/x", "library": "Documents" }
        });
        assert!(matches!(load_value(v), Err(ConfigError::SiteUrlNotHttps { .. })));
    }

    /// D-038 point 3: four fixed levels, so the file names none.
    #[test]
    fn sensitivity_rules() {
        for bad in [0, 5, 9] {
            let mut v = valid_json();
            v["sources"][0]["sensitivity"] = serde_json::json!(bad);
            assert!(matches!(load_value(v), Err(ConfigError::UnknownSensitivity { .. })), "{bad}");
        }
        let c = load_value(valid_json()).unwrap();
        assert_eq!(c.sensitivity_of(&c.config.sources[0]).name, "Internal");
        assert_eq!(c.config.sensitivity_levels.len(), 4);

        let mut v = valid_json();
        v["sensitivityLevels"] = serde_json::json!([{"level":2,"name":"a"}]);
        assert!(matches!(load_value(v), Err(ConfigError::Invalid(_))), "the file cannot define its own");
    }

    #[test]
    fn addresses_must_have_a_port_and_name_one_interface() {
        for (field, value) in [
            ("gate", "127.0.0.1"),
            ("gate", "127.0.0.1:0"),
            ("gate", "127.0.0.1:notaport"),
            ("gate", "0.0.0.0:7580"),
            ("gate", "[::]:7580"),
            // Review R-36: the resolver's shorthand for every interface.
            ("gate", "0:7580"),
            ("gate", "0x0:7580"),
            ("gate", "127.1:7580"),
        ] {
            let mut v = valid_json();
            v[field]["listen"] = serde_json::json!(value);
            match load_value(v) {
                Err(ConfigError::BadAddress { .. }) => {}
                other => panic!("{value} should be a BadAddress, got {other:?}"),
            }
        }
    }

    /// Review R-34: a pin that is not a hash is refused at load, not a panic
    /// later where the preflight's report shortens it.
    #[test]
    fn a_cert_pin_that_is_not_a_hash_is_refused() {
        let mut v = valid_json();
        v["gate"]["certPin"] = serde_json::json!("TODO");
        assert!(matches!(load_value(v), Err(ConfigError::InvalidDevice(_))));
    }

    /// Review R-35: two of one key is refused, not the last one believed.
    #[test]
    fn a_duplicate_key_in_the_authored_file_is_refused() {
        let (a, d) = split(valid_json());
        let doubled = a.replacen("\"sources\":", "\"sources\":[],\"sources\":", 1);
        assert_ne!(doubled, a, "the fixture names sources");
        let err = load_from_bytes(doubled.as_bytes(), d.as_bytes(), &Path::new(cfg_dir()).join("sluse.json")).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid(ref m) if m.contains("duplicate")), "{err:?}");
    }

    #[test]
    fn jsonl_sink_needs_a_path() {
        let mut v = valid_json();
        v["audit"] = serde_json::json!({ "sink": "jsonl" });
        assert!(matches!(load_value(v), Err(ConfigError::JsonlWithoutPath)));

        // The Event Log sink needs none.
        let mut v = valid_json();
        v["audit"] = serde_json::json!({ "sink": "eventlog" });
        assert!(load_value(v).is_ok());
    }

    #[test]
    fn thresholds_of_zero_are_refused() {
        let mut v = valid_json();
        v["volume"]["admissions"] = serde_json::json!(0);
        assert!(matches!(load_value(v), Err(ConfigError::ZeroVolume { field: "admissions" })));

        let mut v = valid_json();
        v["maxReadBytes"] = serde_json::json!(0);
        assert!(matches!(load_value(v), Err(ConfigError::ZeroMaxRead(0))));

        // D-016's two: present-and-zero is a config that alerts on everything
        // or refuses every fetch, and **absent is the default** — so the
        // distinction the loader has to keep is between `None` and `Some(0)`.
        let mut v = valid_json();
        v["volume"]["bytes"] = serde_json::json!(0);
        assert!(matches!(load_value(v), Err(ConfigError::ZeroVolume { field: "bytes" })));

        let mut v = valid_json();
        v["maxFetchBytes"] = serde_json::json!(0);
        assert!(matches!(load_value(v), Err(ConfigError::ZeroMaxFetch)));

        // Both absent loads, and both set loads.
        assert!(load_value(valid_json()).unwrap().config.max_fetch_bytes.is_none());
        let mut v = valid_json();
        v["volume"]["bytes"] = serde_json::json!(1_000_000);
        v["maxFetchBytes"] = serde_json::json!(50_000_000);
        let loaded = load_value(v).unwrap();
        assert_eq!(loaded.config.volume.bytes, Some(1_000_000));
        assert_eq!(loaded.config.max_fetch_bytes, Some(50_000_000));
    }

    #[test]
    fn relative_paths_resolve_against_the_config_file() {
        let loaded = load_value(valid_json()).unwrap();
        assert_eq!(loaded.resolve("artifacts"), Path::new(cfg_dir()).join("artifacts"));
        assert_eq!(loaded.resolve(elsewhere()), Path::new(elsewhere()));
    }

    #[test]
    fn a_real_file_loads_from_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sluse.json");
        let (a, d) = split(valid_json());
        std::fs::write(&path, a).unwrap();
        assert!(matches!(load(&path), Err(ConfigError::Unreadable(_))), "no device half yet");
        std::fs::write(dir.path().join("sluse.device.json"), d).unwrap();
        let loaded = load(&path).expect("should load");
        assert_eq!(loaded.base, dir.path());

        let missing = dir.path().join("nope.json");
        assert!(matches!(load(&missing), Err(ConfigError::Unreadable(_))));
    }
    /// No address: per user, found from the user's profile (D-054).
    #[test]
    fn inputs_is_a_kind_without_an_address() {
        let k: SourceKind = serde_json::from_str(r#"{"type": "inputs"}"#).unwrap();
        assert!(matches!(k, SourceKind::Inputs));
        assert_eq!(k.type_name(), "inputs");
        assert_eq!(serde_json::to_value(&k).unwrap(), serde_json::json!({"type": "inputs"}));
        assert!(serde_json::from_str::<SourceKind>(r#"{"type": "inputs", "address": {"root": "C:\\x"}}"#).is_err());
        let k: SourceKind = serde_json::from_str(r#"{"type": "onedrive"}"#).unwrap();
        assert_eq!(k.type_name(), "onedrive");
    }
}

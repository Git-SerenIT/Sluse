// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The host shell's line to the lifecycle service, and what the service hands
//! the box (D-025, D-027).
//!
//! **The pipe.** The shell runs as the user; the service runs as SYSTEM. The
//! shell writes one [`PipeRequest`] as a JSON line and reads [`PipeEvent`]
//! lines until one is [terminal](PipeEvent::is_terminal). The service decides
//! whose box a request is about from the pipe client's own token, never from
//! anything in the request: the pipe is the identity check (D-027 point 4).
//!
//! **The bootstrap.** What the service writes into the box's Hyper-V KVP pool
//! at every open (D-024 point 7). No file crosses and nothing is mounted. The
//! VNC secret in it is machine-to-machine: the user never sees or types it.

use serde::{Deserialize, Serialize};

use crate::hash::ContentHash;

/// The service's pipe. The ACL is set by the service: SYSTEM, plus
/// interactive users.
pub const PIPE_NAME: &str = r"\\.\pipe\sluse";

/// One request per connection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "camelCase")]
pub enum PipeRequest {
    /// Where the caller's box is.
    Status,
    /// Start the caller's box and the Gate, and answer with how to see it.
    Open {
        /// An xkb layout name, from the user's Windows layout ([`xkb_layout`]).
        keyboard: String,
        /// The host's IANA timezone, from the shell's web view, so the box's
        /// clock is the user's (L1, 2026-10-05: the box ran on UTC). Absent
        /// from an older shell; one [`valid_timezone`] refuses is dropped.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timezone: Option<String>,
        /// The host's sign-in (D-036), handed to the Gate once it runs.
        /// Absent when the config has no `entra` block, or when the shell
        /// could not get one; the box then opens unbound, and the shell
        /// tries again with [`PipeRequest::SignIn`].
        #[serde(default, rename = "signIn", skip_serializing_if = "Option::is_none")]
        sign_in: Option<HostSignIn>,
        /// The theme in use in the shell's window, Follow Windows resolved
        /// there, since the box cannot see Windows (Q3, Q70). Written to the
        /// box beside the bootstrap. Absent from an older shell.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        theme: Option<Theme>,
    },
    /// Sign the caller's open box in again, or for the first time (D-036).
    /// Answered with [`PipeEvent::SignedIn`] or a failure; refused after a
    /// sign-out in the box, which holds until the next open (Q7).
    SignIn {
        #[serde(rename = "signIn")]
        sign_in: HostSignIn,
    },
    /// Sign the caller's open box out: the Sluse bar's Sign out (D-064). The
    /// Gate drops the sign-in and records who signed out; no sign-in is
    /// handed over again until the next open (Q7). Answered with
    /// [`PipeEvent::Done`].
    SignOut,
    /// Stop the Gate, which unbinds the sign-in (D-022), and shut the box
    /// down. Both disks are kept (D-026 point 1).
    Close,
    /// "Reset the system, keep my files" (D-026 point 2): a new system disk
    /// on the device's newest base; the home disk stays.
    Reset {
        /// Another user's box. Only an elevated administrator may name one
        /// (D-026 point 3); the service checks the caller's token, not this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sid: Option<String>,
    },
    /// "Wipe the box": both disks replaced. The host's records of it stay,
    /// the journal's mirror included (D-027 point 5).
    Wipe {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        sid: Option<String>,
    },
    /// The theme changed in the shell while the caller's box runs (Q70): the
    /// box takes it at once. Answered with [`PipeEvent::Done`]; refused as
    /// busy during an open, after which the shell sends it again.
    Theme { theme: Theme },
    /// Whether the caller's box's console has answered since the service
    /// started the box (Q9). Answered with [`PipeEvent::Console`]; the shell
    /// asks until it has, keeping its wait over the box.
    Console,
    /// The person quit the shell while their open runs (Q26, Q75): the open
    /// goes on to finish a build, then leaves the box closed. Answered with
    /// [`PipeEvent::Done`]. The shell sends it on a connection of its own and
    /// keeps the open's, so a build's progress still reaches its tray (Q71).
    Quit,
}

/// The box's theme (Q3): Light or Dark, never "follow", which only the
/// computer can resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    Light,
    Dark,
}

impl Theme {
    /// The KVP value, which the box checks against the same two words.
    pub fn as_str(self) -> &'static str {
        match self {
            Theme::Light => "light",
            Theme::Dark => "dark",
        }
    }
}

/// What a wait's step is part of, so the shell can list the steps, time them
/// and say how long each took last time on this device (D-034).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// The device's own part: network, certificates.
    Check,
    /// The base: Ubuntu's image, downloaded.
    Download,
    /// The base: the image converted and the build VM made.
    Convert,
    /// The base: the system installed in the build VM.
    Install,
    /// The user's box made from the base.
    Make,
    /// The box's VM started, and its checks asked of Hyper-V.
    Start,
    /// The Gate started.
    Gate,
    /// The box's screen waited for.
    Wait,
    Reset,
    Wipe,
    Close,
    /// The host's sign-in: the shell's own first step, never the service's
    /// (D-036, Q21: the shell's own limits).
    SignIn,
    /// The box's console waited for: the shell's last step before the box
    /// is shown (Q9). The service keeps its time and its limit.
    Console,
    /// A phase a newer service names that this build does not know.
    #[serde(other)]
    Other,
}

impl PipeEvent {
    /// A step with nothing but its words, as every service before D-034 sent.
    pub fn step(step: impl Into<String>) -> Self {
        PipeEvent::Progress { step: step.into(), phase: None, pct: None, last_s: None, limit_s: None, plan: vec![] }
    }
}

/// One step a request will take, named by its phase as the ledger shows it
/// (Q19): "Making the box again" for a reset's [`Phase::Make`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannedStep {
    pub phase: Phase,
    pub step: String,
}

/// What the service answers with, one JSON line each.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "camelCase")]
pub enum PipeEvent {
    /// A step is under way. `step` is shown to the user as it stands. The
    /// rest is optional and additive (D-034 point 3), so a shell and a service
    /// of different ages still talk: `phase` names what the step is part of,
    /// `pct` is a real percentage where there is one, `lastS` is how long this
    /// phase took last time on this device, and `limitS` is the service's own
    /// limit on it, a number in code, not a measurement: past it the service
    /// stops and says why (Q21). `plan` comes with a request's first progress
    /// only: every step the request expects to take, this one included, in
    /// order (Q19), so the shell keeps no order of its own.
    Progress {
        step: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        phase: Option<Phase>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pct: Option<u8>,
        #[serde(default, rename = "lastS", skip_serializing_if = "Option::is_none")]
        last_s: Option<u64>,
        #[serde(default, rename = "limitS", skip_serializing_if = "Option::is_none")]
        limit_s: Option<u64>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        plan: Vec<PlannedStep>,
    },
    /// The box is up. `vnc` is a `ws://` URL for the viewer, and `password`
    /// goes straight to it. `update`: the device has a newer base than this
    /// box's, which a reset would give it. Never applied on its own
    /// (D-026 point 1).
    Ready {
        vnc: String,
        password: Secret,
        #[serde(default)]
        update: bool,
        /// The last attempt to prepare the device's base failed, and why: the
        /// box opens on the base it has, and the user is told rather than left
        /// with an update that never comes (L1, 2026-09-30).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        problem: Option<String>,
        /// Whether text may be copied out of the box (`box.copyOut`, D-038
        /// point 7). Absent from an older service, which means it may.
        #[serde(default = "yes", rename = "copyOut")]
        copy_out: bool,
        /// The config's version differs from the one this box last opened
        /// under: the shell says so once (D-038 point 4).
        #[serde(default, rename = "configChanged", skip_serializing_if = "std::ops::Not::not")]
        config_changed: bool,
        /// Which parts changed: `sources`, `egress`, `settings` (D-045 point
        /// 3), so the shell names them and offers a wipe only for sources.
        /// Absent from an older service, which said only that it changed.
        #[serde(default, rename = "configChanges", skip_serializing_if = "Vec::is_empty")]
        config_changes: Vec<String>,
        /// The config has the user's Sluse Inputs as a source (D-054): the
        /// shell offers the folder beside Sluse Artifacts.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        inputs: bool,
        /// The config has the user's OneDrive `Sluse` folder as a source
        /// (D-054): the shell offers to make the folder when it is missing.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        onedrive: bool,
        /// The config has file shares, read as the Windows user (D-054): with
        /// an `entra` block beside them the box is mixed, and its shares and
        /// Sluse Inputs go on reading while the cloud waits for a sign-in (Q8).
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        shares: bool,
    },
    /// The answer to [`PipeRequest::Status`]. `signIn` says where to sign in
    /// when the config has an `entra` block; `signedIn` whether the caller's
    /// running Gate holds a sign-in, absent when no Gate runs for them.
    /// `signedOut`: the box was signed in during this open and the person
    /// signed out in it, which holds until the next open (Q7): the shell
    /// does not sign it in again. `user`: who it is signed in as, for the
    /// bar's "Reading as". `vm` and `dir`: the box's name and its folder on
    /// this device, for the details a person sends IT (Q24); absent for a
    /// caller with no box. The view is boxed to keep the event small: the
    /// service returns it as an error value.
    State {
        state: BoxState,
        #[serde(default, rename = "signIn", skip_serializing_if = "Option::is_none")]
        sign_in: Option<Box<crate::wire::SignInView>>,
        #[serde(default, rename = "signedIn", skip_serializing_if = "Option::is_none")]
        signed_in: Option<bool>,
        #[serde(default, rename = "signedOut", skip_serializing_if = "std::ops::Not::not")]
        signed_out: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        vm: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        dir: Option<String>,
    },
    /// The answer to [`PipeRequest::Console`] (Q9): whether the console has
    /// answered, how long it took last time on this device, and how long the
    /// shell waits for it before it says the console did not start.
    Console {
        answered: bool,
        #[serde(default, rename = "lastS", skip_serializing_if = "Option::is_none")]
        last_s: Option<u64>,
        #[serde(rename = "limitS")]
        limit_s: u64,
    },
    /// The answer to a request with nothing to say back: [`PipeRequest::Theme`].
    Done,
    /// The answer to [`PipeRequest::SignIn`]: who the box now acts for.
    SignedIn { user: String },
    /// The answer to [`PipeRequest::Close`], and to a reset or wipe, which
    /// leave the box closed.
    Closed,
    Failed { code: PipeFailure, message: String },
}

fn yes() -> bool {
    true
}

impl PipeEvent {
    /// Whether this ends the conversation. Everything but progress does.
    pub fn is_terminal(&self) -> bool {
        !matches!(self, PipeEvent::Progress { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BoxState {
    /// This Windows user has no box on this device.
    None,
    Off,
    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PipeFailure {
    /// The request did not parse, or carried a value the service refuses.
    BadRequest,
    /// This Windows user has no box on this device.
    NoBox,
    /// Another user's box is running. One runs at a time (D-027).
    Busy,
    /// The preflight checks refused.
    Preflight,
    /// Hyper-V refused, or the box did not come up.
    Box,
    /// The caller may not do this: another user's box, without being an
    /// elevated administrator.
    NotAllowed,
    /// The Gate did not start.
    Gate,
    /// The Gate could not use the sign-in: Entra refused the code, or it
    /// names someone other than the person the box is signed in as.
    SignIn,
    /// The person signed out in the box during this open; that holds until
    /// the next open (Q7).
    SignedOut,
}

/// An authorization code the shell caught at [`crate::wire::NATIVE_REDIRECT`]
/// (D-036), with what redeeming it needs. The Gate redeems it, so the user's
/// tokens never pass through the shell. `seq` is the service's, to match the
/// Gate's answer to this hand-over; the shell sends 0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostSignIn {
    #[serde(default)]
    pub seq: u64,
    pub code: Secret,
    /// The PKCE verifier for the challenge the code was issued against.
    pub verifier: Secret,
    pub redirect_uri: String,
    /// What the ID token's `nonce` must say.
    pub nonce: String,
}

// ---------------------------------------------------------------------------
// The bootstrap
// ---------------------------------------------------------------------------

/// A secret on the wire: serialised as the plain string, never printed by
/// `Debug`. `PipeEvent` and `Bootstrap` derive `Debug`, and the shell formats
/// an unexpected answer with it into a message the user sees (D-033 point 5).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    /// The value, for the one place it is meant to go.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Secret(s)
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Secret(s.to_owned())
    }
}

/// The KVP key the box reads.
pub const KVP_KEY: &str = "sluse-bootstrap";

/// The KVP key the box's theme goes in (Q70): written at every open beside
/// the bootstrap and again at every change, on its own so a change rewrites
/// neither the VNC secret nor the enrolment token.
pub const THEME_KEY: &str = "sluse-theme";

/// A KVP value record is 2,048 bytes, NUL-terminated, so 2,047 are usable.
pub const KVP_VALUE_MAX: usize = 2047;

/// The box's VNC port, websocket only (wayvnc `--websocket`), for noVNC.
/// The box's firewall accepts it from the host alone.
pub const VNC_PORT: u16 = crate::ports::VNC;

/// The user name wayvnc is configured with. Not a secret; the password is.
pub const VNC_USER: &str = "sluse";

/// Handed to the box at every open. Fields are added, never renamed: a box
/// and a service of different ages both read it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bootstrap {
    /// New at every open. The kiosk hands it to wayvnc; the service hands it
    /// to the shell. Nobody types it.
    pub vnc_password: Secret,
    /// An xkb layout name, checked by [`valid_layout`] on both sides.
    pub keyboard: String,
    /// Where the box enrols: `https://<gate host>:<ENROL_PORT>`.
    pub enrol: String,
    /// The Gate's leaf, which the enrolment call pins. The same leaf serves
    /// the mTLS listener, so the config's `gate.certPin` must match it.
    pub pin: ContentHash,
    /// The host's IANA timezone, checked by [`valid_timezone`] on both sides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timezone: Option<String>,
    /// The config's clipboard setting (D-038 point 7), so the box's CLI
    /// header names only the sign-in route that works (Q64). The proxy and
    /// the shell enforce it; the box only says it.
    #[serde(default = "copy_out_default")]
    pub copy_out: bool,
    /// Single use, and new each time the service starts a Gate. The Gate
    /// is given only its hash ([`Bootstrap::token_hash`]).
    pub token: Secret,
}

const fn copy_out_default() -> bool {
    true
}

impl Bootstrap {
    /// A fresh password and token for the given layout, refused if the layout
    /// is not a layout name.
    pub fn new(keyboard: &str, enrol: String, pin: ContentHash) -> Result<Self, String> {
        if !valid_layout(keyboard) {
            return Err(format!("{keyboard:?} is not an xkb layout name"));
        }
        Ok(Self { vnc_password: random(18)?.into(), keyboard: keyboard.to_owned(), enrol, pin, token: random(40)?.into(), timezone: None, copy_out: true })
    }

    /// What the Gate is told, so that the token itself lives only in KVP
    /// and in the box.
    pub fn token_hash(&self) -> ContentHash {
        ContentHash::of(self.token.expose().as_bytes())
    }

    /// The KVP value, refused if it would not fit.
    pub fn to_kvp(&self) -> Result<String, String> {
        let s = serde_json::to_string(self).map_err(|e| e.to_string())?;
        if s.len() > KVP_VALUE_MAX {
            return Err(format!("the bootstrap is {} bytes; KVP holds {KVP_VALUE_MAX}", s.len()));
        }
        Ok(s)
    }
}

// ---------------------------------------------------------------------------
// The host's sign-in request (D-036)
// ---------------------------------------------------------------------------

/// One authorization request from the shell: a PKCE verifier and its S256
/// challenge, the `state` the redirect must echo and the `nonce` the ID token
/// must carry. Pure, so the guest's tests cover what the shell's window does.
#[derive(Debug, Clone)]
pub struct SignInRequest {
    pub verifier: Secret,
    pub challenge: String,
    pub state: String,
    pub nonce: String,
    /// Where Entra sends the code: [`crate::wire::NATIVE_REDIRECT`] for the
    /// box's sign-in; setup's own sign-in uses its client's redirect.
    pub redirect: String,
}

/// What a navigation in the sign-in window turned out to be.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caught {
    /// The redirect, with a code for this request's `state`.
    Code(String),
    /// A silent attempt that needs the person: show the window and ask.
    NeedsUser,
    /// Entra said no, or the redirect was not this request's.
    Failed(String),
}

impl SignInRequest {
    pub fn new() -> Result<Self, String> {
        Self::with_redirect(crate::wire::NATIVE_REDIRECT)
    }

    pub fn with_redirect(redirect: &str) -> Result<Self, String> {
        // RFC 7636: 43 to 128 unreserved characters; `random`'s alphabet is.
        let verifier = random(64)?;
        Ok(SignInRequest {
            challenge: challenge(&verifier),
            verifier: verifier.into(),
            state: random(24)?,
            nonce: random(24)?,
            redirect: redirect.to_owned(),
        })
    }

    /// Entra's authorize URL for this request. `silent` asks with
    /// `prompt=none`, which answers at the redirect whatever happens.
    pub fn authorize_url(&self, view: &crate::wire::SignInView, silent: bool) -> String {
        let mut url = format!(
            "{}/oauth2/v2.0/authorize?client_id={}&response_type=code&response_mode=query&redirect_uri={}&scope={}&state={}&nonce={}&code_challenge={}&code_challenge_method=S256",
            view.authority.trim_end_matches('/'),
            encode(&view.client_id),
            encode(&self.redirect),
            encode(&view.scope),
            self.state,
            self.nonce,
            self.challenge,
        );
        if silent {
            url.push_str("&prompt=none");
        }
        url
    }

    /// `None` for a navigation that is not the redirect, which the window
    /// lets through; otherwise what the redirect says.
    pub fn caught(&self, url: &str) -> Option<Caught> {
        // `http://localhost/?code=…` and `http://localhost?code=…` alike.
        let rest = url.strip_prefix(self.redirect.as_str())?;
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        let query = rest.strip_prefix('?').unwrap_or("").split('#').next().unwrap_or("");
        let get = |k: &str| {
            query.split('&').find_map(|kv| kv.split_once('=').filter(|(key, _)| *key == k).map(|(_, v)| decode(v)))
        };
        Some(match (get("code"), get("error")) {
            _ if get("state").as_deref() != Some(self.state.as_str()) => {
                Caught::Failed("the sign-in came back for another request".into())
            }
            (Some(code), None) => Caught::Code(code),
            (_, Some(e)) if matches!(e.as_str(), "interaction_required" | "login_required" | "consent_required" | "account_selection_required") => {
                Caught::NeedsUser
            }
            (_, e) => Caught::Failed(format!(
                "{}: {}",
                e.unwrap_or_default(),
                get("error_description").unwrap_or_default().lines().next().unwrap_or_default()
            )),
        })
    }

    /// The hand-over for a code this request caught.
    pub fn host_sign_in(&self, code: String) -> HostSignIn {
        HostSignIn {
            seq: 0,
            code: code.into(),
            verifier: self.verifier.clone(),
            redirect_uri: self.redirect.clone(),
            nonce: self.nonce.clone(),
        }
    }
}

/// `BASE64URL(SHA256(verifier))`, unpadded (RFC 7636 4.2).
fn challenge(verifier: &str) -> String {
    use sha2::{Digest, Sha256};
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let d = Sha256::digest(verifier.as_bytes());
    let mut out = String::new();
    for c in d.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..=c.len() {
            out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// Percent-encoding for a query value: everything but RFC 3986's unreserved.
fn encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let hex = b.get(i + 1..i + 3).and_then(|h| u8::from_str_radix(std::str::from_utf8(h).ok()?, 16).ok());
        match (b[i], hex) {
            (b'+', _) => out.push(b' '),
            (b'%', Some(v)) => {
                out.push(v);
                i += 2;
            }
            (c, _) => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `n` characters from an alphabet with nothing to misread, so a secret that
/// ends up in a log line can at least be compared by eye.
fn random(n: usize) -> Result<String, String> {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut raw = vec![0u8; n];
    getrandom::fill(&mut raw).map_err(|e| format!("no randomness: {e}"))?;
    Ok(raw.iter().map(|b| ALPHABET[*b as usize % ALPHABET.len()] as char).collect())
}

/// Whether a screen address the shell is given is `ws://192.168.77.<n>:<port>`
/// and nothing else: the host-only segment, where only a box can be. The
/// shell refuses anything off it, so a process squatting on the pipe name
/// cannot point the user's sign-in at a screen of its own.
pub fn vnc_on_segment(vnc: &str) -> Result<(), String> {
    let refuse = || format!("the service gave a screen address off the host-only segment: {vnc:?}");
    let rest = vnc.strip_prefix("ws://192.168.77.").ok_or_else(refuse)?;
    let (host, port) = rest.split_once(':').ok_or_else(refuse)?;
    match (host.parse::<u8>(), port.parse::<u16>()) {
        (Ok(h), Ok(_)) if h != 0 && h != 255 && !host.starts_with('0') => Ok(()),
        _ => Err(refuse()),
    }
}

// ---------------------------------------------------------------------------
// The keyboard
// ---------------------------------------------------------------------------

/// Whether `s` can be an IANA timezone name, e.g. `Europe/Copenhagen` or
/// `Etc/GMT+1`. It ends up as a path under `/usr/share/zoneinfo` in the box,
/// so: letters, digits, `_`, `+` and `-` in up to three `/`-separated parts,
/// none empty or starting with `-`, 64 bytes at most. No dots, so no `..`.
pub fn valid_timezone(s: &str) -> bool {
    s.len() <= 64
        && s.split('/').count() <= 3
        && s.split('/').all(|p| {
            !p.is_empty() && !p.starts_with('-') && p.bytes().all(|b| b.is_ascii_alphanumeric() || b"_+-".contains(&b))
        })
}

/// Whether `s` can be an xkb layout name. It ends up on a command line in the
/// box, so the grammar is narrow: 2 to 8 lowercase ASCII letters.
pub fn valid_layout(s: &str) -> bool {
    (2..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase())
}

/// The verbs Sluse's `sluse:` link takes (the new UI's slice 4, jok,
/// 2026-10-20): `open` shows Sluse's window, `close` shows it on its own
/// Close confirm, `artifacts` opens Sluse Artifacts. A link is one of them,
/// with any trailing slash and in any case, or nothing.
pub const LINK_VERBS: [&str; 3] = ["open", "close", "artifacts"];

pub fn link_verb(link: &str) -> Option<&'static str> {
    let rest = link.get(..6).filter(|p| p.eq_ignore_ascii_case("sluse:")).and(link.get(6..))?;
    let v = rest.trim_matches('/').to_ascii_lowercase();
    LINK_VERBS.into_iter().find(|x| *x == v)
}

/// The xkb layout for a Windows keyboard layout id (`GetKeyboardLayoutNameW`,
/// e.g. `00000406`). An exact id first, then its language half, so
/// `00020409` (US International) is `us`. `None` for a layout this table
/// lacks; the config's `keyboardLayout` covers those (D-024 design point).
///
/// `ponytail:` layout only, no variants; add a variant column when a user's
/// dead keys matter.
pub fn xkb_layout(klid: &str) -> Option<&'static str> {
    const TABLE: &[(&str, &str)] = &[
        ("00000402", "bg"), ("00000405", "cz"), ("00000406", "dk"), ("00000407", "de"),
        ("00000408", "gr"), ("00000409", "us"), ("0000040a", "es"), ("0000040b", "fi"),
        ("0000040c", "fr"), ("0000040e", "hu"), ("0000040f", "is"), ("00000410", "it"),
        ("00000411", "jp"), ("00000413", "nl"), ("00000414", "no"), ("00000415", "pl"),
        ("00000416", "br"), ("00000418", "ro"), ("00000419", "ru"), ("0000041a", "hr"),
        ("0000041b", "sk"), ("0000041d", "se"), ("0000041f", "tr"), ("00000422", "ua"),
        ("00000424", "si"), ("00000425", "ee"), ("00000426", "lv"), ("00000427", "lt"),
        ("00000807", "ch"), ("0000080a", "latam"), ("0000080c", "be"), ("00000809", "gb"),
        ("00000813", "be"), ("00000816", "pt"), ("00001009", "ca"), ("0000100c", "ch"),
    ];
    let klid = klid.to_ascii_lowercase();
    let find = |id: &str| TABLE.iter().find(|(k, _)| *k == id).map(|(_, v)| *v);
    find(&klid).or_else(|| (klid.len() == 8).then(|| find(&format!("0000{}", &klid[4..]))).flatten())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_events_round_trip_as_json_lines() {
        for r in [
            PipeRequest::Status,
            PipeRequest::Open { keyboard: "dk".into(), timezone: None, sign_in: None, theme: None },
            PipeRequest::Open {
                keyboard: "dk".into(),
                timezone: Some("Europe/Copenhagen".into()),
                sign_in: Some(code()),
                theme: Some(Theme::Dark),
            },
            PipeRequest::SignIn { sign_in: code() },
            PipeRequest::Close,
            PipeRequest::Reset { sid: None },
            PipeRequest::Wipe { sid: Some("S-1-5-21-1".into()) },
            PipeRequest::Theme { theme: Theme::Light },
            PipeRequest::Console,
        ] {
            let line = serde_json::to_string(&r).unwrap();
            assert!(!line.contains('\n'));
            assert_eq!(serde_json::from_str::<PipeRequest>(&line).unwrap(), r);
        }
        assert_eq!(
            serde_json::to_string(&PipeRequest::Open { keyboard: "dk".into(), timezone: None, sign_in: None, theme: None }).unwrap(),
            r#"{"op":"open","keyboard":"dk"}"#
        );
        assert_eq!(serde_json::to_string(&PipeRequest::Theme { theme: Theme::Dark }).unwrap(), r#"{"op":"theme","theme":"dark"}"#);
        assert!(serde_json::from_str::<PipeRequest>(r#"{"op":"theme","theme":"system"}"#).is_err(), "the box takes Light or Dark only");
        // The code and verifier never reach a debug print.
        let shown = format!("{:?}", PipeRequest::SignIn { sign_in: code() });
        assert!(!shown.contains("the-code") && !shown.contains("the-verifier"), "{shown}");
        // An older service's state has neither sign-in field.
        assert_eq!(
            serde_json::from_str::<PipeEvent>(r#"{"event":"state","state":"none"}"#).unwrap(),
            PipeEvent::State { state: BoxState::None, sign_in: None, signed_in: None, signed_out: false, user: None, vm: None, dir: None }
        );
        let e = PipeEvent::Failed { code: PipeFailure::NoBox, message: "x".into() };
        let line = serde_json::to_string(&e).unwrap();
        assert_eq!(line, r#"{"event":"failed","code":"noBox","message":"x"}"#);
        assert_eq!(serde_json::from_str::<PipeEvent>(&line).unwrap(), e);
        assert!(!PipeEvent::step("s").is_terminal());
        // An older shell reads a newer service's progress, and a phase it does
        // not know is `Other`, not a failure; an older service's has no phase.
        let newer: PipeEvent =
            serde_json::from_str(r#"{"event":"progress","step":"s","phase":"teleport","pct":5,"lastS":3,"limitS":9,"more":1}"#).unwrap();
        assert_eq!(
            newer,
            PipeEvent::Progress { step: "s".into(), phase: Some(Phase::Other), pct: Some(5), last_s: Some(3), limit_s: Some(9), plan: vec![] }
        );
        // The plan rides on the first progress only, named as the ledger
        // shows it; a phase the shell itself runs is spelled for it.
        let first = PipeEvent::Progress {
            step: "Checking this computer".into(),
            phase: Some(Phase::Check),
            pct: None,
            last_s: None,
            limit_s: None,
            plan: vec![PlannedStep { phase: Phase::Check, step: "Checking this computer".into() }],
        };
        let line = serde_json::to_string(&first).unwrap();
        assert!(line.ends_with(r#""plan":[{"phase":"check","step":"Checking this computer"}]}"#), "{line}");
        assert_eq!(serde_json::from_str::<PipeEvent>(&line).unwrap(), first);
        assert_eq!(serde_json::to_string(&Phase::SignIn).unwrap(), r#""sign-in""#);
        // Signed out is said only when it is so; the console's answer always
        // carries its limit.
        assert!(!serde_json::to_string(&PipeEvent::State { state: BoxState::Running, sign_in: None, signed_in: Some(false), signed_out: false, user: None, vm: None, dir: None })
            .unwrap()
            .contains("signedOut"));
        assert_eq!(
            serde_json::to_string(&PipeEvent::Console { answered: false, last_s: None, limit_s: 300 }).unwrap(),
            r#"{"event":"console","answered":false,"limitS":300}"#
        );
        assert_eq!(serde_json::to_string(&PipeEvent::Done).unwrap(), r#"{"event":"done"}"#);
        assert!(PipeEvent::Done.is_terminal());
        let older: PipeEvent = serde_json::from_str(r#"{"event":"progress","step":"s"}"#).unwrap();
        assert_eq!(older, PipeEvent::step("s"));
        assert_eq!(serde_json::to_string(&PipeEvent::step("s")).unwrap(), r#"{"event":"progress","step":"s"}"#);
        assert!(PipeEvent::Closed.is_terminal());
        // A user's own reset names nobody; a Ready from an older service has
        // no `update` and means none.
        assert_eq!(serde_json::to_string(&PipeRequest::Reset { sid: None }).unwrap(), r#"{"op":"reset"}"#);
        assert_eq!(
            serde_json::from_str::<PipeEvent>(r#"{"event":"ready","vnc":"ws://x","password":"p"}"#).unwrap(),
            PipeEvent::Ready {
                vnc: "ws://x".into(),
                password: "p".into(),
                update: false,
                problem: None,
                copy_out: true,
                config_changed: false,
                config_changes: vec![],
                inputs: false,
                onedrive: false,
                shares: false,
            }
        );
    }

    fn code() -> HostSignIn {
        HostSignIn {
            seq: 0,
            code: "the-code".into(),
            verifier: "the-verifier".into(),
            redirect_uri: crate::wire::NATIVE_REDIRECT.into(),
            nonce: "n".into(),
        }
    }

    #[test]
    fn the_host_sign_in_request_is_pkce_s256_and_reads_only_its_own_redirect() {
        // RFC 7636 appendix B.
        assert_eq!(challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let r = SignInRequest::new().unwrap();
        assert_eq!(r.verifier.expose().len(), 64);
        assert_eq!(r.challenge, challenge(r.verifier.expose()));
        let view = crate::wire::SignInView {
            authority: "https://login.microsoftonline.com/t".into(),
            client_id: "c".into(),
            scope: crate::wire::HOST_SCOPE.into(),
        };
        let url = r.authorize_url(&view, true);
        assert!(url.starts_with("https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=c&"), "{url}");
        assert!(url.contains("redirect_uri=https%3A%2F%2Flogin.microsoftonline.com%2Fcommon%2Foauth2%2Fnativeclient"));
        assert!(url.contains("scope=openid%20profile%20offline_access%20https%3A%2F%2Fgraph.microsoft.com%2F.default"));
        assert!(url.contains(&format!("code_challenge={}&code_challenge_method=S256", r.challenge)));
        assert!(url.ends_with("&prompt=none") && !r.authorize_url(&view, false).contains("prompt"));
        assert!(!url.contains(r.verifier.expose()), "the verifier never leaves the shell in the URL");

        let back = |q: &str| r.caught(&format!("{}?{q}", crate::wire::NATIVE_REDIRECT));
        let state = &r.state;
        assert_eq!(back(&format!("code=0.AX%2Fy&state={state}")), Some(Caught::Code("0.AX/y".into())));
        assert_eq!(back(&format!("error=interaction_required&state={state}")), Some(Caught::NeedsUser));
        assert!(matches!(back(&format!("error=access_denied&error_description=AADSTS50105%3A+no&state={state}")), Some(Caught::Failed(e)) if e.contains("AADSTS50105: no")));
        assert!(matches!(back("code=x&state=someone-else"), Some(Caught::Failed(_))), "another request's code");
        assert_eq!(r.caught("https://login.microsoftonline.com/t/oauth2/v2.0/authorize?x"), None, "not the redirect");
        assert_eq!(decode("a%2"), "a%2");
        let handed = r.host_sign_in("c0de".into());
        assert_eq!((handed.code.expose(), handed.nonce.as_str()), ("c0de", r.nonce.as_str()));
    }

    #[test]
    fn a_timezone_is_an_iana_name_and_nothing_a_path_could_escape_with() {
        for ok in ["Europe/Copenhagen", "UTC", "Etc/GMT+1", "America/Argentina/Buenos_Aires", "America/Port-au-Prince"] {
            assert!(valid_timezone(ok), "{ok}");
        }
        for bad in ["", "../etc/passwd", "Europe/../../x", "/Europe/Oslo", "Europe//Oslo", "Europe/Oslo;rm", "a/b/c/d", "-x", &"A".repeat(65)] {
            assert!(!valid_timezone(bad), "{bad}");
        }
        // An older box reads a bootstrap with it; an older service's has none.
        let mut b = Bootstrap::new("dk", "https://192.168.77.1:7581".into(), ContentHash::of(b"leaf")).unwrap();
        assert!(!b.to_kvp().unwrap().contains("timezone"));
        b.timezone = Some("Europe/Copenhagen".into());
        assert!(b.to_kvp().unwrap().contains(r#""timezone":"Europe/Copenhagen""#));
        b.copy_out = false;
        assert!(b.to_kvp().unwrap().contains(r#""copyOut":false"#), "the box's CLI header reads it (Q64)");
    }

    #[test]
    fn the_bootstrap_fits_kvp_and_refuses_a_layout_that_is_not_one() {
        let new = |k: &str| Bootstrap::new(k, "https://192.168.77.1:7581".into(), ContentHash::of(b"leaf"));
        let b = new("dk").unwrap();
        assert_eq!(b.vnc_password.expose().len(), 18);
        let c = new("dk").unwrap();
        assert_ne!(b.vnc_password, c.vnc_password);
        assert_ne!(b.token, c.token);
        assert_eq!(b.token_hash(), ContentHash::of(b.token.expose().as_bytes()));
        // Neither secret reaches a debug print, which is how an unexpected
        // answer reaches the user's screen (D-033 point 5).
        let ready = PipeEvent::Ready {
            vnc: "ws://x".into(),
            password: b.vnc_password.clone(),
            update: false,
            problem: None,
            copy_out: true,
            config_changed: false,
            config_changes: vec![],
            inputs: false,
            onedrive: false,
            shares: false,
        };
        let shown = format!("{b:?} {ready:?}");
        assert!(!shown.contains(b.vnc_password.expose()) && !shown.contains(b.token.expose()), "{shown}");
        let v = b.to_kvp().unwrap();
        assert!(v.len() <= KVP_VALUE_MAX);
        assert_eq!(serde_json::from_str::<Bootstrap>(&v).unwrap(), b);
        for bad in ["", "d", "DK", "dk;reboot", "dk us", "abcdefghi"] {
            assert!(new(bad).is_err(), "{bad:?}");
        }
        let long = Bootstrap { vnc_password: "x".repeat(KVP_VALUE_MAX).into(), ..b };
        assert!(long.to_kvp().is_err());
    }

    #[test]
    fn windows_layout_ids_map_to_xkb_names() {
        assert_eq!(xkb_layout("00000406"), Some("dk"));
        assert_eq!(link_verb("sluse:open"), Some("open"));
        assert_eq!(link_verb("SLUSE:close/"), Some("close"));
        assert_eq!(link_verb("sluse:artifacts"), Some("artifacts"));
        for not in ["sluse:wipe", "sluse:open?x=1", "sluse:", "slus", "https://sluse:open", "sluse://open/../close"] {
            assert_eq!(link_verb(not), None, "{not}");
        }
        assert_eq!(xkb_layout("0000040C"), Some("fr"));
        assert_eq!(xkb_layout("00020409"), Some("us"), "US International falls back to its language");
        assert_eq!(xkb_layout("0000ffff"), None);
        assert_eq!(xkb_layout("junk"), None);
        // Every name the table can produce passes the box's own check.
        for klid in ["00000406", "0000080a", "00000809"] {
            assert!(valid_layout(xkb_layout(klid).unwrap()));
        }
    }

    #[test]
    fn only_a_screen_on_the_host_only_segment_is_accepted() {
        for ok in ["ws://192.168.77.10:7583", "ws://192.168.77.254:1"] {
            assert!(vnc_on_segment(ok).is_ok(), "{ok}");
        }
        for bad in [
            "ws://192.168.77.10",
            "wss://192.168.77.10:7583",
            "ws://192.168.77.10.evil.example:7583",
            "ws://192.168.77.0:7583",
            "ws://192.168.77.255:7583",
            "ws://192.168.77.010:7583",
            "ws://192.168.78.10:7583",
            "ws://192.168.77.10:7583/../x",
            "ws://evil.example:7583",
        ] {
            assert!(vnc_on_segment(bad).is_err(), "{bad}");
        }
    }
}

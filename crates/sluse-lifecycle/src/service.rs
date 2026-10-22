// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The lifecycle service (D-024, D-025, D-027): SYSTEM, one pipe, and one box
//! running at a time.
//!
//! The shell asks over the pipe; the service answers for the Windows user on
//! the other end, whom it learns from the pipe itself (`winsys::client_identity`).
//! Opening a box means:
//! 1. start the VM;
//! 2. start the egress proxy and the broker as children, in a job that dies
//!    with the service (M9, D-035: the proxy is the box's only way out);
//! 3. hand the box a fresh bootstrap over KVP, with its VNC secret;
//! 4. wait for the box's VNC port;
//! 5. give the shell the address and the secret.
//!
//! The broker runs its own preflight gate at start and refuses to serve if
//! it fails, so the gate is step 2's, not a second copy here.
//!
//! Blocking, one thread per connection. An open holds the lock for its whole
//! length, which is what serialises two opens.

use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Child;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sluse_proto::pipe::{
    Phase,
    valid_layout, BoxState, Bootstrap, PipeEvent, PipeFailure, PipeRequest, PlannedStep, Theme, KVP_KEY, THEME_KEY,
    VNC_PORT,
};
use sluse_proto::pipe::HostSignIn;
use sluse_proto::wire::ENROL_PORT;
use sluse_proto::{ContentHash, SourceKind};

use crate::boxes;
use crate::hyperv::HyperV;

/// How long a started box has to open its VNC port. S-8 measured 7 to 11 s
/// to ssh from a prepared base; the kiosk comes a little after. On L1, a
/// nested box's first boot took longer than 180 s (2026-09-30).
/// ponytail: one figure for every boot; measure first and later boots from
/// the serial log (D-030) and split it if they differ.
const BOX_TIMEOUT: Duration = Duration::from_secs(600);

/// A request line longer than this is not a request.
const MAX_REQUEST: usize = 4096;

// The box's shape (slice 3). One box runs at a time (D-027 design point 3),
// so every box can have the same address.
const SWITCH: &str = "Sluse boxes";
const BOX_ADDRESS: Ipv4Addr = Ipv4Addr::new(192, 168, 77, 10);
const GATEWAY: &str = "192.168.77.1";
const PREFIX: &str = "192.168.77.0/24";
const BASE_GB: u32 = 64;
/// The build VM's memory. A box's own size is the config's (D-038 point 7).
const MEMORY_GB: u32 = 4;
const BUILD_VM: &str = "sluse-build";
/// S-8 measured about two minutes to ssh with one runtime; this installs a
/// desktop, a browser and three runtimes.
const BUILD_TIMEOUT: Duration = Duration::from_secs(60 * 60);
/// A failed background build is tried this many times in all, this far apart:
/// one retry, then the next start or open (D-063).
const BUILD_TRIES: u32 = 2;
const BUILD_RETRY: Duration = Duration::from_secs(15 * 60);
/// How long Close waits for a clean shutdown before it turns the box off:
/// 90 s (jok, 2026-10-01: "I would say 60 s, so let's go with 90 s"). Not yet
/// measured: on L1 a clean Close took a while and was not timed. Turning off
/// is a power cut to the box; its disks are journaled filesystems.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(90);
/// The first-time steps' limits (Q21): past one, the step stops and says
/// why. **Stand-ins**, the mock-ups' numbers, until an L1 run measures the
/// steps; not measurements (`docs/sluse_prototype.md`, Limits).
const DOWNLOAD_LIMIT: Duration = Duration::from_secs(45 * 60);
const CONVERT_LIMIT: Duration = Duration::from_secs(20 * 60);
const MAKE_LIMIT: Duration = Duration::from_secs(10 * 60);
const START_LIMIT: Duration = Duration::from_secs(5 * 60);
/// How long the shell waits for the box's console once its screen is up
/// before it says the console did not start (Q9). A **stand-in** too.
const CONSOLE_LIMIT: Duration = Duration::from_secs(5 * 60);
/// A sign-in caught longer ago than this is not handed to the broker at the
/// open (Q22): Microsoft documents about ten minutes for an authorization
/// code, and this is half of it, not a measurement. The shell signs in again
/// silently once the box is up.
const CODE_FRESH: Duration = Duration::from_secs(5 * 60);

/// A phase's limit, where it has one: the service's own (install, the
/// screen, close) and the first-time steps' stand-ins.
fn limit(phase: Phase) -> Option<Duration> {
    match phase {
        Phase::Download => Some(DOWNLOAD_LIMIT),
        Phase::Convert => Some(CONVERT_LIMIT),
        Phase::Install => Some(BUILD_TIMEOUT),
        Phase::Make => Some(MAKE_LIMIT),
        Phase::Start => Some(START_LIMIT),
        Phase::Wait => Some(BOX_TIMEOUT),
        Phase::Close => Some(CLOSE_TIMEOUT),
        Phase::Console => Some(CONSOLE_LIMIT),
        _ => None,
    }
}

/// A phase's name as the ledger shows it (Q19), the plan and the step alike.
/// A reset's make is [`REMAKE`].
fn name(phase: Phase) -> &'static str {
    match phase {
        Phase::Check => "Checking this computer",
        Phase::Download => "Downloading your box's system",
        Phase::Convert => "Preparing your box's disk",
        Phase::Install => "Installing your box's system",
        Phase::Make => "Making your box",
        Phase::Start => "Starting your box",
        Phase::Broker => "Connecting Sluse to your files",
        Phase::Wait => "Waiting for your box's screen",
        Phase::Reset => "Resetting the box's system",
        Phase::Wipe => "Wiping the box",
        Phase::Close => "Closing your box",
        Phase::SignIn => "Signing you in to Microsoft",
        Phase::Console => "Waiting for your box's console",
        Phase::Other => "Opening your box",
    }
}
const REMAKE: &str = "Making the box again";

/// How long a box a failed open started gets to shut down before it is
/// turned off. Short: nothing in it is the user's work yet, and the user is
/// waiting on the failure.
const FAILED_OPEN_STOP: Duration = Duration::from_secs(10);
const USER_DATA: &str = include_str!("../../../packaging/box/user-data.yaml");

/// `images\base.json`: which base is current, and which bundle it was built
/// from.
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BaseRecord {
    name: String,
    bundle: String,
    built: chrono::DateTime<chrono::Utc>,
}

fn sha256_file(p: &std::path::Path) -> Result<String, String> {
    use sha2::Digest;
    let mut f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut h = sha2::Sha256::new();
    std::io::copy(&mut f, &mut h).map_err(|e| e.to_string())?;
    Ok(h.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// `{"7580": "broker", ...}`, so the Hyper-V script names the part in what
/// it says about a port (D-029 point 5).
fn host_port_parts() -> serde_json::Value {
    sluse_proto::ports::ON_HOST
        .iter()
        .map(|p| (p.to_string(), serde_json::Value::from(sluse_proto::ports::part(*p))))
        .collect::<serde_json::Map<_, _>>()
        .into()
}

/// Whether the config has a source of a kind: the user's Sluse Inputs or
/// OneDrive folder (D-054), which the shell offers.
fn has_kind(loaded: &sluse_proto::Loaded, kind: impl Fn(&SourceKind) -> bool) -> bool {
    loaded.config.sources.iter().any(|s| kind(&s.kind))
}

/// A user's VM, named from their SID without showing it.
fn box_vm_name(sid: &str) -> String {
    let h = sluse_proto::ContentHash::of(sid.as_bytes());
    format!("sluse-{}", &h.as_str()[..10])
}

/// The box's fixed address, written by cloud-init into netplan, where it
/// stays once cloud-init is disabled. No route and no DNS (M9, D-035): the
/// segment is all the box can reach, and the proxy on the host resolves names.
fn network_config() -> String {
    format!(
        "version: 2\nethernets:\n  nic:\n    match: {{driver: hv_netvsc}}\n    addresses: [{BOX_ADDRESS}/24]\n"
    )
}

/// How long the proxy has to listen, and to write its counts when stopped.
const PROXY_WAIT: Duration = Duration::from_secs(10);

/// The egress proxy, a child of the service (M9, D-035). Dropped, it is asked
/// to stop by closing its stdin, so it can write its counts; then killed.
pub(crate) struct ProxyChild(Child);

impl Drop for ProxyChild {
    fn drop(&mut self) {
        drop(self.0.stdin.take());
        let deadline = Instant::now() + PROXY_WAIT;
        while matches!(self.0.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct Service {
    pub root: PathBuf,
    hyperv: HyperV,
    running: Mutex<Option<Running>>,
    /// Held while the base is built, once per device (slice 3).
    building: Mutex<()>,
    /// What the build is doing now, for an open that is waiting on it.
    build_step: Mutex<Option<PipeEvent>>,
    /// How long each phase took last time on this device, in seconds, kept in
    /// `phases.json` beside the boxes (D-034 point 1: "last time on this
    /// device", never a constant).
    phase_times: Mutex<HashMap<Phase, u64>>,
    /// Why the last base build failed, until one succeeds. Shown at open.
    build_failed: Mutex<Option<String>>,
    /// Builds failed in a row since the last that succeeded: the shell asks
    /// for IT from the second (D-063).
    build_failures: std::sync::atomic::AtomicU32,
    /// Boxes a reset or wipe is running on now. A second one for the same box
    /// is refused rather than queued behind the first (two resets 19 s apart
    /// on L1, 2026-09-30).
    resetting: Mutex<std::collections::HashSet<String>>,
    /// The host's side of the segment is in place (slice 5): once per
    /// service start, retried at an open until it succeeds.
    device_ready: Mutex<bool>,
    /// The VMs whose serial console is being copied to the host (D-030).
    consoles: Arc<Mutex<HashSet<String>>>,
    /// Per VM this service started from off: when its console answered
    /// (Q9), `None` until it has. A VM not here was not started by this
    /// service, so its console was shown before, or before this service.
    console_up: Arc<Mutex<HashMap<String, Option<Instant>>>>,
    /// VMs whose console showed a login prompt since this service started
    /// them: a system without Sluse, whose screen never comes (D-066).
    no_sluse: Arc<Mutex<HashSet<String>>>,
    /// Who quit the shell during their open (Q26, Q75): that open leaves the
    /// box closed. Cleared when the next open begins.
    quit: Mutex<std::collections::HashSet<String>>,
    #[cfg(windows)]
    job: crate::winsys::KillOnClose,
}

struct Running {
    sid: String,
    vm: String,
    /// Its stdin is the control channel (D-036): sign-ins from the host.
    broker: Child,
    /// The config the broker was started with, to ask it for its status.
    loaded: sluse_proto::Loaded,
    /// The last sign-in handed over, so its answer is known by its number.
    sign_ins: u64,
    /// The broker held a sign-in during this open. Only the person's
    /// sign-out in the box takes it away (D-022), so a bound box that is not
    /// signed in was signed out in, which holds until the next open (Q7).
    bound: bool,
    /// When this open booted the box and said Ready, until the console's
    /// time is kept (Q9).
    shown: Option<Instant>,
    /// Dropped with the rest, which stops it.
    proxy: ProxyChild,
    vnc: String,
    password: sluse_proto::pipe::Secret,
}

/// Who is asking, as the pipe's own token says: never the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub sid: String,
    /// Administrators enabled in the token, which means elevated.
    pub admin: bool,
    /// The logon session the caller is in, where the service takes the token
    /// the broker writes Sluse Artifacts with (D-031).
    pub session: u32,
}

/// What an open was asked with.
struct Open<'a> {
    keyboard: &'a str,
    timezone: Option<String>,
    sign_in: Option<HostSignIn>,
    theme: Option<Theme>,
    /// When the request came, which is about when its sign-in was caught.
    received: Instant,
    /// The shell's window has gone: a step could not be sent to it. An
    /// open whose window quit leaves the box closed (Q26, Q75).
    gone: &'a std::cell::Cell<bool>,
}

fn failed(code: PipeFailure, message: impl Into<String>) -> PipeEvent {
    PipeEvent::Failed { code, message: message.into() }
}

/// One line in the service's log: stderr, which is `logs\service.log`
/// under the SCM (`winsys::stderr_to_file_if_none`).
/// ponytail: unbounded; a few lines per start and per failure. Cap it if a
/// device ever logs more.
pub(crate) fn note(msg: impl std::fmt::Display) {
    eprintln!("{} sluse service: {msg}", chrono::Utc::now().format("%FT%TZ"));
}

/// Where the phases' last durations are kept, under the data directory.
const PHASES_FILE: &str = "phases.json";

/// The phases of one wait, timed (D-034 points 1 and 3). Each `next` ends the
/// phase before it, which therefore finished, and records how long it took;
/// `done` ends the last. A wait that fails records nothing for the phase it
/// failed in, so a failure never becomes "last time".
#[derive(Default)]
struct Steps {
    current: Option<(Phase, Instant)>,
}

impl Steps {
    fn next(&mut self, svc: &Service, send: &mut dyn FnMut(PipeEvent), phase: Phase, step: impl Into<String>) {
        self.done(svc);
        self.current = Some((phase, Instant::now()));
        send(svc.progress(phase, step.into(), None));
    }

    /// What is left of the current step's limit (Q21), for a call that can be
    /// stopped; `None` for a step with no limit.
    fn left(&self) -> Option<Duration> {
        let (phase, since) = self.current?;
        limit(phase).map(|l| l.saturating_sub(since.elapsed()))
    }

    /// A step's failure, said as its limit where it ran past it (Q21).
    fn why(&self, e: String) -> String {
        match self.current {
            Some((phase, since)) if limit(phase).is_some_and(|l| since.elapsed() >= l) => format!(
                "{} took longer than its limit of {} minutes: {e}",
                name(phase),
                limit(phase).unwrap_or_default().as_secs().div_ceil(60)
            ),
            _ => e,
        }
    }

    fn done(&mut self, svc: &Service) {
        if let Some((phase, since)) = self.current.take() {
            svc.record_phase(phase, since.elapsed());
        }
    }
}

impl Service {
    /// A progress event for `phase`, with this device's last duration of it
    /// and the service's own limit, where there is one.
    fn progress(&self, phase: Phase, step: String, pct: Option<u8>) -> PipeEvent {
        let last_s = self.last_time(phase);
        PipeEvent::Progress { step, phase: Some(phase), pct, last_s, limit_s: limit(phase).map(|l| l.as_secs()), plan: vec![] }
    }

    fn last_time(&self, phase: Phase) -> Option<u64> {
        self.phase_times.lock().unwrap_or_else(|p| p.into_inner()).get(&phase).copied()
    }

    fn record_phase(&self, phase: Phase, took: Duration) {
        let mut times = self.phase_times.lock().unwrap_or_else(|p| p.into_inner());
        times.insert(phase, took.as_secs());
        // ponytail: rewritten whole at every phase; a dozen small entries.
        if let Ok(bytes) = serde_json::to_vec_pretty(&*times) {
            let _ = std::fs::write(self.root.join(PHASES_FILE), bytes);
        }
    }

    pub fn new(root: PathBuf, hyperv: HyperV) -> io::Result<Self> {
        let phase_times = std::fs::read(root.join(PHASES_FILE)).ok().and_then(|b| serde_json::from_slice(&b).ok());
        Ok(Service {
            root,
            hyperv,
            running: Mutex::new(None),
            building: Mutex::new(()),
            build_step: Mutex::new(None),
            phase_times: Mutex::new(phase_times.unwrap_or_default()),
            build_failed: Mutex::new(None),
            build_failures: Default::default(),
            resetting: Mutex::default(),
            device_ready: Mutex::new(false),
            consoles: Arc::default(),
            console_up: Arc::default(),
            no_sluse: Arc::default(),
            quit: Mutex::default(),
            #[cfg(windows)]
            job: crate::winsys::KillOnClose::new()?,
        })
    }

    /// One connection: read a request, learn who asked, answer.
    ///
    /// `who` is called after the request is read, because Windows lets a
    /// pipe server impersonate its client only then.
    pub fn handle<C: Read + Write>(&self, conn: &mut C, who: impl FnOnce(&C) -> io::Result<Caller>) {
        let answer = match read_line(conn) {
            Err(e) => failed(PipeFailure::BadRequest, e.to_string()),
            Ok(line) => match (serde_json::from_str::<PipeRequest>(&line), who(conn)) {
                (_, Err(e)) => failed(PipeFailure::BadRequest, format!("who is asking: {e}")),
                (Err(e), _) => failed(PipeFailure::BadRequest, e.to_string()),
                (Ok(req), Ok(caller)) => {
                    // The steps this request expects, with its first progress
                    // (Q19).
                    let mut plan = Some(self.plan(&caller.sid, &req));
                    // A write that fails is a window that has gone (Q26).
                    let gone = std::cell::Cell::new(false);
                    let mut send = |mut e: PipeEvent| {
                        if let (PipeEvent::Progress { plan: p, .. }, Some(planned)) = (&mut e, plan.take()) {
                            *p = planned;
                        }
                        if send_line(conn, &e).is_err() {
                            gone.set(true);
                        }
                    };
                    self.answer(&caller, req, &mut send, &gone)
                }
            },
        };
        let _ = send_line(conn, &answer);
    }

    /// The steps a request expects to take, in order (Q19), from what is on
    /// the device now: a box to make, a base to build or one being built. A
    /// request that turns out otherwise, a build begun in between say, sends
    /// steps the plan did not name, and the shell shows them as they come.
    fn plan(&self, sid: &str, req: &PipeRequest) -> Vec<PlannedStep> {
        let step = |phase: Phase| PlannedStep { phase, step: name(phase).to_owned() };
        let remake = PlannedStep { phase: Phase::Make, step: REMAKE.to_owned() };
        match req {
            PipeRequest::Open { .. } => {
                let running = self.running.try_lock().ok().is_some_and(|r| r.as_ref().is_some_and(|r| r.sid == sid));
                let mut plan = match boxes::load(&self.root, sid) {
                    // Already open: no steps, the same screen at once.
                    Ok(Some(_)) if running => return vec![],
                    // A box that exists waits only for a build under way.
                    Ok(Some(_)) => self.base_plan(true),
                    _ => [self.base_plan(false), vec![step(Phase::Make)]].concat(),
                };
                plan.extend([Phase::Check, Phase::Start, Phase::Broker, Phase::Wait].map(step));
                plan
            }
            PipeRequest::Reset { .. } => [vec![step(Phase::Reset)], self.base_plan(false), vec![remake]].concat(),
            PipeRequest::Wipe { .. } => [vec![step(Phase::Wipe)], self.base_plan(false), vec![remake]].concat(),
            PipeRequest::Close => vec![step(Phase::Close)],
            _ => vec![],
        }
    }

    /// The base's phases still to come: those of a build under way from where
    /// it is, or all three when the device's base is not current, unless
    /// `running_only`.
    fn base_plan(&self, running_only: bool) -> Vec<PlannedStep> {
        let build = [Phase::Download, Phase::Convert, Phase::Install];
        let from = if matches!(self.building.try_lock(), Err(std::sync::TryLockError::WouldBlock)) {
            match self.build_step.lock().unwrap_or_else(|p| p.into_inner()).as_ref() {
                Some(PipeEvent::Progress { phase: Some(p), .. }) => build.iter().position(|b| b == p).unwrap_or(0),
                _ => 0,
            }
        } else if running_only || self.bundle().is_ok_and(|(_, hash)| self.current_base().is_some_and(|b| b.bundle == hash)) {
            return vec![];
        } else {
            0
        };
        build[from..].iter().map(|&phase| PlannedStep { phase, step: name(phase).to_owned() }).collect()
    }

    fn answer(&self, caller: &Caller, req: PipeRequest, send: &mut dyn FnMut(PipeEvent), gone: &std::cell::Cell<bool>) -> PipeEvent {
        let received = Instant::now();
        // Reset and wipe may name another user's box, and only an elevated
        // administrator may (D-026 point 3). Everything else is the caller's.
        let (target, wipe) = match &req {
            PipeRequest::Reset { sid } => (sid.clone(), Some(false)),
            PipeRequest::Wipe { sid } => (sid.clone(), Some(true)),
            _ => (None, None),
        };
        if let Some(wipe) = wipe {
            let target = target.unwrap_or_else(|| caller.sid.clone());
            if target != caller.sid && !caller.admin {
                return failed(PipeFailure::NotAllowed, "Only an administrator can reset or wipe another user's box.");
            }
            if !boxes::valid_sid(&target) {
                return failed(PipeFailure::BadRequest, format!("not a SID: {target:?}"));
            }
            return self.reset(caller, &target, wipe, send);
        }
        let sid = caller.sid.as_str();
        match req {
            PipeRequest::SignIn { sign_in } => return self.sign_in_again(sid, sign_in),
            PipeRequest::SignOut => return self.sign_out(sid),
            PipeRequest::Theme { theme } => return self.theme(sid, theme),
            PipeRequest::Console => return self.console(sid),
            PipeRequest::Quit => {
                self.quit.lock().unwrap_or_else(|p| p.into_inner()).insert(sid.to_owned());
                return PipeEvent::Done;
            }
            _ => {}
        }
        let rec = match boxes::load(&self.root, sid) {
            Ok(Some(r)) => r,
            Ok(None) if req == PipeRequest::Status => {
                return PipeEvent::State {
                    state: BoxState::None,
                    sign_in: self.sign_in_view().map(Box::new),
                    signed_in: None,
                    signed_out: false,
                    user: None,
                    vm: None,
                    dir: None,
                };
            }
            Ok(None) if req == PipeRequest::Close => return PipeEvent::Closed,
            // A user's first open makes their box, and the device's base
            // first if it has none (slice 3).
            Ok(None) => match self.make_box(sid, send) {
                Ok(r) => r,
                Err(e) => return e,
            },
            Err(e) => return failed(PipeFailure::Box, format!("the box record: {e}")),
        };
        match req {
            PipeRequest::Status => match self.hyperv.state(&rec.vm) {
                Ok(state) => {
                    let (signed_in, signed_out, user) = self.sign_in_state(sid);
                    PipeEvent::State {
                        state,
                        sign_in: self.sign_in_view().map(Box::new),
                        signed_in,
                        signed_out,
                        user,
                        vm: Some(rec.vm.clone()),
                        dir: Some(self.root.join("boxes").join(sid).display().to_string()),
                    }
                }
                Err(e) => failed(PipeFailure::Box, e),
            },
            PipeRequest::Open { keyboard, timezone, sign_in, theme } => {
                let open = Open { keyboard: &keyboard, timezone, sign_in, theme, received, gone };
                self.open(caller, &rec, open, send)
            }
            PipeRequest::Close => self.close(sid, &rec, send),
            PipeRequest::Reset { .. }
            | PipeRequest::Wipe { .. }
            | PipeRequest::SignIn { .. }
            | PipeRequest::SignOut
            | PipeRequest::Theme { .. }
            | PipeRequest::Console
            | PipeRequest::Quit => {
                unreachable!("answered above")
            }
        }
    }

    /// Where the shell signs in, from the tenant's file: `None` when it has no
    /// `entra` block, or when there is no readable file yet.
    fn sign_in_view(&self) -> Option<sluse_proto::SignInView> {
        let bytes = std::fs::read(self.root.join("sluse.json")).ok()?;
        let authored = sluse_proto::config::load_authored(&bytes).ok()?;
        authored.entra.as_ref().map(sluse_proto::SignInView::for_entra)
    }

    /// Whether the caller's running broker holds a sign-in, `None` when no
    /// broker runs for them; and whether they signed out in the box since it
    /// was signed in (Q7); and who it is signed in as.
    fn sign_in_state(&self, sid: &str) -> (Option<bool>, bool, Option<String>) {
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = running.as_mut().filter(|r| r.sid == sid) else { return (None, false, None) };
        let user = crate::probe(&r.loaded).ok().map(|s| s.signed_in.map(|u| u.name));
        let signed_in = user.as_ref().map(Option::is_some);
        // A hand-over the service stopped waiting for may still have bound.
        r.bound |= signed_in == Some(true);
        (signed_in, r.bound && signed_in == Some(false), user.flatten())
    }

    /// [`PipeRequest::SignIn`]: the caller's own running box only, and not
    /// after a sign-out in it, which holds until the next open (Q7).
    fn sign_in_again(&self, sid: &str, sign_in: HostSignIn) -> PipeEvent {
        if self.sign_in_state(sid).1 {
            return failed(PipeFailure::SignedOut, "You signed out in your box. To sign in, close the box and open Sluse again.");
        }
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = running.as_mut().filter(|r| r.sid == sid) else {
            return failed(PipeFailure::NoBox, "Your box is not open.");
        };
        r.sign_ins += 1;
        match hand_sign_in(&mut r.broker, &r.loaded, r.sign_ins, sign_in) {
            Ok(user) => {
                r.bound = true;
                self.name_box(sid, &user);
                PipeEvent::SignedIn { user }
            }
            Err(e) => failed(PipeFailure::SignIn, e),
        }
    }

    /// [`PipeRequest::SignOut`]: the caller's own running box (D-064), over
    /// the broker's own route, with the device's leaf (D-058 point 4). The
    /// box then counts as signed out until the next open, as one signed out
    /// from its console did (Q7).
    fn sign_out(&self, sid: &str) -> PipeEvent {
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = running.as_mut().filter(|r| r.sid == sid) else {
            return failed(PipeFailure::NoBox, "Your box is not open.");
        };
        let out = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string()).and_then(|rt| {
            rt.block_on(async {
                let (client, _) = sluse_endpoint::broker_client::BrokerClient::connect(&r.loaded).await?;
                client.sign_out().await
            })
            .map_err(|e| e.to_string())
        });
        match out {
            Ok(_) => {
                r.bound = true;
                PipeEvent::Done
            }
            Err(e) => failed(PipeFailure::Broker, format!("signing out: {e}")),
        }
    }

    /// [`PipeRequest::Theme`]: into the caller's running box at once (Q70).
    /// Busy during an open, which carries the theme it was given; the shell
    /// sends a change made meanwhile once the box is up.
    fn theme(&self, sid: &str, theme: Theme) -> PipeEvent {
        let running = match self.running_or_busy() {
            Ok(g) => g,
            Err(e) => return e,
        };
        let Some(r) = running.as_ref().filter(|r| r.sid == sid) else {
            return failed(PipeFailure::NoBox, "Your box is not open.");
        };
        match self.hyperv.kvp(&r.vm, &[(THEME_KEY, theme.as_str())]) {
            Ok(()) => PipeEvent::Done,
            Err(e) => failed(PipeFailure::Box, format!("the theme: {e}")),
        }
    }

    /// [`PipeRequest::Console`] (Q9): whether the caller's box's console has
    /// answered, from what the box said on its serial console. Its time is
    /// kept, once, from Ready to the answer, as the console's "last time".
    fn console(&self, sid: &str) -> PipeEvent {
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        let Some(r) = running.as_mut().filter(|r| r.sid == sid) else {
            return failed(PipeFailure::NoBox, "Your box is not open.");
        };
        let last_s = self.last_time(Phase::Console);
        let answered = match self.console_up.lock().unwrap_or_else(|p| p.into_inner()).get(&r.vm) {
            Some(None) => false,
            Some(Some(at)) => {
                if let Some(shown) = r.shown.take() {
                    self.record_phase(Phase::Console, at.saturating_duration_since(shown));
                }
                true
            }
            None => true,
        };
        PipeEvent::Console { answered, last_s, limit_s: CONSOLE_LIMIT.as_secs() }
    }

    fn open(&self, caller: &Caller, rec: &boxes::BoxRecord, open: Open<'_>, send: &mut dyn FnMut(PipeEvent)) -> PipeEvent {
        let Open { keyboard, timezone, sign_in, theme, received, gone } = open;
        let sid = caller.sid.as_str();
        if !valid_layout(keyboard) {
            return failed(PipeFailure::BadRequest, format!("{keyboard:?} is not a keyboard layout"));
        }
        // The window has gone, or the person quit it (Q26, Q75).
        self.quit.lock().unwrap_or_else(|p| p.into_inner()).remove(sid);
        let gone = || gone.get() || self.quit.lock().unwrap_or_else(|p| p.into_inner()).contains(sid);
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(r) = running.as_mut() {
            if r.sid != sid {
                return failed(PipeFailure::Busy, "Another user's box is open on this computer.");
            }
            // Already open: the same address and secret, if both halves are
            // still up. Otherwise start over.
            if matches!(r.broker.try_wait(), Ok(None))
                && matches!(r.proxy.0.try_wait(), Ok(None))
                && self.hyperv.state(&r.vm) == Ok(BoxState::Running)
            {
                // The theme in use now, which may have changed meanwhile (Q70).
                if let Some(t) = theme {
                    if let Err(e) = self.hyperv.kvp(&r.vm, &[(THEME_KEY, t.as_str())]) {
                        self.log_device("theme", &format!("at a reopen: {e}"));
                    }
                }
                // A box running unsigned takes this open's sign-in; one the
                // person signed out in keeps that until it is closed (Q7),
                // and the shell sends none for it.
                if let Some(s) = sign_in.filter(|_| !r.bound) {
                    r.sign_ins += 1;
                    match hand_sign_in(&mut r.broker, &r.loaded, r.sign_ins, s) {
                        Ok(_) => r.bound = true,
                        Err(e) => self.log_device("sign-in", &format!("at a reopen: {e}")),
                    }
                }
                return PipeEvent::Ready {
                    vnc: r.vnc.clone(),
                    password: r.password.clone(),
                    update: self.update_for(rec),
                    problem: self.build_problem(),
                    copy_out: self.box_settings().copy_out,
                    config_changed: false,
                    config_changes: vec![],
                    inputs: has_kind(&r.loaded, |k| matches!(k, SourceKind::Inputs)),
                    onedrive: has_kind(&r.loaded, |k| matches!(k, SourceKind::Onedrive)),
                    shares: has_kind(&r.loaded, |k| matches!(k, SourceKind::Smb { .. })),
                };
            }
            let _ = r.broker.kill();
            let _ = r.broker.wait();
            *running = None;
        }

        let mut steps = Steps::default();
        steps.next(self, send, Phase::Check, name(Phase::Check));
        if let Err(e) = self.device_init() {
            return failed(PipeFailure::Preflight, e);
        }
        // A base being built holds the memory a box needs: wait for it, with
        // its steps shown, rather than start beside it.
        if self.building.try_lock().is_err() {
            let _ = self.ensure_base(send);
        }
        steps.next(self, send, Phase::Start, name(Phase::Start));
        // The window quit during the build: it finishes, and the box is left
        // closed rather than started for nobody (Q26).
        if gone() {
            self.log_device("open", "the window quit before the start; the box is left closed");
            return failed(PipeFailure::Box, "the window quit before the box started");
        }
        // Preflight's guest checks, asked of Hyper-V and handed to the broker,
        // whose gate decides on them (slice 5). Before the start: they read
        // the VM's settings and the other VMs' states, nothing that needs this
        // one running, and a refusal here leaves nothing to stop.
        let guest = match self.hyperv.call_within(serde_json::json!({ "verb": "guest-checks", "vm": rec.vm, "switch": SWITCH }), steps.left()) {
            Ok(v) => v.to_string(),
            Err(e) => return failed(PipeFailure::Preflight, steps.why(format!("the guest checks: {e}"))),
        };
        // An open that fails after the start stops the box it started, so a
        // failed open does not leave a VM on the segment that refuses the next
        // user's (review R-16). A box that was already running stays so.
        let was_off = self.hyperv.state(&rec.vm) == Ok(BoxState::Off);
        let undo = |e: PipeEvent| -> PipeEvent {
            if was_off {
                if let Err(stop) = self.hyperv.stop(&rec.vm, FAILED_OPEN_STOP) {
                    self.log_device("open", &format!("{} not stopped after a failed open: {stop}", rec.vm));
                }
            }
            e
        };
        self.size_box(sid, &rec.vm);
        // A box this open boots has a console still to answer (Q9).
        if was_off {
            self.console_up.lock().unwrap_or_else(|p| p.into_inner()).insert(rec.vm.clone(), None);
            self.no_sluse.lock().unwrap_or_else(|p| p.into_inner()).remove(&rec.vm);
        }
        if let Err(e) = self.hyperv.start(&rec.vm, steps.left()) {
            return undo(failed(PipeFailure::Box, steps.why(e)));
        }
        self.follow_console(sid, &rec.vm);

        steps.next(self, send, Phase::Broker, name(Phase::Broker));
        let config = self.root.join("sluse.json");
        let loaded = match sluse_proto::config::load(&config) {
            Ok(l) => l,
            Err(e) => return undo(failed(PipeFailure::Broker, format!("{}: {e}", config.display()))),
        };
        // A box opened under another config keeps what it admitted then
        // (invariant 4); the shell says so once, naming what changed (D-038
        // point 4, D-045 point 3).
        let config_changes = self.config_changes(sid, &std::fs::read(&config).unwrap_or_default(), &loaded.version);
        // This open's bootstrap first: the broker is started with its token's
        // hash, and the box gets the token itself.
        let boot = match enrol_url(&loaded.config.broker.listen)
            .and_then(|url| Bootstrap::new(keyboard, url, loaded.config.broker.cert_pin.clone()))
        {
            // A timezone that is not a name is dropped, not refused: the box
            // keeps its clock as it was rather than not opening.
            // The clipboard setting goes with it, for the CLI's header (Q64).
            Ok(b) => Bootstrap {
                timezone: timezone.filter(|t| sluse_proto::pipe::valid_timezone(t)),
                copy_out: self.box_settings().copy_out,
                ..b
            },
            Err(e) => return undo(failed(PipeFailure::BadRequest, e)),
        };
        // The box's way out, before the box asks for it.
        let proxy = match self.start_proxy(&loaded, Some(sid)) {
            Ok(p) => p,
            Err(e) => return undo(failed(PipeFailure::Broker, e)),
        };
        let mut broker = match self.start_broker(&loaded, &boot.token_hash(), caller, &guest) {
            Ok(b) => b,
            Err(e) => return undo(failed(PipeFailure::Broker, e)),
        };
        // The host's sign-in, before the box's screen (D-036, D-022). One that
        // fails does not stop the open: the box opens unbound, and the shell
        // signs in again, silently, whenever the box says it is not. One
        // caught before a long open, a first build say, is past redeeming by
        // now and is not handed over (Q22).
        let mut bound = false;
        if let Some(s) = sign_in {
            if received.elapsed() > CODE_FRESH {
                self.log_device("sign-in", &format!("at open: caught {} s ago, too old to redeem", received.elapsed().as_secs()));
            } else {
                match hand_sign_in(&mut broker, &loaded, 1, s) {
                    Ok(user) => {
                        bound = true;
                        self.name_box(sid, &user);
                    }
                    Err(e) => self.log_device("sign-in", &format!("at open: {e}")),
                }
            }
        }
        match self.hand_over(rec, &boot, theme, &mut steps, send) {
            // The window quit while the box started: it stops opening, and a
            // box this open started is stopped (Q75). One running from before
            // runs on, as the window said it would.
            Ok(_) if gone() => {
                let _ = broker.kill();
                let _ = broker.wait();
                self.log_device("open", "the window quit while the box started; it is left closed");
                undo(failed(PipeFailure::Box, "the window quit while the box started"))
            }
            Ok(vnc) => {
                steps.done(self);
                let inputs = has_kind(&loaded, |k| matches!(k, SourceKind::Inputs));
                let onedrive = has_kind(&loaded, |k| matches!(k, SourceKind::Onedrive));
                let shares = has_kind(&loaded, |k| matches!(k, SourceKind::Smb { .. }));
                *running = Some(Running {
                    sid: sid.to_owned(),
                    vm: rec.vm.clone(),
                    broker,
                    loaded,
                    sign_ins: 1,
                    bound,
                    shown: was_off.then(Instant::now),
                    proxy,
                    vnc: vnc.clone(),
                    password: boot.vnc_password.clone(),
                });
                PipeEvent::Ready {
                    vnc,
                    password: boot.vnc_password,
                    update: self.update_for(rec),
                    problem: self.build_problem(),
                    copy_out: self.box_settings().copy_out,
                    config_changed: !config_changes.is_empty(),
                    config_changes,
                    inputs,
                    onedrive,
                    shares,
                }
            }
            Err(e) => {
                // No broker without a box the service knows it is serving.
                let _ = broker.kill();
                let _ = broker.wait();
                undo(e)
            }
        }
    }

    /// Copy the box's serial console to `boxes\<sid>\console.log` while it
    /// runs (D-030), once per VM however often it is opened, and note when
    /// the box says its console answers (Q9).
    fn follow_console(&self, sid: &str, vm: &str) {
        if !self.consoles.lock().unwrap_or_else(|p| p.into_inner()).insert(vm.to_owned()) {
            return;
        }
        let (consoles, vm, dir) = (self.consoles.clone(), vm.to_owned(), self.root.join("boxes").join(sid));
        let (up, no_sluse) = (self.console_up.clone(), self.no_sluse.clone());
        std::thread::spawn(move || {
            let mut said = |s| match s {
                crate::console::Said::ConsoleUp => {
                    if let Some(at @ None) = up.lock().unwrap_or_else(|p| p.into_inner()).get_mut(&vm) {
                        *at = Some(Instant::now());
                    }
                }
                crate::console::Said::NoSluse => {
                    no_sluse.lock().unwrap_or_else(|p| p.into_inner()).insert(vm.clone());
                }
            };
            crate::console::follow(&crate::console::pipe_name(&vm), &dir, &mut said);
            consoles.lock().unwrap_or_else(|p| p.into_inner()).remove(&vm);
        });
    }

    /// The bootstrap into the box, with the theme in use (Q70), then wait for
    /// its screen.
    fn hand_over(
        &self,
        rec: &boxes::BoxRecord,
        boot: &Bootstrap,
        theme: Option<Theme>,
        steps: &mut Steps,
        send: &mut dyn FnMut(PipeEvent),
    ) -> Result<String, PipeEvent> {
        boot.to_kvp()
            .and_then(|v| {
                let theme = theme.map(|t| (THEME_KEY, t.as_str()));
                let items: Vec<(&str, &str)> = theme.into_iter().chain([(KVP_KEY, v.as_str())]).collect();
                self.hyperv.kvp(&rec.vm, &items)
            })
            .map_err(|e| failed(PipeFailure::Box, e))?;
        steps.next(self, send, Phase::Wait, name(Phase::Wait));
        // A login prompt on the console ends the wait at once: that system
        // has no Sluse and its screen never comes (D-066).
        let incomplete = || {
            self.no_sluse.lock().unwrap_or_else(|p| p.into_inner()).contains(&rec.vm).then(|| {
                "the box's system has no Sluse on it: its console shows a login prompt, which only a system Sluse was never installed on shows".to_owned()
            })
        };
        wait_for_port(rec.address, VNC_PORT, BOX_TIMEOUT, incomplete).map_err(|e| failed(PipeFailure::Box, e))?;
        Ok(format!("ws://{}:{VNC_PORT}", rec.address))
    }

    fn start_broker(
        &self,
        loaded: &sluse_proto::Loaded,
        token: &sluse_proto::ContentHash,
        caller: &Caller,
        guest_checks: &str,
    ) -> Result<Child, String> {
        let sid = caller.sid.as_str();
        let exe = crate::run::broker_binary().map_err(|e| e.to_string())?;
        let logs = self.root.join("logs");
        std::fs::create_dir_all(&logs).map_err(|e| format!("{}: {e}", logs.display()))?;
        let log = logs.join("broker.log");
        // The box's journal mirror sits beside its disks, not on them, so a
        // wipe keeps it (D-027 point 5).
        let mirror = self.box_dir(sid).join("journal").display().to_string();
        #[cfg_attr(not(windows), allow(unused_mut, clippy::useless_vec))]
        let mut env = vec![
            ("SLUSE_ENROL_TOKEN_SHA256", token.as_str().to_owned()),
            ("SLUSE_JOURNAL_MIRROR", mirror),
            ("SLUSE_GUEST_CHECKS", guest_checks.to_owned()),
        ];
        // The user's token, inherited by the broker, which writes Sluse
        // Artifacts as them (D-031). Ours closes when this returns.
        #[cfg(windows)]
        let user_token = {
            use std::os::windows::io::AsRawHandle;
            let t = crate::winsys::session_token(caller.session, sid)
                .map_err(|e| format!("Sluse Artifacts needs your own sign-in: {e}"))?;
            env.push(("SLUSE_USER_TOKEN", (t.as_raw_handle() as usize).to_string()));
            t
        };
        let env: Vec<(&str, &str)> = env.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let mut child =
            crate::spawn_broker(&exe, &loaded.file, &log, &env).map_err(|e| format!("{}: {e}", exe.display()))?;
        #[cfg(windows)]
        drop(user_token);
        #[cfg(windows)]
        if let Err(e) = self.job.assign(&child) {
            let _ = child.kill();
            return Err(format!("the broker's job: {e}"));
        }
        // Alive and listening, not `/v1/status`: its own gate has checked its
        // leaf against the pin, and a broker whose gate refuses exits. (Until
        // D-058 point 4 no client of ours passed an open's broker; L1,
        // 2026-10-20, every open stopped here.)
        let listen = loaded.config.broker.listen.clone();
        let alive = || match child.try_wait() {
            Ok(None) => None,
            Ok(Some(code)) => Some(format!("the broker exited before it began serving ({code}); its log says why")),
            Err(e) => Some(format!("the broker: {e}")),
        };
        if let Err(e) = wait_until_listening(&listen, Duration::from_secs(crate::START_TIMEOUT_SECONDS), alive) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("{e} (log: {})", log.display()));
        }
        Ok(child)
    }

    /// The egress proxy for this config (M9, D-035): the broker's binary in
    /// its `--proxy` mode, a process of its own, without the user's token.
    /// Every connection goes to `logs\egress.jsonl` when the config turns that
    /// log on (D-038), what it says to
    /// `logs\proxy.log`, its refusals to the Event Log. `opened_by` is the
    /// Windows account the box was opened for; none for a base build.
    fn start_proxy(&self, loaded: &sluse_proto::Loaded, opened_by: Option<&str>) -> Result<ProxyChild, String> {
        use std::process::{Command, Stdio};
        let exe = crate::run::broker_binary().map_err(|e| e.to_string())?;
        let logs = self.root.join("logs");
        std::fs::create_dir_all(&logs).map_err(|e| format!("{}: {e}", logs.display()))?;
        let append = |name: &str| {
            std::fs::OpenOptions::new().create(true).append(true).open(logs.join(name)).map_err(|e| format!("logs\\{name}: {e}"))
        };
        let mut cmd = Command::new(&exe);
        cmd.arg("--config").arg(&loaded.file).arg("--proxy");
        cmd.stdin(Stdio::piped()).stdout(Stdio::null()).stderr(append("proxy.log")?);
        // The per-connection log only when the config turns it on (D-038
        // point 7); refusals reach the Event Log either way.
        cmd.env_remove("SLUSE_EGRESS_LOG");
        if loaded.config.egress.as_ref().and_then(|e| e.log.as_ref()).is_some_and(|l| l.enabled) {
            cmd.env("SLUSE_EGRESS_LOG", logs.join("egress.jsonl"));
        }
        cmd.env_remove("SLUSE_OPENED_BY");
        if let Some(sid) = opened_by {
            cmd.env("SLUSE_OPENED_BY", sid);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const DETACHED_PROCESS: u32 = 0x0000_0008;
            const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
            cmd.creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
        }
        let mut child = ProxyChild(cmd.spawn().map_err(|e| format!("the egress proxy, {}: {e}", exe.display()))?);
        #[cfg(windows)]
        self.job.assign(&child.0).map_err(|e| format!("the egress proxy's job: {e}"))?;
        let host = loaded.config.broker.listen.rsplit_once(':').map_or(GATEWAY, |(h, _)| h);
        let addr: Ipv4Addr = host.parse().map_err(|_| format!("broker.listen {host:?} is not an IPv4 address"))?;
        if let Err(e) = wait_for_port(addr, sluse_proto::ports::PROXY, PROXY_WAIT, || None) {
            let exited = child.0.try_wait().ok().flatten();
            return Err(match exited {
                Some(status) => format!("the egress proxy stopped ({status}); see logs\\proxy.log"),
                None => e,
            });
        }
        Ok(child)
    }

    /// The device's own part of the install (slice 5), idempotent:
    /// - the host-only switch, the host's address on it, the broker's
    ///   firewall rule, and the Event Log source; and no NAT (M9, D-035);
    /// - this device's broker certificate and client CA, made here, and their
    ///   fingerprint written into this device's copy of the config
    ///   (jok, 2026-09-29: per device, so a stolen CA key is good for one).
    ///
    /// Hyper-V itself is the MSI's, with its reboot; before that reboot the
    /// answer is "restart the computer".
    pub fn device_init(&self) -> Result<(), String> {
        self.device_network()?;
        self.ensure_certs()
    }

    /// The host's side of the segment, and the Event Log source.
    pub fn device_network(&self) -> Result<(), String> {
        let mut ready = self.device_ready.lock().unwrap_or_else(|p| p.into_inner());
        if !*ready {
            let broker = crate::run::broker_binary().map_err(|e| e.to_string())?;
            let v = self.hyperv.call(serde_json::json!({
                "verb": "device-init", "switch": SWITCH, "hostAddress": GATEWAY, "prefix": PREFIX,
                "broker": broker.display().to_string(),
                "hostPorts": sluse_proto::ports::ON_HOST, "parts": host_port_parts(),
            }))?;
            if v["restart"] == true {
                return Err("Restart the computer to finish installing Sluse: Hyper-V needs it.".into());
            }
            *ready = true;
        }
        Ok(())
    }

    /// The Sluse log alone (D-023): part of `device_network`'s device init.
    pub fn event_log(&self) -> Result<(), String> {
        self.hyperv.call(serde_json::json!({ "verb": "event-log" })).map(drop)
    }

    /// Uninstall's part (slice 5): every box and the build VM, the switch,
    /// the NAT, the rule, the Event Log source, and the data directory with
    /// the boxes' disks and the host's copies of their journals. Uninstall
    /// leaves nothing (the acceptance, `docs/sluse_prototype.md`).
    pub fn device_remove(&self) -> Result<(), String> {
        self.hyperv
            .call(serde_json::json!({
                "verb": "device-remove", "switch": SWITCH, "prefix": PREFIX, "root": self.root.display().to_string(),
                "hostPorts": sluse_proto::ports::ON_HOST,
            }))
            .map(drop)
    }

    /// Make the device's certificates if it has none, and write the config's
    /// device half (D-038 point 2) beside the tenant's `sluse.json`: this
    /// device's box id, its leaf's pin, and the fixed plumbing. Written at
    /// every open, so an upgrade's plumbing reaches it; a change is logged
    /// with both of the half's versions. `config_version` is the authored
    /// file's and does not move.
    pub fn ensure_certs(&self) -> Result<(), String> {
        let config = self.root.join("sluse.json");
        if !config.is_file() {
            return Err(format!("{} is missing; the tenant package installs it", config.display()));
        }
        let dir = self.root.join("certs");
        let cert = dir.join(crate::devcert::BROKER_CERT_FILE);
        if !cert.is_file() {
            let certs = crate::devcert::generate(&[GATEWAY.to_owned()]).map_err(|e| e.to_string())?;
            crate::devcert::write(&dir, &certs).map_err(|e| e.to_string())?;
            self.log_device("device-certificates", &format!("made; pin {}", certs.pin.as_str()));
        }
        let pem = std::fs::read_to_string(&cert).map_err(|e| format!("{}: {e}", cert.display()))?;
        let pin = crate::run::pin_of_pem(&pem, &cert).map_err(|e| e.to_string())?;

        let half = sluse_proto::config::device_path(&config);
        let before = std::fs::read(&half).ok();
        let box_id = before
            .as_deref()
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
            .and_then(|v| v["boxId"].as_str().map(str::to_owned))
            .map_or_else(new_box_id, Ok)?;
        let after = device_half(&box_id, &pin);
        if before.as_deref() != Some(after.as_bytes()) {
            std::fs::write(&half, &after).map_err(|e| format!("{}: {e}", half.display()))?;
            self.log_device(
                "device-half",
                &format!(
                    "written for {box_id}; {} -> {}",
                    before.map_or("none".to_owned(), |b| ContentHash::of(&b).as_str().to_owned()),
                    ContentHash::of(after.as_bytes()).as_str()
                ),
            );
        }
        sluse_proto::config::load(&config).map(drop).map_err(|e| format!("{}: {e}", config.display()))
    }

    fn log_device(&self, what: &str, detail: &str) {
        let logs = self.root.join("logs");
        let _ = std::fs::create_dir_all(&logs);
        let line = serde_json::json!({ "ts": chrono::Utc::now(), "op": what, "detail": detail });
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(logs.join("actions.jsonl")) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// A new box for `sid`: a system disk on the base and a blank home disk
    /// (D-026, S-8 step 4), then its record.
    fn make_box(&self, sid: &str, send: &mut dyn FnMut(PipeEvent)) -> Result<boxes::BoxRecord, PipeEvent> {
        if !self.root.join("sluse.json").is_file() {
            // Not "no box": the shell tells that user to open Sluse again,
            // which cannot help here; only IT can (review R-39).
            return Err(failed(PipeFailure::Preflight, "This computer is not set up for Sluse yet: it has no Sluse configuration."));
        }
        let base = self.ensure_base(send).map_err(|e| failed(PipeFailure::Box, format!("preparing the box: {e}")))?;
        let mut steps = Steps::default();
        steps.next(self, send, Phase::Make, name(Phase::Make));
        let made = self.create_box(sid, &base, steps.left()).map_err(|e| failed(PipeFailure::Box, steps.why(e)))?;
        steps.done(self);
        Ok(made)
    }

    fn box_dir(&self, sid: &str) -> PathBuf {
        self.root.join("boxes").join(sid)
    }

    /// The VM, a system disk on `base`, and the home disk if there is none,
    /// stopped past `within` (Q21).
    fn create_box(&self, sid: &str, base: &std::path::Path, within: Option<Duration>) -> Result<boxes::BoxRecord, String> {
        let dir = self.box_dir(sid);
        std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let vm = box_vm_name(sid);
        let path = |f: &str| dir.join(f).display().to_string();
        self.hyperv.call_within(
            serde_json::json!({
                "verb": "create-box", "vm": vm, "base": base.display().to_string(),
                "system": path("system.vhdx"), "home": path("home.vhdx"),
                "homeGB": self.box_settings().home_gb, "memoryGB": self.box_settings().memory_gb, "switch": SWITCH,
                // Named in its Hyper-V notes by the Windows account until a
                // sign-in names the work account (Q67).
                "sid": sid,
            }),
            within,
        )?;
        let base_name = base.file_name().map(|n| n.to_string_lossy().into_owned());
        let rec = boxes::BoxRecord { vm, address: BOX_ADDRESS, base: base_name, named: None };
        boxes::save(&self.root, sid, &rec).map_err(|e| e.to_string())?;
        Ok(rec)
    }

    /// The box's Hyper-V notes name the person it reads as (Q67): the work
    /// account, once a sign-in says who that is. Once per box and account;
    /// a failure is logged and the notes keep the Windows account.
    fn name_box(&self, sid: &str, user: &str) {
        let Ok(Some(mut rec)) = boxes::load(&self.root, sid) else { return };
        if user.is_empty() || rec.named.as_deref() == Some(user) {
            return;
        }
        match self.hyperv.call(serde_json::json!({ "verb": "box-notes", "vm": rec.vm, "who": user })) {
            Ok(_) => {
                rec.named = Some(user.to_owned());
                let _ = boxes::save(&self.root, sid, &rec);
            }
            Err(e) => self.log_device("box-notes", &e),
        }
    }

    /// Which parts of the config changed since this box last opened, and
    /// remember them. A box's first open is not a change.
    fn config_changes(&self, sid: &str, authored: &[u8], version: &ContentHash) -> Vec<String> {
        let file = self.box_dir(sid).join("config-version");
        let now = config_parts(authored, version);
        let before = std::fs::read_to_string(&file).ok();
        let _ = std::fs::write(&file, serde_json::to_vec(&now).unwrap_or_default());
        changed_parts(before.as_deref(), &now)
    }

    /// The tenant's box settings, or the defaults when its file cannot be
    /// read; the open fails at its own config check in that case anyway.
    fn box_settings(&self) -> sluse_proto::BoxSettings {
        std::fs::read(self.root.join("sluse.json"))
            .ok()
            .and_then(|b| sluse_proto::config::load_authored(&b).ok())
            .map(|a| a.box_settings)
            .unwrap_or_default()
    }

    /// The box's memory and home disk as the config sets them, before it
    /// starts (D-038 point 7). Logged when it changes anything; a failure
    /// is logged and the box starts as it was, since its size is a setting
    /// and not a reason to refuse the open.
    fn size_box(&self, sid: &str, vm: &str) {
        let b = self.box_settings();
        let home = self.box_dir(sid).join("home.vhdx").display().to_string();
        match self.hyperv.call(serde_json::json!({
            "verb": "size-box", "vm": vm, "home": home, "homeGB": b.home_gb, "memoryGB": b.memory_gb,
        })) {
            Ok(v) => {
                for c in v["changed"].as_array().into_iter().flatten().filter_map(|c| c.as_str()) {
                    self.log_device("box-size", &format!("{vm}: {c}"));
                }
                // Warned, not refused (D-038): a box over half the device's
                // memory leaves Windows little. ponytail: in the log only;
                // into posture when the broker is told the box's size.
                if let Some(host) = v["hostGB"].as_u64().filter(|h| u64::from(b.memory_gb) * 2 > *h) {
                    self.log_device("box-size", &format!("{vm}: warning: the box takes {} of this device's {host} GB", b.memory_gb));
                }
            }
            Err(e) => self.log_device("box-size", &format!("{vm}: not changed: {e}")),
        }
    }

    /// Whether the device has a newer base than this box's. An adopted box
    /// names no base and is never offered one.
    fn update_for(&self, rec: &boxes::BoxRecord) -> bool {
        match (&rec.base, self.current_base()) {
            (Some(mine), Some(current)) => *mine != current.name,
            _ => false,
        }
    }

    fn build_problem(&self) -> Option<String> {
        // Plain words for the user; the cause is in `service.log`, where the
        // failed build noted it (D-034 wording review, 2026-10-01).
        self.build_failed.lock().unwrap_or_else(|p| p.into_inner()).as_ref()?;
        Some("An update for your box could not be prepared. Your box works as before; Sluse tries again by itself and when the computer restarts.".into())
    }

    fn current_base(&self) -> Option<BaseRecord> {
        let bytes = std::fs::read(self.root.join("images").join("base.json")).ok()?;
        let rec: BaseRecord = serde_json::from_slice(&bytes).ok()?;
        self.root.join("images").join(&rec.name).is_file().then_some(rec)
    }

    /// "Reset the system, keep my files", or "Wipe the box" (D-026 point 2).
    /// The box is stopped, its VM and system disk go (and the home disk, for
    /// a wipe), and a new box is made on the device's newest base, which is
    /// how an update arrives. The host keeps its records: the audit, the
    /// journal's mirror, and a line here saying who asked.
    fn reset(&self, caller: &Caller, target: &str, wipe: bool, send: &mut dyn FnMut(PipeEvent)) -> PipeEvent {
        if !self.resetting.lock().unwrap_or_else(|p| p.into_inner()).insert(target.to_owned()) {
            return failed(PipeFailure::Busy, "This box is already being reset or wiped.");
        }
        let result = self.reset_now(caller, target, wipe, send);
        self.resetting.lock().unwrap_or_else(|p| p.into_inner()).remove(target);
        result
    }

    fn reset_now(&self, caller: &Caller, target: &str, wipe: bool, send: &mut dyn FnMut(PipeEvent)) -> PipeEvent {
        let what = if wipe { "wipe" } else { "reset" };
        let mut running = match self.running_or_busy() {
            Ok(g) => g,
            Err(e) => return e,
        };
        let old = match boxes::load(&self.root, target) {
            Ok(Some(r)) => r,
            Ok(None) => return failed(PipeFailure::NoBox, "There is no box to reset."),
            Err(e) => return failed(PipeFailure::Box, e.to_string()),
        };
        // A box Sluse did not make (`sluse box adopt`) is someone's own VM,
        // with disks Sluse did not lay out: it is never removed from here.
        if old.base.is_none() {
            return failed(
                PipeFailure::NotAllowed,
                format!("This box ({}) was set up by hand, not by Sluse, so Sluse cannot reset it. Send the details to your IT department.", old.vm),
            );
        }
        if let Some(r) = running.as_mut().filter(|r| r.sid == target) {
            let _ = r.broker.kill();
            let _ = r.broker.wait();
            *running = None;
        }
        self.log_action(what, target, caller);
        let mut steps = Steps::default();
        let phase = if wipe { Phase::Wipe } else { Phase::Reset };
        steps.next(self, send, phase, name(phase));
        let dir = self.box_dir(target);
        let path = |f: &str| dir.join(f).display().to_string();
        let mut args = serde_json::json!({ "verb": "remove-box", "vm": old.vm, "system": path("system.vhdx") });
        if wipe {
            args["home"] = path("home.vhdx").into();
        }
        if let Err(e) = self.hyperv.call(args) {
            return failed(PipeFailure::Box, e);
        }
        steps.done(self);
        let base = match self.ensure_base(send) {
            Ok(b) => b,
            Err(e) => return failed(PipeFailure::Box, format!("preparing the box: {e}")),
        };
        steps.next(self, send, Phase::Make, REMAKE);
        if let Err(e) = self.create_box(target, &base, steps.left()) {
            return failed(PipeFailure::Box, steps.why(e));
        }
        steps.done(self);
        self.remove_unused_bases();
        PipeEvent::Closed
    }

    /// One line per reset or wipe, beside the service's logs: when, which
    /// box, and who asked.
    /// `ponytail:` a file SYSTEM and Administrators own, not the Event Log;
    /// move it there with M10's SYSTEM-only log.
    fn log_action(&self, what: &str, target: &str, caller: &Caller) {
        let logs = self.root.join("logs");
        let _ = std::fs::create_dir_all(&logs);
        let line = serde_json::json!({
            "ts": chrono::Utc::now(), "op": what, "box": target,
            "by": caller.sid, "byAdmin": caller.admin,
        });
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(logs.join("actions.jsonl")) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Attach to the console of every box already running, as at a service
    /// start while boxes run: without this their pipes stayed free until the
    /// next open, and a standard user could read one (L1, 2026-09-30).
    fn follow_running_consoles(&self) {
        for d in std::fs::read_dir(self.root.join("boxes")).into_iter().flatten().flatten() {
            let sid = d.file_name().to_string_lossy().into_owned();
            if let Some(rec) = boxes::load(&self.root, &sid).ok().flatten() {
                if self.hyperv.state(&rec.vm) == Ok(BoxState::Running) {
                    self.follow_console(&sid, &rec.vm);
                }
            }
        }
    }

    /// Whether any user's box is running. A base built beside one can leave
    /// the device short of memory for both: on L1 the build VM never started
    /// (2026-09-30).
    fn a_box_runs(&self) -> bool {
        std::fs::read_dir(self.root.join("boxes"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|d| boxes::load(&self.root, &d.file_name().to_string_lossy()).ok().flatten())
            .any(|r| self.hyperv.state(&r.vm) == Ok(BoxState::Running))
    }

    /// Bases no box stands on any more, other than the current one.
    fn remove_unused_bases(&self) {
        let images = self.root.join("images");
        let current = self.current_base().map(|b| b.name);
        let used: Vec<String> = std::fs::read_dir(self.root.join("boxes"))
            .into_iter()
            .flatten()
            .flatten()
            .filter_map(|d| boxes::load(&self.root, &d.file_name().to_string_lossy()).ok().flatten())
            .filter_map(|r| r.base)
            .collect();
        for e in std::fs::read_dir(&images).into_iter().flatten().flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with("base-") && name.ends_with(".vhdx") && Some(&name) != current.as_ref() && !used.contains(&name) {
                let _ = self.hyperv.call(serde_json::json!({ "verb": "remove-file", "path": e.path().display().to_string() }));
            }
        }
    }

    /// The device's base, built if it is not there yet. One build at a time;
    /// an open that arrives during one is shown its steps.
    pub fn ensure_base(&self, send: &mut dyn FnMut(PipeEvent)) -> Result<PathBuf, String> {
        let images = self.root.join("images");
        // A build that panicked leaves the lock poisoned, not held: taken,
        // or every later open would wait on it for ever (R-54).
        let take = || match self.building.try_lock() {
            Ok(g) => Some(g),
            Err(std::sync::TryLockError::Poisoned(p)) => Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        };
        let guard = match take() {
            Some(g) => g,
            None => {
                // Someone else is building: report their steps until it ends.
                let mut last = None;
                loop {
                    if let Some(g) = take() {
                        break g;
                    }
                    let now = self.build_step.lock().unwrap_or_else(|p| p.into_inner()).clone();
                    if now != last {
                        if let Some(step) = &now {
                            send(step.clone());
                        }
                        last = now;
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            }
        };
        // A base is current while it was built from the bundle and the
        // cloud-init this install carries: a package added to user-data alone
        // changes the base too (L1, 2026-10-05). A new one (an update) means a
        // new base beside the old, which boxes keep standing on until they are
        // reset.
        let (bundle, bundle_hash) = self.bundle()?;
        if let Some(current) = self.current_base().filter(|b| b.bundle == bundle_hash) {
            return Ok(images.join(current.name));
        }
        let name = format!("base-{}.vhdx", chrono::Utc::now().format("%Y%m%d%H%M%S"));
        let base = images.join(&name);
        let mut step = |e: PipeEvent| {
            *self.build_step.lock().unwrap_or_else(|p| p.into_inner()) = Some(e.clone());
            send(e);
        };
        let result = self.build_base(&images, &bundle, &base, &mut step);
        *self.build_step.lock().unwrap_or_else(|p| p.into_inner()) = None;
        *self.build_failed.lock().unwrap_or_else(|p| p.into_inner()) = result.as_ref().err().cloned();
        let failures = &self.build_failures;
        let result = match result {
            Ok(()) => {
                failures.store(0, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Err(e) => match failures.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1 {
                1 => Err(e),
                n => Err(format!("{e}; failed {n} times in a row")),
            },
        };
        result?;
        let rec = BaseRecord { name, bundle: bundle_hash, built: chrono::Utc::now() };
        let done = images.join("base.json");
        std::fs::write(&done, serde_json::to_vec_pretty(&rec).map_err(|e| e.to_string())?)
            .map_err(|e| format!("{}: {e}", done.display()))?;
        drop(guard);
        Ok(base)
    }

    /// The box bundle this install carries, and what a base built from it
    /// records: the bundle's hash and the cloud-init's.
    fn bundle(&self) -> Result<(PathBuf, String), String> {
        let bundle = crate::run::box_bundle()?;
        let hash = format!("{}:{}", sha256_file(&bundle)?, sluse_proto::ContentHash::of(USER_DATA.as_bytes()).as_str());
        Ok((bundle, hash))
    }

    /// Canonical's image, verified and converted, then one cloud-init run in
    /// a build VM that powers itself off (D-024 point 3; S-8 step 3).
    fn build_base(
        &self,
        images: &std::path::Path,
        bundle: &std::path::Path,
        base: &std::path::Path,
        step: &mut dyn FnMut(PipeEvent),
    ) -> Result<(), String> {
        let mut steps = Steps::default();
        // The converted disk is kept until a build succeeds, so a retry
        // starts at the setup rather than the download (D-063). Written under
        // another name and renamed, so a half-converted one is never taken.
        let vhd = images.join("base.vhd");
        if !vhd.exists() {
            steps.next(self, step, Phase::Download, name(Phase::Download));
            let mut shown = 0;
            let image = crate::image::fetch(images, steps.left(), |have, total| {
                let pct = (have * 100).checked_div(total).unwrap_or(0);
                if pct > shown {
                    shown = pct;
                    step(self.progress(Phase::Download, name(Phase::Download).into(), Some(pct.min(100) as u8)));
                }
            })?;
            // Four silent steps under one phase: each says its name, and the
            // conversion its share (L1, 2026-10-05: 7 minutes with nothing
            // new). The conversion is this machine's own disk work; the calls
            // after it are stopped at what is left of the phase's limit (Q21).
            steps.next(self, step, Phase::Convert, name(Phase::Convert));
            let part = images.join("base.vhd.part");
            let mut shown = 0;
            crate::image::to_fixed_vhd(&image, &part, |have, total| {
                let pct = (have * 100).checked_div(total).unwrap_or(0);
                if pct > shown {
                    shown = pct;
                    step(self.progress(Phase::Convert, "Converting your box's disk".into(), Some(pct.min(100) as u8)));
                }
            })?;
            std::fs::rename(&part, &vhd).map_err(|e| format!("{}: {e}", vhd.display()))?;
            let _ = std::fs::remove_file(&image);
        } else {
            steps.next(self, step, Phase::Convert, name(Phase::Convert));
        }
        let s = |p: &std::path::Path| p.display().to_string();
        step(self.progress(Phase::Convert, "Sizing your box's disk".into(), None));
        self.hyperv
            .call_within(serde_json::json!({ "verb": "base-from-vhd", "vhd": s(&vhd), "base": s(base), "gb": BASE_GB }), steps.left())
            .map_err(|e| steps.why(e))?;

        step(self.progress(Phase::Convert, "Writing your box's setup".into(), None));
        let seed = images.join("seed.vhdx");
        let stamp = chrono::Utc::now().format("%Y%m%d%H%M%S");
        self.hyperv
            .call_within(
                serde_json::json!({
                    "verb": "seed", "seed": s(&seed), "copy": [s(bundle)],
                    "files": {
                        "user-data": USER_DATA,
                        "meta-data": format!("instance-id: sluse-base-{stamp}\nlocal-hostname: sluse-box\n"),
                        "network-config": network_config(),
                    },
                }),
                steps.left(),
            )
            .map_err(|e| steps.why(e))?;
        // The build's way out is the box's: the device's list, so a base
        // that builds is one whose box can update itself (M9, D-035).
        self.ensure_certs()?;
        let config = self.root.join("sluse.json");
        let loaded = sluse_proto::config::load(&config).map_err(|e| format!("{}: {e}", config.display()))?;
        let _proxy = self.start_proxy(&loaded, None)?;
        step(self.progress(Phase::Convert, "Starting the build".into(), None));
        // The build's console, read from before it starts (D-063): what it
        // says of itself decides whether its disk becomes the base.
        let pipe = crate::console::pipe_name(BUILD_VM);
        let record = images.join("build");
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let recording = {
            let (pipe, record, stop) = (pipe.clone(), record.clone(), stop.clone());
            std::thread::spawn(move || crate::console::record(&pipe, &record, &stop))
        };
        let built = (|| {
            self.hyperv
                .call_within(
                    serde_json::json!({
                        "verb": "build-vm", "vm": BUILD_VM, "base": s(base), "seed": s(&seed),
                        "switch": SWITCH, "memoryGB": MEMORY_GB, "pipe": pipe,
                    }),
                    steps.left(),
                )
                .map_err(|e| steps.why(e))?;
            // The build VM powers itself off when cloud-init is done. The
            // shell keeps the clock; nothing here needs to send while it waits.
            steps.next(self, step, Phase::Install, name(Phase::Install));
            let started = Instant::now();
            loop {
                std::thread::sleep(Duration::from_secs(10));
                if self.hyperv.state(BUILD_VM)? == BoxState::Off {
                    return Ok(());
                }
                if started.elapsed() > BUILD_TIMEOUT {
                    return Err(format!("the build did not finish within {} minutes", BUILD_TIMEOUT.as_secs() / 60));
                }
            }
        })();
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        built?;
        let console = record.join("console.log");
        match recording.join() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => note(format_args!("{}: {e}", console.display())),
            Err(_) => note("the build's console copy stopped"),
        }
        let said = std::fs::read(&console).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        // A build that did not finish leaves no base: its disk goes, and the
        // converted one stays for the next try.
        let whole = crate::console::verdict(&said);
        self.hyperv.call(serde_json::json!({
            "verb": "finish-build", "vm": BUILD_VM, "seed": s(&seed), "base": s(base), "vhd": s(&vhd), "keep": whole.is_ok(),
        }))?;
        whole.map_err(|why| format!("the box's system could not be installed ({why}); its console: {}", console.display()))?;
        steps.done(self);
        Ok(())
    }

    /// The running box's lock, or Busy at once while an open, a close or a
    /// reset holds it. A Close or Reset sent during an open used to queue
    /// silently behind it, for up to `BOX_TIMEOUT` plus any base build; the
    /// service cannot cancel an open, so it says so instead (D-034 point 2).
    fn running_or_busy(&self) -> Result<std::sync::MutexGuard<'_, Option<Running>>, PipeEvent> {
        match self.running.try_lock() {
            Ok(g) => Ok(g),
            Err(std::sync::TryLockError::Poisoned(p)) => Ok(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => Err(failed(
                PipeFailure::Busy,
                "Sluse is busy opening or closing a box. Try again when it has finished.",
            )),
        }
    }

    /// Stop the broker if it is this user's, which ends the sign-in (D-022),
    /// then shut the box down. Both disks stay (D-026 point 1).
    fn close(&self, sid: &str, rec: &boxes::BoxRecord, send: &mut dyn FnMut(PipeEvent)) -> PipeEvent {
        let mut running = match self.running_or_busy() {
            Ok(g) => g,
            Err(e) => return e,
        };
        let mut steps = Steps::default();
        steps.next(self, send, Phase::Close, name(Phase::Close));
        if let Some(r) = running.as_mut().filter(|r| r.sid == sid) {
            let _ = r.broker.kill();
            let _ = r.broker.wait();
            *running = None;
        }
        match self.hyperv.stop(&rec.vm, CLOSE_TIMEOUT) {
            Ok(turned_off) => {
                // A turned-off close is the limit, not how long a close takes.
                if !turned_off {
                    steps.done(self);
                }
                if turned_off {
                    note(format_args!(
                        "{}: did not shut down within {} s and was turned off",
                        rec.vm,
                        CLOSE_TIMEOUT.as_secs()
                    ));
                }
                PipeEvent::Closed
            }
            Err(e) => failed(PipeFailure::Box, e),
        }
    }

    /// The SCM is stopping the service. The broker goes; the box is left as
    /// it is, and Hyper-V's own stop action covers the host shutting down.
    pub fn shutdown(&self) {
        let mut running = self.running.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(mut r) = running.take() {
            let _ = r.broker.kill();
            let _ = r.broker.wait();
        }
    }
}

/// Where the box enrols: the broker's own host, on the enrolment port.
fn enrol_url(listen: &str) -> Result<String, String> {
    let host = listen.rsplit_once(':').map(|(h, _)| h).ok_or_else(|| format!("broker.listen {listen:?} has no port"))?;
    Ok(format!("https://{host}:{ENROL_PORT}"))
}

fn read_line(conn: &mut impl Read) -> io::Result<String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while conn.read(&mut byte)? == 1 {
        if byte[0] == b'\n' {
            return String::from_utf8(line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e));
        }
        line.push(byte[0]);
        if line.len() > MAX_REQUEST {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the request is too long"));
        }
    }
    Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the pipe closed before a request"))
}

fn send_line(conn: &mut impl Write, e: &PipeEvent) -> io::Result<()> {
    let mut line = serde_json::to_vec(e).map_err(io::Error::other)?;
    line.push(b'\n');
    conn.write_all(&line)?;
    conn.flush()
}

/// Until `listen` accepts a connection, while `gone` says nothing: the
/// broker's process is alive, and what it says if it is not.
fn wait_until_listening(listen: &str, within: Duration, mut gone: impl FnMut() -> Option<String>) -> Result<(), String> {
    let to: SocketAddr = listen.parse().map_err(|_| format!("broker.listen {listen:?} is not an address"))?;
    let deadline = Instant::now() + within;
    loop {
        if let Some(why) = gone() {
            return Err(why);
        }
        if TcpStream::connect_timeout(&to, Duration::from_secs(1)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("the broker did not listen on {listen} within {} s", within.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Until `port` on `addr` accepts a connection, while `gone` says nothing.
fn wait_for_port(addr: Ipv4Addr, port: u16, within: Duration, gone: impl Fn() -> Option<String>) -> Result<(), String> {
    let deadline = Instant::now() + within;
    let to = SocketAddr::from((addr, port));
    loop {
        if let Some(why) = gone() {
            return Err(why);
        }
        if TcpStream::connect_timeout(&to, Duration::from_secs(2)).is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "{} did not answer within {} s",
                sluse_proto::ports::label(&to.to_string()),
                within.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

/// `sluse service`: run under the SCM, or in the foreground when started
/// from a console, which is how it is tried on L1 before the MSI exists.
#[cfg(windows)]
pub fn run() -> std::process::ExitCode {
    use std::sync::Arc;

    let root = boxes::data_root();
    if let Err(e) = crate::winsys::protect_root(&root) {
        note(format_args!("{}: {e}", root.display()));
        return std::process::ExitCode::from(1);
    }
    let _ = crate::winsys::stderr_to_file_if_none(&root.join("logs").join("service.log"));
    note("started");
    let service = match Service::new(root, HyperV::embedded()) {
        Ok(s) => Arc::new(s),
        Err(e) => {
            note(e);
            return std::process::ExitCode::from(1);
        }
    };
    // Boxes that kept running while the service was down (D-030).
    service.follow_running_consoles();
    // Built after install, not at the first click (D-024 point 2): once the
    // device has its config, the base is made in the background.
    if service.root.join("sluse.json").is_file() {
        let service = service.clone();
        std::thread::spawn(move || {
            if let Err(e) = service.device_init() {
                note(format_args!("the device: {e}"));
            }
            // A failed build is tried again, BUILD_TRIES times in all, so a
            // transient failure (memory, on L1 2026-09-30) does not wait for
            // a reboot. `ponytail:` a fixed pause; a cause that persists
            // costs two builds and then waits for the next start or open.
            for attempt in 1..=BUILD_TRIES {
                // Not beside a running box (see `a_box_runs`): the build
                // waits for it to be closed, and never stops it.
                if service.a_box_runs() {
                    note("a box is running; the base is checked once it is closed");
                    while service.a_box_runs() {
                        std::thread::sleep(Duration::from_secs(30));
                    }
                }
                match service.ensure_base(&mut |_| {}) {
                    Ok(base) => {
                        note(format_args!("the base: {}", base.display()));
                        break;
                    }
                    Err(e) => note(format_args!("the base, attempt {attempt} of {BUILD_TRIES}: {e}")),
                }
                if attempt < BUILD_TRIES {
                    std::thread::sleep(BUILD_RETRY);
                }
            }
        });
    }
    let serve = {
        let service = service.clone();
        move || {
            let r = crate::winsys::serve_pipe(sluse_proto::pipe::PIPE_NAME, move |mut conn| {
                service.handle(&mut conn, crate::winsys::client_identity);
            });
            if let Err(e) = r {
                note(format_args!("{}: {e}", sluse_proto::pipe::PIPE_NAME));
                std::process::exit(1);
            }
        }
    };
    let on_stop = service.clone();
    let result = windows_services::Service::new()
        .can_stop()
        .can_fallback(|_| {
            // Start has already been delivered and the pipe is being served;
            // this only keeps the process up. Ctrl+C ends it, and the job
            // takes the broker with it.
            println!("sluse service: in the foreground on {}. Ctrl+C stops it.", sluse_proto::pipe::PIPE_NAME);
            loop {
                std::thread::park();
            }
        })
        .run(move |_, command| match command {
            windows_services::Command::Start => {
                std::thread::spawn(serve.clone());
            }
            windows_services::Command::Stop => on_stop.shutdown(),
            _ => {}
        });
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            note(e);
            std::process::ExitCode::from(1)
        }
    }
}

/// How long the broker has to redeem a sign-in and say so. Entra answers in
/// a second or two; a code is good for minutes.
const SIGN_IN_WAIT: Duration = Duration::from_secs(30);

/// Hand a sign-in to the broker on its stdin, numbered `seq`, and wait for
/// its answer in `/v1/status` (D-036). The user it bound, or why not.
fn hand_sign_in(broker: &mut Child, loaded: &sluse_proto::Loaded, seq: u64, mut s: HostSignIn) -> Result<String, String> {
    s.seq = seq;
    let line = serde_json::to_string(&s).map_err(|e| e.to_string())?;
    let stdin = broker.stdin.as_mut().ok_or("the broker has no control channel")?;
    writeln!(stdin, "{line}").and_then(|()| stdin.flush()).map_err(|e| format!("the broker's control channel: {e}"))?;
    let deadline = Instant::now() + SIGN_IN_WAIT;
    loop {
        if let Ok(status) = crate::probe(loaded) {
            match status.host_sign_in {
                Some(r) if r.seq == seq => {
                    return match r.error {
                        None => Ok(status.signed_in.map(|u| u.name).unwrap_or_default()),
                        Some(e) => Err(e),
                    }
                }
                _ => {}
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("the broker did not answer the sign-in within {} s", SIGN_IN_WAIT.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// The config's device half on a tenant device (D-038 point 2): the fixed
/// plumbing, this device's box id and its leaf's pin.
fn device_half(box_id: &str, pin: &ContentHash) -> String {
    use sluse_proto::ports;
    let v = serde_json::json!({
        "boxId": box_id,
        "environment": "demo",
        "broker": {
            "listen": format!("{GATEWAY}:{}", ports::BROKER), "url": format!("https://{GATEWAY}:{}", ports::BROKER),
            "certPath": "certs/broker.pem", "keyPath": "certs/broker.key", "clientCaPath": "certs/client-ca.pem",
            "certPin": pin.as_str(),
        },
        "endpoint": { "clientCertPath": "certs/endpoint.pem", "clientKeyPath": "certs/endpoint.key", "consoleListen": format!("127.0.0.1:{}", ports::CONSOLE) },
        "artifacts": "artifacts",
        "workspace": "workspace",
        "journalDir": "journal",
        "audit": { "sink": "eventlog" },
    });
    let mut text = serde_json::to_string_pretty(&v).expect("a JSON value serialises");
    text.push('\n');
    text
}

/// A box id for this device, made once and kept in its device half.
fn new_box_id() -> Result<String, String> {
    let mut b = [0u8; 6];
    getrandom::fill(&mut b).map_err(|e| format!("a box id: {e}"))?;
    Ok(format!("box-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
}

/// The config's parts, each by its own hash, and the whole file's version
/// (D-045 point 3): `sources`, `egress`, and `settings` for the rest but the
/// deployment block, whose revision moves at every publish.
fn config_parts(authored: &[u8], version: &ContentHash) -> std::collections::BTreeMap<String, String> {
    let mut v: serde_json::Value = serde_json::from_slice(authored).unwrap_or_default();
    let mut take = |k: &str| v.as_object_mut().and_then(|o| o.remove(k)).unwrap_or_default();
    let hash = |x: &serde_json::Value| ContentHash::of(&serde_json::to_vec(x).unwrap_or_default()).as_str().to_owned();
    let (sources, egress) = (take("sources"), take("egress"));
    take("deployment");
    [("version", version.as_str().to_owned()), ("sources", hash(&sources)), ("egress", hash(&egress)), ("settings", hash(&v))]
        .into_iter()
        .map(|(k, h)| (k.to_owned(), h))
        .collect()
}

/// What differs from what a box last opened under: nothing at its first open;
/// "sources" from a box last opened before parts were kept, when the file
/// itself changed, which is what the notice said then.
fn changed_parts(before: Option<&str>, now: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    let Some(before) = before else { return vec![] };
    match serde_json::from_str::<std::collections::BTreeMap<String, String>>(before) {
        Ok(old) => ["sources", "egress", "settings"]
            .into_iter()
            .filter(|k| old.get(*k) != now.get(*k))
            .map(str::to_owned)
            .collect(),
        Err(_) if Some(before.trim()) != now.get("version").map(String::as_str) => vec!["sources".to_owned()],
        Err(_) => vec![],
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_brokers_wait_is_for_its_listener_and_its_life_not_for_mtls() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let at = l.local_addr().unwrap().to_string();
        assert_eq!(wait_until_listening(&at, Duration::from_secs(2), || None), Ok(()));
        drop(l);
        let e = wait_until_listening(&at, Duration::from_secs(2), || Some("exited".into())).unwrap_err();
        assert_eq!(e, "exited", "a broker that died is said at once, not waited out");
        let e = wait_until_listening(&at, Duration::from_millis(300), || None).unwrap_err();
        assert!(e.contains("did not listen"), "{e}");
    }

    #[test]
    fn the_notice_names_what_changed() {
        use super::{changed_parts, config_parts};
        let v = |s: &str| sluse_proto::ContentHash::of(s.as_bytes());
        let a = r#"{"sources":[1],"egress":{"allow":["a"]},"box":{"memoryGB":6},"deployment":{"revision":1}}"#;
        let first = config_parts(a.as_bytes(), &v(a));
        let before = serde_json::to_string(&first).unwrap();
        assert!(changed_parts(None, &first).is_empty(), "a first open is not a change");
        let b = r#"{"sources":[1],"egress":{"allow":["a","b"]},"box":{"memoryGB":6},"deployment":{"revision":2}}"#;
        assert_eq!(changed_parts(Some(&before), &config_parts(b.as_bytes(), &v(b))), ["egress"], "L1, 2026-10-05");
        let c = r#"{"sources":[2],"egress":{"allow":["a"]},"box":{"memoryGB":8},"deployment":{"revision":3}}"#;
        assert_eq!(changed_parts(Some(&before), &config_parts(c.as_bytes(), &v(c))), ["sources", "settings"]);
        let d = r#"{"sources":[1],"egress":{"allow":["a"]},"box":{"memoryGB":6},"deployment":{"revision":9}}"#;
        assert!(changed_parts(Some(&before), &config_parts(d.as_bytes(), &v(d))).is_empty(), "a revision alone");
        // A box last opened under the single hash an older service kept.
        assert_eq!(changed_parts(Some(v(a).as_str()), &config_parts(b.as_bytes(), &v(b))), ["sources"]);
        assert!(changed_parts(Some(v(a).as_str()), &first).is_empty());
    }

    use super::*;

    /// A pipe stand-in: what the client wrote, and what the service wrote back.
    struct Conn {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
    }
    impl Read for Conn {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl Write for Conn {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.write(buf)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn ask(service: &Service, request: &str, sid: &str) -> Vec<PipeEvent> {
        let mut conn = Conn { input: io::Cursor::new(request.as_bytes().to_vec()), output: Vec::new() };
        let caller = Caller { sid: sid.to_owned(), admin: false, session: 0 };
        service.handle(&mut conn, move |_| Ok(caller));
        String::from_utf8(conn.output).unwrap().lines().map(|l| serde_json::from_str(l).unwrap()).collect()
    }

    fn service() -> (tempfile::TempDir, Service) {
        let dir = tempfile::tempdir().unwrap();
        let s = Service::new(dir.path().to_owned(), HyperV::embedded()).unwrap();
        (dir, s)
    }

    const SID: &str = "S-1-12-1-1-2-3-4";

    #[test]
    fn a_quit_is_answered_and_held_for_that_user_only() {
        let (_d, s) = service();
        assert_eq!(ask(&s, "{\"op\":\"quit\"}\n", SID), vec![PipeEvent::Done]);
        let quit = s.quit.lock().unwrap();
        assert!(quit.contains(SID) && quit.len() == 1, "{quit:?}");
    }

    #[test]
    fn a_user_with_no_box_is_told_so_and_nothing_is_started() {
        let (_d, s) = service();
        assert_eq!(
            ask(&s, "{\"op\":\"status\"}\n", SID),
            vec![PipeEvent::State { state: BoxState::None, sign_in: None, signed_in: None, signed_out: false, user: None, vm: None, dir: None }]
        );
        let again = ask(&s, "{\"op\":\"signIn\",\"signIn\":{\"code\":\"c\",\"verifier\":\"v\",\"redirectUri\":\"r\",\"nonce\":\"n\"}}\n", SID);
        assert!(matches!(again.as_slice(), [PipeEvent::Failed { code: PipeFailure::NoBox, .. }]), "{again:?}");
        // No configuration on the device: IT's to fix, said as such (R-39).
        let open = ask(&s, "{\"op\":\"open\",\"keyboard\":\"dk\"}\n", SID);
        assert!(matches!(open.as_slice(), [PipeEvent::Failed { code: PipeFailure::Preflight, .. }]), "{open:?}");
        assert!(s.running.lock().unwrap().is_none());
    }

    #[test]
    fn a_phase_is_timed_kept_across_a_restart_and_told_as_last_time() {
        let (d, s) = service();
        let mut sent = Vec::new();
        let mut steps = Steps::default();
        steps.next(&s, &mut |e| sent.push(e), Phase::Wait, "Waiting");
        // The first time on this device: no last time, and the service's limit.
        assert_eq!(sent[0], PipeEvent::Progress {
            step: "Waiting".into(), phase: Some(Phase::Wait), pct: None, last_s: None, limit_s: Some(BOX_TIMEOUT.as_secs()), plan: vec![],
        });
        s.record_phase(Phase::Wait, Duration::from_secs(42));
        let again = Service::new(d.path().to_owned(), HyperV::embedded()).unwrap();
        let PipeEvent::Progress { last_s, .. } = again.progress(Phase::Wait, "Waiting".into(), None) else { unreachable!() };
        assert_eq!(last_s, Some(42), "kept in phases.json");
        // A phase with no limit in code carries none; a first-time step its
        // stand-in (Q21).
        let PipeEvent::Progress { limit_s, .. } = again.progress(Phase::Broker, "s".into(), None) else { unreachable!() };
        assert_eq!(limit_s, None);
        let PipeEvent::Progress { limit_s, .. } = again.progress(Phase::Make, "s".into(), None) else { unreachable!() };
        assert_eq!(limit_s, Some(MAKE_LIMIT.as_secs()));
    }

    #[test]
    fn a_step_past_its_limit_says_so_and_one_within_it_says_what_it_was_told() {
        let (_d, s) = service();
        let mut steps = Steps::default();
        steps.next(&s, &mut |_| {}, Phase::Broker, "b");
        assert_eq!(steps.left(), None, "no limit, nothing to stop");
        steps.next(&s, &mut |_| {}, Phase::Start, "s");
        assert!(steps.left().is_some_and(|l| l <= START_LIMIT && l > START_LIMIT - Duration::from_secs(60)));
        assert_eq!(steps.why("Hyper-V said no".into()), "Hyper-V said no");
        steps.current = Some((Phase::Start, Instant::now() - START_LIMIT));
        assert_eq!(steps.left(), Some(Duration::ZERO));
        assert_eq!(steps.why("x".into()), "Starting your box took longer than its limit of 5 minutes: x");
    }

    #[test]
    fn the_plan_names_every_step_still_to_come_and_rides_on_the_first_progress_only() {
        let (d, s) = service();
        let phases = |plan: Vec<PlannedStep>| plan.into_iter().map(|p| p.phase).collect::<Vec<_>>();
        let open = PipeRequest::Open { keyboard: "dk".into(), timezone: None, sign_in: None, theme: None };
        // No box and no base: the build, the box, then the open (Q19, Q20:
        // the check late in the list). No bundle here, so no base is current.
        use Phase::*;
        assert_eq!(phases(s.plan(SID, &open)), [Download, Convert, Install, Make, Check, Start, Broker, Wait]);
        assert_eq!(phases(s.plan(SID, &PipeRequest::Wipe { sid: None })), [Wipe, Download, Convert, Install, Make]);
        assert_eq!(s.plan(SID, &PipeRequest::Reset { sid: None }).last().unwrap().step, "Making the box again");
        boxes::save(d.path(), SID, &boxes::BoxRecord { vm: "sluse-box".into(), address: Ipv4Addr::LOCALHOST, base: Some("base-1.vhdx".into()), named: None }).unwrap();
        // A box that exists: the open's own steps, unless a build is under way,
        // which it joins where the build is.
        assert_eq!(phases(s.plan(SID, &open)), [Check, Start, Broker, Wait]);
        {
            let _building = s.building.lock().unwrap();
            *s.build_step.lock().unwrap() = Some(s.progress(Convert, "Converting".into(), Some(12)));
            assert_eq!(phases(s.plan(SID, &open)), [Convert, Install, Check, Start, Broker, Wait]);
        }
        assert!(s.plan(SID, &PipeRequest::Status).is_empty() && s.plan(SID, &PipeRequest::Console).is_empty());
        // Close: its plan with its first progress, and none after it. Hyper-V
        // is not here, so it then fails, which is what ends the answer.
        let got = ask(&s, "{\"op\":\"close\"}\n", SID);
        assert!(matches!(&got[0], PipeEvent::Progress { phase: Some(Close), plan, .. } if phases(plan.clone()) == [Close]), "{got:?}");
        assert!(matches!(got.last(), Some(PipeEvent::Failed { .. })), "{got:?}");
    }

    /// The box reads the keys the service writes, and takes the theme's two
    /// words only (Q70).
    #[test]
    fn the_box_reads_the_theme_and_the_bootstrap_under_the_services_keys() {
        let bootstrap = include_str!("../../../packaging/box/kiosk/sluse-bootstrap");
        assert!(bootstrap.contains(&format!("kvp(\"{KVP_KEY}\")")) && bootstrap.contains(&format!("kvp(\"{THEME_KEY}\")")));
        assert!(bootstrap.contains(&format!("({:?}, {:?})", Theme::Light.as_str(), Theme::Dark.as_str())));
    }

    #[test]
    fn the_theme_and_the_console_are_the_callers_open_box_only() {
        let (_d, s) = service();
        for req in [r#"{"op":"theme","theme":"dark"}"#, r#"{"op":"console"}"#] {
            let got = ask(&s, &format!("{req}\n"), SID);
            assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::NoBox, .. }]), "{req}: {got:?}");
        }
        // During an open the theme is refused, not queued: the open carries
        // the one it was given, and the shell sends a later one again.
        let _open = s.running.lock().unwrap();
        let got = ask(&s, "{\"op\":\"theme\",\"theme\":\"light\"}\n", SID);
        assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::Busy, .. }]), "{got:?}");
    }

    #[test]
    fn close_and_reset_during_an_open_are_refused_not_queued() {
        let (d, s) = service();
        boxes::save(d.path(), SID, &boxes::BoxRecord { vm: "sluse-box".into(), address: Ipv4Addr::LOCALHOST, base: Some("base-1.vhdx".into()), named: None }).unwrap();
        // What an open holds for as long as it runs.
        let _open = s.running.lock().unwrap();
        for op in ["close", "reset", "wipe"] {
            let got = ask(&s, &format!("{{\"op\":\"{op}\"}}\n"), SID);
            assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::Busy, .. }]), "{op}: {got:?}");
        }
    }

    #[test]
    fn a_second_reset_of_a_box_being_reset_is_refused_not_queued() {
        let (_d, s) = service();
        s.resetting.lock().unwrap().insert(SID.to_owned());
        for op in ["reset", "wipe"] {
            let got = ask(&s, &format!("{{\"op\":\"{op}\"}}\n"), SID);
            assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::Busy, .. }]), "{op}: {got:?}");
        }
        // And the guard is the running reset's to clear, not the refused one's.
        assert!(s.resetting.lock().unwrap().contains(SID));
    }

    #[test]
    fn a_request_that_is_not_one_is_refused_with_one_line() {
        let (_d, s) = service();
        for bad in ["nonsense\n", "{\"op\":\"format c:\"}\n", "", &format!("{}\n", "x".repeat(MAX_REQUEST + 1))] {
            let got = ask(&s, bad, SID);
            assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::BadRequest, .. }]), "{bad:.20}: {got:?}");
        }
    }

    #[test]
    fn a_keyboard_that_is_not_a_layout_is_refused_before_hyper_v_is_touched() {
        let (d, s) = service();
        boxes::save(d.path(), SID, &boxes::BoxRecord { vm: "sluse-box".into(), address: Ipv4Addr::LOCALHOST, base: None, named: None }).unwrap();
        let got = ask(&s, "{\"op\":\"open\",\"keyboard\":\"dk; rm -rf /\"}\n", SID);
        assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::BadRequest, .. }]), "{got:?}");
    }

    #[test]
    fn only_an_administrator_may_reset_or_wipe_another_users_box() {
        let (_d, s) = service();
        for req in [r#"{"op":"reset","sid":"S-1-12-1-9"}"#, r#"{"op":"wipe","sid":"S-1-12-1-9"}"#] {
            let got = ask(&s, &format!("{req}\n"), SID);
            assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::NotAllowed, .. }]), "{req}: {got:?}");
        }
        // An administrator gets past the check, to a box that is not there.
        let mut conn = Conn { input: io::Cursor::new(br#"{"op":"wipe","sid":"S-1-12-1-9"}
"#.to_vec()), output: Vec::new() };
        s.handle(&mut conn, |_| Ok(Caller { sid: SID.into(), admin: true, session: 0 }));
        let got: PipeEvent = serde_json::from_slice(conn.output.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(matches!(got, PipeEvent::Failed { code: PipeFailure::NoBox, .. }), "{got:?}");
        // Nor can an administrator name something that is not a SID.
        let mut conn = Conn { input: io::Cursor::new(br#"{"op":"reset","sid":"..\\x"}
"#.to_vec()), output: Vec::new() };
        s.handle(&mut conn, |_| Ok(Caller { sid: SID.into(), admin: true, session: 0 }));
        let got: PipeEvent = serde_json::from_slice(conn.output.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(matches!(got, PipeEvent::Failed { code: PipeFailure::BadRequest, .. }), "{got:?}");
    }

    #[test]
    fn an_adopted_box_is_never_reset_or_wiped_from_here() {
        let (d, s) = service();
        boxes::save(d.path(), SID, &boxes::BoxRecord { vm: "sluse-box".into(), address: BOX_ADDRESS, base: None, named: None }).unwrap();
        for req in ["{\"op\":\"reset\"}\n", "{\"op\":\"wipe\"}\n"] {
            let got = ask(&s, req, SID);
            assert!(matches!(got.as_slice(), [PipeEvent::Failed { code: PipeFailure::NotAllowed, .. }]), "{got:?}");
        }
        assert!(!d.path().join("logs/actions.jsonl").exists(), "nothing was done, so nothing is logged");
    }

    #[test]
    fn a_box_is_offered_an_update_only_when_the_device_has_a_newer_base() {
        let (d, s) = service();
        let images = d.path().join("images");
        std::fs::create_dir_all(&images).unwrap();
        let rec = |base: Option<&str>| boxes::BoxRecord { vm: "v".into(), address: BOX_ADDRESS, base: base.map(Into::into), named: None };
        assert!(!s.update_for(&rec(Some("base-1.vhdx"))), "no current base at all");
        std::fs::write(images.join("base-2.vhdx"), b"").unwrap();
        std::fs::write(images.join("base.json"), br#"{"name":"base-2.vhdx","bundle":"x","built":"2026-09-29T00:00:00Z"}"#).unwrap();
        assert!(s.update_for(&rec(Some("base-1.vhdx"))));
        assert!(!s.update_for(&rec(Some("base-2.vhdx"))));
        assert!(!s.update_for(&rec(None)), "an adopted box is never offered one");
    }

    #[test]
    fn a_box_is_named_from_its_sid_and_the_seed_is_well_formed() {
        let a = box_vm_name(SID);
        assert!(a.starts_with("sluse-") && a.len() == 16 && crate::boxes::valid_vm(&a));
        assert_ne!(a, box_vm_name("S-1-12-1-9"));
        assert!(!a.contains("S-1"), "the SID is not in the VM name");
        assert!(USER_DATA.starts_with("#cloud-config"));
        let net = network_config();
        assert!(net.contains("192.168.77.10/24"));
        assert!(!net.contains("routes") && !net.contains("nameservers"), "no way out but the proxy (M9)");
    }

    #[test]
    fn the_box_enrols_on_the_brokers_own_host() {
        assert_eq!(enrol_url("192.168.77.1:7580").unwrap(), "https://192.168.77.1:7581");
        assert!(enrol_url("no-port").is_err());
    }

    #[test]
    fn who_is_asking_comes_from_the_pipe_and_a_failure_there_answers_nothing_else() {
        let (_d, s) = service();
        let mut conn = Conn { input: io::Cursor::new(b"{\"op\":\"status\"}\n".to_vec()), output: Vec::new() };
        s.handle(&mut conn, |_| Err(io::Error::other("no token")));
        let got: PipeEvent = serde_json::from_slice(conn.output.strip_suffix(b"\n").unwrap()).unwrap();
        assert!(matches!(got, PipeEvent::Failed { code: PipeFailure::BadRequest, .. }));
    }
}

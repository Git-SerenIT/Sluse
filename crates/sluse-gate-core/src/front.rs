// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Starting Gate Front and serving it (D-071).
//!
//! The parent, Gate Core for an open or the service for a base build, starts
//! Front with two pipes as its stdin and stdout and serves HTTP/2 over them:
//! Front is the client. The pipes are made for this child and handed to it at
//! its start, so nothing else can speak on them; that is what makes a request
//! on them this box's.
//!
//! **On Windows Front runs as LocalService**: a token from `LogonUserW`, the
//! process made with `CreateProcessAsUserW`, and only its three standard
//! handles inherited (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`). It holds no token
//! for company data and reads no file; its TLS key comes over the pipe
//! ([`sluse_proto::gate::FrontStart`]). It stays in the parent's job, so it
//! dies with it. Elsewhere it is an ordinary child: the development guest
//! proves the protocol, not the privilege (D-011).
//!
//! The pipes are synchronous; two threads copy between them and an in-memory
//! duplex the server reads. Their cost is a copy per chunk, which a box's
//! traffic does not notice.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;

use axum::Router;
use sluse_proto::gate::{route, Claim, FrontGate, FrontProxy, FrontStart};
use sluse_proto::Loaded;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

/// The binary beside this one.
pub fn binary() -> io::Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| io::Error::other("this binary has no directory"))?;
    let front = dir.join(format!("sluse-gate-front{}", std::env::consts::EXE_SUFFIX));
    if front.is_file() {
        Ok(front)
    } else {
        Err(io::Error::new(io::ErrorKind::NotFound, format!("{} is missing", front.display())))
    }
}

/// A started Front: its channel, and the process to stop.
pub struct Started {
    pub io: DuplexStream,
    pub child: Child,
}

/// Start Front with `args`, its stderr to `log`: as LocalService when
/// `local_service`, which only SYSTEM can do (a device's Gate, started by the
/// service), else as this process's child (LOCAL's `sluse start`, CI).
pub fn start(exe: &Path, args: &[&str], log: File, local_service: bool) -> io::Result<Started> {
    let (child, to_child, from_child) = if local_service {
        #[cfg(windows)]
        let spawned = win::spawn(exe, args, log).map(|(p, i, o)| (Child::LocalService(p), i, o));
        #[cfg(not(windows))]
        let spawned = Err(io::Error::other("LocalService is Windows only"));
        spawned?
    } else {
        spawn(exe, args, log)?
    };
    Ok(Started { io: bridge(to_child, from_child), child })
}

/// Serve `router` to Front until the channel closes.
pub async fn serve(io: DuplexStream, router: Router) -> Result<(), hyper::Error> {
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(io), TowerToHyperService::new(router))
        .await
}

/// Two threads between the child's pipes and a duplex the async side holds.
fn bridge(mut to_child: File, mut from_child: File) -> DuplexStream {
    let (ours, theirs) = tokio::io::duplex(256 * 1024);
    let (mut read_half, mut write_half) = tokio::io::split(theirs);
    let runtime = tokio::runtime::Handle::current();
    let rt = runtime.clone();
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match from_child.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if rt.block_on(write_half.write_all(&buf[..n])).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = rt.block_on(write_half.shutdown());
    });
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match runtime.block_on(read_half.read(&mut buf)) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if to_child.write_all(&buf[..n]).and_then(|()| to_child.flush()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    ours
}

/// An append-only log that rolls to `<name>.1` at `cap` bytes, keeping one
/// older file: `egress.jsonl` when the config turns it on (D-038 point 7).
pub struct RollingLog {
    path: std::path::PathBuf,
    cap: u64,
    size: u64,
}

impl RollingLog {
    pub fn new(path: std::path::PathBuf, cap: u64) -> Self {
        let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        RollingLog { path, cap, size }
    }

    /// Append one line. A log that cannot be written is not a reason to
    /// stop connections: the refusals are on the Event Log regardless.
    pub fn line(&mut self, line: &str) {
        use std::io::Write;
        if self.size + line.len() as u64 + 1 > self.cap && self.size > 0 {
            let mut old = self.path.clone().into_os_string();
            old.push(".1");
            let _ = std::fs::rename(&self.path, old);
            self.size = 0;
        }
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            if writeln!(f, "{line}").is_ok() {
                self.size += line.len() as u64 + 1;
            }
        }
    }
}

/// Front's start for an open, from the config Core loaded: the files read
/// here, as SYSTEM, so Front needs no right to them. `enrolling` is an open by
/// the service (slice 2): enrolment beside the Gate, and the pin (D-058).
pub fn gate_start(loaded: &Loaded, listen: &str, enrolling: bool) -> Result<FrontGate, String> {
    let g = &loaded.config.gate;
    let read = |p: &str| {
        let path = loaded.resolve(p);
        std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))
    };
    let host = listen.rsplit_once(':').map(|(h, _)| h).ok_or("gate.listen has no port")?;
    Ok(FrontGate {
        listen: listen.to_owned(),
        cert_pem: read(&g.cert_path)?,
        key_pem: read(&g.key_path)?,
        client_ca_pem: read(&g.client_ca_path)?,
        pinned: enrolling,
        host_leaf_pem: if enrolling { read(&loaded.config.endpoint.client_cert_path).ok() } else { None },
        enrol_listen: enrolling.then(|| format!("{host}:{}", sluse_proto::wire::ENROL_PORT)),
    })
}

/// Front's egress proxy for this config (M9, D-035), on the Gate's host at the
/// proxy port. `opened_by` is the Windows account the box was opened for;
/// none for a base build.
pub fn proxy_start(loaded: &Loaded, opened_by: Option<String>, log_connections: bool) -> Result<FrontProxy, String> {
    let host = loaded.config.gate.listen.rsplit_once(':').map(|(h, _)| h).ok_or("gate.listen has no port")?;
    Ok(FrontProxy {
        listen: format!("{host}:{}", sluse_proto::ports::PROXY),
        allow: loaded.config.egress.clone().unwrap_or_default(),
        about: serde_json::json!({ "boxId": loaded.config.box_id, "configVersion": loaded.version, "openedBy": opened_by }),
        log_connections,
        public_only: true,
    })
}

/// What Front claims, kept: refusals for the Event Log, connections for
/// `egress.jsonl` when the config turns it on (D-038 point 7).
pub struct Claims {
    pub refusals: Refusals,
    connections: Option<std::sync::Mutex<RollingLog>>,
}

impl Claims {
    pub fn new(refusals: Refusals, egress_log: Option<RollingLog>) -> Self {
        Claims { refusals, connections: egress_log.map(std::sync::Mutex::new) }
    }

    pub fn take(&self, claim: Claim) {
        match claim {
            Claim::EgressRefused(r) => self.refusals.claim(r),
            Claim::Connection(r) => {
                if let Some(log) = &self.connections {
                    log.lock().unwrap_or_else(|p| p.into_inner()).line(&r.to_string());
                }
            }
        }
    }
}

/// The parent's own routes for Front: its start, and its claims.
pub fn routes(start: FrontStart, claims: std::sync::Arc<Claims>) -> Router {
    use axum::routing::{get, post};
    let start = std::sync::Arc::new(start);
    Router::new()
        .route(route::START, get(move || {
            let start = start.clone();
            async move { axum::Json((*start).clone()) }
        }))
        .route(route::CLAIM, post(move |axum::Json(c): axum::Json<Claim>| {
            let claims = claims.clone();
            async move {
                claims.take(c);
                axum::http::StatusCode::NO_CONTENT
            }
        }))
}

/// Front's question for a host on `egress.window` (D-075), answered from
/// the window Core holds against the config Core loaded itself.
pub fn window_route(core: std::sync::Arc<crate::app::Core>) -> Router {
    use axum::routing::post;
    Router::new().route(route::WINDOW, post(move |axum::Json(a): axum::Json<sluse_proto::gate::WindowAsk>| {
        let core = core.clone();
        async move {
            let egress = core.loaded.config.egress.clone().unwrap_or_default();
            axum::Json(sluse_proto::gate::WindowAnswer { open: core.window.ask(&egress, &a.host) })
        }
    }))
}

/// Distinct refused hosts recorded one by one; past it, [`OTHER_HOSTS`].
pub const MAX_REFUSED_HOSTS: usize = 1024;
/// Where refusals past [`MAX_REFUSED_HOSTS`] are counted.
pub const OTHER_HOSTS: &str = "(more hosts than Sluse records one by one)";

/// Front's egress refusals, as its parent keeps them: the first of each host
/// to the Event Log at once, the count of each host refused more than once
/// when the parent stops. Kept here and not in Front, which stops first.
/// Bounded (review R-28): past [`MAX_REFUSED_HOSTS`] distinct hosts the rest
/// are counted under one entry, so a box inventing names cannot grow this or
/// the Event Log without end.
pub struct Refusals {
    seen: std::sync::Mutex<std::collections::BTreeMap<String, (u64, serde_json::Value)>>,
    write: Box<dyn Fn(&serde_json::Value) + Send + Sync>,
}

impl Refusals {
    pub fn new(write: Box<dyn Fn(&serde_json::Value) + Send + Sync>) -> Self {
        Refusals { seen: Default::default(), write }
    }

    /// One refusal, as Front claimed it.
    pub fn claim(&self, mut record: serde_json::Value) {
        let host: String = record["host"].as_str().unwrap_or("").chars().take(253).collect();
        let first = {
            let mut seen = self.seen.lock().unwrap_or_else(|p| p.into_inner());
            let key = if seen.len() >= MAX_REFUSED_HOSTS && !seen.contains_key(&host) { OTHER_HOSTS.to_owned() } else { host };
            let n = seen.entry(key.clone()).or_insert((0, record.clone()));
            n.0 += 1;
            (n.0 == 1).then_some(key)
        };
        if let Some(key) = first {
            record["host"] = key.into();
            record["count"] = 1.into();
            (self.write)(&record);
        }
    }

    /// The counts, for each host refused more than once. Once, at the end.
    pub fn finish(&self) {
        let seen = std::mem::take(&mut *self.seen.lock().unwrap_or_else(|p| p.into_inner()));
        for (host, (n, mut r)) in seen.into_iter().filter(|(_, (n, _))| *n > 1) {
            r["host"] = host.into();
            r["count"] = n.into();
            r["ts"] = serde_json::to_value(chrono::Utc::now()).unwrap_or_default();
            r.as_object_mut().map(|o| o.remove("port"));
            (self.write)(&r);
        }
    }
}

/// Front's process.
pub enum Child {
    Plain(std::process::Child),
    #[cfg(windows)]
    LocalService(win::Process),
}

impl Child {
    pub fn kill(&mut self) {
        match self {
            Child::Plain(c) => {
                let _ = c.kill();
                let _ = c.wait();
            }
            #[cfg(windows)]
            Child::LocalService(p) => p.kill(),
        }
    }

    /// `Some` once it has exited.
    pub fn try_wait(&mut self) -> Option<String> {
        match self {
            Child::Plain(c) => match c.try_wait() {
                Ok(Some(status)) => Some(status.to_string()),
                Ok(None) => None,
                Err(e) => Some(e.to_string()),
            },
            #[cfg(windows)]
            Child::LocalService(p) => p.try_wait(),
        }
    }
}

/// An ordinary child, with this process's token.
fn spawn(exe: &Path, args: &[&str], log: File) -> io::Result<(Child, File, File)> {
    use std::process::{Command, Stdio};
    let mut child = Command::new(exe).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(log).spawn()?;
    #[cfg(not(windows))]
    let file = |p: std::os::fd::OwnedFd| File::from(p);
    #[cfg(windows)]
    let file = |p: std::os::windows::io::OwnedHandle| File::from(p);
    let stdin = child.stdin.take().map(|p| file(p.into()));
    let stdout = child.stdout.take().map(|p| file(p.into()));
    match (stdin, stdout) {
        (Some(i), Some(o)) => Ok((Child::Plain(child), i, o)),
        _ => Err(io::Error::other("the child's pipes were not made")),
    }
}

#[cfg(windows)]
mod win {
    use std::fs::File;
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::path::Path;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0};
    use windows::Win32::Security::{LogonUserW, LOGON32_LOGON_SERVICE, LOGON32_PROVIDER_DEFAULT};
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateProcessAsUserW, DeleteProcThreadAttributeList, GetExitCodeProcess, InitializeProcThreadAttributeList,
        TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject, CREATE_NO_WINDOW, CREATE_UNICODE_ENVIRONMENT,
        EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
        STARTF_USESTDHANDLES, STARTUPINFOEXW,
    };

    pub struct Process(OwnedHandle);

    impl Process {
        pub fn kill(&mut self) {
            let h = HANDLE(self.0.as_raw_handle());
            // SAFETY: a process handle this struct owns.
            unsafe {
                let _ = TerminateProcess(h, 1);
                let _ = WaitForSingleObject(h, 5000);
            }
        }

        pub fn try_wait(&mut self) -> Option<String> {
            let h = HANDLE(self.0.as_raw_handle());
            // SAFETY: as above.
            unsafe {
                if WaitForSingleObject(h, 0) != WAIT_OBJECT_0 {
                    return None;
                }
                let mut code = 0u32;
                let _ = GetExitCodeProcess(h, &mut code);
                Some(format!("exit code {code}"))
            }
        }
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    /// One pipe; `child_reads` says which end the child gets, which alone is
    /// made inheritable.
    fn pipe(child_reads: bool) -> io::Result<(OwnedHandle, OwnedHandle)> {
        let (mut r, mut w) = (HANDLE::default(), HANDLE::default());
        // SAFETY: out-pointers to locals; both handles are owned below.
        unsafe { CreatePipe(&mut r, &mut w, None, 64 * 1024) }.map_err(io::Error::other)?;
        // SAFETY: handles CreatePipe just returned.
        let (r, w) = unsafe { (OwnedHandle::from_raw_handle(r.0), OwnedHandle::from_raw_handle(w.0)) };
        let (child, parent) = if child_reads { (r, w) } else { (w, r) };
        // SAFETY: a valid handle we own.
        unsafe { SetHandleInformation(HANDLE(child.as_raw_handle()), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
            .map_err(io::Error::other)?;
        Ok((child, parent))
    }

    /// LocalService's token. SYSTEM may log it on without a password.
    fn local_service() -> io::Result<OwnedHandle> {
        let mut token = HANDLE::default();
        let (user, domain) = (wide("LocalService"), wide("NT AUTHORITY"));
        // SAFETY: wide strings that outlive the call; an out-pointer to a local.
        unsafe {
            LogonUserW(
                PCWSTR(user.as_ptr()),
                PCWSTR(domain.as_ptr()),
                PCWSTR::null(),
                LOGON32_LOGON_SERVICE,
                LOGON32_PROVIDER_DEFAULT,
                &mut token,
            )
        }
        .map_err(|e| io::Error::other(format!("LocalService's sign-in: {e}")))?;
        // SAFETY: a token LogonUserW just returned.
        Ok(unsafe { OwnedHandle::from_raw_handle(token.0) })
    }

    pub fn spawn(exe: &Path, args: &[&str], log: File) -> io::Result<(Process, File, File)> {
        let token = local_service()?;
        let (child_in, parent_in) = pipe(true)?;
        let (child_out, parent_out) = pipe(false)?;
        let log = OwnedHandle::from(log);
        // SAFETY: a valid handle we own.
        unsafe { SetHandleInformation(HANDLE(log.as_raw_handle()), HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT) }
            .map_err(io::Error::other)?;

        // Only these three are inherited, whatever else in this process is
        // marked inheritable.
        let inherit = [
            HANDLE(child_in.as_raw_handle()),
            HANDLE(child_out.as_raw_handle()),
            HANDLE(log.as_raw_handle()),
        ];
        let mut size = 0usize;
        // SAFETY: the documented size query; it fails with the size set.
        let _ = unsafe { InitializeProcThreadAttributeList(None, 1, None, &mut size) };
        let mut list_buf = vec![0u8; size];
        let list = LPPROC_THREAD_ATTRIBUTE_LIST(list_buf.as_mut_ptr().cast());
        // SAFETY: a buffer of the size just asked for; `inherit` outlives the list.
        unsafe {
            InitializeProcThreadAttributeList(Some(list), 1, None, &mut size).map_err(io::Error::other)?;
            UpdateProcThreadAttribute(
                list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(inherit.as_ptr().cast()),
                std::mem::size_of_val(&inherit),
                None,
                None,
            )
            .map_err(io::Error::other)?;
        }

        let mut si = STARTUPINFOEXW::default();
        si.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        si.StartupInfo.hStdInput = inherit[0];
        si.StartupInfo.hStdOutput = inherit[1];
        si.StartupInfo.hStdError = inherit[2];
        si.lpAttributeList = list;

        let quote = |a: &str| format!("\"{}\"", a.replace('"', "\\\""));
        let line = std::iter::once(quote(&exe.display().to_string())).chain(args.iter().map(|a| quote(a))).collect::<Vec<_>>().join(" ");
        let mut line = wide(&line);
        let app = wide(&exe.display().to_string());
        let mut pi = PROCESS_INFORMATION::default();
        // SAFETY: every pointer is to a local that outlives the call.
        let made = unsafe {
            CreateProcessAsUserW(
                Some(HANDLE(token.as_raw_handle())),
                PCWSTR(app.as_ptr()),
                Some(PWSTR(line.as_mut_ptr())),
                None,
                None,
                true,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                None,
                PCWSTR::null(),
                &si.StartupInfo,
                &mut pi,
            )
        };
        // SAFETY: the list was initialised above.
        unsafe { DeleteProcThreadAttributeList(list) };
        made.map_err(|e| io::Error::other(format!("starting {} as LocalService: {e}", exe.display())))?;
        // SAFETY: handles CreateProcessAsUserW returned; the thread's is not kept.
        let process = unsafe {
            let _ = CloseHandle(pi.hThread);
            OwnedHandle::from_raw_handle(pi.hProcess.0)
        };
        // The child's ends close here, ours stay.
        drop((child_in, child_out, log));
        Ok((Process(process), File::from(parent_in), File::from(parent_out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_egress_log_rolls_once_at_its_cap() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("egress.jsonl");
        let mut log = RollingLog::new(path.clone(), 30);
        for i in 0..5 {
            log.line(&format!("{{\"n\":{i}}}"));
        }
        let now = std::fs::read_to_string(&path).unwrap();
        let older = std::fs::read_to_string(dir.path().join("egress.jsonl.1")).unwrap();
        assert!(now.len() <= 30 && older.len() <= 30, "{now:?} {older:?}");
        assert!(now.contains("\"n\":4"));
        assert!(!dir.path().join("egress.jsonl.2").exists(), "one older file");
    }

    type Seen = std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>>;

    fn refusals() -> (Refusals, Seen) {
        let seen: Seen = Default::default();
        let s = seen.clone();
        (Refusals::new(Box::new(move |v| s.lock().unwrap().push(v.clone()))), seen)
    }

    fn refused(host: &str, reason: &str) -> serde_json::Value {
        serde_json::json!({ "op": "egress", "outcome": "refused", "host": host, "port": 443, "reason": reason, "count": 1, "boxId": "box-test" })
    }

    #[test]
    fn the_first_of_each_host_is_written_and_the_rest_counted_at_the_end() {
        let (r, seen) = refusals();
        for _ in 0..3 {
            r.claim(refused("evil.example", "NOT_ALLOWED"));
        }
        r.claim(refused("other.example", "PORT"));
        assert_eq!(seen.lock().unwrap().len(), 2, "the first of each host only");
        r.finish();
        let s = seen.lock().unwrap();
        assert_eq!(s.len(), 3, "a count only for a host refused more than once");
        assert_eq!((s[2]["host"].as_str(), s[2]["count"].as_u64()), (Some("evil.example"), Some(3)));
        assert!(s[2].get("port").is_none());
        assert_eq!(s[2]["boxId"], "box-test", "the record is Front's, counted");
    }

    /// Review R-28: invented names stop being recorded one by one.
    #[test]
    fn refusals_past_the_cap_are_counted_under_one_entry() {
        let (r, seen) = refusals();
        for i in 0..MAX_REFUSED_HOSTS + 5 {
            r.claim(refused(&format!("h{i}.{}.example", "x".repeat(300)), "NOT_ALLOWED"));
        }
        let s = seen.lock().unwrap();
        assert_eq!(s.len(), MAX_REFUSED_HOSTS + 1, "one each, then one for the rest");
        assert!(s.iter().all(|x| x["host"].as_str().unwrap().len() <= 253));
        assert_eq!(s[MAX_REFUSED_HOSTS]["host"], OTHER_HOSTS);
    }
}

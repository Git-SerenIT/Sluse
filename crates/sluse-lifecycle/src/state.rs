// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The state directory: what is running on this machine, and how to tell.
//!
//! `%LOCALAPPDATA%\Sluse\` — `$XDG_STATE_HOME/sluse` on the guest — holds one
//! record per run (`runs\*.json`), one log per run (`logs\*.log`), and nothing
//! else. It is per-user and not per-run, because the question `sluse status`
//! answers is "what is running on this machine", which no single run workspace
//! can answer.
//!
//! ## The pid problem, which is the only hard thing in this module
//!
//! A pid on its own is not an identity. Both platforms reuse them, and a record
//! left behind by a broker that crashed will eventually name a process that is
//! something else entirely — at which point `sluse stop` would kill a stranger.
//! So a record stores the pid *and* the time the process was created, and
//! [`Run::alive`] accepts the process only if both still match. The creation
//! time comes from the kernel, so it cannot be guessed at and cannot collide:
//! two processes with the same pid always have different creation times.
//!
//! The two kernels are asked in their own idiom — `GetProcessTimes` on the host,
//! `/proc/<pid>/stat` field 22 on the guest (D-011) — and the units differ. That
//! is safe because the value is only ever compared with another reading of
//! itself on the same machine; it is never serialised as a duration, never shown
//! to a person, and a record does not travel between the two.
//!
//! The consequence worth stating plainly: this module will say "not running"
//! about a broker that really is running, if the record was lost. It will not
//! say "running" about something that is not the broker. That is the way round
//! it has to fail.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One running — or once running — broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Run {
    /// The box this run serves, from its config.
    pub box_id: String,
    /// The run workspace. Canonical, because it is the key.
    pub workspace: PathBuf,
    /// The config `sluse start` generated and the broker loaded.
    pub config: PathBuf,
    /// What the endpoint dials. From the generated config, so this is the URL
    /// the pin was written for.
    pub url: String,
    /// What the broker bound.
    pub listen: String,
    pub pid: u32,
    /// The broker process's creation time, as the kernel reports it. Half of
    /// the identity; see the module note.
    pub pid_created: u64,
    pub started: DateTime<Utc>,
    /// Where the broker's stderr goes.
    pub log: PathBuf,
}

impl Run {
    /// Whether the recorded process is still the process that was recorded.
    ///
    /// False for a pid that has gone, and false for a pid that has been reused
    /// by something else. Never true for a process this run did not start.
    pub fn alive(&self) -> bool {
        match process_created(self.pid) {
            Some(created) => created == self.pid_created,
            None => false,
        }
    }

    /// How long it has been up, in human terms. `None` if it is not.
    pub fn uptime(&self) -> Option<chrono::Duration> {
        self.alive().then(|| Utc::now() - self.started)
    }
}

// ---------------------------------------------------------------------------
// Where things live
// ---------------------------------------------------------------------------

/// `%LOCALAPPDATA%\Sluse` on the host, `$XDG_STATE_HOME/sluse` on the guest.
///
/// Falls back to the temporary directory if neither variable is set, which on
/// Windows means a service account with no profile. A lifecycle CLI that
/// refused to run there would be refusing over a directory name.
///
/// The unix arm is D-011. `/tmp/Sluse` would have worked and would have been
/// wrong in the way that matters on a development guest: `/tmp` is cleared on
/// reboot, and a run record that disappears leaves a broker this module then
/// reports as not running — the one thing it promises never to do backwards.
/// State, not cache, so `state` rather than `config` or `share`.
pub fn dir() -> PathBuf {
    #[cfg(windows)]
    {
        match std::env::var_os("LOCALAPPDATA") {
            Some(base) => PathBuf::from(base).join("Sluse"),
            None => std::env::temp_dir().join("Sluse"),
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(base) = std::env::var_os("XDG_STATE_HOME") {
            PathBuf::from(base).join("sluse")
        } else if let Some(home) = std::env::var_os("HOME") {
            PathBuf::from(home).join(".local/state/sluse")
        } else {
            std::env::temp_dir().join("Sluse")
        }
    }
}

pub fn runs_dir() -> PathBuf {
    dir().join("runs")
}

pub fn logs_dir() -> PathBuf {
    dir().join("logs")
}

/// A stable file name for a workspace.
///
/// The hash keys it — two workspaces with the same last segment are common, and
/// `run` or `scored` is exactly the name they would collide on — and the segment
/// is appended so the directory can be read by a person.
pub fn key(workspace: &Path) -> String {
    let canonical = workspace
        .canonicalize()
        .map(|p| crate::run::plain(&p))
        .unwrap_or_else(|_| workspace.to_path_buf());
    // Case-insensitively on Windows, because its paths are and a record written
    // from `C:\x` must be found again from `c:\X`. Not on the guest, where
    // `~/runs/A` and `~/runs/a` are two workspaces and folding them would file
    // one run's record over another's. Same reasoning as `scope::fold`, and the
    // same `cfg!` rather than an unconditional `to_lowercase`.
    let lossy = canonical.to_string_lossy();
    let text = if cfg!(windows) { lossy.to_lowercase() } else { lossy.into_owned() };
    let digest = Sha256::digest(text.as_bytes());
    let short: String = format!("{digest:x}").chars().take(8).collect();
    let name: String = canonical
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "run".to_owned())
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' })
        .collect();
    format!("{short}-{name}")
}

pub fn record_path(workspace: &Path) -> PathBuf {
    runs_dir().join(format!("{}.json", key(workspace)))
}

pub fn log_path(workspace: &Path) -> PathBuf {
    logs_dir().join(format!("{}.log", key(workspace)))
}

// ---------------------------------------------------------------------------
// Reading and writing
// ---------------------------------------------------------------------------

pub fn save(run: &Run) -> std::io::Result<PathBuf> {
    let path = record_path(&run.workspace);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = serde_json::to_string_pretty(run)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    std::fs::write(&path, body)?;
    Ok(path)
}

/// The record for a workspace, if there is one that parses.
///
/// A record that will not parse is treated as absent rather than as an error: it
/// is a file this tool wrote and can write again, and the alternative is a
/// `status` that fails instead of reporting.
pub fn load(workspace: &Path) -> Option<Run> {
    let text = std::fs::read_to_string(record_path(workspace)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn forget(workspace: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(record_path(workspace)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Every record in the state directory, newest first.
pub fn all() -> Vec<Run> {
    let mut runs: Vec<Run> = match std::fs::read_dir(runs_dir()) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|x| x == "json"))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .filter_map(|t| serde_json::from_str(&t).ok())
            .collect(),
        Err(_) => Vec::new(),
    };
    // Newest first, so a person who just started something sees it at the top.
    runs.sort_by_key(|r: &Run| std::cmp::Reverse(r.started));
    runs
}

// ---------------------------------------------------------------------------
// The process
// ---------------------------------------------------------------------------

/// The creation time of a pid, as a raw `FILETIME`, or `None` if there is no
/// such process or it cannot be opened.
///
/// `PROCESS_QUERY_LIMITED_INFORMATION` rather than `PROCESS_QUERY_INFORMATION`:
/// the stronger right is refused across integrity levels, and a `status` that
/// could not see its own elevated broker would report it as dead.
#[cfg(windows)]
fn process_created(pid: u32) -> Option<u64> {
    use windows::Win32::Foundation::{CloseHandle, FILETIME};
    use windows::Win32::System::Threading::{
        GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    // SAFETY: the handle is closed on every path out, and the four FILETIMEs are
    // owned locals that outlive the call.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut creation = FILETIME::default();
        let mut exit = FILETIME::default();
        let mut kernel = FILETIME::default();
        let mut user = FILETIME::default();
        let ok = GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user).is_ok();
        let _ = CloseHandle(handle);
        if !ok {
            return None;
        }
        Some((creation.dwHighDateTime as u64) << 32 | creation.dwLowDateTime as u64)
    }
}

/// The unix twin: the start time of a pid in clock ticks since boot, or `None`
/// if there is no such process (D-011).
///
/// Field 22 of `/proc/<pid>/stat` is `starttime`, written by the kernel when the
/// task was created. It answers the same question `GetProcessTimes` does and it
/// cannot be guessed at or collided with: two processes that share a pid always
/// differ here, because the second one started after the first exited.
///
/// The unit differs from Windows' 100-nanosecond FILETIME, and that is fine:
/// the value is only ever compared with another reading of itself on the same
/// machine. It is never serialised as a duration and never shown to a person.
#[cfg(unix)]
fn process_created(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    starttime_field(&stat)
}

/// Pull `starttime` out of a `/proc/<pid>/stat` line.
///
/// Split out from the read, and compiled on every platform, so the parse is
/// covered by the host's test run as well as the guest's. The impure half is
/// one `read_to_string` above; this is where anything can go wrong.
///
/// **The parse starts after the last `)`, not by splitting from the left.**
/// Field 2 is the executable name in parentheses and it is not escaped: a
/// process may legally be called `foo bar)baz`, and a naive split shifts every
/// later field so the comparison silently starts reading a different number.
/// That is the failure this function exists to prevent rather than cause — a
/// wrong field compares unequal, `alive()` says no, and `sluse status` reports
/// a running broker as dead.
// Dead on the host, where nothing but the tests calls it. That is the point:
// compiling it there is how the host's run covers the guest's parse.
#[cfg_attr(not(unix), allow(dead_code))]
fn starttime_field(stat: &str) -> Option<u64> {
    let after_comm = stat.get(stat.rfind(')')? + 1..)?;
    // Field 3 (`state`) is the first token after the name, so `starttime` —
    // field 22 — is the 20th from here.
    after_comm.split_whitespace().nth(19)?.parse().ok()
}

/// This process's own creation time, for the record written just after a spawn.
pub fn created_of(pid: u32) -> Option<u64> {
    process_created(pid)
}

/// Ask a process to stop, then make sure it has.
///
/// There is no `SIGTERM` here. A console-attached child could be sent
/// `CTRL_BREAK_EVENT`, but the broker is started detached precisely so that
/// closing the terminal does not take it down, and a detached process is not in
/// the caller's console group. So this is `TerminateProcess`, and the thing that
/// makes it safe is not the signal but the identity check: the pid is only
/// touched after its creation time has matched the record.
///
/// The cost is stated rather than hidden: the broker does not get to run a
/// shutdown path. It does not need one — the audit sink holds no handle between
/// records and every record is flushed as it is written (`audit.rs`) — but if it
/// ever does, this is the line that has to change.
#[cfg(windows)]
pub fn terminate(run: &Run) -> std::io::Result<bool> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    };

    if !run.alive() {
        return Ok(false);
    }

    // SAFETY: the handle is closed on both paths.
    unsafe {
        let handle =
            OpenProcess(PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION, false, run.pid)
                .map_err(std::io::Error::other)?;
        let result = TerminateProcess(handle, 1);
        let _ = CloseHandle(handle);
        result.map_err(std::io::Error::other)?;
    }
    Ok(true)
}

/// The unix twin (D-011).
///
/// `SIGKILL`, not `SIGTERM`, to match what the Windows path actually does: the
/// broker is started detached on both platforms and gets no shutdown path on
/// either, so a guest that stopped politely and a host that did not would be two
/// behaviours to reason about instead of one. The safety is the same and it is
/// not the signal: `alive()` has already matched the recorded start time, so the
/// pid is known to still be the process that was recorded.
///
/// Racing is bounded the same way as on Windows. Between `alive()` and `kill`
/// the process could exit and the pid be reused, but the window is the width of
/// two syscalls and the loser would have to be a pid allocated in it. Windows
/// has the identical gap between `OpenProcess` and `TerminateProcess`; neither
/// platform offers the atomic version, and pidfd is too new to assume on a guest
/// whose kernel the developer picks.
#[cfg(unix)]
pub fn terminate(run: &Run) -> std::io::Result<bool> {
    if !run.alive() {
        return Ok(false);
    }

    // SAFETY: `kill` takes no pointer and allocates nothing. A pid that has gone
    // returns ESRCH, which is reported rather than swallowed.
    let rc = unsafe { libc::kill(run.pid as libc::pid_t, libc::SIGKILL) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(key(dir.path()), key(dir.path()));
    }

    #[cfg(windows)]
    #[test]
    fn a_key_is_case_insensitive_on_the_host() {
        let dir = tempfile::tempdir().unwrap();
        let shouted = PathBuf::from(dir.path().to_string_lossy().to_uppercase());
        assert_eq!(
            key(&shouted),
            key(dir.path()),
            "Windows paths are case-insensitive and the key must be too"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_key_is_case_sensitive_on_the_guest() {
        // Two real, distinct directories, because on a case-sensitive filesystem
        // they are two workspaces. Folding them would file one run's record over
        // the other's and `sluse stop` would then stop the wrong broker.
        let dir = tempfile::tempdir().unwrap();
        let lower = dir.path().join("run");
        let upper = dir.path().join("RUN");
        std::fs::create_dir(&lower).unwrap();
        std::fs::create_dir(&upper).unwrap();
        assert_ne!(key(&lower), key(&upper));
    }

    // The `/proc` parse, tested on both platforms although only the guest calls
    // it: the host's run is the one that happens on every change (D-011).
    //
    // The samples are real `/proc/<pid>/stat` shapes truncated after field 22 —
    // everything past `starttime` is ignored by the parse and would only be
    // noise here.
    #[test]
    fn starttime_is_field_22() {
        let stat = "1234 (broker) S 1 1234 1234 0 -1 4194560 1200 0 0 0 5 3 0 0 \
                    20 0 8 0 987654321 ";
        assert_eq!(starttime_field(stat), Some(987_654_321));
    }

    #[test]
    fn a_process_name_with_spaces_and_a_bracket_does_not_shift_the_fields() {
        // Linux does not escape field 2, and this is a name a process may
        // legally have. Splitting from the left reads `0` here instead, which
        // compares unequal and reports a live broker as dead.
        let stat = "1234 (od d) na me) S 1 1234 1234 0 -1 4194560 1200 0 0 0 5 3 0 0 \
                    20 0 8 0 987654321 ";
        assert_eq!(starttime_field(stat), Some(987_654_321));
    }

    #[test]
    fn a_truncated_stat_line_is_none_not_a_wrong_number() {
        assert_eq!(starttime_field("1234 (broker) S 1 1234"), None);
        assert_eq!(starttime_field(""), None);
        assert_eq!(starttime_field("nonsense with no bracket"), None);
    }

    #[test]
    fn two_workspaces_with_the_same_name_get_different_keys() {
        let root = tempfile::tempdir().unwrap();
        let one = root.path().join("a").join("scored");
        let two = root.path().join("b").join("scored");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        assert_ne!(key(&one), key(&two));
        // Both still readable by a person.
        assert!(key(&one).ends_with("-scored"));
    }

    #[test]
    fn this_process_is_alive_and_a_pid_that_is_not_ours_is_not() {
        let pid = std::process::id();
        let created = created_of(pid).expect("a process can see its own creation time");

        let run = Run {
            box_id: "box-test".to_owned(),
            workspace: PathBuf::from("."),
            config: PathBuf::from("sluse.json"),
            url: "https://127.0.0.1:7580".to_owned(),
            listen: "127.0.0.1:7580".to_owned(),
            pid,
            pid_created: created,
            started: Utc::now(),
            log: PathBuf::from("broker.log"),
        };
        assert!(run.alive());

        // The same pid with a creation time that is not this process's. This is
        // the pid-reuse case, and it is the one that must not pass.
        let reused = Run { pid_created: created.wrapping_add(1), ..run };
        assert!(!reused.alive(), "a reused pid must not be mistaken for the recorded process");
    }

    #[test]
    fn a_record_round_trips_and_can_be_forgotten() {
        // This writes into the real state directory, which is correct: the key
        // is a hash of a temporary path, so it collides with nothing, and the
        // record is forgotten again below.
        let temp = tempfile::tempdir().unwrap();
        let workspace = temp.path().join("run");
        std::fs::create_dir_all(&workspace).unwrap();

        let run = Run {
            box_id: "box-local".to_owned(),
            workspace: workspace.canonicalize().unwrap(),
            config: workspace.join("sluse.json"),
            url: "https://127.0.0.1:7580".to_owned(),
            listen: "127.0.0.1:7580".to_owned(),
            pid: 4,
            pid_created: 12345,
            started: Utc::now(),
            log: workspace.join("broker.log"),
        };

        save(&run).unwrap();
        let back = load(&workspace).expect("the record just written is readable");
        assert_eq!(back.box_id, "box-local");
        assert_eq!(back.pid_created, 12345);
        assert!(!back.alive(), "pid 4 was not created at 12345");

        forget(&workspace).unwrap();
        assert!(load(&workspace).is_none());
        // Forgetting twice is not an error: `stop` calls it on a run that may
        // already have been stopped.
        forget(&workspace).unwrap();
    }
}

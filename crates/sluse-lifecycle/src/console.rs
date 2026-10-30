// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The box's serial console, copied to the host (D-030): what the box says
//! about itself from boot on, including before enrolment and before its
//! screen is up, for the device's administrators.
//!
//! Hyper-V serves the box's COM1 on a named pipe; the service is its only
//! reader and never writes to it. The copy goes to
//! `boxes\<sid>\console.log`, beside the journal's mirror, so a wipe keeps
//! it. Like the mirror it is what the box said, not a trust anchor.
//!
//! **The console's answer (Q9).** The box's kiosk logs [`CONSOLE_UP`] once
//! its console's port answers, and the copy watches for it, so the shell can
//! keep its wait over the box until then. The box can say it falsely or not
//! at all; either way it only decides when the box's own picture is shown.

use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

/// The most one file holds; one older file is kept beside it.
pub const CAP: u64 = 16 << 20;
/// How long the pipe may be missing before the box counts as off. A reboot
/// inside the box keeps it; a stop takes it away.
const GRACE: Duration = Duration::from_secs(60);

/// What the box's kiosk logs when its console's port answers
/// (`packaging/box/kiosk/browser`, forwarded by `console-log`).
pub const CONSOLE_UP: &[u8] = b"sluse-console-up";

/// A login prompt on the serial console: `install.sh` masks that getty, so
/// only a box whose system never got Sluse shows it (L1, 2026-10-21: such a
/// box held its open for the full 600 s; D-066).
pub const NO_SLUSE: &[u8] = b"sluse-box login:";

/// What the endpoint prints when the box's enrolment failed for good
/// (`sluse-endpoint/src/main.rs`): the open has failed, and waiting on for
/// its console only hid that (L1, 2026-10-30: 791 restarts, no word).
pub const ENROL_FAILED: &[u8] = b"enrolment failed: ";

/// What the box says on its console that the service acts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Said {
    ConsoleUp,
    NoSluse,
    EnrolFailed,
}

const MARKERS: [(&[u8], Said); 3] = [(CONSOLE_UP, Said::ConsoleUp), (NO_SLUSE, Said::NoSluse), (ENROL_FAILED, Said::EnrolFailed)];

/// The cause on the last enrolment failure's line in `dir`'s console log.
/// ponytail: the log's last 64 kB, read when the window asks, a second at
/// most after the line came; enough while the box writes a line a second.
pub fn enrol_cause(dir: &Path) -> Option<String> {
    use std::io::{Seek, SeekFrom};
    let mut f = std::fs::File::open(dir.join("console.log")).ok()?;
    let len = f.metadata().ok()?.len();
    f.seek(SeekFrom::Start(len.saturating_sub(64 << 10))).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let marker = std::str::from_utf8(ENROL_FAILED).ok()?;
    let line = text.lines().rev().find(|l| l.contains(marker))?;
    Some(line[line.find(marker)? + marker.len()..].trim().to_owned())
}

pub fn pipe_name(vm: &str) -> String {
    format!(r"\\.\pipe\sluse-console-{vm}")
}

/// Follow the box's console until it has been gone for [`GRACE`], calling
/// `said` each time the box says one of the [`Said`] things.
///
/// The pipe has one slot, and while the service holds it nobody else can
/// open it. Hyper-V's default DACL lets **Everyone read** (L1, 2026-09-30),
/// so at every attach the service also takes that off (`admins_only`): the
/// log is for administrators (D-030 point 4). What remains is the moment
/// between a box starting and the first attach, which the fast retry keeps
/// short.
pub fn follow(pipe: &str, dir: &Path, said: &mut dyn FnMut(Said)) {
    let mut gone = Instant::now();
    while gone.elapsed() < GRACE {
        match open(pipe) {
            Ok(f) => {
                #[cfg(windows)]
                if let Err(e) = crate::winsys::pipe_admins_only(&f) {
                    crate::service::note(format_args!("{pipe}: Everyone's read not taken off: {e}"));
                }
                if let Err(e) = copy(f, dir, CAP, said) {
                    crate::service::note(format_args!("{}: {e}", dir.join("console.log").display()));
                }
                gone = Instant::now();
            }
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// The build VM's console for one build (D-063): `dir\console.log` started
/// afresh, from the first open of the pipe until the VM stops it. `stop`
/// ends the wait for a pipe that never opened.
pub fn record(pipe: &str, dir: &Path, stop: &std::sync::atomic::AtomicBool) -> io::Result<()> {
    for f in ["console.log", "console.1.log"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    loop {
        match open(pipe) {
            Ok(f) => {
                #[cfg(windows)]
                if let Err(e) = crate::winsys::pipe_admins_only(&f) {
                    crate::service::note(format_args!("{pipe}: Everyone's read not taken off: {e}"));
                }
                return copy(f, dir, CAP, &mut |_| {});
            }
            Err(_) if stop.load(std::sync::atomic::Ordering::Relaxed) => return Ok(()),
            Err(_) => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// What the build says of itself as its last act (`user-data.yaml`): a line
/// `SLUSE-BUILD-OK`, or `SLUSE-BUILD-FAILED: <what is missing>`. No line at
/// all is a failure too: a base is kept only when the build said it is whole.
pub fn verdict(console: &str) -> Result<(), String> {
    for line in console.lines().map(str::trim) {
        if line == "SLUSE-BUILD-OK" {
            return Ok(());
        }
        if let Some(missing) = line.strip_prefix("SLUSE-BUILD-FAILED:") {
            return Err(format!("missing:{missing}"));
        }
    }
    Err("the build did not say whether it finished".into())
}

/// Read, and on Windows the right to read and rewrite the pipe's DACL.
fn open(pipe: &str) -> io::Result<std::fs::File> {
    let mut o = std::fs::OpenOptions::new();
    o.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // FILE_GENERIC_READ (READ_CONTROL included) | WRITE_DAC.
        o.access_mode(0x0012_0089 | 0x0004_0000);
    }
    o.open(pipe)
}

/// A DACL in SDDL with every entry dropped whose trustee is not SYSTEM,
/// Administrators, Hyper-V Administrators, a VM's own SID (`S-1-5-83-`) or a
/// capability (`S-1-15-3-`). An allowlist, so a default Windows adds later is
/// dropped too. The VM's SID stays so Hyper-V can still serve the pipe.
pub fn admins_only(sddl: &str) -> String {
    let (head, aces) = sddl.split_at(sddl.find('(').unwrap_or(sddl.len()));
    let kept: String = aces
        .split_inclusive(')')
        .filter(|ace| {
            let sid = ace.trim_end_matches(')').rsplit(';').next().unwrap_or("");
            matches!(sid, "SY" | "BA" | "HA") || sid.starts_with("S-1-5-83-") || sid.starts_with("S-1-15-3-")
        })
        .collect();
    format!("{head}{kept}")
}

fn stopped(e: &io::Error) -> bool {
    cfg!(windows) && e.raw_os_error() == Some(233)
}

/// Append everything `src` gives to `dir\console.log` until it ends. A file
/// that would pass `cap` becomes `console.1.log`, replacing the one before.
/// `said` is called when a read brings one of the [`MARKERS`], one split
/// across two reads included.
pub fn copy(mut src: impl Read, dir: &Path, cap: u64, said: &mut dyn FnMut(Said)) -> io::Result<()> {
    let longest = MARKERS.iter().map(|(m, _)| m.len()).max().unwrap_or(1);
    std::fs::create_dir_all(dir)?;
    let (log, old) = (dir.join("console.log"), dir.join("console.1.log"));
    let open = || std::fs::OpenOptions::new().create(true).append(true).open(&log);
    let mut out = open()?;
    let mut buf = [0u8; 8192];
    // The last bytes of the reads before, so a marker split across two reads
    // is still seen; never a whole marker, so none is seen twice.
    let mut tail: Vec<u8> = Vec::new();
    loop {
        let n = match src.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            // The box stopped: Hyper-V closed its end. Windows says that as
            // a broken pipe, or as `ERROR_PIPE_NOT_CONNECTED` (233), which
            // `std` does not map and which was logged at every stop.
            Err(e) if e.kind() == io::ErrorKind::BrokenPipe || stopped(&e) => return Ok(()),
            Err(e) => return Err(e),
        };
        if out.metadata()?.len() + n as u64 > cap {
            drop(out);
            std::fs::rename(&log, &old)?;
            out = open()?;
        }
        out.write_all(&buf[..n])?;
        tail.extend_from_slice(&buf[..n]);
        let mut seen = false;
        for (marker, what) in MARKERS {
            if tail.windows(marker.len()).any(|w| w == marker) {
                said(what);
                seen = true;
            }
        }
        if seen {
            tail.clear();
        } else {
            tail.drain(..tail.len().saturating_sub(longest - 1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_admins_and_the_vm_keep_their_entries() {
        // The DACL measured on L1, 2026-09-30.
        let l1 = "D:(A;;FR;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;HA)(A;;FA;;;S-1-5-83-1-1710232228-1244314470-870448543-362023475)(A;;FA;;;S-1-15-3-1024-2268835264)";
        assert_eq!(
            admins_only(l1),
            "D:(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;HA)(A;;FA;;;S-1-5-83-1-1710232228-1244314470-870448543-362023475)(A;;FA;;;S-1-15-3-1024-2268835264)"
        );
        // Anonymous, Authenticated Users, Users and a named user go too; the
        // DACL's own flags stay.
        assert_eq!(
            admins_only("D:P(A;;FR;;;AN)(A;;FR;;;AU)(A;;FR;;;BU)(A;;FR;;;S-1-5-21-1-2-3-1001)(A;;FA;;;SY)"),
            "D:P(A;;FA;;;SY)"
        );
    }

    #[test]
    fn a_base_is_kept_only_when_the_build_says_it_is_whole() {
        assert_eq!(verdict("[  OK  ] Started x\r\nSLUSE-BUILD-OK\r\n[ 99.1] reboot: Power down"), Ok(()));
        assert_eq!(verdict("SLUSE-BUILD-FAILED: Sluse Codex\nE: Unable to locate package sway").unwrap_err(), "missing: Sluse Codex");
        // The 2026-10-21 box: no line at all, which is not a pass.
        assert!(verdict("sluse-box login: \n[ 608.5] reboot: Power down").is_err());
        // Only a whole line counts.
        assert!(verdict("echo SLUSE-BUILD-OK > /dev/ttyS0").is_err());
    }

    #[test]
    fn the_copy_appends_and_keeps_one_older_file_at_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        copy(&b"boot one\n"[..], dir.path(), 16, &mut |_| {}).unwrap();
        copy(&b"boot two\n"[..], dir.path(), 16, &mut |_| {}).unwrap();
        // 18 bytes would pass 16: the first file moves aside.
        assert_eq!(std::fs::read(dir.path().join("console.1.log")).unwrap(), b"boot one\n");
        assert_eq!(std::fs::read(dir.path().join("console.log")).unwrap(), b"boot two\n");
        copy(&b"three\n"[..], dir.path(), 16, &mut |_| {}).unwrap();
        assert_eq!(std::fs::read(dir.path().join("console.log")).unwrap(), b"boot two\nthree\n");
    }

    /// The box says the marker the copy looks for, and its log carries it.
    #[test]
    fn the_box_says_the_consoles_answer_in_the_words_the_copy_looks_for() {
        let marker = std::str::from_utf8(CONSOLE_UP).unwrap();
        assert!(include_str!("../../../packaging/box/kiosk/browser").contains(&format!("logger -t {marker} ")));
        assert!(include_str!("../../../packaging/box/kiosk/console-log").contains(&format!("SYSLOG_IDENTIFIER={marker} ")));
    }

    /// One byte per read: the hardest split there is.
    struct Trickle<'a>(&'a [u8]);
    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let Some((first, rest)) = self.0.split_first() else { return Ok(0) };
            buf[0] = *first;
            self.0 = rest;
            Ok(1)
        }
    }

    #[test]
    fn the_consoles_answer_is_seen_whole_or_split_across_reads() {
        let dir = tempfile::tempdir().unwrap();
        let log = b"2026-10-20T10:00:01 sluse-box sluse-console-up[812]: the console answers on 7582\n";
        let count = |src: &mut dyn Read| {
            let mut n = 0;
            copy(src, dir.path(), CAP, &mut |s| n += usize::from(s == Said::ConsoleUp)).unwrap();
            n
        };
        assert_eq!(count(&mut &log[..]), 1);
        assert_eq!(count(&mut Trickle(log)), 1, "split across reads");
        let twice = [&log[..], &log[..]].concat();
        assert_eq!(count(&mut Trickle(&twice)), 2, "a kiosk that started again says it again");
        assert_eq!(count(&mut &b"Started sluse-console.service\nsluse-console-u\n"[..]), 0);
        assert!(std::fs::read(dir.path().join("console.log")).unwrap().ends_with(b"sluse-console-u\n"), "copied as it came");
        // A login prompt, split across reads: the box without Sluse (D-066).
        let mut no = 0;
        copy(&mut Trickle(b"Ubuntu 26.04.1 LTS sluse-box ttyS0\n\nsluse-box login: "), dir.path(), CAP, &mut |s| no += usize::from(s == Said::NoSluse)).unwrap();
        assert_eq!(no, 1);
    }

    #[test]
    fn an_enrolment_that_failed_is_seen_with_its_cause() {
        let dir = tempfile::tempdir().unwrap();
        let log = b"2026-10-30T10:25:54+01:00 sluse-box sluse-endpoint[1270]: enrolment failed: the Gate's config: unknown field `vibe`\n";
        let mut n = 0;
        copy(&mut Trickle(log), dir.path(), CAP, &mut |s| n += usize::from(s == Said::EnrolFailed)).unwrap();
        assert_eq!(n, 1);
        assert_eq!(enrol_cause(dir.path()).as_deref(), Some("the Gate's config: unknown field `vibe`"));
        assert!(include_str!("../../sluse-endpoint/src/main.rs").contains(r#"eprintln!("enrolment failed: {e}")"#), "the words the endpoint prints");
    }
}

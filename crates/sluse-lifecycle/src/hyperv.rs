// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Hyper-V, through `packaging/box/sluse-box.ps1` (D-027 design point 1).
//!
//! The script is compiled in and handed to Windows PowerShell 5.1 in an
//! environment variable, with its arguments as JSON in another, so nothing is
//! spliced into a command line and AllSigned policy does not refuse it. See
//! the script's header.
//!
//! `ponytail:` about a second of PowerShell start-up per call; move to WMI
//! from Rust if open times ever matter at that grain.

use std::io::Read;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use sluse_proto::pipe::BoxState;

const SCRIPT: &str = include_str!("../../../packaging/box/sluse-box.ps1");

pub struct HyperV {
    script: String,
}

impl HyperV {
    pub fn embedded() -> Self {
        HyperV { script: SCRIPT.to_owned() }
    }

    /// The same runner with a different script: the Windows tests' fake
    /// Hyper-V.
    #[cfg(test)]
    pub fn with_script(script: &str) -> Self {
        HyperV { script: script.to_owned() }
    }

    pub fn call(&self, args: Value) -> Result<Value, String> {
        self.call_within(args, None)
    }

    /// [`call`](Self::call), stopped when `within` runs out: a step past its
    /// limit stops and says why (Q21). PowerShell is ended; what it had asked
    /// of Hyper-V may still finish, and the step's next try starts over.
    pub fn call_within(&self, args: Value, within: Option<Duration>) -> Result<Value, String> {
        let mut cmd = Command::new(powershell());
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", "& ([scriptblock]::Create($env:SLUSE_BOX_PS))"])
            .env("SLUSE_BOX_PS", &self.script)
            .env("SLUSE_BOX_ARGS", args.to_string());
        let out = output_within(&mut cmd, within).map_err(|e| match e {
            Ran::NotStarted(e) => format!("Windows PowerShell did not start: {e}"),
            Ran::TimedOut(w) => format!("Hyper-V did not finish {} within {} s", args["verb"].as_str().unwrap_or("its call"), w.as_secs()),
        })?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err = err.trim();
            return Err(err.chars().take(600).collect());
        }
        let stdout = String::from_utf8_lossy(&out.stdout);
        let line = stdout.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("");
        serde_json::from_str(line).map_err(|e| format!("Hyper-V script said {line:?}: {e}"))
    }

    pub fn state(&self, vm: &str) -> Result<BoxState, String> {
        let v = self.call(json!({ "verb": "state", "vm": vm }))?;
        match v["state"].as_str() {
            Some("none") => Ok(BoxState::None),
            Some("off") => Ok(BoxState::Off),
            Some("running") => Ok(BoxState::Running),
            _ => Err(format!("Hyper-V script said {v}")),
        }
    }

    pub fn start(&self, vm: &str, within: Option<Duration>) -> Result<(), String> {
        self.call_within(json!({ "verb": "start", "vm": vm, "pipe": crate::console::pipe_name(vm) }), within).map(drop)
    }

    /// Shut `vm` down, and turn it off if it has not finished within
    /// `within`. True when it had to be turned off.
    pub fn stop(&self, vm: &str, within: std::time::Duration) -> Result<bool, String> {
        let v = self.call(json!({ "verb": "stop", "vm": vm, "seconds": within.as_secs() }))?;
        Ok(v["turnedOff"].as_bool().unwrap_or(false))
    }

    /// Write `items` into the VM's KVP pool, in order, in one call: the
    /// theme and the bootstrap at an open (Q70).
    pub fn kvp(&self, vm: &str, items: &[(&str, &str)]) -> Result<(), String> {
        let items: Vec<Value> = items.iter().map(|(k, v)| json!({ "key": k, "value": v })).collect();
        self.call(json!({ "verb": "kvp", "vm": vm, "items": items })).map(drop)
    }
}

/// Why [`output_within`] has no output.
#[derive(Debug)]
enum Ran {
    NotStarted(std::io::Error),
    TimedOut(Duration),
}

/// `cmd`'s output, as `Command::output` gives it, unless `within` runs out
/// first: the process is then killed. Its pipes are read on their own
/// threads, so a chatty process cannot block on a full one meanwhile.
fn output_within(cmd: &mut Command, within: Option<Duration>) -> Result<Output, Ran> {
    let mut child =
        cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(Ran::NotStarted)?;
    fn drain(pipe: Option<impl Read + Send + 'static>) -> std::thread::JoinHandle<Vec<u8>> {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut p) = pipe {
                let _ = p.read_to_end(&mut buf);
            }
            buf
        })
    }
    let (stdout, stderr) = (drain(child.stdout.take()), drain(child.stderr.take()));
    let deadline = within.map(|w| Instant::now() + w);
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if deadline.is_some_and(|d| Instant::now() >= d) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Ran::TimedOut(within.unwrap_or_default()));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => return Err(Ran::NotStarted(e)),
        }
    };
    Ok(Output { status, stdout: stdout.join().unwrap_or_default(), stderr: stderr.join().unwrap_or_default() })
}

/// By its full path: a service running as SYSTEM does not look anything up
/// on `PATH`.
fn powershell() -> std::path::PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into());
    std::path::Path::new(&root).join(r"System32\WindowsPowerShell\v1.0\powershell.exe")
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;

    /// The limit, on the guest's own shell: an answer within it is the
    /// output; one past it is a stop, well before the process would end.
    #[test]
    fn a_call_past_its_limit_is_stopped_and_one_within_it_answers() {
        let out = output_within(Command::new("sh").args(["-c", "echo out; echo err >&2"]), Some(Duration::from_secs(10))).unwrap();
        assert!(out.status.success());
        assert_eq!((out.stdout.as_slice(), out.stderr.as_slice()), (&b"out\n"[..], &b"err\n"[..]));
        let started = Instant::now();
        let e = output_within(Command::new("sleep").arg("30"), Some(Duration::from_millis(200))).unwrap_err();
        assert!(matches!(e, Ran::TimedOut(_)), "{e:?}");
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(matches!(output_within(&mut Command::new("/nonexistent/sluse"), None), Err(Ran::NotStarted(_))));
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    /// The real transport with a fake Hyper-V: the script arrives, its JSON
    /// arguments arrive intact, and a throw comes back as an error.
    #[test]
    fn the_script_and_its_arguments_reach_powershell_and_errors_come_back() {
        let fake = r#"
            $ErrorActionPreference = 'Stop'
            [Console]::OutputEncoding = [Text.Encoding]::UTF8
            $a = $env:SLUSE_BOX_ARGS | ConvertFrom-Json
            if ($a.verb -eq 'state') { @{ state = 'running'; saw = $a.vm } | ConvertTo-Json -Compress }
            elseif ($a.verb -eq 'kvp') { @{ sent = $a.value } | ConvertTo-Json -Compress }
            else { throw "fake refuses $($a.verb)" }
        "#;
        let h = HyperV::with_script(fake);
        assert_eq!(h.state("sluse-box").unwrap(), BoxState::Running);
        let v = h.call(json!({ "verb": "kvp", "vm": "b", "value": "{\"a\":\"æøå $x `y\"}" })).unwrap();
        assert_eq!(v["sent"], "{\"a\":\"æøå $x `y\"}", "the value is not reinterpreted by PowerShell");
        let e = h.start("sluse-box", None).unwrap_err();
        assert!(e.contains("fake refuses start"), "{e}");
    }

    /// The embedded script refuses a VM name it would otherwise interpolate
    /// into a WMI filter.
    #[test]
    fn the_real_script_refuses_a_vm_name_that_is_not_one() {
        let e = HyperV::embedded().state("x' OR '1'='1").unwrap_err();
        assert!(e.contains("not a VM name"), "{e}");
    }
}

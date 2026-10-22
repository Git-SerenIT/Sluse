// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Bulk-admission alerting.
//!
//! **Detective, never preventive.** Everything counted here was admitted: the
//! scope said yes, the user's own rights said yes, and the bytes crossed. An
//! alert says a person should look. Nothing in this module stops an agent,
//! delays one, or refuses anything, and no document about Sluse may suggest
//! otherwise (`docs/threat-model.md`, the claim table: *admission volume,
//! detective only*).
//!
//! ## The semantics, and that they are provisional
//!
//! Per source: count **distinct content hashes** admitted inside a
//! sliding window of `windowSeconds`, and sum their bytes. At `admissions`
//! distinct hashes — or at `volume.bytes` bytes, when that is configured — if no
//! alert is open for that pair, one opens. It closes when **both** fall back
//! below their thresholds as the window slides. The alert names the session
//! whose admission tripped it.
//!
//! **Bytes arrived with D-016, and the first scored run is why.** Counting files
//! alone measured the wrong thing: one `fetch` moved a 500 MB file, 582 MB
//! crossed in the session, and the one alert raised described a rate of 25
//! files that had nothing to do with either. Bytes are summed over the same
//! distinct hashes, so the dedupe argument below applies unchanged, and the
//! threshold is absent by default — nothing measured yet says what the number
//! should be.
//!
//! Four choices in that sentence, none of them settled — `docs/config.md` lists
//! the threshold semantics as unspecified and the producer as undecided:
//!
//! - **Distinct hashes, not calls.** An agent that reads the same file twenty
//!   times is doing something inefficient, not something exfiltration-shaped.
//!   The same bytes twice is one admission's worth of material.
//! - **Per source.** Twenty files from one source is a pattern; one file from
//!   each of twenty sources is a session getting started.
//! - **Not per session (D-060).** One broker serves one box, so there are not
//!   two people to keep apart, and a session is something the box mints at
//!   will: keyed on it, a health call before each read put every file in a
//!   window of its own and no alert ever opened (review R-08). Until
//!   2026-10-15 the key was `(session, source)`, for "two people working at
//!   once" (jok, 2026-09-16), which the one-box broker no longer has.
//! - **One alert per crossing.** A window that sits above the threshold for a
//!   minute is one event, not sixty. Without this, the first thing anyone does
//!   with the alert feed is mute it.
//!
//! The floor under any threshold is S-2 finding 7: a first `fetch` of a Rust
//! crate was **12 files in 13 seconds**, and that is ordinary work. The LOCAL
//! default is 25 in 60 s.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use sluse_proto::{ContentHash, SessionId, SourceName, VolumeAlert, VolumeConfig};

/// One admission, as far as counting is concerned.
#[derive(Debug, Clone)]
struct Admission {
    at: DateTime<Utc>,
    hash: ContentHash,
    bytes: u64,
}

#[derive(Debug, Default)]
struct Window {
    events: VecDeque<Admission>,
    /// Index into [`VolumeMonitor::alerts`] of the alert currently open for this
    /// pair, if one is.
    open: Option<usize>,
}

/// What is in the window right now: distinct files, and their bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counted {
    pub files: u32,
    pub bytes: u64,
}

impl Window {
    /// Drop everything that has slid out, and count what is left.
    ///
    /// Both numbers dedupe on content hash: the same bytes admitted twice are
    /// one file and one file's worth of bytes, because an agent re-reading a
    /// file is being inefficient rather than taking more material.
    fn prune_and_count(&mut self, now: DateTime<Utc>, window: Duration) -> Counted {
        let cutoff = now - window;
        while self.events.front().is_some_and(|e| e.at <= cutoff) {
            self.events.pop_front();
        }
        let mut seen: Vec<&str> = Vec::with_capacity(self.events.len());
        let mut bytes = 0u64;
        for e in &self.events {
            let h = e.hash.as_str();
            if !seen.contains(&h) {
                seen.push(h);
                bytes = bytes.saturating_add(e.bytes);
            }
        }
        Counted { files: seen.len() as u32, bytes }
    }
}

/// Counts admissions and raises alerts.
///
/// The broker owns one and shares it across requests, so it locks internally
/// rather than making every call site hold a mutex it would otherwise forget.
#[derive(Debug)]
pub struct VolumeMonitor {
    config: VolumeConfig,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    windows: HashMap<SourceName, Window>,
    /// Every alert this broker has raised, open or closed, oldest first.
    /// `GET /v1/alerts?since=` reads it; nothing prunes it, because a run that
    /// raised enough alerts for this to matter has a bigger problem than memory.
    alerts: Vec<VolumeAlert>,
}

impl VolumeMonitor {
    pub fn new(config: VolumeConfig) -> Self {
        Self { config, state: Mutex::new(State::default()) }
    }

    fn window(&self) -> Duration {
        Duration::seconds(i64::from(self.config.window_seconds))
    }

    /// Record one admitted file.
    ///
    /// Returns the alert if this admission is the one that opened it, so the
    /// caller can write the `Alert` audit record. Returns `None` every other
    /// time, including while an alert is already open.
    ///
    /// Called **after** the admission is decided, never before: this is not a
    /// gate and must never be able to act like one.
    pub fn admit(
        &self,
        session: &SessionId,
        source: &SourceName,
        hash: &ContentHash,
        bytes: u64,
        now: DateTime<Utc>,
    ) -> Option<VolumeAlert> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let window = self.window();
        let entry = state.windows.entry(source.clone()).or_default();
        entry.events.push_back(Admission { at: now, hash: hash.clone(), bytes });
        let counted = entry.prune_and_count(now, window);
        let already_open = entry.open.is_some();

        let tripped = self.tripped(counted)?;
        if already_open {
            return None;
        }

        let alert = VolumeAlert {
            source: source.clone(),
            session_id: session.clone(),
            count: counted.files,
            bytes: counted.bytes,
            window_seconds: self.config.window_seconds,
            opened_at: now,
            closed_at: None,
            // The summary names what tripped, because "25 files" and "500 MB"
            // are different events and the summary is what a person reads first
            // — it is also the `pathRequested` of the `Alert` audit record.
            summary: match tripped {
                Tripped::Files => format!(
                    "{}/ ({} files, {} s)",
                    source.as_str(),
                    counted.files,
                    self.config.window_seconds
                ),
                Tripped::Bytes => format!(
                    "{}/ ({} bytes in {} files, {} s)",
                    source.as_str(),
                    counted.bytes,
                    counted.files,
                    self.config.window_seconds
                ),
            },
        };
        let index = state.alerts.len();
        state.alerts.push(alert.clone());
        state
            .windows
            .get_mut(source)
            .expect("just inserted")
            .open = Some(index);
        Some(alert)
    }

    /// Close any open alert whose window has drained below the threshold.
    ///
    /// Called by the alerts route rather than on a timer: an alert that closed
    /// while nobody was looking closed at the moment someone looked, and a timer
    /// in a prototype is a thread to shut down for no gain.
    pub fn sweep(&self, now: DateTime<Utc>) {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let window = self.window();
        let mut to_close = Vec::new();
        for entry in state.windows.values_mut() {
            let Some(index) = entry.open else { continue };
            // Both, not either: a window still over the byte threshold is still
            // the event that was raised, even if the file count has drained.
            if self.tripped(entry.prune_and_count(now, window)).is_none() {
                entry.open = None;
                to_close.push(index);
            }
        }
        for index in to_close {
            state.alerts[index].closed_at = Some(now);
        }
    }

    /// Alerts opened after `since`, or all of them.
    pub fn alerts(&self, since: Option<DateTime<Utc>>) -> Vec<VolumeAlert> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state
            .alerts
            .iter()
            .filter(|a| since.is_none_or(|s| a.opened_at > s))
            .cloned()
            .collect()
    }

    /// What is in the window right now. For tests and for the console's "why is
    /// this alert open" line.
    pub fn count(&self, source: &SourceName, now: DateTime<Utc>) -> Counted {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let window = self.window();
        state
            .windows
            .get_mut(source)
            .map(|w| w.prune_and_count(now, window))
            .unwrap_or_default()
    }

    /// Which threshold a window has crossed, if either. Files first, because a
    /// file count is what every threshold this project has discussed is in.
    fn tripped(&self, counted: Counted) -> Option<Tripped> {
        if counted.files >= self.config.admissions {
            return Some(Tripped::Files);
        }
        match self.config.bytes {
            Some(limit) if counted.bytes >= limit => Some(Tripped::Bytes),
            _ => None,
        }
    }
}

/// Which threshold opened an alert. Not on the wire: the summary says it in
/// words, and a second enum in the config view would need a schema version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tripped {
    Files,
    Bytes,
}


// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The sign-in window (D-075): for a few minutes the person opened from the
//! Sluse window, the box may reach `egress.window`'s hosts, Microsoft's
//! sign-in. Opened only on the control channel, which only the service can
//! write; asked by Front for each connection to such a host, and answered
//! here. Front may refuse; only Core may allow (D-071).
//!
//! Each opening and each closing is one record (1900), with the box, the
//! config, who opened it and until when; the closing one counts the
//! connections made in it, per host.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

/// The longest window the control channel may open. The service asks for
/// five minutes; nothing longer is taken, whatever is sent.
pub const MAX: Duration = Duration::from_secs(5 * 60);

type Write = Box<dyn Fn(&Value) + Send + Sync>;

pub struct Window {
    open: Mutex<Option<Open>>,
    /// The box and the config, on every record.
    about: Value,
    write: Write,
}

struct Open {
    by: String,
    until: Instant,
    until_utc: DateTime<Utc>,
    connections: BTreeMap<String, u64>,
}

impl Default for Window {
    fn default() -> Self {
        Window::new(json!({}), Box::new(|v| eprintln!("window: {v}")))
    }
}

impl Window {
    pub fn new(about: Value, write: Write) -> Self {
        Window { open: Mutex::new(None), about, write }
    }

    fn record(&self, fields: Value) {
        let mut r = self.about.clone();
        if let (Some(r), Some(f)) = (r.as_object_mut(), fields.as_object()) {
            r.insert("op".into(), "window".into());
            r.insert("ts".into(), json!(Utc::now()));
            r.extend(f.clone());
        }
        (self.write)(&r);
    }

    /// Open a window for `seconds`, at most [`MAX`], by `by`. One open now
    /// is closed first: each window is its own record, never extended.
    /// Zero seconds is the person's "Close it now": the open one closes and
    /// none opens.
    pub fn open(&self, by: &str, seconds: u32) -> Option<DateTime<Utc>> {
        let len = Duration::from_secs(u64::from(seconds)).min(MAX);
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(old) = open.take() {
            self.closed(old, if seconds == 0 { "closed by the person" } else { "replaced by a new window" });
        }
        if seconds == 0 {
            return None;
        }
        let until_utc = Utc::now() + chrono::Duration::from_std(len).unwrap_or_default();
        self.record(json!({ "outcome": "admitted", "state": "opened", "openedBy": by, "until": until_utc }));
        *open = Some(Open { by: by.to_owned(), until: Instant::now() + len, until_utc, connections: BTreeMap::new() });
        Some(until_utc)
    }

    /// Whether the box may reach `host` now; counted when it may. The host is
    /// one Front found on `egress.window`, and is checked here again.
    pub fn ask(&self, egress: &sluse_proto::EgressConfig, host: &str) -> bool {
        if !egress.in_window(host) {
            return false;
        }
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        self.close_if_due(&mut open);
        match open.as_mut() {
            Some(o) => {
                let host: String = host.trim_end_matches('.').to_ascii_lowercase().chars().take(253).collect();
                *o.connections.entry(host).or_default() += 1;
                true
            }
            None => false,
        }
    }

    /// Until when a window is open, if one is.
    pub fn until(&self) -> Option<DateTime<Utc>> {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        self.close_if_due(&mut open);
        open.as_ref().map(|o| o.until_utc)
    }

    /// Close a window whose time is up. Called each second, so its record
    /// is written when it ends, asked or not.
    pub fn tick(&self) {
        let mut open = self.open.lock().unwrap_or_else(|p| p.into_inner());
        self.close_if_due(&mut open);
    }

    /// Close one still open, when Gate Core stops.
    pub fn stop(&self) {
        if let Some(o) = self.open.lock().unwrap_or_else(|p| p.into_inner()).take() {
            self.closed(o, "Sluse stopped");
        }
    }

    fn close_if_due(&self, open: &mut Option<Open>) {
        if open.as_ref().is_some_and(|o| Instant::now() >= o.until) {
            if let Some(o) = open.take() {
                self.closed(o, "its time was up");
            }
        }
    }

    fn closed(&self, o: Open, why: &str) {
        self.record(json!({ "outcome": "admitted", "state": "closed", "why": why, "openedBy": o.by, "until": o.until_utc, "connections": o.connections }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn window() -> (Window, Arc<Mutex<Vec<Value>>>, sluse_proto::EgressConfig) {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let s = seen.clone();
        let w = Window::new(json!({ "boxId": "box-1" }), Box::new(move |v| s.lock().unwrap().push(v.clone())));
        let egress = sluse_proto::EgressConfig {
            allow: vec!["pypi.org".into()],
            window: vec!["login.microsoftonline.com".into()],
            ..Default::default()
        };
        (w, seen, egress)
    }

    #[test]
    fn closed_until_opened_then_open_for_window_hosts_only_and_counted() {
        let (w, seen, egress) = window();
        assert!(!w.ask(&egress, "login.microsoftonline.com"), "closed until the person opens it");
        assert!(w.until().is_none());
        w.open("S-1-12-1-1", 300);
        assert!(w.until().is_some());
        assert!(w.ask(&egress, "login.microsoftonline.com"));
        assert!(w.ask(&egress, "Login.MicrosoftOnline.com."));
        assert!(!w.ask(&egress, "pypi.org"), "a window opens its own hosts, nothing else");
        assert!(!w.ask(&egress, "evil.example"));
        w.stop();
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 2, "{seen:?}");
        assert_eq!((seen[0]["state"].as_str(), seen[0]["openedBy"].as_str(), seen[0]["boxId"].as_str()), (Some("opened"), Some("S-1-12-1-1"), Some("box-1")));
        assert_eq!(seen[1]["state"], "closed");
        assert_eq!(seen[1]["connections"]["login.microsoftonline.com"], 2);
        assert!(w.until().is_none());
    }

    #[test]
    fn it_closes_by_itself_when_its_time_is_up_and_is_never_longer_than_five_minutes() {
        let (w, seen, egress) = window();
        w.open("someone", 1);
        std::thread::sleep(Duration::from_millis(1100));
        w.tick();
        assert!(!w.ask(&egress, "login.microsoftonline.com"));
        assert_eq!(seen.lock().unwrap()[1]["why"], "its time was up");
        let until = w.open("someone", 86_400).unwrap();
        assert!(until <= Utc::now() + chrono::Duration::seconds(301), "capped at five minutes: {until}");
    }

    #[test]
    fn the_person_closes_it_early_and_nothing_opens() {
        let (w, seen, egress) = window();
        w.open("someone", 300);
        assert!(w.open("someone", 0).is_none());
        assert!(!w.ask(&egress, "login.microsoftonline.com"));
        assert_eq!(seen.lock().unwrap()[1]["why"], "closed by the person");
        assert!(w.open("someone", 0).is_none());
        assert_eq!(seen.lock().unwrap().len(), 2, "closing none writes nothing");
    }

    #[test]
    fn a_second_window_closes_the_first() {
        let (w, seen, _) = window();
        w.open("a", 300);
        w.open("b", 300);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.iter().map(|r| r["state"].as_str().unwrap()).collect::<Vec<_>>(), ["opened", "closed", "opened"]);
        assert_eq!(seen[1]["why"], "replaced by a new window");
    }
}

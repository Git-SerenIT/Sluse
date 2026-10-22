// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Sessions the broker issued.
//!
//! **The guest does not choose its own session id.** `/v1/health` mints one and
//! the caller carries it in `x-sluse-session` from then on; a session id the
//! broker did not issue is
//! [`UnknownSession`](sluse_proto::SluseError::UnknownSession).
//!
//! The reason was the volume monitor, which keyed its window on
//! `(session, source)` (jok, 2026-09-16). It no longer does (D-060): `/v1/health`
//! mints on every call, so a session was a threshold the box could reset after
//! all, one health call per read (review R-08). The window is per source now,
//! and a session ties records and a journal to one run, nothing more.
//!
//! ## What this is not
//!
//! Not authentication. The client certificate is what says the caller is the
//! endpoint, and mTLS is mandatory; this only says *which run* is asking. A
//! box can mint as many as it likes; the registry's cap bounds what is held.

use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Duration, Utc};
use sluse_proto::{LineageItem, SessionId, SluseError};

/// How long a session survives with nothing asking on it.
///
/// Long enough to outlast a working day's agent run with pauses in it, short
/// enough that an id copied out of a log yesterday is not a key today.
const DEFAULT_TTL_HOURS: i64 = 12;

/// How many sessions are kept at once.
///
/// `/v1/health` mints on every call and the lifecycle gate calls it to check the
/// broker is up, so unused sessions accumulate by design. The cap bounds that:
/// past it, the least recently used goes. A prototype talking to one endpoint
/// will never come near it.
const DEFAULT_CAP: usize = 256;

struct Entry {
    issued: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    /// What this broker admitted under the session, one entry per content
    /// hash, the latest admission of it: the lineage a publish record
    /// carries (D-059), the broker's own rather than the guest's.
    admitted: Vec<LineageItem>,
}

/// The sessions this broker has issued.
pub struct SessionRegistry {
    inner: Mutex<HashMap<String, Entry>>,
    ttl: Duration,
    cap: usize,
}

impl Default for SessionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self::with_limits(Duration::hours(DEFAULT_TTL_HOURS), DEFAULT_CAP)
    }

    /// For tests that need to watch a session age out without waiting twelve
    /// hours.
    pub fn with_limits(ttl: Duration, cap: usize) -> Self {
        Self { inner: Mutex::new(HashMap::new()), ttl, cap }
    }

    /// Issue a new session.
    ///
    /// A fresh one per `/v1/health` call, so health is not a way to reattach to
    /// a session somebody else is using.
    pub fn mint(&self, now: DateTime<Utc>) -> SessionId {
        let id = SessionId::mint();
        let mut map = self.lock();
        map.insert(id.as_str().to_owned(), Entry { issued: now, last_seen: now, admitted: Vec::new() });
        prune(&mut map, self.ttl, self.cap, now);
        id
    }

    /// Recognise a session id the caller presented, and mark it in use.
    ///
    /// The returned [`SessionId`] is built from the string that was recognised,
    /// so a caller cannot get a well-formed id past this by presenting something
    /// that merely *looks* like one: the map is the authority, not the grammar.
    pub fn recognise(&self, raw: &str, now: DateTime<Utc>) -> Result<SessionId, SluseError> {
        let mut map = self.lock();
        prune(&mut map, self.ttl, self.cap, now);
        match map.get_mut(raw) {
            Some(entry) => {
                entry.last_seen = now;
                Ok(SessionId::new_unchecked(raw))
            }
            // The same answer for a forged id, a typo and one that aged out.
            // Distinguishing them would tell a caller whether an id ever
            // existed, and nothing needs to know that.
            None => Err(SluseError::UnknownSession { session_id: raw.to_owned() }),
        }
    }

    /// How many sessions are held. For tests and for the console's state panel.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Note a completed admission under `raw` (D-059). A later admission of the
    /// same bytes replaces the earlier one, as the guest's lineage does.
    pub fn admit(&self, raw: &str, item: LineageItem) {
        if let Some(entry) = self.lock().get_mut(raw) {
            entry.admitted.retain(|l| l.hash != item.hash);
            entry.admitted.push(item);
        }
    }

    /// What this broker admitted under `raw`, oldest first; empty for a
    /// session it does not hold.
    pub fn admitted(&self, raw: &str) -> Vec<LineageItem> {
        self.lock().get(raw).map(|e| e.admitted.clone()).unwrap_or_default()
    }

    /// When a session was issued, if it is still known.
    pub fn issued_at(&self, raw: &str) -> Option<DateTime<Utc>> {
        self.lock().get(raw).map(|e| e.issued)
    }

    /// A poisoned lock is recovered from rather than propagated.
    ///
    /// The map holds no invariant that a panic mid-update could break — it is
    /// inserts and removals of independent entries — and refusing every request
    /// for the life of the process because one unrelated handler panicked would
    /// turn a bug into an outage.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Drop what has gone idle, then what is oldest if there is still too much.
fn prune(map: &mut HashMap<String, Entry>, ttl: Duration, cap: usize, now: DateTime<Utc>) {
    map.retain(|_, e| now.signed_duration_since(e.last_seen) < ttl);

    if map.len() <= cap {
        return;
    }
    let mut by_age: Vec<(String, DateTime<Utc>)> =
        map.iter().map(|(k, e)| (k.clone(), e.last_seen)).collect();
    by_age.sort_by_key(|(_, seen)| *seen);
    for (key, _) in by_age.into_iter().take(map.len() - cap) {
        map.remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(offset_secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_789_000_000 + offset_secs, 0).unwrap()
    }

    #[test]
    fn a_minted_session_is_recognised_and_an_invented_one_is_not() {
        let reg = SessionRegistry::new();
        let id = reg.mint(t(0));

        assert_eq!(reg.recognise(id.as_str(), t(1)).unwrap(), id);

        // The whole point: a well-formed id the broker never issued is refused.
        // An agent that mints its own to reset the volume window gets here.
        let forged = SessionId::mint();
        let err = reg.recognise(forged.as_str(), t(1)).unwrap_err();
        assert_eq!(err.reason_code(), "UNKNOWN_SESSION");
        assert_eq!(err.http_status(), 401);
    }

    #[test]
    fn every_mint_is_a_different_session() {
        let reg = SessionRegistry::new();
        let a = reg.mint(t(0));
        let b = reg.mint(t(0));
        // Health mints per call, so two callers never share a window by
        // accident — and a second call is not a way to attach to the first.
        assert_ne!(a, b);
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn use_keeps_a_session_alive_and_disuse_does_not() {
        let reg = SessionRegistry::with_limits(Duration::seconds(100), 16);
        let id = reg.mint(t(0));

        // Touched at 90 s, so at 150 s it is 60 s idle and still good.
        assert!(reg.recognise(id.as_str(), t(90)).is_ok());
        assert!(reg.recognise(id.as_str(), t(150)).is_ok());

        // Then nothing for longer than the TTL.
        assert!(reg.recognise(id.as_str(), t(300)).is_err());
        assert!(reg.is_empty(), "an aged-out session is not just refused, it is gone");
    }

    #[test]
    fn the_registry_is_bounded_and_drops_the_least_recently_used() {
        let reg = SessionRegistry::with_limits(Duration::hours(12), 3);
        let first = reg.mint(t(0));
        let second = reg.mint(t(10));
        // Keep the first one warm while the others age.
        assert!(reg.recognise(first.as_str(), t(20)).is_ok());

        let third = reg.mint(t(30));
        let fourth = reg.mint(t(40));

        assert_eq!(reg.len(), 3);
        // `second` was the least recently seen, so it went.
        assert!(reg.recognise(second.as_str(), t(50)).is_err());
        for kept in [&first, &third, &fourth] {
            assert!(reg.recognise(kept.as_str(), t(50)).is_ok(), "{kept} should still be held");
        }
    }

    #[test]
    fn issue_time_survives_use() {
        let reg = SessionRegistry::new();
        let id = reg.mint(t(0));
        reg.recognise(id.as_str(), t(500)).unwrap();
        // `last_seen` moves; `issued` does not. The console shows how long a run
        // has been going, not how long since it last asked for something.
        assert_eq!(reg.issued_at(id.as_str()), Some(t(0)));
    }

    #[test]
    fn an_empty_or_nonsense_header_is_the_same_refusal_as_a_forged_one() {
        let reg = SessionRegistry::new();
        for raw in ["", "   ", "sess-nope", "../../etc/passwd"] {
            let err = reg.recognise(raw, t(0)).unwrap_err();
            assert_eq!(err.reason_code(), "UNKNOWN_SESSION", "{raw}");
        }
    }
}

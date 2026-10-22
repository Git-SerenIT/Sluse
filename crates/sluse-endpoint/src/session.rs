// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Which run this is.
//!
//! **A session belongs to the run, not to the process.** Claude Code restarts
//! its MCP server — on a reconnect, on a config reload, when the user reopens
//! the project — and each restart is a fresh endpoint process. If each of those
//! took a new session id, two things would quietly go wrong:
//!
//! - **Lineage** would start empty. Under Q-12's provisional rule an artifact
//!   derives from every admission in the session, so a publish after a restart
//!   would carry a provenance record that silently omits real sources — and a
//!   record that omits a source is worse than one that includes an unused one.
//! - The **journal** would fork. S-2's journal deliberately spanned endpoint
//!   restarts within one run, and the scorer reads it as one file.
//!
//! So the session id is written into the workspace and read back. jok's answer
//! on 2026-09-16.
//!
//! ## And it is said out loud
//!
//! Resuming is reported, with the session's age, rather than happening silently:
//! a journal that spans a reconnect should be legible as one, not something a
//! person has to infer from timestamps. [`Resumed::describe`] is what the MCP
//! server logs and what `sluse status` will show at M4.
//!
//! ## What the broker still decides
//!
//! The id itself is **always** the broker's. This file only remembers one. A
//! session the broker has forgotten — it holds them for twelve hours idle —
//! answers `UnknownSession` on the first call, and the endpoint takes a new one
//! rather than carrying on with a session that no longer exists anywhere else.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sluse_proto::SessionId;

/// The file inside the workspace that remembers the run.
///
/// Dot-prefixed so it does not appear as a working file to an agent listing its
/// own workspace, and named for what it is rather than for the tool.
const STATE_FILE: &str = ".sluse-session.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct State {
    session_id: String,
    /// When this run started, as the endpoint saw it. Not authoritative — the
    /// broker has its own issue time — and useful for exactly one thing: telling
    /// a person how long the run they are looking at has been going.
    started: DateTime<Utc>,
    /// How many times an endpoint process has attached to this session.
    attachments: u32,
}

/// What happened when the endpoint looked for a run to join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resumed {
    /// No run on disk, or the broker had forgotten the one there was.
    Started { session: SessionId },
    /// An existing run, rejoined.
    Rejoined { session: SessionId, age: Duration, attachments: u32 },
}

impl Resumed {
    pub fn session(&self) -> &SessionId {
        match self {
            Self::Started { session } => session,
            Self::Rejoined { session, .. } => session,
        }
    }

    /// One line, for the log and for the console.
    ///
    /// The age is the point: a journal that spans a reconnect is a fact worth
    /// stating, not one to be inferred from timestamps later.
    pub fn describe(&self) -> String {
        match self {
            Self::Started { session } => format!("session {session}, new"),
            Self::Rejoined { session, age, attachments } => format!(
                "session {session}, rejoined after {} (attachment {attachments}); \
                 the journal, lineage and volume window continue",
                human(*age)
            ),
        }
    }
}

fn human(d: Duration) -> String {
    let secs = d.num_seconds().max(0);
    match secs {
        0..=90 => format!("{secs} s"),
        // Anything past an hour reads better in hours: "1 h 2 min", not "62 min".
        91..=3600 => format!("{} min", (secs + 30) / 60),
        _ => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
    }
}

/// Where the run's state lives.
pub fn state_path(workspace: &Path) -> PathBuf {
    workspace.join(STATE_FILE)
}

/// The session id a previous process left behind, if there is one.
pub fn remembered(workspace: &Path) -> Option<SessionId> {
    read(workspace).map(|s| SessionId::new_unchecked(s.session_id))
}

fn read(workspace: &Path) -> Option<State> {
    let bytes = std::fs::read(state_path(workspace)).ok()?;
    // A state file that cannot be parsed is treated as absent rather than as an
    // error: the worst case is a new session, and refusing to start because a
    // cache file is malformed would be the wrong end of that trade.
    serde_json::from_slice(&bytes).ok()
}

/// Record that this process is attached to `session`, and say what happened.
///
/// `rejoined` is what the caller learned by asking the broker: `true` when the
/// remembered session was still good, `false` when a new one was taken.
pub fn attach(
    workspace: &Path,
    session: &SessionId,
    rejoined: bool,
    now: DateTime<Utc>,
) -> std::io::Result<Resumed> {
    let previous = read(workspace).filter(|s| rejoined && s.session_id == session.as_str());

    let state = match &previous {
        Some(p) => State {
            session_id: p.session_id.clone(),
            started: p.started,
            attachments: p.attachments.saturating_add(1),
        },
        None => State {
            session_id: session.as_str().to_owned(),
            started: now,
            attachments: 1,
        },
    };

    std::fs::create_dir_all(workspace)?;
    let mut bytes = serde_json::to_vec_pretty(&state)?;
    bytes.push(b'\n');
    std::fs::write(state_path(workspace), bytes)?;

    Ok(match previous {
        Some(p) => Resumed::Rejoined {
            session: session.clone(),
            age: now.signed_duration_since(p.started),
            attachments: state.attachments,
        },
        None => Resumed::Started { session: session.clone() },
    })
}

/// Forget the run. `sluse stop` calls this at M4; nothing calls it during a run.
pub fn clear(workspace: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(state_path(workspace)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(offset_secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_789_000_000 + offset_secs, 0).unwrap()
    }

    #[test]
    fn a_workspace_with_no_run_starts_one() {
        let dir = tempfile::tempdir().unwrap();
        assert!(remembered(dir.path()).is_none());

        let id = SessionId::mint();
        let r = attach(dir.path(), &id, false, t(0)).unwrap();
        assert_eq!(r, Resumed::Started { session: id.clone() });
        assert!(r.describe().ends_with("new"));
        assert_eq!(remembered(dir.path()), Some(id));
    }

    #[test]
    fn a_restart_rejoins_the_same_run_and_says_how_old_it_is() {
        let dir = tempfile::tempdir().unwrap();
        let id = SessionId::mint();
        attach(dir.path(), &id, false, t(0)).unwrap();

        // What a reconnect looks like: a new process, the same run.
        let again = attach(dir.path(), &id, true, t(3700)).unwrap();
        match again {
            Resumed::Rejoined { ref session, age, attachments } => {
                assert_eq!(session, &id);
                assert_eq!(age.num_seconds(), 3700);
                assert_eq!(attachments, 2);
            }
            other => panic!("expected a rejoin, got {other:?}"),
        }
        // The age is stated rather than left to be inferred.
        assert!(again.describe().contains("1 h 1 min"), "{}", again.describe());
        assert!(again.describe().contains("volume window continue"));
    }

    #[test]
    fn the_age_is_measured_from_the_start_not_from_the_last_attach() {
        let dir = tempfile::tempdir().unwrap();
        let id = SessionId::mint();
        attach(dir.path(), &id, false, t(0)).unwrap();
        attach(dir.path(), &id, true, t(600)).unwrap();

        match attach(dir.path(), &id, true, t(1200)).unwrap() {
            // 1200 from the start, not 600 from the previous attach: the number
            // a person wants is how long the run has been going.
            Resumed::Rejoined { age, attachments, .. } => {
                assert_eq!(age.num_seconds(), 1200);
                assert_eq!(attachments, 3);
            }
            other => panic!("expected a rejoin, got {other:?}"),
        }
    }

    #[test]
    fn a_session_the_broker_has_forgotten_starts_a_fresh_run() {
        let dir = tempfile::tempdir().unwrap();
        let old = SessionId::mint();
        attach(dir.path(), &old, false, t(0)).unwrap();

        // The caller asked the broker, was told UnknownSession, took a new one.
        // The old run's age must not be inherited by the new session.
        let new = SessionId::mint();
        let r = attach(dir.path(), &new, false, t(90_000)).unwrap();
        assert_eq!(r, Resumed::Started { session: new.clone() });
        assert_eq!(remembered(dir.path()), Some(new));
    }

    #[test]
    fn a_state_file_that_cannot_be_read_is_treated_as_absent() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(state_path(dir.path()), b"{not json").unwrap();
        // Refusing to start because a cache file is malformed would be the
        // wrong end of the trade; the worst case here is a new session.
        assert!(remembered(dir.path()).is_none());
    }

    #[test]
    fn clearing_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        clear(dir.path()).unwrap();
        attach(dir.path(), &SessionId::mint(), false, t(0)).unwrap();
        clear(dir.path()).unwrap();
        assert!(remembered(dir.path()).is_none());
        clear(dir.path()).unwrap();
    }

    #[test]
    fn ages_read_the_way_a_person_would_say_them() {
        assert_eq!(human(Duration::seconds(45)), "45 s");
        assert_eq!(human(Duration::seconds(300)), "5 min");
        assert_eq!(human(Duration::seconds(7_260)), "2 h 1 min");
    }
}

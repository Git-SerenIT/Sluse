// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The audit sink.
//!
//! Two things are under test and only one of them is "does it write the file":
//! a record must survive a round trip through JSON with every field intact, and
//! a sink that cannot write must not fail the operation it was recording.

use sluse_gate_core::audit::{self, AuditSink, JsonlSink, MemorySink};
use sluse_proto::{
    AuditRecord, BoxId, ContentHash, LineageItem, Op, Outcome, SessionId, SluseError, UserRef,
    Writer,
};

fn record(op: Op, path: &str) -> AuditRecord {
    AuditRecord::new(
        Writer::Core,
        BoxId::new_unchecked("box-local-example"),
        UserRef::os_process("SERENIT\\jok"),
        ContentHash::of(b"a config"),
        SessionId::mint(),
        op,
        path,
    )
}

#[test]
fn a_record_survives_the_round_trip_with_every_field_it_had() {
    let dir = tempfile::tempdir().unwrap();
    let sink = JsonlSink::new(dir.path().join("audit").join("core.jsonl")).unwrap();

    let admitted = record(Op::Read, "fixture/in-scope/docs/note.txt")
        .resolved("C:\\Sluse-test\\fixture\\in-scope\\docs\\note.txt")
        .in_scope("fixture/in-scope")
        .admitted(
            sluse_proto::AdmissionId::mint(),
            ContentHash::of(b"note"),
            4,
        );
    let refused = record(Op::Read, "fixture/elsewhere/secret.txt").failed(&SluseError::OutOfScope {
        raw: "fixture/elsewhere/secret.txt".into(),
        resolved: "C:\\Sluse-test\\fixture\\elsewhere\\secret.txt".into(),
        source_name: "fixture".into(),
        scopes: vec!["fixture/in-scope".into()],
    });

    sink.write(&admitted).unwrap();
    sink.write(&refused).unwrap();

    let back = audit::tail(sink.path(), 100).unwrap();
    assert_eq!(back.len(), 2);
    assert_eq!(back[0], admitted, "an admitted record read back unchanged");
    assert_eq!(back[1], refused, "a refusal read back unchanged");

    // The two halves of a refusal that matter to a person reading the log.
    assert_eq!(back[1].outcome, Outcome::Refused);
    assert_eq!(back[1].reason.as_deref(), Some("OUT_OF_SCOPE"));
}

#[test]
fn a_publish_record_keeps_its_lineage() {
    let dir = tempfile::tempdir().unwrap();
    let sink = JsonlSink::new(dir.path().join("core.jsonl")).unwrap();

    let mut rec = record(Op::Publish, "artifacts/summary.md");
    rec.artifact = Some("summary.md".into());
    rec.lineage = Some(vec![LineageItem {
        path: "fixture/in-scope/docs/note.txt".into(),
        hash: ContentHash::of(b"note"),
        admission_id: Some(sluse_proto::AdmissionId::mint()),
        state: Some(sluse_proto::AdmissionState::Fetched),
    }]);
    rec.sources = Some(vec![]);
    // Q-4 and Q-5 are open, so the prototype writes no label rather than
    // inventing one it cannot honour.
    assert_eq!(rec.label, None);

    sink.write(&rec).unwrap();
    let back = audit::tail(sink.path(), 10).unwrap();
    assert_eq!(back[0].lineage.as_ref().unwrap().len(), 1);
    assert_eq!(back[0], rec);
}

#[test]
fn the_tail_returns_the_last_n_oldest_first() {
    let dir = tempfile::tempdir().unwrap();
    let sink = JsonlSink::new(dir.path().join("core.jsonl")).unwrap();
    for i in 0..10 {
        sink.write(&record(Op::List, &format!("fixture/{i}"))).unwrap();
    }

    let back = audit::tail(sink.path(), 3).unwrap();
    assert_eq!(back.len(), 3);
    assert_eq!(back[0].path_requested, "fixture/7");
    assert_eq!(back[2].path_requested, "fixture/9");
}

#[test]
fn a_torn_line_costs_one_record_and_not_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("core.jsonl");
    let sink = JsonlSink::new(&path).unwrap();
    sink.write(&record(Op::List, "fixture")).unwrap();

    // What a file being appended to while it is read looks like.
    std::fs::write(
        &path,
        format!("{}\n{{\"writer\":\"core\",\"boxI", std::fs::read_to_string(&path).unwrap().trim()),
    )
    .unwrap();

    let back = audit::tail(&path, 100).unwrap();
    assert_eq!(back.len(), 1, "the intact record is still there");
}

#[test]
fn a_tail_of_a_file_that_does_not_exist_is_empty_and_not_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(audit::tail(&dir.path().join("nothing.jsonl"), 10).unwrap().is_empty());
}

#[test]
fn a_sink_that_cannot_write_does_not_fail_the_operation() {
    // The directory is where the file should be: every write fails.
    let dir = tempfile::tempdir().unwrap();
    let taken = dir.path().join("core.jsonl");
    std::fs::create_dir(&taken).unwrap();
    let sink = JsonlSink::new(&taken).unwrap();

    let rec = record(Op::Read, "fixture/in-scope/docs/note.txt");
    assert!(sink.write(&rec).is_err(), "the caller that asks is told");
    // And the one that does not ask is not stopped. `record` returns `()`: an
    // admission that happened stays happened, and the loss goes to stderr.
    sink.record(&rec);
}

#[test]
fn the_memory_sink_keeps_what_it_was_given() {
    let sink = MemorySink::new();
    sink.record(&record(Op::Metadata, "fixture/in-scope/docs/note.txt"));
    sink.record(&record(Op::Sources, ""));
    let records = sink.records();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].op, Op::Metadata);
}

#[test]
fn a_sink_whose_directory_is_removed_recreates_it_rather_than_going_quiet() {
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit");
    let sink = JsonlSink::new(audit.join("core.jsonl")).unwrap();
    sink.write(&record(Op::Read, "fixture/a.md")).unwrap();

    // Someone tidies up under a running core.
    std::fs::remove_dir_all(&audit).unwrap();

    // The next record still lands. A sink that swallowed from here on would
    // leave an audit trail that stops without saying so, which is the worst
    // failure mode this design has.
    sink.write(&record(Op::Read, "fixture/b.md")).unwrap();
    let back = audit::tail(sink.path(), 10).unwrap();
    assert_eq!(back.len(), 1, "the file was recreated; the earlier record went with the directory");
    assert_eq!(back[0].path_requested, "fixture/b.md");
}

// ---------------------------------------------------------------------------
// The Windows Event Log
// ---------------------------------------------------------------------------

const OPS: [Op; 14] = [
    Op::Read, Op::Fetch, Op::Reread, Op::Publish, Op::Metadata, Op::List,
    Op::Sources, Op::Alert, Op::Clear, Op::Signin, Op::Signout, Op::Scope, Op::Tail,
    Op::Journal,
];
const OUTCOMES: [Outcome; 4] = [Outcome::Admitted, Outcome::Refused, Outcome::Error, Outcome::Raised];

/// The ids are a contract with whoever writes a SIEM rule, so a few are pinned
/// by value and all of them must differ.
#[test]
fn event_ids_are_distinct_and_the_documented_ones_hold() {
    let mut seen = std::collections::HashSet::new();
    for op in OPS {
        for outcome in OUTCOMES {
            assert!(seen.insert(audit::event_id(op, outcome)), "{op:?} {outcome:?} collides");
        }
    }
    assert_eq!(audit::event_id(Op::Read, Outcome::Admitted), 100);
    assert_eq!(audit::event_id(Op::Tail, Outcome::Refused), 1501, "D-045 point 2");
    assert_eq!(audit::event_id(Op::Read, Outcome::Refused), 101);
    assert_eq!(audit::event_id(Op::Publish, Outcome::Admitted), 400);
    assert_eq!(audit::event_id(Op::Alert, Outcome::Raised), 803);
    assert_eq!(audit::event_id(Op::Signin, Outcome::Admitted), 1000);
    assert_eq!(audit::event_id(Op::Signout, Outcome::Admitted), 1100);
    assert_eq!(audit::event_level(Outcome::Refused), audit::EventLevel::Warning);
    assert_eq!(audit::event_level(Outcome::Error), audit::EventLevel::Error);
}

/// A publish with a long lineage passes the per-string cap. It is split, never
/// cut, and the pieces put back together are the record.
fn big_publish() -> AuditRecord {
    let mut rec = record(Op::Publish, "report.md");
    rec.lineage = Some(
        (0..400)
            .map(|i| LineageItem {
                path: format!("fixture/in-scope/docs/a-long-file-name-number-{i}.txt"),
                hash: ContentHash::of(format!("{i}").as_bytes()),
                admission_id: Some(sluse_proto::AdmissionId::mint()),
                state: Some(sluse_proto::AdmissionState::Read),
            })
            .collect(),
    );
    rec
}

#[test]
fn a_large_record_is_split_over_events_and_reassembles() {
    let small = serde_json::to_string(&record(Op::Read, "fixture/a.txt")).unwrap();
    assert_eq!(audit::event_strings(&small), vec![vec![small.clone()]]);

    let json = serde_json::to_string(&big_publish()).unwrap();
    assert!(json.chars().count() > audit::EVENT_CHUNK, "the fixture must pass the cap");
    let events = audit::event_strings(&json);
    assert!(events.len() > 1);
    let key = ContentHash::of(json.as_bytes());
    let mut whole = String::new();
    for (i, e) in events.iter().enumerate() {
        assert_eq!(e[0], format!("{key} part {}/{}", i + 1, events.len()));
        assert!(e[1].chars().count() <= audit::EVENT_CHUNK);
        whole.push_str(&e[1]);
    }
    assert_eq!(whole, json);
}

/// Written to the real Application log and read back from it. Windows only, so
/// CI's Windows runner is the only place this runs (D-011).
#[cfg(windows)]
mod eventlog {
    use super::*;
    use windows::core::{HSTRING, PCWSTR};
    use windows::Win32::System::EventLog::{
        CloseEventLog, OpenEventLogW, ReadEventLogW, EVENTLOGRECORD, EVENTLOG_SEQUENTIAL_READ,
        READ_EVENT_LOG_READ_FLAGS,
    };

    /// `EVENTLOG_BACKWARDS_READ`, which this version of the bindings does not name.
    const BACKWARDS: u32 = 0x8;

    fn wide_z(bytes: &[u8]) -> String {
        let units: Vec<u16> = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .take_while(|&u| u != 0)
            .collect();
        String::from_utf16_lossy(&units)
    }

    /// The newest events from our source, newest first: `(event id, strings)`.
    fn ours(max: usize) -> Vec<(u32, Vec<String>)> {
        let log = HSTRING::from("Application");
        let h = unsafe { OpenEventLogW(PCWSTR::null(), PCWSTR(log.as_ptr())) }.unwrap();
        let flags = READ_EVENT_LOG_READ_FLAGS(EVENTLOG_SEQUENTIAL_READ.0 | BACKWARDS);
        let mut buf = vec![0u8; 0x10000];
        let mut out = Vec::new();
        let mut scanned = 0;
        'read: while scanned < 5000 {
            let (mut read, mut needed) = (0u32, 0u32);
            let r = unsafe {
                ReadEventLogW(h, flags, 0, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read, &mut needed)
            };
            if r.is_err() {
                if needed as usize > buf.len() {
                    buf.resize(needed as usize, 0);
                    continue;
                }
                break; // the start of the log
            }
            let mut off = 0usize;
            while off < read as usize {
                let rec: EVENTLOGRECORD = unsafe { std::ptr::read_unaligned(buf[off..].as_ptr().cast()) };
                scanned += 1;
                let source = wide_z(&buf[off + std::mem::size_of::<EVENTLOGRECORD>()..]);
                if source == sluse_gate_core::audit::EVENT_SOURCE {
                    let mut at = off + rec.StringOffset as usize;
                    let mut strings = Vec::new();
                    for _ in 0..rec.NumStrings {
                        let s = wide_z(&buf[at..]);
                        at += (s.encode_utf16().count() + 1) * 2;
                        strings.push(s);
                    }
                    // The low word is the id as reported; the high word holds
                    // severity bits Windows may add.
                    out.push((rec.EventID & 0xFFFF, strings));
                    if out.len() >= max {
                        break 'read;
                    }
                }
                off += rec.Length as usize;
            }
        }
        let _ = unsafe { CloseEventLog(h) };
        out
    }

    #[test]
    fn a_record_reaches_the_event_log_whole() {
        let sink = audit::EventLogSink::new().unwrap();
        let marker = format!("fixture/eventlog-test/{}", SessionId::mint());
        let refused = record(Op::Read, &marker).failed(&SluseError::NotFound { raw: marker.clone() });
        sink.write(&refused).unwrap();

        let (id, strings) = ours(50)
            .into_iter()
            .find(|(_, s)| s.iter().any(|x| x.contains(&marker)))
            .expect("the record is in the Application log under our source");
        assert_eq!(id, 101, "read, refused");
        assert_eq!(strings.len(), 1);
        let back: AuditRecord = serde_json::from_str(&strings[0]).unwrap();
        assert_eq!(serde_json::to_value(&back).unwrap(), serde_json::to_value(&refused).unwrap());
    }

    #[test]
    fn a_large_record_reaches_the_event_log_in_parts_that_rejoin() {
        let sink = audit::EventLogSink::new().unwrap();
        let rec = big_publish();
        let json = serde_json::to_string(&rec).unwrap();
        let key = ContentHash::of(json.as_bytes()).to_string();
        sink.write(&rec).unwrap();

        let mut parts: Vec<(u32, Vec<String>)> =
            ours(200).into_iter().filter(|(_, s)| s.first().is_some_and(|h| h.starts_with(&key))).collect();
        parts.reverse(); // read newest first; the parts were written in order
        assert_eq!(parts.len(), audit::event_strings(&json).len());
        assert!(parts.iter().all(|(id, _)| *id == 400));
        let whole: String = parts.iter().map(|(_, s)| s[1].as_str()).collect();
        assert_eq!(whole, json);
    }
}

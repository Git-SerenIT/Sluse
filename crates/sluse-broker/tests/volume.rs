// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The volume window.
//!
//! Time is passed in rather than read, so these are exact rather than nearly:
//! a sliding-window test that sleeps is a test that fails on a slow morning.

use chrono::{Duration, TimeZone, Utc};
use sluse_broker::VolumeMonitor;
use sluse_proto::{ContentHash, SessionId, SourceName, VolumeConfig};

fn monitor(admissions: u32, window_seconds: u32) -> VolumeMonitor {
    VolumeMonitor::new(VolumeConfig { admissions, window_seconds, bytes: None })
}

/// A monitor that watches bytes as well (D-016). `admissions` is set out of
/// reach so the byte threshold is the only one that can trip.
fn byte_monitor(bytes: u64, window_seconds: u32) -> VolumeMonitor {
    VolumeMonitor::new(VolumeConfig {
        admissions: u32::MAX,
        window_seconds,
        bytes: Some(bytes),
    })
}

fn session() -> SessionId {
    SessionId::mint()
}

fn source(name: &str) -> SourceName {
    SourceName::parse(name).expect("valid source name")
}

/// A distinct hash per number, without hashing anything.
fn hash(n: u32) -> ContentHash {
    ContentHash::of(format!("file-{n}").as_bytes())
}

#[test]
fn an_ordinary_first_fetch_does_not_alert() {
    // S-2 finding 7: a first `fetch` of a Rust crate was 12 files in 13
    // seconds. That is the floor under any threshold, and the LOCAL default of
    // 25 sits above it on purpose.
    let m = monitor(25, 60);
    let (s, src) = (session(), source("fixture"));
    let t0 = Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap();

    for i in 0..12 {
        let at = t0 + Duration::seconds(i64::from(i));
        assert!(m.admit(&s, &src, &hash(i), 1, at).is_none(), "file {i} alerted");
    }
    assert_eq!(m.count(&src, t0 + Duration::seconds(13)).files, 12);
}

#[test]
fn crossing_the_threshold_raises_exactly_one_alert() {
    let m = monitor(25, 60);
    let (s, src) = (session(), source("fixture"));
    let t0 = Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap();

    let mut raised = Vec::new();
    for i in 0..40 {
        // 40 files inside one second: the bulk read the alert exists for.
        let at = t0 + Duration::milliseconds(i64::from(i) * 25);
        if let Some(alert) = m.admit(&s, &src, &hash(i), 1, at) {
            raised.push(alert);
        }
    }

    assert_eq!(raised.len(), 1, "one crossing is one event, not fifteen");
    let alert = &raised[0];
    assert_eq!(alert.count, 25, "raised on the file that crossed, not later");
    assert_eq!(alert.window_seconds, 60);
    assert_eq!(alert.summary, "fixture/ (25 files, 60 s)");
    assert!(alert.closed_at.is_none());
    assert_eq!(m.alerts(None).len(), 1);
}

#[test]
fn the_same_file_over_and_over_is_one_admission_worth_of_material() {
    let m = monitor(5, 60);
    let (s, src) = (session(), source("fixture"));
    let t0 = Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap();

    // Twenty reads of one file. Inefficient, not exfiltration-shaped.
    for i in 0..20 {
        let at = t0 + Duration::seconds(i);
        assert!(m.admit(&s, &src, &hash(1), 1, at).is_none());
    }
    assert_eq!(m.count(&src, t0 + Duration::seconds(20)).files, 1);
    assert!(m.alerts(None).is_empty());
}

#[test]
fn the_window_slides_and_the_alert_closes() {
    let m = monitor(5, 60);
    let (s, src) = (session(), source("fixture"));
    let t0 = Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap();

    for i in 0..5 {
        m.admit(&s, &src, &hash(i), 1, t0 + Duration::seconds(i64::from(i)));
    }
    assert_eq!(m.alerts(None).len(), 1);
    assert!(m.alerts(None)[0].closed_at.is_none());

    // Two minutes later the window holds nothing.
    let later = t0 + Duration::seconds(120);
    assert_eq!(m.count(&src, later).files, 0);
    m.sweep(later);

    let alerts = m.alerts(None);
    assert_eq!(alerts.len(), 1, "closing an alert does not raise another");
    assert_eq!(alerts[0].closed_at, Some(later));
}

#[test]
fn a_second_burst_after_the_first_closed_raises_a_second_alert() {
    let m = monitor(5, 60);
    let (s, src) = (session(), source("fixture"));
    let t0 = Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap();

    for i in 0..5 {
        m.admit(&s, &src, &hash(i), 1, t0 + Duration::seconds(i64::from(i)));
    }
    let later = t0 + Duration::seconds(200);
    m.sweep(later);

    for i in 100..105 {
        m.admit(&s, &src, &hash(i), 1, later + Duration::seconds(i64::from(i - 100)));
    }
    assert_eq!(m.alerts(None).len(), 2, "a new crossing is a new event");
}

#[test]
fn sessions_and_sources_are_counted_apart() {
    let m = monitor(5, 60);
    let t0 = Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap();
    let (a, b) = (session(), session());
    let (fixture, share) = (source("fixture"), source("share"));

    // Four each: sixteen admissions, no threshold crossed anywhere.
    for i in 0..4 {
        let at = t0 + Duration::seconds(i64::from(i));
        for (s, src) in [(&a, &fixture), (&a, &share), (&b, &fixture), (&b, &share)] {
            assert!(m.admit(s, src, &hash(i), 1, at).is_none());
        }
    }
    assert!(m.alerts(None).is_empty(), "two people working is not an incident");
    assert_eq!(m.count(&fixture, t0 + Duration::seconds(5)).files, 4);
}

#[test]
fn alerts_can_be_asked_for_by_time() {
    let m = monitor(3, 60);
    let (s, src) = (session(), source("fixture"));
    let t0 = Utc.with_ymd_and_hms(2026, 9, 14, 12, 0, 0).unwrap();

    for i in 0..3 {
        m.admit(&s, &src, &hash(i), 1, t0 + Duration::seconds(i64::from(i)));
    }
    assert_eq!(m.alerts(Some(t0 - Duration::seconds(1))).len(), 1);
    assert_eq!(m.alerts(Some(t0 + Duration::seconds(60))).len(), 0);
}

// ---------------------------------------------------------------------------
// Bytes (D-016)
// ---------------------------------------------------------------------------

#[test]
fn one_large_file_raises_an_alert_that_counting_files_would_miss() {
    // The whole point of D-016, and the first scored run is the case: one
    // `fetch` moved 524,288,000 bytes and the only alert raised that session
    // described a rate of 25 *files*, which had nothing to do with it.
    let m = byte_monitor(1_000_000, 60);
    let s = session();
    let src = source("fixture");
    let t0 = Utc.with_ymd_and_hms(2026, 9, 22, 9, 0, 0).unwrap();

    let alert = m.admit(&s, &src, &hash(1), 2_000_000, t0).expect("one file, over the byte cap");
    assert_eq!(alert.count, 1, "one file");
    assert_eq!(alert.bytes, 2_000_000);
    assert!(alert.summary.contains("2000000 bytes"), "{}", alert.summary);
    assert!(alert.summary.contains("1 files"), "both numbers travel: {}", alert.summary);
}

#[test]
fn bytes_accumulate_across_files_and_dedupe_on_content() {
    let m = byte_monitor(300, 60);
    let s = session();
    let src = source("fixture");
    let t0 = Utc.with_ymd_and_hms(2026, 9, 22, 9, 0, 0).unwrap();

    assert!(m.admit(&s, &src, &hash(1), 100, t0).is_none(), "100 of 300");
    assert!(
        m.admit(&s, &src, &hash(1), 100, t0 + Duration::seconds(1)).is_none(),
        "the same bytes again are not more material — the dedupe `admissions` uses"
    );
    assert_eq!(m.count(&src, t0 + Duration::seconds(1)).bytes, 100);

    assert!(m.admit(&s, &src, &hash(2), 100, t0 + Duration::seconds(2)).is_none(), "200 of 300");
    let alert = m
        .admit(&s, &src, &hash(3), 100, t0 + Duration::seconds(3))
        .expect("300 reaches the threshold");
    assert_eq!(alert.bytes, 300);
    assert_eq!(alert.count, 3);
}

#[test]
fn a_byte_threshold_that_is_not_configured_never_trips() {
    // Absent is the default, and every config written before 2026-09-22 says so
    // by omission. A source that moves a gigabyte under a file threshold it
    // never reaches raises nothing, which is the behaviour those configs have.
    let m = monitor(1000, 60);
    let s = session();
    let src = source("fixture");
    let t0 = Utc.with_ymd_and_hms(2026, 9, 22, 9, 0, 0).unwrap();

    assert!(m.admit(&s, &src, &hash(1), 1_000_000_000, t0).is_none());
    assert_eq!(m.count(&src, t0).bytes, 1_000_000_000, "counted, just not a threshold");
}

#[test]
fn an_alert_stays_open_while_either_threshold_is_still_crossed() {
    // `sweep` closes on *both* being back under. A window that has drained
    // below the file count but is still over the byte count is still the event
    // that was raised.
    let m = VolumeMonitor::new(VolumeConfig {
        admissions: 2,
        window_seconds: 60,
        bytes: Some(1_000),
    });
    let s = session();
    let src = source("fixture");
    let t0 = Utc.with_ymd_and_hms(2026, 9, 22, 9, 0, 0).unwrap();

    // Two files trip the file threshold; between them they are also over the
    // byte threshold, and the big one is young enough to stay in the window.
    assert!(m.admit(&s, &src, &hash(1), 10, t0).is_none());
    assert!(m.admit(&s, &src, &hash(2), 2_000, t0 + Duration::seconds(50)).is_some());

    // t0's file has slid out, so the file count is 1 — under the threshold —
    // but 2,000 bytes are still inside the window.
    let later = t0 + Duration::seconds(70);
    assert_eq!(m.count(&src, later).files, 1);
    m.sweep(later);
    assert!(m.alerts(None)[0].closed_at.is_none(), "still over on bytes");

    // Now both have drained.
    let much_later = t0 + Duration::seconds(200);
    m.sweep(much_later);
    assert!(m.alerts(None)[0].closed_at.is_some(), "both thresholds back under");
}

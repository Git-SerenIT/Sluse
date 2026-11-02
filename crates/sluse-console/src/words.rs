// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Times, sizes, lists and the record's codes in words: the web console's
//! dom.ts and data.ts, in their words.

use chrono::{DateTime, Local, Utc};
use sluse_proto::SourceView;
use sluse_proto::audit::{AuditRecord, Op, Outcome};

/// `14:32:07`, the date too when it is not today, in local time (the box
/// takes the computer's zone at each open).
pub fn when(t: DateTime<Utc>) -> String {
    let l = t.with_timezone(&Local);
    if l.date_naive() == Local::now().date_naive() { l.format("%H:%M:%S").to_string() } else { l.format("%-d %b %H:%M:%S").to_string() }
}

/// `14:32`.
pub fn hhmm(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%H:%M").to_string()
}

/// `19 October 2026`.
pub fn day(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%-d %B %Y").to_string()
}

/// `Monday`.
pub fn weekday(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%A").to_string()
}

pub fn today(t: DateTime<Utc>) -> bool {
    t.with_timezone(&Local).date_naive() == Local::now().date_naive()
}

pub fn plural(n: u64, word: &str) -> String {
    format!("{n} {word}{}", if n == 1 { "" } else { "s" })
}

/// How long ago, in words: "12 seconds ago", "3 minutes ago".
pub fn ago(t: DateTime<Utc>) -> String {
    let s = (Utc::now() - t).num_seconds().max(0) as u64;
    if s < 60 {
        format!("{} ago", plural(s, "second"))
    } else if s < 3600 {
        format!("{} ago", plural((s as f64 / 60.0).round() as u64, "minute"))
    } else {
        format!("{} ago", plural((s as f64 / 3600.0).round() as u64, "hour"))
    }
}

/// A window kept in seconds, said in natural words (Q52): "60 seconds", "10 minutes".
pub fn window(seconds: u32) -> String {
    let s = u64::from(seconds);
    if s >= 3600 && s % 3600 == 0 {
        plural(s / 3600, "hour")
    } else if s >= 120 && s % 60 == 0 {
        plural(s / 60, "minute")
    } else {
        plural(s, "second")
    }
}

/// Bytes, in the units a person reads.
pub fn size(bytes: Option<u64>) -> String {
    let Some(b) = bytes else { return String::new() };
    if b < 1024 {
        return format!("{b} B");
    }
    let mut n = b as f64 / 1024.0;
    let mut unit = "KB";
    for u in ["MB", "GB"] {
        if n < 1024.0 {
            break;
        }
        n /= 1024.0;
        unit = u;
    }
    if n < 10.0 { format!("{n:.1} {unit}") } else { format!("{} {unit}", n.round()) }
}

/// A list joined in words: "a, b and c".
pub fn list(xs: &[String]) -> String {
    match xs {
        [] => String::new(),
        [one] => one.clone(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

/// The source a path belongs to: `finance/2026/Q3/x.csv` is `finance`.
pub fn source_of(path: &str) -> &str {
    path.split('/').next().unwrap_or(path)
}

/// The path within its source.
pub fn within(path: &str) -> &str {
    path.split_once('/').map(|(_, rest)| rest).filter(|r| !r.is_empty()).unwrap_or(path)
}

/// What a source is, in words: "SharePoint library, 2 folders".
pub fn kind_words(s: &SourceView) -> String {
    let n = s.scopes.len() as u64;
    let folders = if n > 0 { format!(", {}", plural(n, "folder")) } else { String::new() };
    match s.kind.as_str() {
        "sharepoint" => format!("SharePoint library{folders}"),
        "smb" => format!("File share{folders}"),
        "onedrive" => "Your Sluse folder in OneDrive".into(),
        "inputs" => "Sluse Inputs on your computer".into(),
        // Its scopes are the tools allowed (D-071).
        "mcp" => format!("Tool server, {}", plural(n, "tool")),
        _ => format!("Folder on this device{folders}"),
    }
}

/// A source's icon.
pub fn kind_icon(kind: &str) -> &'static str {
    match kind {
        "sharepoint" => "library",
        "smb" => "server",
        "onedrive" => "cloud",
        "inputs" => "inbox",
        "mcp" => "apps",
        _ => "folder",
    }
}

/// A publish's folder in Sluse Artifacts, from its record's path,
/// `artifacts/<folder>/<name>`, as Gate Core names it on the host (D-031
/// point 5 amended): `2026-10-19 14.32 q3-variance`.
pub fn folder_of(path: &str, artifact: Option<&str>) -> Option<String> {
    let rest = path.strip_prefix("artifacts/").unwrap_or(path);
    if let Some(a) = artifact {
        if let Some(f) = rest.strip_suffix(&format!("/{a}")) {
            return Some(f.to_owned());
        }
    }
    rest.split_once('/').map(|(f, _)| f.to_owned())
}

/// Each op in words (Record, Work).
pub fn op_words(op: Op) -> &'static str {
    match op {
        Op::Read => "Read",
        Op::Fetch => "Fetched",
        Op::Reread => "Re-read a copy",
        Op::Publish => "Published",
        Op::Metadata => "Looked up details",
        Op::List => "Opened a folder",
        Op::Sources => "Listed the sources",
        Op::Alert => "Volume alert",
        Op::Clear => "Deleted the copies",
        Op::Signin => "Signed in",
        Op::Signout => "Signed out",
        Op::Scope => "Read the scope",
        Op::Tail => "Read the computer's record",
        Op::Journal => "Read this record",
        Op::Call => "Called a tool",
        Op::Tools => "Listed the tools",
    }
}

/// A reason code in words: what happened, and what the person can do. A
/// refusal's hidden reason is said honestly: it is in the Event Log.
pub fn reason_words(code: Option<&str>, outcome: Outcome) -> String {
    let said = match code {
        Some("OFFICE_ENCRYPTED") => "Arrived encrypted. Sluse gave the box no key to open it.",
        Some("NOT_UTF8_TEXT") => "Its text could not be shown to the agent: not text",
        Some("MODIFIED_SINCE_ADMISSION") => "Changed since it was let in",
        Some("NO_PROVENANCE") => "No provenance: not let in through Sluse, or its provenance file is gone",
        Some("SOURCE_NOT_ADMITTED") => "Named a source this box never let in",
        Some("HASH_MISMATCH") => "The file changed while it was being published",
        Some("SOURCE_UNAVAILABLE") => "The source did not answer",
        Some("SIGN_IN_REQUIRED") => "Sluse needed a sign-in it did not have",
        Some("TOO_LARGE") => "Larger than Sluse lets into the box",
        Some("NOT_FOUND") => "Not there at the source",
        Some("GATE_UNREACHABLE") => "Sluse on your computer did not answer",
        _ => "",
    };
    if !said.is_empty() {
        return said.into();
    }
    match code {
        // A code with no words yet: said plainly, with the code under it.
        Some(c) if !c.is_empty() && c.chars().all(|ch| ch.is_ascii_uppercase() || ch == '_') => {
            if outcome == Outcome::Refused { "Refused by Sluse".into() } else { "It did not finish".into() }
        }
        Some(c) if c.starts_with("rendered by") => "Rendered by Sluse from the agent's Markdown".into(),
        Some(c) if c.starts_with("cleared ") => cleared_words(c).unwrap_or_else(|| c.to_owned()),
        None if outcome == Outcome::Refused => "The reason is in this computer's Event Log, which your IT department can read".into(),
        Some(c) => c.to_owned(),
        None => String::new(),
    }
}

/// `cleared 3 file(s), 0 failed` as "3 copies deleted, none failed".
fn cleared_words(code: &str) -> Option<String> {
    let rest = code.strip_prefix("cleared ")?;
    let (n, rest) = rest.split_once(" file(s), ")?;
    let failed = rest.strip_suffix(" failed")?;
    let copies = if n == "1" { "copy" } else { "copies" };
    Some(format!("{n} {copies} deleted, {} failed", if failed == "0" { "none" } else { failed }))
}

/// The pill for a record's outcome: Let in, Published, Done, Refused, Error, Alert.
pub fn outcome_pill(r: &AuditRecord) -> (&'static str, &'static str) {
    match r.outcome {
        Outcome::Refused => ("refused", "Refused"),
        Outcome::Error => ("error", "Error"),
        Outcome::Raised => ("info", "Alert"),
        Outcome::Admitted => match r.op {
            Op::Publish => ("published", "Published"),
            Op::Read | Op::Fetch | Op::Call => ("admitted", "Let in"),
            _ => ("done", "Done"),
        },
    }
}

/// A refusal's code, from its error as the wire carries it.
pub fn code(e: &sluse_proto::SluseError) -> String {
    serde_json::to_value(e).ok().and_then(|v| v["code"].as_str().map(str::to_owned)).unwrap_or_else(|| "INTERNAL".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_words_are_the_web_consoles() {
        assert_eq!(list(&["a".into(), "b".into(), "c".into()]), "a, b and c");
        assert_eq!(window(60), "60 seconds");
        assert_eq!(window(600), "10 minutes");
        assert_eq!(window(7200), "2 hours");
        assert_eq!(size(Some(512)), "512 B");
        assert_eq!(size(Some(1536)), "1.5 KB");
        assert_eq!(size(Some(20 * 1024 * 1024)), "20 MB");
        assert_eq!(within("finance/2026/Q3/x.csv"), "2026/Q3/x.csv");
        assert_eq!(source_of("finance/2026/Q3/x.csv"), "finance");
        assert_eq!(folder_of("artifacts/2026-10-19 14.32 q3/report.md", Some("report.md")).as_deref(), Some("2026-10-19 14.32 q3"));
        assert_eq!(reason_words(Some("cleared 3 file(s), 0 failed"), Outcome::Admitted), "3 copies deleted, none failed");
        assert_eq!(reason_words(Some("SOMETHING_NEW"), Outcome::Refused), "Refused by Sluse");
        assert!(reason_words(None, Outcome::Refused).contains("Event Log"));
    }
}

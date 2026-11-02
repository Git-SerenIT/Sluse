// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Copies in the box: what an agent fetched through Sluse, kept until the
//! person deletes it, every session (D-019). Checking against the sources is a
//! person's click, one question per file, counted as the answers come (Q33);
//! the rows keep their states until every answer is in, so the table never
//! mixes two checks. A check's result survives timed reads; a file let in
//! after it says Not checked. (The web console's views/copies.ts, until 0.3.)

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use iced::widget::{column, row, text};
use iced::{Alignment, Element, Length, Task};
use sluse_endpoint::console::Console as Calls;
use sluse_endpoint::console::api::{Cleared, InventoryRow};
use sluse_endpoint::console::inventory::InventoryState;

use crate::app::{Console, Data, Dialog, Message};
use crate::look::{self, Theme, color};
use crate::widgets::{self, Btn, Kind};
use crate::words::{hhmm, kind_words, list, plural, size, when};

/// A copy's state: its pill, its word, and what it means.
pub const STATES: [(&str, &str, &str); 6] = [
    ("current", "Current", "The source still has these bytes."),
    ("stale", "Changed", "The source has this file and it has changed since it was let in."),
    ("orphaned", "Not at source", "The source no longer answers for this file: it was moved or deleted, or you can no longer open it."),
    ("unknown", "Not known", "Nobody could be asked. This is not a claim about the file."),
    ("missing", "Copy missing", "The copy let into the box is no longer there."),
    ("not-checked", "Not checked", "Not compared with the source yet."),
];

/// The copies still to ask about, those answered, and how many in all.
type Checking = (Vec<String>, HashMap<String, Arc<InventoryRow>>, usize);

/// The last check, the one under way, and the last delete.
#[derive(Default)]
pub struct Copies {
    checked: HashMap<String, Arc<InventoryRow>>,
    checked_at: Option<DateTime<Utc>>,
    checking: Option<Checking>,
    failed: Option<String>,
    cleared: Option<(usize, DateTime<Utc>)>,
}

fn index(state: InventoryState) -> usize {
    match state {
        InventoryState::Current => 0,
        InventoryState::Stale => 1,
        InventoryState::Orphaned => 2,
        InventoryState::Unknown => 3,
        InventoryState::Missing => 4,
    }
}

impl Copies {
    fn state_of(&self, r: &InventoryRow) -> usize {
        if r.state == InventoryState::Missing {
            return 4;
        }
        self.checked.get(&r.item.path).map_or(5, |c| index(c.state))
    }

    /// Ask each source about each copy still in the box, one at a time.
    pub fn start(&mut self, calls: &Arc<Calls>, d: &Data) -> Task<Message> {
        if self.checking.is_some() {
            return Task::none();
        }
        let queue: Vec<String> = d.inventory.iter().filter(|r| r.item.local_present).map(|r| r.item.path.clone()).collect();
        let of = queue.len();
        self.failed = None;
        self.checking = Some((queue, HashMap::new(), of));
        self.next(calls)
    }

    fn next(&mut self, calls: &Arc<Calls>) -> Task<Message> {
        let Some((queue, _, _)) = &mut self.checking else { return Task::none() };
        let Some(path) = queue.first().cloned() else {
            let (_, answers, _) = self.checking.take().unwrap_or_default();
            self.checked = answers;
            self.checked_at = Some(Utc::now());
            return Task::none();
        };
        let calls = calls.clone();
        Task::perform(async move { calls.check(&path).await.map(Arc::new).map_err(|e| e.to_string()) }, Message::Answer)
    }

    pub fn answer(&mut self, calls: &Arc<Calls>, r: Result<Arc<InventoryRow>, String>) -> Task<Message> {
        let Some((queue, answers, _)) = &mut self.checking else { return Task::none() };
        match r {
            Ok(row) => {
                queue.retain(|p| *p != row.item.path);
                answers.insert(row.item.path.clone(), row);
                self.next(calls)
            }
            Err(e) => {
                self.checking = None;
                self.failed = Some(format!("check: {e} at {}", Utc::now().to_rfc3339()));
                Task::none()
            }
        }
    }

    pub fn clear(calls: &Arc<Calls>) -> Task<Message> {
        let calls = calls.clone();
        Task::perform(async move { calls.clear().await.map(Arc::new).map_err(|e| e.to_string()) }, Message::Cleared)
    }

    /// The delete's answer; a dialog when some or all of it did not happen.
    pub fn cleared(&mut self, r: Result<Arc<Cleared>, String>) -> Option<Dialog> {
        self.checked.clear();
        self.checked_at = None;
        match r {
            Ok(done) if done.failed.is_empty() => {
                self.cleared = Some((done.files, Utc::now()));
                None
            }
            Ok(done) => {
                let n = done.failed.len();
                Some(Dialog::Message {
                    title: format!("{} could not be deleted", if n == 1 { "1 copy".to_owned() } else { format!("{n} copies") }),
                    lines: vec![
                        format!("Deleted {} of {} copies. Some are still in the box, in use by a program in the box or with a provenance file that could not be removed.", done.files, done.files + n),
                        "Close the program using it and try again. If it stays, send the details to your IT department.".into(),
                    ],
                    raw: done.failed.join("\n"),
                })
            }
            Err(e) => Some(Dialog::Message {
                title: "The copies were not deleted".into(),
                lines: vec!["The box could not finish deleting them. What is listed now is what is still in the box. Try again; if it happens again, send the details to your IT department.".into()],
                raw: format!("clear: {e}"),
            }),
        }
    }
}

/// What the delete removes, for its confirm.
pub fn what_goes(d: &Data) -> String {
    let present: Vec<&InventoryRow> = d.inventory.iter().filter(|r| r.item.local_present).collect();
    let bytes: u64 = present.iter().map(|r| r.item.bytes.unwrap_or(0)).sum();
    let mut sources: Vec<String> = Vec::new();
    for r in &present {
        if !sources.contains(&r.item.source) {
            sources.push(r.item.source.clone());
        }
    }
    format!("{} {}, {}, from {}", present.len(), if present.len() == 1 { "copy" } else { "copies" }, size(Some(bytes)), list(&sources))
}

pub fn view<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    let s = &c.copies;
    let rows = &d.inventory;
    let busy = s.checking.is_some();
    let mut actions: Vec<Element<'_, Message>> =
        vec![widgets::btn(t, Btn::Plain, false, widgets::label(t, Some("info"), "What the states mean")).on_press(Message::Show(Dialog::States)).into()];
    if !rows.is_empty() {
        actions.push(widgets::btn(t, Btn::Plain, false, widgets::label(t, Some("search"), "Check against the sources")).on_press_maybe((!busy).then_some(Message::Check)).into());
        actions.push(widgets::btn(t, Btn::Destructive, false, widgets::label(t, Some("wipe"), "Delete the copies…")).on_press_maybe((!busy).then_some(Message::Show(Dialog::Clear))).into());
    }
    let head = widgets::pagehead(
        t,
        "Copies in the box",
        "Copies of files an AI agent fetched through Sluse are kept in the box until you delete them. Files an agent only read get no copy from Sluse. What an agent writes from any of them is not listed here. This list covers every session of this box, not only this one.".into(),
        actions,
    );
    if rows.is_empty() {
        let lines = match s.cleared {
            Some((n, at)) => vec![
                format!("You deleted {} at {}. The record of each admission is kept, and the deletion is in Record.", if n == 1 { "1 copy".into() } else { format!("{n} copies") }, hhmm(at)),
                "Anything an AI agent made from these files, or saved elsewhere in the box, is still there. Sluse does not track those; wiping the box removes them.".into(),
            ],
            None => vec!["When an AI agent fetches a file, Sluse keeps a copy here with the record that let it in. Sluse keeps no copy of a file an agent only read. The agent can still save what it was shown.".into()],
        };
        return column![head, widgets::empty(t, "download", "No copies in the box".into(), lines, None)].spacing(look::S8).into();
    }

    let mut notes = column![].spacing(look::S3);
    if s.checked_at.is_none() && !busy && s.failed.is_none() {
        notes = notes.push(widgets::note(
            t,
            Kind::Info,
            text("Not checked against the sources yet. Checking asks each source about each file, and each question is recorded on your computer.").size(look::SMALL),
        ));
    }
    if let Some((queue, _, of)) = &s.checking {
        let asked = of - queue.len();
        notes = notes.push(widgets::card(
            t,
            column![
                text(format!("Asking the sources: {asked} of {of} files asked")).size(look::SMALL).font(look::BOLD),
                widgets::bar(t, if *of == 0 { 1.0 } else { asked as f32 / *of as f32 }),
                text("One question per file, one after another. The states below change when every answer is in.").size(look::SMALL).color(color(t.ink_muted)),
            ]
            .spacing(look::S2),
        ));
    }
    if let (Some(at), false) = (s.checked_at, busy) {
        let mut tally: BTreeMap<usize, usize> = BTreeMap::new();
        for r in rows {
            *tally.entry(s.state_of(r)).or_default() += 1;
        }
        let mut line = row![text(format!("Checked at {}", when(at))).size(look::SMALL)].spacing(look::S2).align_y(Alignment::Center);
        for (k, n) in tally {
            let (status, word, _) = STATES[k];
            line = line.push(widgets::pill(t, status, &format!("{n} {}", word.to_lowercase())));
        }
        notes = notes.push(line);
        let after = rows.iter().filter(|r| !s.checked.contains_key(&r.item.path)).count();
        if after > 0 {
            notes = notes.push(widgets::note(
                t,
                Kind::Info,
                text(format!(
                    "{} let in after the check, so {} Not checked. Check again to compare {}.",
                    if after == 1 { "One file was".to_owned() } else { format!("{after} files were") },
                    if after == 1 { "it says" } else { "they say" },
                    if after == 1 { "it" } else { "them" }
                ))
                .size(look::SMALL),
            ));
        }
    }
    if let Some(raw) = &s.failed {
        notes = notes.push(widgets::strip(
            t,
            Kind::Warning,
            "The check did not finish.".into(),
            "Sluse on your computer did not answer, so nothing was compared. The states below are from before. Try again in a moment; if it keeps happening, send the details to your IT department.".into(),
            vec![widgets::btn(t, Btn::Plain, true, text("Check again").size(look::SMALL)).on_press(Message::Check).into(), crate::app::details(c, t, raw.clone())],
            None,
        ));
    }

    let mut groups: Vec<(String, Vec<&InventoryRow>)> = Vec::new();
    for r in rows {
        match groups.iter_mut().find(|(k, _)| *k == r.item.source) {
            Some((_, g)) => g.push(r),
            None => groups.push((r.item.source.clone(), vec![r])),
        }
    }
    let mut page = column![head, notes].spacing(look::S6);
    for (source, rs) in groups {
        let view = d.view.sources.iter().find(|v| v.name.as_str() == source);
        let sub = format!("{}{}", view.map(|v| format!("{}, ", kind_words(v))).unwrap_or_default(), plural(rs.len() as u64, "file"));
        let table_rows = rs
            .iter()
            .map(|r| {
                let k = s.state_of(r);
                let (status, word, meaning) = STATES[k];
                let mut state = column![widgets::pill(t, status, word)].spacing(2);
                if let Some(at) = s.checked.get(&r.item.path).and_then(|c| c.checked_at) {
                    state = state.push(text(format!("at {}", hhmm(at))).size(look::SMALL).color(color(t.ink_muted)));
                }
                let mut path = column![text(r.item.path.clone()).size(look::PATH).font(look::MONO)].spacing(2);
                if k == 4 {
                    path = path.push(text("The copy is no longer in the box. The record is kept.").size(look::SMALL));
                } else if !r.item.sidecar {
                    path = path.push(text("No provenance file beside this copy").size(look::SMALL));
                }
                if k == 2 {
                    path = path.push(text(meaning).size(look::SMALL));
                }
                let hash = r.item.hash.to_string();
                let copied = c.copied.as_deref() == Some(hash.as_str());
                (
                    false,
                    vec![
                        state.into(),
                        path.into(),
                        text(when(r.item.admitted_at)).size(look::SMALL).into(),
                        text(size(r.item.bytes)).size(look::SMALL).into(),
                        widgets::chip(t, &hash.chars().take(12).collect::<String>(), copied, Message::Copy(hash.clone())),
                    ],
                )
            })
            .collect();
        page = page.push(
            column![
                row![text(source).size(look::H3).font(look::BOLD), text(sub).size(look::SMALL).color(color(t.ink_muted))].spacing(look::S3).align_y(Alignment::End),
                widgets::table(
                    t,
                    &[("State", Length::Fixed(150.0)), ("File", Length::Fill), ("Let in", Length::Fixed(130.0)), ("Size", Length::Fixed(90.0)), ("Hash", Length::Fixed(170.0))],
                    table_rows,
                    false
                ),
            ]
            .spacing(look::S3),
        );
    }
    page.into()
}

/// The delete's confirm: what goes, what stays.
pub fn confirm<'a>(t: Theme, d: &Data) -> Element<'a, Message> {
    let col = |glyph: &'static str, title: &'static str, items: Vec<String>| {
        let mut c = column![row![crate::widgets::icon(glyph, look::ICON_SM, t.ink), text(title).size(look::SMALL).font(look::BOLD)].spacing(look::S2)].spacing(look::S2);
        for i in items {
            c = c.push(text(format!("• {i}")).size(look::SMALL));
        }
        widgets::card(t, c)
    };
    let body = column![
        text("This deletes every copy Sluse let into this box when an AI agent fetched a file, from every session.").size(look::BODY),
        row![
            col("wipe", "Goes", vec![what_goes(d), "The provenance file beside each copy".into(), "Downloads that did not finish".into()]),
            col(
                "check",
                "Stays",
                vec!["The record of every admission, in this box and on your computer".into(), "What was published, in Sluse Artifacts".into(), "The files at their sources".into()]
            ),
        ]
        .spacing(look::S3),
        text("An AI agent can ask Sluse for a file again later. That is a new admission, recorded like the first.").size(look::SMALL).color(color(t.ink_muted)),
    ]
    .spacing(look::S3);
    widgets::dialog(
        t,
        "wipe",
        "Delete the copies in your box?".into(),
        body.into(),
        vec![
            widgets::btn(t, Btn::Plain, false, text("Cancel").size(look::SMALL)).on_press(Message::Close).into(),
            widgets::btn(t, Btn::Destructive, false, widgets::label(t, Some("wipe"), "Delete the copies")).on_press(Message::Clear).into(),
        ],
    )
}

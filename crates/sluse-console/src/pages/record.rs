// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Record: what this box recorded in this session, newest first, in words,
//! with the reason code under the words for whoever supports Sluse. On a
//! development device the computer's record stands beside it, never merged:
//! they are joined by admission id, and merging would hide exactly the
//! disagreement the join exists to find (invariant 7).
//! (The web console's views/record.ts, until 0.3.)

use std::sync::Arc;

use iced::widget::{column, row, text};
use iced::{Alignment, Element, Length, Task};
use sluse_endpoint::console::Console as Calls;
use sluse_proto::audit::{AuditRecord, Op, Outcome};

use crate::app::{Console, Data, Message};
use crate::look::{self, Theme, color};
use crate::widgets::{self, Btn};
use crate::words::{op_words, outcome_pill, reason_words, when};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Shown {
    #[default]
    All,
    In,
    Published,
    Problems,
    Other,
}

const KINDS: [(Shown, &str); 5] =
    [(Shown::All, "All"), (Shown::In, "Let in"), (Shown::Published, "Published"), (Shown::Problems, "Refused and errors"), (Shown::Other, "Other")];

fn kind_of(r: &AuditRecord) -> Shown {
    match (r.outcome, r.op) {
        (Outcome::Refused | Outcome::Error, _) => Shown::Problems,
        (_, Op::Read | Op::Fetch | Op::Call) => Shown::In,
        (_, Op::Publish) => Shown::Published,
        _ => Shown::Other,
    }
}

const PAGE: usize = 50;

#[derive(Default)]
pub struct Record {
    pub shown: Shown,
    pub pages: usize,
    /// The computer's record, on a development device, as last read.
    pub host: Option<Result<Arc<Vec<AuditRecord>>, String>>,
}

impl Record {
    /// On a development device, the computer's record beside the box's.
    pub fn load_host(calls: &Arc<Calls>) -> Task<Message> {
        let calls = calls.clone();
        Task::perform(async move { calls.audit(PAGE).await.map(|t| Arc::new(t.records)).map_err(|e| e.to_string()) }, Message::Host)
    }
}

fn path_words(r: &AuditRecord) -> String {
    if r.op == Op::Clear { "(every copy in the box)".into() } else { r.path_requested.trim_start_matches("artifacts/").to_owned() }
}

fn table<'a>(c: &Console, t: Theme, rs: &[&AuditRecord]) -> Element<'a, Message> {
    let rows = rs
        .iter()
        .map(|r| {
            let (status, word) = outcome_pill(r);
            let note = reason_words(r.reason.as_deref(), r.outcome);
            let code = r.reason.clone().filter(|code| *code != note);
            let mut note_col = column![].spacing(2);
            if !note.is_empty() && Some(&note) != code.as_ref() {
                note_col = note_col.push(text(note).size(look::SMALL));
            }
            if let Some(code) = code {
                note_col = note_col.push(
                    row![text("Recorded as").size(look::SMALL).color(color(t.ink_muted)), text(code).size(look::PATH).font(look::MONO)].spacing(look::S1),
                );
            }
            let hash: Element<'_, Message> = match &r.hash {
                Some(h) => {
                    let h = h.to_string();
                    let copied = c.copied.as_deref() == Some(h.as_str());
                    widgets::chip(t, &h.chars().take(12).collect::<String>(), copied, Message::Copy(h.clone()))
                }
                None => text("none").size(look::SMALL).color(color(t.ink_muted)).into(),
            };
            (
                matches!(r.outcome, Outcome::Refused | Outcome::Error),
                vec![
                    text(when(r.ts)).size(look::SMALL).into(),
                    text(op_words(r.op)).size(look::SMALL).into(),
                    text(path_words(r)).size(look::PATH).font(look::MONO).into(),
                    widgets::pill(t, status, word),
                    note_col.into(),
                    hash,
                ],
            )
        })
        .collect();
    widgets::table(
        t,
        &[
            ("Time", Length::Fixed(90.0)),
            ("What", Length::Fixed(140.0)),
            ("File", Length::FillPortion(4)),
            ("Outcome", Length::Fixed(120.0)),
            ("Note", Length::FillPortion(3)),
            ("Hash", Length::Fixed(160.0)),
        ],
        rows,
        true,
    )
}

pub fn view<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    let s = &c.record;
    let all: Vec<&AuditRecord> = d.journal.iter().rev().collect();
    let count = |k: Shown| if k == Shown::All { all.len() } else { all.iter().filter(|r| kind_of(r) == k).count() };
    let head = widgets::pagehead(
        t,
        "Record",
        if d.state.local {
            "Two records side by side, never merged: this computer's and this box's. They share admission ids. Both hold what reached Sluse, not what an agent did without asking it.".into()
        } else {
            "What this box recorded in this session, newest first. It holds what reached Sluse. What an agent did without asking Sluse is not here. Sluse on your computer keeps its own record, in this computer's Event Log, which your IT department can read; it is separate, and it holds the reasons for refusals.".into()
        },
        vec![],
    );
    if all.is_empty() {
        return column![
            head,
            widgets::empty(
                t,
                "journal",
                "Nothing recorded yet in this session".into(),
                vec!["When an AI agent asks Sluse for a file, or publishes one, the box records it here as it happens.".into()],
                None
            )
        ]
        .spacing(look::S8)
        .into();
    }
    let seg = widgets::seg(t, KINDS.iter().map(|(k, label)| ((*label).to_owned(), count(*k), s.shown == *k, Message::Filter(*k))).collect());
    let shown: Vec<&AuditRecord> = all.iter().copied().filter(|r| s.shown == Shown::All || kind_of(r) == s.shown).collect();
    let total = shown.len();
    let rows: Vec<&AuditRecord> = shown.into_iter().take(s.pages.max(1) * PAGE).collect();
    let mut mine = column![].spacing(look::S3);
    if d.state.local {
        mine = mine.push(text("This box").size(look::H3).font(look::BOLD));
    }
    mine = mine.push(if rows.is_empty() {
        Element::from(text("No records of this kind in this session.").size(look::SMALL).color(color(t.ink_muted)))
    } else {
        table(c, t, &rows)
    });
    if total > rows.len() {
        mine = mine.push(
            row![
                widgets::btn(t, Btn::Plain, false, text("Show 50 more").size(look::SMALL)).on_press(Message::More),
                text(format!("Showing the newest {} of {total}.", rows.len())).size(look::SMALL).color(color(t.ink_muted)),
            ]
            .spacing(look::S3)
            .align_y(Alignment::Center),
        );
    }
    let body: Element<'_, Message> = if d.state.local {
        let host: Element<'_, Message> = match &s.host {
            None => text("Reading…").size(look::SMALL).color(color(t.ink_muted)).into(),
            Some(Ok(records)) => {
                let rs: Vec<&AuditRecord> = records.iter().rev().collect();
                table(c, t, &rs)
            }
            Some(Err(_)) => text("Not available: Sluse on your computer did not send its record. In a box it never does; this column exists on a development device only.")
                .size(look::SMALL)
                .color(color(t.ink_muted))
                .into(),
        };
        column![column![text("This computer: Sluse").size(look::H3).font(look::BOLD), host].spacing(look::S3), mine].spacing(look::S8).into()
    } else {
        mine.into()
    };
    column![head, seg, body].spacing(look::S6).into()
}

// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Your artifacts: every publish from this box, this session first, then
//! earlier sessions, dated (Q37). One group per publish, named as its folder
//! in Sluse Artifacts; each file lists the sources the agent declared (D-055).
//! Sluse checked each declared source was let in; it does not know how the
//! agent used them. Never "verified". (The web console's views/artifacts.ts, until 0.3.)

use iced::widget::{Space, column, container, row, text};
use iced::{Alignment, Border, Element, Length};
use sluse_endpoint::console::api::Provenance;
use sluse_proto::LineageItem;
use sluse_proto::audit::{AdmissionState, Outcome};

use crate::app::{Console, Data, Dialog, Message};
use crate::look::{self, Theme, color};
use crate::widgets::{self, Btn, icon};
use crate::words::{day, folder_of, hhmm, size, weekday, when};

/// A declared source's state: its pill, its word, and what it means.
pub const STATES: [(&str, &str, &str); 4] = [
    ("read", "Read", "Its text was shown to the agent. Sluse kept no copy of it."),
    ("unread", "Let in, not shown", "Sluse let it in, but its text could not be shown to the agent."),
    ("fetched", "Fetched", "A copy was fetched into the box."),
    ("encrypted", "Encrypted", "Arrived encrypted by its label. Sluse gave the box no key to open it."),
];

fn state_of(s: &LineageItem) -> (&'static str, &'static str, &'static str) {
    STATES[match s.state {
        None | Some(AdmissionState::Read) => 0,
        Some(AdmissionState::Unread) => 1,
        Some(AdmissionState::Fetched) => 2,
        Some(AdmissionState::Encrypted) => 3,
    }]
}

fn chip<'a>(c: &Console, t: Theme, value: String) -> Element<'a, Message> {
    let copied = c.copied.as_deref() == Some(value.as_str());
    widgets::chip(t, &value, copied, Message::Copy(value.clone()))
}

/// The first twelve characters of a long value; the chip copies it whole.
fn short(c: &Console, t: Theme, value: String) -> Element<'static, Message> {
    let copied = c.copied.as_deref() == Some(value.as_str());
    widgets::chip(t, &value.chars().take(12).collect::<String>(), copied, Message::Copy(value.clone()))
}

fn fact<'a>(t: Theme, label: &'static str, value: Element<'a, Message>) -> Element<'a, Message> {
    column![text(label.to_uppercase()).size(look::LABEL).color(color(t.ink_muted)), value].spacing(2).into()
}

fn source<'a>(c: &Console, t: Theme, s: &LineageItem) -> Element<'a, Message> {
    let (status, word, _) = state_of(s);
    let mut ids = row![].spacing(look::S4);
    if let Some(a) = &s.admission_id {
        ids = ids.push(fact(t, "Admission", chip(c, t, a.to_string())));
    }
    ids = ids.push(fact(t, "Hash", short(c, t, s.hash.to_string())));
    column![row![chip(c, t, s.path.clone()), widgets::pill(t, status, word)].spacing(look::S2).align_y(Alignment::Center), ids]
        .spacing(look::S2)
        .into()
}

/// One published file: its sources as the agent declared them, and its facts.
fn card<'a>(c: &Console, t: Theme, p: &Provenance) -> Element<'a, Message> {
    let name = p.artifact.clone().unwrap_or_else(|| p.path.clone());
    let mut head = row![icon("artifact", look::ICON, t.ink), text(name).size(look::BODY).font(look::BOLD), widgets::pill(t, "published", "Published")]
        .spacing(look::S2)
        .align_y(Alignment::Center);
    if p.reason.as_deref().is_some_and(|r| r.starts_with("rendered by")) {
        head = head.push(text("Rendered by Sluse from the agent's Markdown.").size(look::SMALL).color(color(t.ink_muted)));
    }
    let muted = |s: &'static str| text(s).size(look::SMALL).color(color(t.ink_muted));
    let body: Element<'_, Message> = match &p.sources {
        None => muted("No declaration on record: published before Sluse asked agents for their sources.").into(),
        Some(s) if s.is_empty() => {
            column![text("Sources the agent declared: none").size(look::SMALL).font(look::BOLD), muted("The agent declared no sources for this file.")]
                .spacing(look::S1)
                .into()
        }
        Some(s) => {
            let mut col = column![text(format!("Sources the agent declared: {}", s.len())).size(look::SMALL).font(look::BOLD)].spacing(look::S3);
            for item in s {
                col = col.push(container(source(c, t, item)).padding(iced::Padding { left: 28.0, ..Default::default() }));
            }
            col.into()
        }
    };
    let mut facts = row![fact(t, "Published", text(when(p.at)).size(look::SMALL).into()), fact(t, "Size", text(size(p.bytes)).size(look::SMALL).into())]
        .spacing(look::S4);
    if let Some(h) = &p.hash {
        facts = facts.push(fact(t, "Hash", short(c, t, h.to_string())));
    }
    widgets::card(t, column![head, body, facts].spacing(look::S3))
}

fn why(code: &str) -> &'static str {
    match code {
        "SOURCE_NOT_ADMITTED" => "The agent declared a source this box never let in. A declaration can only name files Sluse let in.",
        "HASH_MISMATCH" => "The file changed while it was being published, so what arrived did not match what the agent sent. Ask the agent to publish it again.",
        _ => "Sluse did not publish it. Ask the agent to try again. If it happens again, send the details to your IT department.",
    }
}

fn refused<'a>(c: &'a Console, t: Theme, p: &Provenance) -> Element<'a, Message> {
    let code = p.reason.clone().unwrap_or_default();
    let name = p.artifact.clone().unwrap_or_else(|| p.path.trim_start_matches("artifacts/").to_owned());
    let (status, word) = if p.outcome == Outcome::Refused { ("refused", "Refused") } else { ("error", "Error") };
    let raw = format!(
        "publish {}: {}\nrequested: {}\nsession {}, {}",
        if p.outcome == Outcome::Refused { "refused" } else { "error" },
        if code.is_empty() { "no code" } else { &code },
        p.path,
        p.session_id,
        p.at.to_rfc3339()
    );
    widgets::card(
        t,
        column![
            row![icon("artifact", look::ICON, t.ink), text(name).size(look::BODY).font(look::BOLD), text("(attempted)").size(look::SMALL), widgets::pill(t, status, word)]
                .spacing(look::S2)
                .align_y(Alignment::Center),
            text("Nothing was published, so nothing reached Sluse Artifacts.").size(look::SMALL).color(color(t.ink_muted)),
            row![icon("refused", look::ICON, t.ink), text(why(&code)).size(look::SMALL)].spacing(look::S2),
            fact(t, "Attempted", text(when(p.at)).size(look::SMALL).into()),
            crate::app::details(c, t, raw),
        ]
        .spacing(look::S3),
    )
}

/// One publish: one folder in Sluse Artifacts, one group of cards.
fn publish<'a>(c: &'a Console, t: Theme, folder: String, ps: &[&Provenance]) -> Element<'a, Message> {
    let first = ps[ps.len() - 1];
    let mut head = row![
        icon("folder", look::ICON, t.ink_muted),
        chip(c, t, folder),
        text(format!("{} file{}, published at {}", ps.len(), if ps.len() == 1 { "" } else { "s" }, hhmm(first.at))).size(look::SMALL).color(color(t.ink_muted)),
        Space::new().width(Length::Fill),
    ]
    .spacing(look::S2)
    .align_y(Alignment::Center);
    if let Some(id) = &first.publish_id {
        head = head.push(text("Publish id").size(look::SMALL).color(color(t.ink_muted))).push(chip(c, t, id.to_string()));
    }
    let mut cards = column![].spacing(look::S3);
    for p in ps {
        cards = cards.push(card(c, t, p));
    }
    column![
        head,
        text("In Sluse Artifacts on your computer. Open it with Sluse Artifacts in the bar above the box.").size(look::SMALL).color(color(t.ink_muted)),
        cards
    ]
    .spacing(look::S3)
    .into()
}

/// A session's publishes, refused ones first in their own group.
fn publishes<'a>(c: &'a Console, t: Theme, ps: &[&'a Provenance]) -> Vec<Element<'a, Message>> {
    let mut out = Vec::new();
    let bad: Vec<&Provenance> = ps.iter().copied().filter(|p| p.outcome != Outcome::Admitted).collect();
    if !bad.is_empty() {
        let mut cards = column![].spacing(look::S3);
        for p in bad {
            cards = cards.push(refused(c, t, p));
        }
        out.push(
            column![
                row![icon("refused", look::ICON, t.ink), text("Not published").size(look::H3).font(look::BOLD)].spacing(look::S2).align_y(Alignment::Center),
                text("Sluse refused these. Nothing reached Sluse Artifacts. Ask the agent to try again; it was told why.").size(look::SMALL).color(color(t.ink_muted)),
                cards,
            ]
            .spacing(look::S3)
            .into(),
        );
    }
    let mut groups: Vec<(String, Vec<&Provenance>)> = Vec::new();
    for p in ps.iter().copied().filter(|p| p.outcome == Outcome::Admitted) {
        let f = folder_of(&p.path, p.artifact.as_deref())
            .or_else(|| p.publish_id.as_ref().map(|i| i.to_string()))
            .unwrap_or_else(|| p.at.to_rfc3339());
        match groups.iter_mut().find(|(k, _)| *k == f) {
            Some((_, g)) => g.push(p),
            None => groups.push((f, vec![p])),
        }
    }
    for (f, g) in groups {
        out.push(publish(c, t, f, &g));
    }
    out
}

pub fn view<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    let head = widgets::pagehead(
        t,
        "Your artifacts",
        "What AI agents published from this box, this session first, then earlier sessions. One group for each publish, as its folder in Sluse Artifacts. Each file lists the sources the agent declared for it. Sluse checked that each declared source was let into this box; it does not know how the agent used them, or whether it used others.".into(),
        vec![widgets::btn(t, Btn::Plain, false, widgets::label(t, Some("info"), "What the states mean")).on_press(Message::Show(Dialog::States)).into()],
    );
    if d.provenance.is_empty() {
        return column![
            head,
            widgets::empty(
                t,
                "artifact",
                "Nothing published from this box yet".into(),
                vec!["When an AI agent publishes a result, it appears here with the sources the agent declared for it, and lands in Sluse Artifacts on your computer. Every session of this box is listed here, this one first.".into()],
                None,
            )
        ]
        .spacing(look::S8)
        .into();
    }
    // Sessions in the order their newest publish came, this one first.
    let mut sessions: Vec<(String, Vec<&Provenance>)> = Vec::new();
    for p in &d.provenance {
        let id = p.session_id.to_string();
        match sessions.iter_mut().find(|(k, _)| *k == id) {
            Some((_, g)) => g.push(p),
            None => sessions.push((id, vec![p])),
        }
    }
    let this = d.state.session.to_string();
    let mine: Vec<&Provenance> = sessions.iter().find(|(k, _)| *k == this).map(|(_, g)| g.clone()).unwrap_or_default();
    let sess_head = |title: String, span: String, id: String, big: bool| {
        row![
            text(title).size(if big { look::H3 } else { look::BODY }).font(look::BOLD),
            text(span).size(look::SMALL).color(color(t.ink_muted)),
            Space::new().width(Length::Fill),
            text("Session").size(look::SMALL).color(color(t.ink_muted)),
            chip(c, t, id),
        ]
        .spacing(look::S3)
        .align_y(Alignment::Center)
    };
    let start = d.session_start();
    let mut this_one = column![sess_head(
        "This session".into(),
        start.map(|s| format!("Since the box opened at {}, {}", hhmm(s), day(s))).unwrap_or_else(|| "Since the box opened".into()),
        this.clone(),
        true
    )]
    .spacing(look::S6);
    if mine.is_empty() {
        this_one = this_one.push(text("Nothing published yet in this session.").size(look::SMALL).color(color(t.ink_muted)));
    } else {
        for g in publishes(c, t, &mine) {
            this_one = this_one.push(g);
        }
    }
    let mut page = column![head, this_one].spacing(look::S12);
    let earlier: Vec<&(String, Vec<&Provenance>)> = sessions.iter().filter(|(k, _)| *k != this).collect();
    if !earlier.is_empty() {
        let mut col = column![
            text("Earlier sessions").size(look::H3).font(look::BOLD),
            text("Published from this box before it was last opened, newest first. Each folder is still in Sluse Artifacts on your computer.").size(look::SMALL).color(color(t.ink_muted)),
        ]
        .spacing(look::S3);
        for (id, ps) in earlier {
            let (first, last) = (ps[ps.len() - 1].at, ps[0].at);
            let span = if hhmm(first) == hhmm(last) {
                format!("{}, published at {}", weekday(first), hhmm(first))
            } else {
                format!("{}, published from {} to {}", weekday(first), hhmm(first), hhmm(last))
            };
            let mut s = column![sess_head(day(first), span, id.clone(), false)].spacing(look::S6);
            for g in publishes(c, t, ps) {
                s = s.push(g);
            }
            col = col.push(
                container(s).padding(iced::Padding { top: 16.0, ..Default::default() }).style(move |_| container::Style {
                    border: Border { color: color(t.line), width: 0.0, radius: 0.0.into() },
                    ..Default::default()
                }),
            );
        }
        page = page.push(col);
    }
    page.into()
}

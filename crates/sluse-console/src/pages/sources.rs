// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Sources: what the agents in this box can see, folder by folder. Opening a
//! folder asks Sluse (`/v1/list`), and that is recorded on the computer, so it
//! is always a click: "List again" re-lists on purpose, and a timed read never
//! moves the person's place (D-032). Nothing here lets a file in; there is no
//! Open button. In a box every listed row is in scope (D-033); on a
//! development device the out-of-scope ones are listed too, marked.
//! (The web console's views/sources.ts, until 0.3.)

use std::sync::Arc;

use chrono::{DateTime, Utc};
use iced::widget::{Space, button, column, row, text};
use iced::{Alignment, Element, Length, Task};
use sluse_endpoint::console::Console as Calls;
use sluse_proto::{EntryKind, ListResponse, SourceView};

use crate::app::{Console, Data, Message};
use crate::look::{self, Theme, color};
use crate::widgets::{self, Btn, Kind, icon};
use crate::words::{code, kind_icon, kind_words, size, when};

/// Where the person is, and what the last listing said.
#[derive(Default)]
pub struct Sources {
    at: String,
    listing: Option<Arc<ListResponse>>,
    listed_at: Option<DateTime<Utc>>,
    /// The refusal's code and its error as recorded.
    failure: Option<(String, String)>,
    opening: Option<String>,
}

impl Sources {
    /// Open a folder: a click, recorded on the computer as an agent's would be.
    pub fn open(&mut self, calls: &Arc<Calls>, path: String) -> Task<Message> {
        self.at = path.clone();
        if path.is_empty() {
            self.listing = None;
            self.failure = None;
            return Task::none();
        }
        self.opening = Some(path.clone());
        let calls = calls.clone();
        Task::perform(
            async move {
                let r = calls.list(&path).await.map(Arc::new).map_err(|e| (code(&e), serde_json::to_string(&e).unwrap_or_default()));
                (path, r)
            },
            |(path, r)| Message::Listed(path, r),
        )
    }

    pub fn listed(&mut self, path: String, r: Result<Arc<ListResponse>, (String, String)>) {
        if path != self.at {
            return;
        }
        match r {
            Ok(l) => {
                self.listing = Some(l);
                self.failure = None;
            }
            Err(f) => {
                self.listing = None;
                self.failure = Some(f);
            }
        }
        self.listed_at = Some(Utc::now());
        self.opening = None;
    }
}

fn what(s: &SourceView) -> String {
    if s.kind == "onedrive" {
        return "Your Sluse folder".into();
    }
    if s.scopes.is_empty() {
        return "The whole folder".into();
    }
    format!("{} folder{}: {}", s.scopes.len(), if s.scopes.len() == 1 { "" } else { "s" }, s.scopes.join(", "))
}

fn linkrow<'a>(t: Theme, glyph: &'static str, name: String, msg: Message) -> Element<'a, Message> {
    button(row![icon(glyph, look::ICON, t.ink_muted), text(name).size(look::PATH).font(look::MONO)].spacing(look::S2).align_y(Alignment::Center))
        .padding(0)
        .on_press(msg)
        .style(move |_, s| button::Style {
            text_color: color(t.ink),
            background: (s == button::Status::Hovered).then(|| color(t.tint_wash()).into()),
            ..Default::default()
        })
        .into()
}

pub fn view<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    let s = &c.sources;
    let source = s.at.split('/').next().unwrap_or_default().to_owned();
    let mut page = column![
        widgets::pagehead(
            t,
            "Sources",
            "What the AI agents in this box can see, folder by folder. Opening a folder here asks Sluse, and that is recorded on your computer, as it is when an agent asks.".into(),
            vec![]
        ),
        widgets::note(t, Kind::Info, text("There is no Open button here. A file from these sources reaches the box only when an AI agent asks Sluse for it.").size(look::SMALL)),
    ]
    .spacing(look::S6);
    if d.state.local {
        page = page.push(widgets::strip(
            t,
            Kind::Warning,
            "Development device".into(),
            "On this device Sluse also lists what the agents cannot see, marked Out of scope. In a box, those entries are not listed at all.".into(),
            vec![],
            None,
        ));
    }

    // The crumbs, and where the listing stands.
    let crumb = |label: String, path: String, here: bool| {
        button(text(label).size(look::SMALL).font(if here { look::BOLD } else { look::MONO }))
            .padding([look::S1, look::S2])
            .on_press(Message::List(path))
            .style(move |_, st| button::Style {
                text_color: color(t.ink),
                background: (st == button::Status::Hovered).then(|| color(t.tint_wash()).into()),
                ..Default::default()
            })
    };
    let parts: Vec<&str> = if s.at.is_empty() { vec![] } else { s.at.split('/').collect() };
    let mut crumbs = row![crumb("sources".into(), String::new(), s.at.is_empty())].spacing(look::S1).align_y(Alignment::Center);
    for (i, p) in parts.iter().enumerate() {
        crumbs = crumbs.push(text("/").size(look::SMALL).color(color(t.ink_muted)));
        crumbs = crumbs.push(crumb((*p).to_owned(), parts[..=i].join("/"), i + 1 == parts.len()));
    }
    let mut bar = row![crumbs, Space::new().width(Length::Fill)].spacing(look::S3).align_y(Alignment::Center);
    if let Some(o) = &s.opening {
        bar = bar.push(text(format!("Opening {}", o.rsplit('/').next().unwrap_or(o))).size(look::SMALL));
    } else if let (Some(at), false) = (s.listed_at, s.at.is_empty()) {
        bar = bar.push(text(format!("Listed at {}", when(at))).size(look::SMALL).color(color(t.ink_muted)));
    }
    if !s.at.is_empty() {
        bar = bar.push(widgets::btn(t, Btn::Plain, true, widgets::label(t, Some("refresh"), "List again")).on_press(Message::List(s.at.clone())));
    }

    let problem = |title: String, body: String, raw: Option<String>, action: Option<Element<'a, Message>>| {
        let mut col = column![widgets::empty(t, "folder", title, vec![body], action)].spacing(look::S2);
        if let Some(raw) = raw {
            col = col.push(crate::app::details(c, t, raw));
        }
        Element::from(col)
    };
    let body: Element<'_, Message> = if s.at.is_empty() {
        let rows = d
            .view
            .sources
            .iter()
            .map(|v| {
                let sens = v.sensitivity_name.clone();
                let sens = sens.chars().next().map(|f| f.to_uppercase().collect::<String>() + &sens[f.len_utf8()..]).unwrap_or_default();
                (
                    false,
                    vec![
                        linkrow(t, kind_icon(&v.kind), v.name.as_str().to_owned(), Message::List(v.name.as_str().to_owned())),
                        text(kind_words(v).split(',').next().unwrap_or_default().to_owned()).size(look::SMALL).into(),
                        text(what(v)).size(look::SMALL).into(),
                        text(sens).size(look::SMALL).into(),
                    ],
                )
            })
            .collect();
        widgets::table(
            t,
            &[("Source", Length::FillPortion(3)), ("Kind", Length::FillPortion(2)), ("What the agents can see", Length::FillPortion(4)), ("Sensitivity", Length::FillPortion(2))],
            rows,
            false,
        )
    } else if let Some((code, raw)) = &s.failure {
        let raw = Some(raw.clone());
        match code.as_str() {
            "SOURCE_UNAVAILABLE" => problem(
                "The source did not answer".into(),
                format!("{source} did not answer Sluse. Try again in a moment with List again. If it keeps happening, send the details to your IT department."),
                raw,
                None,
            ),
            "SIGN_IN_REQUIRED" => problem(
                "Sluse needs you to sign in again".into(),
                format!("{source} cannot be listed until you do. To sign in, close the box from the bar above and open Sluse again."),
                raw,
                None,
            ),
            "GATE_UNREACHABLE" => problem(
                "Sluse on your computer is not answering".into(),
                "Nothing can be listed until it answers. This page asks again by itself; use List again when the bar above says it is back.".into(),
                raw,
                None,
            ),
            "NOT_FOUND" if s.at == source && d.view.sources.iter().any(|v| v.name.as_str() == source && v.kind == "onedrive") => problem(
                "Your Sluse folder in OneDrive is not there yet".into(),
                "It appears here once OneDrive has synced it. If you have not made it yet, the Sluse window on your computer offers to.".into(),
                None,
                None,
            ),
            "NOT_FOUND" => problem(
                "This folder is no longer there".into(),
                "It was moved or deleted at the source after the list above it was made.".into(),
                raw,
                (s.at != source).then(|| widgets::btn(t, Btn::Plain, false, text(format!("Back to {source}")).size(look::SMALL)).on_press(Message::List(source.clone())).into()),
            ),
            _ => problem(
                "Sluse did not list this folder".into(),
                "The agents in this box cannot open it through Sluse. The reason is in this computer's Event Log, which your IT department can read; send them the details if you need to know.".into(),
                raw,
                None,
            ),
        }
    } else if let Some(listing) = &s.listing {
        let mut entries: Vec<_> = listing.entries.iter().filter(|e| e.in_scope || d.state.local).collect();
        if entries.is_empty() {
            problem("Nothing to see in this folder".into(), format!("Nothing in {} is visible to the AI agents in this box.", s.at), None, None)
        } else {
            entries.sort_by(|a, b| match (a.kind == b.kind, a.kind == EntryKind::Directory) {
                (true, _) => a.name.cmp(&b.name),
                (false, true) => std::cmp::Ordering::Less,
                (false, false) => std::cmp::Ordering::Greater,
            });
            let mut cols = vec![("Name", Length::FillPortion(5)), ("Modified", Length::Fixed(160.0)), ("Size", Length::Fixed(100.0))];
            if d.state.local {
                cols.push(("Scope", Length::Fixed(160.0)));
            }
            let rows = entries
                .iter()
                .map(|e| {
                    let dir = e.kind == EntryKind::Directory;
                    let name: Element<'_, Message> = if dir && e.in_scope {
                        linkrow(t, "folder", e.name.clone(), Message::List(format!("{}/{}", s.at, e.name)))
                    } else {
                        row![icon(if dir { "folder" } else { "file" }, look::ICON, t.ink_muted), text(e.name.clone()).size(look::PATH).font(look::MONO)]
                            .spacing(look::S2)
                            .align_y(Alignment::Center)
                            .into()
                    };
                    let mut cells = vec![name, text(e.modified.map(when).unwrap_or_default()).size(look::SMALL).into(), text(size(e.size)).size(look::SMALL).into()];
                    if d.state.local {
                        cells.push(if e.in_scope { widgets::pill(t, "in-scope", "In scope") } else { widgets::pill(t, "out-of-scope", "Out of scope") });
                    }
                    (false, cells)
                })
                .collect();
            widgets::table(t, &cols, rows, false)
        }
    } else {
        text("Opening…").size(look::SMALL).color(color(t.ink_muted)).into()
    };
    page.push(column![bar, body].spacing(look::S3)).into()
}

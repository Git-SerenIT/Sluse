// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Work: the console's first page (D-034 point 9, Q41, Q72), for the person
//! working, not the person auditing. The chamber is its one picture: the
//! sources converge on the gate in the lock's wall, where Sluse lets files in
//! and counts them per source (Q36), and the box lies past it. Every number
//! here is counted from the box's own journal, except the meters, which are
//! Sluse's own counts in the alert's window, so meter and alert agree.
//! (The web console's views/work.ts, until 0.3.)

use std::collections::{BTreeMap, BTreeSet, HashMap};

use iced::widget::canvas::{self, Frame, Path, Stroke};
use iced::widget::text::Wrapping;
use iced::widget::{Space, button, canvas as canvas_widget, column, container, row, stack, text};
use iced::{Alignment, Border, Element, Length, Point, Rectangle, Renderer, mouse};
use sluse_endpoint::console::api::GateState;
use sluse_proto::audit::{AuditRecord, Op, Outcome};

use crate::app::{Console, Data, Message, Page};
use crate::look::{self, Theme, color};
use crate::widgets::{self, Btn, Kind, icon};
use crate::words::{ago, folder_of, hhmm, kind_icon, kind_words, list, plural, source_of, window, within};

/// The lock's width, and where its gate sits (style.css's `--gate-y`). 300,
/// not the web console's 380, so the sources keep their width in the box's
/// 1024-wide window (L1, 2026-11-03). Fixed: the row takes its height from
/// the lock, and without a fixed column iced drew the sources' column empty.
const LOCK_W: f32 = 300.0;
const GATE_Y: f32 = 76.0;
/// A source's row in the chamber, fixed so the streams know where it is.
const SRC_H: f32 = 58.0;
const SRC_ACTIVE_H: f32 = 78.0;
const SRC_GAP: f32 = 8.0;
/// The column's padding, its label and the label's gap: where the first row starts.
const SRC_TOP: f32 = 24.0 + 16.0 + 12.0;

pub fn view<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    let vol = &d.view.volume;
    let win = window(vol.window_seconds);
    let ins: Vec<&AuditRecord> = d.let_in().collect();
    let files: BTreeSet<String> = ins.iter().map(|r| r.hash.as_ref().map(|h| h.to_string()).unwrap_or_else(|| r.path_requested.clone())).collect();
    let read = ins.iter().filter(|r| r.op == Op::Read).count();
    let fetched = ins.iter().filter(|r| r.op == Op::Fetch).count();
    let pubs: Vec<&AuditRecord> = d.journal.iter().filter(|r| r.op == Op::Publish && r.outcome == Outcome::Admitted).collect();
    let folders: BTreeSet<Option<String>> = pubs.iter().map(|r| folder_of(&r.path_requested, r.artifact.as_deref())).collect();
    let mut from: Vec<String> = Vec::new();
    for r in &ins {
        let s = source_of(&r.path_requested).to_owned();
        if !from.contains(&s) {
            from.push(s);
        }
    }
    let refused: Vec<&AuditRecord> =
        d.journal.iter().filter(|r| r.op == Op::Publish && matches!(r.outcome, Outcome::Refused | Outcome::Error)).collect();
    let earlier = d
        .inventory
        .iter()
        .filter(|row| !ins.iter().any(|r| r.admission_id.is_some() && r.admission_id == row.item.admission_id))
        .count();
    let nothing = ins.is_empty() && pubs.is_empty();
    let limit = format!("{} files from one source in {win}", vol.admissions);

    let mut page = column![widgets::pagehead(t, "Work", "What Sluse let into your box and what AI agents published from it, in this session.".into(), vec![])]
        .spacing(look::S8);

    // Open alerts, and publishes that were not published.
    let mut banners = column![].spacing(look::S2);
    for a in d.alerts.iter().filter(|a| a.closed_at.is_none()) {
        banners = banners.push(widgets::strip(
            t,
            Kind::Info,
            format!("{} files from {} in {}", a.count, a.source.as_str(), window(a.window_seconds)),
            format!(
                "That is past your IT department's volume alert of {limit}. Sluse does not stop the work. It is recorded in this computer's Event Log, which your IT department can read. Since {}.",
                hhmm(a.opened_at)
            ),
            vec![],
            None,
        ));
    }
    if let Some(last) = refused.last() {
        let n = refused.len();
        banners = banners.push(widgets::note(
            t,
            Kind::Warning,
            row![
                text(format!(
                    "{} not published, the last at {}. Nothing reached Sluse Artifacts.",
                    if n == 1 { "One publish was".to_owned() } else { format!("{n} publishes were") },
                    hhmm(last.ts)
                ))
                .size(look::SMALL),
                link(t, "See it in Your artifacts", Message::Page(Page::Artifacts)),
            ]
            .spacing(look::S2),
        ));
    }
    if !d.alerts.iter().all(|a| a.closed_at.is_some()) || !refused.is_empty() {
        page = page.push(banners);
    }

    if nothing && earlier == 0 {
        let step = |n: &'static str, title: &'static str, body: &'static str| {
            row![
                container(text(n).size(look::SMALL).font(look::BOLD)).width(28).height(28).center(28).style(move |_| container::Style {
                    border: Border { color: color(t.ink), width: 1.5, radius: 14.0.into() },
                    ..Default::default()
                }),
                column![text(title).size(look::BODY).font(look::BOLD), text(body).size(look::SMALL).color(color(t.ink_muted))].spacing(look::S1),
            ]
            .spacing(look::S3)
            .width(Length::FillPortion(1))
        };
        page = page.push(
            column![
                text("How work gets in and out").size(look::H3).font(look::BOLD),
                row![
                    step("1", "Open an AI agent", "Claude, Claude Code, Codex or Mistral Vibe, with Open in the bar at the top of this page."),
                    step("2", "Ask it for files", "It asks Sluse. Sluse lets in what you may open yourself, from the sources your IT department chose, and records each one."),
                    step("3", "Find the results", "What the agent publishes lands in Sluse Artifacts on your computer, with the sources it declared."),
                ]
                .spacing(look::S4),
            ]
            .spacing(look::S3),
        );
    }

    page = page.push(chamber(c, t, d, &ins, ChamberFacts { files: files.len(), read, fetched, pubs: pubs.len(), folders: folders.len(), from, earlier, nothing, limit, win }));

    // Let in recently, and this session's artifacts.
    let recent_body: Element<'_, Message> = if ins.is_empty() {
        widgets::empty(
            t,
            "admit",
            "Nothing let in yet".into(),
            vec![format!(
                "Ask an AI agent to read or fetch files from {}. Sluse lets in only what you may open yourself, from the sources your IT department chose.",
                list(&d.view.sources.iter().map(|s| s.name.as_str().to_owned()).collect::<Vec<_>>())
            )],
            Some(widgets::btn(t, Btn::Primary, false, text("Open Claude").size(look::SMALL)).on_press(Message::Open(0)).into()),
        )
    } else {
        let mut items = column![];
        for r in ins.iter().rev().take(5) {
            let (glyph, how) = match r.op {
                Op::Read => ("eye", "read"),
                Op::Call => ("apps", "a tool's answer, saved as a copy"),
                _ => ("download", "fetched as a copy"),
            };
            let note = match r.reason.as_deref() {
                Some("OFFICE_ENCRYPTED") => "; arrived encrypted",
                Some("NOT_UTF8_TEXT") => "; its text could not be shown",
                _ => "",
            };
            items = items.push(
                column![
                    row![
                        icon(glyph, look::ICON, t.ink_muted),
                        column![
                            text(within(&r.path_requested).to_owned()).size(look::PATH).font(look::MONO),
                            text(format!("{}, {how}{note}", source_of(&r.path_requested))).size(look::SMALL).color(color(t.ink_muted)),
                        ]
                        .width(Length::Fill),
                        text(ago(r.ts)).size(look::SMALL).color(color(t.ink_muted)),
                    ]
                    .spacing(look::S3)
                    .align_y(Alignment::Center)
                    .padding([look::S2, 0.0]),
                    widgets::hrule(t),
                ],
            );
        }
        column![items, widgets::btn(t, Btn::Plain, true, text(format!("See all {} in Record", ins.len())).size(look::SMALL)).on_press(Message::Page(Page::Record))]
            .spacing(look::S3)
            .into()
    };
    let recent = widgets::card(t, column![text("Let in recently").size(look::H3).font(look::BOLD), recent_body].spacing(look::S3));

    let mut by_folder: BTreeMap<String, Vec<&AuditRecord>> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for r in &pubs {
        let f = folder_of(&r.path_requested, r.artifact.as_deref())
            .or_else(|| r.publish_id.as_ref().map(|p| p.to_string()))
            .unwrap_or_else(|| r.ts.to_rfc3339());
        if !order.contains(&f) {
            order.push(f.clone());
        }
        by_folder.entry(f).or_default().push(r);
    }
    let earlier_pubs = d.provenance.iter().any(|x| x.session_id != d.state.session && x.outcome == Outcome::Admitted);
    let published_body: Element<'_, Message> = if order.is_empty() {
        widgets::empty(
            t,
            "artifact",
            "Nothing published yet".into(),
            vec![if earlier_pubs {
                "Nothing published in this session. Earlier sessions' publishes are listed in Your artifacts, by session, and are in Sluse Artifacts on your computer.".into()
            } else {
                "When an AI agent publishes a result, it appears here and lands in Sluse Artifacts on your computer, with the sources the agent declared.".into()
            }],
            None,
        )
    } else {
        let mut col = column![].spacing(look::S3);
        for f in order.iter().rev() {
            let rs = &by_folder[f];
            let mut files = column![].spacing(2).padding(iced::Padding { left: 28.0, ..Default::default() });
            for r in rs {
                files = files.push(text(r.artifact.clone().unwrap_or_else(|| within(&r.path_requested).to_owned())).size(look::PATH).font(look::MONO));
            }
            col = col.push(
                column![
                    row![
                        icon("folder", look::ICON, t.ink_muted),
                        widgets::chip(t, f, c.copied.as_deref() == Some(f.as_str()), Message::Copy(f.clone())),
                        Space::new().width(Length::Fill),
                        text(ago(rs[0].ts)).size(look::SMALL).color(color(t.ink_muted)),
                    ]
                    .spacing(look::S2)
                    .align_y(Alignment::Center),
                    files,
                    container(link(t, "Show the sources declared", Message::Page(Page::Artifacts))).padding(iced::Padding { left: 28.0, ..Default::default() }),
                    widgets::hrule(t),
                ]
                .spacing(look::S2),
            );
        }
        col.push(widgets::note(
            t,
            Kind::Info,
            text("Each folder is in Sluse Artifacts on your computer. Open it with Sluse Artifacts in the bar above the box.").size(look::SMALL),
        ))
        .into()
    };
    let mut published = column![text("Your artifacts").size(look::H3).font(look::BOLD), published_body].spacing(look::S3);
    if !order.is_empty() || earlier_pubs {
        published = published.push(
            widgets::btn(t, Btn::Plain, true, text("See this and earlier sessions in Your artifacts").size(look::SMALL)).on_press(Message::Page(Page::Artifacts)),
        );
    }
    page.push(row![recent, widgets::card(t, published)].spacing(look::S6)).into()
}

/// A link in a line of text, `.btn--link`.
pub fn link<'a>(t: Theme, words: &'a str, msg: Message) -> Element<'a, Message> {
    button(text(words).size(look::SMALL).color(color(t.ink)))
        .padding(0)
        .on_press(msg)
        .style(move |_, s| button::Style {
            text_color: color(t.ink),
            border: Border { color: color(if s == button::Status::Hovered { t.ink } else { t.surface }), width: 0.0, radius: 0.0.into() },
            ..Default::default()
        })
        .into()
}

struct ChamberFacts {
    files: usize,
    read: usize,
    fetched: usize,
    pubs: usize,
    folders: usize,
    from: Vec<String>,
    earlier: usize,
    nothing: bool,
    limit: String,
    win: String,
}

/// The chamber: the sources on the left, the lock in the middle with its gate
/// in the left wall, the box on the right; the streams drawn over them.
fn chamber<'a>(c: &'a Console, t: Theme, d: &'a Data, ins: &[&AuditRecord], f: ChamberFacts) -> Element<'a, Message> {
    let _ = c;
    let vol = &d.view.volume;
    let mut from_here: HashMap<String, BTreeSet<String>> = HashMap::new();
    for r in ins {
        from_here
            .entry(source_of(&r.path_requested).to_owned())
            .or_default()
            .insert(r.hash.as_ref().map(|h| h.to_string()).unwrap_or_else(|| r.path_requested.clone()));
    }
    let mut active = Vec::new();
    let mut sources = column![].spacing(SRC_GAP);
    for s in &d.view.sources {
        let n = from_here.get(s.name.as_str()).map_or(0, BTreeSet::len);
        let on = n > 0;
        active.push(on);
        // One line each, clipped inside the card, whose height the streams
        // need: wrapped, they ran out of it in the box's window (L1,
        // 2026-11-03). Sources has each in full.
        let line = |s: String| text(s).wrapping(Wrapping::None);
        let mut words = column![line(s.name.as_str().to_owned()).size(look::PATH).font(look::MONO), line(kind_words(s)).size(look::SMALL).color(color(t.ink_muted))];
        if on {
            words = words.push(text(format!("{n} let in")).size(look::SMALL).font(look::BOLD));
        }
        sources = sources.push(
            container(row![icon(kind_icon(&s.kind), look::ICON, if on { t.ink } else { t.ink_muted }), container(words).width(Length::Fill).clip(true)].spacing(look::S2).align_y(Alignment::Center))
                .padding([look::S2, look::S4])
                .width(Length::Fill)
                .height(if on { SRC_ACTIVE_H } else { SRC_H })
                .align_y(Alignment::Center)
                .style(move |_| container::Style {
                    background: Some(color(t.surface).into()),
                    border: Border { color: color(if on { t.ink } else { t.line }), width: if on { 2.0 } else { 1.0 }, radius: look::RADIUS_MD.into() },
                    ..Default::default()
                }),
        );
    }
    let label = |s: &'static str| text(s.to_uppercase()).size(look::LABEL).color(color(t.ink_muted)).height(16);
    // The side columns carry the panel's ground; the lock between them shows
    // the page's, whatever its height.
    let side = move |_: &iced::Theme| container::Style { background: Some(color(t.surface_2).into()), ..Default::default() };
    let src_col = container(column![label("Your sources"), sources].spacing(look::S3)).padding(look::S6).width(Length::FillPortion(1)).height(Length::Fill).style(side);

    let (serving, counts) = match &d.state.gate {
        GateState::Serving { volume, .. } => (true, volume.iter().filter(|c| c.files > 0).collect::<Vec<_>>()),
        GateState::Unreachable { .. } => (false, vec![]),
    };
    let mut win_col = column![text(format!("Sluse's count for each source, in the last {}", f.win)).size(look::SMALL).color(color(t.ink_muted))].spacing(look::S3);
    for cnt in &counts {
        let over = cnt.files >= vol.admissions;
        win_col = win_col.push(widgets::meter(
            t,
            cnt.source.as_str().to_owned(),
            if over { format!("{} of {}: past the volume alert", cnt.files, vol.admissions) } else { format!("{} of {}", cnt.files, vol.admissions) },
            cnt.files as f32 / vol.admissions.max(1) as f32,
        ));
    }
    let foot = |s: String| text(s).size(look::SMALL).color(color(t.ink_muted));
    win_col = win_col.push(foot(if serving {
        format!("{} let nothing in during the last {}.", if counts.is_empty() { "The sources" } else { "The other sources" }, f.win)
    } else {
        "Not known: these counts come from Sluse on your computer, which is not answering.".into()
    }));
    let lock = container(
        column![
            label("Sluse"),
            column![
                text("Lets in what you may open").size(look::H3).font(look::BOLD),
                text("A file from your sources comes in only when an AI agent asks Sluse for it, you may open it yourself, and it is in a folder your IT department chose. Each one is recorded.").size(look::SMALL),
            ]
            .spacing(look::S1),
            column![widgets::hrule(t), win_col].spacing(look::S3),
            foot(format!("Past {}, Sluse raises your IT department's volume alert. It is recorded in this computer's Event Log, which your IT department can read. Sluse does not stop the work.", f.limit)),
        ]
        .spacing(look::S3),
    )
    .padding(iced::Padding { top: 24.0, right: 24.0, bottom: 24.0, left: 32.0 })
    .width(LOCK_W);
    let wall = || container(Space::new()).width(3).height(Length::Fill).style(move |_| container::Style {
        background: Some(color(t.ink).into()),
        ..Default::default()
    });

    let mut box_col = column![
        label("Your box"),
        column![
            row![text(f.files.to_string()).size(40).font(look::BOLD), text(if f.files == 1 { "file let in" } else { "files let in" }).size(look::BODY)]
                .spacing(look::S2)
                .align_y(Alignment::End),
            text(if !f.from.is_empty() {
                format!("from {}", list(&f.from))
            } else if let Some(s) = d.session_start() {
                format!("Nothing yet since the box opened at {}", hhmm(s))
            } else {
                "Nothing yet in this session".into()
            })
            .size(look::SMALL)
            .color(color(t.ink_muted)),
        ],
    ]
    .spacing(look::S3);
    let fact = |glyph: &str, n: Option<usize>, words: String| {
        row![icon(glyph, look::ICON_SM, t.ink_muted)]
            .push(n.map(|n| text(n.to_string()).size(look::SMALL).font(look::BOLD)))
            .push(text(words).size(look::SMALL))
            .spacing(look::S2)
            .align_y(Alignment::Center)
    };
    if !ins.is_empty() {
        box_col = box_col.push(
            column![
                fact("eye", Some(f.read), "read: their text was shown to the agent. Sluse kept no copy of them.".into()),
                fact("download", Some(f.fetched), "fetched as copies into the box".into()),
                if f.pubs > 0 {
                    fact("artifact", Some(f.pubs), format!("{} published, in {}", if f.pubs == 1 { "file" } else { "files" }, plural(f.folders as u64, "folder") + " in Sluse Artifacts"))
                } else {
                    fact("artifact", None, "Nothing published yet".into())
                },
            ]
            .spacing(look::S2),
        );
    }
    if let Some(last) = ins.last() {
        box_col = box_col.push(
            row![
                text("Last let in:").size(look::SMALL),
                text(within(&last.path_requested).to_owned()).size(look::PATH).font(look::MONO),
                text(format!("from {}, {}.", source_of(&last.path_requested), ago(last.ts))).size(look::SMALL),
            ]
            .spacing(look::S1)
            .wrap(),
        );
    }
    if f.nothing && f.earlier > 0 {
        box_col = box_col.push(
            row![
                fact(
                    "download",
                    Some(f.earlier),
                    format!("{} from earlier sessions {} still in the box.", if f.earlier == 1 { "copy" } else { "copies" }, if f.earlier == 1 { "is" } else { "are" })
                ),
                link(t, "See them", Message::Page(Page::Copies)),
            ]
            .spacing(look::S2),
        );
    }
    let box_col = container(box_col).padding(look::S6).width(Length::FillPortion(1)).height(Length::Fill).style(side);

    let columns = row![src_col, wall(), lock, wall(), box_col].height(Length::Shrink);
    let streams = canvas_widget(Streams { active, ink: t.ink, muted: t.ink_muted, ground: t.surface }).width(Length::Fill).height(Length::Fill);
    container(stack![columns, streams])
        .width(Length::Fill)
        .clip(true)
        .style(move |_| container::Style {
            background: Some(color(t.surface).into()),
            border: Border { radius: look::RADIUS_MD.into(), ..Default::default() },
            ..Default::default()
        })
        .into()
}

/// The streams from each source to the gate, heavier where files came in,
/// and the gate itself in the lock's left wall.
struct Streams {
    active: Vec<bool>,
    ink: u32,
    muted: u32,
    ground: u32,
}

impl<M> canvas::Program<M> for Streams {
    type State = ();

    fn draw(&self, _: &(), renderer: &Renderer, _: &iced::Theme, bounds: Rectangle, _: mouse::Cursor) -> Vec<canvas::Geometry> {
        let mut frame = Frame::new(renderer, bounds.size());
        // The two side columns share what the lock and its walls leave.
        let col_w = (bounds.width - LOCK_W - 6.0) / 2.0;
        let gx = col_w + 1.5;
        let mut y = SRC_TOP;
        for &on in &self.active {
            let h = if on { SRC_ACTIVE_H } else { SRC_H };
            let (x1, y1) = (col_w - look::S6, y + h / 2.0);
            let dx = (gx - x1) / 2.0;
            let path = Path::new(|p| {
                p.move_to(Point::new(x1, y1));
                p.bezier_curve_to(Point::new(x1 + dx, y1), Point::new(gx - dx, GATE_Y), Point::new(gx - 18.0, GATE_Y));
            });
            frame.stroke(&path, Stroke::default().with_color(color(if on { self.ink } else { self.muted })).with_width(if on { 2.5 } else { 1.5 }));
            y += h + SRC_GAP;
        }
        let gate = Path::circle(Point::new(gx, GATE_Y), 18.5);
        frame.fill(&gate, color(self.ground));
        frame.stroke(&gate, Stroke::default().with_color(color(self.ink)).with_width(3.0));
        frame.draw_svg(Rectangle::new(Point::new(gx - 10.0, GATE_Y - 10.0), iced::Size::new(20.0, 20.0)), widgets::svg_of("admit", self.ink));
        vec![frame.into_geometry()]
    }
}

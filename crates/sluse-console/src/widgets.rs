// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The design kit's components (`ui/look/components.css`) the console
//! draws, as iced builders: buttons, pills, strips, cards, a copyable value,
//! details for IT, icons and the mark. Status is shape and words, never a hue
//! (Q1): there is no colour here that is not one of [`Theme`]'s.

use std::collections::HashMap;
use std::sync::LazyLock;

use iced::widget::{Space, button, column, container, row, svg, text};
use iced::{Alignment, Background, Border, Element, Length, Shadow, Vector};

use crate::look::{self, Theme, color};

/// Every icon, once, as an SVG handle (icons.js's 24px grid, 1.75 stroke,
/// round ends; tinted by [`icon`]).
static ICONS: LazyLock<HashMap<&'static str, svg::Handle>> = LazyLock::new(|| {
    crate::icons::PATHS
        .iter()
        .map(|(name, body)| {
            let doc = format!(
                r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="black" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">{}</svg>"#,
                body.replace("currentColor", "black")
            );
            (*name, svg::Handle::from_memory(doc.into_bytes()))
        })
        .collect()
});

/// The logo kit's cuts (D-061): the app icon, and the tileless mark for each
/// ground. Slice 4 moves the kit beside the shell's copy.
/// 32px and below, the kit's small cut (icons.js's `cutFor`); 36 and up, the
/// full one. The console draws it at 24 only.
static APP_ICON_SMALL: LazyLock<svg::Handle> =
    LazyLock::new(|| svg::Handle::from_memory(&include_bytes!("../../../ui/look/logo/sluse-app-icon-small.svg")[..]));
static MARK_ON_LIGHT: LazyLock<svg::Handle> =
    LazyLock::new(|| svg::Handle::from_memory(&include_bytes!("../../../ui/look/logo/sluse-mark-navy.svg")[..]));
static MARK_ON_DARK: LazyLock<svg::Handle> =
    LazyLock::new(|| svg::Handle::from_memory(&include_bytes!("../../../ui/look/logo/sluse-mark-cream.svg")[..]));

/// An icon in `ink`, `size` pixels square. An unknown name draws `unknown`,
/// as icons.js does.
pub fn icon<'a, M: 'a>(name: &str, size: f32, ink: u32) -> Element<'a, M> {
    let handle = ICONS.get(name).or_else(|| ICONS.get("unknown")).cloned().unwrap_or_else(|| svg::Handle::from_memory(&b""[..]));
    svg(handle)
        .width(size)
        .height(size)
        .style(move |_, _| svg::Style { color: Some(color(ink)) })
        .into()
}

/// An icon as a canvas draws it, tinted.
pub fn svg_of(name: &str, ink: u32) -> iced::advanced::svg::Svg {
    let handle = ICONS.get(name).or_else(|| ICONS.get("unknown")).cloned().unwrap_or_else(|| svg::Handle::from_memory(&b""[..]));
    iced::advanced::svg::Svg::new(handle).color(color(ink))
}

/// The icon a status word takes (icons.js's STATUS_ICON).
pub fn status_icon(word: &str) -> Option<&'static str> {
    crate::icons::STATUS.iter().find(|(k, _)| *k == word).and_then(|(_, v)| *v)
}

/// The horizontal lockup: the app icon and the wordmark, `tile` pixels.
pub fn lockup<'a, M: 'a>(tile: f32) -> Element<'a, M> {
    row![
        svg(APP_ICON_SMALL.clone()).width(tile).height(tile),
        text("sluse").size(tile / 1.12).font(look::BOLD),
    ]
    .spacing(tile / 3.0)
    .align_y(Alignment::Center)
    .into()
}

/// The tileless mark, in the cut for the theme's ground.
pub fn mark<'a, M: 'a>(size: f32, dark: bool) -> Element<'a, M> {
    svg(if dark { MARK_ON_DARK.clone() } else { MARK_ON_LIGHT.clone() }).width(size).height(size).into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Btn {
    /// An edge, no fill.
    Plain,
    /// Ink fill: the one action a dialog or a page leads with.
    Primary,
    /// No edge until hovered.
    Quiet,
    /// A double edge: what deletes.
    Destructive,
}

/// A button, `.btn`: 36px, or 32px when `small`.
pub fn btn<'a, M: Clone + 'a>(t: Theme, kind: Btn, small: bool, content: impl Into<Element<'a, M>>) -> button::Button<'a, M> {
    let h = if small { look::CONTROL_H_SM } else { look::CONTROL_H };
    let pad = if small { look::S3 } else { look::S4 };
    button(container(content).height(h).align_y(Alignment::Center))
        .padding([0.0, pad])
        .style(move |_, s| {
            let (hover, press) = (s == button::Status::Hovered, s == button::Status::Pressed);
            let edge = |c: u32, w: f32| Border { color: color(c), width: w, radius: look::RADIUS_MD.into() };
            match kind {
                Btn::Primary => button::Style {
                    background: Some(color(if hover || press { t.ink_hover() } else { t.ink }).into()),
                    text_color: color(t.surface),
                    border: edge(t.ink, 1.0),
                    ..Default::default()
                },
                Btn::Plain | Btn::Quiet | Btn::Destructive => button::Style {
                    background: if press {
                        Some(color(t.tint_press()).into())
                    } else if hover {
                        Some(color(t.tint_wash()).into())
                    } else {
                        None
                    },
                    text_color: color(if s == button::Status::Disabled { t.ink_muted } else { t.ink }),
                    border: match kind {
                        Btn::Quiet => Border { radius: look::RADIUS_MD.into(), ..Default::default() },
                        Btn::Destructive => edge(t.ink, 3.0),
                        _ => edge(if hover { t.ink } else { t.ink_muted }, 1.0),
                    },
                    ..Default::default()
                },
            }
        })
}

/// A button's label: an optional icon and the words, `.btn`'s small text.
pub fn label<'a, M: 'a>(t: Theme, icon_name: Option<&str>, words: impl text::IntoFragment<'a>) -> Element<'a, M> {
    let mut r = row![].spacing(look::S2).align_y(Alignment::Center);
    if let Some(i) = icon_name {
        r = r.push(icon(i, 18.0, t.ink));
    }
    r.push(text(words).size(look::SMALL)).into()
}

/// A status pill, `.pill`: its icon and the word, in capitals.
pub fn pill<'a, M: 'a>(t: Theme, status: &str, words: &str) -> Element<'a, M> {
    let mut r = row![].spacing(look::S1).align_y(Alignment::Center);
    if let Some(i) = status_icon(status) {
        r = r.push(icon(i, 16.0, t.ink));
    }
    container(r.push(text(words.to_uppercase()).size(look::LABEL)))
        .padding([2.0, look::S2])
        .height(24)
        .align_y(Alignment::Center)
        .style(move |_| container::Style {
            background: Some(color(t.surface_2).into()),
            border: Border { radius: look::RADIUS_PILL.into(), ..Default::default() },
            text_color: Some(color(t.ink)),
            ..Default::default()
        })
        .into()
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Info,
    Warning,
}

/// A strip across the page, `.banner--strip`: its title, its text, and what
/// goes under them (actions, details). A warning has an ink edge and a
/// heavier rule on its left; info, the muted rule only.
pub fn strip<'a, M: 'a>(t: Theme, kind: Kind, title: String, body: String, more: Vec<Element<'a, M>>, close: Option<Element<'a, M>>) -> Element<'a, M> {
    let mut col = column![text(title).size(look::BODY).font(look::BOLD), text(body).size(look::SMALL)].spacing(look::S1);
    for m in more {
        col = col.push(m);
    }
    let rule = if kind == Kind::Warning { t.ink } else { t.ink_muted };
    let inner = row![
        container(Space::new()).width(4).height(Length::Fill).style(move |_| container::Style {
            background: Some(color(rule).into()),
            ..Default::default()
        }),
        container(col).padding([look::S3, look::S4]).width(Length::Fill),
    ]
    .push(close.map(|c| container(c).padding(look::S2)));
    container(inner)
        .width(Length::Fill)
        .clip(true)
        .style(move |_| container::Style {
            background: Some(color(t.surface_2).into()),
            border: Border {
                color: color(if kind == Kind::Warning { t.ink } else { t.surface_2 }),
                width: 1.0,
                radius: look::RADIUS_MD.into(),
            },
            text_color: Some(color(t.ink)),
            ..Default::default()
        })
        .into()
}

/// A card, `.card`: an edge on the page's ground.
pub fn card<'a, M: 'a>(t: Theme, inner: impl Into<Element<'a, M>>) -> Element<'a, M> {
    container(inner)
        .padding(look::S4)
        .width(Length::Fill)
        .style(move |_| container::Style {
            border: Border { color: color(t.line), width: 1.0, radius: look::RADIUS_MD.into() },
            ..Default::default()
        })
        .into()
}

/// A value a person copies exactly, `.chip-mono`: an id, a path, a hash.
pub fn chip<'a, M: Clone + 'a>(t: Theme, value: &str, copied: bool, copy: M) -> Element<'a, M> {
    let copy = button(icon(if copied { "check" } else { "copy" }, 16.0, t.ink_muted))
        .padding([look::S1, look::S2])
        .on_press(copy)
        .style(move |_, s| button::Style {
            background: (s == button::Status::Hovered).then(|| Background::from(color(t.tint_press()))),
            ..Default::default()
        });
    container(row![text(value.to_owned()).size(look::PATH).font(look::MONO), copy].spacing(look::S1).align_y(Alignment::Center))
        .padding([0.0, look::S2])
        .style(move |_| container::Style {
            background: Some(color(t.surface_2).into()),
            border: Border { radius: look::RADIUS_SM.into(), ..Default::default() },
            ..Default::default()
        })
        .into()
}

/// Details for IT, `.disclosure`: closed, a "Details" line; open, the raw
/// text under "For your IT department", with Copy details. The words above
/// it are the person's; this is never the headline.
pub fn details<'a, M: Clone + 'a>(t: Theme, raw: &str, open: bool, toggle: M, copy: M) -> Element<'a, M> {
    let summary = button(
        row![icon(if open { "chevron-down" } else { "chevron-right" }, 16.0, t.ink_muted), text("Details").size(look::SMALL)]
            .spacing(look::S1)
            .align_y(Alignment::Center),
    )
    .padding(0)
    .on_press(toggle)
    .style(move |_, _| button::Style { text_color: color(t.ink), ..Default::default() });
    if !open {
        return summary.into();
    }
    let bar = row![
        text("FOR YOUR IT DEPARTMENT").size(look::LABEL).color(color(t.ink_muted)).width(Length::Fill),
        btn(t, Btn::Quiet, true, label(t, Some("copy"), "Copy details")).on_press(copy),
    ]
    .align_y(Alignment::Center);
    let body = container(column![
        container(bar).padding([look::S1, look::S3]),
        container(Space::new()).height(1).width(Length::Fill).style(move |_| container::Style {
            background: Some(color(t.line).into()),
            ..Default::default()
        }),
        container(text(raw.to_owned()).size(look::PATH).font(look::MONO)).padding(look::S3),
    ])
    .width(Length::Fill)
    .style(move |_| container::Style {
        background: Some(color(t.surface_2).into()),
        border: Border { radius: look::RADIUS_MD.into(), ..Default::default() },
        ..Default::default()
    });
    column![summary, body].spacing(look::S2).into()
}

/// A dialog, `.dialog`, over a dimmed page: its icon and title, its body, and
/// its actions on the right.
pub fn dialog<'a, M: Clone + 'a>(t: Theme, icon_name: &str, title: String, body: Element<'a, M>, actions: Vec<Element<'a, M>>) -> Element<'a, M> {
    let head = row![icon(icon_name, 28.0, t.ink), text(title).size(look::H3).font(look::BOLD)].spacing(look::S3).align_y(Alignment::Center);
    let mut acts = row![Space::new().width(Length::Fill)].spacing(look::S2);
    for a in actions {
        acts = acts.push(a);
    }
    container(column![head, body, acts].spacing(look::S6))
        .padding(look::S6)
        .max_width(640)
        .style(move |_| container::Style {
            background: Some(color(t.surface).into()),
            border: Border { color: color(t.ink_muted), width: 1.0, radius: look::RADIUS_MD.into() },
            shadow: Shadow { color: iced::Color { a: 0.3, ..iced::Color::BLACK }, offset: Vector::new(0.0, 8.0), blur_radius: 24.0 },
            text_color: Some(color(t.ink)),
            ..Default::default()
        })
        .into()
}

/// A rule between regions, `--line`.
pub fn hrule<'a, M: 'a>(t: Theme) -> Element<'a, M> {
    container(Space::new()).height(1).width(Length::Fill).style(move |_| container::Style {
        background: Some(color(t.line).into()),
        ..Default::default()
    })
    .into()
}

pub fn vrule<'a, M: 'a>(t: Theme) -> Element<'a, M> {
    container(Space::new()).width(1).height(Length::Fill).style(move |_| container::Style {
        background: Some(color(t.line).into()),
        ..Default::default()
    })
    .into()
}

/// A page's head, `.pagehead`: its title, a line under it, and its actions
/// on the right.
pub fn pagehead<'a, M: 'a>(t: Theme, title: &'a str, lede: String, actions: Vec<Element<'a, M>>) -> Element<'a, M> {
    let text_col = column![text(title).size(look::H2).font(look::BOLD), text(lede).size(look::SMALL).color(color(t.ink_muted))]
        .spacing(look::S2)
        .width(Length::Fill)
        .max_width(820);
    let mut acts = row![].spacing(look::S2);
    for a in actions {
        acts = acts.push(a);
    }
    row![container(text_col).width(Length::Fill), acts].spacing(look::S6).align_y(Alignment::End).into()
}

/// A quiet line with its icon, `.note`: info is muted; a warning has an ink
/// rule on its left.
pub fn note<'a, M: 'a>(t: Theme, kind: Kind, body: impl Into<Element<'a, M>>) -> Element<'a, M> {
    let ink = if kind == Kind::Info { t.ink_muted } else { t.ink };
    let r = row![icon(if kind == Kind::Info { "info" } else { "warning" }, 18.0, ink), body.into()].spacing(look::S2);
    if kind == Kind::Warning {
        return row![
            container(Space::new()).width(2).height(Length::Fill).style(move |_| container::Style {
                background: Some(color(t.ink).into()),
                ..Default::default()
            }),
            r
        ]
        .spacing(look::S2)
        .height(Length::Shrink)
        .into();
    }
    r.into()
}

/// What will appear here and how it gets here, `.empty`: a dashed ring with
/// the icon, a title, the text, and an action under it.
pub fn empty<'a, M: 'a>(t: Theme, icon_name: &str, title: String, lines: Vec<String>, action: Option<Element<'a, M>>) -> Element<'a, M> {
    let ring = container(icon(icon_name, 24.0, t.ink_muted)).width(48).height(48).center(48).style(move |_| container::Style {
        border: Border { color: color(t.ink_muted), width: 1.5, radius: 24.0.into() },
        ..Default::default()
    });
    let mut col = column![ring, text(title).size(look::H3).font(look::BOLD)].spacing(look::S2).max_width(640);
    for l in lines {
        col = col.push(text(l).size(look::SMALL).color(color(t.ink_muted)));
    }
    col.push(action.map(|a| container(a).padding(iced::Padding { top: 8.0, ..Default::default() }))).padding([look::S6, 0.0]).into()
}

/// A table, `.table`: its headers in small capitals over an ink-muted rule,
/// rows over `--line`. A row marked `heavy` (a refusal) carries an ink edge
/// at its start, not a colour.
pub fn table<'a, M: 'a>(t: Theme, cols: &[(&'a str, Length)], rows: Vec<(bool, Vec<Element<'a, M>>)>, dense: bool) -> Element<'a, M> {
    let pad = if dense { [look::S1, look::S2] } else { [look::S2, look::S3] };
    let head = row(cols.iter().map(|(h, w)| {
        container(text(h.to_uppercase()).size(look::LABEL).color(color(t.ink_muted))).padding(pad).width(*w).into()
    }));
    let rule = |c: u32| {
        container(Space::new()).height(1).width(Length::Fill).style(move |_| container::Style {
            background: Some(color(c).into()),
            ..Default::default()
        })
    };
    let mut col = column![head, rule(t.ink_muted)];
    for (heavy, cells) in rows {
        let cells = row(cells.into_iter().zip(cols.iter()).map(|(c, (_, w))| container(c).padding(pad).width(*w).into())).align_y(Alignment::Center);
        let edge = container(Space::new()).width(3).height(Length::Fill).style(move |_| container::Style {
            background: heavy.then(|| color(t.ink).into()),
            ..Default::default()
        });
        col = col.push(stack_row(edge.into(), cells.into())).push(rule(t.line));
    }
    col.into()
}

/// A cell row with an edge laid over its start, so the edge takes no width.
fn stack_row<'a, M: 'a>(edge: Element<'a, M>, cells: Element<'a, M>) -> Element<'a, M> {
    iced::widget::stack![cells, edge].into()
}

/// A meter, `.meter`: a label line and a track; past its limit the fill is
/// whole and the words say so (the kit's stripes are not drawn).
pub fn meter<'a, M: 'a>(t: Theme, name: String, value: String, fraction: f32) -> Element<'a, M> {
    column![
        row![text(name).size(look::PATH).font(look::MONO).width(Length::Fill), text(value).size(look::SMALL).color(color(t.ink_muted))],
        bar(t, fraction),
    ]
    .spacing(look::S1)
    .into()
}

/// A track and its fill, `fraction` of the way.
pub fn bar<'a, M: 'a>(t: Theme, fraction: f32) -> Element<'a, M> {
    let filled = (fraction.clamp(0.0, 1.0) * 1000.0).round() as u16;
    let mut r = row![].height(8);
    if filled > 0 {
        r = r.push(container(Space::new()).width(Length::FillPortion(filled)).height(8).style(move |_| container::Style {
            background: Some(color(t.ink).into()),
            border: Border { radius: look::RADIUS_PILL.into(), ..Default::default() },
            ..Default::default()
        }));
    }
    if filled < 1000 {
        r = r.push(Space::new().width(Length::FillPortion(1000 - filled)).height(8));
    }
    container(r)
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(color(t.tint_track()).into()),
            border: Border { radius: look::RADIUS_PILL.into(), ..Default::default() },
            ..Default::default()
        })
        .into()
}

/// A segmented control, `.seg`: one of `options`, each with its count.
pub fn seg<'a, M: Clone + 'a>(t: Theme, options: Vec<(String, usize, bool, M)>) -> Element<'a, M> {
    let mut r = row![];
    let n = options.len();
    for (i, (label, count, on, msg)) in options.into_iter().enumerate() {
        let b = button(
            container(
                row![text(label).size(look::SMALL).font(if on { look::BOLD } else { look::TEXT }), text(count.to_string()).size(look::LABEL).color(color(t.ink_muted))]
                    .spacing(look::S1)
                    .align_y(Alignment::Center),
            )
            .height(Length::Fill)
            .align_y(Alignment::Center),
        )
        .padding([0.0, look::S3])
        .height(look::CONTROL_H)
        .on_press(msg)
        .style(move |_, s| button::Style {
            background: if on { Some(color(t.surface_2).into()) } else { (s == button::Status::Hovered).then(|| color(t.tint_wash()).into()) },
            text_color: color(t.ink),
            ..Default::default()
        });
        r = r.push(container(b).height(look::CONTROL_H).align_y(Alignment::Center));
        if i + 1 < n {
            r = r.push(container(Space::new()).width(1).height(look::CONTROL_H).style(move |_| container::Style {
                background: Some(color(t.ink_muted).into()),
                ..Default::default()
            }));
        }
    }
    container(r)
        .padding(1)
        .clip(true)
        .style(move |_| container::Style {
            border: Border { color: color(t.ink_muted), width: 1.0, radius: look::RADIUS_MD.into() },
            ..Default::default()
        })
        .into()
}

/// "What the states mean": each status's pill and what it means.
pub fn legend<'a, M: 'a>(t: Theme, rows: &[(&str, &str, &str)]) -> Element<'a, M> {
    column(rows.iter().map(|(status, word, meaning)| {
        row![container(pill(t, status, word)).width(160), text(meaning.to_string()).size(look::SMALL).width(Length::Fill)]
            .spacing(look::S3)
            .align_y(Alignment::Center)
            .into()
    }))
    .spacing(look::S2)
    .into()
}

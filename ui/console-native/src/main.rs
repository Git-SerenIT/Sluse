// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV
//
// Spike 9 (D-079): the box's console without a web stack. One page, Work,
// modelled on ui/console's, with the top bar's Open buttons and the side
// navigation. What it proves is the drawing, not the console: software
// rendering (tiny-skia) in the box's headless sway over VNC, the fonts, the
// theme from /run/sluse/theme, sway's tab name, an app started from a button.
// It reads today's console API on loopback so it runs beside the Firefox
// console unchanged; the product would link the endpoint's library and have
// no port.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use iced::widget::{button, column, container, row, scrollable, space, text};
use iced::{Background, Border, Color, Element, Font, Length, Task, Theme, font, time, window};

const API: &str = "127.0.0.1:7582";

// The two colours and their tints, ui/console/look/tokens.css.
#[derive(Clone, Copy)]
struct Look {
    surface: Color,
    surface_2: Color,
    ink: Color,
    ink_muted: Color,
    line: Color,
}

const LIGHT: Look = Look { surface: rgb(0xf5f8fb), surface_2: rgb(0xe3e7ed), ink: rgb(0x15294a), ink_muted: rgb(0x4d5d76), line: rgb(0xbdc4cf) };
const DARK: Look = Look { surface: rgb(0x15294a), surface_2: rgb(0x273a58), ink: rgb(0xf5f8fb), ink_muted: rgb(0xb2bac6), line: rgb(0x4d5d76) };

const fn rgb(hex: u32) -> Color {
    Color::from_rgb8((hex >> 16) as u8, (hex >> 8 & 0xff) as u8, (hex & 0xff) as u8)
}

const BOLD: Font = Font { weight: font::Weight::Bold, ..Font::with_name("Liberation Sans") };
const TEXT: Font = Font::with_name("Liberation Sans");

// The apps, as the console's top bar has them (Q42), started as
// crates/sluse-endpoint/src/console/api.rs `launch` starts them.
const APPS: [(&str, &str); 6] = [
    ("Claude", "claude-desktop"),
    ("ChatGPT", "/usr/local/libexec/sluse/chatgpt"),
    ("Claude Code", "foot --app-id=sluse-claude-code /usr/local/libexec/sluse/cli claude"),
    ("Codex", "foot --app-id=sluse-codex /usr/local/libexec/sluse/cli codex"),
    ("Mistral Vibe", "foot --app-id=sluse-vibe /usr/local/libexec/sluse/cli vibe"),
    ("Terminal", "foot --app-id=sluse-terminal bash -l"),
];

const PAGES: [&str; 5] = ["Work", "Your artifacts", "Copies in the box", "Sources", "Record"];

#[derive(Default)]
struct Console {
    dark: bool,
    page: usize,
    snap: Option<Result<Snapshot, String>>,
    said: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Snapshot {
    serving: bool,
    read: usize,
    fetched: usize,
    published: usize,
    sources: Vec<String>,
}

#[derive(Debug, Clone)]
enum Message {
    Tick,
    Loaded(Result<Snapshot, String>),
    Open(usize),
    Page(usize),
    Shot(window::Screenshot),
}

fn main() -> iced::Result {
    iced::application(boot, update, view)
        .title(|_: &Console| "Sluse console (spike)".to_owned())
        .theme(|c: &Console| if c.dark { Theme::Dark } else { Theme::Light })
        .subscription(|_| time::every(Duration::from_secs(5)).map(|_| Message::Tick))
        .default_font(TEXT)
        .window(window::Settings {
            // sway names the tab by the app id (sway.conf, Q5).
            platform_specific: window::settings::PlatformSpecific { application_id: "sluse-console".into(), ..Default::default() },
            ..Default::default()
        })
        .run()
}

fn boot() -> (Console, Task<Message>) {
    (Console { dark: dark(), ..Default::default() }, load())
}

fn update(c: &mut Console, m: Message) -> Task<Message> {
    match m {
        Message::Tick => {
            c.dark = dark();
            return load();
        }
        Message::Loaded(s) => {
            c.snap = Some(s);
            // S9_SHOT=<file>: one frame as "W H\n" and raw RGBA, then exit,
            // for a desk with no screenshot tool (2026-11-02).
            if std::env::var_os("S9_SHOT").is_some() {
                eprintln!("s9: loaded {:?}", c.snap);
                let later = Task::perform(tokio::time::sleep(Duration::from_secs(1)), |_| ());
                return later.then(|_| window::latest()).and_then(window::screenshot).map(Message::Shot);
            }
        }
        Message::Shot(shot) => {
            let path = std::env::var_os("S9_SHOT").unwrap_or_default();
            let mut out = format!("{} {}\n", shot.size.width, shot.size.height).into_bytes();
            out.extend_from_slice(&shot.rgba);
            let _ = std::fs::write(path, out);
            return iced::exit();
        }
        Message::Open(i) => c.said = sway_exec(APPS[i].1).err().map(|e| format!("{} did not open: {e}", APPS[i].0)),
        Message::Page(p) => c.page = p,
    }
    Task::none()
}

/// The box takes the Sluse window's theme (Q3, Q70), as packaging/box/kiosk/theme does.
fn dark() -> bool {
    std::fs::read_to_string(std::env::var("S9_THEME").unwrap_or("/run/sluse/theme".into())).is_ok_and(|t| t.trim() == "dark")
}

fn load() -> Task<Message> {
    Task::perform(async { tokio::task::spawn_blocking(snapshot).await.map_err(|e| e.to_string())? }, Message::Loaded)
}

// ponytail: HTTP/1.0 by hand on loopback, for the spike only; the product has
// no port to call.
fn get(path: &str) -> Result<serde_json::Value, String> {
    let mut s = TcpStream::connect(API).map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(Duration::from_secs(5))).ok();
    write!(s, "GET {path} HTTP/1.0\r\nHost: localhost\r\n\r\n").map_err(|e| e.to_string())?;
    let mut buf = String::new();
    s.read_to_string(&mut buf).map_err(|e| e.to_string())?;
    let body = buf.split_once("\r\n\r\n").map(|(_, b)| b).ok_or("no body")?;
    serde_json::from_str(body).map_err(|e| e.to_string())
}

fn snapshot() -> Result<Snapshot, String> {
    let state = get("/api/state")?;
    let journal = get("/api/journal")?;
    let sources = get("/api/sources")?;
    let admitted = |op: &str| {
        journal.as_array().into_iter().flatten().filter(|r| r["op"] == op && r["outcome"] == "admitted").count()
    };
    Ok(Snapshot {
        serving: state["gate"]["status"] == "serving",
        read: admitted("read"),
        fetched: admitted("fetch") + admitted("call"),
        published: admitted("publish"),
        sources: sources["sources"].as_array().into_iter().flatten().filter_map(|s| s["name"].as_str().map(str::to_owned)).collect(),
    })
}

/// `swaymsg exec`, on this user's sway, as the endpoint's launch does.
fn sway_exec(command: &str) -> Result<(), String> {
    let out = std::process::Command::new("swaymsg").args(["exec", command]).output().map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_owned()) }
}

fn view(c: &Console) -> Element<'_, Message> {
    let k = if c.dark { DARK } else { LIGHT };
    let body = row![nav(c, k), container(scrollable(page(c, k)).width(Length::Fill)).padding(32).width(Length::Fill)];
    container(column![top(c, k), body].height(Length::Fill))
        .style(move |_| container::Style { background: Some(k.surface.into()), text_color: Some(k.ink), ..Default::default() })
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn top(c: &Console, k: Look) -> Element<'_, Message> {
    let mut open = row![text("Open").size(12).color(k.ink_muted)].spacing(8).align_y(iced::Alignment::Center);
    for (i, (name, _)) in APPS.iter().enumerate() {
        open = open.push(btn(name, k, i == APPS.len() - 1).on_press(Message::Open(i)));
    }
    let said = c.said.as_deref().map(|s| text(s).size(14).color(k.ink_muted));
    container(
        row![text("sluse").size(20).font(BOLD), space().width(24), open, space().width(Length::Fill)]
            .push(said)
            .align_y(iced::Alignment::Center)
            .spacing(8),
    )
    .padding([8, 16])
    .width(Length::Fill)
    .style(move |_| container::Style { background: Some(k.surface_2.into()), border: line(k, 0.0), ..Default::default() })
    .into()
}

fn nav(c: &Console, k: Look) -> Element<'_, Message> {
    let mut col = column![].spacing(4).padding(16).width(220);
    for (i, name) in PAGES.iter().enumerate() {
        let on = i == c.page;
        col = col.push(
            button(text(*name).size(16).font(if on { BOLD } else { TEXT }))
                .width(Length::Fill)
                .padding([8, 12])
                .on_press(Message::Page(i))
                .style(move |_, s| button::Style {
                    background: (on || s == button::Status::Hovered).then(|| Background::from(k.surface_2)),
                    text_color: k.ink,
                    border: Border { radius: 8.0.into(), ..Default::default() },
                    ..Default::default()
                }),
        );
    }
    container(col).height(Length::Fill).style(move |_| container::Style { border: line(k, 1.0), ..Default::default() }).into()
}

fn page(c: &Console, k: Look) -> Element<'_, Message> {
    let head = column![
        text(PAGES[c.page]).size(28).font(BOLD),
        text("What Sluse let into your box and what AI agents published from it, in this session.").size(16).color(k.ink_muted),
    ]
    .spacing(8);
    if c.page != 0 {
        return column![head, text("Not in the spike: Work only.").size(16).color(k.ink_muted)].spacing(24).into();
    }
    let body: Element<'_, Message> = match &c.snap {
        None => text("Reading the record").size(16).color(k.ink_muted).into(),
        Some(Err(e)) => card(k, column![text("Sluse in the box is not answering").size(20).font(BOLD), text(e.clone()).size(14).color(k.ink_muted)].spacing(8)),
        Some(Ok(s)) => {
            let n = s.read + s.fetched;
            let gate = if s.serving { "Sluse on your computer answers." } else { "Not known: Sluse on your computer is not answering." };
            let sources = if s.sources.is_empty() { "No sources".to_owned() } else { s.sources.join(", ") };
            column![
                card(k, column![
                    text("YOUR BOX").size(12).color(k.ink_muted),
                    row![text(n.to_string()).size(40).font(BOLD), text(if n == 1 { "file let in" } else { "files let in" }).size(20)].spacing(8).align_y(iced::Alignment::End),
                    text(format!("{} read: their text was shown to the agent. Sluse kept no copy of them.", s.read)).size(16),
                    text(format!("{} fetched as copies into the box", s.fetched)).size(16),
                    text(if s.published == 0 { "Nothing published yet".to_owned() } else { format!("{} published to Sluse Artifacts", s.published) }).size(16),
                ].spacing(8)),
                card(k, column![text("YOUR SOURCES").size(12).color(k.ink_muted), text(sources).size(16), text(gate).size(14).color(k.ink_muted)].spacing(8)),
                card(k, column![
                    text("How work gets in and out").size(20).font(BOLD),
                    step("Open an AI agent", "Claude, Claude Code, Codex or Mistral Vibe, with Open in the bar at the top of this page.", k),
                    step("Ask it for files", "It asks Sluse. Sluse lets in what you may open yourself, from the sources your IT department chose, and records each one.", k),
                    step("Find the results", "What the agent publishes lands in Sluse Artifacts on your computer, with the sources it declared.", k),
                ].spacing(12)),
            ]
            .spacing(24)
            .into()
        }
    };
    column![head, body].spacing(24).max_width(960).into()
}

fn step<'a>(title: &'a str, body: &'a str, k: Look) -> Element<'a, Message> {
    column![text(title).size(16).font(BOLD), text(body).size(16).color(k.ink_muted)].spacing(4).into()
}

fn card<'a>(k: Look, inner: impl Into<Element<'a, Message>>) -> Element<'a, Message> {
    container(inner).padding(16).width(Length::Fill).style(move |_| container::Style { border: line(k, 1.0), ..Default::default() }).into()
}

fn btn(label: &str, k: Look, quiet: bool) -> button::Button<'_, Message> {
    button(text(label).size(14)).padding([6, 12]).style(move |_, s| button::Style {
        background: match (quiet, s) {
            (_, button::Status::Hovered | button::Status::Pressed) => Some(k.line.into()),
            (true, _) => None,
            (false, _) => Some(k.surface.into()),
        },
        text_color: k.ink,
        border: if quiet { Border::default() } else { line(k, 1.0) },
        ..Default::default()
    })
}

fn line(k: Look, width: f32) -> Border {
    Border { color: k.line, width, radius: 8.0.into() }
}

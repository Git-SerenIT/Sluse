// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The window: iced, software rendering (tiny-skia), the box having no GPU.
//! The frame is the web console's (its main.ts, until 0.3): the top bar, the
//! strips, the side navigation and its foot, the wait over everything while
//! Sluse has not answered or every source waits for a sign-in (Q8), About
//! this box. The pages are slice 3's.
//!
//! It keeps itself current as the web console did (D-032): every few seconds
//! it reads again whatever **writes no audit record**. What does write one
//! stays a person's click.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use chrono::{DateTime, Utc};
use clap::Parser;
use iced::widget::{Space, button, center, column, container, opaque, row, scrollable, stack, text};
use iced::{Alignment, Background, Border, Element, Length, Subscription, Task, time, window};
use sluse_endpoint::console::Console as Calls;
use sluse_endpoint::console::api::{Cleared, GateState, InventoryRow, Provenance, RunState, launch_app};
use sluse_proto::audit::{AuditRecord, Op, Outcome};
use sluse_proto::{ConfigView, ListResponse, VolumeAlert};

use crate::look::{self, Theme, color};
use crate::pages::{artifacts, copies, record, sources, work};
use crate::widgets::{self, Btn, Kind, icon};
use crate::words::{hhmm, list, when};

#[derive(Debug, Parser)]
#[command(name = "sluse-console", version, about = "Sluse console: the box's first screen")]
struct Cli {
    /// The config file, the box's copy. Default: `~/Sluse/sluse.json`, where
    /// enrolment writes it.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,
}

/// Between reads while the page is open, and while it waits (the web
/// console's 10 s and 3 s).
const EVERY: Duration = Duration::from_secs(10);
const WAITING: Duration = Duration::from_secs(3);
/// After this long, the wait says what to do (Q40).
const LONG: Duration = Duration::from_secs(120);
/// An app's window takes seconds after the launch answers, so its button stays
/// busy for a while and a second click opens nothing more (L1, 2026-10-06).
const APP_SETTLES: Duration = Duration::from_secs(5);

pub fn run() -> Result<(), String> {
    let cli = Cli::parse();
    let config = match cli.config {
        Some(c) => c,
        None => PathBuf::from(std::env::var_os("HOME").ok_or("no HOME, and no --config")?).join("Sluse/sluse.json"),
    };
    iced::application(move || boot(config.clone()), update, view)
        .title(|_: &Console| "Sluse console".to_owned())
        .theme(|c: &Console| if c.dark { iced::Theme::Dark } else { iced::Theme::Light })
        .subscription(subscription)
        .default_font(look::TEXT)
        .window(window::Settings {
            // sway tiles it to the box's screen; this is the size elsewhere,
            // a maximised laptop's (the web console's style.css).
            size: iced::Size::new(1366.0, 768.0),
            // sway names the tab by the app id (sway.conf, Q5).
            platform_specific: window::settings::PlatformSpecific { application_id: "sluse-console".into(), ..Default::default() },
            ..Default::default()
        })
        .run()
        .map_err(|e| e.to_string())
}

/// The apps, as the top bar has them, the AI apps first and Terminal set
/// aside after them (Q42): its label and the name [`launch_app`] takes.
const APPS: [(&str, &str); 6] = [
    ("Claude", "claude-desktop"),
    ("ChatGPT", "chatgpt"),
    ("Claude Code", "claude-code"),
    ("Codex", "codex"),
    ("Mistral Vibe", "vibe"),
    ("Terminal", "terminal"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Work,
    Artifacts,
    Copies,
    Sources,
    Record,
}

const PAGES: [(Page, &str, &str); 5] = [
    (Page::Work, "box", "Work"),
    (Page::Artifacts, "artifact", "Your artifacts"),
    (Page::Copies, "download", "Copies in the box"),
    (Page::Sources, "source", "Sources"),
    (Page::Record, "journal", "Record"),
];

/// Everything one read sees, as the web console read it at once.
pub struct Data {
    pub state: RunState,
    pub view: ConfigView,
    /// This session's records, oldest first.
    pub journal: Vec<AuditRecord>,
    pub alerts: Vec<VolumeAlert>,
    /// Every session's publishes, newest first (Q37).
    pub provenance: Vec<Provenance>,
    /// Every session's copies.
    pub inventory: Vec<InventoryRow>,
    /// What this read saw, to tell a read that changed nothing.
    seen: String,
}

/// Sources read as the signed-in person: SharePoint, OneDrive, tool servers.
const CLOUD: [&str; 3] = ["sharepoint", "onedrive", "mcp"];

impl Data {
    pub fn cloud(&self) -> Vec<String> {
        self.view.sources.iter().filter(|s| CLOUD.contains(&s.kind.as_str())).map(|s| s.name.as_str().to_owned()).collect()
    }
    /// Sources read as the Windows account: file shares, Sluse Inputs.
    pub fn local(&self) -> Vec<String> {
        self.view.sources.iter().filter(|s| !CLOUD.contains(&s.kind.as_str())).map(|s| s.name.as_str().to_owned()).collect()
    }
    /// When this session began: its first record.
    pub fn session_start(&self) -> Option<DateTime<Utc>> {
        self.journal.first().map(|r| r.ts)
    }
    /// What was let in: read, fetched, or a tool's answer, admitted.
    pub fn let_in(&self) -> impl Iterator<Item = &AuditRecord> {
        self.journal.iter().filter(|r| matches!(r.op, Op::Read | Op::Fetch | Op::Call) && r.outcome == Outcome::Admitted)
    }
}

/// Why the wait is over the page (Q8, Q35).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gated {
    /// Sluse on the computer has not answered.
    Waiting,
    /// Every source needs the person, who has not signed in yet.
    SigningIn,
}

#[derive(Clone)]
pub struct Link {
    calls: Arc<Calls>,
    /// The config as joined: a new one is a new enrolment, so it joins again.
    config_at: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Dialog {
    About,
    /// "What the states mean", for the page it was asked on.
    States,
    /// The delete's confirm, on Copies.
    Clear,
    /// What happened when something did not, with details for IT.
    Message { title: String, lines: Vec<String>, raw: String },
}

pub struct Console {
    pub config: PathBuf,
    pub dark: bool,
    pub page: Page,
    pub link: Option<Link>,
    /// Why there is no run to read yet, while joining.
    pub unjoined: Option<String>,
    pub joining: bool,
    pub data: Option<Arc<Data>>,
    pub last_change: Option<DateTime<Utc>>,
    /// When this page stopped getting answers, and why.
    pub lost: Option<(DateTime<Utc>, String)>,
    pub refreshing: bool,
    pub page_ready: DateTime<Utc>,
    pub gated_since: Option<(Gated, Instant)>,
    /// An app that did not open, until dismissed; and one still settling.
    pub launch_failed: Option<(usize, String)>,
    pub launching: Option<usize>,
    pub dialog: Option<Dialog>,
    /// The details blocks a person opened, by their text.
    pub open_details: HashSet<String>,
    /// The value last copied, shown as copied until the next read.
    pub copied: Option<String>,
    pub sources: sources::Sources,
    pub copies: copies::Copies,
    pub record: record::Record,
    /// The serial line the host waits for (Q9) has been said.
    pub announced: bool,
}

#[derive(Clone)]
pub enum Message {
    Tick,
    Second,
    Joined(Result<Link, String>),
    Loaded(Result<Arc<Data>, String>),
    Refresh,
    Open(usize),
    Launched(usize, Result<(), String>),
    Settled(usize),
    DismissLaunch,
    Page(Page),
    Show(Dialog),
    Close,
    Details(String),
    Copy(String),
    Shot(window::Screenshot),
    /// Sources: open a folder, and its listing.
    List(String),
    Listed(String, Result<Arc<ListResponse>, (String, String)>),
    /// Copies: check against the sources, each answer; delete, its answer.
    Check,
    Answer(Result<Arc<InventoryRow>, String>),
    Clear,
    Cleared(Result<Arc<Cleared>, String>),
    /// Record: what it shows, fifty more, the computer's record.
    Filter(record::Shown),
    More,
    Host(Result<Arc<Vec<AuditRecord>>, String>),
}

fn boot(config: PathBuf) -> (Console, Task<Message>) {
    let c = Console {
        dark: dark(),
        page: Page::Work,
        link: None,
        unjoined: None,
        joining: true,
        data: None,
        last_change: None,
        lost: None,
        refreshing: false,
        page_ready: Utc::now(),
        gated_since: None,
        launch_failed: None,
        launching: None,
        dialog: None,
        open_details: HashSet::new(),
        copied: None,
        sources: Default::default(),
        copies: Default::default(),
        record: Default::default(),
        announced: false,
        config,
    };
    let join = join(&c.config);
    (c, join)
}

fn subscription(c: &Console) -> Subscription<Message> {
    let every = if c.link.is_some() && gated(c).is_none() { EVERY } else { WAITING };
    let mut subs = vec![time::every(every).map(|_| Message::Tick)];
    // The wait's clock, by the second.
    if gated(c).is_some() {
        subs.push(time::every(Duration::from_secs(1)).map(|_| Message::Second));
    }
    Subscription::batch(subs)
}

fn update(c: &mut Console, m: Message) -> Task<Message> {
    match m {
        Message::Tick => {
            c.dark = dark();
            c.copied = None;
            match &c.link {
                Some(l) if l.config_at == modified(&c.config) => return load(l.calls.clone()),
                _ if c.joining => {}
                _ => {
                    c.joining = true;
                    return join(&c.config);
                }
            }
        }
        Message::Second => {}
        Message::Joined(r) => {
            c.joining = false;
            match r {
                Ok(l) => {
                    let calls = l.calls.clone();
                    c.link = Some(l);
                    c.unjoined = None;
                    return load(calls);
                }
                Err(e) => {
                    tracing::info!("not joined yet: {e}");
                    c.link = None;
                    c.unjoined = Some(e);
                    note_gate(c);
                    return shot();
                }
            }
        }
        Message::Loaded(r) => {
            c.refreshing = false;
            match r {
                Ok(d) => {
                    sign_in_window(&d);
                    if !c.announced {
                        c.announced = true;
                        announce();
                    }
                    if c.data.as_ref().is_none_or(|old| old.seen != d.seen) || c.lost.is_some() {
                        c.last_change = Some(Utc::now());
                    }
                    c.lost = None;
                    c.data = Some(d);
                }
                Err(e) => {
                    c.lost.get_or_insert((Utc::now(), e));
                }
            }
            note_gate(c);
            return shot();
        }
        Message::Refresh => {
            if let Some(l) = &c.link {
                c.refreshing = true;
                let host = if c.page == Page::Record && c.data.as_ref().is_some_and(|d| d.state.local) { record::Record::load_host(&l.calls) } else { Task::none() };
                return Task::batch([load(l.calls.clone()), host]);
            }
        }
        Message::Open(i) => {
            if c.launching == Some(i) {
                return Task::none();
            }
            c.launching = Some(i);
            let app = APPS[i].1;
            return Task::perform(async move { launch_app(app).map_err(|e| format!("{e:?}")) }, move |r| Message::Launched(i, r));
        }
        Message::Launched(i, Ok(())) => {
            if c.launch_failed.as_ref().is_some_and(|(f, _)| *f == i) {
                c.launch_failed = None;
            }
            return Task::perform(tokio::time::sleep(APP_SETTLES), move |_| Message::Settled(i));
        }
        Message::Launched(i, Err(e)) => {
            c.launching = None;
            c.launch_failed = Some((i, e));
        }
        Message::Settled(i) => {
            if c.launching == Some(i) {
                c.launching = None;
            }
        }
        Message::DismissLaunch => c.launch_failed = None,
        Message::Page(p) => {
            c.page = p;
            if let (Page::Record, Some(l), Some(d)) = (p, &c.link, &c.data) {
                if d.state.local {
                    return record::Record::load_host(&l.calls);
                }
            }
        }
        Message::List(path) => {
            if let Some(l) = &c.link {
                return c.sources.open(&l.calls, path);
            }
        }
        Message::Listed(path, r) => c.sources.listed(path, r),
        Message::Check => {
            if let (Some(l), Some(d)) = (&c.link, &c.data) {
                return c.copies.start(&l.calls, d);
            }
        }
        Message::Answer(r) => {
            if let Some(l) = &c.link {
                return c.copies.answer(&l.calls, r);
            }
        }
        Message::Clear => {
            c.dialog = None;
            if let Some(l) = &c.link {
                return copies::Copies::clear(&l.calls);
            }
        }
        Message::Cleared(r) => {
            c.dialog = c.copies.cleared(r);
            if let Some(l) = &c.link {
                return load(l.calls.clone());
            }
        }
        Message::Filter(k) => {
            c.record.shown = k;
            c.record.pages = 1;
        }
        Message::More => c.record.pages = c.record.pages.max(1) + 1,
        Message::Host(r) => c.record.host = Some(r),
        Message::Show(d) => c.dialog = Some(d),
        Message::Close => c.dialog = None,
        Message::Details(k) => {
            if !c.open_details.remove(&k) {
                c.open_details.insert(k);
            }
        }
        Message::Copy(v) => {
            c.copied = Some(v.clone());
            return iced::clipboard::write(v);
        }
        Message::Shot(shot) => {
            let mut out = format!("{} {}\n", shot.size.width, shot.size.height).into_bytes();
            out.extend_from_slice(&shot.rgba);
            let _ = std::fs::write(std::env::var_os("SLUSE_CONSOLE_SHOT").unwrap_or_default(), out);
            return iced::exit();
        }
    }
    note_gate(c);
    Task::none()
}

/// Said on the box's serial console, where the host's service hears it: the
/// Sluse window keeps its wait over the box until then (Q9). Once, when the
/// console has joined the run and read it, as the web console's port first
/// answered then.
fn announce() {
    if let Err(e) = std::process::Command::new("logger").args(["-t", "sluse-console-up", "the console answers"]).spawn() {
        tracing::warn!("logger: {e}; the host waits for the console's line until its limit");
    }
}

/// The Gate holds a sign-in window open (D-075): a flag the box's sign-in
/// browser reads (`signin-browser`), there while the window is, gone when it
/// closes. It read the console's port for this until 0.3.
fn sign_in_window(d: &Data) {
    let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").map(|d| PathBuf::from(d).join("sluse")) else { return };
    let flag = dir.join("sign-in-window");
    let open = matches!(d.state.gate, GateState::Serving { sign_in_window: true, .. });
    let _ = if open { std::fs::create_dir_all(&dir).and_then(|()| std::fs::write(&flag, b"")) } else { std::fs::remove_file(&flag).or(Ok(())) };
}

/// SLUSE_CONSOLE_SHOT=<file>: one frame as "W H\n" and raw RGBA a second after
/// the first answer or the first failed join, then exit. For a development
/// machine with no screenshot tool; nothing in the box sets it.
fn shot() -> Task<Message> {
    if std::env::var_os("SLUSE_CONSOLE_SHOT").is_none() {
        return Task::none();
    }
    let later = Task::perform(tokio::time::sleep(Duration::from_secs(1)), |_| ());
    later.then(|_| window::latest()).and_then(window::screenshot).map(Message::Shot)
}

/// The box takes the Sluse window's theme (Q3, Q70), as packaging/box/kiosk/theme does.
fn dark() -> bool {
    std::fs::read_to_string(std::env::var_os("SLUSE_CONSOLE_THEME").map(PathBuf::from).unwrap_or("/run/sluse/theme".into()))
        .is_ok_and(|t| t.trim() == "dark")
}

fn modified(config: &std::path::Path) -> Option<SystemTime> {
    std::fs::metadata(config).and_then(|m| m.modified()).ok()
}

fn join(config: &std::path::Path) -> Task<Message> {
    let config = config.to_owned();
    Task::perform(
        async move {
            let config_at = modified(&config);
            let loaded = sluse_proto::config::load(&config).map_err(|e| format!("config: {e}"))?;
            let calls = Calls::join(&loaded).await?;
            Ok(Link { calls: Arc::new(calls), config_at })
        },
        Message::Joined,
    )
}

/// Read everything, as the web console's `refreshAll` did; the alerts alone
/// may fail without the read failing.
fn load(calls: Arc<Calls>) -> Task<Message> {
    Task::perform(
        async move {
            let state = calls.state().await;
            let journal = calls.journal().map_err(|e| e.to_string())?;
            let alerts = calls.alerts(None).await.unwrap_or_default();
            let provenance = calls.provenance().map_err(|e| e.to_string())?;
            let inventory = calls.inventory().map_err(|e| e.to_string())?;
            let seen = serde_json::to_string(&(&state, &journal, &alerts, &provenance, &inventory)).unwrap_or_default();
            Ok(Arc::new(Data { state, view: calls.view.clone(), journal, alerts, provenance, inventory, seen }))
        },
        Message::Loaded,
    )
}

/// The person must sign in first, or Sluse has never answered (Q8, Q35).
fn gated(c: &Console) -> Option<Gated> {
    let Some(d) = &c.data else { return Some(Gated::Waiting) };
    match &d.state.gate {
        GateState::Unreachable { .. } => d.journal.is_empty().then_some(Gated::Waiting),
        GateState::Serving { signed_in, signed_out, .. } => {
            let only_cloud = !d.cloud().is_empty() && d.local().is_empty();
            (only_cloud && signed_in.is_none() && !signed_out).then_some(Gated::SigningIn)
        }
    }
}

/// When the wait's current state began, for its clock and its 2 minutes.
fn note_gate(c: &mut Console) {
    let now = gated(c);
    if c.gated_since.map(|(g, _)| g) != now {
        c.gated_since = now.map(|g| (g, Instant::now()));
    }
}

// ---- The view --------------------------------------------------------------

fn view(c: &Console) -> Element<'_, Message> {
    let t = Theme::of(c.dark);
    let ground = move |_: &iced::Theme| container::Style {
        background: Some(color(t.surface).into()),
        text_color: Some(color(t.ink)),
        ..Default::default()
    };
    if let Some(g) = gated(c) {
        return container(wait(c, t, g)).style(ground).width(Length::Fill).height(Length::Fill).into();
    }
    let Some(d) = &c.data else { unreachable!("gated without data") };
    let main = container(
        scrollable(container(page(c, t, d)).padding(iced::Padding { top: 32.0, right: 48.0, bottom: 48.0, left: 48.0 }).max_width(1240))
            .width(Length::Fill)
            .height(Length::Fill)
            .style(move |_, s| scroll_style(t, s)),
    )
    .width(Length::Fill);
    let mut frame = column![top(c, t), widgets::hrule(t)];
    let strips = strips(c, t, d);
    if !strips.is_empty() {
        frame = frame.push(container(column(strips).spacing(look::S2)).padding([look::S2, look::S4]));
    }
    let frame = frame.push(row![nav(c, t, d), widgets::vrule(t), main].height(Length::Fill));
    let base = container(frame).style(ground).width(Length::Fill).height(Length::Fill);
    let dialog = match &c.dialog {
        None => return base.into(),
        Some(Dialog::About) => about(c, t, d),
        Some(Dialog::States) => states(t, c.page),
        Some(Dialog::Clear) => copies::confirm(t, d),
        Some(Dialog::Message { title, lines, raw }) => {
            let mut body = column![].spacing(look::S3);
            for l in lines {
                body = body.push(text(l.clone()).size(look::BODY));
            }
            widgets::dialog(
                t,
                "problem",
                title.clone(),
                body.push(details(c, t, raw.clone())).into(),
                vec![widgets::btn(t, Btn::Primary, false, text("Close").size(look::SMALL)).on_press(Message::Close).into()],
            )
        }
    };
    stack![base, scrim(t, dialog)].into()
}

/// The page behind a dialog, dimmed and inert.
fn scrim<'a>(t: Theme, dialog: Element<'a, Message>) -> Element<'a, Message> {
    let _ = t;
    opaque(
        center(dialog)
            .style(|_| container::Style { background: Some(iced::Color { a: 0.45, ..iced::Color::BLACK }.into()), ..Default::default() })
            .width(Length::Fill)
            .height(Length::Fill),
    )
}

fn scroll_style(t: Theme, s: scrollable::Status) -> scrollable::Style {
    let mut style = scrollable::default(&iced::Theme::Light, s);
    let rail = scrollable::Rail {
        background: None,
        border: Border::default(),
        scroller: scrollable::Scroller {
            background: Background::from(color(t.line)),
            border: Border { radius: look::RADIUS_PILL.into(), ..Default::default() },
        },
    };
    style.vertical_rail = rail;
    style.horizontal_rail = rail;
    style
}

fn top<'a>(c: &'a Console, t: Theme) -> Element<'a, Message> {
    let mut open = row![text("Open").size(look::SMALL).color(color(t.ink_muted))].spacing(look::S2).align_y(Alignment::Center);
    for (i, (name, _)) in APPS.iter().enumerate() {
        let terminal = i == APPS.len() - 1;
        let busy = c.launching == Some(i);
        let label = if terminal { widgets::label(t, Some("terminal"), *name) } else { text(*name).size(look::SMALL).into() };
        let b = widgets::btn(t, if terminal { Btn::Quiet } else { Btn::Plain }, false, label).on_press_maybe((!busy).then_some(Message::Open(i)));
        if terminal {
            open = open.push(container(widgets::vrule(t)).height(20).padding([0.0, look::S1]));
        }
        open = open.push(b);
    }
    let live: Element<'_, Message> = if c.lost.is_some() {
        widgets::pill(t, "problem", "Not answering")
    } else if c.refreshing {
        text("Refreshing").size(look::SMALL).color(color(t.ink_muted)).into()
    } else if let Some(at) = c.last_change {
        row![text("Last change").size(look::SMALL).color(color(t.ink_muted)), text(when(at)).size(look::SMALL)].spacing(look::S2).into()
    } else {
        text("Reading the record").size(look::SMALL).color(color(t.ink_muted)).into()
    };
    let refresh = widgets::btn(t, Btn::Quiet, false, icon("refresh", look::ICON, t.ink)).padding([0.0, look::S2]).on_press(Message::Refresh);
    container(
        row![widgets::lockup(24.0), container(widgets::vrule(t)).height(24), open, Space::new().width(Length::Fill), live, refresh]
            .spacing(look::S4)
            .align_y(Alignment::Center),
    )
    .padding(iced::Padding { top: 0.0, right: 16.0, bottom: 0.0, left: 24.0 })
    .height(56)
    .align_y(Alignment::Center)
    .width(Length::Fill)
    .into()
}

fn nav<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    let count = |p: Page| match p {
        Page::Work => 0,
        Page::Artifacts => d.provenance.iter().filter(|x| x.outcome == Outcome::Admitted).count(),
        Page::Copies => d.inventory.len(),
        Page::Sources => d.view.sources.len(),
        Page::Record => d.journal.len(),
    };
    let mut items = column![].spacing(2);
    for (p, icon_name, name) in PAGES {
        let on = c.page == p;
        let n = count(p);
        let inner = row![
            icon(icon_name, 18.0, if on { t.ink } else { t.ink_muted }),
            text(name).size(look::SMALL).font(if on { look::BOLD } else { look::TEXT }).width(Length::Fill),
        ]
        .push((n > 0).then(|| text(n.to_string()).size(look::LABEL).color(color(t.ink_muted))))
        .spacing(look::S2)
        .align_y(Alignment::Center);
        let bar = container(Space::new()).width(3).height(40).style(move |_| container::Style {
            background: on.then(|| color(t.ink).into()),
            ..Default::default()
        });
        items = items.push(
            button(row![bar, container(inner).padding([0.0, look::S3]).height(40).align_y(Alignment::Center)])
                .padding(0)
                .width(Length::Fill)
                .on_press(Message::Page(p))
                .style(move |_, s| button::Style {
                    background: if on {
                        Some(color(t.surface_2).into())
                    } else {
                        (s == button::Status::Hovered).then(|| color(t.tint_wash()).into())
                    },
                    text_color: color(t.ink),
                    border: Border { radius: look::RADIUS_SM.into(), ..Default::default() },
                    ..Default::default()
                }),
        );
    }
    let since = d.session_start().map(|s| {
        let today = crate::words::today(s);
        format!("This session: since the box opened at {}{}", hhmm(s), if today { " today" } else { "" })
    });
    let deployment = d.state.deployment.as_ref().map(|dep| format!("{}, revision {}", if dep.name.is_empty() { &dep.id } else { &dep.name }, dep.revision));
    let about = button(row![icon("info", 18.0, t.ink_muted), text("About this box").size(look::SMALL)].spacing(look::S2).align_y(Alignment::Center))
        .padding([look::S2, look::S3])
        .width(Length::Fill)
        .on_press(Message::Show(Dialog::About))
        .style(move |_, s| button::Style {
            background: (s == button::Status::Hovered).then(|| color(t.tint_wash()).into()),
            text_color: color(t.ink),
            border: Border { radius: look::RADIUS_SM.into(), ..Default::default() },
            ..Default::default()
        });
    let muted = |s: String| text(s).size(look::SMALL).color(color(t.ink_muted));
    let foot = column![widgets::hrule(t)]
        .push(since.map(muted))
        .push(about)
        .push(deployment.map(muted))
        .spacing(look::S2);
    container(column![items, Space::new().height(Length::Fill), foot])
        .padding([look::S4, look::S3])
        .width(240)
        .height(Length::Fill)
        .into()
}

pub fn details<'a>(c: &Console, t: Theme, raw: String) -> Element<'a, Message> {
    let open = c.open_details.contains(&raw);
    widgets::details(t, &raw, open, Message::Details(raw.clone()), Message::Copy(raw.clone()))
}

/// What holds on every page (the web console's `drawStrips`).
fn strips<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Vec<Element<'a, Message>> {
    let mut out = Vec::new();
    let (cl, lo) = (d.cloud(), d.local());
    let are = |xs: &[String]| if xs.len() > 1 { "are" } else { "is" };
    if let Some((at, why)) = &c.lost {
        out.push(widgets::strip(
            t,
            Kind::Warning,
            format!("This page stopped getting answers at {}.", when(*at)),
            "What you see is from then. It asks again every 10 seconds. If this stays, close the box from the bar above and open it again.".into(),
            vec![details(c, t, why.clone())],
            None,
        ));
    }
    match &d.state.gate {
        GateState::Unreachable { detail } => out.push(widgets::strip(
            t,
            Kind::Warning,
            "Sluse on your computer is not answering.".into(),
            "Nothing new can be let into the box until it answers. What is already here stays. This page asks again by itself.".into(),
            vec![details(c, t, format!("gate unreachable: {detail}"))],
            None,
        )),
        GateState::Serving { signed_out: true, .. } if !cl.is_empty() => out.push(widgets::strip(
            t,
            Kind::Info,
            "You signed out.".into(),
            format!(
                "{} {} not read until you sign in again{}. To sign in again, close the box from the bar above and open Sluse again.",
                list(&cl),
                are(&cl),
                if lo.is_empty() { String::new() } else { format!("; {} {} still read as your Windows account", list(&lo), are(&lo)) }
            ),
            vec![],
            None,
        )),
        GateState::Serving { signed_in: None, .. } if !cl.is_empty() => out.push(widgets::strip(
            t,
            Kind::Info,
            format!("{} {} for you to sign in.", list(&cl), if cl.len() > 1 { "wait" } else { "waits" }),
            format!("{} {} read now, so you can open an AI agent. If a Microsoft sign-in window has opened on your computer, finish it there.", list(&lo), are(&lo)),
            vec![],
            None,
        )),
        _ => {}
    }
    if let Some((i, why)) = &c.launch_failed {
        let name = APPS[*i].0;
        let retry = widgets::btn(t, Btn::Plain, true, text(format!("Open {name} again")).size(look::SMALL)).on_press(Message::Open(*i));
        let close = widgets::btn(t, Btn::Quiet, true, icon("close", look::ICON_SM, t.ink)).padding([0.0, look::S2]).on_press(Message::DismissLaunch);
        out.push(widgets::strip(
            t,
            Kind::Warning,
            format!("{name} did not open."),
            "Try again. If it still does not open, send the details to your IT department.".into(),
            vec![retry.into(), details(c, t, format!("launch {}: {why}", APPS[*i].1))],
            Some(close.into()),
        ));
    }
    if let GateState::Serving { config_version, .. } = &d.state.gate {
        if *config_version != d.state.config_version {
            out.push(widgets::strip(
                t,
                Kind::Warning,
                "Your IT department changed Sluse's settings on your computer, and this box still has the old ones.".into(),
                "What is let in follows the new settings. If this stays, send the details to your IT department.".into(),
                vec![details(c, t, format!("settings mismatch: computer {config_version}, box {}", d.state.config_version))],
                None,
            ));
        }
    }
    out
}

/// The wait over the whole console (the web console's `renderGate`). Nothing to
/// press: the Sluse window signs in (D-036). After 2 minutes it says what to
/// do (Q40), without claiming to know why.
fn wait<'a>(c: &'a Console, t: Theme, g: Gated) -> Element<'a, Message> {
    let elapsed = c.gated_since.map(|(_, at)| at.elapsed()).unwrap_or_default();
    let long = elapsed >= LONG;
    let waiting = g == Gated::Waiting;
    let muted = |s: String| text(s).size(look::BODY).color(color(t.ink_muted));
    let mut lead = column![
        container(widgets::mark(64.0, c.dark)).padding(iced::Padding { bottom: 16.0, ..Default::default() }),
        text(if waiting { "Waiting for Sluse" } else { "Signing you in" }).size(40).font(look::BOLD),
        text(if waiting {
            "Your box is up. Sluse on your computer has not answered yet. This page asks again every few seconds and goes on by itself."
        } else {
            "The Sluse window on your computer signs you in with your Microsoft account, so Sluse can read files as you and never more than you can open yourself."
        })
        .size(look::BODY),
    ]
    .spacing(look::S4)
    .max_width(576);
    if let (false, Some(d)) = (waiting, &c.data) {
        let cl = d.cloud();
        lead = lead.push(muted(if d.view.sources.iter().all(|s| s.kind == "onedrive") {
            "This box's only source is your Sluse folder in OneDrive, which needs your Microsoft account.".into()
        } else {
            format!("This box's sources are {}, and they need your Microsoft account.", cl.join(" and "))
        }));
    }
    let secs = elapsed.as_secs();
    lead = lead.push(
        row![text("Elapsed").size(look::SMALL).color(color(t.ink_muted)), text(format!("{}:{:02}", secs / 60, secs % 60)).size(look::H2).font(look::BOLD)]
            .spacing(look::S3)
            .align_y(Alignment::End),
    );
    if long {
        let (title, body) = if waiting {
            ("Sluse has not answered for 2 minutes.", "If it stays like this, close the box with Close the box in the bar above and open it again. If that does not help, send the details to your IT department.")
        } else {
            ("You are not signed in after 2 minutes.", "Look for a Microsoft sign-in window on your computer; it can open behind this one. If there is none, the bar above the box says what happened.")
        };
        lead = lead.push(widgets::strip(t, Kind::Warning, title.into(), body.into(), vec![], None));
        let raw = match (&c.data, &c.unjoined) {
            (_, Some(why)) => format!("not joined: {why}"),
            (Some(d), None) => format!(
                "box {}, session {}\ngate: {}",
                d.state.box_id,
                d.state.session,
                match &d.state.gate {
                    GateState::Serving { .. } => "serving, signedIn: none".to_owned(),
                    GateState::Unreachable { detail } => format!("unreachable ({detail})"),
                }
            ),
            (None, None) => "no answer yet".into(),
        };
        lead = lead.push(details(c, t, raw));
    }
    lead = lead.push(column![widgets::hrule(t), text("Nothing to press here. This page goes on by itself.").size(look::SMALL).color(color(t.ink_muted))].spacing(look::S4));

    let step = |status: &'static str, words: &'static str, time: String, sub: Option<&'static str>| {
        let current = status == "current";
        let ink = if current { t.ink } else { t.ink_muted };
        let icon_name = match status {
            "done" => "admitted",
            "current" => "spinner",
            _ => "not-checked",
        };
        let mut col = column![
            row![
                icon(icon_name, look::ICON, ink),
                text(words).size(look::SMALL).font(if current { look::BOLD } else { look::TEXT }).color(color(ink)).width(Length::Fill),
                text(time).size(look::PATH).font(look::MONO).color(color(ink)),
            ]
            .spacing(look::S3)
            .align_y(Alignment::Center)
            .height(32)
        ];
        if let Some(s) = sub {
            col = col.push(container(text(s).size(look::SMALL).color(color(t.ink_muted))).padding(iced::Padding { left: 32.0, ..Default::default() }));
        }
        Element::from(col)
    };
    let ledger = column![
        step("done", "This page is ready", when(c.page_ready), None),
        if waiting { step("current", "Sluse on your computer answers", "asking every 3 s".into(), None) } else { step("done", "Sluse on your computer answers", String::new(), None) },
        if waiting {
            step("next", "You are signed in", String::new(), None)
        } else {
            step("current", "You are signed in", "asking every 3 s".into(), Some("If a Microsoft sign-in window has opened on your computer, finish it there."))
        },
    ]
    .spacing(2)
    .max_width(448);
    let ledger = container(ledger).padding(iced::Padding { top: 96.0, ..Default::default() });
    center(scrollable(row![lead, ledger].spacing(112).padding([look::S12, 64.0]))).into()
}

fn page<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    match c.page {
        Page::Work => work::view(c, t, d),
        Page::Artifacts => artifacts::view(c, t, d),
        Page::Copies => copies::view(c, t, d),
        Page::Sources => sources::view(c, t, d),
        Page::Record => record::view(c, t, d),
    }
}

/// "What the states mean", for the page it was asked on.
fn states<'a>(t: Theme, page: Page) -> Element<'a, Message> {
    let (lede, rows): (&str, &[(&str, &str, &str)]) = match page {
        Page::Copies => (
            "Each copy is compared with its source when you use Check against the sources. Each question is recorded on your computer.",
            &copies::STATES,
        ),
        _ => ("Each source the agent declared is shown with what became of it in the box.", &artifacts::STATES),
    };
    widgets::dialog(
        t,
        "info",
        "What the states mean".into(),
        column![text(lede).size(look::BODY), widgets::legend(t, rows)].spacing(look::S3).into(),
        vec![widgets::btn(t, Btn::Primary, false, text("Close").size(look::SMALL)).on_press(Message::Close).into()],
    )
}

/// About this box (the web console's `about`).
fn about<'a>(c: &'a Console, t: Theme, d: &'a Data) -> Element<'a, Message> {
    let fact = |label: &'static str, value: Element<'a, Message>| {
        column![text(label.to_uppercase()).size(look::LABEL).color(color(t.ink_muted)), value].spacing(2)
    };
    let box_id = d.state.box_id.to_string();
    let session = d.state.session.to_string();
    let since = d.session_start();
    let dep = d.state.deployment.as_ref();
    let settings = match dep {
        Some(dep) => format!("{}, revision {}", if dep.name.is_empty() { &dep.id } else { &dep.name }, dep.revision),
        None => d.state.config_version.to_string().chars().take(12).collect(),
    };
    let mut facts = column![
        fact("Box", widgets::chip(t, &box_id, c.copied.as_deref() == Some(box_id.as_str()), Message::Copy(box_id.clone()))),
        fact("Session", widgets::chip(t, &session, c.copied.as_deref() == Some(session.as_str()), Message::Copy(session.clone()))),
    ]
    .spacing(look::S3);
    if let Some(s) = since {
        facts = facts.push(fact("Opened", text(when(s)).size(look::SMALL).into()));
    }
    facts = facts.push(fact("Settings version", text(settings).size(look::SMALL).into()));
    let raw = format!(
        "box {box_id}\nsession {session}{}\nconfig {}{}",
        since.map(|s| format!(", opened {}", s.to_rfc3339())).unwrap_or_default(),
        dep.map(|dep| format!("{} revision {}, ", if dep.name.is_empty() { &dep.id } else { &dep.name }, dep.revision)).unwrap_or_default(),
        d.state.config_version
    );
    let body = column![
        text("This page shows what Sluse let into this box, what AI agents published from it, and what was recorded. It lets nothing in and refuses nothing: every decision shown here was made by Sluse on your computer.").size(look::BODY),
        facts,
        details(c, t, raw),
        text("This page has no sign-in of its own. Anything running in this box can see it, as anything in the box can use the Sluse tools the AI agents use.").size(look::SMALL).color(color(t.ink_muted)),
    ]
    .spacing(look::S3);
    widgets::dialog(
        t,
        "box",
        "About this box".into(),
        body.into(),
        vec![widgets::btn(t, Btn::Primary, false, text("Close").size(look::SMALL)).on_press(Message::Close).into()],
    )
}

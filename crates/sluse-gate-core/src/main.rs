// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Gate Core (D-071).
//!
//! Runs on the host — as the signed-in user in LOCAL, as SYSTEM impersonating
//! them in the product — and is the only thing that decides whether a file may
//! cross into the guest. It does not face the box: its Gate Front does, which
//! it starts and serves over a pipe (`sluse_gate_core::front`).
//!
//! Three modes. `--check` compiles a config, runs the preflight and prints what
//! would be served, touching no socket; `sluse check` calls it. `--serve` does
//! all of that, refuses to continue if a **required** check failed (invariant
//! 6, and there is no override), and then starts Front and serves it.
//! `--proxy` starts a Front that is only the egress proxy, for a base build,
//! and keeps what it claims.
//!
//! The order in `--serve` is deliberate and is the one thing to keep if this is
//! ever rewritten: load the config, compile scope against the real filesystem,
//! check the certificate, run the preflight *with what that check found*, write
//! the posture snapshot, start Front, which binds before it serves, and only
//! then say it is up. Each step's failure is reportable while it can still be
//! explained.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use sluse_gate_core::app::Core;
use sluse_gate_core::audit::{AuditSink, JsonlSink};
use sluse_gate_core::front::{self, Claims, Refusals, RollingLog};
use sluse_gate_core::{http, identity, preflight, scope, sources, tls};
use sluse_proto::gate::FrontStart;
use sluse_proto::AuditSinkKind;

/// `EX_CONFIG`. Anything that means "this box will not run on this config".
const EX_CONFIG: u8 = 78;

#[derive(Debug, Parser)]
#[command(
    name = "sluse-gate-core",
    version,
    about = "Sluse token core — path validation, capability issue, audit, volume"
)]
struct Cli {
    /// The config file. Everything relative in it resolves against its own
    /// directory, so a config is moved as a unit with the tree it describes.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// Compile the config, run the preflight, print what would be served.
    /// Touches no socket.
    #[arg(long, conflicts_with = "serve")]
    check: bool,

    /// Serve.
    #[arg(long)]
    serve: bool,

    /// Start a Front that is only the box's egress proxy (M9, D-035): the
    /// config's `egress.allow`, on the Gate's host at the proxy port. For a
    /// base build, which has no box to serve. Stops when stdin closes.
    #[arg(long, conflicts_with_all = ["check", "serve"])]
    proxy: bool,

    /// Have Front bind this address instead of the config's `gate.listen`.
    ///
    /// For a test that wants an ephemeral port. `gate.url` still names the
    /// configured one, so a run started this way is not one an endpoint can dial
    /// from an unmodified config.
    #[arg(long, value_name = "ADDR", requires = "serve")]
    listen: Option<String>,
}

fn main() -> ExitCode {
    // First statement of the process. axum-server brings `aws-lc-rs` and a
    // client could bring `ring`; with two providers linked, rustls refuses to
    // guess which is the default and panics on the first handshake.
    tls::install_provider();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sluse_gate_core=info".into()),
        )
        // stderr, always: stdout belongs to whatever is reading this process.
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Invariant 6, and it is the first thing that happens after the provider:
    // config absent, invalid or of an unknown schema version means nothing runs.
    let mut loaded = match sluse_proto::config::load(&cli.config) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("config: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    if cli.proxy {
        return proxy(&loaded);
    }

    // On a device, Sluse Artifacts is the user's own folder, written as them
    // (D-031), and replaces the config's `artifacts` before anything checks
    // it: the scope compile below still refuses it inside a source root, and
    // the preflight probes it as the user.
    match sluse_gate_core::as_user::adopt() {
        Ok(Some(dir)) => loaded.config.artifacts = dir.display().to_string(),
        Ok(None) => {}
        Err(e) => {
            eprintln!("artifacts: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    }

    // Every path in the file, resolved once. A root or scope that cannot be
    // reached is not a failure here: its source starts unavailable, recorded
    // as 1303, and the others serve (review R-22). What fails is a config that
    // means something other than it says.
    // As the user on a device: an SMB root canonicalised as SYSTEM is the
    // computer account asking (D-054).
    let compiled = match sluse_gate_core::as_user::enter().map(|_as_user| scope::compile(&loaded)) {
        Err(e) => {
            eprintln!("config: {e}");
            return ExitCode::from(EX_CONFIG);
        }
        Ok(c) => c,
    };
    let compiled = match compiled {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    // Gate Core's Entra half, when a sharepoint source needs one (M7). No
    // credential to read: Gate Core is a public client (D-036).
    let entra = match sluse_gate_core::entra::Entra::from_loaded(&loaded) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("entra: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    let user = identity::acting_as(loaded.config.environment);

    // The TLS configuration is built before the preflight, because the preflight
    // reports on the certificate and re-reading it to answer a question already
    // answered would let two answers differ.
    // An open's core accepts only the leaf its own enrolment issues (D-058);
    // LOCAL's development leaf, with no enrolment, is checked against the CA.
    let enrol_token = std::env::var("SLUSE_ENROL_TOKEN_SHA256").ok();
    let server_tls = tls::server_config(&loaded);
    let cert_check = match &server_tls {
        Ok(t) => match &t.check {
            preflight::CertCheck::Ok { pin } => preflight::CertCheck::Ok { pin: pin.clone() },
            preflight::CertCheck::PinMismatch { expected, presented } => {
                preflight::CertCheck::PinMismatch {
                    expected: expected.clone(),
                    presented: presented.clone(),
                }
            }
            preflight::CertCheck::Missing { detail } => {
                preflight::CertCheck::Missing { detail: detail.clone() }
            }
        },
        Err(e) => tls::missing(e),
    };

    let posture = preflight::run(&loaded, cert_check);

    println!("box            {}", loaded.config.box_id);
    println!("environment    {:?}", loaded.config.environment);
    println!("config version {}", loaded.version);
    println!("acting as      {}", user.display());
    println!(
        "volume         {} distinct files in {} s",
        loaded.config.volume.admissions, loaded.config.volume.window_seconds
    );
    println!("posture        {}", posture.id);
    println!();

    for source in &compiled.sources {
        let backend = sources::backend_for(source);
        let where_ = source.root.as_ref().map(|r| r.display().to_owned());
        println!("source {} ({})", source.name, backend.kind());
        match where_ {
            Some(root) => println!("  root   {root}"),
            // A sharepoint source has no filesystem root: it is served
            // through Graph (M7), its bytes through Gate Core (D-046).
            None => println!("  site   {} (Graph)", source.kind.address()),
        }
        for scope in source.remote.iter().flatten() {
            println!("  scope  {}/{}", source.name, scope.rel);
        }
        for scope in &source.scopes {
            println!("  scope  {}", scope::request_form(source.name.as_str(), &scope.rel));
        }
    }

    println!();
    preflight::print(&posture);

    if cli.check {
        // `check` reports and does not judge: a failed required check is printed above
        // with the rest, and the exit code says whether this config would start.
        return if posture.required_passed() { ExitCode::SUCCESS } else { ExitCode::from(EX_CONFIG) };
    }

    if !cli.serve {
        eprintln!();
        eprintln!("sluse-gate-core: pass --check or --serve.");
        return ExitCode::from(2);
    }

    if !posture.required_passed() {
        eprintln!();
        eprintln!("sluse-gate-core: a required check failed; not starting. There is no override.");
        return ExitCode::from(EX_CONFIG);
    }

    let sink = match build_sink(&loaded) {
        Ok(s) => s,
        Err(e) => {
            // The sink is not optional. A Gate Core that admitted files without
            // recording them would be the one failure this design cannot absorb.
            eprintln!("audit: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    // An open by the service enrols its box and has its proxy (slice 2, M9);
    // LOCAL's `sluse start` has neither.
    let open = enrol_token.is_some();
    let listen = cli.listen.clone().unwrap_or_else(|| loaded.config.gate.listen.clone());
    let start = match front_start(&loaded, &listen, open) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Gate Front: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };
    let claims = match claims(&loaded) {
        Ok(c) => Arc::new(c),
        Err(code) => return code,
    };
    let enrolment = match enrol_token.as_deref().map(|hex| enrolment(&loaded, hex)).transpose() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("enrolment: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };
    let mirror = std::env::var_os("SLUSE_JOURNAL_MIRROR").map(PathBuf::from);
    // The sign-in window's records (D-075), beside the proxy's.
    let window = match event_writer(&loaded, sluse_gate_core::audit::SIGN_IN_WINDOW, "window") {
        Ok(write) => sluse_gate_core::window::Window::new(
            serde_json::json!({ "boxId": loaded.config.box_id, "configVersion": loaded.version }),
            write,
        ),
        Err(code) => return code,
    };
    // The clipboard's records (D-076), from the control channel.
    let clipboard = match event_writer(&loaded, sluse_gate_core::audit::CLIPBOARD, "clipboard") {
        Ok(write) => write,
        Err(code) => return code,
    };
    let core = Arc::new(
        Core::new(loaded, compiled, sink, posture).with_entra(entra).with_journal_mirror(mirror).with_window(window)
            .with_clipboard(clipboard),
    );

    core.report_unavailable();

    match core.write_posture() {
        Ok(Some(p)) => println!("posture snapshot written to {}", p.display()),
        Ok(None) => {}
        Err(e) => eprintln!("posture snapshot could not be written: {e}"),
    }

    // Front runs as LocalService on a device, where the service starts Core
    // as SYSTEM; LOCAL's `sluse start` and CI have no SYSTEM to start it so,
    // and its Front is an ordinary child (D-071).
    let local_service = core.loaded.config.environment != sluse_proto::Environment::Local;
    let mut router =
        http::router(core.clone()).merge(front::routes(start, claims.clone())).merge(front::window_route(core.clone()));
    if let Some(e) = enrolment {
        router = router.merge(http::enrol_router(Arc::new(e)));
    }
    run_front(router, claims, Some(core), local_service)
}

/// Start Front, serve it until it stops or this process is told to, and
/// write the refusals' counts at the end. `core` is none for `--proxy`.
fn run_front(router: axum::Router, claims: Arc<Claims>, core: Option<Arc<Core>>, local_service: bool) -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::from(1);
        }
    };
    let code = runtime.block_on(async move {
        let started = match front::binary().and_then(|exe| {
            let log = front_log()?;
            front::start(&exe, &[], log, local_service)
        }) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Gate Front: {e}");
                return ExitCode::from(EX_CONFIG);
            }
        };
        let mut child = started.child;
        let serving = tokio::spawn(front::serve(started.io, router));
        // A sign-in window ends on time, asked or not (D-075).
        if let Some(core) = core.clone() {
            tokio::spawn(async move {
                let mut each = tokio::time::interval(std::time::Duration::from_secs(1));
                loop {
                    each.tick().await;
                    core.window.tick();
                }
            });
        }
        println!("Gate Front started; it binds the box's ports and asks here");

        // The service's control channel (D-036): sign-ins from the host, on
        // stdin. Null in LOCAL, where it ends at once. Under the service its
        // end is the stop, so the counts below are written (D-071); in LOCAL
        // a stop is Ctrl+C.
        let stop_on_eof = std::env::var_os("SLUSE_STOP_ON_EOF").is_some();
        let control = async {
            match &core {
                Some(core) => sluse_gate_core::control::run(core.clone(), tokio::io::BufReader::new(tokio::io::stdin())).await,
                None => {
                    use tokio::io::AsyncReadExt;
                    let mut stdin = tokio::io::stdin();
                    let mut buf = [0u8; 64];
                    while matches!(stdin.read(&mut buf).await, Ok(n) if n > 0) {}
                }
            }
            if !(stop_on_eof || core.is_none()) {
                std::future::pending::<()>().await;
            }
        };
        let code = tokio::select! {
            _ = tokio::signal::ctrl_c() => ExitCode::SUCCESS,
            _ = control => ExitCode::SUCCESS,
            r = serving => {
                // Front has gone: the box has no Gate, and this process stops
                // so the service sees it.
                eprintln!("Gate Front stopped ({}); its log says why", child.try_wait().unwrap_or_else(|| match r {
                    Ok(Err(e)) => e.to_string(),
                    _ => "the channel closed".into(),
                }));
                ExitCode::from(1)
            }
        };
        if let Some(core) = &core {
            core.window.stop();
        }
        child.kill();
        code
    });
    claims.refusals.finish();
    code
}

/// Front's start: the Gate for the box, enrolment and the proxy for an open.
fn front_start(loaded: &sluse_proto::Loaded, listen: &str, open: bool) -> Result<FrontStart, String> {
    let gate = front::gate_start(loaded, listen, open)?;
    let proxy = if open { Some(proxy_start(loaded)?) } else { None };
    Ok(FrontStart { gate: Some(gate), proxy })
}

fn proxy_start(loaded: &sluse_proto::Loaded) -> Result<sluse_proto::gate::FrontProxy, String> {
    // The Windows account the service opened the box for; none for a build.
    let opened_by = std::env::var("SLUSE_OPENED_BY").ok();
    front::proxy_start(loaded, opened_by, std::env::var_os("SLUSE_EGRESS_LOG").is_some())
}

/// Where Front's claims go: refusals to the Event Log (1201) on a device and
/// to stderr elsewhere; connections to the file the service named when the
/// config turns that log on (D-038 point 7), capped.
fn claims(loaded: &sluse_proto::Loaded) -> Result<Claims, ExitCode> {
    let write = event_writer(loaded, sluse_gate_core::audit::EGRESS_REFUSED, "refused")?;
    let log = std::env::var_os("SLUSE_EGRESS_LOG").map(|path| {
        let cap = loaded.config.egress.as_ref().and_then(|e| e.log.as_ref()).map_or(50, |l| l.max_mb);
        RollingLog::new(PathBuf::from(path), u64::from(cap) << 20)
    });
    Ok(Claims::new(Refusals::new(write), log))
}

type Writer = Box<dyn Fn(&serde_json::Value) + Send + Sync>;

/// A record that is not an `AuditRecord` (the proxy's refusals, the sign-in
/// window's): to the Event Log as `id` on a device, a refusal a warning and
/// the rest information; to stderr, labelled, elsewhere.
fn event_writer(loaded: &sluse_proto::Loaded, id: u32, label: &'static str) -> Result<Writer, ExitCode> {
    match loaded.config.audit.sink {
        #[cfg(windows)]
        AuditSinkKind::Eventlog => match sluse_gate_core::audit::EventLogSink::new() {
            Ok(sink) => Ok(Box::new(move |v| {
                let level = if id % 100 == 1 { sluse_gate_core::audit::EventLevel::Warning } else { sluse_gate_core::audit::EventLevel::Information };
                if let Err(e) = sink.report(id, level, &v.to_string()) {
                    eprintln!("event log: {e}");
                }
            })),
            Err(e) => {
                eprintln!("audit: {e}");
                Err(ExitCode::from(EX_CONFIG))
            }
        },
        _ => {
            let _ = id;
            Ok(Box::new(move |v| eprintln!("{label}: {v}")))
        }
    }
}

/// Front's log, beside this process's own: the service gives Core a file as
/// stderr, and `SLUSE_FRONT_LOG` names Front's.
fn front_log() -> std::io::Result<std::fs::File> {
    match std::env::var_os("SLUSE_FRONT_LOG") {
        Some(path) => std::fs::OpenOptions::new().create(true).append(true).open(path),
        None => discard(),
    }
}

/// No log named: Front's stderr is discarded.
fn discard() -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new().write(true).open(if cfg!(windows) { "NUL" } else { "/dev/null" })
}

/// `--proxy`: no scope, no sign-in, no token, none of Gate Core's state; a
/// Front that is only the proxy, and its claims kept here.
fn proxy(loaded: &sluse_proto::Loaded) -> ExitCode {
    let start = match proxy_start(loaded) {
        Ok(p) => FrontStart { gate: None, proxy: Some(p) },
        Err(e) => {
            eprintln!("egress proxy: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };
    let claims = match claims(loaded) {
        Ok(c) => Arc::new(c),
        Err(code) => return code,
    };
    // As LocalService on a device; LOCAL's has no SYSTEM to start it so.
    let local_service = loaded.config.environment != sluse_proto::Environment::Local;
    run_front(front::routes(start, claims.clone()), claims, None, local_service)
}

/// Enrolment for this open: the token's hash, from the service.
fn enrolment(loaded: &sluse_proto::Loaded, token_hex: &str) -> Result<sluse_gate_core::enrol::Enrolment, String> {
    let token = sluse_proto::ContentHash::from_hex(token_hex.trim()).ok_or("the token hash is not a SHA-256")?;
    sluse_gate_core::enrol::Enrolment::load(loaded, token)
}

fn build_sink(loaded: &sluse_proto::Loaded) -> std::io::Result<Arc<dyn AuditSink>> {
    match loaded.config.audit.sink {
        AuditSinkKind::Jsonl => {
            // The loader guarantees a path when the sink is jsonl.
            let path = loaded.config.audit.path.as_ref().expect("jsonl implies a path");
            Ok(Arc::new(JsonlSink::new(loaded.resolve(path))?))
        }
        #[cfg(windows)]
        AuditSinkKind::Eventlog => Ok(Arc::new(sluse_gate_core::audit::EventLogSink::new()?)),
        #[cfg(not(windows))]
        AuditSinkKind::Eventlog => Err(std::io::Error::other(
            "the Event Log sink is Windows only; use \"jsonl\" here",
        )),
    }
}

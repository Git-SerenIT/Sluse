// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The token broker.
//!
//! Runs on the host — as the signed-in user in LOCAL, as SYSTEM impersonating
//! them in the product — and is the only thing that decides whether a file may
//! cross into the guest.
//!
//! Two modes. `--check` compiles a config, runs the preflight and prints what
//! would be served, touching no socket; it is what `sluse check` will call at M4.
//! `--serve` does all of that, refuses to continue if a **gate** check failed
//! (invariant 6, and the gate has no override), and then listens.
//!
//! The order in `--serve` is deliberate and is the one thing to keep if this is
//! ever rewritten: load the config, compile scope against the real filesystem,
//! build the TLS configuration, run the preflight *with what the TLS
//! configuration found about the certificate*, write the posture snapshot, bind
//! the socket, and only then serve. Each step's failure is reportable while it
//! can still be explained.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use sluse_broker::app::Broker;
use sluse_broker::audit::{AuditSink, JsonlSink};
use sluse_broker::{http, identity, preflight, scope, serve, sources, tls};
use sluse_proto::AuditSinkKind;

/// `EX_CONFIG`. Anything that means "this box will not run on this config".
const EX_CONFIG: u8 = 78;

#[derive(Debug, Parser)]
#[command(
    name = "sluse-broker",
    version,
    about = "Sluse token broker — path validation, capability issue, audit, volume"
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

    /// Be the box's egress proxy (M9, D-035) instead: the config's
    /// `egress.allow`, on the broker's host at the proxy port. Stops when
    /// stdin closes.
    #[arg(long, conflicts_with_all = ["check", "serve"])]
    proxy: bool,

    /// Bind this address instead of the config's `broker.listen`.
    ///
    /// For a test that wants an ephemeral port. `broker.url` still names the
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
                .unwrap_or_else(|_| "sluse_broker=info".into()),
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
        return proxy(&loaded, cli.listen.as_deref());
    }

    // On a device, Sluse Artifacts is the user's own folder, written as them
    // (D-031), and replaces the config's `artifacts` before anything checks
    // it: the scope compile below still refuses it inside a source root, and
    // the preflight probes it as the user.
    match sluse_broker::as_user::adopt() {
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
    let compiled = match sluse_broker::as_user::enter().map(|_as_user| scope::compile(&loaded)) {
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

    // The broker's Entra half, when a sharepoint source needs one (M7). No
    // credential to read: the broker is a public client (D-036).
    let entra = match sluse_broker::entra::Entra::from_loaded(&loaded) {
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
    // An open's broker accepts only the leaf its own enrolment issues (D-058);
    // LOCAL's development leaf, with no enrolment, is checked against the CA.
    let enrol_token = std::env::var("SLUSE_ENROL_TOKEN_SHA256").ok();
    let leaf_pin = enrol_token.as_ref().map(|_| tls::LeafPin::default());
    let server_tls = tls::server_config_pinned(&loaded, leaf_pin.clone());
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
            // through Graph (M7), its bytes through the broker (D-046).
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
        // `check` reports and does not judge: a gate failure is printed above
        // with the rest, and the exit code says whether this config would start.
        return if posture.gate_passed() { ExitCode::SUCCESS } else { ExitCode::from(EX_CONFIG) };
    }

    if !cli.serve {
        eprintln!();
        eprintln!("sluse-broker: pass --check or --serve.");
        return ExitCode::from(2);
    }

    if !posture.gate_passed() {
        eprintln!();
        eprintln!("sluse-broker: a gate check failed; not starting. There is no override.");
        return ExitCode::from(EX_CONFIG);
    }

    let server_tls = match server_tls {
        Ok(t) => t,
        Err(e) => {
            // Unreachable in practice — a TLS failure is a gate failure and was
            // caught above — and handled rather than unwrapped, because "in
            // practice" is how a panic in a service gets written.
            eprintln!("tls: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    let sink = match build_sink(&loaded) {
        Ok(s) => s,
        Err(e) => {
            // The sink is not optional. A broker that admitted files without
            // recording them would be the one failure this design cannot absorb.
            eprintln!("audit: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    let listen = cli.listen.clone().unwrap_or_else(|| loaded.config.broker.listen.clone());
    let mirror = std::env::var_os("SLUSE_JOURNAL_MIRROR").map(PathBuf::from);
    let broker = Arc::new(Broker::new(loaded, compiled, sink, posture).with_entra(entra).with_journal_mirror(mirror));

    broker.report_unavailable();

    match broker.write_posture() {
        Ok(Some(p)) => println!("posture snapshot written to {}", p.display()),
        Ok(None) => {}
        Err(e) => eprintln!("posture snapshot could not be written: {e}"),
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::from(1);
        }
    };

    runtime.block_on(async move {
        // Bind before announcing. `sluse start` checks reachability immediately
        // after launching this, and "listening" has to be a fact by the time it
        // is claimed.
        let listener = match serve::bind(&listen) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{}: {e}", sluse_proto::ports::label(&listen));
                return ExitCode::from(EX_CONFIG);
            }
        };

        let router = http::router(broker.clone());
        let (running, task) = match serve::serve(listener, server_tls.config, router) {
            Ok(pair) => pair,
            Err(e) => {
                eprintln!("serve: {e}");
                return ExitCode::from(1);
            }
        };

        println!("listening on https://{} (mTLS required)", running.addr);

        // The service's control channel (D-036): sign-ins from the host, on
        // stdin. Null in LOCAL, where it ends at once.
        tokio::spawn(sluse_broker::control::run(broker.clone(), tokio::io::BufReader::new(tokio::io::stdin())));

        // The enrolment listener, only when the service started this broker
        // for an open and gave it the token's hash (slice 2). Asked for and
        // not possible is a failure, not a broker without it: the box would
        // wait for an identity that never comes.
        let _enrolling = match (&enrol_token, leaf_pin) {
            (None, _) | (_, None) => None,
            (Some(hex), Some(pin)) => match enrol_listener(&broker.loaded, &listen, hex, pin) {
                Ok(r) => {
                    println!("enrolment on https://{} (one route, no client certificate)", r.addr);
                    Some(r)
                }
                Err(e) => {
                    eprintln!("enrolment: {e}");
                    return ExitCode::from(EX_CONFIG);
                }
            },
        };

        let mut task = task;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                println!();
                println!("stopping; letting reads in flight finish");
                running.shutdown();
                // Waited on rather than abandoned: a read in flight is an
                // admission in flight, and its record is written when the body
                // ends. Dropping the task here would lose it.
                let _ = task.await;
                ExitCode::SUCCESS
            }
            result = &mut task => match result {
                Ok(Ok(())) => ExitCode::SUCCESS,
                Ok(Err(e)) => {
                    eprintln!("serve: {e}");
                    ExitCode::from(1)
                }
                Err(e) => {
                    eprintln!("serve: {e}");
                    ExitCode::from(1)
                }
            },
        }
    })
}

/// `--proxy`: no scope, no sign-in, no token, none of the broker's state. A
/// process of its own, so whatever the box sends it never shares an address
/// space with the user's token.
fn proxy(loaded: &sluse_proto::Loaded, listen: Option<&str>) -> ExitCode {
    use sluse_broker::proxy::{Proxy, Records};
    let addr = match listen {
        Some(a) => a.to_owned(),
        None => match loaded.config.broker.listen.rsplit_once(':') {
            Some((host, _)) => format!("{host}:{}", sluse_proto::ports::PROXY),
            None => return ExitCode::from(EX_CONFIG),
        },
    };
    let refusal: Box<dyn Fn(&serde_json::Value) + Send + Sync> = match loaded.config.audit.sink {
        #[cfg(windows)]
        AuditSinkKind::Eventlog => match sluse_broker::audit::EventLogSink::new() {
            Ok(sink) => Box::new(move |v| {
                if let Err(e) = sink.report(sluse_broker::audit::EGRESS_REFUSED, sluse_broker::audit::EventLevel::Warning, &v.to_string()) {
                    eprintln!("event log: {e}");
                }
            }),
            Err(e) => {
                eprintln!("audit: {e}");
                return ExitCode::from(EX_CONFIG);
            }
        },
        // Elsewhere, on stderr beside the rest of what it says.
        _ => Box::new(|v| eprintln!("refused: {v}")),
    };
    // Every connection, to the file the service named when the config turns
    // the log on (D-038 point 7), capped; else to stdout, which the service
    // discards and a person running this by hand reads.
    let connection: Box<dyn Fn(&serde_json::Value) + Send + Sync> = match std::env::var_os("SLUSE_EGRESS_LOG") {
        Some(path) => {
            let cap = loaded.config.egress.as_ref().and_then(|e| e.log.as_ref()).map_or(50, |l| l.max_mb);
            let log = std::sync::Mutex::new(sluse_broker::proxy::RollingLog::new(PathBuf::from(path), u64::from(cap) << 20));
            Box::new(move |v| log.lock().unwrap_or_else(|p| p.into_inner()).line(&v.to_string()))
        }
        None => Box::new(|v| {
            use std::io::Write;
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{v}");
            let _ = out.flush();
        }),
    };
    let records = Records { connection, refusal };
    let about = serde_json::json!({
        "boxId": loaded.config.box_id, "configVersion": loaded.version,
        // The Windows account the service opened the box for; none for a build.
        "openedBy": std::env::var("SLUSE_OPENED_BY").ok(),
    });
    let allow = loaded.config.egress.clone().unwrap_or_default();
    let proxy = std::sync::Arc::new(Proxy::new(allow, about, records));
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(async move {
        let listener = match tokio::net::TcpListener::bind(&addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("{}: {e}", sluse_proto::ports::label(&addr));
                return ExitCode::from(EX_CONFIG);
            }
        };
        eprintln!("egress proxy on {addr}: {} allowed hosts", loaded.config.egress.as_ref().map_or(0, |e| e.allow.len()));
        let stdin_closed = async {
            use tokio::io::AsyncReadExt;
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 64];
            while matches!(stdin.read(&mut buf).await, Ok(n) if n > 0) {}
        };
        let code = tokio::select! {
            r = proxy.clone().serve(listener) => {
                eprintln!("egress proxy: {}", r.err().map_or("stopped".into(), |e| e.to_string()));
                ExitCode::from(1)
            }
            _ = stdin_closed => ExitCode::SUCCESS,
            _ = tokio::signal::ctrl_c() => ExitCode::SUCCESS,
        };
        proxy.finish();
        code
    })
}

/// Bind `<listen host>:ENROL_PORT` and serve the one enrolment route on it.
fn enrol_listener(
    loaded: &sluse_proto::Loaded,
    listen: &str,
    token_hex: &str,
    pin: tls::LeafPin,
) -> Result<serve::Running, String> {
    let token = sluse_proto::ContentHash::from_hex(token_hex.trim()).ok_or("the token hash is not a SHA-256")?;
    let enrolment = Arc::new(sluse_broker::enrol::Enrolment::load(loaded, token)?.pinning(pin));
    let tls = tls::enrol_server_config(loaded).map_err(|e| e.to_string())?;
    let host = listen.rsplit_once(':').map(|(h, _)| h).ok_or("broker.listen has no port")?;
    let addr = format!("{host}:{}", sluse_proto::wire::ENROL_PORT);
    let listener = serve::bind(&addr).map_err(|e| format!("{}: {e}", sluse_proto::ports::label(&addr)))?;
    let (running, _task) = serve::serve(listener, tls, http::enrol_router(enrolment)).map_err(|e| e.to_string())?;
    Ok(running)
}

fn build_sink(loaded: &sluse_proto::Loaded) -> std::io::Result<Arc<dyn AuditSink>> {
    match loaded.config.audit.sink {
        AuditSinkKind::Jsonl => {
            // The loader guarantees a path when the sink is jsonl.
            let path = loaded.config.audit.path.as_ref().expect("jsonl implies a path");
            Ok(Arc::new(JsonlSink::new(loaded.resolve(path))?))
        }
        #[cfg(windows)]
        AuditSinkKind::Eventlog => Ok(Arc::new(sluse_broker::audit::EventLogSink::new()?)),
        #[cfg(not(windows))]
        AuditSinkKind::Eventlog => Err(std::io::Error::other(
            "the Event Log sink is Windows only; use \"jsonl\" here",
        )),
    }
}

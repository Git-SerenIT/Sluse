// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The endpoint. Runs in the guest: an MCP server over stdio (`--mcp`) and, at
//! M5, the console's loopback API (`--console`).
//!
//! **Everything on stdout belongs to the MCP transport.** Diagnostics go to
//! stderr, always. A single stray `println!` in this process is a protocol
//! error the client reports as a malformed message, and the cause is invisible
//! from the other end.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;
use sluse_endpoint::gate_client::GateClient;
use sluse_endpoint::journal::Journal;
use sluse_endpoint::server::Endpoint;
use sluse_endpoint::session;

/// `EX_CONFIG`. Anything that means "this endpoint will not run on this config".
const EX_CONFIG: u8 = 78;

#[derive(Debug, Parser)]
#[command(
    name = "sluse-endpoint",
    version,
    about = "Sluse endpoint — the guest's only way to reach a source"
)]
struct Cli {
    /// The config file. The guest's copy; the Gate enforces from its own.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// Serve MCP over stdio.
    #[arg(long)]
    mcp: bool,

    /// The console's loopback API.
    #[arg(long, conflicts_with = "mcp")]
    console: bool,

    /// Enrol this box (slice 2): read the host's bootstrap from KVP, get an
    /// identity from the Gate, and write it and the Gate's config to
    /// `--config`. Run as root, by `sluse-enrol.service`.
    #[arg(long, conflicts_with_all = ["mcp", "console"])]
    enrol: bool,

    /// With `--enrol`: who owns the written files, as `uid:gid`.
    #[arg(long, value_name = "UID:GID", requires = "enrol")]
    owner: Option<String>,

    /// With `--enrol`: the KVP pool to read.
    #[arg(long, value_name = "PATH", default_value = sluse_endpoint::kvp::POOL, requires = "enrol")]
    pool: PathBuf,

    /// With `--enrol`: a systemd unit to restart once a new identity is
    /// written, which is the console.
    #[arg(long, value_name = "UNIT", requires = "enrol")]
    restart: Option<String>,

    /// Where the console's files are. Only read with `--console`.
    #[arg(long, value_name = "DIR", default_value = sluse_endpoint::console::assets::DEFAULT_UI_DIR)]
    ui: PathBuf,
}

fn main() -> ExitCode {
    // First statement, as in the Gate: with two crypto providers linked,
    // rustls refuses to guess which is the default and panics on the first
    // handshake.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sluse_endpoint=info".into()),
        )
        // stderr, and it is not a preference: stdout is the MCP transport.
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    if !cli.mcp && !cli.console && !cli.enrol {
        eprintln!("sluse-endpoint: pass --mcp, --console or --enrol.");
        return ExitCode::from(2);
    }

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("runtime: {e}");
            return ExitCode::from(1);
        }
    };

    if cli.enrol {
        return runtime.block_on(run_enrol(&cli));
    }

    let result = if cli.console {
        runtime.block_on(run_console(&cli.config, &cli.ui))
    } else {
        runtime.block_on(run(&cli.config))
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(code) => ExitCode::from(code),
    }
}

/// `--enrol`. Exit 0 when the box has an identity for this bootstrap; 75
/// (`EX_TEMPFAIL`) when the host has sent none yet or the Gate did not
/// answer the connection, so the unit tries again; 1 when enrolment failed,
/// which is final: the host sees it on the serial console and the window
/// says so (jok, 2026-10-30: retrying is the person's decision).
async fn run_enrol(cli: &Cli) -> ExitCode {
    let owner = match cli.owner.as_deref().map(sluse_endpoint::enrol::parse_owner).transpose() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    match sluse_endpoint::enrol::run(&cli.config, &cli.pool, owner).await {
        Ok(sluse_endpoint::enrol::Outcome::Enrolled) => {
            eprintln!("enrolled: {}", cli.config.display());
            // Queued, not waited for: the console is ordered after this
            // unit, so waiting here waits for ourselves (L1, 2026-09-30).
            if let Some(unit) = &cli.restart {
                let _ = std::process::Command::new("systemctl").args(["restart", "--no-block", unit]).status();
            }
            ExitCode::SUCCESS
        }
        Ok(sluse_endpoint::enrol::Outcome::Unchanged) => {
            eprintln!("already enrolled with this bootstrap");
            ExitCode::SUCCESS
        }
        Ok(sluse_endpoint::enrol::Outcome::NoBootstrap) => {
            eprintln!("no bootstrap from the host yet");
            ExitCode::from(75)
        }
        Ok(sluse_endpoint::enrol::Outcome::NotReached) => {
            eprintln!("the Gate did not answer yet");
            ExitCode::from(75)
        }
        Err(e) => {
            eprintln!("enrolment failed: {e}");
            ExitCode::from(1)
        }
    }
}

/// The console's loopback API (M5).
///
/// **It joins the run rather than starting one.** The journal is per session and
/// the session belongs to the run, so a console that minted its own would read
/// an empty file and show a person nothing while their agent worked. It takes
/// the session the workspace remembers, and only falls back to a fresh one when
/// there is no run to join yet — which is still worth serving, because the
/// sources and the Gate are worth looking at before anything has been admitted.
///
/// It does **not** call [`session::attach`]. Recording a session is the running
/// endpoint's business; a console that wrote there would claim a run it is only
/// watching.
async fn run_console(config_path: &std::path::Path, ui_dir: &std::path::Path) -> Result<(), u8> {
    let loaded = sluse_proto::config::load(config_path).map_err(|e| {
        eprintln!("config: {e}");
        EX_CONFIG
    })?;

    let addr: std::net::SocketAddr =
        loaded.config.endpoint.console_listen.parse().map_err(|e| {
            eprintln!("endpoint.consoleListen {}: {e}", loaded.config.endpoint.console_listen);
            EX_CONFIG
        })?;
    // Checked before the Gate is contacted, so a config that could not have
    // been served says so immediately rather than after a handshake.
    sluse_endpoint::console::api::require_loopback(addr).map_err(|e| {
        eprintln!("{e}");
        EX_CONFIG
    })?;

    let workspace = loaded.resolve(&loaded.config.workspace);
    let remembered = session::remembered(&workspace);
    let joined = remembered.is_some();
    let (client, health, _) = connect(&loaded, remembered).await?;
    if joined {
        tracing::info!(session = %client.session(), "console joined the run's session");
    } else {
        tracing::warn!("no run to join yet; the journal and inventory will be empty until one starts");
    }

    let view = client.config_view().await.map_err(|e| {
        eprintln!("the Gate refused the config view: {e}");
        EX_CONFIG
    })?;

    let local = client.status_now().await.ok().and_then(|s| s.environment) == Some(sluse_proto::Environment::Local);
    let state = std::sync::Arc::new(sluse_endpoint::console::Console {
        session: client.session().clone(),
        gate: client,
        view,
        workspace,
        journal_dir: loaded.resolve(&loaded.config.journal_dir),
        box_id: health.box_id.clone(),
        config_version: health.config_version.clone(),
        ui_dir: ui_dir.to_path_buf(),
        mirrored: std::sync::atomic::AtomicU64::new(0),
        local,
        deployment: loaded.config.deployment.clone(),
    });

    if !ui_dir.join("index.html").is_file() {
        // Said now, not discovered as a blank page. The API is still worth
        // serving without the views — `curl` is a console too.
        tracing::warn!(
            dir = %ui_dir.display(),
            "no index.html here; the API is served and the views are not. Build them with \
             `npm --prefix ui/console run build`, or pass --ui"
        );
    }

    eprintln!("console on http://{addr} — loopback, no authentication (M5 limitation)");
    sluse_endpoint::console::serve(state, addr).await.map_err(|e| {
        eprintln!("console: {e}");
        EX_CONFIG
    })
}

async fn run(config_path: &std::path::Path) -> Result<(), u8> {
    // Invariant 6 on the guest's side too. The Gate enforces from its own
    // copy; this one only has to be loadable for the endpoint to know where the
    // Gate is and which certificate to expect.
    let loaded = sluse_proto::config::load(config_path).map_err(|e| {
        eprintln!("config: {e}");
        EX_CONFIG
    })?;

    let workspace = loaded.resolve(&loaded.config.workspace);
    std::fs::create_dir_all(&workspace).map_err(|e| {
        eprintln!("workspace {}: {e}", workspace.display());
        EX_CONFIG
    })?;

    // A session belongs to the run, not to this process. If one is remembered
    // and the Gate still holds it, the journal and the lineage continue
    // across the restart.
    let remembered = session::remembered(&workspace);
    let (client, health, rejoined) = connect(&loaded, remembered).await?;

    let resumed = session::attach(&workspace, client.session(), rejoined, chrono::Utc::now())
        .map_err(|e| {
            eprintln!("recording the session: {e}");
            EX_CONFIG
        })?;
    // Said out loud rather than inferred from timestamps later.
    tracing::info!("{}", resumed.describe());

    let view = client.config_view().await.map_err(|e| {
        eprintln!("the Gate refused the config view: {e}");
        EX_CONFIG
    })?;

    let journal_dir = loaded.resolve(&loaded.config.journal_dir);
    let journal = Journal::open_session(&journal_dir, client.session()).map_err(|e| {
        eprintln!("journal {}: {e}", journal_dir.display());
        EX_CONFIG
    })?;

    tracing::info!(
        box_id = %health.box_id,
        gate = %health.gate_version,
        user = %health.user.display(),
        sources = view.sources.len(),
        journal = %journal.path().display(),
        "endpoint ready"
    );

    let endpoint = Endpoint::new(
        client,
        journal,
        view,
        workspace,
        health.box_id.clone(),
        health.config_version.clone(),
    );

    use rmcp::transport::stdio;
    use rmcp::ServiceExt;
    let service = endpoint.serve(stdio()).await.map_err(|e| {
        eprintln!("mcp: {e}");
        1u8
    })?;
    service.waiting().await.map_err(|e| {
        eprintln!("mcp: {e}");
        1u8
    })?;
    Ok(())
}

/// Connect, resuming the run's session when the Gate still has it.
///
/// A remembered session the Gate has forgotten — it holds them for twelve
/// hours idle — is not carried on with silently: a new one is taken, and the
/// journal and lineage start fresh, which is visible in the log rather than
/// discovered later in a provenance record.
async fn connect(
    loaded: &sluse_proto::Loaded,
    remembered: Option<sluse_proto::SessionId>,
) -> Result<(GateClient, sluse_proto::Health, bool), u8> {
    let (client, health) = GateClient::connect(loaded).await.map_err(|e| {
        eprintln!("gate: {e}");
        eprintln!("Nothing is admitted when the Gate cannot be reached; this fails closed.");
        EX_CONFIG
    })?;

    let Some(previous) = remembered else {
        return Ok((client, health, false));
    };

    // The Gate is the authority on whether that session still exists, so it is
    // asked rather than assumed: on the status route, which answers without a
    // refusal in the Sluse log for a session that aged out.
    let resumed = client.with_session(previous);
    match resumed.session_held().await {
        Ok(true) => Ok((resumed, health, true)),
        Ok(false) => {
            tracing::info!(
                session_id = %resumed.session(),
                "the Gate no longer holds the previous session; starting a new run"
            );
            let (client, health) = GateClient::connect(loaded).await.map_err(|e| {
                eprintln!("gate: {e}");
                EX_CONFIG
            })?;
            Ok((client, health, false))
        }
        Err(e) => {
            eprintln!("gate: {e}");
            Err(EX_CONFIG)
        }
    }
}

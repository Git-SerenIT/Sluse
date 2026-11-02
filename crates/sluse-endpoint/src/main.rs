// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The endpoint. Runs in the guest: an MCP server over stdio (`--mcp`), the
//! box's enrolment (`--enrol`), and the console's answers as JSON for the
//! acceptance script (`--query`). The console itself is `sluse-console`.
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

    /// Enrol this box (slice 2): read the host's bootstrap from KVP, get an
    /// identity from the Gate, and write it and the Gate's config to
    /// `--config`. Run as root, by `sluse-enrol.service`.
    #[arg(long, conflicts_with = "mcp")]
    enrol: bool,

    /// With `--enrol`: who owns the written files, as `uid:gid`.
    #[arg(long, value_name = "UID:GID", requires = "enrol")]
    owner: Option<String>,

    /// With `--enrol`: the KVP pool to read.
    #[arg(long, value_name = "PATH", default_value = sluse_endpoint::kvp::POOL, requires = "enrol")]
    pool: PathBuf,

    /// One of the console's answers as JSON on stdout, for the acceptance
    /// script (D-079): `state`, `sources`, or `list` with `--path`.
    #[arg(long, value_enum, conflicts_with_all = ["mcp", "enrol"])]
    query: Option<Query>,

    /// With `--query list`: `<source>` or `<source>/<relative path>`.
    #[arg(long, value_name = "PATH", requires = "query")]
    path: Option<String>,

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

    if !cli.mcp && !cli.enrol && cli.query.is_none() {
        eprintln!("sluse-endpoint: pass --mcp, --enrol or --query.");
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

    let result = if let Some(what) = cli.query {
        runtime.block_on(run_query(&cli.config, what, cli.path.as_deref()))
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
            // The console sees the new config and joins again by itself.
            eprintln!("enrolled: {}", cli.config.display());
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

/// `--query`: one of the console's calls, its answer as JSON on stdout (D-079
/// point 5). For the acceptance script, which drove the console's HTTP API
/// for the same answers. A refusal is an answer: its error, as JSON, on
/// stdout too, and exit 1; only a run that could not ask exits otherwise.
async fn run_query(config_path: &std::path::Path, what: Query, path: Option<&str>) -> Result<(), u8> {
    let loaded = sluse_proto::config::load(config_path).map_err(|e| {
        eprintln!("config: {e}");
        EX_CONFIG
    })?;
    let console = sluse_endpoint::console::Console::join(&loaded).await.map_err(|e| {
        eprintln!("{e}");
        EX_CONFIG
    })?;
    let answer = match what {
        Query::State => serde_json::to_value(console.state().await).map_err(|e| e.to_string()),
        Query::Sources => serde_json::to_value(&console.view).map_err(|e| e.to_string()),
        Query::List => {
            let Some(path) = path else {
                eprintln!("--query list needs --path");
                return Err(2);
            };
            match console.list(path).await {
                Ok(l) => serde_json::to_value(l).map_err(|e| e.to_string()),
                Err(refused) => {
                    println!("{}", serde_json::to_string(&refused).unwrap_or_default());
                    return Err(1);
                }
            }
        }
    };
    match answer {
        Ok(v) => {
            println!("{v}");
            Ok(())
        }
        Err(e) => {
            eprintln!("{e}");
            Err(1)
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum Query {
    State,
    Sources,
    List,
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
    sluse_endpoint::gate_client::connect_resuming(loaded, remembered).await.map_err(|e| {
        eprintln!("{e}");
        EX_CONFIG
    })
}

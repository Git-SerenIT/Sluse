// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! `sluse` — the lifecycle CLI: `check`, `start`, `stop`, `status`, `devcert`.
//! A CLI first and a Windows service later (D-010); the preflight checks it runs
//! is the same either way.
//!
//! ## Where the work actually lives
//!
//! Almost nothing here is new logic, which is the point. The preflight checks
//! are `sluse_gate_core::preflight`, and they are there rather than here because
//! `/v1/health` reports the `posture_id` every audit record cites — two runners
//! would eventually describe one machine two ways. The probe behind `status` and
//! the "gate reachable" Gate is the guest's own pinned client,
//! `sluse_endpoint::gate_client::status`, for the same reason in the other
//! direction: a host-side probe that trusted anything the guest does not would
//! answer a different question from the one the endpoint asks a moment later.
//!
//! What is new is the three things nobody else can own: the run workspace
//! ([`run`]), the record of what is running ([`state`]), and the order these
//! happen in.
//!
//! ## `start` generates the run's config
//!
//! It writes the file and lets the Gate load it, rather than handing the
//! Gate settings on a command line. `config_version` is the hash of the config
//! file and every audit record cites it; a runtime override would leave every
//! record in the run pointing at a file that says something else. **D-019 took
//! `--fetch on|off` out**: there is one read-path shape now, so there is nothing
//! left for a mode flag to name. See [`run`].
//!
//! ## `stop` does not clear the session
//!
//! M3 decided the run owns the session and a rejoin reports its age. So `stop`
//! stops the Gate and leaves `.sluse-session.json` where it is: starting again
//! in the same workspace rejoins the same session, appends to the same journal
//! file, and keeps accumulating lineage. `stop --reset` is how a person says
//! they meant a new run, and it says so out loud when it does it.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};

// The service runs on Windows only; on the guest its logic is compiled and
// tested, and nothing calls it.
use sluse_admin::setup as admin;
#[cfg_attr(not(windows), allow(dead_code))]
mod boxes;
#[cfg_attr(not(windows), allow(dead_code))]
mod console;
mod devcert;
#[cfg_attr(not(windows), allow(dead_code))]
mod hyperv;
mod image;
mod run;
#[cfg_attr(not(windows), allow(dead_code))]
mod service;
mod state;
#[cfg(windows)]
mod winsys;

/// `EX_CONFIG`. The same code the Gate uses for a config it will not run on.
const EX_CONFIG: u8 = 78;

/// How long `start` waits for the Gate to answer `/v1/status`.
///
/// Generous: the Gate canonicalises every source root and probes the artifacts
/// directory before it binds, and a cold `Z:` has been slower than this deserves
/// to suggest. A Gate that has not answered by now has not started, and the
/// log says why.
const START_TIMEOUT_SECONDS: u64 = 20;

#[derive(Parser)]
#[command(name = "sluse", version, about = "Sluse lifecycle")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the preflight against a config and print both lists. Starts nothing.
    Check {
        /// The config file.
        #[arg(long, value_name = "PATH")]
        config: PathBuf,
    },

    /// Lay out a run workspace and start a Gate for it.
    ///
    /// Writes the config, the development certificates, `.mcp.json`, `launch.ps1`
    /// and the task, then starts the Gate and waits until it answers.
    Start {
        /// The run workspace. Created if it is not there.
        #[arg(long, value_name = "DIR")]
        workspace: PathBuf,

        /// The fixture root the source is rooted at. Generate one with
        /// `tools\fixture\make-fixture.ps1`.
        #[arg(long, value_name = "PATH")]
        fixture: PathBuf,

        /// What the Gate binds. Change it to run two modes at once.
        #[arg(long, value_name = "ADDR", default_value = "127.0.0.1:7580")]
        listen: String,

        /// The box id in the generated config.
        #[arg(long, value_name = "ID")]
        box_id: Option<String>,
    },

    /// Stop the Gate for a run.
    Stop {
        /// The run workspace. Defaults to the current directory.
        #[arg(long, value_name = "DIR", default_value = ".")]
        workspace: PathBuf,

        /// Also forget the session, so the next `start` is a new run.
        ///
        /// Without it the session survives and the next run rejoins it, which is
        /// what a Gate restart in the middle of a task should do.
        #[arg(long)]
        reset: bool,
    },

    /// What is running on this machine.
    Status {
        /// Just this run. Without it, every run in the state directory.
        #[arg(long, value_name = "DIR")]
        workspace: Option<PathBuf>,
    },

    /// Generate development certificates: a CA, a Gate leaf and an endpoint
    /// leaf, and print the pin.
    Devcert {
        /// Where the six files go. Usually the `certs` directory beside the
        /// config.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,

        /// An extra DNS name or address the Gate should answer to, beyond
        /// `localhost` and `127.0.0.1`. Repeatable.
        #[arg(long = "hostname", value_name = "NAME")]
        hostnames: Vec<String>,

        /// Write the pin into `gate.certPin` in this config's device half
        /// (`<name>.device.json` beside it).
        ///
        /// Without it, `devcert` prints the pin and edits nothing. The device
        /// half is not part of `config_version` (D-038).
        #[arg(long, value_name = "PATH")]
        update_config: Option<PathBuf>,
    },

    /// The lifecycle service: started by the SCM as SYSTEM, or in the
    /// foreground from an elevated console to try it (D-027).
    Service,

    /// The boxes the service knows, one per Windows user. Run elevated.
    #[command(subcommand)]
    Box(BoxCommand),

    /// The box's base image, by hand: what the service does before a first
    /// build (slice 3). For trying the steps one at a time.
    #[command(subcommand)]
    Image(ImageCommand),

    /// This device's part of the install (slice 5). Run elevated, or by the
    /// MSI as SYSTEM.
    #[command(subcommand)]
    Device(DeviceCommand),

    /// A tenant, once, as its administrator (slice 5).
    #[command(subcommand)]
    Admin(AdminCommand),
}

#[derive(Subcommand)]
enum AdminCommand {
    /// Make or repair Sluse's Entra registration, a public client with no
    /// credential (D-036), through Microsoft Graph, and write the
    /// deployment's package for Intune: the MSI, the config and the script,
    /// one Win32 app (D-043). Signs in by device code. Running it again
    /// changes nothing.
    Setup {
        /// Where the package goes. Keep it: a rerun into it keeps the
        /// deployment's id.
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// The Sluse.msi the package carries.
        #[arg(long, value_name = "FILE")]
        msi: PathBuf,
        /// The SharePoint site, e.g. https://contoso.sharepoint.com/sites/Team.
        #[arg(long, value_name = "URL")]
        site: String,
        /// The document library in it.
        #[arg(long, default_value = "Documents")]
        library: String,
        /// The source's name, the first segment of every path the agent uses.
        #[arg(long, default_value = "spo")]
        source_name: String,
        /// A folder in the library the agent may work in, relative to it.
        /// Repeat for more than one. None: the whole library is in scope.
        #[arg(long = "scope", value_name = "FOLDER")]
        scopes: Vec<String>,
        /// The public client to sign in with, if the tenant blocks Microsoft's.
        #[arg(long, default_value = admin::GRAPH_CLI_CLIENT)]
        client_id: String,
    },
    /// Wrap a folder as an `.intunewin` for Intune's Win32 app, with our own
    /// writer (D-039 point 2) in place of Microsoft's tool.
    Intunewin {
        /// The folder; everything in it goes in.
        #[arg(long, value_name = "DIR")]
        source: PathBuf,
        /// The file in it Intune runs, e.g. Install-Sluse.ps1.
        #[arg(long, value_name = "FILE")]
        setup: String,
        #[arg(long, value_name = "FILE")]
        out: PathBuf,
    },
    /// Package a saved configuration with an MSI for Intune (D-043): the
    /// folder and `.intunewin` Sluse Admin's Save writes, beside the file.
    /// For a new Sluse release over a saved deployment; no sign-in.
    Package {
        /// The saved configuration, e.g. sluse-pilot.json.
        #[arg(long, value_name = "FILE")]
        config: PathBuf,
        /// The Sluse.msi the package carries.
        #[arg(long, value_name = "FILE")]
        msi: PathBuf,
    },
    /// An MSI's product code and version, as JSON.
    MsiInfo {
        path: PathBuf,
    },
}

#[derive(Subcommand)]
enum DeviceCommand {
    /// The host-only switch, the host's address, the Gate's firewall
    /// rule, the Event Log source, and no NAT (M9); then the device's
    /// certificates, once `sluse.json` is there. What the service does at every start.
    Init,
    /// Everything `init` and the service made, the boxes and their disks
    /// included, and the data directory. Uninstall runs this.
    Remove,
    /// The Sluse Event Log, which only SYSTEM may write (D-023), on its own:
    /// part of `init`, and what CI checks the descriptor with.
    EventLog,
}

#[derive(Subcommand)]
enum ImageCommand {
    /// Fetch Canonical's cloud image and check it against the signed
    /// SHA256SUMS.
    Fetch {
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
    },
    /// Convert the qcow2 image to a fixed VHD, which `Convert-VHD` takes.
    Vhd {
        #[arg(long, value_name = "PATH")]
        from: PathBuf,
        #[arg(long, value_name = "PATH")]
        to: PathBuf,
    },
}

#[derive(Subcommand)]
enum BoxCommand {
    /// Give a Windows user a box that already exists in Hyper-V.
    Adopt {
        /// The user's SID. As that user: `whoami /user`.
        #[arg(long)]
        sid: String,
        /// The Hyper-V VM's name.
        #[arg(long)]
        vm: String,
        /// The box's address on the host-only segment.
        #[arg(long)]
        address: std::net::Ipv4Addr,
    },
    /// "Reset the system, keep my files", for a user: a new system disk on the
    /// newest base, the home disk kept (D-026 point 3). Run elevated.
    Reset {
        #[arg(long)]
        sid: String,
    },
    /// "Wipe the box", for a user: both disks replaced. The host's records
    /// stay. Run elevated.
    Wipe {
        #[arg(long)]
        sid: String,
    },
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Check { config } => cmd_check(&config),
        Command::Start { workspace, fixture, listen, box_id } => {
            cmd_start(&workspace, &fixture, &listen, box_id.as_deref())
        }
        Command::Stop { workspace, reset } => cmd_stop(&workspace, reset),
        Command::Status { workspace } => cmd_status(workspace.as_deref()),
        Command::Devcert { out, hostnames, update_config } => {
            cmd_devcert(&out, &hostnames, update_config.as_deref())
        }
        Command::Service => cmd_service(),
        Command::Device(what) => cmd_device(what),
        Command::Admin(AdminCommand::Setup { out, msi, site, library, source_name, scopes, client_id }) => {
            let msi = match admin::MsiFile::read(&msi) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("sluse admin setup: {e}");
                    return ExitCode::from(1);
                }
            };
            cmd_admin_setup(admin::Options {
                out,
                msi,
                site,
                library,
                source_name,
                scopes,
                client_id,
                login: "https://login.microsoftonline.com".into(),
                graph: "https://graph.microsoft.com/v1.0".into(),
            })
        }
        Command::Admin(AdminCommand::Intunewin { source, setup, out }) => {
            match sluse_admin::intunewin::build(&source, &setup).and_then(|p| {
                std::fs::write(&out, &p.intunewin).map_err(|e| format!("{}: {e}", out.display()))
            }) {
                Ok(()) => {
                    println!("Wrote {}.", out.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("sluse admin intunewin: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Command::Admin(AdminCommand::Package { config, msi }) => {
            let saved = std::fs::read_to_string(&config)
                .map_err(|e| format!("{}: {e}", config.display()))
                .and_then(|text| admin::MsiFile::read(&msi).and_then(|m| admin::save(&config, &text, &m)));
            match saved {
                Ok(s) => {
                    println!("Wrote {} and {}.", s.package.display(), s.intunewin.display());
                    print_intune_app(&s.version);
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("sluse admin package: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Command::Admin(AdminCommand::MsiInfo { path }) => match sluse_admin::msi::info(&path) {
            Ok(m) => {
                println!("{}", serde_json::json!({ "productCode": m.product_code, "version": m.version }));
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sluse admin msi-info: {e}");
                ExitCode::from(1)
            }
        },
        Command::Image(ImageCommand::Fetch { dir }) => {
            let mut shown = 0;
            match image::fetch(&dir, None, |have, total| {
                let pct = (have * 100).checked_div(total).unwrap_or(0);
                if pct >= shown + 10 {
                    shown = pct;
                    println!("  {pct}%  ({} MB)", have >> 20);
                }
            }) {
                Ok(p) => {
                    println!("verified    {}", p.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("sluse image fetch: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Command::Image(ImageCommand::Vhd { from, to }) => match image::to_fixed_vhd(&from, &to, |_, _| {}) {
            Ok(()) => {
                println!("fixed VHD   {}", to.display());
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("sluse image vhd: {e}");
                ExitCode::from(1)
            }
        },
        Command::Box(BoxCommand::Reset { sid }) => cmd_box_action(sluse_proto::pipe::PipeRequest::Reset { sid: Some(sid) }),
        Command::Box(BoxCommand::Wipe { sid }) => cmd_box_action(sluse_proto::pipe::PipeRequest::Wipe { sid: Some(sid) }),
        Command::Box(BoxCommand::Adopt { sid, vm, address }) => {
            match boxes::save(&boxes::data_root(), &sid, &boxes::BoxRecord { vm, address, base: None, named: None }) {
                Ok(p) => {
                    println!("box         {}", p.display());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("sluse box adopt: {e}");
                    ExitCode::from(1)
                }
            }
        }
    }
}

#[cfg(windows)]
fn cmd_service() -> ExitCode {
    service::run()
}

/// Ask the service, as the administrator running this, and print its steps.
///
/// The pipe is opened at identification level: whoever answers can learn who
/// is asking, and cannot act as them, which matters when the asker is an
/// elevated administrator.
#[cfg(windows)]
fn cmd_box_action(req: sluse_proto::pipe::PipeRequest) -> ExitCode {
    use std::io::{BufRead, Write};
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT};

    let pipe = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .access_mode(crate::winsys::PIPE_CLIENT_ACCESS)
        .security_qos_flags(SECURITY_SQOS_PRESENT.0 | SECURITY_IDENTIFICATION.0)
        .open(sluse_proto::pipe::PIPE_NAME)
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sluse box: the service is not answering on {}: {e}", sluse_proto::pipe::PIPE_NAME);
            return ExitCode::from(1);
        }
    };
    let mut line = serde_json::to_vec(&req).expect("a request serialises");
    line.push(b'\n');
    if let Err(e) = (&pipe).write_all(&line) {
        eprintln!("sluse box: {e}");
        return ExitCode::from(1);
    }
    for l in std::io::BufReader::new(&pipe).lines().map_while(Result::ok) {
        match serde_json::from_str::<sluse_proto::pipe::PipeEvent>(&l) {
            Ok(sluse_proto::pipe::PipeEvent::Progress { step, .. }) => println!("  {step}"),
            Ok(sluse_proto::pipe::PipeEvent::Closed) => {
                println!("done; the box is closed, and opens on the new system disk");
                return ExitCode::SUCCESS;
            }
            Ok(sluse_proto::pipe::PipeEvent::Failed { message, .. }) => {
                eprintln!("sluse box: {message}");
                return ExitCode::from(1);
            }
            other => {
                eprintln!("sluse box: the service answered {other:?}");
                return ExitCode::from(1);
            }
        }
    }
    eprintln!("sluse box: the service closed the pipe without an answer");
    ExitCode::from(1)
}

#[cfg(not(windows))]
fn cmd_box_action(_: sluse_proto::pipe::PipeRequest) -> ExitCode {
    eprintln!("sluse box: Windows only; the service drives Hyper-V.");
    ExitCode::from(1)
}

/// The one Win32 app's settings (D-043), for a package of `version`.
fn print_intune_app(version: &str) {
    println!("Install command:   powershell.exe -NoProfile -ExecutionPolicy Bypass -File {}", admin::SCRIPT);
    println!("Uninstall command: powershell.exe -NoProfile -ExecutionPolicy Bypass -File {} -Uninstall", admin::SCRIPT);
    println!("Install behaviour: System. Device restart: based on return codes (3010 when Hyper-V needs it).");
    println!("Requirements:      64-bit, Windows 10 2004 or later.");
    println!("Detection rules: a custom detection rule; add both.");
    println!("  Rule 1, Registry");
    println!("    Key path:          HKEY_LOCAL_MACHINE\\SOFTWARE\\Sluse\\Deployment");
    println!("    Value name:        PackageVersion");
    println!("    Detection method:  String comparison");
    println!("    Operator:          Equals");
    println!("    Value:             {version}");
    println!("    Associated with a 32-bit app on 64-bit clients: No");
    println!("  Rule 2, File");
    println!("    Path:              {}      (the folder only)", admin::DETECT_DIR);
    println!("    File or folder:    {}", admin::DETECT_FILE);
    println!("    Detection method:  File or folder exists");
    println!("    Associated with a 32-bit app on 64-bit clients: No");
    println!("A device that runs another Sluse deployment refuses this one with exit code 2.");
}

fn cmd_admin_setup(o: admin::Options) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("sluse admin setup: {e}");
            return ExitCode::from(1);
        }
    };
    let result = rt.block_on(async {
        let http = reqwest::Client::new();
        let token = admin::sign_in(&http, &o, &mut |m| println!("{m}")).await?;
        admin::setup(&http, token, &o).await
    });
    match result {
        Ok(done) => {
            println!();
            println!("tenant      {}", done.tenant);
            println!("app         {} ({}, a public client)", done.gate_app, admin::GATE_NAME);
            if done.created.is_empty() {
                println!("changed     nothing new; the registrations were repaired to match");
            }
            for c in &done.created {
                println!("made        {c}");
            }
            println!();
            // Not the `/adminconsent` URL: it failed on L1 against apps that
            // already had consent (2026-09-30), and the portal shows each
            // permission's state, which a link does not.
            println!("Grant admin consent as a tenant admin:");
            println!("  portal.azure.com > Microsoft Entra ID > App registrations > {} > API permissions", admin::GATE_NAME);
            println!("  > \"Grant admin consent for <tenant>\". Every row should then say Granted.");
            println!("  https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/CallAnAPI/appId/{}", done.gate_app);
            println!("A rerun that adds a permission needs the grant again; one that changes nothing does not.");
            println!();
            println!("The package is {}: Sluse.msi, the config and the script. It holds no", done.package.display());
            println!("key, but names your sources and scopes. One Win32 app in Intune; wrap it with:");
            println!("  sluse admin intunewin --source \"{}\" --setup {} --out <file>.intunewin", done.package.display(), admin::SCRIPT);
            print_intune_app(&done.version);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sluse admin setup: {e}");
            ExitCode::from(1)
        }
    }
}

fn cmd_device(what: DeviceCommand) -> ExitCode {
    let service = match service::Service::new(boxes::data_root(), hyperv::HyperV::embedded()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("sluse device: {e}");
            return ExitCode::from(1);
        }
    };
    let result = match what {
        DeviceCommand::Init => service.device_network().and_then(|()| {
            if service.root.join("sluse.json").is_file() {
                service.ensure_certs().map(|()| "the device is ready")
            } else {
                Ok("the device's network is ready; its certificates are made once sluse.json is installed")
            }
        }),
        DeviceCommand::Remove => service.device_remove().map(|()| "removed: the boxes, the switch, the NAT, the rule, the data"),
        DeviceCommand::EventLog => service.event_log().map(|()| "the Sluse log is there, and only SYSTEM may write to it"),
    };
    match result {
        Ok(what) => {
            println!("{what}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("sluse device: {e}");
            ExitCode::from(1)
        }
    }
}

#[cfg(not(windows))]
fn cmd_service() -> ExitCode {
    eprintln!("sluse service: Windows only; the service drives Hyper-V.");
    ExitCode::from(1)
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

/// Run the preflight without starting anything.
///
/// The same code the Gate runs at start, so a `check` that passes and a Gate
/// that refuses to start would be a bug rather than a difference of opinion. The
/// one check this cannot answer is "gate reachable", which is a call from
/// outside the Gate; it is probed separately below and reported as its own
/// line rather than written into the snapshot, because the snapshot belongs to
/// whichever Gate is serving and this command is not one.
fn cmd_check(config: &Path) -> ExitCode {
    let loaded = match sluse_proto::config::load(config) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("config: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    let compiled = match sluse_gate_core::scope::compile(&loaded) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config: {e}");
            return ExitCode::from(EX_CONFIG);
        }
    };

    let cert_check = match sluse_gate_core::tls::server_config(&loaded) {
        Ok(t) => t.check,
        Err(e) => sluse_gate_core::tls::missing(&e),
    };
    let posture = sluse_gate_core::preflight::run(&loaded, cert_check);

    println!("box            {}", loaded.config.box_id);
    println!("environment    {:?}", loaded.config.environment);
    println!("config         {}", config.display());
    println!("config version {}", loaded.version);
    println!("posture        {}", posture.id);
    println!();

    for source in &compiled.sources {
        println!("source {}", source.name);
        if let Some(why) = &source.unavailable {
            println!("  unavailable: {why}");
        }
        for why in &source.dropped {
            println!("  scope dropped: {why}");
        }
        match source.root.as_ref() {
            Some(root) => println!("  root   {}", root.display()),
            None if source.unavailable.is_some() => {}
            // A library: no root to canonicalise at start, because it is
            // reachable only as the signed-in user, and there is none yet (M7).
            None => println!("  library {} (read as the signed-in user)", source.kind.address()),
        }
        for rel in source.remote.iter().flatten().map(|s| &s.rel) {
            println!("  scope  {}", sluse_gate_core::scope::request_form(source.name.as_str(), rel));
        }
        for scope in &source.scopes {
            println!(
                "  scope  {}",
                sluse_gate_core::scope::request_form(source.name.as_str(), &scope.rel)
            );
        }
    }
    println!();

    sluse_gate_core::preflight::print(&posture);

    // The required check the snapshot leaves unanswered. Reported here, outside the
    // two lists, so it cannot be mistaken for something this process decided.
    println!();
    match probe(&loaded) {
        Ok(status) => println!(
            "gate         reachable at {} — {}, up {}",
            loaded.config.gate.url,
            status.box_id,
            human(status.uptime_seconds)
        ),
        Err(e) => println!("gate         not reachable at {}: {e}", loaded.config.gate.url),
    }

    if posture.required_passed() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EX_CONFIG)
    }
}

// ---------------------------------------------------------------------------
// start
// ---------------------------------------------------------------------------

fn cmd_start(workspace: &Path, fixture: &Path, listen: &str, box_id: Option<&str>) -> ExitCode {
    // Canonical from here on: the state record is keyed on the workspace path
    // and `.\runs\one` and an absolute path must be one key.
    if let Err(e) = std::fs::create_dir_all(workspace) {
        eprintln!("sluse start: workspace {}: {e}", workspace.display());
        return ExitCode::from(1);
    }
    let workspace = match workspace.canonicalize().map(|p| run::plain(&p)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sluse start: workspace {}: {e}", workspace.display());
            return ExitCode::from(1);
        }
    };
    let fixture = match fixture.canonicalize().map(|p| run::plain(&p)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("sluse start: fixture {}: {e}", fixture.display());
            eprintln!("Generate one with tools\\fixture\\make-fixture.ps1 -Root <path>.");
            return ExitCode::from(1);
        }
    };

    // Refuse to start a second Gate over a live one. Not because two would
    // fail — the second would lose the port and say so — but because the state
    // record would then name whichever process wrote it last, and `stop` would
    // kill the wrong one.
    if let Some(existing) = state::load(&workspace) {
        if existing.alive() {
            eprintln!(
                "sluse start: a Gate is already running for this workspace (pid {}, up {}).",
                existing.pid,
                human(existing.started.signed_duration_since(chrono::Utc::now()).num_seconds().abs())
            );
            eprintln!("Stop it with `sluse stop --workspace {}`.", workspace.display());
            return ExitCode::from(1);
        }
    }

    let url = format!("https://{}", listen);
    let plan = run::Plan {
        workspace: workspace.clone(),
        fixture,
        box_id: box_id.unwrap_or("box-local-prototype").to_owned(),
        listen: listen.to_owned(),
        url: url.clone(),
    };

    let written = match run::lay_out(&plan) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("sluse start: {e}");
            return ExitCode::from(1);
        }
    };

    println!("workspace   {}", workspace.display());
    println!("fixture     {}", plan.fixture.display());
    println!(
        "certs       {}",
        if written.certs_generated { "generated" } else { "kept (already present)" }
    );
    println!("pin         {}", written.pin.as_str());

    let loaded = match sluse_proto::config::load(&written.config) {
        Ok(l) => l,
        Err(e) => {
            // The config this process just wrote does not load. That is a bug in
            // the generator, not in the user's input, and it is worth saying so.
            eprintln!("sluse start: the generated config does not load: {e}");
            eprintln!("This is a bug in `sluse start`, not in anything you typed.");
            return ExitCode::from(EX_CONFIG);
        }
    };
    println!("config      {} ({})", written.config.display(), loaded.version);
    println!("mcp         {}", written.mcp_json.display());

    let gate = match run::gate_binary() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sluse start: {e}");
            return ExitCode::from(1);
        }
    };

    let log = state::log_path(&workspace);
    if let Some(parent) = log.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!("sluse start: log directory {}: {e}", parent.display());
            return ExitCode::from(1);
        }
    }

    let mut child = match spawn_gate(&gate, &written.config, &log, &[]) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sluse start: {} : {e}", gate.display());
            return ExitCode::from(1);
        }
    };

    let pid = child.id();
    println!("gate      pid {pid}, log {}", log.display());
    print!("waiting     ");
    let _ = std::io::Write::flush(&mut std::io::stdout());

    match wait_until_serving(&loaded, &mut child) {
        Ok(status) => {
            println!("serving as {}", status.user.display());
            let created = state::created_of(pid).unwrap_or(0);
            let record = state::Run {
                box_id: loaded.config.box_id.to_string(),
                workspace: workspace.clone(),
                config: written.config.clone(),
                url,
                listen: listen.to_owned(),
                pid,
                pid_created: created,
                started: chrono::Utc::now(),
                log,
            };
            if let Err(e) = state::save(&record) {
                // The Gate is up. Saying so and warning is better than
                // stopping it over a file in the state directory.
                eprintln!();
                eprintln!("sluse start: the Gate is running but its record could not be");
                eprintln!("written ({e}). `sluse stop` will not find it; kill pid {pid} by hand.");
            }
            println!();
            println!("posture     {}", status.posture_id);
            println!("sessions    {}", status.sessions);
            println!();
            println!("Start the agent with:");
            println!("  {}", written.launch.display());
            println!();
            println!("The task is {}.", written.task.display());
            println!("Stop with `sluse stop --workspace {}`.", workspace.display());
            ExitCode::SUCCESS
        }
        Err(why) => {
            println!();
            eprintln!("sluse start: {why}");
            eprintln!("The Gate's own output is in {}.", state::log_path(&workspace).display());
            // Leave nothing half-started behind.
            let _ = child.kill();
            let _ = child.wait();
            ExitCode::from(EX_CONFIG)
        }
    }
}

/// Start the Gate detached, with its stderr in the log.
///
/// Detached on purpose: the Gate outlives the terminal `sluse start` was typed
/// in, because the next thing a person does is open another one and run Claude
/// Code. `CREATE_NEW_PROCESS_GROUP` keeps a Ctrl-C in that first terminal from
/// reaching it for the same reason.
#[cfg(windows)]
fn spawn_gate(
    gate: &Path,
    config: &Path,
    log: &Path,
    env: &[(&str, &str)],
) -> std::io::Result<std::process::Child> {
    use std::os::windows::process::CommandExt;

    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

    let out = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
    let err = out.try_clone()?;

    std::process::Command::new(gate)
        .arg("--config")
        .arg(config)
        .arg("--serve")
        .envs(env.iter().copied())
        // The control channel (D-036): the service writes sign-ins here.
        .stdin(std::process::Stdio::piped())
        .stdout(out)
        .stderr(err)
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
}

#[cfg(not(windows))]
fn spawn_gate(
    gate: &Path,
    config: &Path,
    log: &Path,
    env: &[(&str, &str)],
) -> std::io::Result<std::process::Child> {
    let out = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
    let err = out.try_clone()?;
    std::process::Command::new(gate)
        .arg("--config")
        .arg(config)
        .arg("--serve")
        .envs(env.iter().copied())
        // The control channel (D-036): the service writes sign-ins here.
        .stdin(std::process::Stdio::piped())
        .stdout(out)
        .stderr(err)
        .spawn()
}

/// Poll `/v1/status` until the Gate answers, it exits, or the wait runs out.
///
/// This is the "gate reachable" required check, run from outside the Gate, which
/// is the only place it can be run from. It uses the same pinned client the
/// guest uses, so a Gate that answers here is a Gate the endpoint can reach
/// — and a pin that does not match fails here rather than at the agent's first
/// tool call.
fn wait_until_serving(
    loaded: &sluse_proto::Loaded,
    child: &mut std::process::Child,
) -> Result<sluse_proto::Status, String> {
    let deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(START_TIMEOUT_SECONDS);
    // The last transport error, so a timeout says what it kept failing on
    // rather than only that it ran out of time.
    let mut last;

    loop {
        // A Gate that has exited will never answer, and the reason is in the
        // log rather than in the next timeout.
        if let Ok(Some(code)) = child.try_wait() {
            return Err(format!(
                "the Gate exited before it began serving ({code}); its log says why"
            ));
        }

        match probe(loaded) {
            Ok(status) => return Ok(status),
            Err(e) => last = e,
        }

        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "the Gate did not answer {} within {START_TIMEOUT_SECONDS} s: {last}",
                loaded.config.gate.url
            ));
        }
        print!(".");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

// ---------------------------------------------------------------------------
// stop
// ---------------------------------------------------------------------------

fn cmd_stop(workspace: &Path, reset: bool) -> ExitCode {
    let workspace = workspace.canonicalize().map(|p| run::plain(&p)).unwrap_or_else(|_| workspace.to_path_buf());

    let Some(record) = state::load(&workspace) else {
        eprintln!("sluse stop: no run recorded for {}.", workspace.display());
        eprintln!("`sluse status` lists what this machine knows about.");
        return ExitCode::from(1);
    };

    match state::terminate(&record) {
        Ok(true) => println!("stopped pid {} ({})", record.pid, record.box_id),
        Ok(false) => println!(
            "pid {} was not running; forgetting the record for {}",
            record.pid,
            workspace.display()
        ),
        Err(e) => {
            eprintln!("sluse stop: pid {}: {e}", record.pid);
            return ExitCode::from(1);
        }
    }

    if let Err(e) = state::forget(&workspace) {
        eprintln!("sluse stop: the Gate is stopped but its record remains ({e}).");
    }

    // The session outlives the Gate unless a person says otherwise. M3 decided
    // the run owns it: restarting in the same workspace rejoins, keeps the same
    // journal file, and keeps accumulating lineage.
    if reset {
        match reset_session(&record.config) {
            Ok(Some(path)) => {
                println!("forgot the session ({}).", path.display());
                println!("The next `sluse start` here is a new run: new session, new journal.");
            }
            Ok(None) => println!("there was no session to forget."),
            Err(e) => {
                eprintln!("sluse stop: the session file could not be removed: {e}");
                return ExitCode::from(1);
            }
        }
    } else {
        println!();
        println!("The session is kept. Starting again here rejoins it and appends to the");
        println!("same journal; `sluse stop --reset` is how you say you meant a new run.");
    }

    ExitCode::SUCCESS
}

/// Remove the run's session file, if the config still names a workspace.
fn reset_session(config: &Path) -> std::io::Result<Option<PathBuf>> {
    let loaded = match sluse_proto::config::load(config) {
        Ok(l) => l,
        // The config is gone. Nothing to resolve the session path against, and
        // the session file went with it.
        Err(_) => return Ok(None),
    };
    let guest_workspace = loaded.resolve(&loaded.config.workspace);
    let path = sluse_endpoint::session::state_path(&guest_workspace);
    if !path.exists() {
        return Ok(None);
    }
    sluse_endpoint::session::clear(&guest_workspace)?;
    Ok(Some(path))
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

fn cmd_status(workspace: Option<&Path>) -> ExitCode {
    let runs = match workspace {
        Some(w) => {
            let w = w.canonicalize().map(|p| run::plain(&p)).unwrap_or_else(|_| w.to_path_buf());
            match state::load(&w) {
                Some(r) => vec![r],
                None => {
                    println!("no run recorded for {}", w.display());
                    return ExitCode::SUCCESS;
                }
            }
        }
        None => state::all(),
    };

    if runs.is_empty() {
        println!("nothing recorded in {}", state::runs_dir().display());
        return ExitCode::SUCCESS;
    }

    for (i, run) in runs.iter().enumerate() {
        if i > 0 {
            println!();
        }
        println!("{}", run.workspace.display());
        println!("  box        {}", run.box_id);
        println!("  url        {}", run.url);
        println!("  log        {}", run.log.display());

        match run.uptime() {
            None => {
                // The record says a Gate; the machine says no such process, or
                // a different one wearing its pid. Either way this is not it.
                println!("  process    not running (pid {} is gone or is not it)", run.pid);
                println!("  gate     —");
                println!();
                println!("  `sluse stop --workspace {}` clears the record.", run.workspace.display());
                continue;
            }
            Some(up) => println!("  process    pid {}, up {}", run.pid, human(up.num_seconds())),
        }

        // A live process is not a serving Gate. Asked rather than assumed, and
        // asked without minting a session: `/v1/status` exists for this.
        match sluse_proto::config::load(&run.config) {
            Err(e) => println!("  gate     cannot ask: the config no longer loads ({e})"),
            Ok(loaded) => match probe(&loaded) {
                Ok(s) => {
                    println!(
                        "  gate     serving as {}, {} session(s), up {}",
                        s.user.display(),
                        s.sessions,
                        human(s.uptime_seconds)
                    );
                    println!("  posture    {}", s.posture_id);
                    println!("  config     {}", s.config_version);
                }
                Err(e) => println!("  gate     the process is up but is not answering: {e}"),
            },
        }
    }

    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// devcert
// ---------------------------------------------------------------------------

fn cmd_devcert(out: &Path, hostnames: &[String], config: Option<&Path>) -> ExitCode {
    let certs = match devcert::generate(hostnames) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("sluse devcert: {e}");
            return ExitCode::from(1);
        }
    };

    let written = match devcert::write(out, &certs) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("sluse devcert: {e}");
            return ExitCode::from(1);
        }
    };

    println!("Wrote {} files to {}:", written.len(), out.display());
    for p in &written {
        println!("  {}", p.file_name().unwrap_or_default().to_string_lossy());
    }
    println!();
    println!("  gate.certPin  {}", certs.pin.as_str());
    println!();

    match config {
        None => {
            // Said every time, because the pin is useless until it is in the
            // config and a person who assumed otherwise finds out at the first
            // handshake.
            println!("The config was not touched. Put the pin in `gate.certPin` of its device half");
            println!("yourself, or re-run with --update-config <path>.");
        }
        Some(path) => match devcert::update_config(&sluse_proto::config::device_path(path), &certs.pin) {
            Ok(_) => {
                println!("Wrote the pin into {}.", sluse_proto::config::device_path(path).display());
                println!("config_version is unchanged: it is the hash of the authored file alone.");
            }
            Err(e) => {
                eprintln!("sluse devcert: {e}");
                eprintln!("The certificates were written; the config was not changed.");
                return ExitCode::from(EX_CONFIG);
            }
        },
    }

    ExitCode::SUCCESS
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

/// One `/v1/status` call, on a runtime built for it and thrown away.
///
/// A fresh runtime per probe is wasteful and this is a CLI that makes at most a
/// handful of calls in its life. The alternative — one runtime built in `main`
/// for the sake of the two commands that might use it — costs more to read than
/// it saves.
fn probe(loaded: &sluse_proto::Loaded) -> Result<sluse_proto::Status, String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("no runtime: {e}"))?;
    runtime
        .block_on(sluse_endpoint::gate_client::status(loaded))
        .map_err(|e| e.to_string())
}

/// Seconds as something a person reads without counting zeroes.
fn human(seconds: i64) -> String {
    match seconds {
        s if s < 0 => "just now".to_owned(),
        s if s < 90 => format!("{s} s"),
        s if s < 3600 => format!("{} min", s / 60),
        s => format!("{} h {} min", s / 3600, (s % 3600) / 60),
    }
}

#[cfg(test)]
mod tests {
    /// D-023: the device init sets the Sluse log's descriptor, and the
    /// Gate's posture checks it; the two spell it the same.
    #[test]
    fn the_sluse_logs_descriptor_is_the_gates() {
        assert!(include_str!("../../../packaging/box/sluse-box.ps1").contains(sluse_gate_core::audit::AUDIT_SDDL));
    }

    /// D-029: the box's scripts, the shell's CSP and the config examples spell
    /// the ports that `sluse_proto::ports` defines, and no old port is left in
    /// anything that ships.
    #[test]
    fn ports_agree() {
        use sluse_proto::ports::{GATE, CONSOLE, PROXY, VNC};
        let files = [
            ("vnc.nft", include_str!("../../../packaging/box/kiosk/vnc.nft")),
            ("sluse-bootstrap", include_str!("../../../packaging/box/kiosk/sluse-bootstrap")),
            ("browser", include_str!("../../../packaging/box/kiosk/browser")),
            ("tauri.conf.json", include_str!("../../../ui/shell/src-tauri/tauri.conf.json")),
            ("local.example.json", include_str!("../../../config/local.example.device.json")),
            ("sluse-box.ps1", include_str!("../../../packaging/box/sluse-box.ps1")),
            ("user-data.yaml", include_str!("../../../packaging/box/user-data.yaml")),
            ("policies.json", include_str!("../../../packaging/box/kiosk/policies.json")),
        ];
        let text = |name: &str| files.iter().find(|(n, _)| *n == name).unwrap().1;
        assert!(text("vnc.nft").contains(&format!("tcp dport {VNC} ip saddr 192.168.77.1 accept")));
        assert!(text("vnc.nft").contains(&format!("tcp dport {VNC} drop")));
        assert!(text("sluse-bootstrap").contains(&format!("port={VNC}")));
        assert!(text("browser").matches(&format!("http://localhost:{CONSOLE}/")).count() == 2);
        assert!(text("tauri.conf.json").contains(&format!("ws://*:{VNC}")));
        assert!(text("local.example.json").contains(&format!("127.0.0.1:{GATE}")));
        assert!(text("local.example.json").contains(&format!("127.0.0.1:{CONSOLE}")));
        // The box's proxy settings (M9): apt's two, four each in the
        // environment, profile.d and systemd's, snapd's two; and the browser's.
        assert_eq!(text("user-data.yaml").matches(&format!("http://192.168.77.1:{PROXY}")).count(), 16);
        assert!(text("policies.json").contains(&format!("\"192.168.77.1:{PROXY}\"")));
        for (name, body) in files {
            for old in ["7443", "7444", "7480", "5900"] {
                assert!(!body.contains(old), "{name} still says {old}");
            }
        }
    }

    use super::*;

    #[test]
    fn durations_read_as_durations() {
        assert_eq!(human(0), "0 s");
        assert_eq!(human(89), "89 s");
        assert_eq!(human(90), "1 min");
        assert_eq!(human(3599), "59 min");
        assert_eq!(human(3600), "1 h 0 min");
        // Past an hour it says hours, rather than "62 min".
        assert_eq!(human(3700), "1 h 1 min");
        // Clock skew between the record and now is not an error worth a panic.
        assert_eq!(human(-5), "just now");
    }

    /// The CLI's own shape, so a rename or a lost argument fails here rather
    /// than in a smoke run somebody has already started.
    #[test]
    fn the_commands_parse() {
        use clap::CommandFactory;
        Cli::command().debug_assert();

        let cli = Cli::parse_from(["sluse", "start", "--workspace", "w", "--fixture", "f"]);
        match cli.command {
            Command::Start { workspace, fixture, listen, box_id } => {
                assert_eq!(workspace, PathBuf::from("w"));
                assert_eq!(fixture, PathBuf::from("f"));
                assert_eq!(listen, "127.0.0.1:7580");
                assert!(box_id.is_none());
            }
            _ => panic!("start did not parse as start"),
        }

        // D-019 removed the mode flag. A script that still passes it must fail
        // loudly rather than start a run whose name says something the config
        // does not.
        assert!(
            Cli::try_parse_from(["sluse", "start", "--workspace", "w", "--fixture", "f", "--fetch", "off"])
                .is_err(),
            "--fetch is gone and is not silently ignored"
        );

        // `stop` defaults to here, so a person standing in the run workspace
        // types four words.
        let cli = Cli::parse_from(["sluse", "stop"]);
        match cli.command {
            Command::Stop { workspace, reset } => {
                assert_eq!(workspace, PathBuf::from("."));
                assert!(!reset, "the session survives a stop unless --reset is typed");
            }
            _ => panic!("stop did not parse as stop"),
        }

        // `status` with no workspace is the machine-wide question.
        let cli = Cli::parse_from(["sluse", "status"]);
        match cli.command {
            Command::Status { workspace } => assert!(workspace.is_none()),
            _ => panic!("status did not parse as status"),
        }
    }
}

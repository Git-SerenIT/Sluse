# Contributing

Issues and pull requests are welcome. For anything that changes a claim, an
invariant or the design, open an issue first: those are decided by the
project's owners, SerenIT ApS and Prompted EV. By Apache-2.0 §5, a
contribution is licensed under the same licence as the project.

## Build and test

```sh
cargo build --workspace
cargo test  --workspace
cargo clippy --workspace --all-targets -- -D warnings
npm --prefix ui/console ci && npm --prefix ui/console run check
```

The MSRV is `rust-version` in the root `Cargo.toml`, measured from the
locked dependency graph. A change to the dependencies re-derives it. The
host shell, `ui/shell`, is its own Cargo workspace with its own, higher
`rust-version` (Tauri).

**On Ubuntu** (`aws-lc-sys` compiles C):

```sh
sudo apt install -y build-essential cmake pkg-config libclang-dev cifs-utils rustup
```

**Windows binaries and the MSI come from CI.** Development happens on Linux;
the Windows jobs build, test and package, then install the MSI on the
runner, run the acceptance script against a fixture with real NTFS
permissions, and uninstall it. Some behaviour exists only on Windows
(junctions, UNC paths, ACLs, case-folding): its tests are `#[cfg(windows)]`
and run only there. **A green Linux run proves nothing about it.**

## Layout

| Path | What | Runs |
|---|---|---|
| `crates/sluse-proto` | The shared contract: config schema, capability request and response, journal record, errors | both sides |
| `crates/sluse-broker` | Scope enforcement (`scope.rs`), sources read as the person, the mTLS listener, the egress proxy, the Event Log | host, SYSTEM |
| `crates/sluse-endpoint` | The MCP server the agent talks to, the journal, the envelope, the console's API | the box |
| `crates/sluse-lifecycle` | `sluse check / start / stop / status`, the lifecycle service, the box's image build | host, SYSTEM |
| `crates/sluse-admin` | Setup: the Entra registration, sources and egress, the deployment package, Intune | the admin's PC |
| `ui/shell` | The host shell and Sluse Admin (`--admin`): Tauri 2 and noVNC | host, as the person |
| `ui/console` | The console in the box: TypeScript, no framework | the box |
| `packaging/` | The MSI (WiX), the install and acceptance scripts; `packaging/box/` holds the box's side | host, the box |
| `config/` | The config schema, generated from `sluse-proto`; a test fails if it is stale | |
| `tools/` | The fixture generator and run scorers | |

## Conventions

- **Write the claim and its limit together.** Sluse claims authorised
  inputs with recorded provenance; never describe it as validating data or
  preventing exfiltration. A known gap is written down as a gap. The claims
  and channels are in [SECURITY.md](SECURITY.md).
- **The invariants are assertions.** A change that breaks one is wrong,
  however convenient ([SECURITY.md](SECURITY.md#invariants)).
- **Numbers are measured, not carried.** A timing, count or threshold quoted
  in a doc or a message comes from a run, not from an older paragraph.
- **`D-NNN` and `Q-N` in comments** cite the project's internal decision log
  and open questions. They explain why code is the way it is; the log
  itself is not published.

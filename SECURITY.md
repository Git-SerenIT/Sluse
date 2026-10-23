# Security

**Sluse's claim is authorised inputs with recorded provenance.** It is not a
data validator, and it does not prevent exfiltration. This page says what
is claimed, what is not, and every way out of the box we know of.

## Reporting a vulnerability

Use **Report a vulnerability** on this repository's Security tab (GitHub's
private reporting). Please do not open a public issue for it. There is no
release yet; reports are taken against `main`.

A known channel listed below is not a vulnerability. A way past one of the
claims, or a channel missing from the list, is.

## Whom it defends against

**Sluse contains the agent, not the user.** The inside of the box is
assumed hostile: the agent may be prompt-injected, over-eager, or running
as root.

| Adversary | Posture | What holds |
|---|---|---|
| The agent: over-collection, prompt injection, unintended action | Preventive on scope, detective on volume | It cannot reach a source except through the broker, and never beyond the person's own access. **It can read everything inside its scope.** |
| The user: deliberate misuse | Detective | A tamper-evident record, not a tamper-proof one. A determined insider, or an administrator, can defeat it. |

## What is claimed, and what is not

| Against the agent | Against the user | Not claimed |
|---|---|---|
| Admission scope, preventive: the broker checks every path, and the source's permissions have the last word | An audit trail, tamper-evident | Prevention of exfiltration through the AI provider: the agent can send everything in scope into its conversation |
| Admission volume, **detective only**: bulk admission raises an alert | Provenance for each published artifact: the sources the agent declares, each checked against what it was given | Output from an injected agent that a person then copies or pastes |
| Network confinement: no route, no DNS, only the listed hosts through a proxy on the host | An inventory of the material Sluse admitted, not of copies something else made | Aggregation risk: what many files together reveal |
| A single write path out, into Sluse Artifacts on the host | | Data correctness |
| | | A record of what the agent *attempted*: refusals inside the agent's own client never reach Sluse |
| | | Keeping admitted files from staying in the box |
| | | A clean box at the start of a session: what an agent changed can persist until a reset or wipe |
| | | An envelope on a file the agent reads directly from disk |
| | | Which AI provider account the box is signed in to |

## Invariants

Assertions the design holds to. A change that breaks one is a bug.

1. **No filesystem mounts in either direction.** The endpoint is the only
   way file content crosses into the box. The clipboard is a separate,
   known channel.
2. **The box cannot assert its own scope.** Scope comes from the admin's
   config and is checked by the broker, outside the box.
3. **No durable credential for company data exists in the box.** The
   person's tokens live in the broker on the host, in memory. What does
   live in the box: the AI runtime's own sign-in, and the box's mTLS
   certificate, which identifies the box, not a person.
4. **Admission is the control point, not residence.** Once given and
   recorded, a file may live on the box's disk.
5. **A file read through `sluse_read` is enveloped**, wherever it came
   from. A file the agent reads straight from disk is not, and cannot be
   made to be.
6. **No valid config, nothing runs.** Absent, invalid or of an unknown
   schema version.
7. **Audit is uniform.** Every admission is hashed from the bytes received,
   on both sides.
8. **The box's authority never exceeds the person's own.** Structural: the
   broker acts as the person.

**Where scope is checked.** The endpoint in the box checks it too, but only
as advice: it is inside the hostile zone. Its job is to keep what is out of
scope absent from the agent's view, so there is nothing to route around.
The broker on the host is the enforcing check, and the source's own
permissions are final.

**The untrusted-data envelope** wraps every `sluse_read`: a per-read random
delimiter the content cannot forge, a header naming the file and its hash,
and an instruction to report embedded instructions as a finding. It is
probabilistic: whether a model honours it is the model's behaviour, and it
is **unmeasured**. No adherence figure is claimed.

## Known channels

Written down as channels, not as mitigations. Each is open in v0.1.

**Ways out of the box**
- **The inference channel.** Anything in scope can go to the AI provider.
  Provider-side web search runs over it too. Detective only, by volume.
- **Every host on the egress list.** The proxy sees a host, never a path or
  the bytes, so a listed host that takes uploads is a way out. The AI
  providers are on by default; npm and GitHub take uploads and are off by
  default. Allowed traffic is recorded only when IT turns on the egress
  log, and never its content.
- **The clipboard** carries text both ways, unrecorded. Copying out can be
  switched off; retyping and photographing the screen cannot. While it is
  on, the box can also replace what is on the host's clipboard at any time.
- **The AI provider's account.** Conversations are kept there and readable
  from any device signed in to it. Claude in Chrome, and connectors that
  read company data from the provider's side (Microsoft 365, Google Drive,
  custom remote MCP), reach data around Sluse with no record here. The
  guide says to turn them off; Sluse cannot enforce or check that.
- **Injection-driven output a person pastes.** A published artifact carries
  provenance; text copied out of it, or out of the box, carries none.

**Around the records**
- **A direct read of a fetched file** gets no envelope and leaves no record.
  Computing on fetched bytes (a spreadsheet in pandas) is always this path.
- **Admitted files can move.** The agent can copy or move them anywhere in
  the box, unrecorded. The admission's record and the publish lineage hold;
  the inventory shows the file missing, not where it went. Only Wipe
  removes everything.
- **The box's certificate is readable by the agent.** Used directly against
  the broker, it has the endpoint's authority and no more: same scope, same
  person, recorded on the host. It skips the box's journal and the envelope.
- **The console's API in the box is unauthenticated.** Anything in the box
  can sign the person out, clear the workspace or open an app, and read each
  source's address. None widens what can be read.
- **An artifact's sources are the agent's word.** Sluse checks each one was
  admitted in that session, not that it was used, nor that an undeclared one
  was not.

**On the host**
- **Runnable content in Sluse Artifacts.** App Control, where the admin
  deploys it, blocks executables there on Windows 11; scripts run if the
  person starts them, and a copy moved elsewhere carries only the mark of
  the web.
- **Sluse's client id is public.** Any process running as the person on the
  host can get a token under Sluse's consented scopes: no more than the
  person can reach, but a pre-consented app for malware on the host.
- **The box's screen crosses the host-only network unencrypted**, keystrokes
  included. Reading it needs administrator rights on the host. The VNC
  secret, new at every open, guards the port, and is readable inside the box.
- **The box's diagnostic log** can be read by another person signed in to
  the same PC at the same time, for that session.
- **The `sluse:` link** can be followed by any page or program. It only
  opens Sluse's window, its Close confirm or Sluse Artifacts.
- **The tenant package** names the tenant's sources and scopes; copies of it
  in transit are not protected by Sluse.

## Not yet proven

Built, and not yet run on a device:
- that the Sluse log accepts writes from SYSTEM only (an administrator can
  change it either way);
- the App Control policy on Sluse Artifacts;
- whether Conditional Access cuts off a device when the broker refreshes the
  person's token as SYSTEM;
- Codex and Mistral Vibe, which are installed and wired like the other
  runtimes and not checked. Vibe uses Mistral's EU endpoint; where Mistral
  processes and keeps what it is sent is Mistral's term, not Sluse's claim.

## Out of scope

Positions, not omissions:
- Write-back to any source.
- Unattended operation: no signed-in person, no reads.
- Several people sharing one PC at the same time.
- Human-driven exfiltration.
- Model output constraint.
- Revoking copies already in a box.
- Reading files a sensitivity label encrypts: they arrive encrypted and stay
  unreadable. To keep a document from an agent, encrypt it.
- macOS and Linux workstations.

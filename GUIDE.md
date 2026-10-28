# Using Sluse

For two readers: **the IT administrator** who sets Sluse up and watches it,
and **the person** who works in it. Each part says which.

- [What Sluse is, and is not](#what-sluse-is-and-is-not)
- [What you need](#what-you-need) (IT)
- [Setting it up](#setting-it-up) (IT)
- [What to put in reach](#what-to-put-in-reach) (IT)
- [Working in Sluse](#working-in-sluse) (the person)
- [What IT sees](#what-it-sees) (IT)
- [Known edges](#known-edges) (both)
- [Telling us what happened](#telling-us-what-happened) (both)

## What Sluse is, and is not

Sluse runs an AI agent in a **box**, a Linux virtual machine on the
person's own Windows PC, with no access of its own to company data. Sluse,
outside the box, hands it files one at a time, as that person, from the
places IT allowed, and records each one. What the agent produces leaves the
box one way, into a directory on the PC called **Sluse Artifacts**, with a
record of what it was made from.

**What it claims: authorised inputs with recorded provenance.** Every file
the agent got was one IT allowed and the person could open, and it is
recorded. Every document the agent published carries the files the agent
says it used, each checked to be one it was given, beside every file it was
given in that session. Which ones it really used is the agent's word.

**What it does not claim** (the full list is in [SECURITY.md](SECURITY.md)):
- **It does not prevent data leaving.** The agent talks to its AI provider,
  and anything it was given can go into that conversation. The box's
  network reaches only the hosts the configuration lists, and each of them
  is a way out for what the box sends it.
- It does not check that the agent's work is correct, or that a document
  it was given did not try to steer it.
- It does not keep files from staying in the box once given. They stay
  until the person clears them or wipes the box; Reset keeps them.
- It cannot see which account of the AI provider the box is signed in to.

## What you need

**Each PC:**
- Windows 11 Pro, Enterprise or Education (no Home), 64-bit, with
  virtualisation on in the firmware. The installer turns on Hyper-V and
  Intune restarts the PC once.
- Managed by Intune and **Entra-joined**, one person per PC, 16 GB of
  memory or more. Hybrid-joined PCs are expected to work and are untested.
- The person is not a local administrator and not in Hyper-V
  Administrators. Sluse records both as posture.
- Room for the box: it takes 6 GB of memory while open, with 4 virtual
  processors on a PC with 8 or more, and keeps its files on a disk of its
  own, 40 GB by default.

**The tenant:**
- Entra ID and Intune. SharePoint or OneDrive licences for what you put in
  reach.
- Someone with the roles for each step. Sluse Admin says which you hold
  and who else is needed:

  | Step | Roles |
  |---|---|
  | Make Sluse's app registration | Application Administrator, Cloud Application Administrator or Global Administrator |
  | Grant admin consent | one of those, or Privileged Role Administrator |
  | Publish straight to Intune | Intune Administrator or Global Administrator. Saving a `.intunewin` file needs neither |

- **Recommended:** Conditional Access requiring a compliant device on
  Sluse's app. Whether it cuts off a box already open on a PC that falls
  out of compliance is not yet measured.

**The AI runtimes:** company seats for the runtimes in the box (Claude
Desktop, Claude Code, ChatGPT, Codex, Mistral Vibe). Each is signed in once
inside the box. ChatGPT is OpenAI's Linux preview, about 1.7 GB of the
box's system, and comes with the Codex group. Mistral Vibe needs its egress group ticked, which is off by
default, and an organisation account whose inputs Mistral does not train
on: check the plan, since some train by default. Turn
**Claude in Chrome off** for those accounts in the provider's admin
console: it would let the agent drive a browser elsewhere, outside every
record. Turn off, too, every connector that reads company data from the
provider's side: Microsoft 365, Google Drive, and any custom remote MCP
connector. They reach files around Sluse, outside the folders you picked,
and nothing records it. **Sluse Admin reads whether the Microsoft 365 ones
are open in your tenant** (Tenant, "The AI providers' own connectors"):
Claude's two Microsoft 365 apps, and ChatGPT's app once it is in the
tenant, with their consent and whether users may consent for themselves.
It offers to turn an app's sign-in off in Entra, which stops that
connector for everyone; it changes nothing unless you choose it. A
connector a user adds to a personal account involves no app of yours, and
it cannot see that.

## Setting it up

All of it in **Sluse Admin**, on the administrator's own PC (install
`Sluse.msi` and tick "Sluse Admin"). It never needs to run on a user's PC.
`Sluse.msi` is on the repository's Releases page, with a `SHA256SUMS` to
check it against (`Get-FileHash Sluse.msi`); it is not signed yet.

1. **Sign in** as the tenant administrator. Microsoft's consent page asks
   for what setup does as you. **Leave "Consent on behalf of your
   organization" unticked**: ticked, it grants those permissions to
   Microsoft's tool for everyone in the tenant.
2. **Tenant:** Sluse Admin makes one app registration, "Sluse Gate". It
   has no secret and no certificate, and reads only: Graph's
   `Files.Read.All` and `Sites.Read.All`, delegated, and the delegated
   scope of each tool server you add, so it can never reach more than the
   signed-in person can. Grant admin consent in the portal
   (the link is shown), then pick the group of people who may sign in.
3. **Sources:** what the agent may read, below.
4. **Egress:** which groups of hosts the box may reach (the AI providers,
   package registries), each saying whether it also accepts uploads.
5. **Advanced:** the volume alert, the largest fetch, the box's memory and
   disk, copying text out, the egress log.
6. **Review:** what the box would refuse, the warnings, what changed.
7. **Publish:** pick `Sluse.msi`; save the configuration and publish it to
   Intune for a device group, or save a `.intunewin` to upload by hand.

**Keep the saved `.json`.** To change anything later, open it on the first
screen and publish again: each publish is a new revision, and Intune
replaces the last. A revision that changes only the configuration does not
reinstall Sluse. Devices pick it up on Intune's own schedule, usually within
the hour, sometimes longer; the box reads it the next time it opens.

### Blocking programs in Sluse Artifacts

Sluse never installs a device-wide code-integrity policy by itself; you
deploy it. Without it, a program the agent publishes can be run from Sluse
Artifacts, and Sluse's posture check says so at each open.

The policy ships with Sluse, in `C:\Program Files\Sluse\intune\`: an App
Control for Business base policy that allows everything and denies
`%OSDRIVE%\Users\*\Sluse Artifacts\*`, id
`{3CA83446-6F47-4A65-9891-2685B75CD7E3}`. Deploy either:
- Intune > Endpoint security > App control for business > Create policy,
  and upload `sluse-artifacts-deny.xml`; or
- a custom profile, OMA-URI
  `./Vendor/MSFT/ApplicationControl/Policies/3CA83446-6F47-4A65-9891-2685B75CD7E3/Policy`,
  Base64 (file), with the `.cip` renamed to `.bin`.

It blocks `.exe`, `.com`, `.dll` and `.msi` there, on Windows 11 only.
Scripts (`.ps1`, `.vbs`, `.js`, `.bat`, `.cmd`) are not blocked, because
that would put every user's PowerShell in Constrained Language Mode. A copy
the person moves elsewhere carries only the mark of the web. Built, not yet
run on a device.

## What to put in reach

Each source has a name the agent sees and a sensitivity you choose.

| Source | What the agent reaches | Read as |
|---|---|---|
| **SharePoint or Teams library** | The folders you pick in it (the scope). With none picked, the whole library | the person, through their Entra sign-in |
| **SMB share** | The folders you pick on a `\\server\share` | the person's Windows logon |
| **The person's OneDrive `Sluse` folder** | Only that folder, at the top of their OneDrive | the person, through their Entra sign-in |
| **Sluse Inputs** | A folder on the PC, `C:\Users\<person>\Sluse Inputs` | the person's Windows logon |
| **Tool server (MCP)** | The tools you tick on a remote MCP server, below | the person, through their Entra sign-in, as far as the server goes |

**Scope is enforced outside the box.** Sluse refuses anything outside the
folders you picked, and the source's own permissions have the last word: a
file the person cannot open, the agent cannot get.

**OneDrive and Sluse Inputs are filled by the person,** with anything they
can open. Sluse Admin warns about it. A file from Sluse Inputs is recorded
as coming from that PC and nothing more, so it is off unless you add it.
Shortcuts in OneDrive ("Add shortcut to My files") are out of reach: a
shortcut to a folder is not shown to the agent at all, and a shortcut to a
file is read as the link it is, never as the file it points to.

### Tool servers

A tool server is a remote MCP server that the agent calls through Sluse,
as the person. **Built, not yet run on a device.** It must:
- answer MCP over HTTPS, in version 2025-11-25 or 2026-07-28;
- accept an Entra token for a delegated scope of its own app registration,
  in your tenant. A server with its own sign-in or an API key cannot be
  added.

The box never reaches the server: Sluse on the PC calls it, so it needs no
Egress entry. To build one of your own, copy
[`examples/mcp-reference-server/`](examples/mcp-reference-server/), an
Azure Functions server that reads Microsoft Graph as the person.

**Adding one:** Sources, Add a source, **Tool server**. Give its address
and the permission Sluse asks for: the server's app (its ID URI or app id)
and the permission's name, for example `api://<app>/user_impersonation`.
Not sure of the name? Type the app alone and **List its permissions**,
then pick one that only reads. A vendor's app that is not in your tenant
yet is added there, and Sluse Admin says so. Then Read its tools. Sluse Admin adds
that scope to Sluse Gate's app; grant admin consent in the portal (the link
is shown) and Check again. It then lists the server's tools and the MCP
version it answers, which is kept in the configuration. **Tick only tools
that read.** A tool's "read only" mark is the server's own claim; Sluse
cannot see what a tool does. You may fix an argument of a tool: the value
you set replaces whatever the agent sends.

## Working in Sluse

For the person. **Open "Sluse"** from the Start menu. The first time on a
PC, Sluse prepares the box's system, which takes a while; after that it
opens in under a minute. If the preparation fails, Sluse says so and offers
Try again. Sign in when asked, with the account you use for Windows: Sluse
asks once each time it opens the box, and once more if a first preparation
took long. The box shows once its console is ready.

**In the box:** the Sluse console in Firefox, and the AI apps (Claude
Desktop, ChatGPT, Claude Code, Codex, Mistral Vibe), which the console's
Open buttons start. Each opens as a tab along the top of the box, named
Sluse console, Claude, ChatGPT, Claude Code, Codex, Mistral Vibe or
Terminal; switch tabs
with the mouse, or with Ctrl+Alt+Right, which goes round from the last tab
to the first. Close an app's tab with a middle click on it, or Ctrl+Alt+W
for the tab in front; the Sluse console's tab stays. The box is
drawn at the size of the window, so making the window larger gives the box
more room.

Sign each app in to your company's AI account once; it stays signed in.
The first run of Claude Code, Codex and Mistral Vibe says how, since
Microsoft's sign-in cannot open in the box. They start in the box's
workspace, where the files Sluse lets in land; Claude Desktop opens a Code
session there and asks you to confirm the folder. ChatGPT signs in through
Firefox in the box.

The console's pages: **Work** (what Sluse let in this session, its count
for each source against the volume alert, and what was published), **Your
artifacts** (every publish from this box, this session first, with the
sources the agent declared), **Copies in the box** (with Check against the
sources and Delete the copies), **Sources** (what the agents can see,
folder by folder) and **Record**.

**The bar above the box:**
- **Reading as** names the account Sluse reads SharePoint and OneDrive as,
  with **Sign out**. Signed out, Sluse stops reading SharePoint and
  OneDrive for the box; file shares and Sluse Inputs, read as your Windows
  account, go on. It lasts until you close the box and open Sluse again,
  which signs you in.
- **Sluse Artifacts** opens the folder where everything the agent publishes
  lands: `C:\Users\<you>\Sluse Artifacts`, a folder per publish.
- **Sluse Inputs**, if IT turned it on: put files there for the agent.
- If your OneDrive `Sluse` folder is missing, the bar says so, with a
  button that creates it.
- **The theme switch** (Follow Windows, Light, Dark) sets the box too, at
  once: the console, the box's background, and apps that follow the
  desktop's light or dark setting. A terminal already open keeps its
  colours until you open it again.

**Asking the agent:** ask in plain words. It lists and reads files through
Sluse's tools, and only the files IT put in reach. If IT added a tool
server, its tools are there too, each named after the source; an answer
from one is saved in the box's workspace as a file the agent was given.
Opened before signing in, the tools appear within about 15 seconds of the
sign-in; an app that still does not show them shows them once you open it
again. When it publishes, it
names the files it used; the console's provenance card shows them for each
document. Sluse checks each one against its own record of what it gave the
agent in that session; it cannot check that the agent used it.

**Close, Reset, Wipe:**
- **Close** stops the box; your work in it stays. Sluse asks first.
- **The window's X** asks whether to close the box or leave it running.
  Left running, Sluse stays in the notification area until the box is
  closed. A second X within 5 seconds closes both. Quitting while the box
  is still opening leaves it closed; quitting while its system is still
  being prepared lets the preparation finish in the notification area,
  says when it is ready, and leaves the box closed.
- **Reset the system, keep my files** gives the box a fresh system,
  including Sluse's updates; your files in the box stay.
- **Wipe the box** removes everything in it. Use it when you are done with
  a piece of work: files given to the agent stay in the box until you do.

## What IT sees

**The Event Log,** source `Sluse`, one event per decision. The event id is
100 × the operation + the outcome (0 admitted, 1 refused, 2 error,
3 raised), so a SIEM rule can filter on either.

| Id | Means |
|---|---|
| 100, 200 | A file read, or fetched to the box's disk |
| 101, 201 | Refused: out of scope, or the person may not open it |
| 102, 602 … | The source could not be reached; the record says why (DNS, connection, licence, throttling) |
| 400 | A publish: the files, the sources the agent declared, and everything given in that session |
| 1000 | A sign-in |
| 1303 | A folder in the configuration is not there for this person (or they cannot open it), or a file share could not be reached when Sluse started. The other sources still work; that one stays unavailable until the box is opened again |
| 1201 | The box tried a host it may not reach |
| 1700 | A tool server's tool called: the tool, the server, the hash of the answer. The arguments are not recorded |
| 1701, 1702 | A tool call refused (a tool not ticked, no sign-in, the server refusing the person), or the server unreachable or failing |
| 1801, 1802 | A tool server's list of tools could not be had |
| 803 | Many files in a short time (the volume alert) |

A record of something done for the person names them by their Entra
account once they have signed in. Some do not: a record from before the
first sign-in, or after a sign-out, names the PC's own Sluse service; the
proxy's refusals (1201) carry the Windows account's SID the box was opened
for; the PC check at start (1400, 1401) names no one.

**Posture:** at each open Sluse records how the PC is set up (Hyper-V,
the person not an administrator, enhanced session off, and more) and starts
the box only if the essentials hold.

**On the PC:** Sluse's network for the boxes is the Hyper-V switch
"Sluse boxes", and Windows lists its adapter, vEthernet (Sluse boxes), as
an "Unidentified network". That is expected: the network is host-only and
has no gateway, so a box reaches nothing but Sluse on the PC. Its firewall
rule is "Sluse boxes: Sluse Gate (host-only)", in group Sluse, for
`sluse-gate-front.exe`. In Hyper-V Manager each box's notes name the person
it reads as.

## Known edges

- **Encrypted, labelled files cannot be read in the box.** A file with a
  Purview label that encrypts it arrives encrypted, and nothing in the box
  holds a key. This is the control, not a fault: **to keep a document out
  of an agent, encrypt it.** It is measured on Word files; a
  password-protected PDF or zip, and old `.doc`/`.xls`, are not recognised.
- **Windows and Sluse must be signed in as the same person.** Sources read
  as the Windows logon (SMB, Sluse Inputs) and publishing are refused when
  the Sluse sign-in is another account; SharePoint and OneDrive go on
  working. On a domain-joined or hybrid PC this needs Sluse's app
  registration made by this version of Sluse Admin. Built, not yet run.
- **Network clients that capture Microsoft 365 traffic** (Global Secure
  Access and the like) can break Sluse's calls to Microsoft Graph when
  they are on but not connected: SharePoint answered "could not be reached"
  until the client was turned off, on our test PC.
- **The first open on a PC is slow**: the box's system is built there,
  about 20 minutes or more on our test PC. Later opens take under a minute.
- **Hosts that accept uploads.** The AI providers' groups (Claude, Codex and ChatGPT,
  and Mistral Vibe when ticked) take whatever the box sends them: that is
  the conversation. Claude and Codex are on by default. npm and GitHub
  serve the agent's tools and also accept uploads on the same hosts; they
  are off by default. Turn them on in Egress only if your agents need them.
- **Text can be copied into the box, and out of it** while copying out is
  on (the default; Advanced turns it off). Files cannot.
- **The `sluse:` link.** Sluse's notifications use a `sluse:` link to open
  Sluse, bring up its Close confirm, or open Sluse Artifacts. Any web page
  or program can follow that link too; it does nothing else, and closing
  the box still asks the person first.
- **A tool server reads as the person only as far as the server does.**
  Sluse calls it with the person's token; a server that reads its own back
  end with a service account answers with what that account sees, and
  Sluse cannot tell. Which tools are read only is the server's word.
- **The AI provider keeps the conversations** in its account, readable from
  any device signed in to it.
- **On a PC that several people sign in to at once** (switching users,
  remote desktop), another of them can read a box's diagnostic log while it
  starts and keep reading it for that session. The log holds no passwords
  or tokens, but can name files the agent worked on. A PC with one person
  signed in at a time is not affected.
- **Proven on our test PC only:** SharePoint, OneDrive and SMB read as the
  person, for one user in one tenant (SMB: one domain, the whole share in
  scope). **Built, not yet run on any device:** the App Control policy on
  Sluse Artifacts, that the Sluse log takes writes only from the system,
  and tool servers.

## Telling us what happened

When something goes wrong or reads oddly, collect:
- what you did and what you expected, with the time;
- the Event Log's `Sluse` events around that time (exported, or copied
  from the Details tab);
- from `C:\ProgramData\Sluse\`: `phases.json` (how long each step took)
  and, for a box that would not start, `boxes\<id>\console.log`; for a
  box's system that could not be installed, `images\build\console.log`;
- from `%LOCALAPPDATA%\Sluse\logs\`: `shell.log`, what the Sluse window did
  and when.

Open an issue on this repository with what you did and saw. **The logs can
name your files, folders and accounts:** read them before attaching them to
a public issue, or ask in the issue for a private way to send them. For a
security problem, follow [SECURITY.md](SECURITY.md) instead.

Edge cases are what v0.1 is for: the more of them we hear about, the better
the next release.

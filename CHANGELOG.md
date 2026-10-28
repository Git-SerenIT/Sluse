# Changelog

One section per release, newest first. The release workflow publishes a
version's section as its notes and refuses a version without one. Each
section says what changed for an administrator and for the person using
Sluse, and what is still not proven.

## 0.1.6

**For the administrator and the person using Sluse**
- **A busy button's ring keeps turning** when Windows' animation effects
  are off (Settings, Accessibility, Visual effects). It stood still
  before, which looked as if Sluse had frozen; now it turns slowly.

**For the administrator**
- **Sluse Admin no longer waits in silence** when Microsoft Graph does not
  answer. Each call to Graph now gives up after a minute and says which
  one did not answer, so the step shows a problem you can act on. Before,
  a stalled call (seen at Tenant's "Make or repair") turned for as long as
  the window stayed open.
- **Tenant works again in Sluse Admin.** Reading the AI providers' own
  connectors broke the page while it drew the answer, which left "Reading
  the providers' apps" turning and stopped "Make or repair" before it
  asked Entra anything. An error in Sluse Admin's own page is now shown,
  and written to `shell.log`, instead of leaving a step turning.
- **Turning a provider's app off** says why when Entra refuses it; the
  reason was lost before. **Review** names a change to the AI runtimes'
  organisations (Advanced); changed alone, it read "Nothing changed".

**Not proven:** not yet run on a device.

## 0.1.5

**For the administrator and the person using Sluse**
- **Sluse's new mark**: the ring with the storm inside it, without the
  breakers. In the Sluse window, the Start menu, the taskbar, the tray,
  the console and the README, and now also for Sluse in Installed apps,
  which showed Windows' default icon before. Nothing else changes.

**Not proven:** not yet run on a device.

## 0.1.4

**For the administrator**
- **The AI runtimes' organisations** (Sluse Admin, Advanced): your
  ChatGPT workspaces and your Claude organisation. In the box, Claude Code
  signs in only to that organisation, and Codex only with ChatGPT, to
  those workspaces. The runtimes enforce this from their own managed
  settings, which Sluse writes; Sluse does not check the accounts itself.
  An account outside your organisation is not your company's.
- **ChatGPT's desktop app in the box**, beside Claude: OpenAI's Linux
  preview, from the Codex egress group, which now also lists its hosts
  (`ws.chatgpt.com`, `cdn.openai.com`, `persistent.oaistatic.com`). Sluse
  Admin shows them as new for a configuration made earlier; publish it
  again to apply them. It adds about 1.7 GB to the box's system. The
  ChatGPT workspaces above hold it too, as it is OpenAI's Codex app;
  whether its plain chat obeys them is not documented.

**For the person using Sluse**
- **ChatGPT** among the console's Open buttons. Sign in once, through
  Firefox in the box.

**Not proven:** not yet run on a device.

## 0.1.3

**For the administrator**
- **Tool servers as sources.** A source of the new kind `mcp` is an MCP
  server over HTTPS that accepts an Entra token: Sluse calls it as the
  signed-in person, with the delegated scope you name, using the MCP
  version you name. Its `scope` lists the tools the agent may call, at
  least one; list only tools that read. Arguments can be fixed per tool
  (`pins`); the agent does not see them.
- **Sluse Admin adds a tool server**: Sources, Add a source, Tool server.
  Give its address and the permission Sluse asks for; Sluse Admin adds
  that permission to Sluse's app, waits for your admin consent in the
  portal as it does for Graph's, then reads the server's tools as Sluse's
  app and keeps the MCP version it answers. Tick the tools, fix arguments
  if you want. Running Tenant setup again keeps these permissions.
- **The AI providers' own connectors**, at Tenant: Sluse Admin reads
  whether Claude's Microsoft 365 apps and ChatGPT's app are open in your
  tenant, their consent, and whether users may consent for themselves, and
  can turn an app's sign-in off in Entra if you choose. Signing in to Sluse
  Admin now also asks `Policy.Read.All`, to read that consent setting.
- In the Event Log, a tool call is **1700** (refused 1701, failed 1702);
  a tool list that could not be had is 1801 or 1802.

- **Uninstalling leaves your own port reservations.** Sluse removes only
  the reservations it made.

**For the person using it**
- **A file share that comes back needs no reopen.** If a share could not be
  reached when the box opened (off the VPN, say), Sluse tries it again
  when it is next asked, at most every 30 seconds.
- **A large copy no longer fails at two minutes.** It takes as long as it
  takes while data keeps arriving.
- The agent sees each allowed tool as its own, named
  `<source>__<tool>`. Each answer is saved in the workspace and shown to
  the agent as untrusted data, as a file is; it can be named as a source
  of what is published. The console counts it as let in.

**Not yet proven on a device:** tool servers as a whole, against a real
server and a real Entra scope.

## 0.1.2

**For the administrator**
- **Sluse Gate** is the new name for what ran beside each box (the
  "broker"), and it is now two processes. **Gate Front**, one per box,
  runs as LOCAL SERVICE with no token and is the only part the box can
  reach: its TLS, every request it sends, and its egress proxy. **Gate
  Core** runs as SYSTEM, holds the person's sign-in and reads the sources
  as them; it no longer listens on the network. In Task Manager:
  `sluse-gate-front.exe` and `sluse-gate-core.exe`.
- The firewall rule is now **"Sluse boxes: Sluse Gate (host-only)"** and
  names `sluse-gate-front.exe`. An older rule, "Sluse boxes: broker and
  proxy (host-only)", can be deleted.
- Sluse's app registration is now looked for as **"Sluse Gate"**. Rename
  an existing "Sluse broker" app in Entra (Branding & properties, Name)
  before running Tenant setup again, or setup makes a second app.
- In the Event Log, records Sluse Gate writes say `"writer":"core"`; the
  preflight's blocking checks are called **required** checks.
- Gate Front's own log is `logs\front.log` in Sluse's data folder.

**For the person using it:** nothing changes.

**Not yet proven on a device:** Gate Front's start as LOCAL SERVICE, and
everything else in this version; it is built and tested on the
development machine only.

## 0.1.1

**For the administrator**
- **Mistral Vibe** as a fourth runtime in the box, for teams that want an
  EU vendor's agent. Tick its egress group, **Mistral Vibe**, in Sluse
  Admin: it is off by default, and takes whatever the box sends it, as the
  other AI providers' groups do. Vibe uses Mistral's EU endpoint. Use an
  organisation plan whose inputs Mistral does not train on.
- Sluse Admin's egress catalog is version 4. Until a deployment is
  published again, the device's posture says its catalog is older; nothing
  changes in its egress until then.
- Vibe comes from PyPI when the box's system is built, so the Python
  packages group must be on then. Without it the box is built without Vibe,
  and its button says so. **Codex the same:** with its group off, the box
  is now built without Codex; before, the build failed.
- `THIRD-PARTY-NOTICES.txt` in Sluse's install folder: the licences of the
  third-party code in Sluse's programs, which 0.1.0 left out.

**For the person using it**
- **Mistral Vibe** in the console's Open bar, in its own tab. Its first run
  says how to sign in: open the address it shows in your browser on
  Windows; Vibe carries on by itself.

**Not yet proven on a device:** Mistral Vibe, and whether Vibe's default
model is served on Mistral's EU endpoint. A box made before 0.1.1 gets
Vibe at its next Reset, which moves it onto the new system and keeps its
files.

## 0.1.0 — the pilot release

The first release, for a small group of pilot companies. Not signed: check
`Sluse.msi` against `SHA256SUMS`.

**For the administrator**
- Sluse Admin makes Sluse's Entra app registration (a public client, no
  secret or certificate), picks the sources and their folders, the egress
  groups and the box's settings, and publishes the deployment to Intune.
- Sources: SharePoint and Teams libraries, SMB shares, each person's
  OneDrive `Sluse` folder, and a local Sluse Inputs folder.
- The Sluse Event Log: one event for every file let in, refused or
  published, and for each sign-in, volume alert and refused host.
- A default-deny egress proxy on the PC; the AI providers on by default,
  package hosts that take uploads off.
- An App Control policy for Sluse Artifacts, shipped for you to deploy.

**For the person using it**
- Sluse opens a box on the PC, built there on first use, with the Sluse
  console, Claude Desktop, Claude Code and Codex.
- The agent reads and fetches files through Sluse's tools, and publishes
  into Sluse Artifacts with the sources it used.
- Close, Reset (keeps your files) and Wipe; Light and Dark.

**Not yet proven on a device:** that the Sluse log takes writes from
SYSTEM only, the App Control policy, the check that the Windows user and
the signed-in user are the same person, Conditional Access cutting off a
box, and Codex. The known edges are in [GUIDE.md](GUIDE.md#known-edges).

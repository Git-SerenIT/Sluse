# Changelog

One section per release, newest first. The release workflow publishes a
version's section as its notes and refuses a version without one. Each
section says what changed for an administrator and for the person using
Sluse, and what is still not proven.

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
box, and Codex. The known edges are in [GUIDE.md](GUIDE.md#known-edges-in-v01).

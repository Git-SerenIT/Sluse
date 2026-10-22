# Sluse

Sluse gives AI agents a box of their own on this computer: a Hyper-V virtual
machine for each person who opens Sluse. Acting as the person signed in, Sluse
lets files into the box one at a time, only from the sources your organisation
chose, and records each one. What the agents publish lands in that person's
Sluse Artifacts folder, with the sources they declared recorded.

**What Sluse claims: authorised inputs with recorded provenance.** It does not
claim to prevent data leaving the box, by the agents' AI service or otherwise;
to judge what many files together reveal; to check that data is right; to
record what an agent tried to do; or to keep files from staying in the box once
let in. The box's lifetime is the only control on that.

## On this computer

| | |
|---|---|
| `C:\Program Files\Sluse` | The programs, the box's bundle, this file, the App Control policy (`intune\`) |
| `C:\ProgramData\Sluse` | The configuration, the logs, each person's box |
| Event Viewer > Applications and Services Logs > Sluse | One event for each file let in, refused or published |
| `%USERPROFILE%\Sluse Artifacts` | What each person's box published; kept on uninstall |

## Telling us what happened

Collect the Sluse events around the time, `C:\ProgramData\Sluse\phases.json`,
`C:\ProgramData\Sluse\boxes\<id>\console.log` (or `images\build\console.log`
for a box's system that could not be installed) and
`%LOCALAPPDATA%\Sluse\logs\shell.log`. The guide has the steps:
<https://github.com/Git-SerenIT/Sluse/blob/main/GUIDE.md>.

## Removing Sluse

Settings > Apps > Sluse > Uninstall, or through Intune. This deletes every box
on this computer. Each person's Sluse Artifacts folder stays.

This is a prototype build, 0.0.x. It stays at 0.0.x until someone other than
its author has run it against a real source.

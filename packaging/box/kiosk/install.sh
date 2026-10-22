#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 SerenIT ApS and Prompted EV
#
# Put the box's side of Sluse into an existing box by hand: the kiosk
# (slice 1), and enrolment and the console (slice 2). Slice 3's image build
# does the same with no person. In the box, from the unpacked bundle:
#
#   sudo bash kiosk/install.sh <the box's desktop user>
#
# The bundle's `bin/sluse-endpoint` and `ui/console` go to /usr/local. The
# box then gets its VNC secret, keyboard, identity and config from the host
# at every open, with nothing copied in by hand again.
set -euo pipefail
user=${1:?usage: sudo bash install.sh <user>}
id "$user" >/dev/null
here=$(cd "$(dirname "$0")" && pwd)
bundle=$(dirname "$here")
uid=$(id -u "$user"); gid=$(id -g "$user")
home=$(getent passwd "$user" | cut -d: -f6)
[ -x "$bundle/bin/sluse-endpoint" ] || { echo "no $bundle/bin/sluse-endpoint: run this from the unpacked bundle" >&2; exit 1; }

apt-get install -y sway xwayland wayvnc nftables python3 openssh-client
# The box's own pixels in Liberation Sans and Mono (Q4): sway's strip, foot.
apt-get install -y fonts-liberation
# The theme (Q70, kiosk/theme): sway's ground needs swaybg; the colour-scheme
# preference is a GSettings key the desktop portal's GTK backend serves, and
# dconf keeps it. Most come with sway already; named, because the theme
# depends on them.
apt-get install -y swaybg libglib2.0-bin dconf-gsettings-backend xdg-desktop-portal-gtk
# Claude Desktop's keyring (D-045 point 6; see kiosk). Without the
# recommended PAM module, which would start a second daemon at login.
apt-get install -y --no-install-recommends gnome-keyring

install -d /usr/local/libexec/sluse /usr/local/lib/sluse /etc/firefox/policies
install -m 0755 "$here/sluse-bootstrap" "$here/kiosk" "$here/vnc" "$here/home-init" "$here/browser" "$here/console-log" "$here/cli" "$here/theme" /usr/local/libexec/sluse/
install -m 0644 "$here/sway.conf" "$here/vnc.nft" "$here/no-images.lua" /usr/local/lib/sluse/
install -m 0644 "$here/policies.json" /etc/firefox/policies/policies.json
install -m 0755 "$bundle/bin/sluse-endpoint" /usr/local/bin/sluse-endpoint
rm -rf /usr/local/share/sluse/ui && install -d /usr/local/share/sluse/ui
cp -r "$bundle/ui/console" /usr/local/share/sluse/ui/console

# wayvnc's RSA key, for viewers that speak RSA-AES. Once per box.
install -d -m 0750 -g "$(id -gn "$user")" /var/lib/sluse
if [ ! -f /var/lib/sluse/vnc-rsa.pem ]; then
    ssh-keygen -q -m pem -t rsa -b 3072 -N "" -f /var/lib/sluse/vnc-rsa.pem
    rm -f /var/lib/sluse/vnc-rsa.pem.pub
fi
chgrp "$(id -gn "$user")" /var/lib/sluse/vnc-rsa.pem
chmod 0640 /var/lib/sluse/vnc-rsa.pem

units="sluse-home.service sluse-kiosk.service sluse-vnc.service sluse-firewall.service sluse-bootstrap.service sluse-bootstrap.path sluse-enrol.service sluse-console.service sluse-console-log.service"
for u in $units; do
    sed -e "s/@KIOSK_USER@/$user/g" -e "s/@UID@/$uid/g" -e "s/@GID@/$gid/g" -e "s#@HOME@#$home#g" "$here/$u" > "/etc/systemd/system/$u"
done
systemctl daemon-reload
systemctl enable --now sluse-firewall.service sluse-bootstrap.path sluse-kiosk.service
systemctl enable sluse-home.service sluse-vnc.service sluse-enrol.service sluse-console.service sluse-bootstrap.service
# The serial console carries the log out and nothing in (D-030): no login
# listens on it, whatever the kernel command line says.
systemctl mask serial-getty@ttyS0.service
# No route out by design (M9, D-035), so wait-online never sees the network
# online and held every boot for its 120 s limit (L1, 2026-10-08). Nothing in
# the box needs more than its own segment, which is up within a second.
systemctl mask systemd-networkd-wait-online.service
systemctl enable sluse-console-log.service
systemctl start sluse-bootstrap.service

# The agent's runtime reaches Sluse through the endpoint, started by the
# runtime itself (--mcp). Each of the three runtimes (D-027 point 3) that is
# installed for this user. Best effort: a runtime's own config format is its
# vendor's, and a failure here is a runtime without Sluse, said below.
# Claude Code's telemetry and error reports (Datadog intake, outside the
# catalog by D-035) switched off where every session reads them and the user's
# settings cannot undo it (code.claude.com/docs/en/managed-settings). Not
# CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: it also stops the updater, and
# the runtimes update themselves (D-026 point 4); the changelog's fetch from
# raw.githubusercontent.com stays, refused unless the github bundle is on.
install -d /etc/claude-code
cat > /etc/claude-code/managed-settings.json <<'JSON'
{
  "env": {
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1"
  }
}
JSON

mcp="/usr/local/bin/sluse-endpoint --config $home/Sluse/sluse.json --mcp"
as_user() { sudo -u "$user" -H bash -lc "$1"; }
if as_user 'command -v claude' >/dev/null 2>&1; then
    as_user "claude mcp remove --scope user sluse >/dev/null 2>&1; claude mcp add --scope user sluse -- $mcp" \
        || echo "Claude Code: the sluse MCP server was not added" >&2
fi
if as_user 'command -v codex' >/dev/null 2>&1; then
    as_user "codex mcp remove sluse >/dev/null 2>&1; codex mcp add sluse -- $mcp" \
        || echo "Codex: the sluse MCP server was not added" >&2
fi
if [ -x /usr/bin/claude-desktop ]; then
    install -m 0755 "$here/claude-desktop" /usr/local/bin/claude-desktop
    # Claude Desktop reads local stdio servers from its own config file.
    as_user "python3 - '$home' <<'PY'
import json, os, sys
p = os.path.join(sys.argv[1], '.config/Claude/claude_desktop_config.json')
os.makedirs(os.path.dirname(p), exist_ok=True)
c = json.load(open(p)) if os.path.exists(p) else {}
c.setdefault('mcpServers', {})['sluse'] = {
    'command': '/usr/local/bin/sluse-endpoint',
    'args': ['--config', os.path.join(sys.argv[1], 'Sluse/sluse.json'), '--mcp'],
}
json.dump(c, open(p, 'w'), indent=2)
PY" || echo "Claude Desktop: the sluse MCP server was not added" >&2
fi

# Sluse's install got this far: the build's verdict reads it (user-data.yaml,
# D-063). Before the status below, which fails under pipefail while a unit is
# not running yet.
touch /var/lib/sluse/installed

systemctl --no-pager status sluse-kiosk.service sluse-vnc.service sluse-enrol.service | head -n 30
echo
echo "Installed. At the next open from the host, the box gets its VNC secret,"
echo "its identity and its config, and the console starts on its own."

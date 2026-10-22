// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! Sluse's ports (D-029): one block, **7580 to 7589**. 758 is S-L-U on a
//! phone keypad. The host's ports came first, then the box's; the proxy,
//! added with M9, is the host's and comes after them (D-035), so a number
//! names its part, and [`ON_HOST`] says which machine.
//!
//! This is the one definition. The config defaults, `admin setup`'s
//! template, the service and the shell use these constants; the box's
//! scripts and the shell's CSP spell the numbers, and a test checks that
//! they agree (`sluse-lifecycle`, `ports_agree`).

/// The broker, mTLS. Host, on the host-only address.
pub const BROKER: u16 = 7580;
/// Enrolment: server TLS, one route, no client certificate (slice 2). Host.
pub const ENROL: u16 = 7581;
/// The console. Box, loopback only. The sign-in left it for the host shell
/// (D-036).
pub const CONSOLE: u16 = 7582;
/// The box's screen, VNC over a websocket, for the shell. Box, host-only
/// side, admitted from the host alone.
pub const VNC: u16 = 7583;

/// The egress proxy (M9, D-035): the box's only way out. Host, on the
/// host-only address.
pub const PROXY: u16 = 7584;

/// The block Sluse keeps for itself. 7585 to 7589 are reserved and **not
/// named** until something needs one.
pub const BLOCK: std::ops::RangeInclusive<u16> = 7580..=7589;

/// The ports that listen on the host. Only these are reserved in Windows
/// (`excludedportrange`): a Windows reservation also stops other programs
/// binding a port, and one Sluse does not use is not Sluse's to hold.
pub const ON_HOST: [u16; 3] = [BROKER, ENROL, PROXY];

/// What part a port is, for a message a person reads: "broker (7580)".
pub fn part(port: u16) -> &'static str {
    match port {
        BROKER => "broker",
        ENROL => "enrolment",
        CONSOLE => "console",
        VNC => "the box's screen (VNC)",
        PROXY => "the egress proxy",
        p if BLOCK.contains(&p) => "a reserved Sluse port",
        _ => "not a Sluse port",
    }
}

/// `"broker, 192.168.77.1:7580"` for an address, so every bind, connect
/// and refusal names the part as well as the port (D-029 point 5).
pub fn label(addr: &str) -> String {
    let port = addr.rsplit_once(':').and_then(|(_, p)| p.parse::<u16>().ok());
    match port {
        Some(p) => format!("{}, {addr}", part(p)),
        None => addr.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_block_is_host_first_and_every_port_names_its_part() {
        for p in [BROKER, ENROL, CONSOLE, VNC, PROXY] {
            assert!(BLOCK.contains(&p));
        }
        assert!(!ON_HOST.contains(&CONSOLE) && !ON_HOST.contains(&VNC), "the box's ports are not the host's");
        assert_eq!(label("192.168.77.1:7580"), "broker, 192.168.77.1:7580");
        assert_eq!(label("127.0.0.1:7582"), "console, 127.0.0.1:7582");
        assert_eq!(part(7588), "a reserved Sluse port");
        assert_eq!(label("192.168.77.1:7584"), "the egress proxy, 192.168.77.1:7584");
        assert_eq!(part(443), "not a Sluse port");
        assert_eq!(label("no-port"), "no-port");
    }
}

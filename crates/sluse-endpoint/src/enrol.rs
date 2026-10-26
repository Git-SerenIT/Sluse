// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The box's half of enrolment (slice 2, D-024 point 7): no `scp`, no mount.
//!
//! Run as root by `sluse-enrol.service`, at boot and whenever the host's KVP
//! bootstrap changes:
//! 1. read this open's bootstrap from the KVP pool;
//! 2. if it is the one already enrolled with, stop: the identity stands;
//! 3. make a P-256 key pair, here, and keep the private half;
//! 4. send the public half and the token to the enrolment listener, pinned to
//!    the Gate's leaf;
//! 5. check that the config it returns pins the same leaf;
//! 6. write the key, the certificate and the config into the user's
//!    directory, owned by the user the agent runs as, and the config last.
//!
//! The key is readable by that user, as `endpoint.key` was in the S-3 runs:
//! the endpoint runs as the agent's user, because the agent's runtime starts
//! it. It is the box's identity, not the user's authority (invariant 3).

use std::path::{Path, PathBuf};

use sluse_proto::pipe::{Bootstrap, KVP_KEY};
use sluse_proto::wire::EnrolRequest;

use crate::kvp;

/// Beside the config: the hash of the token this identity was enrolled with.
const MARKER: &str = ".enrolled";

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A new identity and config were written.
    Enrolled,
    /// This bootstrap was enrolled with already.
    Unchanged,
    /// The host has not sent a bootstrap yet.
    NoBootstrap,
}

/// Enrol into `config`'s directory from the pool at `pool`.
/// `owner` is who the written files belong to.
pub async fn run(config: &Path, pool: &Path, owner: Option<(u32, u32)>) -> Result<Outcome, String> {
    let bytes = match std::fs::read(pool) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Outcome::NoBootstrap),
        Err(e) => return Err(format!("{}: {e}", pool.display())),
    };
    let Some(raw) = kvp::find(&bytes, KVP_KEY) else { return Ok(Outcome::NoBootstrap) };
    let boot: Bootstrap = serde_json::from_str(&raw).map_err(|e| format!("the bootstrap: {e}"))?;

    let dir = config.parent().filter(|d| !d.as_os_str().is_empty()).ok_or("the config path has no directory")?;
    let marker = dir.join(MARKER);
    let enrolled_with = boot.token_hash();
    if config.is_file() && std::fs::read_to_string(&marker).ok().as_deref() == Some(enrolled_with.as_str()) {
        return Ok(Outcome::Unchanged);
    }

    let key = rcgen::KeyPair::generate().map_err(|e| format!("a key pair: {e}"))?;
    let req = EnrolRequest {
        token: boot.token.expose().to_owned(),
        public_key: key.public_key_raw().iter().map(|b| format!("{b:02x}")).collect(),
        hostname: hostname(),
    };
    let resp = crate::gate_client::enrol(&boot.enrol, boot.pin.clone(), &req)
        .await
        .map_err(|e| format!("{}: {e}", boot.enrol))?;

    // The config decides where the key and certificate go, so it is read
    // before anything is written, and refused if it would put them elsewhere.
    let loaded = sluse_proto::config::load_from_bytes(resp.config.as_bytes(), resp.device.as_bytes(), config)
        .map_err(|e| format!("the Gate's config: {e}"))?;
    if loaded.config.gate.cert_pin != boot.pin {
        return Err("the Gate's config pins a different leaf from the one this bootstrap pinned".into());
    }
    let cert_path = inside(dir, &loaded.config.endpoint.client_cert_path)?;
    let key_path = inside(dir, &loaded.config.endpoint.client_key_path)?;

    std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    write(&key_path, key.serialize_pem().as_bytes(), 0o600, owner)?;
    write(&cert_path, resp.cert_pem.as_bytes(), 0o644, owner)?;
    write(&sluse_proto::config::device_path(config), resp.device.as_bytes(), 0o644, owner)?;
    write(config, resp.config.as_bytes(), 0o644, owner)?;
    write(&marker, enrolled_with.as_str().as_bytes(), 0o644, owner)?;
    Ok(Outcome::Enrolled)
}

/// A path from the config, resolved against `dir`, refused unless it stays
/// there: relative, and with no `..`.
fn inside(dir: &Path, rel: &str) -> Result<PathBuf, String> {
    let p = Path::new(rel);
    if p.is_absolute() || p.components().any(|c| !matches!(c, std::path::Component::Normal(_))) {
        return Err(format!("the config puts the box's identity at {rel:?}, outside its directory"));
    }
    Ok(dir.join(p))
}

/// Write through a temporary file and rename, so a reader never sees half a
/// file, then set the mode and the owner.
fn write(path: &Path, bytes: &[u8], mode: u32, owner: Option<(u32, u32)>) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(err)?;
        #[cfg(unix)]
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(parent, Some(uid), Some(gid)).map_err(err)?;
        }
    }
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, bytes).map_err(err)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(err)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(&tmp, Some(uid), Some(gid)).map_err(err)?;
        }
    }
    #[cfg(not(unix))]
    let _ = (mode, owner);
    std::fs::rename(&tmp, path).map_err(err)
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname").map(|h| h.trim().to_owned()).unwrap_or_else(|_| "unknown".into())
}

/// `uid:gid`, as `--owner` takes it.
pub fn parse_owner(s: &str) -> Result<(u32, u32), String> {
    let (u, g) = s.split_once(':').ok_or("--owner is uid:gid")?;
    Ok((u.parse().map_err(|_| "--owner: uid is not a number")?, g.parse().map_err(|_| "--owner: gid is not a number")?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_identity_stays_in_its_directory() {
        let d = Path::new("/home/u/Sluse");
        assert_eq!(inside(d, "certs/endpoint.key").unwrap(), d.join("certs/endpoint.key"));
        for bad in ["/etc/shadow", "../x", "certs/../../x", "./x"] {
            assert!(inside(d, bad).is_err(), "{bad}");
        }
        assert_eq!(parse_owner("1000:1001").unwrap(), (1000, 1001));
        assert!(parse_owner("1000").is_err());
    }
}

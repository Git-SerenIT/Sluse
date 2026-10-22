// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The box's base image, made on the device from Canonical's own (D-024
//! point 3, D-027 point 1).
//!
//! 1. [`fetch`]: `SHA256SUMS` and its signature, checked against Canonical's
//!    pinned key ([`openpgp`]). Then the image, resumed if a download was
//!    cut, and checked against the signed list.
//! 2. [`to_fixed_vhd`]: qcow2 to raw ([`qcow2`]), plus a VHD footer ([`vhd`]).
//!
//! Hyper-V does the rest (`packaging/box/sluse-box.ps1`): `Convert-VHD` to a
//! dynamic VHDX, and `Resize-VHD`. Nothing is redistributed: every device
//! fetches its own copy.

pub mod openpgp;
pub mod qcow2;
pub mod vhd;

use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// The release directory. `26.04` redirects to the codename's directory,
/// which is followed.
pub const RELEASE_URL: &str = "https://cloud-images.ubuntu.com/releases/26.04/release/";
pub const IMAGE_NAME: &str = "ubuntu-26.04-server-cloudimg-amd64.img";
/// The most `SHA256SUMS` or its signature may be; both are a few kilobytes.
const LIST_CAP: usize = 1 << 20;

/// The expected SHA-256 of `name` in a `SHA256SUMS` body (`<hex> *<name>`).
pub fn listed_hash(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|l| {
        let (hash, file) = l.trim().split_once(char::is_whitespace)?;
        (file.trim().trim_start_matches('*') == name && hash.len() == 64).then(|| hash.to_ascii_lowercase())
    })
}

/// Fetch and verify the image into `dir`, and return its path. `progress`
/// is called with (bytes so far, total). Past `within` it stops and says so
/// (Q21); the part already fetched stays, and the next try resumes it.
pub fn fetch(dir: &Path, within: Option<std::time::Duration>, mut progress: impl FnMut(u64, u64)) -> Result<PathBuf, String> {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    let fetching = async {
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|e| e.to_string())?;
        let get = |name: &str| {
            let url = format!("{RELEASE_URL}{name}");
            let http = http.clone();
            async move {
                let mut r = http.get(&url).send().await.map_err(|e| format!("{url}: {e}"))?;
                if !r.status().is_success() {
                    return Err(format!("{url}: {}", r.status()));
                }
                // Capped: both are a few kilobytes, and are read before the
                // signature is checked (R-54).
                let mut body = Vec::new();
                while let Some(c) = r.chunk().await.map_err(|e| format!("{url}: {e}"))? {
                    body.extend_from_slice(&c);
                    if body.len() > LIST_CAP {
                        return Err(format!("{url}: larger than {LIST_CAP} bytes"));
                    }
                }
                Ok(body)
            }
        };
        let sums = get("SHA256SUMS").await?;
        let sig = get("SHA256SUMS.gpg").await?;
        openpgp::verify(&sums, &String::from_utf8_lossy(&sig))?;
        let sums = String::from_utf8_lossy(&sums).into_owned();
        let expected = listed_hash(&sums, IMAGE_NAME).ok_or_else(|| format!("{IMAGE_NAME} is not in the signed SHA256SUMS"))?;

        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let done = dir.join(IMAGE_NAME);
        if done.is_file() && sha256_file(&done)? == expected {
            return Ok(done);
        }
        // Resume a cut download: hash what is there, and ask for the rest.
        let part = dir.join(format!("{IMAGE_NAME}.part"));
        let mut hasher = Sha256::new();
        let mut have = 0u64;
        if let Ok(mut f) = std::fs::File::open(&part) {
            have = std::io::copy(&mut f, &mut HashWriter(&mut hasher)).map_err(|e| e.to_string())?;
        }
        let url = format!("{RELEASE_URL}{IMAGE_NAME}");
        let mut req = http.get(&url);
        if have > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={have}-"));
        }
        let mut r = req.send().await.map_err(|e| format!("{url}: {e}"))?;
        // A `.part` as long as the file, or longer, is past what the server
        // can resume: start over next time rather than ask again for ever
        // (review R-38).
        if r.status() == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            let _ = std::fs::remove_file(&part);
            return Err(format!("{url}: {} for a partial download; it is removed, and the next build starts over", r.status()));
        }
        if have > 0 && r.status() != reqwest::StatusCode::PARTIAL_CONTENT {
            // The server sent the whole file again: start over.
            have = 0;
            hasher = Sha256::new();
        }
        if !r.status().is_success() {
            return Err(format!("{url}: {}", r.status()));
        }
        let total = have + r.content_length().unwrap_or(0);
        let file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(have > 0)
            .truncate(have == 0)
            .open(&part)
            .map_err(|e| format!("{}: {e}", part.display()))?;
        let mut w = BufWriter::new(file);
        while let Some(chunk) = r.chunk().await.map_err(|e| format!("{url}: {e}"))? {
            w.write_all(&chunk).map_err(|e| e.to_string())?;
            hasher.update(&chunk);
            have += chunk.len() as u64;
            progress(have, total);
        }
        w.flush().map_err(|e| e.to_string())?;
        drop(w);
        let got = hex(&hasher.finalize());
        if got != expected {
            let _ = std::fs::remove_file(&part);
            return Err(format!("{IMAGE_NAME} does not match Canonical's signed SHA256SUMS"));
        }
        std::fs::rename(&part, &done).map_err(|e| e.to_string())?;
        Ok(done)
    };
    rt.block_on(async {
        match within {
            Some(w) => tokio::time::timeout(w, fetching)
                .await
                .unwrap_or_else(|_| Err(format!("the download did not finish within {} minutes", w.as_secs() / 60))),
            None => fetching.await,
        }
    })
}

/// qcow2 to a fixed VHD at `out`: the raw disk, then the footer.
pub fn to_fixed_vhd(qcow2_path: &Path, out: &Path, progress: impl FnMut(u64, u64)) -> Result<(), String> {
    let mut src = std::fs::File::open(qcow2_path).map_err(|e| format!("{}: {e}", qcow2_path.display()))?;
    let dst = std::fs::File::create(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let mut w = BufWriter::with_capacity(1 << 20, dst);
    let size = qcow2::to_raw(&mut src, &mut w, progress).map_err(|e| e.to_string())?;
    if size % 512 != 0 {
        return Err(format!("the disk is {size} bytes, not whole sectors"));
    }
    let mut uuid = [0u8; 16];
    getrandom::fill(&mut uuid).map_err(|e| e.to_string())?;
    let since_2000 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().saturating_sub(946_684_800) as u32)
        .unwrap_or(0);
    w.write_all(&vhd::footer(size, uuid, since_2000)).map_err(|e| e.to_string())?;
    w.flush().map_err(|e| e.to_string())
}

fn sha256_file(p: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(p).map_err(|e| format!("{}: {e}", p.display()))?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut HashWriter(&mut h)).map_err(|e| e.to_string())?;
    Ok(hex(&h.finalize()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct HashWriter<'a>(&'a mut Sha256);

impl Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_images_line_is_found_in_the_signed_list() {
        let sums = include_str!("testdata/SHA256SUMS");
        assert_eq!(
            listed_hash(sums, IMAGE_NAME).as_deref(),
            Some("8800651811af9a85465ad1d552add729947bb16488dddb4a9b5305a3d97332b2")
        );
        assert_eq!(listed_hash(sums, "ubuntu-26.04-server-cloudimg-amd64"), None, "a prefix is not the name");
    }
}

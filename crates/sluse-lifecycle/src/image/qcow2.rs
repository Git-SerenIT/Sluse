// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! A qcow2 reader, just enough for Canonical's cloud image (D-027 point 1):
//! the product ships no `qemu-img`, and no GPL code.
//!
//! **Read:**
//! - header versions 2 and 3;
//! - the L1 and L2 tables;
//! - standard clusters, zero clusters, and unallocated clusters, which read as
//!   zeros;
//! - clusters compressed with deflate, the compression Canonical uses.
//!
//! **Refused, by name:**
//! - a backing file;
//! - encryption;
//! - an external data file;
//! - extended L2 entries;
//! - compression other than deflate;
//! - an image marked corrupt.
//!
//! Anything this reader does not know is a refusal, never a guess: a wrong
//! guess here is a box with a damaged disk.
//!
//! The output is written sequentially, zeros included, so the file is never
//! sparse. Hyper-V refuses sparse disks (S-8 step 3, `0xC03A001A`).

use std::io::{self, Read, Seek, SeekFrom, Write};

const MAGIC: &[u8; 4] = b"QFI\xfb";
const OFFSET_MASK: u64 = 0x00ff_ffff_ffff_fe00;
const COMPRESSED: u64 = 1 << 62;
const ZERO: u64 = 1;

pub struct Header {
    pub size: u64,
    cluster_bits: u32,
    l1_size: u32,
    l1_offset: u64,
}

pub fn header(r: &mut impl Read) -> io::Result<Header> {
    let mut h = [0u8; 112];
    // The magic first, so a file that is not an image says so rather than
    // running out of bytes.
    if r.read_exact(&mut h[..4]).is_err() || &h[..4] != MAGIC {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "qcow2: not a qcow2 image"));
    }
    r.read_exact(&mut h[4..72])?;
    let refuse = |why: &str| Err(io::Error::new(io::ErrorKind::InvalidData, format!("qcow2: {why}")));
    let version = be32(&h, 4);
    if !(2..=3).contains(&version) {
        return refuse(&format!("version {version}"));
    }
    if be64(&h, 8) != 0 {
        return refuse("a backing file");
    }
    if be32(&h, 32) != 0 {
        return refuse("encryption");
    }
    let cluster_bits = be32(&h, 20);
    if !(9..=21).contains(&cluster_bits) {
        return refuse(&format!("cluster size 2^{cluster_bits}"));
    }
    if version == 3 {
        r.read_exact(&mut h[72..104])?;
        let incompatible = be64(&h, 72);
        let header_length = be32(&h, 100) as usize;
        const DIRTY: u64 = 1;
        const CORRUPT: u64 = 2;
        const EXTERNAL: u64 = 4;
        const COMPRESSION: u64 = 8;
        const EXTENDED_L2: u64 = 16;
        if incompatible & CORRUPT != 0 {
            return refuse("the image is marked corrupt");
        }
        if incompatible & EXTERNAL != 0 {
            return refuse("an external data file");
        }
        if incompatible & EXTENDED_L2 != 0 {
            return refuse("extended L2 entries");
        }
        if incompatible & !(DIRTY | CORRUPT | EXTERNAL | COMPRESSION | EXTENDED_L2) != 0 {
            return refuse(&format!("unknown incompatible features {incompatible:#x}"));
        }
        if incompatible & COMPRESSION != 0 {
            if header_length < 105 {
                return refuse("a compression type with no field for it");
            }
            r.read_exact(&mut h[104..105])?;
            if h[104] != 0 {
                return refuse(&format!("compression type {} (only deflate is read)", h[104]));
            }
        }
    }
    Ok(Header { size: be64(&h, 24), cluster_bits, l1_size: be32(&h, 36), l1_offset: be64(&h, 40) })
}

fn be32(h: &[u8], o: usize) -> u32 {
    u32::from_be_bytes(h[o..o + 4].try_into().unwrap())
}

fn be64(h: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(h[o..o + 8].try_into().unwrap())
}

/// Write the image's contents, as a raw disk, to `out`. `progress` is called
/// with the bytes written so far and the disk's whole size.
pub fn to_raw<R: Read + Seek, W: Write>(r: &mut R, out: &mut W, mut progress: impl FnMut(u64, u64)) -> io::Result<u64> {
    r.seek(SeekFrom::Start(0))?;
    let h = header(r)?;
    let cluster = 1u64 << h.cluster_bits;
    let per_l2 = cluster / 8;
    let clusters = h.size.div_ceil(cluster);
    if clusters.div_ceil(per_l2) > h.l1_size as u64 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "qcow2: the L1 table is too small for the disk"));
    }

    let mut l1 = vec![0u8; h.l1_size as usize * 8];
    r.seek(SeekFrom::Start(h.l1_offset))?;
    r.read_exact(&mut l1)?;

    let zeros = vec![0u8; cluster as usize];
    let mut data = vec![0u8; cluster as usize];
    let mut packed = Vec::new();
    let mut l2 = vec![0u8; cluster as usize];
    let mut l2_loaded = u64::MAX;
    let mut written = 0u64;

    for i in 0..clusters {
        let l1_index = i / per_l2;
        let l2_offset = u64::from_be_bytes(l1[l1_index as usize * 8..][..8].try_into().unwrap()) & OFFSET_MASK;
        let entry = if l2_offset == 0 {
            0
        } else {
            if l2_loaded != l1_index {
                r.seek(SeekFrom::Start(l2_offset))?;
                r.read_exact(&mut l2)?;
                l2_loaded = l1_index;
            }
            u64::from_be_bytes(l2[(i % per_l2) as usize * 8..][..8].try_into().unwrap())
        };

        let this = if entry & COMPRESSED != 0 {
            // x = 62 - (cluster_bits - 8): the offset below it, the extra
            // 512-byte sectors above it (qcow2 spec, "Compressed Clusters").
            let x = 62 - (h.cluster_bits - 8);
            let offset = entry & ((1u64 << x) - 1);
            let sectors = (entry >> x) & ((1u64 << (62 - x)) - 1);
            let len = (sectors + 1) * 512 - (offset & 511);
            packed.resize(len as usize, 0);
            r.seek(SeekFrom::Start(offset))?;
            let got = read_up_to(r, &mut packed)?;
            let mut d = flate2::read::DeflateDecoder::new(&packed[..got]);
            d.read_exact(&mut data).map_err(|e| {
                io::Error::new(io::ErrorKind::InvalidData, format!("qcow2: cluster {i} does not decompress: {e}"))
            })?;
            &data[..]
        } else if entry & ZERO != 0 || entry & OFFSET_MASK == 0 {
            &zeros[..]
        } else {
            r.seek(SeekFrom::Start(entry & OFFSET_MASK))?;
            r.read_exact(&mut data)?;
            &data[..]
        };

        let n = cluster.min(h.size - i * cluster) as usize;
        out.write_all(&this[..n])?;
        written += n as u64;
        if i % 256 == 0 {
            progress(written, h.size);
        }
    }
    out.flush()?;
    progress(written, h.size);
    Ok(written)
}

/// A compressed cluster's sector count can run past the end of the file; the
/// last cluster's always may.
fn read_up_to(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match r.read(&mut buf[got..])? {
            0 => break,
            n => got += n,
        }
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// `qemu-img` is the oracle here and only here: a test tool on the build
    /// machine, never shipped (D-027 point 1). CI's Linux job installs it.
    ///
    /// Where `SLUSE_REQUIRE_QEMU_IMG` is set (CI), a missing oracle fails the
    /// test instead of skipping it: a skipped proof is not a proof.
    fn qemu_img() -> Option<&'static str> {
        let found = Command::new("qemu-img").arg("--version").output().ok().filter(|o| o.status.success());
        if found.is_none() && std::env::var_os("SLUSE_REQUIRE_QEMU_IMG").is_some() {
            panic!("SLUSE_REQUIRE_QEMU_IMG is set and qemu-img is not installed");
        }
        found.map(|_| "qemu-img")
    }

    /// A raw disk with data, runs of zeros, and a tail that is not a whole
    /// cluster, so every kind of entry and the last partial cluster appear.
    fn sample(dir: &std::path::Path) -> std::path::PathBuf {
        let mut raw = Vec::new();
        for i in 0..(3 * 1024 * 1024 + 4096 + 512) {
            raw.push(if (i / 65536) % 3 == 1 { 0 } else { (i * 7 % 251) as u8 });
        }
        let p = dir.join("disk.raw");
        std::fs::write(&p, raw).unwrap();
        p
    }

    fn convert(dir: &std::path::Path, raw: &std::path::Path, name: &str, opts: &[&str]) -> std::path::PathBuf {
        let out = dir.join(name);
        let mut c = Command::new("qemu-img");
        c.args(["convert", "-f", "raw", "-O", "qcow2"]).args(opts).arg(raw).arg(&out);
        assert!(c.status().unwrap().success(), "qemu-img {opts:?}");
        out
    }

    #[test]
    fn every_image_shape_reads_back_as_the_disk_it_was_made_from() {
        let Some(_) = qemu_img() else {
            eprintln!("qemu-img not installed: the qcow2 oracle test did not run");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let raw = sample(dir.path());
        let expected = std::fs::read(&raw).unwrap();
        for (name, opts) in [
            ("v3.qcow2", &["-o", "compat=1.1"][..]),
            ("v3-compressed.qcow2", &["-c", "-o", "compat=1.1"][..]),
            ("v2-compressed.qcow2", &["-c", "-o", "compat=0.10"][..]),
            ("small-clusters.qcow2", &["-c", "-o", "cluster_size=4096"][..]),
        ] {
            let img = convert(dir.path(), &raw, name, opts);
            let mut out = Vec::new();
            let n = to_raw(&mut std::fs::File::open(&img).unwrap(), &mut out, |_, _| {}).unwrap();
            assert_eq!(n, expected.len() as u64, "{name}");
            assert!(out == expected, "{name} does not read back as its disk");
        }
    }

    #[test]
    fn what_this_reader_does_not_know_is_refused_by_name() {
        let Some(_) = qemu_img() else {
            eprintln!("qemu-img not installed: the qcow2 refusal test did not run");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let raw = sample(dir.path());
        let base = convert(dir.path(), &raw, "base.qcow2", &[]);
        let cases: [(&str, Vec<String>, &str); 3] = [
            ("backed.qcow2", vec!["-o".into(), format!("backing_file={},backing_fmt=qcow2", base.display())], "backing file"),
            ("zstd.qcow2", vec!["-c".into(), "-o".into(), "compression_type=zstd".into()], "compression type"),
            ("ext-l2.qcow2", vec!["-o".into(), "extended_l2=on".into()], "extended L2"),
        ];
        for (name, opts, why) in cases {
            let out = dir.path().join(name);
            let mut c = Command::new("qemu-img");
            if name == "backed.qcow2" {
                c.args(["create", "-f", "qcow2"]).args(&opts).arg(&out);
            } else {
                c.args(["convert", "-f", "raw", "-O", "qcow2"]).args(&opts).arg(&raw).arg(&out);
            }
            if !c.status().unwrap().success() {
                eprintln!("qemu-img could not make {name}; skipped");
                continue;
            }
            let err = to_raw(&mut std::fs::File::open(&out).unwrap(), &mut Vec::new(), |_, _| {}).err().unwrap();
            assert!(err.to_string().contains(why), "{name}: {err}");
        }
        let err = header(&mut &b"not an image"[..]).err().unwrap();
        assert!(err.to_string().contains("not a qcow2"));
    }
}

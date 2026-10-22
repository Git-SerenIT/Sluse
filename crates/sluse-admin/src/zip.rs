// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 SerenIT ApS and Prompted EV

//! The few lines of ZIP an `.intunewin` needs: entries stored or deflated,
//! a central directory, no encryption, no ZIP64.
//!
//! ponytail: no ZIP64, so an entry or an archive over 4 GiB is refused; the
//! MSI and the tenant package are far below it. Add ZIP64 if that changes.

use std::io::Write;

/// One file in the archive: its name with forward slashes, its bytes, and
/// whether to deflate them (already-encrypted bytes are stored).
pub struct Entry<'a> {
    pub name: &'a str,
    pub data: &'a [u8],
    pub deflate: bool,
}

pub fn write(entries: &[Entry<'_>]) -> Result<Vec<u8>, String> {
    let big = |n: usize| u32::try_from(n).map_err(|_| "over 4 GiB, which this writer does not do (no ZIP64)".to_owned());
    let mut out = Vec::new();
    let mut central = Vec::new();
    for e in entries {
        let mut crc = flate2::Crc::new();
        crc.update(e.data);
        let packed = if e.deflate {
            let mut z = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            z.write_all(e.data).map_err(|x| x.to_string())?;
            z.finish().map_err(|x| x.to_string())?
        } else {
            e.data.to_vec()
        };
        let method: u16 = if e.deflate { 8 } else { 0 };
        let (offset, csize, usize_, name) = (big(out.len())?, big(packed.len())?, big(e.data.len())?, e.name.as_bytes());
        // Version 2.0, the UTF-8 name flag, 1980-01-01 00:00.
        let common = |b: &mut Vec<u8>| {
            for v in [20u16, 0x0800, method, 0, 0x21] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            for v in [crc.sum(), csize, usize_] {
                b.extend_from_slice(&v.to_le_bytes());
            }
            b.extend_from_slice(&(name.len() as u16).to_le_bytes());
            b.extend_from_slice(&0u16.to_le_bytes());
        };
        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        common(&mut out);
        out.extend_from_slice(name);
        out.extend_from_slice(&packed);

        central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
        central.extend_from_slice(&20u16.to_le_bytes());
        common(&mut central);
        for v in [0u16, 0, 0] {
            central.extend_from_slice(&v.to_le_bytes());
        }
        central.extend_from_slice(&0u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name);
    }
    let (cd_offset, cd_size, n) = (big(out.len())?, big(central.len())?, entries.len() as u16);
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    for v in [0u16, 0, n, n] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.extend_from_slice(&cd_size.to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    big(out.len())?;
    Ok(out)
}

/// Read an archive this module wrote, or one like it: name and bytes per
/// entry, by its central directory, checking each CRC.
#[cfg(test)]
pub fn read(zip: &[u8]) -> Result<Vec<(String, Vec<u8>)>, String> {
    use std::io::Read;
    let u16_at = |i: usize| zip.get(i..i + 2).map(|b| u16::from_le_bytes([b[0], b[1]])).ok_or("truncated");
    let u32_at = |i: usize| zip.get(i..i + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or("truncated");
    let eocd = (0..zip.len().saturating_sub(21)).rev().find(|&i| u32_at(i) == Ok(0x0605_4b50)).ok_or("no end of central directory")?;
    let (n, mut p) = (u16_at(eocd + 10)? as usize, u32_at(eocd + 16)? as usize);
    let mut out = Vec::new();
    for _ in 0..n {
        if u32_at(p)? != 0x0201_4b50 {
            return Err("bad central directory".into());
        }
        let (method, crc, csize) = (u16_at(p + 10)?, u32_at(p + 16)?, u32_at(p + 20)? as usize);
        let (nlen, xlen, clen) = (u16_at(p + 28)? as usize, u16_at(p + 30)? as usize, u16_at(p + 32)? as usize);
        let local = u32_at(p + 42)? as usize;
        let name = String::from_utf8_lossy(zip.get(p + 46..p + 46 + nlen).ok_or("truncated")?).into_owned();
        let start = local + 30 + u16_at(local + 26)? as usize + u16_at(local + 28)? as usize;
        let packed = zip.get(start..start + csize).ok_or("truncated")?;
        let data = match method {
            0 => packed.to_vec(),
            8 => {
                let mut d = Vec::new();
                flate2::read::DeflateDecoder::new(packed).read_to_end(&mut d).map_err(|e| e.to_string())?;
                d
            }
            m => return Err(format!("compression method {m}")),
        };
        let mut c = flate2::Crc::new();
        c.update(&data);
        if c.sum() != crc {
            return Err(format!("{name}: CRC mismatch"));
        }
        out.push((name, data));
        p += 46 + nlen + xlen + clen;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_is_written_reads_back() {
        let big = vec![b'a'; 100_000];
        let z = write(&[
            Entry { name: "dir/a.txt", data: b"alpha", deflate: true },
            Entry { name: "b.bin", data: &big, deflate: false },
            Entry { name: "empty", data: b"", deflate: true },
        ])
        .unwrap();
        let back = read(&z).unwrap();
        assert_eq!(back[0], ("dir/a.txt".into(), b"alpha".to_vec()));
        assert_eq!(back[1].1, big);
        assert_eq!(back[2].1, b"");
    }
}

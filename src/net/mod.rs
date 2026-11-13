//! Network layer: proxy probes, subscription handling and update integrity.
//!
//! Implemented by the network-engineering branch. All protocol checks are
//! read-only; nothing here modifies the system at import time.
//!
//! Layers:
//! - [`links`] — structural parsing/validation of proxy links (`vless://`, …)
//! - [`proxy`] — DNS/TCP/TLS probes with explicit, honest verdicts
//! - [`manager`] — node store, ranking, filters and failover policy
//! - [`trust`] — SHA-256 / Ed25519 verification for releases
//!
//! Everything in this module is pure or reads files; no registry, no hosts,
//! no DNS changes.

// The manager/UI wiring lands separately; these types are the public API of
// the network layer, so unused-by-bin warnings here are noise.
#![allow(dead_code)]

pub mod links;
pub mod manager;
pub mod proxy;
pub mod trust;

use std::fs;
use std::io::{self, Write};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Seconds since the Unix epoch (0 when the clock is before 1970).
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Lowercase hex SHA-256 of a byte slice.
pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    hex(&h.finalize())
}

/// Lowercase hex SHA-256 of a file. Streams the file, so a 2 GB archive is fine.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut f = fs::File::open(path)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    const T: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(T[(b >> 4) as usize] as char);
        out.push(T[(b & 0x0f) as usize] as char);
    }
    out
}

/// Base64 decoder that accepts standard and URL-safe alphabets, optional
/// padding and embedded whitespace. Returns `None` on invalid characters.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => continue,
            c if c.is_ascii_whitespace() => continue,
            _ => return None,
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
        }
    }
    Some(out)
}

/// Base64 decoder restricted to UTF-8 text (configs and manifests).
pub fn b64_decode_text(s: &str) -> Option<String> {
    String::from_utf8(b64_decode(s)?).ok()
}

/// Standard base64 with padding, for signatures and small binary blobs.
pub fn b64_encode(bytes: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

/// Writes `data` to `path` atomically: a sibling temp file is flushed and
/// renamed over the destination. Windows refuses the rename while a reader
/// holds the file, so a few short retries are attempted.
///
/// An empty write still replaces the file; callers that must keep the old
/// content on empty input have to check that themselves (see
/// `modules::subs`).
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = parent.join(format!(
        ".{name}.tmp-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    {
        let mut f = fs::File::create(&tmp)?;
        f.write_all(data)?;
        f.flush()?;
        let _ = f.sync_all();
    }
    let mut last = None;
    for i in 0..8 {
        match fs::rename(&tmp, path) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                std::thread::sleep(Duration::from_millis(15 * (i + 1)));
            }
        }
    }
    let _ = fs::remove_file(&tmp);
    Err(last.unwrap_or_else(|| io::Error::other("rename failed")))
}

/// Short non-cryptographic but unpredictable-looking identifier: first 16 hex
/// chars of SHA-256 over the process, clock and a caller salt.
pub fn short_id(salt: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seed = format!("{}:{}:{}:{}", std::process::id(), nanos, salt, unix_now());
    let mut h = sha256_hex(seed.as_bytes());
    h.truncate(16);
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn base64_roundtrip_variants() {
        assert_eq!(b64_decode_text("SGVsbG8=").as_deref(), Some("Hello"));
        assert_eq!(b64_decode_text("SGVsbG8").as_deref(), Some("Hello"));
        assert_eq!(b64_decode_text("SGk_").as_deref(), Some("Hi?"));
        assert!(b64_decode_text("!!!").is_none());
    }

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("state.json");
        atomic_write(&p, b"one").unwrap();
        atomic_write(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        let temp_count = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(temp_count, 0);
    }

    #[test]
    fn sha256_file_matches_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.bin");
        fs::write(&p, b"abc").unwrap();
        assert_eq!(sha256_file(&p).unwrap(), sha256_hex(b"abc"));
    }
}

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::util;

/// The local subscription server is started once per process: repeated
/// "update subscription" clicks reuse the same URL instead of a new port.
static URL: OnceLock<Option<String>> = OnceLock::new();

pub fn start(path: PathBuf, title: &str) -> Option<String> {
    URL.get_or_init(|| start_inner(path, title)).clone()
}

/// Serves the subscription file over 127.0.0.1 for the lifetime of the process.
/// `GET /sub` (default) returns base64, `GET /sub.txt` returns plain links —
/// so both "base64 subscription" and "plain list" clients work.
fn start_inner(path: PathBuf, title: &str) -> Option<String> {
    let listener = TcpListener::bind("127.0.0.1:0").ok()?;
    let port = listener.local_addr().ok()?.port();
    let path = Arc::new(path);
    let title = Arc::new(title.to_string());

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut s = match stream {
                Ok(s) => s,
                Err(_) => continue,
            };
            let path = Arc::clone(&path);
            let title = Arc::clone(&title);
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]);
                let body = clean_body(&std::fs::read_to_string(path.as_ref()).unwrap_or_default());
                let plain = req.starts_with("GET /sub.txt") || req.starts_with("GET /sub/plain");
                let payload = if plain { body } else { util::base64(&body) };
                let title_b64 = util::base64(title.as_str());
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/plain; charset=utf-8\r\n\
                     Access-Control-Allow-Origin: *\r\n\
                     Cache-Control: no-store\r\n\
                     Profile-Title: base64:{title_b64}\r\n\
                     Profile-Update-Interval: 12\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n{}",
                    payload.len(),
                    payload
                );
                let _ = s.flush();
            });
        }
    });

    Some(format!("http://127.0.0.1:{port}/sub"))
}

/// Drops comments (`# 300 ms`) and empty lines: some clients treat them as
/// broken configs.
fn clean_body(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}
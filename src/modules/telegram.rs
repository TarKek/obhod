use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::modules::Ctx;
use crate::util;

const SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/fast/tg.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/verified/tg.txt",
];
const MAX_TEST: usize = 700;
const THREADS: usize = 96;

pub fn run(ctx: &Ctx) -> Result<()> {
    let client = util::http_client()?;
    let mut links: Vec<String> = Vec::new();
    for src in SOURCES {
        match util::get_text(&client, src) {
            Ok(body) => {
                let n = body.lines().filter(|l| l.contains("server=")).count();
                ctx.log(format!("Источник: {} — {} строк", short(src), n));
                links.extend(
                    body.lines()
                        .map(|l| l.trim().to_string())
                        .filter(|l| l.contains("server=")),
                );
            }
            Err(e) => ctx.log(format!("⚠ не удалось получить {}: {e}", short(src))),
        }
    }

    let mut seen = HashSet::new();
    let mut items: Vec<(String, u16, String)> = Vec::new();
    let mut skipped = 0usize;
    for l in links {
        let (server, port, link) = match parse_link(&l) {
            Some(v) => v,
            None => {
                skipped += 1;
                continue;
            }
        };
        if !seen.insert((server.clone(), port)) {
            continue;
        }
        items.push((server, port, link));
        if items.len() >= MAX_TEST {
            break;
        }
    }
    if skipped > 0 {
        ctx.log(format!(
            "Пропущено ссылок без корректного secret: {skipped}"
        ));
    }
    ctx.log(format!("Проверяю {} прокси (TCP) ...", items.len()));

    let queue = Arc::new(Mutex::new(VecDeque::from(items)));
    let (tx, rx) = std::sync::mpsc::channel::<(u128, String, String, u16)>();
    let mut handles = Vec::new();
    for _ in 0..THREADS.min(queue.lock().unwrap().len().max(1)) {
        let q = Arc::clone(&queue);
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || loop {
            let next = { q.lock().unwrap().pop_front() };
            let (server, port, link) = match next {
                Some(v) => v,
                None => break,
            };
            if let Some(ms) = probe(&server, port) {
                let _ = tx.send((ms, server, link, port));
            }
        }));
    }
    drop(tx);
    let mut alive: Vec<(u128, String, String, u16)> = rx.iter().collect();
    for h in handles {
        let _ = h.join();
    }
    alive.sort_by_key(|x| x.0);

    if alive.is_empty() {
        ctx.log("⚠ Ни один прокси не ответил. Попробуйте позже.");
        return Ok(());
    }

    let mut out = format!("# MTProto, проверено {}\n", crate::brand::name());
    for (ms, _server, link, _port) in &alive {
        out.push_str(&format!("{ms} ms  {link}\n"));
    }
    let path = ctx.data.join("mtproto.txt");
    std::fs::write(&path, out)?;
    ctx.log(format!(
        "✓ Живых: {} из {}. Список: {}",
        alive.len(),
        MAX_TEST,
        path.display()
    ));

    let (ms, server, link, _) = &alive[0];
    ctx.log(format!("Лучший: {server} — {ms} мс"));
    ctx.log("Применяю в Telegram (откроется подтверждение)...");
    if let Err(e) = util::open_url(link) {
        ctx.log(format!("⚠ не удалось открыть ссылку: {e}"));
    }
    Ok(())
}

fn short(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}

fn parse_link(l: &str) -> Option<(String, u16, String)> {
    if !l.starts_with("tg://proxy") && !l.starts_with("https://t.me/proxy") {
        return None;
    }
    let q = l.split_once('?')?.1;
    let mut server = None;
    let mut port = None;
    let mut secret = None;
    for part in q.split('&') {
        let (k, v) = match part.split_once('=') {
            Some(kv) => kv,
            None => continue,
        };
        match k {
            "server" => server = Some(v.trim().to_string()),
            "port" => port = v.trim().parse::<u16>().ok(),
            "secret" => secret = valid_secret(v),
            _ => {}
        }
    }
    let server = server.filter(|s| !s.is_empty())?;
    let port = port.filter(|p| *p > 0)?;
    let secret = secret?;
    Some((server.clone(), port, format!(
        "tg://proxy?server={server}&port={port}&secret={secret}"
    )))
}

/// Telegram calls a link "invalid proxy" when the secret is missing or
/// malformed, so only links with a real 16-byte secret are kept.
fn valid_secret(raw: &str) -> Option<String> {
    let s = percent_decode(raw.trim());
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let hex32 = s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit());
    let hex34 = s.len() == 34
        && (s.starts_with("dd") || s.starts_with("ee"))
        && s[2..].bytes().all(|b| b.is_ascii_hexdigit());
    if hex32 || hex34 {
        return Some(s.to_string());
    }
    // Some lists ship base64 / base64url secrets (16 bytes = 22 chars).
    let b64 = base64_bytes(s)?;
    if b64 >= 16 {
        return Some(s.to_string());
    }
    None
}

fn base64_bytes(s: &str) -> Option<usize> {
    let mut chars = 0usize;
    for c in s.bytes() {
        match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'-' | b'_' | b'=' => {
                chars += 1
            }
            _ => return None,
        }
    }
    chars.checked_mul(6).map(|bits| bits / 8)
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(h) = std::str::from_utf8(&b[i + 1..i + 3]) {
                if let Ok(v) = u8::from_str_radix(h, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn probe(host: &str, port: u16) -> Option<u128> {
    let addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
    for a in addrs {
        let t = Instant::now();
        if TcpStream::connect_timeout(&a, Duration::from_millis(1600)).is_ok() {
            return Some(t.elapsed().as_millis());
        }
    }
    None
}

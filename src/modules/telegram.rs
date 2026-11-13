//! MTProto proxies for Telegram.
//!
//! What is checked: the link structure, the secret format (Telegram rejects a
//! malformed secret with "invalid proxy"), DNS and TCP reachability with
//! latency. What is **not** implemented: the MTProto/obfuscated2 handshake.
//! An open port is therefore reported as "порт открыт, протокол не проверен"
//! and never as a proven working proxy.
//!
//! The previous good list (`data\mtproto.txt`) is kept when a run finds
//! nothing, and the file is written atomically.

use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::modules::Ctx;
use crate::net::links;
use crate::net::proxy::{self, ProbeConfig};
use crate::net::atomic_write;
use crate::util;

const SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/fast/tg.txt",
    "https://raw.githubusercontent.com/0xRadikal/Free-Telegram-Proxy/main/verified/tg.txt",
];
const MAX_TEST: usize = 700;
const THREADS: usize = 96;

#[derive(Clone, PartialEq, Eq)]
pub struct MtProxy {
    pub server: String,
    pub port: u16,
    /// Normalized secret (hex, lowercase).
    pub secret: String,
}

impl MtProxy {
    pub fn link(&self) -> String {
        format!(
            "tg://proxy?server={}&port={}&secret={}",
            self.server, self.port, self.secret
        )
    }

    /// Dedupe key: same endpoint and same secret.
    pub fn key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.server.to_ascii_lowercase(),
            self.port,
            self.secret
        )
    }
}

/// Debug output must not leak the proxy secret.
impl std::fmt::Debug for MtProxy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MtProxy")
            .field("server", &self.server)
            .field("port", &self.port)
            .field("secret", &"<hidden>")
            .finish()
    }
}

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
    let mut items: Vec<MtProxy> = Vec::new();
    let mut skipped = 0usize;
    for l in links {
        match parse_link(&l) {
            Some(p) => {
                if seen.insert(p.key()) {
                    items.push(p);
                }
            }
            None => skipped += 1,
        }
        if items.len() >= MAX_TEST {
            break;
        }
    }
    if skipped > 0 {
        ctx.log(format!(
            "Пропущено ссылок без корректного сервера/порта/секрета: {skipped}"
        ));
    }
    ctx.log(format!("Проверяю {} прокси (DNS + TCP) ...", items.len()));

    let cfg = ProbeConfig::fast();
    let queue = Arc::new(Mutex::new(VecDeque::from(items)));
    let (tx, rx) = std::sync::mpsc::channel::<Probe>();
    let mut handles = Vec::new();
    let workers = THREADS.min(queue.lock().unwrap().len().max(1));
    for _ in 0..workers {
        let q = Arc::clone(&queue);
        let tx = tx.clone();
        let cfg = cfg.clone();
        handles.push(std::thread::spawn(move || loop {
            let next = { q.lock().unwrap().pop_front() };
            let Some(p) = next else { break };
            let r = proxy::probe_mtproto(
                &p.server,
                p.port,
                Some(&p.secret),
                &cfg,
            );
            let msg = Probe {
                ms: r.latency_ms.unwrap_or(u64::MAX),
                ok: r.tcp_ok,
                proxy: p,
                summary: r.summary_ru(),
            };
            if tx.send(msg).is_err() {
                break;
            }
        }));
    }
    drop(tx);
    let all: Vec<Probe> = rx.iter().collect();
    for h in handles {
        let _ = h.join();
    }
    let tested = all.len();
    let mut alive: Vec<Probe> = all.into_iter().filter(|p| p.ok).collect();
    alive.sort_by_key(|p| p.ms);
    let dead = tested.saturating_sub(alive.len());

    if alive.is_empty() {
        let prev = count_links(&ctx.data.join("mtproto.txt"));
        if prev > 0 {
            ctx.log(format!(
                "⚠ Ни один прокси не ответил (проверено {tested}). Оставляю прежний список: {prev}."
            ));
        } else {
            ctx.log(format!(
                "⚠ Ни один прокси не ответил (проверено {tested}). Прежнего списка нет."
            ));
        }
        return Ok(());
    }

    // Re-check the finalists with a longer timeout: the top of the list is what
    // the user actually opens, so it deserves a second attempt.
    let deep = ProbeConfig::deep();
    let finalists: Vec<Probe> = alive.iter().take(5).cloned().collect();
    let mut verified: Vec<Probe> = Vec::new();
    for p in &finalists {
        let r = proxy::probe_mtproto(&p.proxy.server, p.proxy.port, Some(&p.proxy.secret), &deep);
        if r.tcp_ok {
            verified.push(Probe {
                ms: r.latency_ms.unwrap_or(p.ms),
                ok: true,
                proxy: p.proxy.clone(),
                summary: r.summary_ru(),
            });
        } else {
            ctx.log(format!(
                "  ⚠ {}:{} не прошёл повторную проверку: {}",
                p.proxy.server,
                p.proxy.port,
                r.summary_ru()
            ));
        }
    }
    verified.sort_by_key(|p| p.ms);
    if verified.is_empty() {
        let prev = count_links(&ctx.data.join("mtproto.txt"));
        ctx.log(format!(
            "⚠ Повторная проверка не удалась. Оставляю прежний список ({prev})."
        ));
        return Ok(());
    }

    let mut out = format!("# MTProto, проверено {}\n", crate::brand::name());
    out.push_str("# TCP-доступность; протокол MTProto не проверялся (handshake не реализован)\n");
    for p in &alive {
        out.push_str(&format!("{} ms  {}\n", p.ms, p.proxy.link()));
    }
    atomic_write(&ctx.data.join("mtproto.txt"), out.as_bytes())?;

    ctx.log(format!(
        "✓ Порт открыт у {} из {}. Не ответили: {dead}. Список: {}",
        alive.len(),
        tested,
        ctx.data.join("mtproto.txt").display()
    ));
    ctx.log(
        "  Важно: открытый порт не гарантирует рабочий секрет — MTProto-handshake не выполняется.",
    );

    let best = &verified[0];
    ctx.log(format!(
        "Лучший: {}:{} — {} мс ({})",
        best.proxy.server, best.proxy.port, best.ms, best.summary
    ));
    ctx.log("Применяю в Telegram (откроется подтверждение)...");
    if let Err(e) = util::open_url(&best.proxy.link()) {
        ctx.log(format!("⚠ не удалось открыть ссылку: {e}"));
    }
    Ok(())
}

fn short(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}

fn count_links(path: &std::path::Path) -> usize {
    std::fs::read_to_string(path)
        .map(|t| {
            t.lines()
                .filter(|l| {
                    let l = l.trim();
                    l.contains("tg://proxy") || l.contains("t.me/proxy")
                })
                .count()
        })
        .unwrap_or(0)
}

#[derive(Clone)]
struct Probe {
    ms: u64,
    ok: bool,
    proxy: MtProxy,
    summary: String,
}

/// Parses `tg://proxy?...` and `https://t.me/proxy?...` links. Returns `None`
/// for anything with a missing/zero port or a malformed secret, matching what
/// Telegram itself would reject.
pub fn parse_link(l: &str) -> Option<MtProxy> {
    let l = l.trim();
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
    let server = server.filter(|s| {
        !s.is_empty() && !s.chars().any(|c| c.is_whitespace() || c == '/')
    })?;
    let port = port.filter(|p| *p > 0)?;
    Some(MtProxy {
        server,
        port,
        secret: secret?,
    })
}

/// Telegram calls a link "invalid proxy" when the secret is missing or
/// malformed, so only links with a real 16-byte secret are kept.
pub fn valid_secret(raw: &str) -> Option<String> {
    links::normalize_mtproto_secret(raw)
}

/// Re-exported for callers that want a probe without parsing Telegram sources.
pub fn probe(host: &str, port: u16, secret: &str, cfg: &ProbeConfig) -> proxy::ProbeResult {
    proxy::probe_mtproto(host, port, Some(secret), cfg)
}

/// Default probe budget for a single proxy in the check screen.
pub fn default_probe_config() -> ProbeConfig {
    ProbeConfig {
        connect_timeout: Duration::from_millis(1200),
        read_timeout: Duration::from_millis(1200),
        attempts: 2,
        ..ProbeConfig::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_hex_and_prefixed_secrets() {
        let a = parse_link(
            "tg://proxy?server=1.2.3.4&port=443&secret=0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(a.server, "1.2.3.4");
        assert_eq!(a.port, 443);
        assert_eq!(a.secret, "0123456789abcdef0123456789abcdef");

        let b = parse_link(
            "https://t.me/proxy?server=proxy.example&port=8443&secret=dd0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        assert_eq!(b.server, "proxy.example");
        assert!(b.link().starts_with("tg://proxy?server=proxy.example&port=8443"));

        // base64 secret (16 bytes) is normalized to hex
        let b64 = util::base64("\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}\u{8}\u{9}\u{10}\u{11}\u{12}\u{13}\u{14}\u{15}\u{16}");
        let c = parse_link(&format!("tg://proxy?server=h&port=1&secret={b64}")).unwrap();
        assert_eq!(c.secret, "01020304050607080910111213141516");
    }

    #[test]
    fn rejects_invalid_links() {
        assert!(parse_link("tg://proxy?server=1.2.3.4&port=0&secret=0123456789abcdef0123456789abcdef").is_none());
        assert!(parse_link("tg://proxy?server=1.2.3.4&port=443&secret=zz").is_none());
        assert!(parse_link("tg://proxy?port=443&secret=0123456789abcdef0123456789abcdef").is_none());
        assert!(parse_link("vless://x@h:443").is_none());
        assert!(parse_link("").is_none());
    }

    #[test]
    fn duplicates_are_removed_by_secret_and_endpoint() {
        let a = parse_link("tg://proxy?server=H&port=443&secret=0123456789abcdef0123456789abcdef").unwrap();
        let b = parse_link("tg://proxy?server=h&port=443&secret=0123456789abcdef0123456789abcdef").unwrap();
        assert_eq!(a.key(), b.key());
        let c = parse_link("tg://proxy?server=h&port=443&secret=0123456789abcdef0123456789abcdee").unwrap();
        assert_ne!(a.key(), c.key());
    }

    #[test]
    fn debug_hides_the_secret() {
        let p = parse_link("tg://proxy?server=h&port=443&secret=0123456789abcdef0123456789abcdef").unwrap();
        let text = format!("{p:?}");
        assert!(!text.contains("0123456789abcdef"));
        assert!(text.contains("<hidden>"));
    }

    #[test]
    fn valid_secret_accepts_what_telegram_accepts() {
        assert!(valid_secret("0123456789abcdef0123456789abcdef").is_some());
        assert!(valid_secret("ee0123456789abcdef0123456789abcdef").is_some());
        assert!(valid_secret("0123456789").is_none());
        assert!(valid_secret("%30%31%32%33%34%35%36%37%38%39abcdef0123456789abcdef").is_some());
    }
}
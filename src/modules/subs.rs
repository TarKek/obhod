use anyhow::Result;
use std::collections::{HashSet, VecDeque};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::modules::Ctx;
use crate::util;

const DEFAULT_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix",
];
const MAX_TEST: usize = 420;
const THREADS: usize = 80;

pub fn run(ctx: &Ctx) -> Result<()> {
    let client = util::http_client()?;

    let mut sources: Vec<String> = DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect();
    let extra = ctx.data.join("subs_sources.txt");
    if let Ok(text) = std::fs::read_to_string(&extra) {
        for l in text.lines() {
            let l = l.trim();
            if l.starts_with("http") {
                sources.push(l.to_string());
            }
        }
    }
    if ctx.opts.components.subs {
        ctx.log(format!("Источников подписок: {}", sources.len()));
    }

    let mut configs: Vec<String> = Vec::new();
    for src in &sources {
        match util::get_text(&client, src) {
            Ok(body) => {
                let body = maybe_b64(&body);
                let n = body
                    .lines()
                    .filter(|l| {
                        l.starts_with("vless://")
                            || l.starts_with("trojan://")
                            || l.starts_with("vmess://")
                    })
                    .count();
                ctx.log(format!("{} — {} конфигов", short(src), n));
                configs.extend(body.lines().map(|s| s.trim().to_string()));
            }
            Err(e) => ctx.log(format!("⚠ {} — {e}", short(src))),
        }
    }

    let mut seen = HashSet::new();
    let mut items: Vec<(String, u16, String)> = Vec::new();
    for c in configs {
        let parsed = if c.starts_with("vless://") || c.starts_with("trojan://") {
            parse_url_cfg(&c)
        } else if c.starts_with("vmess://") {
            parse_vmess(&c)
        } else {
            None
        };
        if let Some((h, p)) = parsed {
            if seen.insert((h.clone(), p)) {
                items.push((h, p, c));
            }
        }
        if items.len() >= MAX_TEST {
            break;
        }
    }
    ctx.log(format!("Проверяю {} узлов (TCP) ...", items.len()));

    let queue = Arc::new(Mutex::new(VecDeque::from(items)));
    let (tx, rx) = std::sync::mpsc::channel::<(u128, String, String)>();
    let mut handles = Vec::new();
    for _ in 0..THREADS.min(queue.lock().unwrap().len().max(1)) {
        let q = Arc::clone(&queue);
        let tx = tx.clone();
        handles.push(std::thread::spawn(move || loop {
            let next = { q.lock().unwrap().pop_front() };
            let (h, p, link) = match next {
                Some(v) => v,
                None => break,
            };
            if let Some((ms, ip)) = probe(&h, p) {
                let _ = tx.send((ms, link, ip.to_string()));
            }
        }));
    }
    drop(tx);
    let mut alive: Vec<(u128, String, String)> = rx.iter().collect();
    for h in handles {
        let _ = h.join();
    }
    alive.sort_by_key(|x| x.0);

    if alive.is_empty() {
        ctx.log("⚠ Ни один узел не ответил. Попробуйте позже.");
        std::fs::write(ctx.data.join("subs_alive.txt"), "")?;
        std::fs::write(ctx.data.join("subs_alive_plain.txt"), "")?;
        return Ok(());
    }

    // Keep only the 2 fastest nodes per country and rename them for the brand.
    let ips: Vec<String> = {
        let mut set = HashSet::new();
        alive.iter().filter(|n| set.insert(n.2.clone())).map(|n| n.2.clone()).collect()
    };
    let geo = lookup_countries(&ips);
    if geo.is_empty() {
        ctx.log("⚠ Не удалось определить страны — оставляю все живые узлы.");
    }
    let nodes = pick_two_per_country(&alive, &geo, !geo.is_empty());
    let shown = nodes.len();

    let out_path = ctx.data.join("subs_alive.txt");
    let text: String = nodes
        .iter()
        .map(|(ms, l)| format!("# {ms} ms\n{l}\n"))
        .collect();
    std::fs::write(&out_path, text)?;

    let plain = ctx.data.join("subs_alive_plain.txt");
    let plain_text: String = nodes.iter().map(|(_, l)| format!("{l}\n")).collect();
    std::fs::write(&plain, plain_text)?;

    ctx.log(format!(
        "✓ Живых узлов: {} из {}. Отобрано {} (по 2 быстрейших с каждой страны): {}",
        alive.len(),
        MAX_TEST,
        shown,
        out_path.display()
    ));
    let mut countries: Vec<String> = Vec::new();
    for (_, l) in &nodes {
        let t = node_title(l);
        if !t.is_empty() && !countries.contains(&t) {
            countries.push(t);
        }
    }
    if !countries.is_empty() {
        ctx.log(format!("  {}", countries.join(" · ")));
    }
    if let Some((ms, _)) = nodes.first() {
        ctx.log(format!("Лучший узел: {ms} мс"));
    }
    Ok(())
}

fn short(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}

fn maybe_b64(s: &str) -> String {
    let t = s.trim();
    if t.contains("://") {
        return s.to_string();
    }
    // some sources return base64 subscription; decode without extra deps
    match b64decode(t) {
        Some(v) if v.contains("://") => v,
        _ => s.to_string(),
    }
}

fn b64decode(s: &str) -> Option<String> {
    let mut out = Vec::new();
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
    String::from_utf8(out).ok()
}

/// `vmess://<base64 json>`: only host/port are needed for the TCP probe.
fn parse_vmess(c: &str) -> Option<(String, u16)> {
    let raw = c.strip_prefix("vmess://")?;
    let json = b64decode(raw)?;
    let v: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
    let host = v["add"].as_str()?.trim().to_string();
    let port = match &v["port"] {
        serde_json::Value::Number(n) => u16::try_from(n.as_u64()?).ok()?,
        serde_json::Value::String(s) => s.trim().parse::<u16>().ok()?,
        _ => return None,
    };
    if host.is_empty() || port == 0 {
        return None;
    }
    Some((host, port))
}

fn parse_url_cfg(c: &str) -> Option<(String, u16)> {
    let rest = c.split_once("://")?.1;
    let at = rest.rfind('@')?;
    let authority = &rest[at + 1..];
    let hostport = authority
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(authority);
    let (h, p) = if let Some(stripped) = hostport.strip_prefix('[') {
        // [ipv6]:port
        let end = stripped.find(']')?;
        let h = &stripped[..end];
        let p = stripped[end + 1..].strip_prefix(':')?;
        (h.to_string(), p.parse::<u16>().ok()?)
    } else {
        let (h, p) = hostport.rsplit_once(':')?;
        (h.to_string(), p.parse::<u16>().ok()?)
    };
    if h.is_empty() {
        return None;
    }
    Some((h, p))
}

fn probe(host: &str, port: u16) -> Option<(u128, std::net::IpAddr)> {
    let addrs: Vec<_> = (host, port).to_socket_addrs().ok()?.collect();
    for a in addrs {
        let t = Instant::now();
        if TcpStream::connect_timeout(&a, Duration::from_millis(1500)).is_ok() {
            return Some((t.elapsed().as_millis(), a.ip()));
        }
    }
    None
}

/// Country per IP via the free ip-api batch endpoint (100 IPs per request).
/// Returns an empty map when the service is unreachable, so callers can keep
/// all nodes instead of dropping them.
fn lookup_countries(ips: &[String]) -> std::collections::HashMap<String, (String, String)> {
    use std::collections::HashMap;
    let mut out = HashMap::new();
    let client = match reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("obhod/0.1")
        .build()
    {
        Ok(c) => c,
        Err(_) => return out,
    };
    for chunk in ips.chunks(100) {
        let body = match serde_json::to_string(chunk) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let resp = client
            .post("http://ip-api.com/batch?fields=status,countryCode,country&lang=ru")
            .header("Content-Type", "application/json")
            .body(body)
            .send();
        let arr: Vec<serde_json::Value> = match resp.and_then(|r| r.json()) {
            Ok(a) => a,
            Err(_) => continue,
        };
        for (i, v) in arr.iter().enumerate() {
            if v["status"] != "success" {
                continue;
            }
            let code = v["countryCode"].as_str().unwrap_or("").to_uppercase();
            let name = v["country"].as_str().unwrap_or("").to_string();
            if code.is_empty() || name.is_empty() {
                continue;
            }
            if let Some(ip) = chunk.get(i) {
                out.insert(ip.clone(), (code, name));
            }
        }
    }
    out
}

/// Two fastest nodes per country; unknown countries form their own bucket.
/// `filter` = false keeps every alive node (geo lookup failed entirely).
fn pick_two_per_country(
    alive: &[(u128, String, String)],
    geo: &std::collections::HashMap<String, (String, String)>,
    filter: bool,
) -> Vec<(u128, String)> {
    use std::collections::HashMap;
    if !filter {
        return alive
            .iter()
            .map(|(ms, link, _)| (*ms, rename_link(link, &brand_name("", ""))))
            .collect();
    }
    let mut buckets: HashMap<String, Vec<(u128, String)>> = HashMap::new();
    let mut names: HashMap<String, String> = HashMap::new();
    for (ms, link, ip) in alive {
        let (code, country) = geo
            .get(ip)
            .cloned()
            .unwrap_or_else(|| ("ZZ".to_string(), "Другая страна".to_string()));
        names.insert(code.clone(), country);
        buckets.entry(code).or_default().push((*ms, link.clone()));
    }
    let mut out: Vec<(u128, String)> = Vec::new();
    for (code, mut nodes) in buckets {
        nodes.sort_by_key(|n| n.0);
        nodes.truncate(2);
        let country = names.get(&code).map(String::as_str).unwrap_or("");
        for (ms, link) in nodes {
            out.push((ms, rename_link(&link, &brand_name(&code, country))));
        }
    }
    out.sort_by_key(|n| n.0);
    out
}

/// `🇩🇪 Германия | obhod` — the format lives in `brand.json`.
fn brand_name(code: &str, country: &str) -> String {
    let flag = flag_emoji(code);
    crate::brand::server_name(&flag, code, country)
}

fn flag_emoji(code: &str) -> String {
    if code.len() == 2 && code.bytes().all(|b| b.is_ascii_alphabetic()) {
        code.chars()
            .filter_map(|c| {
                char::from_u32(0x1F1E6 + (c.to_ascii_uppercase() as u32 - 'A' as u32))
            })
            .collect()
    } else {
        "🌐".to_string()
    }
}

/// Replaces the display name of a config (URI fragment or vmess `ps`).
fn rename_link(link: &str, name: &str) -> String {
    if let Some(rest) = link.strip_prefix("vmess://") {
        if let Some(decoded) = b64decode(rest) {
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(decoded.trim()) {
                v["ps"] = serde_json::Value::String(name.to_string());
                if let Ok(s) = serde_json::to_string(&v) {
                    return format!("vmess://{}", crate::util::base64(&s));
                }
            }
        }
        return link.to_string();
    }
    let base = link.split('#').next().unwrap_or(link);
    format!("{}#{}", base, percent_encode(name))
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Human title of a renamed node, for logs.
fn node_title(link: &str) -> String {
    if let Some(rest) = link.strip_prefix("vmess://") {
        let decoded = b64decode(rest).unwrap_or_default();
        let v: serde_json::Value = serde_json::from_str(decoded.trim()).unwrap_or_default();
        return v["ps"].as_str().unwrap_or("").to_string();
    }
    link.split_once('#')
        .map(|(_, n)| percent_decode_fragment(n))
        .unwrap_or_default()
}

fn percent_decode_fragment(s: &str) -> String {
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

#[allow(dead_code)]
fn _p() -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        crate::util::base64(s)
    }

    #[test]
    fn vmess_parses_host_and_port() {
        let json = r#"{"v":"2","ps":"t","add":"1.2.3.4","port":"443","id":"x"}"#;
        let link = format!("vmess://{}", b64(json));
        assert_eq!(parse_vmess(&link), Some(("1.2.3.4".into(), 443)));
    }

    #[test]
    fn vmess_accepts_numeric_port_and_rejects_garbage() {
        let json = r#"{"add":"example.org","port":8443}"#;
        assert_eq!(
            parse_vmess(&format!("vmess://{}", b64(json))),
            Some(("example.org".into(), 8443))
        );
        assert_eq!(parse_vmess("vmess://!!!not-base64!!!"), None);
        assert_eq!(parse_vmess("vmess://"), None);
    }

    #[test]
    fn url_cfg_handles_names_and_ipv6() {
        assert_eq!(
            parse_url_cfg("vless://u@example.org:2053?x=1#n"),
            Some(("example.org".into(), 2053))
        );
        assert_eq!(
            parse_url_cfg("trojan://u@[2001:db8::1]:443#n"),
            Some(("2001:db8::1".into(), 443))
        );
        assert_eq!(parse_url_cfg("not-a-link"), None);
    }

    #[test]
    fn base64_decoder_accepts_url_safe() {
        assert_eq!(b64decode("SGVsbG8").as_deref(), Some("Hello"));
        assert_eq!(b64decode("SGk_").as_deref(), Some("Hi?"));
    }

    #[test]
    fn flag_emoji_from_country_code() {
        assert_eq!(flag_emoji("DE"), "🇩🇪");
        assert_eq!(flag_emoji(""), "🌐");
        assert_eq!(flag_emoji("ZZZ"), "🌐");
    }

    #[test]
    fn rename_replaces_fragment_and_vmess_name() {
        let l = rename_link("vless://u@1.2.3.4:443?x=1#old", "🇩🇪 | Германия | obhod");
        assert!(l.starts_with("vless://u@1.2.3.4:443?x=1#"));
        assert_eq!(node_title(&l), "🇩🇪 | Германия | obhod");

        let json = r#"{"add":"1.2.3.4","port":443,"ps":"old"}"#;
        let vm = format!("vmess://{}", b64(json));
        let renamed = rename_link(&vm, "🇩🇪 | Германия | obhod");
        assert_eq!(node_title(&renamed), "🇩🇪 | Германия | obhod");
        assert!(parse_vmess(&renamed).is_some());
    }

    #[test]
    fn two_fastest_per_country() {
        use std::collections::HashMap;
        let alive = vec![
            (10u128, "vless://u@1.1.1.1:443#a".to_string(), "1.1.1.1".to_string()),
            (20, "vless://u@1.1.1.2:443#b".to_string(), "1.1.1.2".to_string()),
            (30, "vless://u@1.1.1.3:443#c".to_string(), "1.1.1.3".to_string()),
            (40, "vless://u@2.2.2.2:443#d".to_string(), "2.2.2.2".to_string()),
        ];
        let mut geo = HashMap::new();
        geo.insert("1.1.1.1".to_string(), ("DE".to_string(), "Германия".to_string()));
        geo.insert("1.1.1.2".to_string(), ("DE".to_string(), "Германия".to_string()));
        geo.insert("1.1.1.3".to_string(), ("DE".to_string(), "Германия".to_string()));
        geo.insert("2.2.2.2".to_string(), ("NL".to_string(), "Нидерланды".to_string()));
        let picked = pick_two_per_country(&alive, &geo, true);
        assert_eq!(picked.len(), 3);
        let titles: Vec<String> = picked.iter().map(|(_, l)| node_title(l)).collect();
        assert_eq!(titles.iter().filter(|t| t.contains("Германия")).count(), 2);
        assert_eq!(titles.iter().filter(|t| t.contains("Нидерланды")).count(), 1);
    }
}

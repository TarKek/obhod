//! Free VLESS/Trojan/VMess subscriptions: fetch, validate, probe, select.
//!
//! Safety properties:
//!
//! - **Last Known Good**: an empty or broken run never overwrites a previously
//!   working list. `subs_alive.txt` / `subs_alive_plain.txt` are only rewritten
//!   when at least one node survived the checks.
//! - **Atomic writes**: temp file + rename, so a half-written list is never
//!   visible to the VPN client or to the local subscription server.
//! - **Honest probing**: TCP is separated from TLS; a node is only marked
//!   `TLS подтверждён` when a TLS ServerHello came back. VLESS/Trojan/VMess
//!   authentication is not implemented (see `net::proxy`).
//! - Shadowsocks/Hysteria2/TUIC links are structurally validated and skipped
//!   for the client subscription (they need a different client and are marked
//!   as such in the stats).
//!
//! Files written (all inside `data\`):
//! - `subs_alive.txt` — `# <ms> ms` + link, for humans and logs;
//! - `subs_alive_plain.txt` — links only, for clients (unchanged format);
//! - `subs_state.json` — counts of the last run (no secrets).

use anyhow::Result;
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::modules::Ctx;
use crate::net::links::{self, LinkInfo};
use crate::net::proxy::{self, ProbeConfig};
use crate::net::{self, atomic_write};
use crate::util;

const DEFAULT_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/ALIILAPRO/v2rayNG-Config/main/server.txt",
    "https://raw.githubusercontent.com/mahdibland/V2RayAggregator/master/sub/sub_merge.txt",
    "https://raw.githubusercontent.com/MhdiTaheri/V2rayCollector/main/sub/mix",
];
const MAX_TEST: usize = 420;
const THREADS: usize = 80;
const PER_COUNTRY: usize = 2;

#[derive(Default, Clone, Debug)]
struct Stats {
    sources_total: usize,
    sources_ok: usize,
    sources_failed: usize,
    fetched: usize,
    invalid: usize,
    external: usize,
    duplicate: usize,
    unique: usize,
    tested: usize,
    alive: usize,
    tls_ok: usize,
    dead: usize,
    selected: usize,
    kept_previous: usize,
}

pub fn run(ctx: &Ctx) -> Result<()> {
    std::fs::create_dir_all(&ctx.data)?;
    let client = util::http_client()?;
    let sources = collect_sources(&ctx.data);
    let mut stats = Stats {
        sources_total: sources.len(),
        ..Stats::default()
    };
    if ctx.opts.components.subs {
        ctx.log(format!("Источников подписок: {}", sources.len()));
    }

    let mut fetched: Vec<String> = Vec::new();
    for src in &sources {
        match fetch_source(&client, src) {
            Ok(body) => {
                let body = maybe_b64(&body);
                let links = collect_links(&body);
                stats.sources_ok += 1;
                stats.fetched += links.len();
                ctx.log(format!("{} — {} конфигов", short(src), links.len()));
                fetched.extend(links);
            }
            Err(e) => {
                stats.sources_failed += 1;
                ctx.log(format!("⚠ {} — {e}", short(src)));
            }
        }
    }

    let batch = dedupe_and_filter(fetched);
    stats.invalid = batch.invalid;
    stats.external = batch.external;
    stats.duplicate = batch.duplicate;
    stats.unique = batch.items.len();
    if stats.invalid > 0 || stats.external > 0 {
        ctx.log(format!(
            "Разбор: {} уникальных, {} некорректных, {} внешних (ss/hysteria2/tuic)",
            stats.unique, stats.invalid, stats.external
        ));
    }
    if batch.items.is_empty() {
        keep_previous(ctx, &stats, "в источниках нет разобранных узлов");
        return Ok(());
    }

    ctx.progress(40, "серверы: проверка".to_string());
    ctx.log(format!(
        "Проверяю {} узлов (TCP, TLS где заявлен) ...",
        batch.items.len()
    ));

    let cfg = ProbeConfig::fast();
    let queue = Arc::new(Mutex::new(VecDeque::from(batch.items)));
    let (tx, rx) = std::sync::mpsc::channel::<Alive>();
    let mut handles = Vec::new();
    let workers = THREADS.min(queue.lock().unwrap().len().max(1));
    for _ in 0..workers {
        let q = Arc::clone(&queue);
        let tx = tx.clone();
        let cfg = cfg.clone();
        handles.push(std::thread::spawn(move || loop {
            let next = { q.lock().unwrap().pop_front() };
            let Some(cand) = next else { break };
            let r = proxy::probe_info(&cand.info, &cfg);
            let msg = Alive {
                ms: r.latency_ms.unwrap_or(0) as u128,
                link: cand.link,
                ip: r.endpoint_ip.map(|i| i.to_string()),
                tls_verified: r.tls_verified,
                verdict: r.verdict,
                summary: r.summary_ru(),
            };
            if tx.send(msg).is_err() {
                break;
            }
        }));
    }
    drop(tx);
    let all: Vec<Alive> = rx.iter().collect();
    for h in handles {
        let _ = h.join();
    }
    stats.tested = all.len();
    stats.dead = all.iter().filter(|a| !a.verdict.alive()).count();
    let mut dead_examples: Vec<String> = Vec::new();
    for a in all.iter().filter(|a| !a.verdict.alive()) {
        if dead_examples.len() >= 3 {
            break;
        }
        if !a.summary.is_empty() && !dead_examples.contains(&a.summary) {
            dead_examples.push(a.summary.clone());
        }
    }
    let mut alive: Vec<Alive> = all.into_iter().filter(|a| a.verdict.alive()).collect();
    stats.alive = alive.len();
    stats.tls_ok = alive.iter().filter(|a| a.tls_verified).count();
    alive.sort_by_key(|a| a.ms);

    if alive.is_empty() {
        keep_previous(ctx, &stats, "ни один узел не ответил (TCP/TLS)");
        return Ok(());
    }

    // Keep only the fastest nodes per country and rename them for the brand.
    let ips: Vec<String> = {
        let mut set = HashSet::new();
        alive
            .iter()
            .filter_map(|n| n.ip.clone())
            .filter(|ip| set.insert(ip.clone()))
            .collect()
    };
    let geo = lookup_countries(&client, &ips);
    if geo.is_empty() {
        ctx.log("⚠ Не удалось определить страны — оставляю все живые узлы.");
    }
    let nodes = pick_two_per_country(&alive, &geo, !geo.is_empty());
    stats.selected = nodes.len();

    let save = save_alive(&ctx.data, &nodes)?;
    if let SaveOutcome::KeptPrevious(n) = save {
        stats.kept_previous = n;
        let _ = write_state(&ctx.data, &stats, true);
        return Ok(());
    }
    write_state(&ctx.data, &stats, false)?;

    ctx.log(format!(
        "✓ Живых узлов: {} из {} проверенных (TLS-ответ получен у {}; {} не ответили). Отобрано {}: по {} с каждой страны.",
        stats.alive, stats.tested, stats.tls_ok, stats.dead, stats.selected, PER_COUNTRY
    ));
    ctx.log(format!(
        "  Источники: {}/{} · разобрано {} · дублей {} · некорректных {}",
        stats.sources_ok, stats.sources_total, stats.unique, stats.duplicate, stats.invalid
    ));
    if !dead_examples.is_empty() {
        ctx.log(format!(
            "  Примеры отказов (всего {}): {}",
            stats.dead,
            dead_examples.join(" · ")
        ));
    }
    ctx.log(
        "  Проверка честная: открытый порт — это не «рабочий прокси», вход в узел не проверялся.",
    );
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

/// Previous list is kept when the new run produced nothing. Returns how many
/// nodes were preserved (0 when there was no previous list either).
fn keep_previous(ctx: &Ctx, stats: &Stats, why: &str) -> usize {
    let prev = count_plain_nodes(&ctx.data);
    if prev > 0 {
        ctx.log(format!(
            "⚠ {why}. Оставляю прежний список: {prev} узлов (проверено {} из {}).",
            stats.tested, stats.unique
        ));
    } else {
        ctx.log(format!(
            "⚠ {why}. Прежнего списка нет — файлы не изменены (проверено {} из {}).",
            stats.tested, stats.unique
        ));
    }
    let mut s = stats.clone();
    s.kept_previous = prev;
    let _ = write_state(&ctx.data, &s, true);
    prev
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

fn collect_sources(data: &Path) -> Vec<String> {
    let mut v: Vec<String> = DEFAULT_SOURCES.iter().map(|s| s.to_string()).collect();
    if let Ok(text) = std::fs::read_to_string(data.join("subs_sources.txt")) {
        for l in text.lines() {
            let l = l.trim();
            if l.starts_with("http://") || l.starts_with("https://") {
                v.push(l.to_string());
            }
        }
    }
    let mut seen = HashSet::new();
    v.retain(|s| seen.insert(s.clone()));
    v
}

/// Two attempts for transient errors; no long retry storms in the setup flow.
fn fetch_source(client: &reqwest::blocking::Client, url: &str) -> Result<String> {
    let mut last = None;
    for attempt in 0..2 {
        match util::get_text(client, url) {
            Ok(body) => return Ok(body),
            Err(e) => {
                last = Some(e);
                if attempt == 0 {
                    std::thread::sleep(Duration::from_millis(250));
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("пустой ответ")))
}

fn short(s: &str) -> String {
    s.rsplit('/').next().unwrap_or(s).to_string()
}

/// Some sources return a base64 subscription instead of plain lines.
fn maybe_b64(s: &str) -> String {
    let t = s.trim();
    if t.contains("://") {
        return s.to_string();
    }
    match net::b64_decode_text(t) {
        Some(v) if v.contains("://") => v,
        _ => s.to_string(),
    }
}

const SCHEMES: &[&str] = &[
    "vless://",
    "trojan://",
    "vmess://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "tuic://",
];

fn collect_links(body: &str) -> Vec<String> {
    body.lines()
        .map(|l| l.trim().trim_start_matches('\u{feff}'))
        .filter(|l| SCHEMES.iter().any(|s| l.starts_with(s)))
        .map(str::to_string)
        .collect()
}

struct Candidate {
    link: String,
    info: LinkInfo,
}

#[derive(Default)]
struct ParseBatch {
    items: Vec<Candidate>,
    seen: usize,
    invalid: usize,
    duplicate: usize,
    external: usize,
}

/// Structural validation + dedupe by normalized key. External protocols are
/// counted but not queued: they need a client we do not implement.
fn dedupe_and_filter(links: impl IntoIterator<Item = String>) -> ParseBatch {
    let mut batch = ParseBatch::default();
    let mut seen: HashSet<String> = HashSet::new();
    for link in links {
        batch.seen += 1;
        let info = match links::parse(&link) {
            Ok(i) => i,
            Err(_) => {
                batch.invalid += 1;
                continue;
            }
        };
        if info.external {
            batch.external += 1;
            continue;
        }
        if !seen.insert(info.key.clone()) {
            batch.duplicate += 1;
            continue;
        }
        batch.items.push(Candidate {
            link: link.trim().to_string(),
            info,
        });
        if batch.items.len() >= MAX_TEST {
            break;
        }
    }
    batch
}

// ---------------------------------------------------------------------------
// Results, Last Known Good, atomic writes
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Alive {
    ms: u128,
    link: String,
    ip: Option<String>,
    tls_verified: bool,
    verdict: proxy::Verdict,
    summary: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SaveOutcome {
    Written(usize),
    KeptPrevious(usize),
    Nothing,
}

fn save_alive(data: &Path, nodes: &[(u128, String)]) -> Result<SaveOutcome> {
    if nodes.is_empty() {
        let prev = count_plain_nodes(data);
        return Ok(if prev > 0 {
            SaveOutcome::KeptPrevious(prev)
        } else {
            SaveOutcome::Nothing
        });
    }
    let text: String = nodes
        .iter()
        .map(|(ms, l)| format!("# {ms} ms\n{l}\n"))
        .collect();
    atomic_write(&data.join("subs_alive.txt"), text.as_bytes())?;
    let plain: String = nodes.iter().map(|(_, l)| format!("{l}\n")).collect();
    atomic_write(&data.join("subs_alive_plain.txt"), plain.as_bytes())?;
    Ok(SaveOutcome::Written(nodes.len()))
}

fn count_plain_nodes(data: &Path) -> usize {
    std::fs::read_to_string(data.join("subs_alive_plain.txt"))
        .map(|t| {
            t.lines()
                .filter(|l| {
                    let l = l.trim();
                    !l.is_empty() && !l.starts_with('#')
                })
                .count()
        })
        .unwrap_or(0)
}

fn write_state(data: &Path, s: &Stats, kept: bool) -> Result<()> {
    let state = serde_json::json!({
        "updated_at": net::unix_now(),
        "sources": {"total": s.sources_total, "ok": s.sources_ok, "failed": s.sources_failed},
        "links": {"fetched": s.fetched, "unique": s.unique, "invalid": s.invalid,
                  "external": s.external, "duplicate": s.duplicate},
        "probes": {"tested": s.tested, "alive": s.alive, "tls_ok": s.tls_ok, "dead": s.dead},
        "selected": s.selected,
        "kept_previous": kept,
        "note": "TCP/TLS reachability only; VPN credentials are not verified"
    });
    atomic_write(
        &data.join("subs_state.json"),
        &serde_json::to_vec_pretty(&state)?,
    )?;
    Ok(())
}

/// Country per IP via the free ip-api batch endpoint (100 IPs per request).
/// Uses the caller's HTTP client. Returns an empty map when the service is
/// unreachable, so callers keep all nodes instead of dropping them.
fn lookup_countries(
    client: &reqwest::blocking::Client,
    ips: &[String],
) -> HashMap<String, (String, String)> {
    let mut out = HashMap::new();
    for chunk in ips.chunks(100) {
        let body = match serde_json::to_string(chunk) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let resp = client
            .post("http://ip-api.com/batch?fields=status,countryCode,country&lang=ru")
            .header("Content-Type", "application/json")
            .body(body)
            .timeout(Duration::from_secs(8))
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
    alive: &[Alive],
    geo: &HashMap<String, (String, String)>,
    filter: bool,
) -> Vec<(u128, String)> {
    if !filter {
        return alive
            .iter()
            .map(|a| (a.ms, rename_link(&a.link, &brand_name("", ""))))
            .collect();
    }
    let mut buckets: HashMap<String, Vec<(u128, String)>> = HashMap::new();
    let mut names: HashMap<String, String> = HashMap::new();
    for a in alive {
        let (code, country) = a
            .ip
            .as_deref()
            .and_then(|ip| geo.get(ip).cloned())
            .unwrap_or_else(|| ("ZZ".to_string(), "Другая страна".to_string()));
        names.insert(code.clone(), country);
        buckets.entry(code).or_default().push((a.ms, a.link.clone()));
    }
    let mut out: Vec<(u128, String)> = Vec::new();
    for (code, mut nodes) in buckets {
        nodes.sort_by_key(|n| n.0);
        nodes.truncate(PER_COUNTRY);
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
        if let Some(decoded) = net::b64_decode_text(rest) {
            if let Ok(mut v) = serde_json::from_str::<serde_json::Value>(decoded.trim()) {
                v["ps"] = serde_json::Value::String(name.to_string());
                if let Ok(s) = serde_json::to_string(&v) {
                    return format!("vmess://{}", util::base64(&s));
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
    links::parse(link)
        .ok()
        .map(|l| l.name)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vless(host: &str, port: u16, uuid: &str, frag: &str) -> String {
        format!("vless://{uuid}@{host}:{port}?security=tls&sni={host}#{frag}")
    }

    const UUID_A: &str = "11111111-1111-4111-8111-111111111111";
    const UUID_B: &str = "22222222-2222-4222-8222-222222222222";

    #[test]
    fn collect_links_ignores_noise_and_empty_bodies() {
        assert!(collect_links("").is_empty());
        assert!(collect_links("# comment\n\nnot a link\n").is_empty());
        let body = format!(
            "\u{feff}{}\n  {}\nss://abc\n",
            vless("a.example", 443, UUID_A, "a"),
            vless("b.example", 443, UUID_B, "b")
        );
        assert_eq!(collect_links(&body).len(), 3);
    }

    #[test]
    fn base64_subscription_is_decoded() {
        let plain = vless("a.example", 443, UUID_A, "a");
        let b64 = util::base64(&plain);
        assert!(maybe_b64(&b64).contains("://"));
        assert_eq!(collect_links(&maybe_b64(&b64)).len(), 1);
        // Broken base64 must not panic and must not invent links.
        assert_eq!(maybe_b64("!!!not-base64!!!"), "!!!not-base64!!!");
        assert!(collect_links(&maybe_b64("!!!not-base64!!!")).is_empty());
        assert_eq!(maybe_b64(""), "");
    }

    #[test]
    fn dedupe_filters_invalid_and_external() {
        let links = vec![
            vless("a.example", 443, UUID_A, "first"),
            // Same node, different fragment: duplicate by normalized key.
            vless("a.example", 443, UUID_A, "second"),
            vless("b.example", 8443, UUID_B, "b"),
            "vless://broken".to_string(),
            "garbage".to_string(),
            "ss://YWVzLTI1Ni1nY206cHc=@1.2.3.4:8388#x".to_string(),
        ];
        let b = dedupe_and_filter(links);
        assert_eq!(b.seen, 6);
        assert_eq!(b.items.len(), 2);
        assert_eq!(b.duplicate, 1);
        assert_eq!(b.invalid, 2);
        assert_eq!(b.external, 1);
    }

    #[test]
    fn empty_run_keeps_last_known_good_files() {
        let dir = tempfile::tempdir().unwrap();
        let nodes = vec![
            (10u128, vless("a.example", 443, UUID_A, "a")),
            (20, vless("b.example", 443, UUID_B, "b")),
        ];
        assert_eq!(
            save_alive(dir.path(), &nodes).unwrap(),
            SaveOutcome::Written(2)
        );
        let plain_before =
            std::fs::read_to_string(dir.path().join("subs_alive_plain.txt")).unwrap();
        assert_eq!(count_plain_nodes(dir.path()), 2);
        assert!(plain_before.contains("a.example"));

        // Empty result: previous files must stay byte-identical.
        assert_eq!(
            save_alive(dir.path(), &[]).unwrap(),
            SaveOutcome::KeptPrevious(2)
        );
        let plain_after =
            std::fs::read_to_string(dir.path().join("subs_alive_plain.txt")).unwrap();
        assert_eq!(plain_before, plain_after);

        // No previous list and no nodes: nothing is created.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(save_alive(empty.path(), &[]).unwrap(), SaveOutcome::Nothing);
        assert!(!empty.path().join("subs_alive_plain.txt").exists());
    }

    #[test]
    fn writes_are_atomic_and_leave_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let nodes = vec![(5u128, vless("a.example", 443, UUID_A, "a"))];
        save_alive(dir.path(), &nodes).unwrap();
        let temps = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(temps, 0);
        let plain = std::fs::read_to_string(dir.path().join("subs_alive_plain.txt")).unwrap();
        assert!(plain.lines().all(|l| !l.starts_with('#')));
        assert!(plain.trim_end().starts_with("vless://"));
    }

    #[test]
    fn count_plain_ignores_comments_and_blanks() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("subs_alive_plain.txt"),
            "# comment\n\nvless://a\n  \nvless://b\n",
        )
        .unwrap();
        assert_eq!(count_plain_nodes(dir.path()), 2);
        assert_eq!(count_plain_nodes(&dir.path().join("missing")), 0);
    }

    #[test]
    fn two_fastest_per_country() {
        let geo: HashMap<String, (String, String)> = [
            ("1.1.1.1", "DE", "Германия"),
            ("1.1.1.2", "DE", "Германия"),
            ("1.1.1.3", "DE", "Германия"),
            ("2.2.2.2", "NL", "Нидерланды"),
        ]
        .into_iter()
        .map(|(ip, code, name)| (ip.to_string(), (code.to_string(), name.to_string())))
        .collect();
        let alive: Vec<Alive> = (0..4)
            .map(|i| Alive {
                ms: (i as u128 + 1) * 10,
                link: vless(&format!("h{i}.example"), 443, UUID_A, "n"),
                ip: Some(if i == 3 {
                    "2.2.2.2".to_string()
                } else {
                    format!("1.1.1.{}", i + 1)
                }),
                tls_verified: true,
                verdict: proxy::Verdict::TlsReachable,
                summary: String::new(),
            })
            .collect();
        let picked = pick_two_per_country(&alive, &geo, true);
        assert_eq!(picked.len(), 3);
        let titles: Vec<String> = picked.iter().map(|(_, l)| node_title(l)).collect();
        assert_eq!(titles.iter().filter(|t| t.contains("Германия")).count(), 2);
        assert_eq!(titles.iter().filter(|t| t.contains("Нидерланды")).count(), 1);
    }

    #[test]
    fn geo_failure_keeps_every_alive_node() {
        let alive: Vec<Alive> = (1..=3)
            .map(|i| Alive {
                ms: i as u128 * 10,
                link: vless(&format!("h{i}.example"), 443, UUID_A, "n"),
                ip: Some(format!("1.1.1.{i}")),
                tls_verified: false,
                verdict: proxy::Verdict::PortOpen,
                summary: String::new(),
            })
            .collect();
        let picked = pick_two_per_country(&alive, &HashMap::new(), false);
        assert_eq!(picked.len(), 3);
        assert!(picked.iter().all(|(_, l)| node_title(l).contains("obhod")));
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

        let json = r#"{"add":"1.2.3.4","port":443,"id":"11111111-1111-4111-8111-111111111111","ps":"old"}"#;
        let vm = format!("vmess://{}", util::base64(json));
        let renamed = rename_link(&vm, "🇩🇪 | Германия | obhod");
        assert_eq!(node_title(&renamed), "🇩🇪 | Германия | obhod");
        assert_eq!(links::parse(&renamed).unwrap().port, 443);
    }

    #[test]
    fn source_list_is_deduped_and_only_http() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("subs_sources.txt"),
            "https://a.example/sub\n\nhttp://b.example/sub\nfile:///etc/passwd\nhttps://a.example/sub\n",
        )
        .unwrap();
        let src = collect_sources(dir.path());
        assert_eq!(src.len(), DEFAULT_SOURCES.len() + 2);
        assert!(src.iter().all(|s| s.starts_with("http")));
    }
}
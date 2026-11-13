use anyhow::Result;
use std::path::PathBuf;

use crate::modules::Ctx;
use crate::util;

/// Writes a local diagnostic report next to the log and returns its path.
/// No network access, nothing is uploaded. Secrets in links are masked.
pub fn write_diagnostics(
    cfg: &crate::config::Config,
    mode: &str,
    checks: &[crate::modules::check::CheckItem],
    svc_on: bool,
    tg_on: bool,
) -> Result<PathBuf> {
    let data = cfg.data_dir();
    std::fs::create_dir_all(&data)?;
    let path = data.join(format!("report-{}.txt", crate::logger::stamp()));

    let mut b = String::new();
    b.push_str(&format!("{} report\n", crate::brand::name()));
    b.push_str(&format!("generated: {}\n", crate::logger::stamp()));
    b.push_str(&format!("version: {}\n", env!("CARGO_PKG_VERSION")));
    b.push_str(&format!("mode: {mode}\n"));
    b.push_str(&format!(
        "admin: {}\n",
        if util::is_admin() { "yes" } else { "no" }
    ));
    b.push_str(&format!("exe: {}\n", util::exe_dir().display()));
    b.push_str(&format!("data: {}\n", data.display()));
    b.push_str(&format!("lang: {}\n", cfg.lang));
    b.push_str(&format!(
        "health: service={} tg_proxy={}\n",
        if svc_on { "on" } else { "off" },
        if tg_on { "present" } else { "missing" }
    ));
    b.push_str(&format!(
        "options: autostart={} service_mode={} components: zapret={} mtproto={} tgws={} hosts={} subs={} dns={}\n",
        cfg.autostart,
        cfg.service_mode,
        cfg.components.zapret,
        cfg.components.mtproto,
        cfg.components.tgws,
        cfg.components.hosts,
        cfg.components.subs,
        cfg.components.dns
    ));
    b.push_str(&format!("found_servers: {}\n", cfg.last_found.len()));

    if checks.is_empty() {
        b.push_str("\nchecks: not run\n");
    } else {
        b.push_str("\nchecks:\n");
        for c in checks {
            b.push_str(&format!(
                "  {} {} - {}\n",
                if c.ok { "OK  " } else { "FAIL" },
                c.ru,
                c.detail_ru
            ));
        }
    }

    b.push_str("\n--- log (last 120 lines) ---\n");
    if let Some(log_path) = crate::logger::path() {
        if let Ok(log) = std::fs::read_to_string(log_path) {
            let lines: Vec<&str> = log.lines().rev().take(120).collect();
            for line in lines.into_iter().rev() {
                b.push_str(&scrub(line));
                b.push('\n');
            }
        }
    }

    std::fs::write(&path, b)?;
    Ok(path)
}

/// Hides proxy/VLESS links, credentials, UUIDs, sensitive IP:port pairs and
/// personal Windows profile paths before they reach a report that a user may
/// paste into a public issue. Reports are only written on an explicit key
/// press (`R`) and are never uploaded automatically.
fn scrub(line: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for token in line.split_whitespace() {
        if is_sensitive_link(token) {
            out.push("<ссылка скрыта>".to_string());
        } else {
            out.push(mask_paths(token));
        }
    }
    let joined = out.join(" ");
    mask_sub_token_path(&mask_params(&mask_ips(&mask_uuids(&joined))))
}

/// `/sub/<token>` and `/sub.txt/<token>` → `/sub/<token>` (token hidden).
fn mask_sub_token_path(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        let (matched, prefix_len) = if starts_with_ci(b, "/sub.txt/", i) {
            (true, 9)
        } else if starts_with_ci(b, "/sub/", i) {
            (true, 5)
        } else {
            (false, 0)
        };
        if matched {
            out.extend_from_slice(&b[i..i + prefix_len]);
            out.extend_from_slice(b"<token>");
            let mut j = i + prefix_len;
            while j < b.len()
                && !matches!(
                    b[j],
                    b'/' | b'?' | b'#' | b'"' | b'\'' | b' ' | b'\t' | b')' | b','
                )
            {
                j += 1;
            }
            i = j;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

const SENSITIVE_SCHEMES: &[&str] = &[
    "vless://",
    "vmess://",
    "trojan://",
    "ss://",
    "hysteria2://",
    "hy2://",
    "tuic://",
    "tg://proxy",
    "t.me/proxy",
    "https://t.me/proxy",
];

fn is_sensitive_link(token: &str) -> bool {
    let low = token.to_ascii_lowercase();
    SENSITIVE_SCHEMES.iter().any(|s| low.contains(s))
}

const SENSITIVE_KEYS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "uuid",
    "id",
    "auth",
    "key",
    "obfs-password",
    "psk",
];

fn lower_byte(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

fn starts_with_ci(b: &[u8], key: &str, at: usize) -> bool {
    let k = key.as_bytes();
    if at + k.len() > b.len() {
        return false;
    }
    b[at..at + k.len()]
        .iter()
        .zip(k)
        .all(|(x, y)| lower_byte(*x) == lower_byte(*y))
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// `secret=…`, `token=…`, `password=…`, `id=…` → `secret=<скрыто>`.
fn mask_params(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    'outer: while i < b.len() {
        if i == 0 || !is_word_byte(b[i - 1]) {
            for key in SENSITIVE_KEYS {
                if starts_with_ci(b, key, i) && b.get(i + key.len()) == Some(&b'=') {
                    out.extend_from_slice(&b[i..i + key.len() + 1]);
                    out.extend_from_slice("<скрыто>".as_bytes());
                    i += key.len() + 1;
                    while i < b.len()
                        && !matches!(b[i], b'&' | b' ' | b'\t' | b'"' | b'\'' | b',' | b';')
                    {
                        i += 1;
                    }
                    continue 'outer;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_byte(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Canonical UUID anywhere in the text → `<uuid>`.
fn mask_uuids(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if i + 36 <= b.len() && (i == 0 || !is_word_byte(b[i - 1])) {
            let mut ok = true;
            for (j, c) in b[i..i + 36].iter().enumerate() {
                let good = match j {
                    8 | 13 | 18 | 23 => *c == b'-',
                    _ => hex_byte(*c).is_some(),
                };
                if !good {
                    ok = false;
                    break;
                }
            }
            let next_ok = b.get(i + 36).map(|c| !is_word_byte(*c)).unwrap_or(true);
            if ok && next_ok {
                out.extend_from_slice(b"<uuid>");
                i += 36;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// IPv4 (optionally with `:port`) → `<ip>`. Loopback stays readable because it
/// is useful in diagnostics and not personal.
fn mask_ips(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        if (i == 0 || !(b[i - 1].is_ascii_digit() || b[i - 1] == b'.')) && b[i].is_ascii_digit() {
            if let Some(end) = ipv4_end(b, i) {
                let ip = &s[i..end];
                let mut full_end = end;
                // Optional :port
                if b.get(full_end) == Some(&b':') {
                    let mut j = full_end + 1;
                    while j < b.len() && b[j].is_ascii_digit() {
                        j += 1;
                    }
                    if j > full_end + 1 && j - full_end <= 6 {
                        full_end = j;
                    }
                }
                if ip == "127.0.0.1" || ip == "0.0.0.0" {
                    out.extend_from_slice(&b[i..full_end]);
                } else {
                    out.extend_from_slice(b"<ip>");
                }
                i = full_end;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Returns the end offset of a dotted-quad starting at `start` (4 parts,
/// each 0..=255, no leading '+' etc.).
fn ipv4_end(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start;
    for part in 0..4 {
        let begin = i;
        while i < b.len() && b[i].is_ascii_digit() && i - begin < 3 {
            i += 1;
        }
        if i == begin {
            return None;
        }
        let value: u32 = std::str::from_utf8(&b[begin..i]).ok()?.parse().ok()?;
        if value > 255 {
            return None;
        }
        if part < 3 {
            if b.get(i) != Some(&b'.') {
                return None;
            }
            i += 1;
        }
    }
    // Do not eat the first digit of a longer number.
    if b.get(i).map(|c| c.is_ascii_digit()).unwrap_or(false) {
        return None;
    }
    Some(i)
}

/// `C:\Users\<name>\…` → `C:\Users\<user>\…` (also for other drives and the
/// legacy `Documents and Settings` layout).
fn mask_paths(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0usize;
    while i < b.len() {
        let at_users = i + 7 <= b.len()
            && starts_with_ci(b, "\\Users\\", i)
            && i >= 2
            && b[i - 1] == b':'
            && b[i - 2].is_ascii_alphabetic();
        let at_old = i + 24 <= b.len()
            && starts_with_ci(b, "\\Documents and Settings\\", i)
            && i >= 2
            && b[i - 1] == b':'
            && b[i - 2].is_ascii_alphabetic();
        if at_users || at_old {
            let prefix_len = if at_users { 7 } else { 24 };
            out.extend_from_slice(&b[i..i + prefix_len]);
            let mut j = i + prefix_len;
            while j < b.len() && !matches!(b[j], b'\\' | b'/' | b'"' | b'\'' | b' ' | b'\t') {
                j += 1;
            }
            out.extend_from_slice(b"<user>");
            i = j;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn run(ctx: &Ctx) -> Result<()> {
    if !ctx.opts.telemetry {
        ctx.log("Телеметрия выключена — ничего не отправляю.");
        return Ok(());
    }
    if ctx.opts.repo.trim().is_empty() {
        ctx.log("⚠ Телеметрия включена, но не задан GitHub-репозиторий в настройках.");
        return Ok(());
    }

    let mut body = String::new();
    body.push_str(&format!("### {} report\n\n", crate::brand::name()));
    body.push_str(&format!("- version: {}\n", env!("CARGO_PKG_VERSION")));
    body.push_str(&format!("- os: {}\n", std::env::consts::OS));
    body.push_str(&format!(
        "- admin: {}\n",
        if ctx.admin { "yes" } else { "no" }
    ));
    body.push_str(&format!("- data_dir: {}\n", ctx.data.display()));
    body.push_str(&format!(
        "- components: zapret={} mtproto={} tgws={} hosts={} subs={} dns={}\n",
        ctx.opts.components.zapret,
        ctx.opts.components.mtproto,
        ctx.opts.components.tgws,
        ctx.opts.components.hosts,
        ctx.opts.components.subs,
        ctx.opts.components.dns
    ));
    body.push_str("\n_Отправлено добровольно, без идентификаторов._\n");

    let path = ctx.data.join("report.txt");
    std::fs::write(&path, &body)?;

    let url = format!(
        "https://github.com/{}/issues/new?title={}&body={}",
        ctx.opts.repo,
        enc("obhod report"),
        enc(&body)
    );
    ctx.log("Открываю GitHub с готовым отчётом (вы можете его не отправлять).");
    if let Err(e) = util::open_url(&url) {
        ctx.log(format!("⚠ не удалось открыть браузер: {e}"));
    }
    Ok(())
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_hides_proxy_links_and_secrets() {
        let line = "proxy tg://proxy?server=1.2.3.4&port=443&secret=abc ok";
        let s = scrub(line);
        assert!(!s.contains("1.2.3.4"));
        assert!(!s.contains("secret=abc"));
        assert!(s.contains("<ссылка скрыта>"));
        assert!(s.ends_with(" ok"));
    }

    #[test]
    fn scrub_keeps_plain_text() {
        let line = "[2026-01-01] шаг: проверка DNS";
        assert_eq!(scrub(line), line);
    }

    #[test]
    fn scrub_hides_uuids_and_ips() {
        let line = "node 11111111-2222-4333-8444-555555555555 at 203.0.113.7:8443 ok";
        let s = scrub(line);
        assert!(!s.contains("11111111-2222"));
        assert!(!s.contains("203.0.113.7"));
        assert!(!s.contains("8443"));
        assert!(s.contains("<uuid>"));
        assert!(s.contains("<ip>"));
        assert!(s.ends_with(" ok"));
    }

    #[test]
    fn scrub_keeps_loopback_addresses_for_diagnostics() {
        let s = scrub("subscription http://127.0.0.1:8080/sub/abc");
        assert!(s.contains("127.0.0.1:8080"));
        // The token value is still hidden.
        assert!(!s.contains("/sub/abc"));
    }

    #[test]
    fn scrub_masks_sensitive_query_parameters() {
        let s = scrub("url?server=a.example&port=443&secret=abcdef&token=xyz&password=pw");
        assert!(!s.contains("abcdef"));
        assert!(!s.contains("xyz"));
        assert!(!s.contains("password=pw"));
        assert!(s.contains("secret=<скрыто>"));
        assert!(s.contains("token=<скрыто>"));
        assert!(s.contains("password=<скрыто>"));
        assert!(s.contains("server=a.example"));
    }

    #[test]
    fn scrub_masks_personal_windows_paths() {
        let s = scrub(r"data: C:\Users\Alice\AppData\Roaming\obhod\data");
        assert!(!s.contains("Alice"));
        assert!(s.contains(r"C:\Users\<user>\AppData"));

        let d = scrub(r"path D:\Users\Bob\Desktop\TgWsProxy.exe");
        assert!(!d.contains("Bob"));
        assert!(d.contains(r"D:\Users\<user>\Desktop"));

        // A non-profile path is not a secret.
        let plain = scrub(r"tool E:\games\obhod\obhod.exe");
        assert_eq!(plain, r"tool E:\games\obhod\obhod.exe");
    }

    #[test]
    fn scrub_hides_all_supported_schemes() {
        for link in [
            "ss://YWVzLTI1Ni1nY206cHc=@1.2.3.4:8388",
            "hysteria2://pw@example.org:443",
            "tuic://uuid:pw@example.org:443",
            "vmess://eyJhZGQiOiIxLjIuMy40In0=",
        ] {
            let s = scrub(&format!("link {link} end"));
            assert!(!s.contains(link), "leaked {link}");
            assert!(s.contains("<ссылка скрыта>"));
        }
    }

    #[test]
    fn mask_uuids_does_not_touch_short_hex() {
        assert_eq!(mask_uuids("deadbeef"), "deadbeef");
        assert_eq!(mask_ips("version 1.2.3"), "version 1.2.3");
        assert_eq!(mask_ips("999.1.1.1"), "999.1.1.1");
    }

    #[test]
    fn writes_report_to_configured_dir() {
        let mut cfg = crate::config::Config::default();
        let dir = std::env::temp_dir().join(format!("obhod-report-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        cfg.data_dir = dir.to_string_lossy().to_string();

        let path = write_diagnostics(&cfg, "test", &[], false, false).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("version:"));
        assert!(text.contains("mode: test"));
        assert!(text.contains("checks: not run"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

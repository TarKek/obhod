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

/// Hides proxy/VLESS links and `secret=` values before they reach a report
/// that a user may paste into a public issue.
fn scrub(line: &str) -> String {
    let mut out: Vec<String> = Vec::new();
    for token in line.split_whitespace() {
        let low = token.to_ascii_lowercase();
        let is_link = low.starts_with("vless://")
            || low.starts_with("trojan://")
            || low.starts_with("vmess://")
            || low.starts_with("tg://proxy")
            || low.contains("secret=");
        if is_link {
            out.push("<ссылка скрыта>".to_string());
        } else {
            out.push(token.to_string());
        }
    }
    out.join(" ")
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

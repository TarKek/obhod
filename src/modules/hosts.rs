use anyhow::Result;
use std::path::PathBuf;

use crate::modules::Ctx;
use crate::util;

const MARK_START: &str = "# >>> obhod-ads >>>";
const MARK_END: &str = "# <<< obhod-ads <<<";
const ADS_SRC: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

fn hosts_path() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join("System32")
        .join("drivers")
        .join("etc")
        .join("hosts")
}

pub fn run(ctx: &Ctx) -> Result<()> {
    let path = hosts_path();
    let original = std::fs::read_to_string(&path).unwrap_or_default();

    // 1. Always make a backup (never destructive).
    let backup = ctx.data.join(format!("hosts.backup-{}", util::timestamp()));
    std::fs::write(&backup, &original)?;
    ctx.log(format!("✓ Резервная копия hosts: {}", backup.display()));

    if !ctx.opts.hosts_block_ads {
        ctx.log("hosts не изменялся (выбран режим «только бэкап»).");
        return Ok(());
    }
    if !ctx.admin {
        ctx.log("⚠ Для правки hosts нужны права администратора — пропущено.");
        return Ok(());
    }

    let client = util::http_client()?;
    let ads = util::get_text(&client, ADS_SRC)?;
    let mut block = String::new();
    block.push_str(MARK_START);
    block.push('\n');
    for line in ads.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        // keep only "IP domain" lines from the ad list
        let mut it = l.split_whitespace();
        if let (Some(ip), Some(domain)) = (it.next(), it.next()) {
            if ip == "0.0.0.0" || ip == "127.0.0.1" {
                block.push_str(&format!("0.0.0.0 {domain}\n"));
            }
        }
    }
    block.push_str(MARK_END);
    block.push('\n');

    let cleaned = strip_block(&original);
    let new = format!("{cleaned}\n{block}");
    std::fs::write(&path, new)?;
    let _ = util::hidden_str("ipconfig", &["/flushdns"]);
    ctx.log(format!(
        "✓ hosts обновлён (блок рекламы/трекеров). Старые записи сохранены."
    ));
    Ok(())
}

/// Removes only our own marked block; the user's original lines stay intact.
pub fn remove_block(ctx: &Ctx) -> Result<()> {
    let path = hosts_path();
    let original = std::fs::read_to_string(&path).unwrap_or_default();
    if !original.contains(MARK_START) {
        ctx.log("• Блока рекламы в hosts нет — пропускаю.");
        return Ok(());
    }
    if !ctx.admin {
        ctx.log("⚠ Чтобы убрать блок из hosts, нужны права администратора — пропущено.");
        return Ok(());
    }
    std::fs::write(&path, strip_block(&original))?;
    let _ = util::hidden_str("ipconfig", &["/flushdns"]);
    ctx.log("✓ Блок рекламы убран из hosts, остальные записи на месте.");
    Ok(())
}

fn strip_block(s: &str) -> String {
    let mut out = Vec::new();
    let mut inside = false;
    for line in s.lines() {
        if line.trim() == MARK_START {
            inside = true;
            continue;
        }
        if line.trim() == MARK_END {
            inside = false;
            continue;
        }
        if !inside {
            out.push(line);
        }
    }
    out.join("\n")
}

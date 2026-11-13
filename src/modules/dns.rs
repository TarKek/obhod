use anyhow::Result;

use crate::modules::Ctx;
use crate::util;

pub fn run(ctx: &Ctx) -> Result<()> {
    if !ctx.admin {
        ctx.log("⚠ DNS: нужны права администратора — шаг пропущен.");
        return Ok(());
    }
    let iface = match active_iface() {
        Some(i) => i,
        None => {
            ctx.log("⚠ DNS: не удалось определить активный интерфейс.");
            return Ok(());
        }
    };
    ctx.log(format!("Активный интерфейс: {iface}"));

    let ps = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ServerAddresses 1.1.1.1,8.8.8.8",
        iface.replace('\'', "''")
    );
    let out = util::hidden_str(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    )?;
    if out.status.success() {
        ctx.log("✓ DNS выставлен на 1.1.1.1 / 8.8.8.8");
    } else {
        ctx.log(format!(
            "⚠ DNS не изменён: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }

    // Windows 11 DoH (best effort)
    for (server, tpl) in [
        ("1.1.1.1", "https://cloudflare-dns.com/dns-query"),
        ("8.8.8.8", "https://dns.google/dns-query"),
    ] {
        let out = util::hidden_str(
            "netsh",
            &[
                "dns",
                "add",
                "encryption",
                &format!("server={server}"),
                &format!("dohtemplate={tpl}"),
                "autoupgrade=yes",
            ],
        );
        match out {
            Ok(o) if o.status.success() => ctx.log(format!("✓ DoH включён для {server}")),
            _ => ctx.log(format!("• DoH для {server} недоступен (старая Windows) — пропуск")),
        }
    }
    let _ = util::hidden_str("ipconfig", &["/flushdns"]);
    ctx.log("Кэш DNS очищен.");
    Ok(())
}

/// Returns DNS to "obtain automatically" on the active interface.
pub fn reset(ctx: &Ctx) -> Result<()> {
    if !ctx.admin {
        ctx.log("⚠ DNS: нужны права администратора — пропущено.");
        return Ok(());
    }
    let iface = match active_iface() {
        Some(i) => i,
        None => {
            ctx.log("⚠ DNS: не удалось определить активный интерфейс.");
            return Ok(());
        }
    };
    let ps = format!(
        "Set-DnsClientServerAddress -InterfaceAlias '{}' -ResetServerAddresses",
        iface.replace('\'', "''")
    );
    let out = util::hidden_str(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    )?;
    if out.status.success() {
        ctx.log("✓ DNS снова получается автоматически.");
    } else {
        ctx.log(format!(
            "⚠ DNS не изменён: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    let _ = util::hidden_str("ipconfig", &["/flushdns"]);
    Ok(())
}

fn active_iface() -> Option<String> {
    let out = util::hidden_str(
        "powershell",
        &[
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway} | Select-Object -First 1).InterfaceAlias",
        ],
    )
    .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

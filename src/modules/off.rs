//! "Выключить и вернуть как было": stops the bypass and undoes the changes
//! this toolkit made. Files stay in place, so turning it on again is fast.

use anyhow::Result;

use crate::modules::{dns, hosts, Ctx};
use crate::util;

pub fn run(ctx: &Ctx) -> Result<()> {
    ctx.progress(5, "остановка обхода");
    stop_zapret(ctx);

    ctx.progress(35, "hosts");
    if let Err(e) = hosts::remove_block(ctx) {
        ctx.log(format!("⚠ hosts: {e:#}"));
    }

    ctx.progress(55, "DNS");
    if let Err(e) = dns::reset(ctx) {
        ctx.log(format!("⚠ DNS: {e:#}"));
    }

    ctx.progress(75, "автозагрузка");
    stop_tgws(ctx);

    ctx.progress(100, "готово");
    ctx.log("✓ Готово: обход выключен, система возвращена как была.");
    ctx.log("  Файлы программы остались на месте — включить можно снова.");
    Ok(())
}

fn stop_zapret(ctx: &Ctx) {
    let installed = util::hidden_str("sc", &["query", "zapret"])
        .map(|o| o.status.success())
        .unwrap_or(false);
    if installed {
        let _ = util::hidden_str("sc", &["stop", "zapret"]);
        match util::hidden_str("sc", &["delete", "zapret"]) {
            Ok(o) if o.status.success() => {
                ctx.log("✓ Служба обхода остановлена и удалена.");
            }
            _ => {
                ctx.log("⚠ Служба остановлена, но удалить её не удалось.");
                if !ctx.admin {
                    ctx.log("  Нужны права администратора — запустите программу от имени администратора.");
                }
            }
        }
    } else {
        ctx.log("• Служба обхода не была установлена — пропускаю.");
    }
    let _ = util::hidden_str("taskkill", &["/IM", "winws.exe", "/F"]);
}

fn stop_tgws(ctx: &Ctx) {
    let _ = util::hidden_str("taskkill", &["/IM", "TgWsProxy.exe", "/F"]);
    let run = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let a = util::reg_delete_value("HKCU", run, "TgWsProxy");
    let b = util::reg_delete_value("HKCU", run, "obhod");
    if a.is_ok() || b.is_ok() {
        ctx.log("✓ Автозапуск выключен.");
    } else {
        ctx.log("• Автозапуск не был настроен — пропускаю.");
    }
}
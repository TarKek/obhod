use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::modules::Ctx;
use crate::sys::proc::ProcBackend;
use crate::util;

const REPO: &str = "Flowseal/tg-ws-proxy";

pub fn run(ctx: &Ctx) -> Result<()> {
    run_from(ctx, None)
}

/// Starts TgWsProxy, optionally using an already verified copy (the updater
/// stages and checks the file first, then asks this function to run it).
pub fn run_from(ctx: &Ctx, provided: Option<&Path>) -> Result<()> {
    let dir = ctx.dir("tgws");
    std::fs::create_dir_all(&dir)?;

    if provided.is_none() && ctx.opts.keep_tgws {
        if let Some(p) = find_existing() {
            ctx.log(format!(
                "TgWsProxy уже есть — использую его: {}",
                p.display()
            ));
            let _ = std::process::Command::new(&p)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            return Ok(());
        }
    }

    let exe = match provided {
        Some(p) => {
            ctx.log(format!("Использую проверенную копию: {}", p.display()));
            p.to_path_buf()
        }
        None => match find_existing() {
            Some(p) => {
                ctx.log(format!("Найден локально: {}", p.display()));
                p
            }
            None => {
                ctx.log("Скачиваю TgWsProxy с GitHub...");
                let client = util::http_client()?;
                let dl = ctx.dir("downloads");
                std::fs::create_dir_all(&dl)?;
                let file = util::github_asset(&client, REPO, ".exe", &dl)?;
                let dest = dir.join(file.file_name().unwrap_or_default());
                std::fs::copy(&file, &dest)?;
                dest
            }
        },
    };

    // Record which process we spawn: stop/update may only kill our own copy.
    let before = crate::sys::proc::SystemProcs
        .list("TgWsProxy.exe")
        .unwrap_or_default();
    let mut c = std::process::Command::new(&exe);
    use std::os::windows::process::CommandExt;
    c.creation_flags(util::CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match c.spawn() {
        Ok(_) => {
            ctx.log("✓ TgWsProxy запущен (запасной путь для Telegram).");
            let _ = crate::sys::proc::record_new(
                &ctx.data,
                &crate::sys::proc::SystemProcs,
                "TgWsProxy.exe",
                &before,
            );
        }
        Err(e) => ctx.log(format!("⚠ не удалось запустить TgWsProxy: {e}")),
    }

    if ctx.opts.autostart {
        // Autostart the bridge itself, not the toolkit.
        let val = format!("\"{}\"", exe.display());
        match util::reg_set_string(
            "HKCU",
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            "TgWsProxy",
            &val,
        ) {
            Ok(_) => {
                ctx.log("✓ TgWsProxy добавлен в автозагрузку");
                let _ = crate::sys::proc::own_run_value(
                    &ctx.data,
                    &crate::sys::proc::RunValue {
                        root: "HKCU".into(),
                        path: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                        name: "TgWsProxy".into(),
                        value: val,
                    },
                );
            }
            Err(e) => ctx.log(format!("⚠ автозагрузка TgWsProxy: {e}")),
        }
    }
    Ok(())
}

fn find_existing() -> Option<PathBuf> {
    let mut cands: Vec<PathBuf> = Vec::new();
    let here = util::exe_dir();
    if let Ok(rd) = std::fs::read_dir(&here) {
        for e in rd.flatten() {
            let p = e.path();
            if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                if n.to_lowercase().starts_with("tgwsproxy") && n.ends_with(".exe") {
                    cands.push(p);
                }
            }
        }
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        for sub in ["Desktop", "Downloads"] {
            let d = PathBuf::from(&profile).join(sub);
            if let Ok(rd) = std::fs::read_dir(d) {
                for e in rd.flatten() {
                    let p = e.path();
                    if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                        if n.to_lowercase().starts_with("tgwsproxy") && n.ends_with(".exe") {
                            cands.push(p);
                        }
                    }
                }
            }
        }
    }
    cands.into_iter().next()
}

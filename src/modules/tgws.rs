use anyhow::Result;
use std::path::PathBuf;

use crate::modules::Ctx;
use crate::util;

const REPO: &str = "Flowseal/tg-ws-proxy";

pub fn run(ctx: &Ctx) -> Result<()> {
    let dir = ctx.dir("tgws");
    std::fs::create_dir_all(&dir)?;

    if ctx.opts.keep_tgws {
        if let Some(p) = find_existing() {
            ctx.log(format!("TgWsProxy уже есть — использую его: {}", p.display()));
            let _ = std::process::Command::new(&p)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            return Ok(());
        }
    }

    let exe = match find_existing() {
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
    };

    // TgWsProxy is a GUI bridge; start it detached.
    let mut c = std::process::Command::new(&exe);
    use std::os::windows::process::CommandExt;
    c.creation_flags(util::CREATE_NO_WINDOW)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    match c.spawn() {
        Ok(_) => ctx.log("✓ TgWsProxy запущен (запасной путь для Telegram)."),
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
            Ok(_) => ctx.log("✓ TgWsProxy добавлен в автозагрузку"),
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

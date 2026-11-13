use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::modules::Ctx;
use crate::util;

const REPO: &str = "Flowseal/zapret-discord-youtube";

/// True when our service exists and is running. Used for the home status line.
pub fn service_running() -> bool {
    match util::hidden_str("sc", &["query", "zapret"]) {
        Ok(o) => {
            o.status.success() && String::from_utf8_lossy(&o.stdout).to_ascii_uppercase().contains("RUNNING")
        }
        Err(_) => false,
    }
}

pub fn run(ctx: &Ctx) -> Result<()> {
    // Never touch a working installation unless the user explicitly asked to.
    if ctx.opts.keep_zapret
        && (crate::modules::detect::service_exists("zapret")
            || Path::new(r"C:\zapret\bin\winws.exe").exists())
    {
        ctx.log("Найден уже установленный zapret — оставляю как есть.");
        let _ = util::hidden_str("sc", &["start", "zapret"]);
        if !crate::modules::detect::proc_running("winws.exe") {
            if Path::new(r"C:\zapret\general (ALT9).bat").exists() {
                let _ = util::run_hidden_file(Path::new(r"C:\zapret\general (ALT9).bat"));
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(3));
        if crate::modules::detect::proc_running("winws.exe") {
            ctx.log("✓ Существующий обход работает.");
        } else {
            ctx.log("⚠ Существующий zapret найден, но не запущен. Можно переустановить в «Тонкой настройке».");
        }
        return Ok(());
    }

    let client = util::http_client()?;
    let dir = ctx.dir("zapret");
    let winws = dir.join("bin").join("winws.exe");

    if !winws.exists() {
        ctx.log("Скачиваю zapret с GitHub (Flowseal)...");
        let dl = ctx.dir("downloads");
        fs::create_dir_all(&dl)?;
        let zip = util::github_asset(&client, REPO, ".zip", &dl)
            .context("не удалось скачать релиз zapret")?;
        ctx.log(format!("Распаковываю {}", zip.file_name().unwrap_or_default().to_string_lossy()));
        util::unzip(&zip, &dir)?;
    } else {
        ctx.log("zapret уже скачан, использую локальную копию.");
    }

    if !winws.exists() {
        anyhow::bail!("в архиве нет bin/winws.exe");
    }

    let preset = choose_preset(&dir);
    ctx.log(format!("Пресет: {preset}"));

    if ctx.opts.service_mode && ctx.admin {
        install_service(ctx, &dir, &preset)?;
    } else {
        if ctx.opts.service_mode && !ctx.admin {
            ctx.log("⚠ Нет прав администратора — ставлю в портативном режиме (без службы).");
        }
        start_portable(ctx, &dir, &preset)?;
    }

    if ctx.opts.autostart && ctx.admin && ctx.opts.service_mode {
        let _ = util::hidden_str("sc", &["config", "zapret", "start=", "auto"]);
        ctx.log("Служба zapret переведена в автозапуск.");
    }
    Ok(())
}

fn choose_preset(dir: &Path) -> String {
    for name in [
        "general (ALT9).bat",
        "general (ALT11).bat",
        "general (ALT4).bat",
        "general.bat",
    ] {
        if dir.join(name).exists() {
            return name.to_string();
        }
    }
    "general.bat".into()
}

fn start_portable(ctx: &Ctx, dir: &Path, preset: &str) -> Result<()> {
    let _ = util::hidden_str("taskkill", &["/IM", "winws.exe", "/F"]);
    let bat = dir.join(preset);
    // Direct start via cmd, hidden, no extra console window.
    let mut c = std::process::Command::new("cmd");
    c.args(["/c", "start", "", "/min"]).arg(&bat);
    use std::os::windows::process::CommandExt;
    c.creation_flags(util::CREATE_NO_WINDOW);
    c.stdin(std::process::Stdio::null());
    c.spawn()
        .with_context(|| format!("не удалось запустить {}", bat.display()))?;
    ctx.log("zapret запущен (портативно). Проверяю...");
    std::thread::sleep(std::time::Duration::from_secs(4));
    let ok = util::hidden_str("tasklist", &["/FI", "IMAGENAME eq winws.exe"])
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("winws.exe"))
        .unwrap_or(false);
    if ok {
        ctx.log("✓ winws.exe работает");
    } else {
        ctx.log("⚠ winws.exe не найден. Нужны права администратора (WinDivert).");
    }
    Ok(())
}

fn install_service(ctx: &Ctx, dir: &Path, preset: &str) -> Result<()> {
    let bat = dir.join(preset);
    let text = fs::read_to_string(&bat).unwrap_or_default();
    let cmdline = match bat_to_cmdline(&text, dir) {
        Some(s) => s,
        None => anyhow::bail!("не удалось разобрать аргументы {preset}"),
    };

    let _ = util::hidden_str("sc", &["stop", "zapret"]);
    let _ = util::hidden_str("sc", &["delete", "zapret"]);
    let _ = util::hidden_str("taskkill", &["/IM", "winws.exe", "/F"]);

    let start_mode = if ctx.opts.autostart { "auto" } else { "demand" };
    let out = util::hidden_str(
        "sc",
        &[
            "create",
            "zapret",
            "binPath=",
            &cmdline,
            "DisplayName=",
            "zapret",
            "start=",
            start_mode,
        ],
    )?;
    if !out.status.success() {
        anyhow::bail!("sc create: {}", String::from_utf8_lossy(&out.stderr));
    }
    let _ = util::hidden_str("sc", &["description", "zapret", "Zapret DPI bypass (obhod)"]);
    let started = util::hidden_str("sc", &["start", "zapret"])?;
    if started.status.success() {
        ctx.log("✓ Служба zapret установлена и запущена (автозапуск).");
    } else {
        ctx.log("⚠ Служба создана, но не стартовала — проверьте лог Windows.");
    }
    let _ = util::reg_set_string(
        "HKLM",
        r"System\CurrentControlSet\Services\zapret",
        "obhod-preset",
        preset,
    );
    Ok(())
}

/// Turn a zapret .bat into a single winws.exe command line.
pub fn bat_to_cmdline(text: &str, dir: &Path) -> Option<String> {
    let joined = text.replace("^\r\n", " ").replace("^\n", " ").replace("\\\r\n", " ");
    let flat: String = joined
        .lines()
        .filter(|l| !l.trim_start().starts_with("::"))
        .collect::<Vec<_>>()
        .join(" ");

    let bin = format!("{}\\bin\\", dir.display());
    let lists = format!("{}\\lists\\", dir.display());
    let mut s = flat
        .replace("%BIN%", &bin)
        .replace("%LISTS%", &lists)
        .replace("%~dp0", &format!("{}\\", dir.display()))
        .replace("%GameFilterTCP%", "")
        .replace("%GameFilterUDP%", "")
        .replace("%GameFilter%", "");

    let idx = s.find("winws.exe")?;
    // keep the opening quote (if any) right before winws.exe
    let start = s[..idx].rfind('"').unwrap_or(idx);
    s = s[start..].to_string();
    if let Some(pos) = s.find(" & ") {
        s.truncate(pos);
    }

    // Drop rules whose port list became empty (GameFilter was not set).
    let mut blocks: Vec<String> = Vec::new();
    for block in s.split("--new") {
        let b = block.trim();
        if b.is_empty() {
            continue;
        }
        let mut empty = false;
        for key in ["--filter-tcp=", "--filter-udp="] {
            if let Some(i) = b.find(key) {
                let rest = &b[i + key.len()..];
                if rest.chars().next().map_or(true, |c| c.is_whitespace()) {
                    empty = true;
                }
            }
        }
        if !empty {
            blocks.push(b.to_string());
        }
    }
    let mut full = blocks.join(" --new ");

    // Clean stray commas in --wf-tcp / --wf-udp lists.
    for key in ["--wf-tcp=", "--wf-udp="] {
        if let Some(i) = full.find(key) {
            let start = i + key.len();
            let end = full[start..]
                .find(' ')
                .map(|x| x + start)
                .unwrap_or(full.len());
            let list = full[start..end].to_string();
            let cleaned: Vec<&str> = list
                .split(',')
                .map(|x| x.trim())
                .filter(|x| !x.is_empty())
                .collect();
            full.replace_range(start..end, &cleaned.join(","));
        }
    }

    if full.contains("winws.exe\"") {
        Some(full)
    } else {
        Some(format!("\"{bin}winws.exe\" {full}"))
    }
}

pub fn status(ctx: &Ctx) -> Vec<String> {
    let mut v = Vec::new();
    let dir = ctx.dir("zapret");
    v.push(format!(
        "zapret: {}",
        if dir.join("bin").join("winws.exe").exists() {
            "скачан"
        } else {
            "нет"
        }
    ));
    let run = util::hidden_str("tasklist", &["/FI", "IMAGENAME eq winws.exe"])
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("winws.exe"))
        .unwrap_or(false);
    let svc = util::hidden_str("sc", &["query", "zapret"])
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("RUNNING"))
        .unwrap_or(false);
    v.push(format!(
        "  процесс: {} | служба: {}",
        if run { "работает" } else { "нет" },
        if svc { "работает" } else { "нет" }
    ));
    v
}

pub fn _paths(dir: &Path) -> PathBuf {
    dir.join("bin").join("winws.exe")
}

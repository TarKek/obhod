use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::modules::Ctx;
use crate::sys::journal::{self, Journal};
use crate::sys::proc::{self, ProcBackend, SystemProcs};
use crate::util;

const REPO: &str = "Flowseal/zapret-discord-youtube";
const SERVICE: &str = "zapret";
const IMAGE: &str = "winws.exe";

/// True when our service exists and is running. Used for the home status line.
pub fn service_running() -> bool {
    match util::hidden_str("sc", &["query", SERVICE]) {
        Ok(o) => {
            o.status.success() && String::from_utf8_lossy(&o.stdout).to_ascii_uppercase().contains("RUNNING")
        }
        Err(_) => false,
    }
}

fn service_exists() -> bool {
    util::hidden_str("sc", &["query", SERVICE])
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// The service is ours if the ownership ledger says so or the preset marker we
/// write at install time is present. A zapret the user installed themselves is
/// never replaced or deleted.
pub fn owns_service(data_dir: &Path) -> bool {
    proc::service_owned(data_dir, SERVICE)
        || util::reg_get_string(
            "HKLM",
            &format!(r"System\CurrentControlSet\Services\{SERVICE}"),
            "obhod-preset",
        )
        .map(|v| v.is_some())
        .unwrap_or(false)
}

pub fn run(ctx: &Ctx) -> Result<()> {
    // Never touch a working installation unless the user explicitly asked to.
    if ctx.opts.keep_zapret
        && (crate::modules::detect::service_exists(SERVICE)
            || Path::new(r"C:\zapret\bin\winws.exe").exists())
    {
        ctx.log("Найден уже установленный zapret — оставляю как есть.");
        let _ = util::hidden_str("sc", &["start", SERVICE]);
        if !crate::modules::detect::proc_running(IMAGE)
            && Path::new(r"C:\zapret\general (ALT9).bat").exists()
        {
            let _ = util::run_hidden_file(Path::new(r"C:\zapret\general (ALT9).bat"));
        }
        std::thread::sleep(Duration::from_secs(3));
        if crate::modules::detect::proc_running(IMAGE) {
            ctx.log("✓ Существующий обход работает.");
        } else {
            ctx.log("⚠ Существующий zapret найден, но не запущен. Можно переустановить в «Тонкой настройке».");
        }
        return Ok(());
    }

    let client = util::http_client()?;
    let dir = ctx.dir("zapret");
    let winws = dir.join("bin").join(IMAGE);

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

    if ctx.opts.autostart && ctx.admin && ctx.opts.service_mode && owns_service(&ctx.data) {
        let _ = util::hidden_str("sc", &["config", SERVICE, "start=", "auto"]);
        ctx.log("Служба zapret переведена в автозапуск.");
    }
    Ok(())
}

/// Command line for `sc create binPath=`: the exe quoted, then each argument
/// quoted only when needed. `sc` stores this string verbatim, so a path with
/// spaces must keep its quotes.
pub fn service_bin_path(cmdline: &str) -> Option<String> {
    let parts = util::split_windows_cmdline(cmdline);
    let (exe, args) = parts.split_first()?;
    if exe.is_empty() {
        return None;
    }
    let mut out = format!("\"{exe}\"");
    for a in args {
        if a.is_empty() {
            continue;
        }
        out.push(' ');
        out.push_str(&util::quote_win_arg(a));
    }
    Some(out)
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
    let be = SystemProcs;
    // Stop only a winws.exe we started earlier (recorded pid + image path).
    match proc::owned_alive(&ctx.data, &be, IMAGE) {
        Ok(list) => {
            for p in list {
                match proc::kill_owned(&be, IMAGE, p.pid, &p.exe) {
                    Ok(()) => ctx.log(format!("Останавливаю прошлый winws.exe (pid {})", p.pid)),
                    Err(e) => ctx.log(format!("⚠ прошлый winws.exe не остановлен: {e:#}")),
                }
            }
            let _ = proc::forget(&ctx.data, IMAGE);
        }
        Err(e) => ctx.log(format!("⚠ не удалось получить список процессов: {e:#}")),
    }

    // Remember what was already running so we only claim what we start.
    let before = match be.list(IMAGE) {
        Ok(v) => v,
        Err(e) => {
            ctx.log(format!(
                "⚠ не удалось записать владение процессом: {e:#} — при выключении трогать его не будем"
            ));
            Vec::new()
        }
    };
    if !before.is_empty() {
        ctx.log(format!(
            "⚠ winws.exe уже запущен ({} шт.) и не наш — не трогаю его",
            before.len()
        ));
    }

    let bat = dir.join(preset);
    util::run_hidden_file(&bat)
        .with_context(|| format!("не удалось запустить {}", bat.display()))?;
    ctx.log("zapret запущен (портативно). Проверяю...");

    // Poll for the process instead of a blind sleep.
    let started = Instant::now();
    let mut seen = false;
    while started.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(500));
        if let Ok(list) = be.list(IMAGE) {
            if list.iter().any(|p| !before.iter().any(|b| b.pid == p.pid)) {
                seen = true;
                break;
            }
        }
    }

    if seen {
        match proc::record_new(&ctx.data, &be, IMAGE, &before) {
            Ok(fresh) if !fresh.is_empty() => {
                for p in &fresh {
                    ctx.log(format!(
                        "✓ winws.exe работает (pid {}, {})",
                        p.pid,
                        if p.exe.is_empty() { "путь неизвестен" } else { &p.exe }
                    ));
                }
            }
            Ok(_) => ctx.log("✓ winws.exe работает"),
            Err(e) => ctx.log(format!("⚠ процесс работает, но владение не записано: {e:#}")),
        }
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
    let bin_path = service_bin_path(&cmdline)
        .ok_or_else(|| anyhow::anyhow!("не удалось собрать binPath для службы"))?;

    if service_exists() {
        if owns_service(&ctx.data) {
            let _ = util::hidden_str("sc", &["stop", SERVICE]);
            let _ = util::hidden_str("sc", &["delete", SERVICE]);
            if !wait_service_gone(Duration::from_secs(5)) {
                ctx.log("⚠ служба ещё числится удаляемой — Windows завершит удаление сама");
            }
        } else {
            ctx.log("⚠ Служба zapret уже есть и установлена не нами — оставляю её как есть.");
            ctx.log("  Переустановить можно вручную: sc delete zapret, затем повторить.");
            return Ok(());
        }
    }

    // Stop our own portable instance only; a foreign winws.exe is left alone.
    if let Ok(list) = proc::owned_alive(&ctx.data, &SystemProcs, IMAGE) {
        for p in list {
            let _ = proc::kill_owned(&SystemProcs, IMAGE, p.pid, &p.exe);
        }
        let _ = proc::forget(&ctx.data, IMAGE);
    }

    let start_mode = if ctx.opts.autostart { "auto" } else { "demand" };
    let mut args: Vec<String> = vec!["create".into(), SERVICE.into(), "binPath=".into()];
    // One argument: `sc` joins argv with spaces, which would drop the quotes
    // around a path containing spaces.
    args.push(bin_path);
    args.push("DisplayName=".into());
    args.push("zapret".into());
    args.push("start=".into());
    args.push(start_mode.into());
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let out = util::hidden_str("sc", &refs)?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        anyhow::bail!("sc create: {}", err.trim());
    }
    if !service_exists() {
        anyhow::bail!("sc create сообщил об успехе, но службы {SERVICE} нет");
    }

    // Mark it as ours: the marker is what `off` and a later run check.
    let svc_key = format!(r"System\CurrentControlSet\Services\{SERVICE}");
    let _ = util::reg_set_string("HKLM", &svc_key, "obhod-preset", preset);
    let _ = util::reg_set_string("HKLM", &svc_key, "obhod-owned", "1");
    let _ = proc::own_service(&ctx.data, SERVICE);
    let _ = util::hidden_str("sc", &["description", SERVICE, "Zapret DPI bypass (obhod)"]);

    journal::note_action(
        &Journal::new(ctx.data.clone()),
        "zapret",
        "service-create",
        serde_json::json!({ "service": SERVICE, "preset": preset }),
        crate::sys::journal::Undo::Note {
            component: "zapret".into(),
            text: format!("служба {SERVICE} создана нами"),
        },
    )
    .ok();

    let started = util::hidden_str("sc", &["start", SERVICE])?;
    if started.status.success() {
        ctx.log("✓ Служба zapret установлена и запущена (автозапуск).");
    } else {
        ctx.log("⚠ Служба создана, но не стартовала — проверьте лог Windows.");
    }
    Ok(())
}

fn wait_service_gone(timeout: Duration) -> bool {
    let started = Instant::now();
    while started.elapsed() < timeout {
        if !service_exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    !service_exists()
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
                if rest.chars().next().is_none_or(|c| c.is_whitespace()) {
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

#[allow(dead_code)]
fn _paths(dir: &Path) -> PathBuf {
    dir.join("bin").join("winws.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bin_path_quotes_the_exe_and_args_with_spaces() {
        let cmd = r#""C:\my tools\bin\winws.exe" --wf-tcp=80,443 --hostlist="C:\my tools\lists\list.txt" --new --filter-udp=443"#;
        let bin = service_bin_path(cmd).unwrap();
        assert_eq!(
            bin,
            r#""C:\my tools\bin\winws.exe" --wf-tcp=80,443 "--hostlist=C:\my tools\lists\list.txt" --new --filter-udp=443"#
        );
        // It must survive a trip through a command line unchanged.
        assert_eq!(util::split_windows_cmdline(&util::quote_win_arg(&bin)), vec![bin.clone()]);
    }

    #[test]
    fn bin_path_without_spaces_has_no_extra_quotes() {
        let cmd = r#""C:\zapret\bin\winws.exe" --wf-tcp=80"#;
        assert_eq!(
            service_bin_path(cmd).unwrap(),
            r#""C:\zapret\bin\winws.exe" --wf-tcp=80"#
        );
        assert!(service_bin_path("").is_none());
        assert!(service_bin_path("   ").is_none());
    }

    #[test]
    fn bat_parser_turns_a_preset_into_a_winws_command() {
        let bat = "\
@echo off
chcp 65001 > nul
cd /d \"%~dp0\"
start \"zapret\" /min \"%BIN%winws.exe\" --wf-tcp=80,443 --wf-udp=443 ^
 --filter-tcp=80 --hostlist=\"%LISTS%list.txt\" --new --filter-udp=443 ^
 --filter-l7=discord,stun
";
        let dir = Path::new(r"C:\tools\data\zapret");
        let cmd = bat_to_cmdline(bat, dir).unwrap();
        assert!(cmd.contains(r"C:\tools\data\zapret\bin\winws.exe"), "{cmd}");
        assert!(cmd.contains(r#"--hostlist="C:\tools\data\zapret\lists\list.txt""#), "{cmd}");
        assert!(cmd.contains("--filter-l7=discord,stun"), "{cmd}");
        // Still a single command line that can be split into argv.
        assert!(util::split_windows_cmdline(&cmd).len() >= 6);
    }

    #[test]
    fn ownership_check_does_not_claim_a_foreign_service() {
        // No ledger and no marker: a service installed by the user is not ours.
        let dir = tempfile::tempdir().unwrap();
        assert!(!owns_service(dir.path()));
    }
}

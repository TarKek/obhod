use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::modules::{clients, detect, Ctx};
use crate::net::{sha256_file, trust};
use crate::state::{now_secs, State};
use crate::sys::proc;
use crate::util;

/// Stops only processes that obhod spawned and recorded in its ownership
/// ledger. Foreign copies (a user's Happ, another TgWsProxy) are left alone.
fn stop_owned(ctx: &Ctx, image: &str) {
    let be = proc::SystemProcs;
    let owned = proc::owned_alive(&ctx.data, &be, image).unwrap_or_default();
    for p in owned {
        if let Err(e) = proc::kill_owned(&be, image, p.pid, &p.exe) {
            ctx.log(format!("⚠ не удалось остановить свой {image}: {e:#}"));
        }
    }
}

pub struct Tool {
    pub id: &'static str,
    pub name: &'static str,
    pub repo: &'static str,
}

pub const TOOLS: &[Tool] = &[
    Tool {
        id: "zapret",
        name: "zapret",
        repo: "Flowseal/zapret-discord-youtube",
    },
    Tool {
        id: "tgws",
        name: "TgWsProxy",
        repo: "Flowseal/tg-ws-proxy",
    },
    Tool {
        id: "client_hiddify",
        name: "Hiddify",
        repo: "hiddify/hiddify-app",
    },
    Tool {
        id: "client_v2rayn",
        name: "v2rayN",
        repo: "2dust/v2rayN",
    },
    Tool {
        id: "client_happ",
        name: "Happ",
        repo: "Happ-proxy/happ-desktop",
    },
];

fn ver_nums(s: &str) -> Vec<u64> {
    s.split(|c: char| !c.is_ascii_digit())
        .filter(|p| !p.is_empty())
        .filter_map(|p| p.parse::<u64>().ok())
        .collect()
}

/// True when `installed` is the same version or newer than `latest`.
pub fn version_current(installed: &str, latest: &str) -> bool {
    let a = ver_nums(installed);
    let b = ver_nums(latest);
    if a.is_empty() || b.is_empty() {
        return false;
    }
    for i in 0..a.len().max(b.len()) {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        if x != y {
            return x > y;
        }
    }
    true
}

fn short(v: &str) -> String {
    let s = v.trim().trim_start_matches('v');
    if s.is_empty() {
        "?".into()
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// Staged component updates
// ---------------------------------------------------------------------------
//
// Rule: the working copy is never deleted before the new one is downloaded,
// extracted, CRC-checked, hash-checked and its expected executable is present.
// The old file/directory is kept as a backup; if the swap or the post-swap
// verification fails, the old version is put back automatically.

/// Verified payload waiting to be swapped in.
#[derive(Debug)]
pub struct Staging {
    pub root: PathBuf,
    /// Expected executable (for archives) or the staged copy of it.
    pub exe: PathBuf,
    pub sha256: String,
    #[allow(dead_code)] // reported by tests and future UI
    pub entries: usize,
}

#[derive(Debug)]
pub struct InstallReport {
    pub target: PathBuf,
    pub exe: PathBuf,
    pub backup: Option<PathBuf>,
    pub sha256: String,
    #[allow(dead_code)] // used by tests; kept for the UI's "what changed" view
    pub moved_old: bool,
}

fn stamp() -> String {
    now_secs().to_string()
}

fn fresh_dir(root: &Path, tag: &str) -> Result<PathBuf> {
    fs::create_dir_all(root)?;
    let safe: String = tag
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(24)
        .collect();
    let dir = root.join(format!("{}-{}-{}", safe, std::process::id(), stamp()));
    if dir.exists() {
        let _ = fs::remove_dir_all(&dir);
    }
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn is_windows_exe(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return false;
    };
    let mut b = [0u8; 2];
    matches!(f.read_exact(&mut b), Ok(())) && &b == b"MZ"
}

/// Reads every archive entry once: a CRC/size error means the download is
/// corrupt. Also caps the unpacked size to avoid a zip bomb.
fn verify_zip(zip: &Path) -> Result<usize> {
    const MAX_TOTAL: u64 = 2 * 1024 * 1024 * 1024;
    let f = fs::File::open(zip).with_context(|| format!("открыть {}", zip.display()))?;
    let mut ar = zip::ZipArchive::new(f).context("архив не читается как zip")?;
    if ar.is_empty() {
        bail!("архив пуст");
    }
    let mut total: u64 = 0;
    for i in 0..ar.len() {
        let mut entry = ar
            .by_index(i)
            .with_context(|| format!("запись #{i} повреждена"))?;
        total = total.saturating_add(entry.size());
        if total > MAX_TOTAL {
            bail!("распакованный размер архива слишком большой");
        }
        if entry.is_dir() {
            continue;
        }
        let name = entry.name().to_string();
        std::io::copy(&mut entry, &mut std::io::sink())
            .with_context(|| format!("CRC-проверка записи «{name}»"))?;
    }
    Ok(ar.len())
}

fn extract_zip(zip: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    let f = fs::File::open(zip)?;
    let mut ar = zip::ZipArchive::new(f)?;
    // The zip crate rejects entries escaping the destination directory.
    ar.extract(dest).context("не удалось распаковать архив")?;
    Ok(())
}

fn check_exe(path: &Path, expected_sha: Option<&str>) -> Result<String> {
    if !path.is_file() {
        bail!("нет файла {}", path.display());
    }
    if fs::metadata(path)?.len() < 2 {
        bail!("файл {} пуст", path.display());
    }
    if !is_windows_exe(path) {
        bail!(
            "файл {} не является программой Windows (нет MZ)",
            path.display()
        );
    }
    let sha = sha256_file(path)?;
    if let Some(exp) = expected_sha {
        let want = trust::normalize_sha256(exp).unwrap_or_else(|| exp.trim().to_ascii_lowercase());
        if want != sha {
            bail!("sha256 не совпадает: ожидалось {want}, получено {sha}");
        }
    }
    Ok(sha)
}

/// Verifies a zip and extracts it to a fresh staging directory.
pub fn prepare_from_zip(
    zip: &Path,
    staging_root: &Path,
    expected_exe: &str,
    expected_archive_sha: Option<&str>,
) -> Result<Staging> {
    if let Some(exp) = expected_archive_sha {
        let got = sha256_file(zip)?;
        let want = trust::normalize_sha256(exp).unwrap_or_else(|| exp.trim().to_ascii_lowercase());
        if want != got {
            bail!("sha256 архива не совпадает: ожидалось {want}, получено {got}");
        }
    }
    let entries = verify_zip(zip)?;
    let root = fresh_dir(staging_root, "zip")?;
    let result = (|| -> Result<Staging> {
        extract_zip(zip, &root)?;
        let exe = detect::find_exe_in(&root, expected_exe, 6)
            .with_context(|| format!("в архиве нет {expected_exe} — версия несовместима"))?;
        let sha = check_exe(&exe, None)?;
        Ok(Staging {
            root: root.clone(),
            exe,
            sha256: sha,
            entries,
        })
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&root);
    }
    result
}

/// Copies a single executable into staging after MZ/hash checks.
pub fn prepare_from_exe(
    exe: &Path,
    staging_root: &Path,
    expected_sha: Option<&str>,
) -> Result<Staging> {
    let sha = check_exe(exe, expected_sha)?;
    let root = fresh_dir(staging_root, "exe")?;
    let name = exe
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("component.exe"));
    let dest = root.join(name);
    if let Err(e) = fs::copy(exe, &dest) {
        let _ = fs::remove_dir_all(&root);
        return Err(e).context("не удалось скопировать файл в staging");
    }
    let dest_sha = match check_exe(&dest, Some(&sha)) {
        Ok(s) => s,
        Err(e) => {
            let _ = fs::remove_dir_all(&root);
            return Err(e);
        }
    };
    Ok(Staging {
        root,
        exe: dest,
        sha256: dest_sha,
        entries: 1,
    })
}

fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if from.is_dir() {
            copy_tree(&from, &to)?;
        } else {
            fs::copy(&from, &to).with_context(|| format!("копирование {}", from.display()))?;
        }
    }
    Ok(())
}

fn move_dir(src: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        fs::remove_dir_all(dest)?;
    }
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Different volume (e.g. data dir on D:, client in %LOCALAPPDATA%).
            copy_tree(src, dest)?;
            fs::remove_dir_all(src).ok();
            Ok(())
        }
    }
}

/// Deletes older staging directories, keeping the one just used.
pub fn cleanup_staging(root: &Path, keep: &Path) {
    let Ok(rd) = fs::read_dir(root) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p == keep {
            continue;
        }
        if p.is_dir() {
            let _ = fs::remove_dir_all(&p);
        }
    }
}

/// Swaps a single executable in place, with a backup and rollback.
pub fn install_exe(staged: &Staging, target: &Path, backup_root: &Path) -> Result<InstallReport> {
    if sha256_file(&staged.exe)? != staged.sha256 {
        bail!("подготовленный файл изменился после проверки");
    }
    let parent = target
        .parent()
        .with_context(|| format!("у {} нет папки", target.display()))?;
    fs::create_dir_all(parent)?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("component.exe");

    let backup = if target.exists() {
        fs::create_dir_all(backup_root)?;
        let b = backup_root.join(format!("{name}.bak-{}", stamp()));
        fs::copy(target, &b)
            .with_context(|| format!("не удалось сохранить резервную копию {}", b.display()))?;
        let src_len = fs::metadata(target)?.len();
        if fs::metadata(&b)?.len() != src_len {
            bail!("резервная копия {} неполная", b.display());
        }
        Some(b)
    } else {
        None
    };

    let tmp = parent.join(format!(".{name}.new-{}", stamp()));
    fs::copy(&staged.exe, &tmp).context("не удалось записать новую версию")?;
    if sha256_file(&tmp).unwrap_or_default() != staged.sha256 {
        let _ = fs::remove_file(&tmp);
        bail!("новая версия повреждена при записи");
    }

    let old = parent.join(format!(".{name}.old-{}", stamp()));
    let moved = if target.exists() {
        if let Err(e) = fs::rename(target, &old) {
            let _ = fs::remove_file(&tmp);
            return Err(e).with_context(|| format!("не удалось отодвинуть {}", target.display()));
        }
        true
    } else {
        false
    };

    if let Err(e) = fs::rename(&tmp, target) {
        let _ = fs::remove_file(&tmp);
        if moved {
            let _ = fs::rename(&old, target);
        }
        return Err(e).context("не удалось заменить файл");
    }

    // Post-swap verification: compare what actually landed on disk.
    match sha256_file(target) {
        Ok(h) if h == staged.sha256 => {}
        _ => {
            let _ = fs::remove_file(target);
            if moved {
                let _ = fs::rename(&old, target);
            }
            bail!("после замены файл не совпадает — вернул прежнюю версию");
        }
    }
    if moved {
        let _ = fs::remove_file(&old);
    }
    Ok(InstallReport {
        target: target.to_path_buf(),
        exe: target.to_path_buf(),
        backup,
        sha256: staged.sha256.clone(),
        moved_old: moved,
    })
}

/// Swaps a whole directory (portable program), with a backup and rollback.
pub fn install_dir(
    staged: &Staging,
    target: &Path,
    expected_exe: &str,
    backup_root: &Path,
) -> Result<InstallReport> {
    let staged_exe = detect::find_exe_in(&staged.root, expected_exe, 6)
        .with_context(|| format!("подготовленная копия не содержит {expected_exe}"))?;
    let sha = sha256_file(&staged_exe)?;
    if sha != staged.sha256 {
        bail!("подготовленная копия изменилась после проверки");
    }
    let parent = target
        .parent()
        .with_context(|| format!("у {} нет папки", target.display()))?;
    fs::create_dir_all(parent)?;
    fs::create_dir_all(backup_root)?;
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("component");

    let backup = if target.exists() {
        let b = backup_root.join(format!("{name}.bak-{}", stamp()));
        copy_tree(target, &b)
            .with_context(|| format!("не удалось сохранить копию {}", target.display()))?;
        Some(b)
    } else {
        None
    };

    let old = parent.join(format!(".{name}.old-{}", stamp()));
    let moved = if target.exists() {
        if let Err(e) = fs::rename(target, &old) {
            return Err(e).with_context(|| {
                format!(
                    "не удалось отодвинуть папку {} (закройте программу и повторите)",
                    target.display()
                )
            });
        }
        true
    } else {
        false
    };

    if let Err(e) = move_dir(&staged.root, target) {
        if moved {
            let _ = fs::rename(&old, target);
        }
        return Err(e).context("не удалось подменить папку");
    }

    let installed_exe = detect::find_exe_in(target, expected_exe, 6);
    let ok = installed_exe
        .as_deref()
        .map(|p| sha256_file(p).map(|h| h == sha).unwrap_or(false))
        .unwrap_or(false);
    if !ok {
        let _ = fs::remove_dir_all(target);
        if moved {
            let _ = fs::rename(&old, target);
        }
        bail!("после замены {expected_exe} не найден или повреждён — вернул прежнюю версию");
    }
    if moved {
        let _ = fs::remove_dir_all(&old);
    }
    Ok(InstallReport {
        target: target.to_path_buf(),
        exe: installed_exe.unwrap_or_else(|| target.join(expected_exe)),
        backup,
        sha256: sha,
        moved_old: moved,
    })
}

/// Downloads the latest zip of `repo`, verifies it and swaps it into
/// `target_dir` (used for our own portable copies).
fn update_own_zip(
    ctx: &Ctx,
    client: &reqwest::blocking::Client,
    repo: &str,
    expected_exe: &str,
    target_dir: &Path,
) -> Result<()> {
    let dl = ctx.dir("downloads");
    fs::create_dir_all(&dl)?;
    let zip = util::github_asset(client, repo, ".zip", &dl)?;
    let staging_root = ctx.dir("staging");
    let staged = prepare_from_zip(&zip, &staging_root, expected_exe, None)?;
    let report = install_dir(&staged, target_dir, expected_exe, &ctx.dir("backup"))?;
    cleanup_staging(&staging_root, &report.target);
    let backup = report
        .backup
        .as_ref()
        .map(|b| b.display().to_string())
        .unwrap_or_else(|| "нет (первая установка)".into());
    ctx.log(format!(
        "  проверено: sha256 {}… · старая версия: {}",
        &report.sha256[..12],
        backup
    ));
    Ok(())
}

/// Same for a single executable component (TgWsProxy).
fn update_own_exe(
    ctx: &Ctx,
    client: &reqwest::blocking::Client,
    repo: &str,
    target_dir: &Path,
) -> Result<PathBuf> {
    let dl = ctx.dir("downloads");
    fs::create_dir_all(&dl)?;
    let exe = util::github_asset(client, repo, ".exe", &dl)?;
    let staging_root = ctx.dir("staging");
    let staged = prepare_from_exe(&exe, &staging_root, None)?;
    let name = exe
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("component.exe"));
    let report = install_exe(&staged, &target_dir.join(name), &ctx.dir("backup"))?;
    cleanup_staging(&staging_root, &report.target);
    ctx.log(format!(
        "  проверено: sha256 {}… · резервная копия: {}",
        &report.sha256[..12],
        report
            .backup
            .as_ref()
            .map(|b| b.display().to_string())
            .unwrap_or_else(|| "нет".into())
    ));
    Ok(report.exe)
}

/// Read-only check: finds installed programs anywhere on the machine and
/// reports their real version next to the latest release of their own source.
pub fn check(ctx: &Ctx) -> Result<()> {
    let client = util::http_client()?;
    ctx.log("Ищу установленные программы...");
    let found = detect::installed();
    for t in TOOLS {
        let app = found.iter().find(|f| f.key == t.id);
        let (latest, source) = if t.id == "zapret" {
            match app.and_then(|a| zapret_latest(&client, a)) {
                Some(v) => v,
                None => {
                    ctx.log(format!("• {}: не удалось проверить обновления", t.name));
                    continue;
                }
            }
        } else {
            match util::github_latest_tag(&client, t.repo) {
                Ok(v) => (v, String::new()),
                Err(e) => {
                    ctx.log(format!("• {}: не удалось проверить ({e})", t.name));
                    continue;
                }
            }
        };
        let from = if source.is_empty() {
            String::new()
        } else {
            format!(" · источник: {source}")
        };
        match app {
            Some(app) => {
                let loc = app
                    .path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "найдено".into());
                match &app.version {
                    Some(v) if version_current(v, &latest) => ctx.log(format!(
                        "• {}: {} — актуально ({loc}{from})",
                        t.name,
                        short(v)
                    )),
                    Some(v) => ctx.log(format!(
                        "• {}: {} → {} — есть обновление ({loc}{from})",
                        t.name,
                        short(v),
                        short(&latest)
                    )),
                    None => ctx.log(format!(
                        "• {}: установлен, но версию определить не удалось · последняя {} ({loc}{from})",
                        t.name,
                        short(&latest)
                    )),
                }
            }
            None => ctx.log(format!(
                "• {}: не найден · последняя {}{from}",
                t.name,
                short(&latest)
            )),
        }
    }
    ctx.log("Готово. Списки прокси обновляются отдельным пунктом.");
    Ok(())
}

/// zapret can be installed from different builds (Flowseal, zapret-roblox, ...).
/// Its own service.bat names the version feed, so we ask that feed instead of
/// comparing apples to oranges.
fn zapret_update_source(app: &detect::Installed) -> Option<(String, String)> {
    let exe = app.path.as_ref()?;
    let root = exe.parent()?.parent()?;
    let text = std::fs::read_to_string(root.join("service.bat")).ok()?;
    let url = detect::bat_var(&text, "GITHUB_VERSION_URL")?;
    let label = detect::bat_var(&text, "GITHUB_RELEASE_URL")
        .and_then(|u| repo_from_url(&u))
        .unwrap_or_else(|| "service.bat".into());
    Some((url, label))
}

fn repo_from_url(u: &str) -> Option<String> {
    let after = u.split("github.com/").nth(1)?;
    let parts: Vec<&str> = after.split('/').filter(|s| !s.is_empty()).collect();
    if parts.len() >= 2 {
        Some(format!("{}/{}", parts[0], parts[1]))
    } else {
        None
    }
}

fn fetch_version(client: &reqwest::blocking::Client, url: &str) -> Option<String> {
    let s = client.get(url).send().ok()?.text().ok()?;
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(s.lines().next().unwrap_or(s).trim().to_string())
    }
}

fn zapret_latest(
    client: &reqwest::blocking::Client,
    app: &detect::Installed,
) -> Option<(String, String)> {
    if let Some((url, label)) = zapret_update_source(app) {
        if let Some(v) = fetch_version(client, &url) {
            return Some((v, label));
        }
    }
    util::github_latest_tag(client, "Flowseal/zapret-discord-youtube")
        .ok()
        .map(|v| (v, "Flowseal".into()))
}

/// Updates what is actually installed. Own copies in `data\` are refreshed;
/// a found Happ / TgWsProxy is updated in place (with a backup for TgWsProxy).
/// Portable Hiddify/v2rayN folders in random locations are left untouched.
pub fn update_tools(ctx: &Ctx) -> Result<()> {
    let client = util::http_client()?;
    let mut st = State::load(&ctx.data);
    let found = detect::installed();
    let mut handled: Vec<&'static str> = Vec::new();

    for app in &found {
        // Copies under our own data dir are handled by the block below.
        if app
            .path
            .as_ref()
            .map(|p| p.starts_with(&ctx.data))
            .unwrap_or(false)
        {
            continue;
        }
        match app.key {
            "tgws" => {
                if update_found_tgws(ctx, &client, app, &mut st) {
                    handled.push("tgws");
                }
            }
            "client_happ" => {
                if update_found_happ(ctx, &client, app, &mut st) {
                    handled.push("client_happ");
                }
            }
            "zapret" => {
                let loc = app
                    .path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "C:\\zapret".into());
                match (&app.version, zapret_latest(&client, app)) {
                    (Some(v), Some((tag, src))) if version_current(v, &tag) => {
                        ctx.log(format!(
                            "• zapret: {} — актуально ({loc} · {src})",
                            short(v)
                        ));
                    }
                    (Some(v), Some((tag, src))) => {
                        ctx.log(format!(
                            "• zapret: {} → {} — есть обновление ({src}). Автоматически не трогаю, чтобы не сломать пресет; обновление ставится через service.bat.",
                            short(v),
                            short(&tag)
                        ));
                    }
                    _ => ctx.log(format!(
                        "• zapret: установлен в {loc}, версию определить не удалось — не трогаю."
                    )),
                }
            }
            "client_hiddify" | "client_v2rayn" => {
                if handled_client_by_config(ctx, app.key) {
                    continue;
                }
                if let (Some(v), Ok(tag)) = (
                    app.version.as_deref(),
                    util::github_latest_tag(&client, repo_for(app.key)),
                ) {
                    if !version_current(v, &tag) {
                        ctx.log(format!(
                            "• {}: {} → {} — обновление есть, но чужую папку не трогаю. Обновите внутри приложения.",
                            app.name,
                            short(v),
                            short(&tag)
                        ));
                    }
                }
            }
            _ => {}
        }
    }

    // --- our own copies under data\ -------------------------------------
    if ctx.opts.components.zapret {
        let dir = ctx.dir("zapret");
        if dir.exists() && !handled.contains(&"zapret") {
            ctx.progress(20, "zapret".to_string());
            let tag = util::github_latest_tag(&client, "Flowseal/zapret-discord-youtube").ok();
            ctx.log("Обновляю свою копию zapret: скачиваю и проверяю новую версию...");
            match update_own_zip(
                ctx,
                &client,
                "Flowseal/zapret-discord-youtube",
                "winws.exe",
                &dir,
            ) {
                Ok(_) => match crate::modules::zapret::run(&forced_ctx(ctx)) {
                    Ok(_) => {
                        if let Some(t) = &tag {
                            st.set_tool("zapret", t);
                        }
                        ctx.log("✓ zapret обновлён.");
                    }
                    Err(e) => ctx.log(format!("⚠ zapret скачан, но настроить не удалось: {e:#}")),
                },
                Err(e) => ctx.log(format!(
                    "⚠ zapret: {e:#}. Прежняя копия сохранена и не тронута."
                )),
            }
        }
    }

    if ctx.opts.components.tgws {
        let dir = ctx.dir("tgws");
        if dir.exists() && !handled.contains(&"tgws") {
            ctx.progress(40, "TgWsProxy".to_string());
            let tag = util::github_latest_tag(&client, "Flowseal/tg-ws-proxy").ok();
            ctx.log("Обновляю свою копию TgWsProxy: скачиваю и проверяю новую версию...");
            match update_own_exe(ctx, &client, "Flowseal/tg-ws-proxy", &dir) {
                Ok(exe) => match crate::modules::tgws::run_from(&forced_ctx(ctx), Some(&exe)) {
                    Ok(_) => {
                        if let Some(t) = &tag {
                            st.set_tool("tgws", t);
                        }
                        ctx.log("✓ TgWsProxy обновлён.");
                    }
                    Err(e) => ctx.log(format!("⚠ TgWsProxy: {e:#}")),
                },
                Err(e) => ctx.log(format!(
                    "⚠ TgWsProxy: {e:#}. Прежняя копия сохранена и не тронута."
                )),
            }
        }
    }

    let app = ctx.opts.client.as_str();
    if app != "none" && !app.is_empty() {
        let key = match app {
            "hiddify" => "client_hiddify",
            "v2rayn" => "client_v2rayn",
            "happ" => "client_happ",
            _ => "",
        };
        let base = clients::app_base_dir(ctx, app);
        if base.exists() && !handled.contains(&key) {
            let tag = util::github_latest_tag(&client, repo_for(key)).ok();
            let name = match app {
                "hiddify" => "Hiddify",
                "v2rayn" => "v2rayN",
                "happ" => "Happ",
                _ => app,
            };
            ctx.progress(60, name.to_string());
            ctx.log(format!(
                "Обновляю {name}: скачиваю и проверяю новую версию..."
            ));
            match clients::update_copy(&forced_ctx(ctx)) {
                Ok(_) => {
                    if let Some(t) = &tag {
                        st.set_tool(key, t);
                    }
                    ctx.log(format!("✓ {name} обновлён."));
                }
                Err(e) => ctx.log(format!(
                    "⚠ {name}: {e:#}. Прежняя копия сохранена и не тронута."
                )),
            }
        }
    }

    st.save(&ctx.data)?;
    Ok(())
}

fn repo_for(key: &str) -> &'static str {
    match key {
        "zapret" => "Flowseal/zapret-discord-youtube",
        "tgws" => "Flowseal/tg-ws-proxy",
        "hiddify" | "client_hiddify" => "hiddify/hiddify-app",
        "v2rayn" | "client_v2rayn" => "2dust/v2rayN",
        "happ" | "client_happ" => "Happ-proxy/happ-desktop",
        _ => "",
    }
}

fn handled_client_by_config(ctx: &Ctx, key: &str) -> bool {
    matches!(
        (ctx.opts.client.as_str(), key),
        ("hiddify", "client_hiddify") | ("v2rayn", "client_v2rayn") | ("happ", "client_happ")
    )
}

fn update_found_happ(
    ctx: &Ctx,
    client: &reqwest::blocking::Client,
    app: &detect::Installed,
    st: &mut State,
) -> bool {
    let Some(path) = &app.path else {
        return false;
    };
    let latest = match util::github_latest_tag(client, "Happ-proxy/happ-desktop") {
        Ok(v) => v,
        Err(e) => {
            ctx.log(format!("⚠ Happ: не удалось узнать версию ({e})"));
            return false;
        }
    };
    if let Some(cur) = &app.version {
        if version_current(cur, &latest) {
            ctx.log(format!("• Happ: {} — актуально", short(cur)));
            return true;
        }
    }
    let dir = path.parent().unwrap_or(Path::new("."));
    ctx.progress(65, "Happ".to_string());
    ctx.log(format!(
        "Обновляю Happ {} → {} в {}",
        app.version
            .as_deref()
            .map(short)
            .unwrap_or_else(|| "?".into()),
        short(&latest),
        dir.display()
    ));
    let setup = match util::github_asset_filtered(
        client,
        "Happ-proxy/happ-desktop",
        ".exe",
        "x64",
        &ctx.dir("downloads"),
    ) {
        Ok(p) => p,
        Err(e) => {
            ctx.log(format!("⚠ Happ: {e:#}"));
            return false;
        }
    };
    // The installer cannot replace files of a running app. Stop only a copy
    // that obhod itself started; a user-installed Happ is never killed.
    stop_owned(ctx, "Happ.exe");
    let arg = format!("/D={}", dir.display());
    let status = Command::new(&setup)
        .arg("/S")
        .arg(&arg)
        .spawn()
        .and_then(|mut c| c.wait());
    match status {
        Ok(s) if s.success() => {
            st.set_tool("client_happ", &latest);
            ctx.log("✓ Happ обновлён.");
            if path.exists() {
                let _ = Command::new(path).spawn();
            }
            true
        }
        Ok(_) => {
            ctx.log("⚠ Установщик Happ завершился с ошибкой. Можно обновить вручную.");
            false
        }
        Err(e) => {
            ctx.log(format!("⚠ Не удалось запустить установщик Happ: {e}"));
            false
        }
    }
}

fn update_found_tgws(
    ctx: &Ctx,
    client: &reqwest::blocking::Client,
    app: &detect::Installed,
    st: &mut State,
) -> bool {
    let Some(path) = &app.path else {
        return false;
    };
    let latest = match util::github_latest_tag(client, "Flowseal/tg-ws-proxy") {
        Ok(v) => v,
        Err(e) => {
            ctx.log(format!("⚠ TgWsProxy: не удалось узнать версию ({e})"));
            return false;
        }
    };
    if let Some(cur) = &app.version {
        if version_current(cur, &latest) {
            ctx.log(format!("• TgWsProxy: {} — актуально", short(cur)));
            return true;
        }
    }
    ctx.progress(45, "TgWsProxy".to_string());
    ctx.log(format!(
        "Обновляю TgWsProxy {} → {} ({})",
        app.version
            .as_deref()
            .map(short)
            .unwrap_or_else(|| "?".into()),
        short(&latest),
        path.display()
    ));
    let new_exe = match util::github_asset_filtered(
        client,
        "Flowseal/tg-ws-proxy",
        ".exe",
        "windows.exe",
        &ctx.dir("downloads"),
    ) {
        Ok(p) => p,
        Err(e) => {
            ctx.log(format!("⚠ TgWsProxy: {e:#}"));
            return false;
        }
    };
    let staged = match prepare_from_exe(&new_exe, &ctx.dir("staging"), None) {
        Ok(s) => s,
        Err(e) => {
            ctx.log(format!("⚠ TgWsProxy: {e:#}. Текущая версия не тронута."));
            return false;
        }
    };
    if app.running {
        stop_owned(ctx, "TgWsProxy.exe");
    }
    match install_exe(&staged, path, &ctx.dir("backup")) {
        Ok(report) => {
            cleanup_staging(&ctx.dir("staging"), &report.target);
            st.set_tool("tgws", &latest);
            ctx.log(format!(
                "✓ TgWsProxy обновлён (резервная копия: {})",
                report
                    .backup
                    .as_ref()
                    .map(|b| b.display().to_string())
                    .unwrap_or_else(|| "нет".into())
            ));
            if app.running {
                let _ = Command::new(path).spawn();
            }
            true
        }
        Err(e) => {
            ctx.log(format!(
                "⚠ Не удалось заменить TgWsProxy: {e:#}. Прежняя версия сохранена."
            ));
            false
        }
    }
}

/// Re-fetch and re-test Telegram proxies; the best one is opened in Telegram.
pub fn update_telegram_proxies(ctx: &Ctx) -> Result<()> {
    ctx.log("Обновляю прокси Telegram...");
    if let Err(e) = crate::modules::telegram::run(ctx) {
        ctx.log(format!("⚠ Telegram-прокси: {e:#}"));
    }
    let mut st = State::load(&ctx.data);
    st.lists_updated = now_secs();
    st.save(&ctx.data)?;
    Ok(())
}

/// Re-fetch free servers and refresh the subscription the VPN client reads.
pub fn update_vpn_subscription(ctx: &Ctx) -> Result<()> {
    if ctx.opts.client == "none" || ctx.opts.client.is_empty() {
        ctx.log("VPN-клиент не выбран — обновляю список серверов и файл подписки.");
    }
    ctx.log("Обновляю бесплатные серверы...");
    if let Err(e) = crate::modules::subs::run(ctx) {
        ctx.log(format!("⚠ Серверы: {e:#}"));
    }
    ctx.log("Обновляю подписку клиента...");
    if let Err(e) = clients::prepare_subscription(ctx) {
        ctx.log(format!("⚠ Подписка: {e:#}"));
    }
    let mut st = State::load(&ctx.data);
    st.lists_updated = now_secs();
    st.save(&ctx.data)?;
    Ok(())
}

fn forced_ctx(ctx: &Ctx) -> Ctx {
    let mut opts = ctx.opts.clone();
    opts.keep_zapret = false;
    opts.keep_tgws = false;
    opts.keep_client = false;
    Ctx {
        data: ctx.data.clone(),
        opts,
        tx: ctx.tx.clone(),
        admin: ctx.admin,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn fake_exe(tag: &[u8]) -> Vec<u8> {
        let mut v = b"MZ".to_vec();
        v.extend_from_slice(tag);
        v
    }

    fn write_zip(path: &Path, entries: &[(&str, Vec<u8>)]) {
        let f = fs::File::create(path).unwrap();
        let mut zw = zip::ZipWriter::new(f);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            zw.start_file(*name, opts).unwrap();
            zw.write_all(data).unwrap();
        }
        zw.finish().unwrap();
    }

    #[test]
    fn prepares_and_installs_a_single_exe() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("new.exe");
        fs::write(&src, fake_exe(b"new")).unwrap();
        let staging = dir.path().join("staging");
        let staged = prepare_from_exe(&src, &staging, None).unwrap();
        assert_eq!(sha256_file(&staged.exe).unwrap(), staged.sha256);
        assert_eq!(staged.entries, 1);

        let target = dir.path().join("app").join("TgWsProxy.exe");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"MZold").unwrap();
        let report = install_exe(&staged, &target, &dir.path().join("backup")).unwrap();

        assert_eq!(fs::read(&target).unwrap(), fake_exe(b"new"));
        assert_eq!(sha256_file(&target).unwrap(), report.sha256);
        let backup = report.backup.expect("backup");
        assert_eq!(fs::read(&backup).unwrap(), b"MZold");
        assert!(report.moved_old);
    }

    #[test]
    fn rejects_non_exe_and_bad_hash_before_touching_anything() {
        let dir = tempfile::tempdir().unwrap();
        let not_exe = dir.path().join("readme.exe");
        fs::write(&not_exe, b"plain text, not a program").unwrap();
        assert!(prepare_from_exe(&not_exe, &dir.path().join("staging"), None).is_err());

        let good = dir.path().join("good.exe");
        fs::write(&good, fake_exe(b"x")).unwrap();
        let wrong = "0".repeat(64);
        assert!(prepare_from_exe(&good, &dir.path().join("staging"), Some(&wrong)).is_err());

        // Nothing left behind by the failed attempts.
        let leftovers = fs::read_dir(dir.path().join("staging"))
            .map(|rd| rd.count())
            .unwrap_or(0);
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn tampered_staging_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("app.exe");
        fs::write(&src, fake_exe(b"new")).unwrap();
        let mut staged = prepare_from_exe(&src, &dir.path().join("staging"), None).unwrap();
        staged.sha256 = "0".repeat(64);
        let target = dir.path().join("app").join("app.exe");
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::write(&target, b"MZold").unwrap();

        assert!(install_exe(&staged, &target, &dir.path().join("backup")).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"MZold");
    }

    #[test]
    fn verifies_and_extracts_a_zip_with_the_expected_exe() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("component.zip");
        write_zip(
            &zip,
            &[
                ("bin/winws.exe", fake_exe(b"payload")),
                ("readme.txt", b"hello".to_vec()),
            ],
        );
        let staged =
            prepare_from_zip(&zip, &dir.path().join("staging"), "winws.exe", None).unwrap();
        assert!(staged.exe.ends_with("winws.exe"));
        assert_eq!(staged.entries, 2);
        assert!(fs::read(&staged.exe).unwrap().starts_with(b"MZ"));
    }

    #[test]
    fn rejects_broken_or_incompatible_archives() {
        let dir = tempfile::tempdir().unwrap();
        let staging = dir.path().join("staging");

        let junk = dir.path().join("junk.zip");
        fs::write(&junk, b"this is not a zip").unwrap();
        assert!(prepare_from_zip(&junk, &staging, "winws.exe", None).is_err());

        let no_exe = dir.path().join("no-exe.zip");
        write_zip(&no_exe, &[("readme.txt", b"hi".to_vec())]);
        let err = prepare_from_zip(&no_exe, &staging, "winws.exe", None).unwrap_err();
        assert!(format!("{err:#}").contains("winws.exe"));

        let good = dir.path().join("good.zip");
        write_zip(&good, &[("winws.exe", fake_exe(b"a"))]);
        let wrong = "1".repeat(64);
        assert!(prepare_from_zip(&good, &staging, "winws.exe", Some(&wrong)).is_err());
        // No half-extracted staging directories survive failures.
        let leftovers = fs::read_dir(&staging).map(|rd| rd.count()).unwrap_or(0);
        assert_eq!(leftovers, 0);
    }

    #[test]
    fn installs_a_directory_with_a_backup() {
        let dir = tempfile::tempdir().unwrap();
        let old = dir.path().join("program");
        fs::create_dir_all(old.join("bin")).unwrap();
        fs::write(old.join("old.txt"), b"old version").unwrap();
        fs::write(old.join("bin").join("winws.exe"), b"MZold").unwrap();

        let zip = dir.path().join("new.zip");
        write_zip(&zip, &[("bin/winws.exe", fake_exe(b"new"))]);
        let staged =
            prepare_from_zip(&zip, &dir.path().join("staging"), "winws.exe", None).unwrap();
        let backup_root = dir.path().join("backup");
        let report = install_dir(&staged, &old, "winws.exe", &backup_root).unwrap();

        assert_eq!(
            fs::read(old.join("bin").join("winws.exe")).unwrap(),
            fake_exe(b"new")
        );
        assert!(!old.join("old.txt").exists());
        let backup = report.backup.expect("backup");
        assert_eq!(fs::read(backup.join("old.txt")).unwrap(), b"old version");
        assert!(report.exe.ends_with("winws.exe"));
        // Staging was moved, not copied, when on the same volume.
        assert!(!staged.root.exists() || staged.root == old);
    }

    #[test]
    fn incompatible_directory_update_preserves_the_old_copy() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("program");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("keep.txt"), b"working").unwrap();

        let shadow = dir.path().join("staged");
        fs::create_dir_all(&shadow).unwrap();
        fs::write(shadow.join("other.exe"), fake_exe(b"other")).unwrap();
        let staged = Staging {
            root: shadow,
            exe: dir.path().join("other.exe"),
            sha256: "0".repeat(64),
            entries: 1,
        };
        assert!(install_dir(&staged, &target, "winws.exe", &dir.path().join("backup")).is_err());
        assert_eq!(fs::read(target.join("keep.txt")).unwrap(), b"working");
    }

    #[test]
    fn cleanup_staging_removes_everything_but_the_kept_dir() {
        let dir = tempfile::tempdir().unwrap();
        let keep = dir.path().join("keep");
        let old = dir.path().join("old");
        fs::create_dir_all(&keep).unwrap();
        fs::create_dir_all(&old).unwrap();
        fs::write(old.join("x"), b"x").unwrap();
        cleanup_staging(dir.path(), &keep);
        assert!(keep.exists());
        assert!(!old.exists());
    }
}

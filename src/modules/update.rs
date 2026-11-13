use anyhow::Result;
use std::path::Path;
use std::process::Command;

use crate::modules::{clients, detect, Ctx};
use crate::state::{now_secs, State};
use crate::util;

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
                        ctx.log(format!("• zapret: {} — актуально ({loc} · {src})", short(v)));
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
            ctx.log("Обновляю свою копию zapret...");
            std::fs::remove_dir_all(&dir).ok();
            match crate::modules::zapret::run(&forced_ctx(ctx)) {
                Ok(_) => {
                    if let Some(t) = &tag {
                        st.set_tool("zapret", t);
                    }
                    ctx.log("✓ zapret обновлён.");
                }
                Err(e) => ctx.log(format!("⚠ zapret: {e:#}")),
            }
        }
    }

    if ctx.opts.components.tgws {
        let dir = ctx.dir("tgws");
        if dir.exists() && !handled.contains(&"tgws") {
            ctx.progress(40, "TgWsProxy".to_string());
            let tag = util::github_latest_tag(&client, "Flowseal/tg-ws-proxy").ok();
            ctx.log("Обновляю свою копию TgWsProxy...");
            std::fs::remove_dir_all(&dir).ok();
            match crate::modules::tgws::run(&forced_ctx(ctx)) {
                Ok(_) => {
                    if let Some(t) = &tag {
                        st.set_tool("tgws", t);
                    }
                    ctx.log("✓ TgWsProxy обновлён.");
                }
                Err(e) => ctx.log(format!("⚠ TgWsProxy: {e:#}")),
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
            ctx.log(format!("Обновляю {name}..."));
            std::fs::remove_dir_all(&base).ok();
            match clients::run(&forced_ctx(ctx)) {
                Ok(_) => {
                    if let Some(t) = &tag {
                        st.set_tool(key, t);
                    }
                    ctx.log(format!("✓ {name} обновлён."));
                }
                Err(e) => ctx.log(format!("⚠ {name}: {e:#}")),
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
        app.version.as_deref().map(short).unwrap_or_else(|| "?".into()),
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
    // The installer cannot replace files of a running app.
    let _ = util::hidden_str("taskkill", &["/IM", "Happ.exe", "/F"]);
    let arg = format!("/D={}", dir.display());
    let status = Command::new(&setup).arg("/S").arg(&arg).spawn().and_then(|mut c| c.wait());
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
        app.version.as_deref().map(short).unwrap_or_else(|| "?".into()),
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
    if app.running {
        let _ = util::hidden_str("taskkill", &["/IM", "TgWsProxy.exe", "/F"]);
    }
    let backup = path.with_file_name(format!(
        "{}.bak-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("TgWsProxy.exe"),
        now_secs()
    ));
    let _ = std::fs::copy(path, &backup);
    match std::fs::copy(&new_exe, path) {
        Ok(_) => {
            st.set_tool("tgws", &latest);
            ctx.log(format!(
                "✓ TgWsProxy обновлён (бэкап: {})",
                backup.display()
            ));
            if app.running {
                let _ = Command::new(path).spawn();
            }
            true
        }
        Err(e) => {
            ctx.log(format!("⚠ Не удалось заменить TgWsProxy: {e}"));
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
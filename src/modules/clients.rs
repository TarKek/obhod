use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::modules::update::{cleanup_staging, install_dir, prepare_from_zip};
use crate::modules::{detect, servesub, Ctx};
use crate::util;

pub fn app_base_dir(ctx: &Ctx, app: &str) -> PathBuf {
    let target_dir = if ctx.opts.client_dir.as_os_str().is_empty() {
        detect::dir_local_appdata().join("Programs")
    } else {
        ctx.opts.client_dir.clone()
    };
    match app {
        "hiddify" => target_dir.join("hiddify"),
        "v2rayn" => target_dir.join("v2rayn"),
        "happ" => detect::dir_local_appdata().join("Programs").join("Happ"),
        _ => target_dir,
    }
}

pub fn run(ctx: &Ctx) -> Result<()> {
    let app = ctx.opts.client.as_str();
    if app == "none" || app.is_empty() {
        ctx.log("Приложение для серверов не выбрано — пропускаю.");
        return Ok(());
    }

    let target_dir = if ctx.opts.client_dir.as_os_str().is_empty() {
        detect::dir_local_appdata().join("Programs")
    } else {
        ctx.opts.client_dir.clone()
    };
    std::fs::create_dir_all(&target_dir)?;

    let existing = match app {
        "hiddify" => detect::find_exe_in(&target_dir.join("hiddify"), "Hiddify.exe", 3),
        "v2rayn" => detect::find_exe_in(&target_dir.join("v2rayn"), "v2rayN.exe", 3),
        "happ" => detect::find_exe_in(
            &detect::dir_local_appdata().join("Programs").join("Happ"),
            "Happ.exe",
            3,
        ),
        _ => None,
    };

    let exe = match existing {
        Some(p) if ctx.opts.keep_client => {
            ctx.log(format!("{} уже установлен — не трогаю.", label(app)));
            p
        }
        _ => install(ctx, app, &target_dir)?,
    };

    prepare_subscription(ctx)?;

    match std::process::Command::new(&exe).spawn() {
        Ok(_) => ctx.log(format!("✓ {} запущен.", label(app))),
        Err(e) => ctx.log(format!("⚠ не удалось запустить {}: {e}", exe.display())),
    }
    Ok(())
}

fn label(app: &str) -> &'static str {
    match app {
        "hiddify" => "Hiddify",
        "v2rayn" => "v2rayN",
        "happ" => "Happ",
        _ => "приложение",
    }
}

/// Updates a portable copy in place: download → verify archive → swap the
/// directory with a backup and rollback. The old copy stays untouched until
/// the new one is fully verified.
pub fn update_copy(ctx: &Ctx) -> Result<PathBuf> {
    let app = ctx.opts.client.as_str();
    if app == "none" || app.is_empty() {
        anyhow::bail!("VPN-клиент не выбран");
    }
    let parent = if ctx.opts.client_dir.as_os_str().is_empty() {
        detect::dir_local_appdata().join("Programs")
    } else {
        ctx.opts.client_dir.clone()
    };
    std::fs::create_dir_all(&parent)?;
    let exe = install(ctx, app, &parent)?;
    if exe.exists() {
        match std::process::Command::new(&exe).spawn() {
            Ok(_) => ctx.log(format!("✓ {} запущен.", label(app))),
            Err(e) => ctx.log(format!("⚠ не удалось запустить {}: {e}", exe.display())),
        }
    }
    Ok(exe)
}

fn portable_spec(app: &str) -> Option<(&'static str, &'static str, &'static str, &'static str)> {
    match app {
        "hiddify" => Some(("hiddify/hiddify-app", "portable", "Hiddify.exe", "hiddify")),
        "v2rayn" => Some(("2dust/v2rayN", "windows-64", "v2rayN.exe", "v2rayn")),
        _ => None,
    }
}

fn install_portable(ctx: &Ctx, app: &str, target_dir: &Path) -> Result<PathBuf> {
    let (repo, needle, exe_name, folder) =
        portable_spec(app).ok_or_else(|| anyhow::anyhow!("неизвестное приложение: {app}"))?;
    ctx.log(format!("Скачиваю {} (портативная версия)...", label(app)));
    let client = util::http_client()?;
    let dl = ctx.dir("downloads");
    std::fs::create_dir_all(&dl)?;
    let zip = util::github_asset_filtered(&client, repo, ".zip", needle, &dl)?;
    ctx.log("Проверяю архив и распаковываю в staging...");
    let staged = prepare_from_zip(&zip, &ctx.dir("staging"), exe_name, None)?;
    let target = target_dir.join(folder);
    let report = install_dir(&staged, &target, exe_name, &ctx.dir("backup"))?;
    cleanup_staging(&ctx.dir("staging"), &report.target);
    ctx.log(format!(
        "✓ {} распакован: {} (резервная копия: {})",
        label(app),
        target.display(),
        report
            .backup
            .as_ref()
            .map(|b| b.display().to_string())
            .unwrap_or_else(|| "нет".into())
    ));
    Ok(report.exe)
}

fn install(ctx: &Ctx, app: &str, target_dir: &Path) -> Result<PathBuf> {
    match app {
        "hiddify" | "v2rayn" => install_portable(ctx, app, target_dir),
        "happ" => install_happ(ctx),
        _ => anyhow::bail!("неизвестное приложение: {app}"),
    }
}

fn install_happ(ctx: &Ctx) -> Result<PathBuf> {
    let client = util::http_client()?;
    let dl = ctx.dir("downloads");
    std::fs::create_dir_all(&dl)?;
    ctx.log("Скачиваю установщик Happ...");
    let setup =
        util::github_asset_filtered(&client, "Happ-proxy/happ-desktop", ".exe", "x64", &dl)?;
    ctx.log("Устанавливаю Happ тихо (без мастера)...");
    let out = std::process::Command::new(&setup)
        .arg("/S")
        .spawn()
        .and_then(|mut c| c.wait())
        .map_err(|e| anyhow::anyhow!("запуск установщика Happ: {e}"))?;
    if !out.success() {
        ctx.log("⚠ установщик Happ завершился с ошибкой, пробую найти программу.");
    }
    std::thread::sleep(std::time::Duration::from_secs(3));
    let dir = detect::dir_local_appdata().join("Programs").join("Happ");
    find_exe(&dir, "Happ.exe")
        .ok_or_else(|| anyhow::anyhow!("Happ установился, но Happ.exe не найден"))
}

fn find_exe(dir: &Path, exe: &str) -> Option<PathBuf> {
    detect::find_exe_in(dir, exe, 4)
}

pub fn prepare_subscription(ctx: &Ctx) -> Result<()> {
    let app = ctx.opts.client.as_str();
    let alive = ctx.data.join("subs_alive_plain.txt");

    // Only real VPN configs go into the subscription. MTProto (tg://) links are
    // a different protocol and make Happ/Hiddify/v2rayN show an empty profile.
    let mut body = String::new();
    if let Ok(text) = std::fs::read_to_string(&alive) {
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            body.push_str(l);
            body.push('\n');
        }
    }

    let sub_path = ctx.data.join("subscription.txt");
    std::fs::write(&sub_path, &body)?;

    if body.trim().is_empty() {
        ctx.log("⚠ Пока нет конфигов для приложения — сначала включите «Бесплатные серверы».");
        ctx.log("  Telegram-прокси в VPN-клиенты не подставляются: это другой протокол.");
        return Ok(());
    }

    // Ready-to-import copies: a plain list and a base64 one.
    let import_dir = ctx.data.join("import");
    std::fs::create_dir_all(&import_dir)?;
    let slug = crate::brand::slug();
    let plain_file = import_dir.join(format!(
        "{slug}_{}.txt",
        if app.is_empty() { "configs" } else { app }
    ));
    std::fs::write(&plain_file, &body)?;
    let b64_file = import_dir.join(format!("{slug}_base64.txt"));
    std::fs::write(&b64_file, util::base64(&body))?;

    if let Some(url) = servesub::start(sub_path.clone(), crate::brand::name()) {
        util::set_clipboard(&url);
        ctx.log("✓ Ссылка на подписку скопирована в буфер обмена.");
        ctx.log(format!("  {}", import_hint(app)));
        if let (_, Some(plain)) = servesub::urls() {
            ctx.log(format!("  Обычный текст без base64: {plain}"));
        }
        ctx.log(format!(
            "  Ссылка работает, пока открыто это окно {}.",
            crate::brand::name()
        ));
    }
    write_instructions(&import_dir)?;

    ctx.log(format!("  Файл конфигов: {}", plain_file.display()));
    ctx.log(format!("  То же в base64: {}", b64_file.display()));
    ctx.log("  Если ссылка не подошла — импортируйте файл вручную.");
    Ok(())
}

/// Short per-client steps shown in the log and in `data\import\README.txt`.
fn import_hint(app: &str) -> &'static str {
    match app {
        "hiddify" => "Hiddify: «Профили» → «+» → «Импорт из буфера обмена».",
        "v2rayn" => "v2rayN: «Подписки» → «Добавить подписку» → вставить ссылку → OK.",
        "happ" => "Happ: «Профили» → «+» → «Импорт по ссылке» → вставить ссылку.",
        _ => "В VPN-приложении: «Добавить подписку» → вставить (Ctrl+V) → «Добавить».",
    }
}

fn write_instructions(dir: &std::path::Path) -> Result<()> {
    let name = crate::brand::name();
    let slug = crate::brand::slug();
    let sample = crate::brand::sample("ru");
    let text = format!(
        "\
{name} — как добавить серверы в VPN-приложение

1. Ссылка на подписку уже скопирована в буфер обмена.
2. Откройте Happ / Hiddify / v2rayN и нажмите «Добавить подписку».
3. Вставьте ссылку (Ctrl+V) и подтвердите.
4. Серверы появятся списком: «{sample}» — по 2 самых быстрых
   на каждую страну.

Если ссылка не работает ({name} уже закрыт), импортируйте файл из этой папки:
  {slug}_<клиент>.txt      — обычный список
  {slug}_base64.txt        — тот же список в base64

Ссылка http://127.0.0.1:... живёт только пока запущен {name}.
"
    );
    std::fs::write(dir.join("README.txt"), text)?;
    Ok(())
}

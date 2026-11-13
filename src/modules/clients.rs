use anyhow::Result;
use std::path::{Path, PathBuf};

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

fn install(ctx: &Ctx, app: &str, target_dir: &Path) -> Result<PathBuf> {
    let client = util::http_client()?;
    let dl = ctx.dir("downloads");
    std::fs::create_dir_all(&dl)?;

    match app {
        "hiddify" => {
            ctx.log("Скачиваю Hiddify (портативная версия)...");
            let zip = util::github_asset_filtered(
                &client,
                "hiddify/hiddify-app",
                ".zip",
                "portable",
                &dl,
            )?;
            let dir = target_dir.join("hiddify");
            util::unzip(&zip, &dir)?;
            let exe = find_exe(&dir, "Hiddify.exe")
                .ok_or_else(|| anyhow::anyhow!("в архиве Hiddify нет Hiddify.exe"))?;
            ctx.log(format!("✓ Hiddify распакован: {}", dir.display()));
            Ok(exe)
        }
        "v2rayn" => {
            ctx.log("Скачиваю v2rayN (портативная версия)...");
            let zip = util::github_asset_filtered(
                &client,
                "2dust/v2rayN",
                ".zip",
                "windows-64.zip",
                &dl,
            )?;
            let dir = target_dir.join("v2rayn");
            util::unzip(&zip, &dir)?;
            let exe = find_exe(&dir, "v2rayN.exe")
                .ok_or_else(|| anyhow::anyhow!("в архиве v2rayN нет v2rayN.exe"))?;
            ctx.log(format!("✓ v2rayN распакован: {}", dir.display()));
            Ok(exe)
        }
        "happ" => {
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
        _ => anyhow::bail!("неизвестное приложение: {app}"),
    }
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

use std::sync::mpsc::{channel, Receiver};

use crate::modules::{self, Ctx, RunOptions};

pub enum Msg {
    Log(String),
    Progress(u8, String),
    Done(bool),
}

pub fn spawn_demo() -> Receiver<Msg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let steps = [
            ("zapret", "Скачиваю обход (демо, без загрузки)..."),
            ("DNS / DoH", "Проверяю интернет и DNS (демо)..."),
            ("MTProto", "Подбираю прокси для Telegram (демо)..."),
            ("TgWsProxy", "Готовлю запасной способ (демо)..."),
            ("подписки", "Ищу бесплатные серверы (демо)..."),
            ("приложение", "Готовлю приложение и подписку (демо)..."),
            ("готово", "Демо завершено — ничего не изменено."),
        ];
        for (i, (label, line)) in steps.iter().enumerate() {
            let _ = tx.send(Msg::Log(format!("• {line}")));
            let _ = tx.send(Msg::Progress(
                ((i * 100) / steps.len()) as u8,
                (*label).to_string(),
            ));
            std::thread::sleep(std::time::Duration::from_millis(900));
        }
        let _ = tx.send(Msg::Progress(100, "готово".into()));
        let _ = tx.send(Msg::Log("✓ Это был демо-режим. Реальная система не изменена.".into()));
        let _ = tx.send(Msg::Done(true));
    });
    rx
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UpdateMode {
    Proxy,
    Subs,
    Tools,
}

impl UpdateMode {
    pub fn label(self) -> &'static str {
        match self {
            UpdateMode::Proxy => "прокси Telegram",
            UpdateMode::Subs => "подписка в VPN-клиенте",
            UpdateMode::Tools => "программы",
        }
    }

    pub fn label_lang(self, lang: &str) -> &'static str {
        if lang == "en" {
            match self {
                UpdateMode::Proxy => "Telegram proxy",
                UpdateMode::Subs => "VPN client subscription",
                UpdateMode::Tools => "programs",
            }
        } else {
            self.label()
        }
    }
}

pub fn spawn_update(opts: RunOptions, mode: UpdateMode) -> Receiver<Msg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let admin = crate::util::is_admin();
        let data = opts.data_dir.clone();
        let ctx = Ctx {
            data,
            opts,
            tx: tx.clone(),
            admin,
        };
        let mut ok = true;
        let result = (|| -> anyhow::Result<()> {
            ctx.progress(5, mode.label().to_string());
            match mode {
                UpdateMode::Proxy => crate::modules::update::update_telegram_proxies(&ctx)?,
                UpdateMode::Subs => crate::modules::update::update_vpn_subscription(&ctx)?,
                UpdateMode::Tools => {
                    ctx.log("── проверка версий ──");
                    crate::modules::update::check(&ctx)?;
                    ctx.progress(35, "программы".to_string());
                    ctx.log("── обновление программ ──");
                    crate::modules::update::update_tools(&ctx)?;
                }
            }
            ctx.progress(100, "готово".to_string());
            Ok(())
        })();
        if let Err(e) = result {
            ok = false;
            ctx.log(format!("Ошибка: {e:#}"));
        }
        let _ = tx.send(Msg::Done(ok));
    });
    rx
}

pub fn spawn_update_demo(mode: UpdateMode) -> Receiver<Msg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let lines = match mode {
            UpdateMode::Proxy => vec![
                "• проверяю прокси Telegram (демо)",
                "• выбираю самый быстрый (демо)",
                "• открываю его в Telegram (демо)",
            ],
            UpdateMode::Subs => vec![
                "• проверяю бесплатные серверы (демо)",
                "• выбираю живые узлы (демо)",
                "• обновляю подписку клиента (демо)",
            ],
            UpdateMode::Tools => vec![
                "• проверяю версии программ (демо)",
                "• обновляю программы (демо)",
            ],
        };
        for (i, line) in lines.iter().enumerate() {
            let _ = tx.send(Msg::Log(line.to_string()));
            let _ = tx.send(Msg::Progress(
                (((i + 1) * 100) / lines.len()) as u8,
                mode.label().to_string(),
            ));
            std::thread::sleep(std::time::Duration::from_millis(700));
        }
        let _ = tx.send(Msg::Log(
            "✓ Демо обновления завершено. Реальная система не изменена.".into(),
        ));
        let _ = tx.send(Msg::Done(true));
    });
    rx
}

pub fn spawn_off(opts: RunOptions) -> Receiver<Msg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let admin = crate::util::is_admin();
        let data = opts.data_dir.clone();
        let ctx = Ctx {
            data,
            opts,
            tx: tx.clone(),
            admin,
        };
        let res = crate::modules::off::run(&ctx);
        let ok = res.is_ok();
        if let Err(e) = res {
            ctx.log(format!("Ошибка: {e:#}"));
        }
        let _ = tx.send(Msg::Done(ok));
    });
    rx
}

pub fn spawn_off_demo() -> Receiver<Msg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let steps = [
            ("служба обхода", "• останавливаю службу обхода (демо)"),
            ("hosts", "• убираю блок рекламы из hosts (демо)"),
            ("DNS", "• возвращаю DNS на автоматический (демо)"),
            ("автозагрузка", "• выключаю автозапуск (демо)"),
        ];
        for (i, (label, line)) in steps.iter().enumerate() {
            let _ = tx.send(Msg::Log((*line).to_string()));
            let _ = tx.send(Msg::Progress(
                (((i + 1) * 100) / steps.len()) as u8,
                (*label).to_string(),
            ));
            std::thread::sleep(std::time::Duration::from_millis(600));
        }
        let _ = tx.send(Msg::Log(
            "✓ Демо: «выключено». Настоящая система не изменена.".into(),
        ));
        let _ = tx.send(Msg::Done(true));
    });
    rx
}

pub fn spawn(opts: RunOptions) -> Receiver<Msg> {
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        let admin = crate::util::is_admin();
        let data = opts.data_dir.clone();
        let telemetry = opts.telemetry;
        let ctx = Ctx {
            data,
            opts,
            tx: tx.clone(),
            admin,
        };
        let res = modules::run_all(&ctx);

        // Autostart belongs to the bypass components (zapret service / TgWsProxy),
        // not to this setup wizard. Opening the TUI at every login would be annoying.
        if !telemetry {
            ctx.log("Телеметрия: выключена.");
        }

        let ok = res.is_ok();
        if let Err(e) = res {
            ctx.log(format!("Ошибка: {e:#}"));
        }
        let _ = tx.send(Msg::Done(ok));
    });
    rx
}

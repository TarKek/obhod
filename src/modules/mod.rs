use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::util;

pub mod check;
pub mod clients;
pub mod detect;
pub mod dns;
pub mod hosts;
pub mod off;
pub mod report;
pub mod servesub;
pub mod subs;
pub mod telegram;
pub mod tgws;
pub mod update;
pub mod zapret;

#[derive(Clone, Debug)]
pub struct RunOptions {
    pub components: crate::config::Components,
    pub data_dir: PathBuf,
    pub autostart: bool,
    pub service_mode: bool,
    pub hosts_block_ads: bool,
    pub autoupdate_days: u32,
    pub reminders: bool,
    pub telemetry: bool,
    pub repo: String,
    pub keep_zapret: bool,
    pub keep_tgws: bool,
    pub keep_client: bool,
    pub client: String,
    pub client_dir: PathBuf,
}

pub struct Ctx {
    pub data: PathBuf,
    pub opts: RunOptions,
    pub tx: std::sync::mpsc::Sender<crate::worker::Msg>,
    pub admin: bool,
}

impl Ctx {
    pub fn log(&self, s: impl Into<String>) {
        let _ = self.tx.send(crate::worker::Msg::Log(s.into()));
    }
    pub fn progress(&self, p: u8, s: impl Into<String>) {
        let _ = self.tx.send(crate::worker::Msg::Progress(p, s.into()));
    }
    pub fn dir(&self, name: &str) -> PathBuf {
        self.data.join(name)
    }
}

pub fn run_all(ctx: &Ctx) -> bool {
    let c = ctx.opts.components.clone();
    let mut steps: Vec<(&str, fn(&Ctx) -> Result<()>)> = Vec::new();
    if c.zapret {
        steps.push(("zapret", crate::modules::zapret::run));
    }
    if c.dns {
        steps.push(("DNS / DoH", crate::modules::dns::run));
    }
    if c.mtproto {
        steps.push(("MTProto", crate::modules::telegram::run));
    }
    if c.tgws {
        steps.push(("TgWsProxy", crate::modules::tgws::run));
    }
    if c.subs {
        steps.push(("подписки", crate::modules::subs::run));
    }
    if ctx.opts.client != "none" && !ctx.opts.client.is_empty() {
        steps.push(("приложение", crate::modules::clients::run));
    }
    if c.hosts {
        steps.push(("hosts", crate::modules::hosts::run));
    }
    steps.push(("отчёт", crate::modules::report::run));

    let n = steps.len().max(1);
    let mut failed = 0usize;
    for (i, (name, f)) in steps.iter().enumerate() {
        ctx.progress(((i * 100) / n) as u8, *name);
        ctx.log(format!("── {name} ──"));
        if let Err(e) = f(ctx) {
            failed += 1;
            ctx.log(format!("⚠ {name}: {e:#}"));
        }
    }
    ctx.progress(100, "готово");
    failed == 0
}

pub fn prepare(cfg: &Config) -> Result<RunOptions> {
    let data = cfg.data_dir();
    fs::create_dir_all(&data)?;
    Ok(RunOptions {
        components: cfg.components.clone(),
        data_dir: data,
        autostart: cfg.autostart,
        service_mode: cfg.service_mode,
        hosts_block_ads: cfg.hosts_block_ads,
        autoupdate_days: cfg.autoupdate_days,
        reminders: cfg.reminders,
        telemetry: cfg.telemetry,
        repo: cfg.repo.clone(),
        keep_zapret: false,
        keep_tgws: false,
        keep_client: true,
        client: cfg.client.clone(),
        client_dir: PathBuf::from(&cfg.client_dir),
    })
}

pub fn install_autostart(exe_name: &str) -> Result<()> {
    let exe = std::env::current_exe()?;
    let val = format!("\"{}\" --minimized", exe.display());
    util::reg_set_string(
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        exe_name,
        &val,
    )
    .context("не удалось прописать автозагрузку")
}

pub fn remove_autostart(exe_name: &str) -> Result<()> {
    util::reg_delete_value(
        "HKCU",
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        exe_name,
    )
}

pub fn read_text_if_exists(p: &Path) -> Option<String> {
    fs::read_to_string(p).ok()
}

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

use crate::util;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Components {
    pub zapret: bool,
    pub mtproto: bool,
    pub tgws: bool,
    pub hosts: bool,
    pub subs: bool,
    pub dns: bool,
}

impl Default for Components {
    fn default() -> Self {
        Self {
            zapret: true,
            mtproto: true,
            tgws: false,
            hosts: false,
            subs: false,
            dns: true,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Config {
    pub lang: String,
    pub first_run: bool,
    pub data_dir: String,
    pub autostart: bool,
    pub service_mode: bool,
    pub autoupdate_days: u32,
    pub reminders: bool,
    pub telemetry: bool,
    pub components: Components,
    pub hosts_block_ads: bool,
    pub last_update_check: u64,
    pub repo: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub client_dir: String,
    #[serde(default)]
    pub last_found: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            lang: "ru".into(),
            first_run: true,
            data_dir: String::new(),
            autostart: true,
            service_mode: false,
            autoupdate_days: 0,
            reminders: true,
            telemetry: false,
            components: Components::default(),
            hosts_block_ads: false,
            last_update_check: 0,
            repo: String::new(),
            client: "hiddify".into(),
            client_dir: String::new(),
            last_found: Vec::new(),
        }
    }
}

impl Config {
    pub fn path() -> PathBuf {
        util::exe_dir().join("obhod.json")
    }

    pub fn load() -> Self {
        let p = Self::path();
        fs::read_to_string(&p)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let s = serde_json::to_string_pretty(self)?;
        fs::write(Self::path(), s)?;
        Ok(())
    }

    pub fn data_dir(&self) -> PathBuf {
        if self.data_dir.is_empty() {
            util::exe_dir().join("data")
        } else {
            PathBuf::from(&self.data_dir)
        }
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(self.data_dir())?;
        fs::create_dir_all(self.data_dir().join("downloads"))?;
        Ok(())
    }

    pub fn backup_path(name: &str) -> PathBuf {
        util::exe_dir().join("backup").join(name)
    }

    pub fn chk(&self, p: &Path) -> bool {
        p.exists()
    }
}

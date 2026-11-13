//! `obhod.json`: settings next to the exe.
//!
//! Rules:
//! * the file carries a `version`; an unversioned (old) file is migrated in
//!   memory, then written back once — with a `.bak` copy of the original;
//! * every field is `serde(default)`, so a partial or older file loads with
//!   defaults instead of being thrown away;
//! * corrupt JSON is **never** silently replaced: the broken file is copied to
//!   `obhod.json.corrupt-<stamp>`, a clear message is recorded (see
//!   [`Config::take_load_error`]) and defaults are used;
//! * saving is atomic (temp file + rename) and keeps one `.bak` of the previous
//!   version.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::sys::fsx;
use crate::util;

/// Bumped whenever the on-disk format changes in a way that needs code.
pub const CONFIG_VERSION: u32 = 1;

static LAST_LOAD_ERROR: Mutex<Option<String>> = Mutex::new(None);

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
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
#[serde(default)]
pub struct Config {
    /// 0 (or absent) means "written by an older build": see [`migrate`].
    #[serde(default)]
    pub version: u32,
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
    pub client: String,
    pub client_dir: String,
    pub last_found: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
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

    /// Loads the config next to the exe. Never fails: see [`Self::take_load_error`].
    pub fn load() -> Self {
        Self::load_from(&Self::path())
    }

    /// Loads from `path`. A broken file is preserved and defaults are returned.
    pub fn load_from(path: &Path) -> Self {
        match Self::load_checked(path) {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("{e:#}");
                crate::logger::info(format!("config: {msg}"));
                set_last_error(msg);
                Self::default()
            }
        }
    }

    /// Same as [`Self::load_from`], but reports why the file was unusable.
    pub fn load_checked(path: &Path) -> Result<Self> {
        let mut cfg = match fs::read(path) {
            Ok(bytes) => {
                let text = String::from_utf8_lossy(&bytes);
                let text = text.trim_start_matches('\u{feff}');
                match serde_json::from_str::<Config>(text) {
                    Ok(c) => c,
                    Err(e) => {
                        let saved = preserve_broken(path, &bytes);
                        anyhow::bail!(
                            "файл настроек {} повреждён: {e}. {}Настройки по умолчанию — прежний файл не потерян.",
                            path.display(),
                            match saved {
                                Some(p) => format!("Копия: {}. ", p.display()),
                                None => String::new(),
                            }
                        );
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => anyhow::bail!("не удалось прочитать {}: {e}", path.display()),
        };

        if cfg.version < CONFIG_VERSION {
            let from = cfg.version;
            migrate(&mut cfg, from);
            // Persist the migrated form once; a failure is not fatal (the
            // in-memory config is already usable).
            if let Err(e) = cfg.save_to(path) {
                crate::logger::info(format!(
                    "config: не удалось сохранить миграцию {}->{}: {e:#}",
                    from, CONFIG_VERSION
                ));
            }
        }
        Ok(cfg)
    }

    /// Atomic save next to the exe.
    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::path())
    }

    /// Atomic save to `path`, keeping the previous version as `<name>.bak`.
    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("не удалось создать {}", parent.display()))?;
            }
        }
        // Rolling backup of the previous file (best effort, never fatal).
        if let Ok(prev) = fs::read(path) {
            let _ = fsx::write_atomic(&backup_path(path), &prev);
        }
        let mut data = serde_json::to_vec_pretty(self)?;
        data.push(b'\n');
        fsx::write_atomic(path, &data)
            .with_context(|| format!("не удалось записать {}", path.display()))
    }

    /// The last load error, if the file had to be ignored.
    #[allow(dead_code)] // shown by the settings screen
    pub fn take_load_error() -> Option<String> {
        LAST_LOAD_ERROR.lock().ok().and_then(|mut g| g.take())
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

    #[allow(dead_code)] // часть публичного API настроек
    pub fn backup_path(name: &str) -> PathBuf {
        util::exe_dir().join("backup").join(name)
    }

    #[allow(dead_code)]
    pub fn chk(&self, p: &Path) -> bool {
        p.exists()
    }
}

fn set_last_error(msg: String) {
    if let Ok(mut g) = LAST_LOAD_ERROR.lock() {
        *g = Some(msg);
    }
}

/// `<config>.bak` next to the config file.
pub fn backup_path(path: &Path) -> PathBuf {
    match path.file_name() {
        Some(name) => path.with_file_name(format!("{}.bak", name.to_string_lossy())),
        None => path.with_extension("bak"),
    }
}

/// Keeps a copy of the unparsable file next to it. Returns the copy's path.
fn preserve_broken(path: &Path, bytes: &[u8]) -> Option<PathBuf> {
    let name = path.file_name()?.to_string_lossy().to_string();
    let dst = path.with_file_name(format!("{name}.corrupt-{}", crate::logger::stamp()));
    match fsx::write_atomic(&dst, bytes) {
        Ok(()) => Some(dst),
        Err(e) => {
            crate::logger::info(format!(
                "config: не удалось сохранить копию повреждённого {}: {e}",
                path.display()
            ));
            None
        }
    }
}

/// Bring an older config up to date. Additive: nothing the user set is dropped.
fn migrate(cfg: &mut Config, from: u32) {
    if from < 1 {
        if cfg.lang.trim().is_empty() {
            cfg.lang = "ru".into();
        }
        if cfg.client.trim().is_empty() {
            cfg.client = "hiddify".into();
        }
        // Older builds accepted any number; keep it sane.
        if cfg.autoupdate_days > 365 {
            cfg.autoupdate_days = 0;
        }
        // `telemetry` was opt-in before 1.0 and stays opt-in.
    }
    cfg.version = CONFIG_VERSION;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// `LAST_LOAD_ERROR` is process-global; tests that touch it must not race.
    static LOCK: Mutex<()> = Mutex::new(());

    fn guard() -> std::sync::MutexGuard<'static, ()> {
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn write(path: &Path, s: &str) {
        fs::write(path, s).unwrap();
    }

    #[test]
    fn unversioned_file_is_migrated_and_persisted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obhod.json");
        write(
            &path,
            r#"{"lang":"en","first_run":false,"data_dir":"D:\\obhod-data","telemetry":true}"#,
        );
        let cfg = Config::load_checked(&path).unwrap();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert_eq!(cfg.lang, "en");
        assert!(!cfg.first_run);
        assert_eq!(cfg.data_dir, r"D:\obhod-data");
        assert!(cfg.telemetry);
        // Defaults filled in for the fields the old file did not have.
        assert_eq!(cfg.client, "hiddify");
        assert!(cfg.components.zapret);
        // Written back: the file on disk now carries the version.
        let text = fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("\"version\""),
            "migrated file not saved: {text}"
        );
        // And a backup of the pre-migration file exists.
        assert!(backup_path(&path).exists());
    }

    #[test]
    fn empty_version_and_missing_fields_are_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obhod.json");
        write(&path, "{}");
        let cfg = Config::load_checked(&path).unwrap();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert_eq!(cfg.lang, "ru");
        assert!(cfg.components.dns);
    }

    #[test]
    fn blank_client_is_repaired_during_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obhod.json");
        write(&path, r#"{"client":""}"#);
        let cfg = Config::load_checked(&path).unwrap();
        assert_eq!(cfg.client, "hiddify");
    }

    #[test]
    fn corrupt_file_is_preserved_and_reported() {
        let _g = guard();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obhod.json");
        write(&path, "{ this is not json");
        let cfg = Config::load_from(&path);
        // Defaults, not garbage.
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert_eq!(cfg.lang, "ru");
        // The broken file itself is untouched...
        assert_eq!(fs::read_to_string(&path).unwrap(), "{ this is not json");
        // ...and copied aside.
        let copies: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains(".corrupt-"))
            .collect();
        assert_eq!(copies.len(), 1, "{copies:?}");
        let err = Config::take_load_error().expect("error must be recorded");
        assert!(err.contains("повреждён"), "{err}");
        assert!(Config::take_load_error().is_none(), "error is taken once");
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obhod.json");
        write(
            &path,
            r#"{"version":1,"lang":"ru","future_field":{"a":1},"another":true}"#,
        );
        let cfg = Config::load_checked(&path).unwrap();
        assert_eq!(cfg.lang, "ru");
    }

    #[test]
    fn save_is_atomic_and_keeps_the_previous_version() {
        let _g = guard();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obhod.json");
        let mut cfg = Config {
            lang: "ru".into(),
            ..Config::default()
        };
        cfg.save_to(&path).unwrap();
        cfg.lang = "en".into();
        cfg.save_to(&path).unwrap();

        let now = fs::read_to_string(&path).unwrap();
        let prev = fs::read_to_string(backup_path(&path)).unwrap();
        assert!(now.contains("\"en\""));
        assert!(
            prev.contains("\"ru\""),
            "backup must hold the previous file"
        );

        // No temporary files left behind.
        let leftovers: Vec<String> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("obhod-tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");

        // The file we just wrote loads again without an error.
        Config::take_load_error();
        let back = Config::load_checked(&path).unwrap();
        assert_eq!(back.lang, "en");
        assert_eq!(back.version, CONFIG_VERSION);
        assert!(Config::take_load_error().is_none());
    }

    #[test]
    fn bom_and_crlf_do_not_break_loading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("obhod.json");
        let mut bytes = vec![0xEF, 0xBB, 0xBF];
        bytes.extend_from_slice(b"{\"version\":1,\"lang\":\"en\"}\r\n");
        fs::write(&path, bytes).unwrap();
        let cfg = Config::load_checked(&path).unwrap();
        assert_eq!(cfg.lang, "en");
    }

    #[test]
    fn data_dir_falls_back_next_to_the_exe() {
        let mut cfg = Config {
            data_dir: String::new(),
            ..Config::default()
        };
        assert_eq!(cfg.data_dir(), util::exe_dir().join("data"));
        cfg.data_dir = r"D:\x".into();
        assert_eq!(cfg.data_dir(), PathBuf::from(r"D:\x"));
    }
}

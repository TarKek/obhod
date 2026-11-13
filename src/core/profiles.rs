//! User profiles: built-in presets, custom profiles, safe import/export.
//!
//! A profile never touches the system by itself. Applying one produces a
//! [`Vec<Change>`] that the UI must show before the user confirms.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

/// Components a profile can switch. Kept separate from `config::Components`
/// so the profile file stays stable and cannot smuggle arbitrary settings.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub name_ru: String,
    pub name_en: String,
    #[serde(default)]
    pub description_ru: String,
    #[serde(default)]
    pub description_en: String,
    pub bypass: bool,
    pub dns: bool,
    pub hosts: bool,
    pub mtproto: bool,
    pub tgws: bool,
    pub subscriptions: bool,
    /// One of: none, hiddify, v2rayn, happ.
    #[serde(default = "none_client")]
    pub client: String,
    #[serde(default)]
    pub autostart: bool,
}

fn none_client() -> String {
    "none".into()
}

impl Profile {
    pub fn name(&self, lang: &str) -> &str {
        if lang == "en" {
            &self.name_en
        } else {
            &self.name_ru
        }
    }

    pub fn description(&self, lang: &str) -> &str {
        if lang == "en" {
            &self.description_en
        } else {
            &self.description_ru
        }
    }

    pub fn validate(&self) -> Result<()> {
        let id = self.id.trim();
        if id.is_empty() || id.len() > 48 {
            bail!("profile id must be 1..48 characters");
        }
        if !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            bail!("profile id may contain only letters, digits, '-' and '_'");
        }
        if self.name_ru.trim().is_empty() && self.name_en.trim().is_empty() {
            bail!("profile needs a name");
        }
        if !matches!(self.client.as_str(), "none" | "hiddify" | "v2rayn" | "happ") {
            bail!("unknown client '{}'", self.client);
        }
        if !self.bypass
            && !self.dns
            && !self.hosts
            && !self.mtproto
            && !self.tgws
            && !self.subscriptions
        {
            bail!("profile switches nothing on");
        }
        Ok(())
    }
}

/// The user's current configuration, for building a human-readable plan.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Current {
    pub bypass: bool,
    pub dns: bool,
    pub hosts: bool,
    pub mtproto: bool,
    pub tgws: bool,
    pub subscriptions: bool,
    pub client: String,
    pub autostart: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    pub ru: String,
    pub en: String,
}

impl Change {
    pub fn text(&self, lang: &str) -> &str {
        if lang == "en" {
            &self.en
        } else {
            &self.ru
        }
    }
}

fn toggle(changes: &mut Vec<Change>, label_ru: &str, label_en: &str, from: bool, to: bool) {
    if from != to {
        changes.push(Change {
            ru: format!(
                "{label_ru}: {} → {}",
                if from { "вкл" } else { "выкл" },
                if to { "вкл" } else { "выкл" }
            ),
            en: format!(
                "{label_en}: {} → {}",
                if from { "on" } else { "off" },
                if to { "on" } else { "off" }
            ),
        });
    }
}

/// Everything that will change if this profile is applied.
pub fn plan(profile: &Profile, cur: &Current) -> Vec<Change> {
    let mut changes = Vec::new();
    toggle(
        &mut changes,
        "Обход YouTube/Discord",
        "YouTube/Discord bypass",
        cur.bypass,
        profile.bypass,
    );
    toggle(&mut changes, "DNS", "DNS", cur.dns, profile.dns);
    toggle(&mut changes, "Hosts", "Hosts", cur.hosts, profile.hosts);
    toggle(
        &mut changes,
        "Прокси Telegram",
        "Telegram proxy",
        cur.mtproto,
        profile.mtproto,
    );
    toggle(
        &mut changes,
        "Мост TgWsProxy",
        "TgWsProxy bridge",
        cur.tgws,
        profile.tgws,
    );
    toggle(
        &mut changes,
        "Подписки",
        "Subscriptions",
        cur.subscriptions,
        profile.subscriptions,
    );
    toggle(
        &mut changes,
        "Автозапуск",
        "Autostart",
        cur.autostart,
        profile.autostart,
    );
    if cur.client != profile.client {
        changes.push(Change {
            ru: format!(
                "Приложение для серверов: {} → {}",
                client_name(&cur.client, "ru"),
                client_name(&profile.client, "ru")
            ),
            en: format!(
                "Servers app: {} → {}",
                client_name(&cur.client, "en"),
                client_name(&profile.client, "en")
            ),
        });
    }
    changes
}

pub fn client_name(id: &str, lang: &str) -> &'static str {
    match (id, lang) {
        ("hiddify", "en") => "Hiddify",
        ("hiddify", _) => "Hiddify",
        ("v2rayn", _) => "v2rayN",
        ("happ", _) => "Happ",
        ("none", "en") => "not needed",
        ("none", _) => "не нужно",
        _ => "unknown",
    }
}

pub fn builtins() -> Vec<Profile> {
    vec![
        Profile {
            id: "minimal".into(),
            name_ru: "Минимальный".into(),
            name_en: "Minimal".into(),
            description_ru: "Только обход YouTube и Discord, без лишнего".into(),
            description_en: "Only the YouTube/Discord bypass, nothing extra".into(),
            bypass: true,
            dns: true,
            hosts: false,
            mtproto: false,
            tgws: false,
            subscriptions: false,
            client: "none".into(),
            autostart: true,
        },
        Profile {
            id: "telegram".into(),
            name_ru: "Telegram".into(),
            name_en: "Telegram".into(),
            description_ru: "Прокси Telegram и запасной мост".into(),
            description_en: "Telegram proxy and the fallback bridge".into(),
            bypass: false,
            dns: true,
            hosts: false,
            mtproto: true,
            tgws: true,
            subscriptions: false,
            client: "none".into(),
            autostart: true,
        },
        Profile {
            id: "gaming".into(),
            name_ru: "Игры".into(),
            name_en: "Gaming".into(),
            description_ru: "Обход и DNS, без прокси и подписок — меньше задержка".into(),
            description_en: "Bypass and DNS, no proxy or subscriptions — lower latency".into(),
            bypass: true,
            dns: true,
            hosts: false,
            mtproto: false,
            tgws: false,
            subscriptions: false,
            client: "none".into(),
            autostart: true,
        },
        Profile {
            id: "browser".into(),
            name_ru: "Браузер".into(),
            name_en: "Browser".into(),
            description_ru: "Обход, DNS и серверы для браузера".into(),
            description_en: "Bypass, DNS and servers for the browser".into(),
            bypass: true,
            dns: true,
            hosts: false,
            mtproto: false,
            tgws: false,
            subscriptions: true,
            client: "hiddify".into(),
            autostart: true,
        },
        Profile {
            id: "full".into(),
            name_ru: "Полный".into(),
            name_en: "Full".into(),
            description_ru: "Всё сразу: обход, Telegram, подписки, приложение".into(),
            description_en: "Everything: bypass, Telegram, subscriptions, app".into(),
            bypass: true,
            dns: true,
            hosts: false,
            mtproto: true,
            tgws: true,
            subscriptions: true,
            client: "hiddify".into(),
            autostart: true,
        },
        Profile {
            id: "custom".into(),
            name_ru: "Свой".into(),
            name_en: "Custom".into(),
            description_ru: "Заготовка для собственного набора".into(),
            description_en: "A starting point for your own set".into(),
            bypass: true,
            dns: true,
            hosts: false,
            mtproto: false,
            tgws: false,
            subscriptions: false,
            client: "none".into(),
            autostart: true,
        },
    ]
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileStore {
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

impl ProfileStore {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("profiles.json")
    }

    pub fn load(data_dir: &Path) -> Self {
        let path = Self::path(data_dir);
        match fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<ProfileStore>(&text) {
                Ok(mut store) => {
                    // Never let a broken custom entry hide the built-ins.
                    store.profiles.retain(|p| p.validate().is_ok());
                    store.merge_builtins();
                    store
                }
                Err(e) => {
                    crate::logger::info(format!(
                        "profiles: {} повреждён ({e}), беру встроенные",
                        path.display()
                    ));
                    let mut s = Self::default();
                    s.merge_builtins();
                    s
                }
            },
            Err(_) => {
                let mut s = Self::default();
                s.merge_builtins();
                s
            }
        }
    }

    fn merge_builtins(&mut self) {
        for b in builtins() {
            if !self.profiles.iter().any(|p| p.id == b.id) {
                self.profiles.push(b);
            }
        }
    }

    pub fn save(&self, data_dir: &Path) -> Result<()> {
        fs::create_dir_all(data_dir)?;
        let path = Self::path(data_dir);
        let tmp = path.with_extension("json.tmp");
        let text = serde_json::to_string_pretty(self)?;
        fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, &path).with_context(|| format!("replace {}", path.display()))?;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }

    pub fn upsert(&mut self, profile: Profile) -> Result<()> {
        profile.validate()?;
        if let Some(slot) = self.profiles.iter_mut().find(|p| p.id == profile.id) {
            *slot = profile;
        } else {
            self.profiles.push(profile);
        }
        Ok(())
    }

    pub fn export(&self, profile: &Profile, dir: &Path) -> Result<PathBuf> {
        profile.validate()?;
        fs::create_dir_all(dir)?;
        let path = dir.join(format!("{}.json", profile.id));
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(profile)?)?;
        fs::rename(&tmp, &path)?;
        Ok(path)
    }

    pub fn import_str(&mut self, text: &str) -> Result<Profile> {
        let profile: Profile = serde_json::from_str(text).context("профиль не распознан")?;
        profile.validate()?;
        self.upsert(profile.clone())?;
        Ok(profile)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtins_are_valid_and_cover_required_ids() {
        let all = builtins();
        for p in &all {
            p.validate().unwrap();
        }
        for id in ["minimal", "telegram", "gaming", "browser", "full", "custom"] {
            assert!(all.iter().any(|p| p.id == id), "{id}");
        }
    }

    #[test]
    fn plan_reports_only_real_changes() {
        let cur = Current {
            bypass: false,
            dns: true,
            hosts: false,
            mtproto: false,
            tgws: false,
            subscriptions: false,
            client: "none".into(),
            autostart: true,
        };
        let p = builtins().into_iter().find(|p| p.id == "telegram").unwrap();
        let changes = plan(&p, &cur);
        assert!(changes.iter().any(|c| c.ru.contains("Прокси Telegram")));
        assert!(!changes.iter().any(|c| c.ru.contains("Обход")));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_client() {
        let text = r#"{"id":"x","name_ru":"X","name_en":"X","bypass":true,"dns":false,"hosts":false,"mtproto":false,"tgws":false,"subscriptions":false,"client":"evil","autostart":false}"#;
        assert!(serde_json::from_str::<Profile>(text).is_ok());
        let p: Profile = serde_json::from_str(text).unwrap();
        assert!(p.validate().is_err());

        let extra = r#"{"id":"x","name_ru":"X","name_en":"X","bypass":true,"dns":false,"hosts":false,"mtproto":false,"tgws":false,"subscriptions":false,"autostart":false,"evil":1}"#;
        assert!(serde_json::from_str::<Profile>(extra).is_err());
    }

    #[test]
    fn store_roundtrip_and_corruption_keeps_builtins() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = ProfileStore::default();
        store.merge_builtins();
        let mut custom = store.get("custom").unwrap().clone();
        custom.id = "mine".into();
        store.upsert(custom).unwrap();
        store.save(dir.path()).unwrap();

        let loaded = ProfileStore::load(dir.path());
        assert!(loaded.get("mine").is_some());
        assert!(loaded.get("minimal").is_some());

        std::fs::write(ProfileStore::path(dir.path()), "{not json").unwrap();
        let recovered = ProfileStore::load(dir.path());
        assert_eq!(recovered.profiles.len(), builtins().len());
    }

    #[test]
    fn import_rejects_traversal_ids() {
        let mut store = ProfileStore::default();
        let text = r#"{"id":"../../evil","name_ru":"X","name_en":"X","bypass":true,"dns":false,"hosts":false,"mtproto":false,"tgws":false,"subscriptions":false,"autostart":false}"#;
        assert!(store.import_str(text).is_err());
    }
}

//! Small local operation history: what obhod did and when.
//! Entries never contain proxy links or secrets.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::state::now_secs;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub at: u64,
    pub kind: String,
    pub ru: String,
    pub en: String,
    #[serde(default)]
    pub ok: bool,
}

impl HistoryEntry {
    pub fn new(kind: &str, ru: impl Into<String>, en: impl Into<String>, ok: bool) -> Self {
        Self {
            at: now_secs(),
            kind: kind.into(),
            ru: ru.into(),
            en: en.into(),
            ok,
        }
    }

    pub fn text(&self, lang: &str) -> &str {
        if lang == "en" {
            &self.en
        } else {
            &self.ru
        }
    }

    /// `2026-11-13 21:05` in local time is overkill for a log; this is a
    /// compact, unambiguous UTC stamp.
    pub fn stamp(&self) -> String {
        let secs = self.at;
        let days = secs / 86_400;
        let rem = secs % 86_400;
        let (y, m, d) = civil_from_days(days as i64);
        format!(
            "{y:04}-{m:02}-{d:02} {:02}:{:02}",
            rem / 3600,
            (rem % 3600) / 60
        )
    }
}

/// Howard Hinnant's civil-from-days, valid for the Unix epoch range we use.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[derive(Clone, Debug, Default)]
pub struct History {
    pub entries: Vec<HistoryEntry>,
    max: usize,
}

impl History {
    pub fn path(data_dir: &Path) -> PathBuf {
        data_dir.join("history.jsonl")
    }

    pub fn load(data_dir: &Path, max: usize) -> Self {
        let mut out = Self {
            entries: Vec::new(),
            max,
        };
        let Ok(text) = fs::read_to_string(Self::path(data_dir)) else {
            return out;
        };
        for line in text.lines() {
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<HistoryEntry>(line) {
                Ok(e) => out.entries.push(e),
                // A half-written line after a crash must not hide the rest.
                Err(_) => continue,
            }
        }
        if out.entries.len() > max {
            out.entries = out.entries.split_off(out.entries.len() - max);
        }
        out
    }

    pub fn append(data_dir: &Path, entry: HistoryEntry, max: usize) -> Result<HistoryEntry> {
        fs::create_dir_all(data_dir)?;
        let line = serde_json::to_string(&entry)?;
        let path = Self::path(data_dir);
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("open {}", path.display()))?;
        writeln!(f, "{line}")?;
        f.flush()?;
        // Keep the file bounded. A failed compaction is not fatal.
        let text = fs::read_to_string(&path).unwrap_or_default();
        if text.lines().count() > max {
            let mut h = Self::load(data_dir, max);
            h.compact(data_dir).ok();
        }
        Ok(entry)
    }

    fn compact(&mut self, data_dir: &Path) -> Result<()> {
        if self.entries.len() > self.max {
            self.entries = self.entries.split_off(self.entries.len() - self.max);
        }
        let mut text = String::new();
        for e in &self.entries {
            text.push_str(&serde_json::to_string(e)?);
            text.push('\n');
        }
        let path = Self::path(data_dir);
        let tmp = path.with_extension("jsonl.tmp");
        fs::write(&tmp, text)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    pub fn recent(&self, n: usize) -> impl Iterator<Item = &HistoryEntry> {
        let skip = self.entries.len().saturating_sub(n);
        self.entries.iter().skip(skip).rev()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_load_and_tolerate_broken_line() {
        let dir = tempfile::tempdir().unwrap();
        History::append(
            dir.path(),
            HistoryEntry::new("setup", "Включено", "Turned on", true),
            100,
        )
        .unwrap();
        // Simulate a crash mid-write.
        let mut f = OpenOptions::new()
            .append(true)
            .open(History::path(dir.path()))
            .unwrap();
        writeln!(f, "{{\"at\": 1, \"kind\"").unwrap();
        drop(f);
        History::append(
            dir.path(),
            HistoryEntry::new("off", "Выключено", "Turned off", true),
            100,
        )
        .unwrap();
        let h = History::load(dir.path(), 100);
        assert_eq!(h.entries.len(), 2);
        assert_eq!(h.recent(1).next().unwrap().kind, "off");
    }

    #[test]
    fn compacts_to_max() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..10 {
            History::append(
                dir.path(),
                HistoryEntry::new("check", format!("проверка {i}"), "check", true),
                3,
            )
            .unwrap();
        }
        let h = History::load(dir.path(), 100);
        assert!(h.entries.len() <= 4);
        assert_eq!(h.entries.last().unwrap().ru, "проверка 9");
    }

    #[test]
    fn civil_date_is_sane() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
    }
}
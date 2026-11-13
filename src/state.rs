use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Default, Serialize, Deserialize, Clone)]
pub struct State {
    /// tool id -> installed release tag
    pub tools: BTreeMap<String, String>,
    pub lists_updated: u64,
}

impl State {
    pub fn load(data: &Path) -> Self {
        std::fs::read_to_string(data.join("state.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, data: &Path) -> Result<()> {
        std::fs::create_dir_all(data)?;
        std::fs::write(data.join("state.json"), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn set_tool(&mut self, id: &str, tag: &str) {
        self.tools.insert(id.to_string(), tag.to_string());
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

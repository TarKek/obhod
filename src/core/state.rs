use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::state::now_secs;

/// A part of the product whose state matters to the user.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    Bypass,
    Dns,
    Hosts,
    Mtproto,
    Tgws,
    Subscriptions,
    Client,
    Update,
}

impl Component {
    pub fn all() -> [Component; 8] {
        [
            Component::Bypass,
            Component::Dns,
            Component::Hosts,
            Component::Mtproto,
            Component::Tgws,
            Component::Subscriptions,
            Component::Client,
            Component::Update,
        ]
    }

    pub fn name_ru(self) -> &'static str {
        match self {
            Component::Bypass => "Обход YouTube/Discord",
            Component::Dns => "DNS",
            Component::Hosts => "Hosts",
            Component::Mtproto => "Прокси Telegram",
            Component::Tgws => "Мост TgWsProxy",
            Component::Subscriptions => "Подписки",
            Component::Client => "Приложение для серверов",
            Component::Update => "Обновления",
        }
    }

    pub fn name_en(self) -> &'static str {
        match self {
            Component::Bypass => "YouTube/Discord bypass",
            Component::Dns => "DNS",
            Component::Hosts => "Hosts",
            Component::Mtproto => "Telegram proxy",
            Component::Tgws => "TgWsProxy bridge",
            Component::Subscriptions => "Subscriptions",
            Component::Client => "Servers app",
            Component::Update => "Updates",
        }
    }
}

/// Lifecycle of a component. Deliberately finer than "on/off": a proxy whose
/// port is open is not the same as a working proxy.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Installed,
    Configured,
    Running,
    Connected,
    Operational,
    Degraded,
    Failed,
    Disabled,
    Unknown,
}

impl Phase {
    pub fn is_working(self) -> bool {
        matches!(self, Phase::Operational)
    }

    pub fn is_problem(self) -> bool {
        matches!(self, Phase::Degraded | Phase::Failed)
    }

    pub fn name_ru(self) -> &'static str {
        match self {
            Phase::Installed => "установлено",
            Phase::Configured => "настроено",
            Phase::Running => "запущено",
            Phase::Connected => "подключено",
            Phase::Operational => "работает",
            Phase::Degraded => "работает частично",
            Phase::Failed => "ошибка",
            Phase::Disabled => "выключено",
            Phase::Unknown => "неизвестно",
        }
    }

    pub fn name_en(self) -> &'static str {
        match self {
            Phase::Installed => "installed",
            Phase::Configured => "configured",
            Phase::Running => "running",
            Phase::Connected => "connected",
            Phase::Operational => "operational",
            Phase::Degraded => "degraded",
            Phase::Failed => "failed",
            Phase::Disabled => "disabled",
            Phase::Unknown => "unknown",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ComponentStatus {
    pub component: Component,
    pub phase: Phase,
    pub detail_ru: String,
    pub detail_en: String,
    pub latency_ms: Option<u32>,
    pub failures: u32,
    pub last_ok: Option<u64>,
    pub last_check: Option<u64>,
}

impl ComponentStatus {
    pub fn unknown(component: Component) -> Self {
        Self {
            component,
            phase: Phase::Unknown,
            detail_ru: "ещё не проверялось".into(),
            detail_en: "not checked yet".into(),
            latency_ms: None,
            failures: 0,
            last_ok: None,
            last_check: None,
        }
    }

    pub fn detail(&self, lang: &str) -> &str {
        if lang == "en" {
            &self.detail_en
        } else {
            &self.detail_ru
        }
    }
}

/// A probe result. Screens emit it; one place applies it to the state.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Event {
    Probe {
        component: Component,
        phase: Phase,
        detail_ru: String,
        detail_en: String,
        latency_ms: Option<u32>,
    },
}

#[derive(Clone, Debug)]
pub struct CoreState {
    statuses: BTreeMap<Component, ComponentStatus>,
}

impl Default for CoreState {
    fn default() -> Self {
        Self::new()
    }
}

impl CoreState {
    pub fn new() -> Self {
        let mut statuses = BTreeMap::new();
        for c in Component::all() {
            statuses.insert(c, ComponentStatus::unknown(c));
        }
        Self { statuses }
    }

    pub fn status(&self, c: Component) -> &ComponentStatus {
        // Every component is seeded in `new`, so this cannot fail in practice.
        self.statuses
            .get(&c)
            .expect("component status is always seeded")
    }

    pub fn set(&mut self, c: Component, phase: Phase, detail: &str, latency_ms: Option<u32>) {
        let detail = detail.to_string();
        self.apply(Event::Probe {
            component: c,
            phase,
            detail_ru: detail.clone(),
            detail_en: detail,
            latency_ms,
        });
    }

    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Probe {
                component,
                phase,
                detail_ru,
                detail_en,
                latency_ms,
            } => {
                let now = now_secs();
                if let Some(s) = self.statuses.get_mut(&component) {
                    s.phase = phase;
                    s.detail_ru = detail_ru;
                    s.detail_en = detail_en;
                    s.latency_ms = latency_ms;
                    s.last_check = Some(now);
                    if phase == Phase::Operational {
                        s.last_ok = Some(now);
                        s.failures = 0;
                    } else if phase.is_problem() {
                        s.failures = s.failures.saturating_add(1);
                    }
                }
            }
        }
    }

    /// Overall state used by the dashboard badge.
    pub fn overall(&self) -> Phase {
        let relevant = [
            Component::Bypass,
            Component::Mtproto,
            Component::Tgws,
            Component::Subscriptions,
        ];
        let phases: Vec<Phase> = relevant.iter().map(|c| self.status(*c).phase).collect();
        if phases.iter().all(|p| *p == Phase::Disabled) {
            return Phase::Disabled;
        }
        if phases.iter().all(|p| *p == Phase::Unknown) {
            return Phase::Unknown;
        }
        if phases.contains(&Phase::Failed) {
            return Phase::Failed;
        }
        if phases.contains(&Phase::Degraded) {
            return Phase::Degraded;
        }
        if phases.iter().any(|p| p.is_working()) {
            return Phase::Operational;
        }
        Phase::Configured
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_until_probed() {
        let s = CoreState::new();
        assert_eq!(s.overall(), Phase::Unknown);
        assert_eq!(s.status(Component::Bypass).phase, Phase::Unknown);
    }

    #[test]
    fn failure_wins_over_success() {
        let mut s = CoreState::new();
        s.set(Component::Bypass, Phase::Operational, "ok", Some(12));
        s.set(Component::Mtproto, Phase::Failed, "boom", None);
        assert_eq!(s.overall(), Phase::Failed);
        assert_eq!(s.status(Component::Bypass).latency_ms, Some(12));
    }

    #[test]
    fn failures_accumulate_and_success_resets() {
        let mut s = CoreState::new();
        for _ in 0..3 {
            s.apply(Event::Probe {
                component: Component::Bypass,
                phase: Phase::Degraded,
                detail_ru: "x".into(),
                detail_en: "x".into(),
                latency_ms: None,
            });
        }
        assert_eq!(s.status(Component::Bypass).failures, 3);
        s.apply(Event::Probe {
            component: Component::Bypass,
            phase: Phase::Operational,
            detail_ru: "ok".into(),
            detail_en: "ok".into(),
            latency_ms: Some(5),
        });
        assert_eq!(s.status(Component::Bypass).failures, 0);
        assert!(s.status(Component::Bypass).last_ok.is_some());
    }
}

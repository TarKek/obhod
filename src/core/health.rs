//! Connection health: turns raw signals into a diagnosis of the failing stage.
//!
//! This module is pure. The caller collects signals from real probes and file
//! checks; tests cover the classification without touching the network.

use serde::{Deserialize, Serialize};

use super::state::Phase;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Dns,
    Tcp,
    Tls,
    Protocol,
    Proxy,
    Target,
}

impl Stage {
    pub fn name_ru(self) -> &'static str {
        match self {
            Stage::Dns => "DNS",
            Stage::Tcp => "Соединение (TCP)",
            Stage::Tls => "Шифрование (TLS)",
            Stage::Protocol => "Протокол прокси",
            Stage::Proxy => "Прокси",
            Stage::Target => "Целевые сайты",
        }
    }

    pub fn name_en(self) -> &'static str {
        match self {
            Stage::Dns => "DNS",
            Stage::Tcp => "Connection (TCP)",
            Stage::Tls => "Encryption (TLS)",
            Stage::Protocol => "Proxy protocol",
            Stage::Proxy => "Proxy",
            Stage::Target => "Target sites",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StageResult {
    pub stage: Stage,
    /// None means "not checked" (for example no proxy is configured).
    pub ok: Option<bool>,
    pub detail_ru: String,
    pub detail_en: String,
    pub latency_ms: Option<u32>,
}

impl StageResult {
    pub fn detail(&self, lang: &str) -> &str {
        if lang == "en" {
            &self.detail_en
        } else {
            &self.detail_ru
        }
    }
}

/// Signals gathered elsewhere. `None` means "not applicable / not checked".
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Signals {
    pub dns_ok: Option<bool>,
    pub tcp_ok: Option<bool>,
    pub tls_ok: Option<bool>,
    pub protocol_ok: Option<bool>,
    pub proxy_configured: bool,
    pub proxy_running: bool,
    pub proxy_verified: bool,
    pub bypass_running: bool,
    pub mtproto_ready: bool,
    pub tgws_running: bool,
    pub subscriptions_present: bool,
    pub client_installed: bool,
    pub target_ok: Option<bool>,
    pub admin: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthReport {
    pub overall: Phase,
    pub stages: Vec<StageResult>,
    pub checked_at: u64,
}

impl HealthReport {
    /// The first failing stage is the useful one for a user: what to fix.
    pub fn first_problem(&self) -> Option<&StageResult> {
        self.stages.iter().find(|s| s.ok == Some(false))
    }

    pub fn working_stages(&self) -> usize {
        self.stages.iter().filter(|s| s.ok == Some(true)).count()
    }

    pub fn checked_stages(&self) -> usize {
        self.stages.iter().filter(|s| s.ok.is_some()).count()
    }
}

fn stage(
    stage: Stage,
    ok: Option<bool>,
    ru: impl Into<String>,
    en: impl Into<String>,
    latency_ms: Option<u32>,
) -> StageResult {
    StageResult {
        stage,
        ok,
        detail_ru: ru.into(),
        detail_en: en.into(),
        latency_ms,
    }
}

/// Classifies the first broken link in the chain. Later stages are reported
/// as unchecked when an earlier one already failed, so the UI does not blame
/// TLS for a DNS outage.
pub fn evaluate(sig: &Signals, now: u64) -> HealthReport {
    let mut stages = Vec::new();

    let dns_ok = sig.dns_ok;
    stages.push(stage(
        Stage::Dns,
        dns_ok,
        match dns_ok {
            Some(true) => "имена сайтов определяются",
            Some(false) => "не удаётся определить имя сайта",
            None => "не проверялось",
        },
        match dns_ok {
            Some(true) => "names resolve",
            Some(false) => "cannot resolve a host name",
            None => "not checked",
        },
        None,
    ));

    let mut blocked = dns_ok == Some(false);
    let tcp_ok = if blocked { None } else { sig.tcp_ok };
    stages.push(stage(
        Stage::Tcp,
        tcp_ok,
        match tcp_ok {
            Some(true) => "соединение устанавливается",
            Some(false) => "сервер не отвечает на соединение",
            None => "не проверялось",
        },
        match tcp_ok {
            Some(true) => "connection established",
            Some(false) => "server does not accept connections",
            None => "not checked",
        },
        None,
    ));
    blocked |= tcp_ok == Some(false);

    let tls_ok = if blocked { None } else { sig.tls_ok };
    stages.push(stage(
        Stage::Tls,
        tls_ok,
        match tls_ok {
            Some(true) => "шифрование в порядке",
            Some(false) => "ошибка TLS: сертификат или SNI",
            None => "не проверялось",
        },
        match tls_ok {
            Some(true) => "encryption is fine",
            Some(false) => "TLS error: certificate or SNI",
            None => "not checked",
        },
        None,
    ));
    blocked |= tls_ok == Some(false);

    let protocol_ok = if blocked {
        None
    } else if sig.proxy_configured {
        sig.protocol_ok
    } else {
        None
    };
    stages.push(stage(
        Stage::Protocol,
        protocol_ok,
        match (sig.proxy_configured, protocol_ok) {
            (false, _) => "прокси не настроен",
            (true, Some(true)) => "протокол прокси отвечает",
            (true, Some(false)) => "порт открыт, но протокол не подтверждён",
            (true, None) => "проверка протокола не выполнялась",
        },
        match (sig.proxy_configured, protocol_ok) {
            (false, _) => "no proxy configured",
            (true, Some(true)) => "proxy protocol responds",
            (true, Some(false)) => "port is open, protocol is not confirmed",
            (true, None) => "protocol not checked",
        },
        None,
    ));

    let proxy_phase = if !sig.proxy_configured {
        None
    } else if sig.proxy_running && sig.proxy_verified {
        Some(true)
    } else if sig.proxy_running {
        Some(false)
    } else {
        Some(false)
    };
    stages.push(stage(
        Stage::Proxy,
        proxy_phase,
        if !sig.proxy_configured {
            "не используется"
        } else if sig.proxy_running && sig.proxy_verified {
            "прокси работает"
        } else if sig.proxy_running {
            "процесс запущен, но прокси не подтверждён"
        } else {
            "прокси не запущен"
        },
        if !sig.proxy_configured {
            "not used"
        } else if sig.proxy_running && sig.proxy_verified {
            "proxy is working"
        } else if sig.proxy_running {
            "process runs, proxy is not confirmed"
        } else {
            "proxy is not running"
        },
        None,
    ));

    let target_ok = if blocked { None } else { sig.target_ok };
    stages.push(stage(
        Stage::Target,
        target_ok,
        match target_ok {
            Some(true) => "YouTube и Discord открываются",
            Some(false) => "целевые сайты не открываются",
            None => "не проверялось",
        },
        match target_ok {
            Some(true) => "YouTube and Discord are reachable",
            Some(false) => "target sites are unreachable",
            None => "not checked",
        },
        None,
    ));

    let overall = overall_phase(sig, &stages);
    HealthReport {
        overall,
        stages,
        checked_at: now,
    }
}

fn overall_phase(sig: &Signals, stages: &[StageResult]) -> Phase {
    let any_fail = stages.iter().any(|s| s.ok == Some(false));
    let any_ok = stages.iter().any(|s| s.ok == Some(true));
    if sig.target_ok == Some(true) {
        return Phase::Operational;
    }
    if !sig.proxy_configured
        && !sig.bypass_running
        && !sig.mtproto_ready
        && !sig.tgws_running
        && !sig.subscriptions_present
        && !sig.client_installed
    {
        return Phase::Disabled;
    }
    if any_fail {
        if any_ok {
            return Phase::Degraded;
        }
        return Phase::Failed;
    }
    if any_ok {
        return Phase::Connected;
    }
    Phase::Configured
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals() -> Signals {
        Signals {
            dns_ok: Some(true),
            tcp_ok: Some(true),
            tls_ok: Some(true),
            protocol_ok: Some(true),
            proxy_configured: true,
            proxy_running: true,
            proxy_verified: true,
            bypass_running: true,
            target_ok: Some(true),
            ..Signals::default()
        }
    }

    #[test]
    fn all_good_is_operational() {
        let r = evaluate(&signals(), 10);
        assert_eq!(r.overall, Phase::Operational);
        assert_eq!(r.checked_stages(), 6);
        assert_eq!(r.working_stages(), 6);
    }

    #[test]
    fn dns_failure_does_not_blame_tls() {
        let mut s = signals();
        s.dns_ok = Some(false);
        s.tcp_ok = None;
        s.target_ok = Some(false);
        let r = evaluate(&s, 10);
        assert_eq!(r.overall, Phase::Failed);
        assert_eq!(r.stages[0].stage, Stage::Dns);
        assert_eq!(r.stages[0].ok, Some(false));
        assert_eq!(r.stages[2].ok, None);
    }

    #[test]
    fn open_port_is_not_a_working_proxy() {
        let mut s = signals();
        s.protocol_ok = Some(false);
        s.proxy_verified = false;
        s.target_ok = Some(false);
        let r = evaluate(&s, 10);
        assert_eq!(r.overall, Phase::Degraded);
        assert_eq!(r.stages[3].ok, Some(false));
        assert!(r.stages[3].detail_ru.contains("не подтверждён"));
    }

    #[test]
    fn nothing_installed_is_disabled() {
        let r = evaluate(&Signals::default(), 10);
        assert_eq!(r.overall, Phase::Disabled);
    }
}
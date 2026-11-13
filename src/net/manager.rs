//! Proxy-node registry: import, filters, ranking, check history and failover.
//!
//! This is the foundation for a proxy manager, not a traffic router. It stores
//! what was imported and what checks observed, ranks candidates, and computes
//! a failover *decision* as a pure function. Nothing here switches traffic on
//! its own.
//!
//! Honesty rules baked into the model:
//! - `tls_verified` means a TLS ServerHello was observed; it does not mean the
//!   node accepted our credentials (VLESS/Trojan/VMess auth is not implemented).
//! - `external` nodes need a third-party client; their protocol was only
//!   structurally validated.
//! - Failover requires `fail_threshold` consecutive failed checks (>= 2) and
//!   honours cooldowns, so one flaky measurement cannot flap the active node.
//!
//! Persistence is JSON written atomically; the full config (including its
//! secret) stays on disk in `data\proxy-nodes.json` and is never logged.

use std::collections::HashSet;
use std::fmt;
use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::net::links::{self, Protocol};
use crate::net::{atomic_write, sha256_hex, unix_now};

pub const STORE_VERSION: u32 = 1;
/// How many check points are kept per node.
pub const HISTORY_LIMIT: usize = 24;

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    #[default]
    Primary,
    Backup,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Ranking {
    BestLatency,
    MostStable,
    #[default]
    Balanced,
}

impl Ranking {
    pub fn ru(self) -> &'static str {
        match self {
            Ranking::BestLatency => "самые быстрые",
            Ranking::MostStable => "самые стабильные",
            Ranking::Balanced => "баланс скорости и стабильности",
        }
    }
}

/// One operational check result.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CheckPoint {
    pub at: u64,
    pub ok: bool,
    /// The check reached the TLS layer (but never proves credentials).
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    /// Short cause without secrets, e.g. "порт открыт, протокол не проверен".
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Node {
    /// Stable short id derived from `key`.
    pub id: String,
    /// Normalized dedupe key; contains only a hash of the credential.
    pub key: String,
    /// Full config, including its secret. Persisted locally, never logged.
    pub link: String,
    pub protocol: Protocol,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub successes: u32,
    #[serde(default)]
    pub failures: u32,
    #[serde(default)]
    pub last_ok: Option<u64>,
    #[serde(default)]
    pub last_check: Option<u64>,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub role: Role,
    /// No protocol client implemented; only link structure was checked.
    #[serde(default)]
    pub external: bool,
    /// TLS layer answered on the last check. Not an auth proof.
    #[serde(default)]
    pub tls_verified: bool,
    #[serde(default)]
    pub history: Vec<CheckPoint>,
    /// Until this timestamp the node is not chosen as a failover target.
    #[serde(default)]
    pub cooldown_until: Option<u64>,
}

impl Node {
    /// Trailing failed checks (most recent first).
    pub fn consecutive_failures(&self) -> u32 {
        self.history.iter().rev().take_while(|p| !p.ok).count() as u32
    }

    pub fn recent_failures(&self, window: usize) -> u32 {
        self.history
            .iter()
            .rev()
            .take(window)
            .filter(|p| !p.ok)
            .count() as u32
    }

    /// Success ratio over the last `window` checks, or over all time when the
    /// history is empty. Unknown nodes score 0.5 so they are not preferred
    /// over nodes with a proven record, but are not excluded either.
    pub fn success_rate(&self, window: usize) -> f64 {
        if self.history.is_empty() {
            let total = self.successes as f64 + self.failures as f64;
            return if total == 0.0 {
                0.5
            } else {
                self.successes as f64 / total
            };
        }
        let slice = &self.history[self.history.len().saturating_sub(window)..];
        slice.iter().filter(|p| p.ok).count() as f64 / slice.len() as f64
    }

    pub fn is_cooling(&self, now: u64) -> bool {
        self.cooldown_until.map(|t| now < t).unwrap_or(false)
    }

    /// Higher is better. Recent failures dominate, fresh success is rewarded.
    pub fn stability_score(&self, now: u64) -> i64 {
        let mut score = (self.success_rate(10) * 1000.0) as i64;
        score -= self.consecutive_failures() as i64 * 400;
        score -= self.recent_failures(10) as i64 * 60;
        if let Some(ok) = self.last_ok {
            if now.saturating_sub(ok) < 3600 {
                score += 100;
            }
        }
        if self.tls_verified {
            score += 40;
        }
        score
    }

    /// Higher is better. Latency is capped so one dead-slow node cannot ride
    /// a lucky single measurement to the top forever.
    pub fn balance_score(&self, now: u64) -> i64 {
        let lat = self.latency_ms.unwrap_or(2000).min(5000) as i64;
        let rate = (self.success_rate(10) * 100.0) as i64;
        let mut score = rate * 10 - lat / 10;
        score -= self.consecutive_failures() as i64 * 150;
        score -= self.recent_failures(10) as i64 * 20;
        if self.favorite {
            score += 50;
        }
        if self.tls_verified {
            score += 10;
        }
        if let Some(ok) = self.last_ok {
            if now.saturating_sub(ok) < 3600 {
                score += 20;
            }
        }
        score
    }

    pub fn history(&self, limit: usize) -> &[CheckPoint] {
        let start = self.history.len().saturating_sub(limit);
        &self.history[start..]
    }
}

/// Redacts the config: debug output must not leak UUIDs/passwords/tokens.
impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("id", &self.id)
            .field("key", &self.key)
            .field("link", &"<config hidden>")
            .field("protocol", &self.protocol)
            .field("source", &self.source)
            .field("country", &self.country_code)
            .field("latency_ms", &self.latency_ms)
            .field("failures", &self.failures)
            .field("successes", &self.successes)
            .field("favorite", &self.favorite)
            .field("role", &self.role)
            .field("external", &self.external)
            .field("tls_verified", &self.tls_verified)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct Filter {
    /// Country code (`DE`) or a part of the country name (`Герм`).
    pub country: Option<String>,
    pub protocol: Option<Protocol>,
    pub max_latency_ms: Option<u64>,
    pub favorites_only: bool,
    /// Include ss/hysteria2/tuic-ish nodes that need an external client.
    pub include_external: bool,
    /// Include nodes currently in failover cooldown.
    pub include_cooling: bool,
}

impl Default for Filter {
    fn default() -> Self {
        Self {
            country: None,
            protocol: None,
            max_latency_ms: None,
            favorites_only: false,
            include_external: true,
            include_cooling: false,
        }
    }
}

impl Filter {
    pub fn matches(&self, node: &Node, now: u64) -> bool {
        if !self.include_external && node.external {
            return false;
        }
        if self.favorites_only && !node.favorite {
            return false;
        }
        if let Some(p) = self.protocol {
            if node.protocol != p {
                return false;
            }
        }
        if let Some(want) = self
            .country
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let code_ok = node.country_code.eq_ignore_ascii_case(want);
            let name_ok = !node.country.is_empty()
                && node.country.to_lowercase().contains(&want.to_lowercase());
            if !code_ok && !name_ok {
                return false;
            }
        }
        if let Some(max) = self.max_latency_ms {
            match node.latency_ms {
                Some(l) if l <= max => {}
                _ => return false,
            }
        }
        if !self.include_cooling && node.is_cooling(now) {
            return false;
        }
        true
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct NodeStore {
    #[serde(default = "store_version")]
    pub version: u32,
    #[serde(default)]
    pub updated_at: u64,
    #[serde(default)]
    pub nodes: Vec<Node>,
    /// Currently selected node id.
    #[serde(default)]
    pub active: Option<String>,
    /// Last working node before the current one (fast path back).
    #[serde(default)]
    pub previous: Option<String>,
    #[serde(default)]
    pub active_since: u64,
    #[serde(default)]
    pub last_switch: Option<u64>,
}

fn store_version() -> u32 {
    STORE_VERSION
}

impl Default for NodeStore {
    fn default() -> Self {
        Self {
            version: STORE_VERSION,
            updated_at: 0,
            nodes: Vec::new(),
            active: None,
            previous: None,
            active_since: 0,
            last_switch: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoadOutcome {
    Loaded,
    Missing,
    Corrupt(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub seen: usize,
    pub imported: usize,
    pub duplicates: usize,
    pub invalid: usize,
    pub external: usize,
}

impl ImportStats {
    pub fn ru(&self) -> String {
        format!(
            "получено {}, новых {}, дублей {}, некорректных {}, внешних {}",
            self.seen, self.imported, self.duplicates, self.invalid, self.external
        )
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StoreStats {
    pub total: usize,
    pub primary: usize,
    pub backup: usize,
    pub favorites: usize,
    pub external: usize,
    pub tls_verified: usize,
    pub cooling: usize,
    pub countries: usize,
}

impl NodeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node_id(key: &str) -> String {
        let mut h = sha256_hex(key.as_bytes());
        h.truncate(16);
        h
    }

    /// Loads the store; a corrupt file yields an empty store *and* the reason,
    /// so the caller can decide to keep the file for inspection.
    pub fn load(path: &Path) -> (Self, LoadOutcome) {
        match std::fs::read_to_string(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                (Self::default(), LoadOutcome::Missing)
            }
            Err(e) => (Self::default(), LoadOutcome::Corrupt(e.to_string())),
            Ok(text) => match serde_json::from_str::<Self>(&text) {
                Ok(mut s) => {
                    // Tolerate older files without new fields.
                    s.version = STORE_VERSION;
                    (s, LoadOutcome::Loaded)
                }
                Err(e) => (Self::default(), LoadOutcome::Corrupt(e.to_string())),
            },
        }
    }

    pub fn load_or_default(path: &Path) -> Self {
        Self::load(path).0
    }

    /// Atomic JSON save (temp file + rename).
    pub fn save(&mut self, path: &Path) -> io::Result<()> {
        self.version = STORE_VERSION;
        self.updated_at = unix_now();
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        atomic_write(path, &json)
    }

    pub fn get(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }

    pub fn get_mut(&mut self, id: &str) -> Option<&mut Node> {
        self.nodes.iter_mut().find(|n| n.id == id)
    }

    pub fn active_node(&self) -> Option<&Node> {
        self.active.as_deref().and_then(|id| self.get(id))
    }

    /// Multi-source import. Existing nodes are never reset: their metrics and
    /// history survive a re-import.
    pub fn import(&mut self, links: &[String], source: &str, now: u64) -> ImportStats {
        let mut stats = ImportStats::default();
        let mut known: HashSet<String> = self.nodes.iter().map(|n| n.key.clone()).collect();
        for raw in links {
            stats.seen += 1;
            let info = match links::parse(raw) {
                Ok(i) => i,
                Err(_) => {
                    stats.invalid += 1;
                    continue;
                }
            };
            if !known.insert(info.key.clone()) {
                stats.duplicates += 1;
                continue;
            }
            let id = Self::node_id(&info.key);
            let mut node = Node {
                id,
                key: info.key.clone(),
                link: raw.trim().to_string(),
                protocol: info.protocol,
                source: source.to_string(),
                country_code: String::new(),
                country: String::new(),
                latency_ms: None,
                successes: 0,
                failures: 0,
                last_ok: None,
                last_check: None,
                favorite: false,
                role: Role::Primary,
                external: info.external,
                tls_verified: false,
                history: Vec::new(),
                cooldown_until: None,
            };
            if info.external {
                stats.external += 1;
                node.role = Role::Backup;
            }
            self.nodes.push(node);
            stats.imported += 1;
        }
        self.updated_at = now;
        stats
    }

    pub fn stats(&self, now: u64) -> StoreStats {
        let mut s = StoreStats {
            total: self.nodes.len(),
            ..StoreStats::default()
        };
        let mut countries = HashSet::new();
        for n in &self.nodes {
            match n.role {
                Role::Primary => s.primary += 1,
                Role::Backup => s.backup += 1,
            }
            if n.favorite {
                s.favorites += 1;
            }
            if n.external {
                s.external += 1;
            }
            if n.tls_verified {
                s.tls_verified += 1;
            }
            if n.is_cooling(now) {
                s.cooling += 1;
            }
            if !n.country_code.is_empty() {
                countries.insert(n.country_code.clone());
            }
        }
        s.countries = countries.len();
        s
    }

    pub fn set_favorite(&mut self, id: &str, favorite: bool) -> bool {
        match self.get_mut(id) {
            Some(n) => {
                n.favorite = favorite;
                true
            }
            None => false,
        }
    }

    pub fn set_role(&mut self, id: &str, role: Role) -> bool {
        match self.get_mut(id) {
            Some(n) => {
                n.role = role;
                true
            }
            None => false,
        }
    }

    /// Attaches geo data from a country lookup.
    pub fn set_country(&mut self, id: &str, code: &str, name: &str) {
        if let Some(n) = self.get_mut(id) {
            n.country_code = code.to_ascii_uppercase();
            n.country = name.to_string();
        }
    }

    /// Deterministic ordering: filter → rank → tie-break by id.
    pub fn ranked(&self, ranking: Ranking, filter: &Filter, now: u64) -> Vec<&Node> {
        let mut v: Vec<&Node> = self
            .nodes
            .iter()
            .filter(|n| filter.matches(n, now))
            .collect();
        let latency_cmp = |a: &Node, b: &Node| match (a.latency_ms, b.latency_ms) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        };
        v.sort_by(|a, b| {
            let ord = match ranking {
                Ranking::BestLatency => latency_cmp(a, b),
                Ranking::MostStable => b.stability_score(now).cmp(&a.stability_score(now)),
                Ranking::Balanced => b.balance_score(now).cmp(&a.balance_score(now)),
            };
            ord.then_with(|| a.id.cmp(&b.id))
        });
        v
    }

    /// Records one check and maintains counters, latency and cooldown.
    pub fn record_check(&mut self, id: &str, point: CheckPoint, policy: &FailoverPolicy) {
        let policy = policy.clone().normalized();
        let Some(n) = self.get_mut(id) else {
            return;
        };
        n.last_check = Some(point.at);
        n.tls_verified = point.verified;
        if point.ok {
            n.successes = n.successes.saturating_add(1);
            n.last_ok = Some(point.at);
            if let Some(l) = point.latency_ms {
                n.latency_ms = Some(l);
            }
            n.cooldown_until = None;
        } else {
            n.failures = n.failures.saturating_add(1);
            n.cooldown_until = Some(point.at.saturating_add(policy.cooldown_secs));
        }
        n.history.push(point);
        if n.history.len() > HISTORY_LIMIT {
            let drop = n.history.len() - HISTORY_LIMIT;
            n.history.drain(0..drop);
        }
    }

    /// Applies a failover decision. Traffic is not touched: this only moves
    /// the `active`/`previous` pointers in the store.
    pub fn apply_decision(&mut self, decision: &FailoverDecision, now: u64) {
        if let FailoverDecision::Switch { to, .. } = decision {
            if self.active.as_deref() == Some(to.as_str()) {
                return;
            }
            let old = self.active.clone();
            if let Some(old_id) = old {
                let was_working = self
                    .get(&old_id)
                    .map(|n| n.last_ok.is_some())
                    .unwrap_or(false);
                if was_working {
                    self.previous = Some(old_id);
                }
            }
            self.active = Some(to.clone());
            self.active_since = now;
            self.last_switch = Some(now);
            return;
        }
        if let FailoverDecision::Keep { node: Some(id), .. } = decision {
            if self.active.is_none() {
                self.active = Some(id.clone());
                self.active_since = now;
            }
        }
    }

    /// Convenience: decide and apply. Returns the decision for logging.
    pub fn record_and_decide(
        &mut self,
        policy: &FailoverPolicy,
        filter: &Filter,
        now: u64,
    ) -> FailoverDecision {
        let decision = decide(self, policy, filter, now);
        self.apply_decision(&decision, now);
        decision
    }
}

/// Failover tuning. `fail_threshold` is clamped to at least 2: a single bad
/// measurement must never move traffic.
#[derive(Clone, Debug)]
pub struct FailoverPolicy {
    /// Consecutive failed checks before switching.
    pub fail_threshold: u32,
    /// How long a failed node is not chosen as a target.
    pub cooldown_secs: u64,
    /// Minimum delay between two switches (anti-flapping).
    pub switch_cooldown_secs: u64,
    /// Candidate must have this many successful checks.
    pub min_successes: u32,
    /// Only switch to nodes whose TLS layer was observed.
    pub require_verified: bool,
}

impl Default for FailoverPolicy {
    fn default() -> Self {
        Self {
            fail_threshold: 2,
            cooldown_secs: 120,
            switch_cooldown_secs: 60,
            min_successes: 0,
            require_verified: false,
        }
    }
}

impl FailoverPolicy {
    pub fn normalized(mut self) -> Self {
        self.fail_threshold = self.fail_threshold.max(2);
        self
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FailoverDecision {
    Keep {
        node: Option<String>,
        reason: String,
    },
    Switch {
        from: Option<String>,
        to: String,
        reason: String,
    },
    NoCandidate {
        reason: String,
    },
}

impl FailoverDecision {
    pub fn reason(&self) -> &str {
        match self {
            FailoverDecision::Keep { reason, .. }
            | FailoverDecision::Switch { reason, .. }
            | FailoverDecision::NoCandidate { reason } => reason,
        }
    }

    pub fn target(&self) -> Option<&str> {
        match self {
            FailoverDecision::Keep { node, .. } => node.as_deref(),
            FailoverDecision::Switch { to, .. } => Some(to),
            FailoverDecision::NoCandidate { .. } => None,
        }
    }

    pub fn switched(&self) -> bool {
        matches!(self, FailoverDecision::Switch { .. })
    }
}

/// Pure failover policy: decides whether the active node should change.
pub fn decide(
    store: &NodeStore,
    policy: &FailoverPolicy,
    filter: &Filter,
    now: u64,
) -> FailoverDecision {
    let policy = policy.clone().normalized();
    let threshold = policy.fail_threshold;
    let current = store.active_node();
    let active_id = current.map(|n| n.id.clone());

    if let Some(n) = current {
        if n.consecutive_failures() < threshold {
            return FailoverDecision::Keep {
                node: active_id,
                reason: "текущий узел в норме".into(),
            };
        }
    }

    // Anti-flapping: after a recent switch, wait before moving again.
    let switch_ready = store
        .last_switch
        .map(|t| now >= t.saturating_add(policy.switch_cooldown_secs))
        .unwrap_or(true);
    if !switch_ready && current.is_some() {
        return FailoverDecision::Keep {
            node: active_id,
            reason: "гистерезис: переключение было недавно, ждём стабилизации".into(),
        };
    }

    let mut candidates: Vec<&Node> = store
        .ranked(Ranking::Balanced, filter, now)
        .into_iter()
        .filter(|n| Some(n.id.as_str()) != store.active.as_deref())
        .filter(|n| n.consecutive_failures() < threshold)
        .filter(|n| !n.is_cooling(now))
        .filter(|n| n.successes >= policy.min_successes)
        .filter(|n| !policy.require_verified || n.tls_verified)
        .collect();

    // Prefer the node that worked before the current one, if it recovered.
    if let Some(prev_id) = store.previous.as_deref() {
        if let Some(prev) = candidates.iter().position(|n| n.id == prev_id) {
            let prev = candidates.remove(prev);
            return FailoverDecision::Switch {
                from: active_id,
                to: prev.id.clone(),
                reason: "возврат к прежнему рабочему узлу".into(),
            };
        }
    }

    if let Some(best) = candidates.first() {
        let reason = match current {
            Some(n) => format!(
                "текущий узел не отвечает: {} ошибок подряд, переключаюсь",
                n.consecutive_failures()
            ),
            None => "активного узла нет — выбираю лучший".to_string(),
        };
        return FailoverDecision::Switch {
            from: active_id,
            to: best.id.clone(),
            reason,
        };
    }

    match current {
        Some(n) => FailoverDecision::Keep {
            node: Some(n.id.clone()),
            reason: "нет лучшего узла — оставляю последний рабочий".into(),
        },
        None => FailoverDecision::NoCandidate {
            reason: "нет проверенных узлов для переключения".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(host: &str, port: u16, uuid: &str) -> String {
        format!("vless://{uuid}@{host}:{port}?security=tls&sni={host}#{host}")
    }

    fn store_with(three: bool) -> NodeStore {
        let mut s = NodeStore::new();
        let mut links = vec![
            link("a.example", 443, "11111111-1111-4111-8111-111111111111"),
            link("b.example", 443, "22222222-2222-4222-8222-222222222222"),
        ];
        if three {
            links.push(link(
                "c.example",
                443,
                "33333333-3333-4333-8333-333333333333",
            ));
        }
        let st = s.import(&links, "test", 1000);
        assert_eq!(st.imported, links.len());
        s
    }

    fn id_of(s: &NodeStore, host: &str) -> String {
        s.nodes
            .iter()
            .find(|n| n.host_hint() == host)
            .map(|n| n.id.clone())
            .unwrap()
    }

    impl Node {
        fn host_hint(&self) -> String {
            self.link
                .split('@')
                .nth(1)
                .and_then(|r| r.split(':').next())
                .unwrap_or("")
                .to_string()
        }
    }

    fn ok(at: u64, latency: u64) -> CheckPoint {
        CheckPoint {
            at,
            ok: true,
            verified: true,
            latency_ms: Some(latency),
            reason: None,
        }
    }

    fn fail(at: u64) -> CheckPoint {
        CheckPoint {
            at,
            ok: false,
            verified: false,
            latency_ms: None,
            reason: Some("таймаут".into()),
        }
    }

    #[test]
    fn import_dedupes_and_keeps_metrics_on_reimport() {
        let mut s = NodeStore::new();
        let a = link("a.example", 443, "11111111-1111-4111-8111-111111111111");
        let st = s.import(
            &[
                a.clone(),
                a.clone(),
                "garbage".to_string(),
                link("b.example", 8443, "22222222-2222-4222-8222-222222222222"),
            ],
            "src1",
            1000,
        );
        assert_eq!(st.imported, 2);
        assert_eq!(st.duplicates, 1);
        assert_eq!(st.invalid, 1);

        let id = s.nodes[0].id.clone();
        s.record_check(&id, ok(1100, 40), &FailoverPolicy::default());
        let st2 = s.import(&[a], "src2", 2000);
        assert_eq!(st2.imported, 0);
        assert_eq!(s.nodes.len(), 2);
        assert_eq!(s.nodes[0].successes, 1);
        assert_eq!(s.nodes[0].latency_ms, Some(40));
        assert_eq!(s.nodes[0].source, "src1");
    }

    #[test]
    fn filters_by_country_protocol_latency_and_favorites() {
        let mut s = store_with(true);
        let id_a = id_of(&s, "a.example");
        s.set_country(&id_a, "de", "Германия");
        s.set_favorite(&id_a, true);
        s.record_check(&id_a, ok(1000, 50), &FailoverPolicy::default());
        let id_b = id_of(&s, "b.example");
        s.record_check(&id_b, ok(1000, 500), &FailoverPolicy::default());

        let f = Filter {
            country: Some("DE".into()),
            ..Filter::default()
        };
        assert_eq!(s.ranked(Ranking::Balanced, &f, 1000).len(), 1);

        let f = Filter {
            country: Some("герм".into()),
            ..Filter::default()
        };
        assert_eq!(s.ranked(Ranking::Balanced, &f, 1000).len(), 1);

        let f = Filter {
            max_latency_ms: Some(100),
            ..Filter::default()
        };
        let ids: Vec<&str> = s
            .ranked(Ranking::BestLatency, &f, 1000)
            .iter()
            .map(|n| n.id.as_str())
            .collect();
        assert_eq!(ids, vec![id_a.as_str()]);

        let f = Filter {
            favorites_only: true,
            ..Filter::default()
        };
        assert_eq!(s.ranked(Ranking::Balanced, &f, 1000).len(), 1);

        let f = Filter {
            protocol: Some(Protocol::Trojan),
            ..Filter::default()
        };
        assert!(s.ranked(Ranking::Balanced, &f, 1000).is_empty());
    }

    #[test]
    fn ranking_is_deterministic_and_latency_first() {
        let mut s = store_with(true);
        let id_a = id_of(&s, "a.example");
        let id_b = id_of(&s, "b.example");
        let id_c = id_of(&s, "c.example");
        s.record_check(&id_a, ok(1000, 300), &FailoverPolicy::default());
        s.record_check(&id_b, ok(1000, 100), &FailoverPolicy::default());
        // c has no measurement: it must sort after measured nodes.
        let f = Filter::default();
        let order: Vec<&str> = s
            .ranked(Ranking::BestLatency, &f, 1000)
            .iter()
            .map(|n| n.id.as_str())
            .collect();
        assert_eq!(order, vec![id_b.as_str(), id_a.as_str(), id_c.as_str()]);

        // Same input twice → same output.
        let again: Vec<&str> = s
            .ranked(Ranking::BestLatency, &f, 1000)
            .iter()
            .map(|n| n.id.as_str())
            .collect();
        assert_eq!(order, again);
    }

    #[test]
    fn one_failure_does_not_switch() {
        let mut s = store_with(false);
        let id_a = id_of(&s, "a.example");
        let id_b = id_of(&s, "b.example");
        s.record_check(&id_a, ok(1000, 50), &FailoverPolicy::default());
        s.record_check(&id_b, ok(1000, 100), &FailoverPolicy::default());
        s.active = Some(id_a.clone());
        s.active_since = 1000;

        s.record_check(&id_a, fail(2000), &FailoverPolicy::default());
        let d = decide(&s, &FailoverPolicy::default(), &Filter::default(), 2000);
        assert!(matches!(d, FailoverDecision::Keep { .. }), "{d:?}");
        assert_eq!(d.target(), Some(id_a.as_str()));
    }

    #[test]
    fn two_consecutive_failures_switch_to_best_candidate() {
        let mut s = store_with(false);
        let id_a = id_of(&s, "a.example");
        let id_b = id_of(&s, "b.example");
        let policy = FailoverPolicy::default();
        s.record_check(&id_a, ok(1000, 50), &policy);
        s.record_check(&id_b, ok(1000, 100), &policy);
        s.active = Some(id_a.clone());
        s.active_since = 1000;
        s.record_check(&id_a, fail(2000), &policy);
        s.record_check(&id_a, fail(3000), &policy);
        s.record_check(&id_b, ok(3100, 110), &policy);

        let d = s.record_and_decide(&policy, &Filter::default(), 3200);
        assert!(d.switched(), "{d:?}");
        assert_eq!(d.target(), Some(id_b.as_str()));
        assert_eq!(s.active.as_deref(), Some(id_b.as_str()));
        assert_eq!(s.previous.as_deref(), Some(id_a.as_str()));
        // Failed node is cooling down and excluded from candidates while the
        // cooldown is active.
        let node_a = s.get(&id_a).unwrap();
        assert!(node_a.is_cooling(3100));
        assert!(!node_a.is_cooling(3200));
        let f = Filter::default();
        assert!(!f.matches(node_a, 3100));
    }

    #[test]
    fn switch_cooldown_prevents_flapping() {
        let mut s = store_with(true);
        let id_a = id_of(&s, "a.example");
        let id_b = id_of(&s, "b.example");
        let id_c = id_of(&s, "c.example");
        let policy = FailoverPolicy::default();
        for id in [&id_a, &id_b, &id_c] {
            s.record_check(id, ok(1000, 100), &policy);
        }
        s.active = Some(id_b.clone());
        s.active_since = 1000;
        s.last_switch = Some(2200);
        s.record_check(&id_b, fail(2100), &policy);
        s.record_check(&id_b, fail(2200), &policy);
        // 2200 + 60 s: 2250 is still inside the anti-flap window.
        let d = decide(&s, &policy, &Filter::default(), 2250);
        assert!(matches!(d, FailoverDecision::Keep { .. }), "{d:?}");
        assert!(d.reason().contains("гистерезис"));
        // After the cooldown it switches.
        let d2 = decide(&s, &policy, &Filter::default(), 3000);
        assert!(d2.switched(), "{d2:?}");
    }

    #[test]
    fn returns_to_previous_working_node() {
        let mut s = store_with(true);
        let id_a = id_of(&s, "a.example");
        let id_b = id_of(&s, "b.example");
        let id_c = id_of(&s, "c.example");
        let policy = FailoverPolicy::default();
        for id in [&id_a, &id_b, &id_c] {
            s.record_check(id, ok(1000, 100), &policy);
        }
        // a worked, then switched to b, then to c (a is `previous`).
        s.active = Some(id_c.clone());
        s.previous = Some(id_a.clone());
        s.active_since = 1000;
        s.last_switch = Some(500);
        s.record_check(&id_c, fail(2000), &policy);
        s.record_check(&id_c, fail(2100), &policy);
        // c was better ranked (lower latency) than a, but the policy returns
        // to the proven node first.
        s.get_mut(&id_c).unwrap().latency_ms = Some(10);
        let d = s.record_and_decide(&policy, &Filter::default(), 2200);
        assert!(d.switched(), "{d:?}");
        assert_eq!(d.target(), Some(id_a.as_str()));
        assert!(d.reason().contains("прежнему"));
    }

    #[test]
    fn no_candidate_keeps_last_working_node() {
        let mut s = store_with(false);
        let id_a = id_of(&s, "a.example");
        let policy = FailoverPolicy::default();
        s.record_check(&id_a, ok(1000, 50), &policy);
        s.active = Some(id_a.clone());
        s.active_since = 1000;
        s.record_check(&id_a, fail(2000), &policy);
        s.record_check(&id_a, fail(2100), &policy);
        // The only other node is dead too and cooling down.
        let id_b = id_of(&s, "b.example");
        s.record_check(&id_b, fail(2100), &policy);
        s.record_check(&id_b, fail(2200), &policy);
        let d = decide(&s, &policy, &Filter::default(), 2200);
        assert!(matches!(d, FailoverDecision::Keep { .. }), "{d:?}");
        assert_eq!(d.target(), Some(id_a.as_str()));
        assert!(d.reason().contains("последний рабочий"));
    }

    #[test]
    fn no_nodes_at_all_is_reported() {
        let s = NodeStore::new();
        let d = decide(
            &s,
            &FailoverPolicy {
                fail_threshold: 0,
                ..FailoverPolicy::default()
            },
            &Filter::default(),
            1000,
        );
        // fail_threshold is normalized to 2, but with no nodes it cannot switch.
        assert!(matches!(d, FailoverDecision::NoCandidate { .. }), "{d:?}");
    }

    #[test]
    fn history_is_bounded_and_ordered() {
        let mut s = store_with(false);
        let id = id_of(&s, "a.example");
        let policy = FailoverPolicy::default();
        for i in 0..(HISTORY_LIMIT as u64 + 10) {
            s.record_check(&id, ok(1000 + i, 10 + i), &policy);
        }
        let n = s.get(&id).unwrap();
        assert_eq!(n.history.len(), HISTORY_LIMIT);
        assert_eq!(
            n.history.last().unwrap().at,
            1000 + HISTORY_LIMIT as u64 + 9
        );
        assert_eq!(n.history(3).len(), 3);
        assert_eq!(n.consecutive_failures(), 0);
    }

    #[test]
    fn persistence_roundtrip_is_atomic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("proxy-nodes.json");
        let mut s = store_with(true);
        let id = id_of(&s, "b.example");
        s.record_check(&id, ok(1000, 42), &FailoverPolicy::default());
        s.active = Some(id.clone());
        s.save(&path).unwrap();

        let (back, outcome) = NodeStore::load(&path);
        assert_eq!(outcome, LoadOutcome::Loaded);
        assert_eq!(back.nodes.len(), 3);
        assert_eq!(back.active.as_deref(), Some(id.as_str()));
        assert_eq!(back.get(&id).unwrap().latency_ms, Some(42));
        assert_eq!(back.get(&id).unwrap().history.len(), 1);

        // No temp files left behind.
        let temps = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp-"))
            .count();
        assert_eq!(temps, 0);
    }

    #[test]
    fn missing_and_corrupt_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nope.json");
        let (s, o) = NodeStore::load(&path);
        assert!(s.nodes.is_empty());
        assert_eq!(o, LoadOutcome::Missing);

        std::fs::write(&path, "{ broken").unwrap();
        let (s, o) = NodeStore::load(&path);
        assert!(s.nodes.is_empty());
        assert!(matches!(o, LoadOutcome::Corrupt(_)));
        // The caller still owns the file: load must not overwrite it.
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{ broken");
    }

    #[test]
    fn debug_does_not_leak_the_config() {
        let s = store_with(false);
        let text = format!("{:?}", s.nodes[0]);
        assert!(!text.contains("vless://"));
        assert!(!text.contains("11111111-1111"));
        assert!(text.contains("<config hidden>"));
    }

    #[test]
    fn external_nodes_are_backup_by_default() {
        let mut s = NodeStore::new();
        s.import(
            &["ss://YWVzLTI1Ni1nY206cHc=@1.2.3.4:8388#x".to_string()],
            "src",
            1000,
        );
        let n = &s.nodes[0];
        assert!(n.external);
        assert_eq!(n.role, Role::Backup);
        let f = Filter {
            include_external: false,
            ..Filter::default()
        };
        assert!(s.ranked(Ranking::Balanced, &f, 1000).is_empty());
    }
}

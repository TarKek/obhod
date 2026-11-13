//! DNS / DoH: point the active adapter at public resolvers, and put the exact
//! previous configuration back on request.
//!
//! * Before any change the whole per-interface state is snapshotted (GUID,
//!   alias, DHCP vs static per family, exact server lists, DoH templates) into
//!   `data\dns-snapshot.json` — atomically, and marked `complete` only at the
//!   end. A crash while capturing leaves `complete: false`, which startup
//!   recovery discards (nothing was applied).
//! * The change runs as a `sys::transaction` step. Its undo record is
//!   `Undo::RestoreDns { snapshot }`, so an interruption at any phase is rolled
//!   back on the next start without any extra state.
//! * Restore puts the exact lists back per interface (matched by GUID, so a
//!   renamed adapter still works), falls back to "automatic" only where the
//!   adapter really was DHCP, and restores DoH templates where Windows has them.
//! * DoH is best effort: on builds without the cmdlets it is skipped with a
//!   clear log line, never treated as failure.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::modules::Ctx;
use crate::sys::dns_state::{
    self, DnsBackend, DnsSnapshot, IfaceDns, SnapshotState, SystemDns, PUBLIC_DOH, PUBLIC_V4,
};
use crate::sys::journal::{Journal, Undo};
use crate::sys::transaction::{self, Step, TxHandle};

pub fn run(ctx: &Ctx) -> Result<()> {
    if !ctx.admin {
        ctx.log("⚠ DNS: нужны права администратора — шаг пропущен.");
        return Ok(());
    }
    let journal = Journal::new(ctx.data.clone());
    let step = SetDnsStep::new(ctx.data.clone());
    let res = transaction::run("dns", &journal, vec![Box::new(step)]);
    for m in &res.messages {
        ctx.log(m.clone());
    }
    res.into_result().map(|_| ())
}

/// Returns DNS to the state saved before the first change.
///
/// Prefers the snapshot (exact lists). Without a snapshot it resets the active
/// adapter to automatic — the old, less precise behaviour — and says so.
pub fn reset(ctx: &Ctx) -> Result<()> {
    if !ctx.admin {
        ctx.log("⚠ DNS: нужны права администратора — пропущено.");
        return Ok(());
    }
    let state = dns_state::read_state(&ctx.data)?;
    let journal = Journal::new(ctx.data.clone());
    let step = match state {
        SnapshotState::Complete(snap) => {
            ctx.log(format!(
                "Возвращаю DNS из снимка ({} интерфейсов, от {})",
                snap.interfaces.len(),
                snap.created
            ));
            RestoreStep::from_snapshot(*snap)
        }
        SnapshotState::Incomplete => {
            // Capture never finished, so no DNS change was made by us.
            let _ = dns_state::remove_snapshot(&ctx.data);
            ctx.log("Незавершённый снимок DNS удалён — изменений не было.");
            RestoreStep::active_only()
        }
        SnapshotState::Missing => {
            ctx.log("Снимка DNS нет (меняли не мы) — сбрасываю активный интерфейс на автоматический.");
            RestoreStep::active_only()
        }
    };
    let res = transaction::run("dns", &journal, vec![Box::new(step)]);
    for m in &res.messages {
        ctx.log(m.clone());
    }
    res.into_result().map(|_| ())
}

/// Path of the DNS snapshot, for diagnostics.
#[allow(dead_code)] // wired by the UI/diagnostics screen
pub fn snapshot_path(ctx: &Ctx) -> PathBuf {
    dns_state::snapshot_path(&ctx.data)
}

// ───────────────────────── steps ─────────────────────────

/// Snapshot → set 1.1.1.1/8.8.8.8 (+DoH) → verify → flush.
struct SetDnsStep {
    dir: PathBuf,
    snap: Option<DnsSnapshot>,
    logs: Vec<String>,
}

impl SetDnsStep {
    fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            snap: None,
            logs: Vec::new(),
        }
    }

    fn snap_ref(&self) -> Result<&DnsSnapshot> {
        self.snap
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("внутренняя ошибка: нет снимка DNS"))
    }
}

impl Step for SetDnsStep {
    fn component(&self) -> &str {
        "dns"
    }

    fn action(&self) -> &'static str {
        "set-public-dns"
    }

    fn snapshot(&mut self, h: &TxHandle) -> Result<Undo> {
        let snap = dns_state::capture_and_save(&self.dir, &SystemDns, &h.tx)?;
        let path = dns_state::snapshot_path(&self.dir);
        self.logs.push(format!(
            "DNS-снимок: {} интерфейсов, DoH: {}",
            snap.interfaces.len(),
            if snap.doh.supported {
                format!("{} шаблонов", snap.doh.entries.len())
            } else {
                "не поддерживается".to_string()
            }
        ));
        for i in &snap.interfaces {
            self.logs.push(format!(
                "  {} ({}) v4={} v6={} {}",
                i.alias,
                short_guid(&i.guid),
                if i.dhcp_v4 {
                    "авто".to_string()
                } else {
                    i.servers_v4.join(",")
                },
                if i.dhcp_v6 {
                    "авто".to_string()
                } else {
                    i.servers_v6.join(",")
                },
                if i.connected { "up" } else { "down" }
            ));
        }
        self.snap = Some(snap);
        Ok(Undo::RestoreDns {
            snapshot: path.display().to_string(),
        })
    }

    fn apply(&mut self, h: &TxHandle) -> Result<()> {
        let snap = self.snap_ref()?.clone();
        let servers: Vec<String> = PUBLIC_V4.iter().map(|s| s.to_string()).collect();
        let outcomes = dns_state::apply_v4(&SystemDns, &snap, &servers);
        if outcomes.is_empty() {
            anyhow::bail!("не нашли ни одного активного интерфейса — DNS не изменён");
        }
        let mut failed = Vec::new();
        for o in &outcomes {
            if o.ok {
                self.logs.push(format!("✓ DNS {}: {}", o.alias, o.detail));
                h.info(
                    "dns",
                    &format!("set-v4 {}", o.alias),
                    None,
                    Some(serde_json::json!({ "servers": servers })),
                )?;
            } else {
                self.logs
                    .push(format!("⚠ DNS {}: {}", o.alias, o.detail));
                failed.push(format!("{}: {}", o.alias, o.detail));
            }
        }
        if !failed.is_empty() {
            anyhow::bail!("DNS выставлен не на всех интерфейсах: {}", failed.join("; "));
        }
        self.logs
            .push(format!("✓ DNS выставлен на {}", servers.join(" / ")));

        // DoH is best effort (Windows 11 only).
        if snap.doh.supported {
            for (server, template) in PUBLIC_DOH {
                match SystemDns.add_doh(server, template, true) {
                    Ok(()) => {
                        self.logs.push(format!("✓ DoH включён для {server}"));
                        h.info(
                            "dns",
                            &format!("doh {server}"),
                            None,
                            Some(serde_json::json!({ "template": template, "auto": true })),
                        )?;
                    }
                    Err(e) => self
                        .logs
                        .push(format!("• DoH для {server} не включён: {e:#}")),
                }
            }
        } else {
            self.logs
                .push("• DoH не поддерживается этой Windows — пропуск".into());
        }
        Ok(())
    }

    fn verify(&mut self, _h: &TxHandle) -> Result<()> {
        let snap = self.snap_ref()?.clone();
        let want: Vec<String> = PUBLIC_V4.iter().map(|s| s.to_string()).collect();
        let mut problems = Vec::new();
        for iface in snap.active() {
            if !dns_state::verify_v4(&SystemDns, iface, &want)? {
                problems.push(iface.label());
            }
        }
        if problems.is_empty() {
            self.logs.push("✓ DNS проверен: серверы на месте".into());
            Ok(())
        } else {
            anyhow::bail!("проверка DNS не прошла: {}", problems.join(", "))
        }
    }

    fn commit(&mut self, _h: &TxHandle) -> Result<()> {
        SystemDns.flush().context("не удалось очистить кэш DNS")?;
        self.logs.push("Кэш DNS очищен.".into());
        Ok(())
    }

    fn rollback(&mut self, _h: &TxHandle) -> Result<()> {
        let Some(snap) = self.snap.clone() else {
            return Ok(());
        };
        let outcomes = dns_state::restore(&SystemDns, &snap);
        let failed: Vec<String> = outcomes
            .iter()
            .filter(|o| !o.ok)
            .map(|o| format!("{} {}", o.alias, o.detail))
            .collect();
        for o in outcomes.iter().filter(|o| o.ok) {
            self.logs
                .push(format!("↩ DNS {}: {}", o.alias, o.detail));
        }
        if !failed.is_empty() {
            anyhow::bail!("откат DNS неполный: {}", failed.join("; "));
        }
        Ok(())
    }

    fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.logs)
    }
}

/// Restore from a snapshot, or (no snapshot) just reset the active adapter.
struct RestoreStep {
    snap: Option<DnsSnapshot>,
    active_only: Option<IfaceDns>,
    logs: Vec<String>,
}

impl RestoreStep {
    fn from_snapshot(snap: DnsSnapshot) -> Self {
        Self {
            snap: Some(snap),
            active_only: None,
            logs: Vec::new(),
        }
    }

    fn active_only() -> Self {
        Self {
            snap: None,
            active_only: None,
            logs: Vec::new(),
        }
    }
}

impl Step for RestoreStep {
    fn component(&self) -> &str {
        "dns"
    }

    fn action(&self) -> &'static str {
        "restore-dns"
    }

    fn snapshot(&mut self, _h: &TxHandle) -> Result<Undo> {
        if self.snap.is_some() {
            // A restore is its own recovery path: retrying it is safe and
            // idempotent, and re-applying public DNS would not help anyone.
            return Ok(Undo::None);
        }
        let all = SystemDns.read_all()?;
        let pick = all
            .iter()
            .find(|i| i.connected && i.gateway)
            .or_else(|| all.iter().find(|i| i.connected))
            .or_else(|| all.first())
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("не нашли ни одного сетевого интерфейса"))?;
        self.logs.push(format!("Активный интерфейс: {}", pick.label()));
        self.active_only = Some(pick);
        Ok(Undo::None)
    }

    fn apply(&mut self, _h: &TxHandle) -> Result<()> {
        if let Some(snap) = &self.snap {
            let outcomes = dns_state::restore(&SystemDns, snap);
            let mut failed = Vec::new();
            for o in &outcomes {
                if o.ok {
                    self.logs.push(format!("✓ {}: {}", o.alias, o.detail));
                } else {
                    self.logs.push(format!("⚠ {}: {}", o.alias, o.detail));
                    failed.push(format!("{}: {}", o.alias, o.detail));
                }
            }
            if snap.doh.supported {
                let ours: Vec<String> = PUBLIC_V4.iter().map(|s| s.to_string()).collect();
                for o in dns_state::restore_doh(&SystemDns, &snap.doh.entries, &ours) {
                    if o.ok {
                        self.logs.push(format!("✓ DoH {}: {}", o.alias, o.detail));
                    } else {
                        self.logs
                            .push(format!("⚠ DoH {}: {}", o.alias, o.detail));
                        failed.push(format!("DoH {}: {}", o.alias, o.detail));
                    }
                }
            }
            if !failed.is_empty() {
                anyhow::bail!("DNS восстановлен не полностью: {}", failed.join("; "));
            }
            return Ok(());
        }

        let iface = self
            .active_only
            .clone()
            .ok_or_else(|| anyhow::anyhow!("нет интерфейса для сброса"))?;
        SystemDns.reset_all(&iface)?;
        self.logs
            .push(format!("✓ DNS {}: снова получается автоматически", iface.alias));
        Ok(())
    }

    fn verify(&mut self, _h: &TxHandle) -> Result<()> {
        if let Some(snap) = &self.snap {
            let problems = dns_state::verify_restored(&SystemDns, snap)?;
            if problems.is_empty() {
                self.logs.push("✓ DNS проверен: как было до включения".into());
                return Ok(());
            }
            anyhow::bail!("проверка восстановления DNS: {}", problems.join("; "));
        }
        let iface = self
            .active_only
            .clone()
            .ok_or_else(|| anyhow::anyhow!("нет интерфейса для проверки"))?;
        let live = SystemDns.read_all()?;
        match live.iter().find(|i| i.guid.eq_ignore_ascii_case(&iface.guid)) {
            Some(i) if i.dhcp_v4 => {
                self.logs.push("✓ DNS снова автоматический".into());
                Ok(())
            }
            Some(_) => anyhow::bail!("DNS {} не вернулся на автоматический режим", iface.label()),
            None => Ok(()), // adapter vanished while we were working
        }
    }

    fn commit(&mut self, _h: &TxHandle) -> Result<()> {
        SystemDns.flush().ok();
        self.logs.push("Кэш DNS очищен.".into());
        Ok(())
    }

    fn rollback(&mut self, _h: &TxHandle) -> Result<()> {
        // Nothing sensible to undo: the snapshot is kept on disk, so a retry of
        // `reset` (or `run`, which re-snapshots) is the recovery path.
        Ok(())
    }

    fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.logs)
    }
}

fn short_guid(guid: &str) -> String {
    let g = guid.trim_matches(|c| c == '{' || c == '}');
    g.chars().take(8).collect()
}

/// Whether a snapshot exists (used by the UI/`off` to decide what to restore).
pub fn has_snapshot(data_dir: &std::path::Path) -> bool {
    matches!(
        dns_state::read_state(data_dir),
        Ok(SnapshotState::Complete(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_guid_trims_braces() {
        assert_eq!(short_guid("{B356F5DC-B57B-4B86-B73D-0151063F7176}"), "B356F5DC");
        assert_eq!(short_guid(""), "");
    }

    #[test]
    fn snapshot_detection_matches_the_file_layer() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!has_snapshot(dir.path()));
        let snap = DnsSnapshot::empty("t");
        dns_state::write_snapshot(&dns_state::snapshot_path(dir.path()), &snap).unwrap();
        assert!(!has_snapshot(dir.path()), "incomplete snapshot is not usable");
        let mut done = DnsSnapshot::empty("t");
        done.complete = true;
        dns_state::write_snapshot(&dns_state::snapshot_path(dir.path()), &done).unwrap();
        assert!(has_snapshot(dir.path()));
    }

    #[test]
    fn step_types_report_stable_names() {
        let set = SetDnsStep::new(PathBuf::from("data"));
        assert_eq!(set.component(), "dns");
        assert_eq!(set.action(), "set-public-dns");
        let restore = RestoreStep::active_only();
        assert_eq!(restore.action(), "restore-dns");
    }
}
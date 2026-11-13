//! Windows system layer: transactions, journal, DNS state, hosts file and
//! process ownership.
//!
//! Design rules for everything in this module:
//! * nothing here touches the real system at import time;
//! * every effect is behind a trait (`FsIo`, `DnsBackend`, `ProcBackend`,
//!   [`UndoExecutor`]) so tests run against mocks;
//! * every change is journaled before it happens and can be undone from the
//!   journal alone — see [`journal::recover_pending_with`];
//! * no shell strings: values travel as `Command::args` or as base64 JSON in an
//!   environment variable, never interpolated into a command line.
//!
//! The layer is a public API for the rest of the crate: some helpers are used
//! only by tests or reserved for the UI, hence the module-wide allow.
#![allow(dead_code)]

pub mod dns_state;
pub mod fsx;
pub mod hosts_file;
pub mod journal;
pub mod proc;
pub mod transaction;

#[allow(unused_imports)]
pub use dns_state::{DnsBackend, DnsSnapshot, DohEntry, DohState, Family, IfaceDns, SnapshotState};
// Re-exported for modules; a binary crate still warns about unused re-exports
// until every caller lands, so the allow is deliberate.
#[allow(unused_imports)]
pub use journal::{
    recover_pending_with, Journal, Phase, Record, RecoveryReport, Status, Undo, UndoExecutor,
};
#[allow(unused_imports)]
pub use transaction::{run as run_tx, Step, TxHandle, TxResult};

use anyhow::Result;
use std::path::Path;

/// Real implementation of every undo action the journal can record.
pub struct SystemUndo;

impl UndoExecutor for SystemUndo {
    fn restore_file(&self, path: &Path, backup: &Path) -> Result<()> {
        let bytes = std::fs::read(backup)
            .map_err(|e| anyhow::anyhow!("нет резервной копии {}: {e}", backup.display()))?;
        if let Err(e) = fsx::write_atomic(path, &bytes) {
            // Atomic replace can lose to an antivirus holding the file; a plain
            // write is worse than nothing but better than leaving a broken file.
            crate::logger::info(format!(
                "restore: атомарная замена {} не удалась ({e}), пишу напрямую",
                path.display()
            ));
            std::fs::write(path, &bytes)
                .map_err(|e| anyhow::anyhow!("не удалось восстановить {}: {e}", path.display()))?;
        }
        Ok(())
    }

    fn delete_file(&self, path: &Path) -> Result<()> {
        fsx::RealFs::remove(path)?;
        Ok(())
    }

    fn restore_dns(&self, snapshot: &Path) -> Result<()> {
        dns_state::restore_from_file(snapshot, &dns_state::SystemDns)
    }

    fn delete_service(&self, name: &str) -> Result<()> {
        if !service_exists(name) {
            return Ok(()); // idempotent
        }
        let _ = crate::util::hidden_str("sc", &["stop", name]);
        crate::util::run_checked("sc", &["delete", name])
            .map_err(|e| anyhow::anyhow!("sc delete {name}: {e:#}"))?;
        if service_exists(name) {
            anyhow::bail!("служба {name} всё ещё существует после sc delete");
        }
        Ok(())
    }

    fn delete_reg_value(&self, root: &str, path: &str, name: &str) -> Result<()> {
        crate::util::reg_delete_value(root, path, name)
    }

    fn kill_process(&self, pid: u32, exe: &str) -> Result<()> {
        let image = Path::new(exe)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        if image.is_empty() {
            anyhow::bail!("в записи нет пути процесса, не трогаю pid {pid}");
        }
        proc::kill_owned(&proc::SystemProcs, &image, pid, exe)
    }

    fn note(&self, component: &str, text: &str) -> Result<()> {
        crate::logger::info(format!("undo/{component}: {text}"));
        Ok(())
    }
}

/// A service exists if `sc query` prints anything on stdout (locale-independent,
/// see `modules::detect::service_exists`).
fn service_exists(name: &str) -> bool {
    crate::util::hidden_str("sc", &["query", name])
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

/// The journal for a data directory.
pub fn journal(data_dir: &Path) -> Journal {
    Journal::new(data_dir)
}

/// Undo interrupted transactions. Call once at startup, before any module runs.
pub fn recover_pending(data_dir: &Path) -> Result<RecoveryReport> {
    std::fs::create_dir_all(data_dir).ok();
    let j = Journal::new(data_dir);
    let rep = recover_pending_with(&j, &SystemUndo)?;
    for line in &rep.log {
        crate::logger::info(line);
    }
    // A stale incomplete DNS snapshot means capture died before doing anything.
    if matches!(
        dns_state::read_state(data_dir).unwrap_or(SnapshotState::Missing),
        SnapshotState::Incomplete
    ) {
        let _ = dns_state::remove_snapshot(data_dir);
        crate::logger::info("DNS-снимок был недописан (сбой при снятии) — удалён, изменений не было");
    }
    Ok(rep)
}

/// [`recover_pending`] that never fails: for the startup path of the UI.
pub fn recover_pending_quiet(data_dir: &Path) -> RecoveryReport {
    match recover_pending(data_dir) {
        Ok(rep) => rep,
        Err(e) => {
            let msg = format!("⚠ восстановление после сбоя: {e:#}");
            crate::logger::info(&msg);
            RecoveryReport {
                log: vec![msg],
                ..Default::default()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recover_pending_on_empty_dir_is_clean() {
        let dir = tempfile::tempdir().unwrap();
        let rep = recover_pending(dir.path()).unwrap();
        assert!(rep.is_clean());
        assert!(rep.ok());
    }

    #[test]
    fn stale_incomplete_dns_snapshot_is_removed_on_startup() {
        let dir = tempfile::tempdir().unwrap();
        let snap = dns_state::DnsSnapshot::empty("tx");
        dns_state::write_snapshot(&dns_state::snapshot_path(dir.path()), &snap).unwrap();
        assert_eq!(
            dns_state::read_state(dir.path()).unwrap(),
            SnapshotState::Incomplete
        );
        recover_pending(dir.path()).unwrap();
        assert_eq!(
            dns_state::read_state(dir.path()).unwrap(),
            SnapshotState::Missing
        );
    }
}
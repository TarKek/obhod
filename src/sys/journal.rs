//! Append-only JSONL journal: the durable memory of every system change.
//!
//! One line per event. Each line is written with a single `write_all` + fsync
//! append, so a crash can only ever tear the *last* line; readers skip a
//! malformed trailing line instead of giving up on the whole file.
//!
//! A transaction is identified by `tx` and gets a terminal record when it is
//! either committed ([`ACTION_COMMIT`]) or rolled back ([`ACTION_ROLLBACK_DONE`]).
//! Anything without a terminal record is an interrupted transaction and is
//! picked up by [`recover_pending_with`] on the next start.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use super::fsx;

pub const JOURNAL_FILE: &str = "journal.jsonl";
/// Journal is rotated to `.1` once it grows past this; history is not critical.
pub const JOURNAL_MAX_BYTES: u64 = 4 * 1024 * 1024;

pub const ACTION_COMMIT: &str = "tx_commit_complete";
pub const ACTION_ROLLBACK_DONE: &str = "tx_rollback_complete";

/// Transaction phases, in the order the engine runs them.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Snapshot,
    Prepare,
    Apply,
    Verify,
    Commit,
    Rollback,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Snapshot => "snapshot",
            Phase::Prepare => "prepare",
            Phase::Apply => "apply",
            Phase::Verify => "verify",
            Phase::Commit => "commit",
            Phase::Rollback => "rollback",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Failed,
}

/// Everything needed to undo one recorded action, without reading any code.
///
/// Recovery replays these through [`UndoExecutor`]; every variant must be
/// idempotent (running it twice is harmless).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Undo {
    #[default]
    None,
    /// Put `backup` back over `path`.
    RestoreFile { path: String, backup: String },
    /// Remove a file this tool created.
    DeleteFile { path: String },
    /// Re-apply a DNS snapshot file written by `sys::dns_state`.
    RestoreDns { snapshot: String },
    /// Stop (if running) and delete a service this tool created.
    DeleteService { name: String },
    /// Remove a value we added to the registry.
    DeleteRegValue {
        root: String,
        path: String,
        name: String,
    },
    /// Kill a process we started (pid + image path are cross-checked first).
    KillProcess { pid: u32, exe: String },
    /// Nothing to undo, but worth remembering.
    Note { component: String, text: String },
}

/// External effects used when undoing journal entries. Mockable.
pub trait UndoExecutor {
    fn restore_file(&self, path: &Path, backup: &Path) -> Result<()>;
    fn delete_file(&self, path: &Path) -> Result<()>;
    fn restore_dns(&self, snapshot: &Path) -> Result<()>;
    fn delete_service(&self, name: &str) -> Result<()>;
    fn delete_reg_value(&self, root: &str, path: &str, name: &str) -> Result<()>;
    fn kill_process(&self, pid: u32, exe: &str) -> Result<()>;
    fn note(&self, component: &str, text: &str) -> Result<()>;
}

pub fn apply_undo(undo: &Undo, ex: &dyn UndoExecutor) -> Result<()> {
    match undo {
        Undo::None => Ok(()),
        Undo::RestoreFile { path, backup } => {
            ex.restore_file(Path::new(path), Path::new(backup))
        }
        Undo::DeleteFile { path } => ex.delete_file(Path::new(path)),
        Undo::RestoreDns { snapshot } => ex.restore_dns(Path::new(snapshot)),
        Undo::DeleteService { name } => ex.delete_service(name),
        Undo::DeleteRegValue { root, path, name } => ex.delete_reg_value(root, path, name),
        Undo::KillProcess { pid, exe } => ex.kill_process(*pid, exe),
        Undo::Note { component, text } => ex.note(component, text),
    }
}

/// One journal line.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    /// Unix seconds.
    pub ts: u64,
    /// Monotonic-ish sequence inside the file; assigned by [`Journal::append`].
    #[serde(default)]
    pub seq: u64,
    pub tx: String,
    pub component: String,
    pub phase: Phase,
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<serde_json::Value>,
    #[serde(default)]
    pub undo: Undo,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Record {
    pub fn is_terminal(&self) -> bool {
        self.status == Status::Ok
            && match self.phase {
                Phase::Commit => self.action == ACTION_COMMIT,
                Phase::Rollback => self.action == ACTION_ROLLBACK_DONE,
                _ => false,
            }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum TxStatus {
    Pending,
    Committed,
    RolledBack,
}

/// Aggregated view of one transaction in the journal.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxState {
    pub tx: String,
    pub component: String,
    pub started: u64,
    pub last: u64,
    pub records: usize,
    pub status: TxStatus,
}

/// Append-only journal in a data directory.
pub struct Journal {
    dir: PathBuf,
}

static TX_SEQ: AtomicU64 = AtomicU64::new(0);

impl Journal {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn path(&self) -> PathBuf {
        self.dir.join(JOURNAL_FILE)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Unique transaction id: time + pid + counter. No extra dependency.
    pub fn new_tx_id(&self) -> String {
        let n = TX_SEQ.fetch_add(1, Ordering::Relaxed);
        format!("{}-{}-{}", crate::util::now_unix(), std::process::id(), n)
    }

    /// Append one record, assigning `seq`, rotating the file when huge.
    pub fn append(&self, mut rec: Record) -> Result<Record> {
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("не удалось создать {}", self.dir.display()))?;
        let path = self.path();
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() > JOURNAL_MAX_BYTES {
                let _ = std::fs::rename(&path, self.dir.join(format!("{JOURNAL_FILE}.1")));
            }
        }
        let seq = self.read_records().map(|v| v.last().map(|r| r.seq + 1).unwrap_or(1)).unwrap_or(1);
        rec.seq = seq;
        let mut line = serde_json::to_string(&rec)?;
        line.push('\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .with_context(|| format!("не удалось открыть журнал {}", path.display()))?;
        f.write_all(line.as_bytes())?;
        f.flush()?;
        // Cheap durability: journal drives recovery, it must survive a crash.
        let _ = f.sync_all();
        Ok(rec)
    }

    /// All readable records. A torn trailing line is ignored.
    pub fn read_records(&self) -> Result<Vec<Record>> {
        let Some(bytes) = fsx::try_read(&self.path())? else {
            return Ok(Vec::new());
        };
        let text = String::from_utf8_lossy(&bytes);
        let mut out = Vec::new();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            match serde_json::from_str::<Record>(line) {
                Ok(r) => out.push(r),
                Err(_) => {
                    // Only the last line may be torn by a crash; ignore it.
                    if i + 1 != lines.len() {
                        crate::logger::info(format!(
                            "journal: пропущена битая строка {}",
                            i + 1
                        ));
                    }
                }
            }
        }
        Ok(out)
    }

    pub fn tx_records(&self, tx: &str) -> Result<Vec<Record>> {
        Ok(self
            .read_records()?
            .into_iter()
            .filter(|r| r.tx == tx)
            .collect())
    }

    /// Transactions and their state, oldest first.
    pub fn states(&self) -> Result<Vec<TxState>> {
        let mut out: Vec<TxState> = Vec::new();
        for rec in self.read_records()? {
            match out.iter_mut().find(|s| s.tx == rec.tx) {
                Some(st) => {
                    st.last = rec.ts;
                    st.records += 1;
                    if rec.is_terminal() {
                        st.status = if rec.phase == Phase::Commit {
                            TxStatus::Committed
                        } else {
                            TxStatus::RolledBack
                        };
                    }
                }
                None => out.push(TxState {
                    tx: rec.tx.clone(),
                    component: rec.component.clone(),
                    started: rec.ts,
                    last: rec.ts,
                    records: 1,
                    status: if rec.is_terminal() {
                        if rec.phase == Phase::Commit {
                            TxStatus::Committed
                        } else {
                            TxStatus::RolledBack
                        }
                    } else {
                        TxStatus::Pending
                    },
                }),
            }
        }
        Ok(out)
    }

    /// Interrupted transactions (no commit and no completed rollback).
    pub fn pending(&self) -> Result<Vec<TxState>> {
        Ok(self
            .states()?
            .into_iter()
            .filter(|s| s.status == TxStatus::Pending)
            .collect())
    }
}

/// Records a one-shot action that has no separate rollback (deleting our own
/// service, killing our own process).
///
/// Writes an `apply` record and a terminal `commit` record, so startup recovery
/// never mistakes a finished action for an interrupted transaction.
pub fn note_action(
    journal: &Journal,
    component: &str,
    action: &str,
    detail: serde_json::Value,
    undo: Undo,
) -> Result<()> {
    let tx = journal.new_tx_id();
    let make = |phase: Phase, action: String, undo: Undo| Record {
        ts: crate::util::now_unix(),
        seq: 0,
        tx: tx.clone(),
        component: component.to_string(),
        phase,
        action,
        before: None,
        after: Some(detail.clone()),
        undo,
        status: Status::Ok,
        error: None,
    };
    journal.append(make(Phase::Apply, action.to_string(), undo))?;
    journal.append(make(Phase::Commit, ACTION_COMMIT.to_string(), Undo::None))?;
    Ok(())
}

/// Result of a startup recovery pass.
#[derive(Debug, Default, Clone)]
pub struct RecoveryReport {
    /// Transactions found without a terminal record.
    pub pending: Vec<String>,
    /// Transactions fully undone.
    pub recovered: Vec<String>,
    /// Transactions that could not be undone: (tx, reason).
    pub failed: Vec<(String, String)>,
    /// Human-readable log lines for the UI/log.
    pub log: Vec<String>,
}

impl RecoveryReport {
    pub fn is_clean(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn ok(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Undo every interrupted transaction. Idempotent: safe to call on each start.
pub fn recover_pending_with(journal: &Journal, ex: &dyn UndoExecutor) -> Result<RecoveryReport> {
    let mut report = RecoveryReport::default();
    for st in journal.pending()? {
        report.pending.push(st.tx.clone());
        let records = journal.tx_records(&st.tx)?;
        let mut problems: Vec<String> = Vec::new();
        // Newest first: the last thing applied is the first thing to undo.
        for rec in records.iter().rev() {
            if rec.status != Status::Ok || rec.undo == Undo::None {
                continue;
            }
            if let Err(e) = apply_undo(&rec.undo, ex) {
                problems.push(format!("{}: {e:#}", rec.action));
            }
        }
        if problems.is_empty() {
            report.recovered.push(st.tx.clone());
            report.log.push(format!(
                "↩ незавершённое изменение «{}» отменено ({} действий)",
                st.component,
                records.len()
            ));
            // Terminal record: a second start must not undo it again.
            journal.append(Record {
                ts: crate::util::now_unix(),
                seq: 0,
                tx: st.tx.clone(),
                component: st.component.clone(),
                phase: Phase::Rollback,
                action: ACTION_ROLLBACK_DONE.to_string(),
                before: None,
                after: None,
                undo: Undo::None,
                status: Status::Ok,
                error: None,
            })?;
        } else {
            let reason = problems.join("; ");
            report
                .failed
                .push((st.tx.clone(), reason.clone()));
            report.log.push(format!(
                "⚠ не удалось отменить «{}»: {reason}",
                st.component
            ));
            journal.append(Record {
                ts: crate::util::now_unix(),
                seq: 0,
                tx: st.tx,
                component: st.component,
                phase: Phase::Rollback,
                action: "tx_rollback_failed".to_string(),
                before: None,
                after: None,
                undo: Undo::None,
                status: Status::Failed,
                error: Some(reason),
            })?;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(tx: &str, phase: Phase, action: &str, undo: Undo, status: Status) -> Record {
        Record {
            ts: crate::util::now_unix(),
            seq: 0,
            tx: tx.to_string(),
            component: "test".into(),
            phase,
            action: action.into(),
            before: None,
            after: None,
            undo,
            status,
            error: None,
        }
    }

    #[test]
    fn append_assigns_increasing_seq_and_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        j.append(rec("t1", Phase::Snapshot, "snap", Undo::None, Status::Ok))
            .unwrap();
        j.append(rec("t1", Phase::Apply, "do", Undo::None, Status::Ok))
            .unwrap();
        let all = j.read_records().unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[1].seq, 2);
        assert_eq!(all[0].phase, Phase::Snapshot);
    }

    #[test]
    fn torn_trailing_line_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        j.append(rec("t1", Phase::Apply, "do", Undo::None, Status::Ok))
            .unwrap();
        let mut f = OpenOptions::new().append(true).open(j.path()).unwrap();
        f.write_all(br#"{"ts":1,"tx":"t1","component":"c","phase":"app"#)
            .unwrap();
        let all = j.read_records().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn pending_only_until_terminal_record() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        j.append(rec("t1", Phase::Apply, "do", Undo::None, Status::Ok))
            .unwrap();
        assert_eq!(j.pending().unwrap().len(), 1);
        j.append(rec("t1", Phase::Commit, ACTION_COMMIT, Undo::None, Status::Ok))
            .unwrap();
        assert!(j.pending().unwrap().is_empty());
        assert_eq!(j.states().unwrap()[0].status, TxStatus::Committed);
    }

    #[test]
    fn failed_rollback_stays_pending() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        j.append(rec("t1", Phase::Apply, "do", Undo::None, Status::Ok))
            .unwrap();
        j.append(rec(
            "t1",
            Phase::Rollback,
            "tx_rollback_failed",
            Undo::None,
            Status::Failed,
        ))
        .unwrap();
        assert_eq!(j.pending().unwrap().len(), 1);
    }

    #[test]
    fn undo_json_is_tagged_and_stable() {
        let u = Undo::RestoreFile {
            path: r"C:\Windows\System32\drivers\etc\hosts".into(),
            backup: r"C:\tools\data\hosts.backup-1".into(),
        };
        let s = serde_json::to_string(&u).unwrap();
        assert!(s.contains("\"kind\":\"restore_file\""));
        let back: Undo = serde_json::from_str(&s).unwrap();
        assert_eq!(u, back);
    }

    #[test]
    fn recovery_undoes_in_reverse_order_once() {
        struct Ex {
            calls: std::sync::Mutex<Vec<String>>,
        }
        impl UndoExecutor for Ex {
            fn restore_file(&self, path: &Path, backup: &Path) -> Result<()> {
                self.calls.lock().unwrap().push(format!(
                    "restore {}<-{}",
                    path.display(),
                    backup.display()
                ));
                Ok(())
            }
            fn delete_file(&self, path: &Path) -> Result<()> {
                self.calls.lock().unwrap().push(format!("del {}", path.display()));
                Ok(())
            }
            fn restore_dns(&self, snapshot: &Path) -> Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("dns {}", snapshot.display()));
                Ok(())
            }
            fn delete_service(&self, name: &str) -> Result<()> {
                self.calls.lock().unwrap().push(format!("svc {name}"));
                Ok(())
            }
            fn delete_reg_value(&self, root: &str, path: &str, name: &str) -> Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("reg {root}\\{path}\\{name}"));
                Ok(())
            }
            fn kill_process(&self, pid: u32, exe: &str) -> Result<()> {
                self.calls.lock().unwrap().push(format!("kill {pid} {exe}"));
                Ok(())
            }
            fn note(&self, component: &str, text: &str) -> Result<()> {
                self.calls
                    .lock()
                    .unwrap()
                    .push(format!("note {component}: {text}"));
                Ok(())
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        let ex = Ex {
            calls: std::sync::Mutex::new(Vec::new()),
        };

        j.append(rec(
            "t1",
            Phase::Snapshot,
            "snap",
            Undo::RestoreFile {
                path: "H".into(),
                backup: "H.bak".into(),
            },
            Status::Ok,
        ))
        .unwrap();
        j.append(rec(
            "t1",
            Phase::Apply,
            "svc",
            Undo::DeleteService {
                name: "zapret".into(),
            },
            Status::Ok,
        ))
        .unwrap();

        let rep = recover_pending_with(&j, &ex).unwrap();
        assert_eq!(rep.recovered, vec!["t1".to_string()]);
        assert_eq!(
            ex.calls.lock().unwrap().clone(),
            vec![
                "svc zapret".to_string(),
                "restore H<-H.bak".to_string()
            ]
        );

        // Second pass: the transaction has a terminal record now.
        ex.calls.lock().unwrap().clear();
        let rep2 = recover_pending_with(&j, &ex).unwrap();
        assert!(rep2.pending.is_empty());
        assert!(ex.calls.lock().unwrap().is_empty());
    }
}
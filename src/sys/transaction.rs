//! Transaction engine: Snapshot → Prepare → Apply → Verify → Commit.
//!
//! Every system change goes through a [`Step`]. The engine journals each phase
//! before and after running it, so an interrupted run is always recoverable:
//! whatever reached the journal can be undone from
//! [`super::journal::Undo`] data alone.
//!
//! Failure handling: the failing step *and* every already applied step are
//! rolled back in reverse order. If a rollback fails, the transaction keeps no
//! terminal record, so the next start retries it (`recover_pending_with`).
//!
//! All side effects live inside the steps, so tests use plain mocks and the
//! real machine is never touched.

use anyhow::Result;
use serde_json::Value;

use super::journal::{
    Journal, Phase, Record, Status, Undo, ACTION_COMMIT, ACTION_ROLLBACK_DONE,
};

/// Context handed to a step. Steps use it to journal extra detail and to learn
/// their transaction id (useful in log lines).
pub struct TxHandle<'a> {
    pub tx: String,
    pub journal: &'a Journal,
}

impl<'a> TxHandle<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn record(
        &self,
        component: &str,
        phase: Phase,
        action: &str,
        status: Status,
        undo: Undo,
        before: Option<Value>,
        after: Option<Value>,
        error: Option<String>,
    ) -> Result<()> {
        self.journal.append(Record {
            ts: crate::util::now_unix(),
            seq: 0,
            tx: self.tx.clone(),
            component: component.to_string(),
            phase,
            action: action.to_string(),
            before,
            after,
            undo,
            status,
            error,
        })?;
        Ok(())
    }

    /// Successful phase record.
    pub fn ok(
        &self,
        component: &str,
        phase: Phase,
        action: &str,
        undo: Undo,
        before: Option<Value>,
        after: Option<Value>,
    ) -> Result<()> {
        self.record(component, phase, action, Status::Ok, undo, before, after, None)
    }

    /// Extra detail inside a phase (e.g. one line per network interface).
    /// Carries no undo of its own: undo is recorded once, at snapshot time.
    pub fn info(
        &self,
        component: &str,
        action: &str,
        before: Option<Value>,
        after: Option<Value>,
    ) -> Result<()> {
        self.ok(component, Phase::Apply, action, Undo::None, before, after)
    }
}

/// One atomic-ish unit of system change.
pub trait Step {
    /// Component name for the journal ("hosts", "dns", "zapret").
    fn component(&self) -> &str;
    /// Short action name for the journal.
    fn action(&self) -> &'static str;

    /// Read the current state and return how to undo the upcoming change.
    fn snapshot(&mut self, _h: &TxHandle) -> Result<Undo> {
        Ok(Undo::None)
    }
    /// Everything that can fail before the visible change (downloads, temp files).
    fn prepare(&mut self, _h: &TxHandle) -> Result<()> {
        Ok(())
    }
    /// The visible change.
    fn apply(&mut self, _h: &TxHandle) -> Result<()>;
    /// Read the state back and fail if it does not match the intent.
    fn verify(&mut self, _h: &TxHandle) -> Result<()> {
        Ok(())
    }
    /// Drop temporary artefacts; the change stays.
    fn commit(&mut self, _h: &TxHandle) -> Result<()> {
        Ok(())
    }
    /// Best-effort return to the snapshot state.
    fn rollback(&mut self, _h: &TxHandle) -> Result<()>;
    /// Human-readable log lines produced during the run.
    fn take_log(&mut self) -> Vec<String> {
        Vec::new()
    }
}

#[derive(Debug, Clone)]
pub struct TxResult {
    pub tx: String,
    pub committed: bool,
    pub error: Option<String>,
    /// Log lines from the steps, in execution order.
    pub messages: Vec<String>,
    pub rollback_errors: Vec<String>,
}

impl TxResult {
    fn new(tx: String) -> Self {
        Self {
            tx,
            committed: false,
            error: None,
            messages: Vec::new(),
            rollback_errors: Vec::new(),
        }
    }

    /// Turn a failed transaction into an `Err` for `?`-style callers.
    pub fn into_result(self) -> Result<Self> {
        match (&self.committed, &self.error) {
            (true, _) => Ok(self),
            (false, Some(e)) => {
                let mut msg = e.clone();
                if !self.rollback_errors.is_empty() {
                    msg.push_str("; откат: ");
                    msg.push_str(&self.rollback_errors.join("; "));
                }
                Err(anyhow::anyhow!("{msg}"))
            }
            (false, None) => Err(anyhow::anyhow!("транзакция не завершена")),
        }
    }
}

/// Run a transaction. Never panics; inspect [`TxResult::committed`].
pub fn run(component: &str, journal: &Journal, mut steps: Vec<Box<dyn Step>>) -> TxResult {
    let tx = journal.new_tx_id();
    let mut res = TxResult::new(tx.clone());
    let mut applied: Vec<usize> = Vec::new();

    let outcome = execute(
        component,
        journal,
        &tx,
        steps.as_mut_slice(),
        &mut applied,
    );

    if let Err(e) = outcome {
        res.error = Some(format!("{e:#}"));
        rollback(journal, &mut res, &tx, steps.as_mut_slice(), &applied);
    } else {
        res.committed = true;
    }

    for s in steps.iter_mut() {
        res.messages.extend(s.take_log());
    }
    res
}

fn execute(
    component: &str,
    journal: &Journal,
    tx: &str,
    steps: &mut [Box<dyn Step>],
    applied: &mut Vec<usize>,
) -> Result<()> {
    let h = TxHandle {
        tx: tx.to_string(),
        journal,
    };

    // ── Snapshot ──────────────────────────────────────────────────────────
    for step in steps.iter_mut() {
        let comp = step.component().to_string();
        let act = step.action();
        match step.snapshot(&h) {
            Ok(undo) => {
                h.ok(&comp, Phase::Snapshot, act, undo, None, None)?;
            }
            Err(e) => {
                h.record(
                    &comp,
                    Phase::Snapshot,
                    act,
                    Status::Failed,
                    Undo::None,
                    None,
                    None,
                    Some(format!("{e:#}")),
                )?;
                return Err(e);
            }
        }
    }

    // ── Prepare ───────────────────────────────────────────────────────────
    for step in steps.iter_mut() {
        let comp = step.component().to_string();
        let act = step.action();
        match step.prepare(&h) {
            Ok(()) => h.ok(&comp, Phase::Prepare, act, Undo::None, None, None)?,
            Err(e) => {
                h.record(
                    &comp,
                    Phase::Prepare,
                    act,
                    Status::Failed,
                    Undo::None,
                    None,
                    None,
                    Some(format!("{e:#}")),
                )?;
                return Err(e);
            }
        }
    }

    // ── Apply ─────────────────────────────────────────────────────────────
    for (i, step) in steps.iter_mut().enumerate() {
        let comp = step.component().to_string();
        let act = step.action();
        // Registered before the call: a half-applied step must be rolled back.
        applied.push(i);
        match step.apply(&h) {
            Ok(()) => h.ok(&comp, Phase::Apply, act, Undo::None, None, None)?,
            Err(e) => {
                h.record(
                    &comp,
                    Phase::Apply,
                    act,
                    Status::Failed,
                    Undo::None,
                    None,
                    None,
                    Some(format!("{e:#}")),
                )?;
                return Err(e);
            }
        }
    }

    // ── Verify ────────────────────────────────────────────────────────────
    for step in steps.iter_mut() {
        let comp = step.component().to_string();
        let act = step.action();
        match step.verify(&h) {
            Ok(()) => h.ok(&comp, Phase::Verify, act, Undo::None, None, None)?,
            Err(e) => {
                h.record(
                    &comp,
                    Phase::Verify,
                    act,
                    Status::Failed,
                    Undo::None,
                    None,
                    None,
                    Some(format!("{e:#}")),
                )?;
                return Err(e);
            }
        }
    }

    // ── Commit ────────────────────────────────────────────────────────────
    for step in steps.iter_mut() {
        let comp = step.component().to_string();
        let act = step.action();
        step.commit(&h)?;
        h.ok(&comp, Phase::Commit, act, Undo::None, None, None)?;
    }
    h.ok(component, Phase::Commit, ACTION_COMMIT, Undo::None, None, None)?;
    Ok(())
}

fn rollback(
    journal: &Journal,
    res: &mut TxResult,
    tx: &str,
    steps: &mut [Box<dyn Step>],
    applied: &[usize],
) {
    let h = TxHandle {
        tx: tx.to_string(),
        journal,
    };
    let mut all_ok = true;
    for i in applied.iter().rev() {
        let comp = steps[*i].component().to_string();
        let act = steps[*i].action();
        match steps[*i].rollback(&h) {
            Ok(()) => {
                let _ = h.ok(&comp, Phase::Rollback, act, Undo::None, None, None);
            }
            Err(e) => {
                all_ok = false;
                let msg = format!("{comp}/{act}: {e:#}");
                res.rollback_errors.push(msg.clone());
                let _ = h.record(
                    &comp,
                    Phase::Rollback,
                    act,
                    Status::Failed,
                    Undo::None,
                    None,
                    None,
                    Some(msg),
                );
            }
        }
    }
    // A failed rollback stays pending on purpose: startup recovery retries it.
    let terminal = if all_ok {
        ACTION_ROLLBACK_DONE
    } else {
        "tx_rollback_failed"
    };
    let status = if all_ok { Status::Ok } else { Status::Failed };
    let _ = h.record(
        "transaction",
        Phase::Rollback,
        terminal,
        status,
        Undo::None,
        None,
        None,
        if all_ok {
            None
        } else {
            Some(res.rollback_errors.join("; "))
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::journal::{recover_pending_with, RecoveryReport, UndoExecutor};
    use std::path::Path;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct Log(Arc<Mutex<Vec<String>>>);

    impl Log {
        fn push(&self, s: impl Into<String>) {
            self.0.lock().unwrap().push(s.into());
        }
        fn lines(&self) -> Vec<String> {
            self.0.lock().unwrap().clone()
        }
    }

    /// A step that logs its phases and can be told to fail at one of them.
    struct MockStep {
        name: &'static str,
        log: Log,
        fail_at: Option<&'static str>,
        undo: Undo,
        messages: Vec<String>,
    }

    impl MockStep {
        fn new(name: &'static str, log: &Log) -> Self {
            Self {
                name,
                log: log.clone(),
                fail_at: None,
                undo: Undo::None,
                messages: Vec::new(),
            }
        }

        fn failing(name: &'static str, log: &Log, at: &'static str) -> Self {
            Self {
                fail_at: Some(at),
                ..Self::new(name, log)
            }
        }

        fn with_undo(mut self, undo: Undo) -> Self {
            self.undo = undo;
            self
        }

        fn check(&self, phase: &'static str) -> Result<()> {
            self.log.push(format!("{}:{phase}", self.name));
            if self.fail_at == Some(phase) {
                anyhow::bail!("{} failed at {phase}", self.name);
            }
            Ok(())
        }
    }

    impl Step for MockStep {
        fn component(&self) -> &str {
            self.name
        }
        fn action(&self) -> &'static str {
            "mock"
        }
        fn snapshot(&mut self, _h: &TxHandle) -> Result<Undo> {
            self.check("snapshot")?;
            self.messages.push(format!("{} snapshot", self.name));
            Ok(self.undo.clone())
        }
        fn prepare(&mut self, _h: &TxHandle) -> Result<()> {
            self.check("prepare")
        }
        fn apply(&mut self, _h: &TxHandle) -> Result<()> {
            self.check("apply")
        }
        fn verify(&mut self, _h: &TxHandle) -> Result<()> {
            self.check("verify")
        }
        fn commit(&mut self, _h: &TxHandle) -> Result<()> {
            self.check("commit")
        }
        fn rollback(&mut self, _h: &TxHandle) -> Result<()> {
            self.check("rollback")
        }
        fn take_log(&mut self) -> Vec<String> {
            std::mem::take(&mut self.messages)
        }
    }

    #[test]
    fn happy_path_runs_all_phases_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        let log = Log::default();
        let res = run(
            "test",
            &j,
            vec![
                Box::new(MockStep::new("a", &log)),
                Box::new(MockStep::new("b", &log)),
            ],
        );
        assert!(res.committed, "{:?}", res.error);
        assert_eq!(
            log.lines(),
            vec![
                "a:snapshot",
                "b:snapshot",
                "a:prepare",
                "b:prepare",
                "a:apply",
                "b:apply",
                "a:verify",
                "b:verify",
                "a:commit",
                "b:commit",
            ]
        );
        assert_eq!(res.messages.len(), 2);
        assert!(j.pending().unwrap().is_empty());
    }

    #[test]
    fn failure_mid_apply_rolls_back_applied_steps_in_reverse() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        let log = Log::default();
        let res = run(
            "test",
            &j,
            vec![
                Box::new(MockStep::new("a", &log)),
                Box::new(MockStep::failing("b", &log, "apply")),
            ],
        );
        assert!(!res.committed);
        assert!(res.error.as_deref().unwrap().contains("b failed at apply"));
        let lines = log.lines();
        assert_eq!(
            lines.iter().rev().take(2).cloned().collect::<Vec<_>>(),
            vec!["a:rollback".to_string(), "b:rollback".to_string()]
        );
        assert!(j.pending().unwrap().is_empty(), "rollback completed -> no retry");
    }

    #[test]
    fn failure_at_each_phase_is_recoverable() {
        for phase in ["snapshot", "prepare", "apply", "verify", "commit"] {
            let dir = tempfile::tempdir().unwrap();
            let j = Journal::new(dir.path());
            let log = Log::default();
            let res = run(
                "test",
                &j,
                vec![Box::new(MockStep::failing("x", &log, phase))],
            );
            assert!(!res.committed, "phase {phase} must fail the transaction");
            assert!(
                j.pending().unwrap().is_empty(),
                "phase {phase}: rollback must leave a terminal record"
            );
        }
    }

    #[test]
    fn failed_rollback_stays_pending_for_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        let log = Log::default();
        struct BadRollback(MockStep);
        impl Step for BadRollback {
            fn component(&self) -> &str {
                self.0.component()
            }
            fn action(&self) -> &'static str {
                "mock"
            }
            fn apply(&mut self, _h: &TxHandle) -> Result<()> {
                Ok(())
            }
            fn rollback(&mut self, _h: &TxHandle) -> Result<()> {
                anyhow::bail!("cannot undo")
            }
        }
        let steps: Vec<Box<dyn Step>> = vec![
            Box::new(BadRollback(MockStep::new("bad", &log))),
            Box::new(MockStep::failing("boom", &log, "verify")),
        ];
        let res = run("test", &j, steps);
        assert!(!res.committed);
        assert_eq!(res.rollback_errors.len(), 1);
        assert_eq!(j.pending().unwrap().len(), 1);
    }

    #[test]
    fn journal_has_terminal_commit_record() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        let log = Log::default();
        let res = run("test", &j, vec![Box::new(MockStep::new("a", &log))]);
        assert!(res.committed);
        let recs = j.tx_records(&res.tx).unwrap();
        let last = recs.last().unwrap();
        assert_eq!(last.phase, Phase::Commit);
        assert_eq!(last.action, ACTION_COMMIT);
        assert!(last.is_terminal());
    }

    #[test]
    fn snapshot_undo_reaches_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        let log = Log::default();
        let undo = Undo::RestoreFile {
            path: "H".into(),
            backup: "H.bak".into(),
        };
        let res = run(
            "test",
            &j,
            vec![Box::new(MockStep::new("a", &log).with_undo(undo.clone()))],
        );
        assert!(res.committed);
        let recs = j.tx_records(&res.tx).unwrap();
        assert_eq!(recs[0].undo, undo);
    }

    /// Simulates a crash at each phase: the journal is written up to that
    /// phase, then a fresh process calls startup recovery.
    #[test]
    fn recovery_after_interruption_at_every_phase() {
        struct CountingUndo {
            restored: Mutex<usize>,
        }
        impl UndoExecutor for CountingUndo {
            fn restore_file(&self, _p: &Path, _b: &Path) -> Result<()> {
                *self.restored.lock().unwrap() += 1;
                Ok(())
            }
            fn delete_file(&self, _p: &Path) -> Result<()> {
                Ok(())
            }
            fn restore_dns(&self, _p: &Path) -> Result<()> {
                Ok(())
            }
            fn delete_service(&self, _n: &str) -> Result<()> {
                Ok(())
            }
            fn delete_reg_value(&self, _r: &str, _p: &str, _n: &str) -> Result<()> {
                Ok(())
            }
            fn kill_process(&self, _pid: u32, _exe: &str) -> Result<()> {
                Ok(())
            }
            fn note(&self, _c: &str, _t: &str) -> Result<()> {
                Ok(())
            }
        }

        for (idx, phase) in [
            Phase::Snapshot,
            Phase::Prepare,
            Phase::Apply,
            Phase::Verify,
            Phase::Commit,
        ]
        .iter()
        .enumerate()
        {
            let dir = tempfile::tempdir().unwrap();
            let j = Journal::new(dir.path());
            let tx = "tx-crash";
            // Records a real engine would have written before dying at `phase`.
            for p in [
                Phase::Snapshot,
                Phase::Prepare,
                Phase::Apply,
                Phase::Verify,
                Phase::Commit,
            ]
            .iter()
            .take(idx + 1)
            {
                let undo = if *p == Phase::Snapshot {
                    Undo::RestoreFile {
                        path: "H".into(),
                        backup: "H.bak".into(),
                    }
                } else {
                    Undo::None
                };
                j.append(Record {
                    ts: 1,
                    seq: 0,
                    tx: tx.into(),
                    component: "hosts".into(),
                    phase: *p,
                    action: p.as_str().to_string(),
                    before: None,
                    after: None,
                    undo,
                    status: Status::Ok,
                    error: None,
                })
                .unwrap();
            }
            // Died before the terminal record: recovery must undo once.
            let ex = CountingUndo {
                restored: Mutex::new(0),
            };
            let rep: RecoveryReport = recover_pending_with(&j, &ex).unwrap();
            assert_eq!(rep.pending.len(), 1, "phase {phase:?}");
            assert_eq!(rep.recovered.len(), 1, "phase {phase:?}");
            assert_eq!(*ex.restored.lock().unwrap(), 1, "phase {phase:?}");
            assert!(j.pending().unwrap().is_empty(), "phase {phase:?}");
        }
    }
}
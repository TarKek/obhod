//! hosts: backup and an optional ad/tracker block.
//!
//! The file is owned by the system, so every step is defensive:
//! * the current file is read first — if that fails the step **aborts** and
//!   nothing is written (never "only our block" instead of the user's file);
//! * a timestamped backup is written and verified before the change;
//! * changes go through `sys::transaction`, with the undo record pointing at
//!   that backup, so an interrupted run is rolled back on the next start;
//! * only our marked block is ever added or removed.

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::modules::Ctx;
use crate::sys::fsx::{self, FsIo, RealFs};
use crate::sys::hosts_file::{self, Outcome};
use crate::sys::journal::{Journal, Phase, Status, Undo};
use crate::sys::transaction::{self, Step, TxHandle};
use crate::util;

const ADS_SRC: &str = "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts";

/// `C:\Windows\System32\drivers\etc\hosts` (honours `SystemRoot`).
pub fn hosts_path() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into()))
        .join("System32")
        .join("drivers")
        .join("etc")
        .join("hosts")
}

pub fn run(ctx: &Ctx) -> Result<()> {
    let path = hosts_path();

    // 1. Read first. An unreadable hosts file stops everything: writing our
    //    block over a file we could not read would destroy the user's entries.
    let text = hosts_file::read(&RealFs, &path).map_err(|e| {
        ctx.log(format!("⚠ hosts не изменён: {e:#}"));
        e
    })?;
    ctx.log(format!(
        "hosts: {} строк, наш блок: {}",
        text.lines.len(),
        if text.has_block() { "есть" } else { "нет" }
    ));

    // 2. Backup-only mode still makes a backup (documented behaviour).
    if !ctx.opts.hosts_block_ads {
        let backup = hosts_file::backup_path(&RealFs, &ctx.data, &crate::logger::stamp());
        if let Some(dir) = backup.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        fsx::backup_copy(&RealFs, &path, &backup)?;
        ctx.log(format!("✓ Резервная копия hosts: {}", backup.display()));
        ctx.log("hosts не изменялся (выбран режим «только бэкап»).");
        return Ok(());
    }

    if !ctx.admin {
        ctx.log("⚠ Для правки hosts нужны права администратора — шаг пропущен, файл не тронут.");
        return Ok(());
    }

    // 3. Fetch the list before touching the file.
    let entries = match fetch_entries() {
        Ok(e) => e,
        Err(e) => {
            ctx.log(format!("⚠ список рекламы не получен, hosts не изменён: {e:#}"));
            return Err(e);
        }
    };
    ctx.log(format!("Записей для блок-листа: {}", entries.len()));

    // 4. Journaled, verified write.
    let journal = Journal::new(ctx.data.clone());
    let step = HostsStep::new(RealFs, ctx.data.clone(), path, Mode::Write(entries));
    let res = transaction::run("hosts", &journal, vec![Box::new(step)]);
    for m in &res.messages {
        ctx.log(m.clone());
    }
    res.into_result()?;
    let _ = util::run_checked("ipconfig", &["/flushdns"]);
    ctx.log("Кэш DNS очищен.");
    Ok(())
}

/// Removes only our block. Returns `true` when the file actually changed.
pub fn remove_block(ctx: &Ctx) -> Result<bool> {
    let path = hosts_path();
    let text = hosts_file::read(&RealFs, &path).map_err(|e| {
        ctx.log(format!("⚠ hosts не изменён: {e:#}"));
        e
    })?;
    if !text.has_block() {
        ctx.log("• Блока рекламы в hosts нет — пропускаю.");
        return Ok(false);
    }
    if !ctx.admin {
        ctx.log("⚠ Чтобы убрать блок из hosts, нужны права администратора — пропущено.");
        return Ok(false);
    }

    let journal = Journal::new(ctx.data.clone());
    let step = HostsStep::new(RealFs, ctx.data.clone(), path, Mode::Remove);
    let res = transaction::run("hosts", &journal, vec![Box::new(step)]);
    for m in &res.messages {
        ctx.log(m.clone());
    }
    if res.committed {
        let _ = util::run_checked("ipconfig", &["/flushdns"]);
    }
    res.into_result()?;
    Ok(true)
}

fn fetch_entries() -> Result<Vec<String>> {
    let client = util::http_client()?;
    let raw = util::get_text(&client, ADS_SRC).context("не удалось скачать блок-лист")?;
    let entries = hosts_file::entries_from_list(&raw);
    if entries.is_empty() {
        anyhow::bail!("блок-лист пуст — нечего записывать");
    }
    Ok(entries)
}

#[derive(Clone, Debug)]
enum Mode {
    Write(Vec<String>),
    Remove,
}

/// One transaction step: snapshot → backup → atomic write → verify.
///
/// Generic over [`FsIo`] so tests run it against an in-memory filesystem while
/// production uses [`RealFs`].
struct HostsStep<I: FsIo> {
    io: I,
    dir: PathBuf,
    path: PathBuf,
    mode: Mode,
    backup: Option<PathBuf>,
    logs: Vec<String>,
    applied: bool,
}

impl<I: FsIo> HostsStep<I> {
    fn new(io: I, dir: PathBuf, path: PathBuf, mode: Mode) -> Self {
        Self {
            io,
            dir,
            path,
            mode,
            backup: None,
            logs: Vec::new(),
            applied: false,
        }
    }

    fn action_name(&self) -> &'static str {
        match self.mode {
            Mode::Write(_) => "hosts-ads-block",
            Mode::Remove => "hosts-ads-unblock",
        }
    }
}

impl<I: FsIo> Step for HostsStep<I> {
    fn component(&self) -> &str {
        "hosts"
    }

    fn action(&self) -> &'static str {
        self.action_name()
    }

    fn snapshot(&mut self, _h: &TxHandle) -> Result<Undo> {
        // Fail here (before anything is written) if the file is unreadable.
        let text = hosts_file::read(&self.io, &self.path)?;
        self.logs.push(format!(
            "hosts: снимок {} строк, наш блок: {}",
            text.lines.len(),
            if text.has_block() { "есть" } else { "нет" }
        ));
        Ok(Undo::None)
    }

    fn prepare(&mut self, h: &TxHandle) -> Result<()> {
        // The backup path is decided now, so the undo record can name it before
        // the file is touched (no window where a crash loses the undo).
        let backup = hosts_file::backup_path(&self.io, &self.dir, &crate::logger::stamp());
        self.backup = Some(backup.clone());
        h.record(
            "hosts",
            Phase::Prepare,
            self.action_name(),
            Status::Ok,
            Undo::RestoreFile {
                path: self.path.display().to_string(),
                backup: backup.display().to_string(),
            },
            None,
            Some(serde_json::json!({ "backup": backup.display().to_string() })),
            None,
        )?;
        Ok(())
    }

    fn apply(&mut self, h: &TxHandle) -> Result<()> {
        let backup = self
            .backup
            .clone()
            .ok_or_else(|| anyhow::anyhow!("нет пути резервной копии"))?;
        let outcome: Outcome = match &self.mode {
            Mode::Write(entries) => {
                hosts_file::apply_block_to(&self.io, &self.path, &backup, entries)?
            }
            Mode::Remove => hosts_file::remove_block_to(&self.io, &self.path, &backup)?,
        };
        self.applied = outcome.changed;
        let msg = if outcome.changed {
            match &self.mode {
                Mode::Write(entries) => format!(
                    "✓ hosts обновлён: блок из {} записей, строки пользователя сохранены",
                    entries.len()
                ),
                Mode::Remove => "✓ Блок убран из hosts, остальные записи на месте".to_string(),
            }
        } else {
            "• hosts уже в нужном состоянии — запись не потребовалась".to_string()
        };
        self.logs.push(msg);
        if let Some(b) = &outcome.backup {
            self.logs.push(format!("✓ Резервная копия hosts: {}", b.display()));
        }
        h.record(
            "hosts",
            Phase::Apply,
            self.action_name(),
            Status::Ok,
            Undo::None,
            Some(serde_json::json!({ "hash": outcome.before_hash, "entries": outcome.entries })),
            Some(serde_json::json!({ "hash": outcome.after_hash, "changed": outcome.changed })),
            None,
        )?;
        Ok(())
    }

    fn verify(&mut self, _h: &TxHandle) -> Result<()> {
        match &self.mode {
            Mode::Write(entries) => hosts_file::verify_block(&self.io, &self.path, entries)?,
            Mode::Remove => hosts_file::verify_no_block(&self.io, &self.path)?,
        }
        self.logs.push("✓ hosts проверен после записи".into());
        Ok(())
    }

    fn rollback(&mut self, _h: &TxHandle) -> Result<()> {
        let Some(backup) = &self.backup else {
            return Ok(());
        };
        if !self.applied || !self.io.exists(backup) {
            return Ok(());
        }
        let bytes = self
            .io
            .read(backup)
            .with_context(|| format!("резервная копия {} не читается", backup.display()))?;
        self.io
            .write_atomic(&self.path, &bytes)
            .with_context(|| format!("не удалось вернуть {}", self.path.display()))?;
        self.logs
            .push(format!("↩ hosts возвращён из {}", backup.display()));
        Ok(())
    }

    fn take_log(&mut self) -> Vec<String> {
        std::mem::take(&mut self.logs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fsx::testing::MemFs;
    use crate::sys::hosts_file::HostsText;

    fn memfs() -> std::sync::Arc<MemFs> {
        std::sync::Arc::new(MemFs::new())
    }

    #[test]
    fn hosts_path_ends_with_the_system_file() {
        let p = hosts_path();
        assert!(p.ends_with(
            std::path::Path::new("System32")
                .join("drivers")
                .join("etc")
                .join("hosts")
        ));
    }

    /// End-to-end: transaction + journal + in-memory hosts file.
    #[test]
    fn step_writes_journals_and_verifies() {
        let dir = tempfile::tempdir().unwrap();
        let fs = memfs();
        let hosts = dir.path().join("hosts");
        fs.put(&hosts, "127.0.0.1 localhost\r\n");
        let journal = Journal::new(dir.path().join("data"));

        let step = HostsStep::new(
            fs.clone(),
            dir.path().join("data"),
            hosts.clone(),
            Mode::Write(vec!["0.0.0.0 ads.example".to_string()]),
        );
        let res = transaction::run("hosts", &journal, vec![Box::new(step)]);
        assert!(res.committed, "{:?}", res.error);
        assert!(res.messages.iter().any(|m| m.contains("✓ hosts обновлён")));

        let text = fs.text(&hosts).unwrap();
        assert!(text.contains(hosts_file::MARK_START));
        assert!(text.starts_with("127.0.0.1 localhost\r\n"));

        // Journal: undo points at a real backup of the previous content.
        let recs = journal.tx_records(&res.tx).unwrap();
        let undo = recs
            .iter()
            .find_map(|r| match &r.undo {
                Undo::RestoreFile { path, backup } => Some((path.clone(), backup.clone())),
                _ => None,
            })
            .expect("undo record");
        assert_eq!(undo.0, hosts.display().to_string());
        assert_eq!(
            fs.text(std::path::Path::new(&undo.1)).unwrap(),
            "127.0.0.1 localhost\r\n"
        );
        assert!(journal.pending().unwrap().is_empty());
    }

    #[test]
    fn unreadable_hosts_stops_the_step_before_any_write() {
        let dir = tempfile::tempdir().unwrap();
        let fs = memfs();
        let hosts = dir.path().join("hosts");
        fs.deny_read(&hosts);
        let journal = Journal::new(dir.path().join("data"));
        let step = HostsStep::new(
            fs.clone(),
            dir.path().join("data"),
            hosts.clone(),
            Mode::Write(vec!["0.0.0.0 ads.example".to_string()]),
        );
        let res = transaction::run("hosts", &journal, vec![Box::new(step)]);
        assert!(!res.committed);
        assert_eq!(fs.write_count(), 0);
        assert!(journal.pending().unwrap().is_empty(), "rollback left a terminal record");
        // A failed snapshot is journaled as failed, which is what recovery reads.
        let recs = journal.tx_records(&res.tx).unwrap();
        assert!(recs.iter().any(|r| r.phase == Phase::Snapshot && r.status == Status::Failed));
    }

    #[test]
    fn remove_mode_drops_only_our_block() {
        let dir = tempfile::tempdir().unwrap();
        let fs = memfs();
        let hosts = dir.path().join("hosts");
        fs.put(
            &hosts,
            format!(
                "127.0.0.1 localhost\n{}\n0.0.0.0 ads\n{}\n# после блока\n",
                hosts_file::MARK_START,
                hosts_file::MARK_END
            ),
        );
        let journal = Journal::new(dir.path().join("data"));
        let step = HostsStep::new(fs.clone(), dir.path().join("data"), hosts.clone(), Mode::Remove);
        let res = transaction::run("hosts", &journal, vec![Box::new(step)]);
        assert!(res.committed, "{:?}", res.error);
        assert_eq!(fs.text(&hosts).unwrap(), "127.0.0.1 localhost\n# после блока\n");
    }

    #[test]
    fn idempotent_write_does_not_touch_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let fs = memfs();
        let hosts = dir.path().join("hosts");
        fs.put(
            &hosts,
            format!(
                "x\n{}\n0.0.0.0 ads.example\n{}\n",
                hosts_file::MARK_START,
                hosts_file::MARK_END
            ),
        );
        let journal = Journal::new(dir.path().join("data"));
        let before = fs.write_count();
        let step = HostsStep::new(
            fs.clone(),
            dir.path().join("data"),
            hosts.clone(),
            Mode::Write(vec!["0.0.0.0 ads.example".to_string()]),
        );
        let res = transaction::run("hosts", &journal, vec![Box::new(step)]);
        assert!(res.committed);
        assert_eq!(fs.write_count(), before);
        assert!(res.messages.iter().any(|m| m.contains("уже в нужном состоянии")));
    }

    #[test]
    fn rollback_restores_the_previous_file() {
        let dir = tempfile::tempdir().unwrap();
        let fs = memfs();
        let hosts = dir.path().join("hosts");
        let original = "127.0.0.1 localhost\n";
        fs.put(&hosts, original);
        let journal = Journal::new(dir.path().join("data"));

        // Force a failure *after* apply by making verify fail: write a step that
        // is asked to write a block, then break the file behind its back.
        struct Broken<I: FsIo>(HostsStep<I>);
        impl<I: FsIo> Step for Broken<I> {
            fn component(&self) -> &str {
                "hosts"
            }
            fn action(&self) -> &'static str {
                "hosts-ads-block"
            }
            fn snapshot(&mut self, h: &TxHandle) -> Result<Undo> {
                self.0.snapshot(h)
            }
            fn prepare(&mut self, h: &TxHandle) -> Result<()> {
                self.0.prepare(h)
            }
            fn apply(&mut self, h: &TxHandle) -> Result<()> {
                self.0.apply(h)?;
                // Simulate something else breaking the file right after apply.
                let p = self.0.path.clone();
                self.0.io.write_atomic(&p, b"corrupted by something else\n")?;
                Ok(())
            }
            fn verify(&mut self, h: &TxHandle) -> Result<()> {
                self.0.verify(h)
            }
            fn rollback(&mut self, h: &TxHandle) -> Result<()> {
                self.0.rollback(h)
            }
            fn take_log(&mut self) -> Vec<String> {
                self.0.take_log()
            }
        }

        let step = HostsStep::new(
            fs.clone(),
            dir.path().join("data"),
            hosts.clone(),
            Mode::Write(vec!["0.0.0.0 ads.example".to_string()]),
        );
        let res = transaction::run("hosts", &journal, vec![Box::new(Broken(step))]);
        assert!(!res.committed);
        assert_eq!(
            fs.text(&hosts).unwrap(),
            original,
            "rollback must restore the original file"
        );
        assert!(journal.pending().unwrap().is_empty());
    }

    #[test]
    fn parse_helper_is_reused_for_the_module() {
        // Sanity: the module and the file layer agree on the block format.
        let t = HostsText::parse(
            format!("{}\n0.0.0.0 ads.example\n{}\n", hosts_file::MARK_START, hosts_file::MARK_END)
                .as_bytes(),
        )
        .unwrap();
        assert!(t.has_block());
        assert!(t.user_lines().unwrap().is_empty());
    }
}
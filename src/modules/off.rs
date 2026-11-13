//! "Выключить и вернуть как было".
//!
//! Ownership policy — only what this tool created is removed:
//!
//! | Ресурс | Удаляем | Проверка «наше» |
//! |---|---|---|
//! | служба `zapret` | `sc stop` + `sc delete` | запись в `data\ownership.json`, маркер `obhod-preset` в реестре службы или `ImagePath` внутри нашей папки |
//! | процессы `winws.exe`, `TgWsProxy.exe` | `taskkill /PID` только для записанного pid (у `TgWsProxy` ещё и точный путь из нашего `Run`-значения) | pid + путь образа совпадают с записью в `ownership.json` |
//! | блок в `hosts` | только наш размеченный блок | маркеры `# >>> obhod-ads >>>` |
//! | DNS | снимок `dns-snapshot.json` (точные списки) | файл снимка с `complete: true` |
//! | автозапуск | значение `Run`, указывающее внутрь нашей папки | путь в значении |
//!
//! `taskkill /IM` не используется никогда: чужие `winws.exe` и `TgWsProxy.exe`
//! (например, из `C:\zapret` или с рабочего стола) остаются работать.
//!
//! Every step reports its own result, failed steps can be retried with
//! [`retry`], and each change is written to the journal. Hosts and DNS are
//! fully undoable and go through `sys::transaction`; deleting a service or
//! killing our own process is terminal by nature and is journaled as a note.

use anyhow::Result;
use std::path::Path;

use crate::modules::{dns, hosts, Ctx};
use crate::sys::journal::{Journal, Undo};
use crate::sys::proc::{self, ProcBackend, SystemProcs};
use crate::util;

const SERVICE: &str = "zapret";
const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Done,
    Skipped,
    Failed,
}

#[derive(Debug, Clone)]
pub struct StepResult {
    /// Stable id used by [`retry`].
    pub id: &'static str,
    pub title: String,
    pub state: StepState,
    pub detail: String,
}

#[derive(Debug, Default, Clone)]
pub struct Report {
    pub steps: Vec<StepResult>,
}

impl Report {
    pub fn ok(&self) -> bool {
        !self.steps.iter().any(|s| s.state == StepState::Failed)
    }

    pub fn failed_ids(&self) -> Vec<&'static str> {
        self.steps
            .iter()
            .filter(|s| s.state == StepState::Failed)
            .map(|s| s.id)
            .collect()
    }

    pub fn summary(&self) -> String {
        let done = self.steps.iter().filter(|s| s.state == StepState::Done).count();
        let skipped = self
            .steps
            .iter()
            .filter(|s| s.state == StepState::Skipped)
            .count();
        let failed = self.failed_ids().len();
        let mut s = format!("изменено: {done}, пропущено: {skipped}");
        if failed > 0 {
            s.push_str(&format!(", не удалось: {failed}"));
        }
        s
    }
}

/// Runs every step once, logs each result and fails if anything is left over.
pub fn run(ctx: &Ctx) -> Result<()> {
    let rep = run_steps(ctx, None);
    for s in &rep.steps {
        let icon = match s.state {
            StepState::Done => "✓",
            StepState::Skipped => "•",
            StepState::Failed => "⚠",
        };
        ctx.log(format!("{icon} {}: {}", s.title, s.detail));
    }
    ctx.log(format!("Итог: {}", rep.summary()));
    if rep.ok() {
        ctx.log("✓ Готово: обход выключен, система возвращена как была.");
        ctx.log("  Файлы программы остались на месте — включить можно снова.");
        Ok(())
    } else {
        let names: Vec<&str> = rep
            .steps
            .iter()
            .filter(|s| s.state == StepState::Failed)
            .map(|s| s.title.as_str())
            .collect();
        ctx.log(format!(
            "⚠ Не всё удалось: {}. Повторите «Выключить» — уже сделанное пропускается.",
            names.join(", ")
        ));
        anyhow::bail!("не удалось выключить: {}", names.join(", "))
    }
}

/// Retries only the steps that failed last time.
///
/// The UI can call this after a partial "Выключить" without touching the steps
/// that already succeeded.
#[allow(dead_code)] // wired by the Off screen
pub fn retry(ctx: &Ctx, prev: &Report) -> Report {
    let ids = prev.failed_ids();
    if ids.is_empty() {
        return prev.clone();
    }
    run_steps(ctx, Some(&ids))
}

fn run_steps(ctx: &Ctx, only: Option<&[&'static str]>) -> Report {
    let wanted = |id: &str| only.map(|list| list.contains(&id)).unwrap_or(true);
    let mut rep = Report::default();
    let journal = Journal::new(ctx.data.clone());
    let mut push = |r: StepResult| rep.steps.push(r);

    ctx.progress(5, "остановка обхода");
    if wanted("service") {
        push(step_service(ctx, &journal));
    }
    if wanted("process") {
        push(step_process(ctx, &journal));
    }
    ctx.progress(35, "hosts");
    if wanted("hosts") {
        push(step_hosts(ctx));
    }
    ctx.progress(55, "DNS");
    if wanted("dns") {
        push(step_dns(ctx));
    }
    ctx.progress(75, "автозагрузка");
    if wanted("autostart") {
        push(step_autostart(ctx, &journal));
    }
    ctx.progress(100, "готово");
    rep
}

// ───────────────────────── steps ─────────────────────────

fn step_service(ctx: &Ctx, journal: &Journal) -> StepResult {
    let r = |state, detail: String| StepResult {
        id: "service",
        title: "Служба обхода".into(),
        state,
        detail,
    };
    if !service_exists(SERVICE) {
        return r(StepState::Skipped, "не установлена".into());
    }
    if !owns_service(ctx, SERVICE) {
        return r(
            StepState::Skipped,
            "служба zapret не наша — оставлена как есть".into(),
        );
    }
    if !ctx.admin {
        return r(
            StepState::Failed,
            "нужны права администратора, служба не остановлена".into(),
        );
    }
    let _ = util::hidden_str("sc", &["stop", SERVICE]);
    if let Err(e) = util::run_checked("sc", &["delete", SERVICE]) {
        return r(StepState::Failed, format!("sc delete: {e:#}"));
    }
    if service_exists(SERVICE) {
        return r(
            StepState::Failed,
            "служба всё ещё существует после sc delete".into(),
        );
    }
    let _ = proc::disown_service(&ctx.data, SERVICE);
    let _ = record_action(
        journal,
        "zapret",
        "service-delete",
        serde_json::json!({ "service": SERVICE }),
    );
    r(StepState::Done, "остановлена и удалена".into())
}

fn step_process(ctx: &Ctx, journal: &Journal) -> StepResult {
    let r = |state, detail: String| StepResult {
        id: "process",
        title: "Процесс обхода".into(),
        state,
        detail,
    };

    // (image, pid, exe) that we are allowed to stop.
    let mut targets: Vec<(&'static str, u32, String)> = Vec::new();
    let mut problems = Vec::new();

    // 1. winws.exe: only pids recorded when we started it.
    match proc::owned_alive(&ctx.data, &SystemProcs, "winws.exe") {
        Ok(list) => targets.extend(list.iter().map(|p| ("winws.exe", p.pid, p.exe.clone()))),
        Err(e) => problems.push(format!("список winws.exe: {e:#}")),
    }

    // 2. TgWsProxy.exe: recorded pids, plus the exact binary our Run value
    //    points at when it lives in our folder (that is what we launched).
    match proc::owned_alive(&ctx.data, &SystemProcs, "TgWsProxy.exe") {
        Ok(list) => targets.extend(list.iter().map(|p| ("TgWsProxy.exe", p.pid, p.exe.clone()))),
        Err(e) => problems.push(format!("список TgWsProxy.exe: {e:#}")),
    }
    if let Some(ours) = our_binary_from_run_value(ctx) {
        if let Ok(list) = SystemProcs.list("TgWsProxy.exe") {
            for p in list {
                if p.exe.eq_ignore_ascii_case(&ours) {
                    targets.push(("TgWsProxy.exe", p.pid, p.exe.clone()));
                }
            }
        }
    }

    targets.sort_by_key(|t| t.1);
    targets.dedup_by_key(|t| t.1);
    if targets.is_empty() && problems.is_empty() {
        return r(
            StepState::Skipped,
            "ни winws.exe, ни TgWsProxy.exe не запускали мы".into(),
        );
    }

    let mut killed: Vec<String> = Vec::new();
    for (image, pid, exe) in &targets {
        match proc::kill_owned(&SystemProcs, image, *pid, exe) {
            Ok(()) => {
                killed.push(format!("{image} (pid {pid})"));
                let _ = record_action(
                    journal,
                    "process",
                    "process-kill",
                    serde_json::json!({ "pid": pid, "exe": exe, "image": image }),
                );
            }
            Err(e) => problems.push(format!("{image} pid {pid}: {e:#}")),
        }
    }
    for image in ["winws.exe", "TgWsProxy.exe"] {
        let _ = proc::forget(&ctx.data, image);
    }
    if problems.is_empty() {
        r(StepState::Done, format!("остановлено: {}", killed.join(", ")))
    } else {
        r(StepState::Failed, problems.join("; "))
    }
}

/// The binary our own autostart value points at, if it lives in our folder.
fn our_binary_from_run_value(ctx: &Ctx) -> Option<String> {
    for name in ["TgWsProxy", "obhod"] {
        let Some(raw) = util::reg_get_string("HKCU", RUN_KEY, name).ok().flatten() else {
            continue;
        };
        let path = raw.trim().trim_matches('"');
        let first = path.split('"').next().unwrap_or(path).trim();
        if first.to_ascii_lowercase().ends_with(".exe") && points_into_our_folder(first, &ctx.data) {
            return Some(first.to_string());
        }
    }
    None
}

fn step_hosts(ctx: &Ctx) -> StepResult {
    let r = |state, detail: String| StepResult {
        id: "hosts",
        title: "hosts".into(),
        state,
        detail,
    };
    match hosts::remove_block(ctx) {
        Ok(true) => r(StepState::Done, "наш блок убран, остальное на месте".into()),
        Ok(false) => r(StepState::Skipped, "нашего блока нет".into()),
        Err(e) => r(StepState::Failed, format!("{e:#}")),
    }
}

fn step_dns(ctx: &Ctx) -> StepResult {
    let r = |state, detail: String| StepResult {
        id: "dns",
        title: "DNS".into(),
        state,
        detail,
    };
    let had_snapshot = dns::has_snapshot(&ctx.data);
    if !had_snapshot && !ctx.admin {
        return r(
            StepState::Skipped,
            "снимка нет, а без прав администратора DNS не меняем".into(),
        );
    }
    match dns::reset(ctx) {
        Ok(()) => {
            if had_snapshot {
                match crate::sys::dns_state::remove_snapshot(&ctx.data) {
                    Ok(_) => r(
                        StepState::Done,
                        "прежние серверы возвращены, снимок удалён".into(),
                    ),
                    Err(e) => r(
                        StepState::Done,
                        format!("серверы возвращены, снимок не удалён: {e:#}"),
                    ),
                }
            } else {
                r(StepState::Skipped, "снимка не было — DNS не менялся".into())
            }
        }
        Err(e) => r(StepState::Failed, format!("{e:#}")),
    }
}

fn step_autostart(ctx: &Ctx, journal: &Journal) -> StepResult {
    let r = |state, detail: String| StepResult {
        id: "autostart",
        title: "Автозагрузка".into(),
        state,
        detail,
    };
    let ledger = proc::load(&ctx.data);
    let mut removed = Vec::new();
    let mut kept = Vec::new();
    for name in ["TgWsProxy", "obhod"] {
        let value = match util::reg_get_string("HKCU", RUN_KEY, name) {
            Ok(Some(v)) => v,
            Ok(None) => continue,
            Err(e) => return r(StepState::Failed, format!("reg query {name}: {e:#}")),
        };
        let recorded = ledger
            .run_values
            .iter()
            .any(|rv| rv.name.eq_ignore_ascii_case(name));
        if !recorded && !points_into_our_folder(&value, &ctx.data) {
            kept.push(name.to_string());
            continue;
        }
        match util::reg_delete_value("HKCU", RUN_KEY, name) {
            Ok(()) => {
                let _ = proc::forget_run_value(&ctx.data, name);
                let _ = record_action(
                    journal,
                    "autostart",
                    "run-value-delete",
                    serde_json::json!({ "name": name, "value": value }),
                );
                removed.push(name.to_string());
            }
            Err(e) => return r(StepState::Failed, format!("reg delete {name}: {e:#}")),
        }
    }
    if !removed.is_empty() {
        return r(StepState::Done, format!("снята: {}", removed.join(", ")));
    }
    if !kept.is_empty() {
        return r(
            StepState::Skipped,
            format!("{} не наш — оставлена", kept.join(", ")),
        );
    }
    r(StepState::Skipped, "не была настроена".into())
}

// ───────────────────────── helpers ─────────────────────────

fn service_exists(name: &str) -> bool {
    util::hidden_str("sc", &["query", name])
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

fn service_image(name: &str) -> Option<String> {
    util::reg_get_string(
        "HKLM",
        &format!(r"System\CurrentControlSet\Services\{name}"),
        "ImagePath",
    )
    .ok()
    .flatten()
}

/// A service is ours when the ownership ledger says so, when the preset marker
/// exists (older installs of this tool), or when its image lives in our folder.
fn owns_service(ctx: &Ctx, name: &str) -> bool {
    if proc::service_owned(&ctx.data, name) {
        return true;
    }
    if util::reg_get_string(
        "HKLM",
        &format!(r"System\CurrentControlSet\Services\{name}"),
        "obhod-preset",
    )
    .ok()
    .flatten()
    .is_some()
    {
        return true;
    }
    service_image(name)
        .map(|img| points_into_our_folder(&img, &ctx.data))
        .unwrap_or(false)
}

/// True when a path (or a full command line) refers inside our data/exe folder.
fn points_into_our_folder(value: &str, data: &Path) -> bool {
    let v = value.to_ascii_lowercase();
    let mut roots: Vec<String> = Vec::new();
    roots.push(data.display().to_string().to_ascii_lowercase());
    roots.push(util::exe_dir().display().to_string().to_ascii_lowercase());
    if let Ok(cfg) = std::env::current_exe() {
        if let Some(dir) = cfg.parent() {
            roots.push(dir.display().to_string().to_ascii_lowercase());
        }
    }
    roots
        .into_iter()
        .filter(|r| !r.is_empty())
        .any(|r| v.contains(&r))
}

fn record_action(
    journal: &Journal,
    component: &str,
    action: &str,
    detail: serde_json::Value,
) -> Result<()> {
    crate::sys::journal::note_action(
        journal,
        component,
        action,
        detail,
        Undo::Note {
            component: component.to_string(),
            text: action.to_string(),
        },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn report_summarises_states() {
        let rep = Report {
            steps: vec![
                StepResult {
                    id: "a",
                    title: "A".into(),
                    state: StepState::Done,
                    detail: String::new(),
                },
                StepResult {
                    id: "b",
                    title: "B".into(),
                    state: StepState::Skipped,
                    detail: String::new(),
                },
            ],
        };
        assert!(rep.ok());
        assert_eq!(rep.summary(), "изменено: 1, пропущено: 1");
        assert!(rep.failed_ids().is_empty());
    }

    #[test]
    fn failed_steps_are_retryable_by_id() {
        let rep = Report {
            steps: vec![
                StepResult {
                    id: "service",
                    title: "Служба".into(),
                    state: StepState::Failed,
                    detail: "нет прав".into(),
                },
                StepResult {
                    id: "hosts",
                    title: "hosts".into(),
                    state: StepState::Done,
                    detail: String::new(),
                },
            ],
        };
        assert!(!rep.ok());
        assert_eq!(rep.failed_ids(), vec!["service"]);
        assert!(rep.summary().contains("не удалось: 1"));
    }

    #[test]
    fn ownership_detection_uses_our_folder() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        std::fs::create_dir_all(&data).unwrap();
        let inside = format!(r#""{}" --minimized"#, data.join("obhod.exe").display());
        assert!(points_into_our_folder(&inside, &data));
        assert!(!points_into_our_folder(
            r#""C:\zapret\bin\winws.exe" --wf-tcp=80"#,
            &data
        ));
        assert!(!points_into_our_folder(
            r#""C:\Users\me\Desktop\TgWsProxy.exe""#,
            &data
        ));
    }

    #[test]
    fn record_action_writes_a_terminal_transaction() {
        use crate::sys::journal::Phase;
        let dir = tempfile::tempdir().unwrap();
        let j = Journal::new(dir.path());
        record_action(&j, "zapret", "service-delete", serde_json::json!({"a": 1})).unwrap();
        assert!(j.pending().unwrap().is_empty(), "must not look interrupted");
        let recs = j.read_records().unwrap();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].phase, Phase::Apply);
        assert_eq!(recs[1].phase, Phase::Commit);
        assert!(recs[1].is_terminal());
    }
}
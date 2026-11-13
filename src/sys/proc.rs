//! Process and ownership bookkeeping.
//!
//! Rule: obhod may only kill a process that it started itself. Ownership is
//! proven by a record in `data\ownership.json` (pid + image path + image name);
//! before killing, the pid is looked up again and the image path must still
//! match, so a recycled pid is never touched. Process *names* are never used as
//! a kill target (`taskkill /IM` is banned on purpose).
//!
//! Ownership is filled in by diffing the process list around a start: whatever
//! appeared in between belongs to us.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::fsx;

pub const OWNERSHIP_FILE: &str = "ownership.json";
pub const OWNERSHIP_VERSION: u32 = 1;

/// One process we are responsible for.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProcRecord {
    pub pid: u32,
    /// Full image path at the time of recording; used to reject reused pids.
    #[serde(default)]
    pub exe: String,
    #[serde(default)]
    pub image: String,
    #[serde(default)]
    pub started: u64,
}

/// A registry value we wrote (autostart), so we can remove exactly ours.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RunValue {
    pub root: String,
    pub path: String,
    pub name: String,
    #[serde(default)]
    pub value: String,
}

/// Persistent ownership ledger. Small, atomic, human-readable.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Ownership {
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub processes: Vec<ProcRecord>,
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub run_values: Vec<RunValue>,
}

pub trait ProcBackend {
    /// Live processes whose image name matches (case-insensitive).
    fn list(&self, image: &str) -> Result<Vec<ProcRecord>>;
    /// Kill one pid. Must verify the pid is gone before reporting success.
    fn kill(&self, pid: u32) -> Result<()>;
}

fn valid_image(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

fn same_exe(a: &str, b: &str) -> bool {
    if a.is_empty() || b.is_empty() {
        return false;
    }
    a.eq_ignore_ascii_case(b)
}

// ───────────────────────── persistence ─────────────────────────

pub fn ownership_path(dir: &Path) -> PathBuf {
    dir.join(OWNERSHIP_FILE)
}

/// Missing or corrupt ledger reads as empty: we simply own nothing then.
pub fn load(dir: &Path) -> Ownership {
    let path = ownership_path(dir);
    match fsx::try_read(&path) {
        Ok(Some(bytes)) => match serde_json::from_slice::<Ownership>(&bytes) {
            Ok(mut o) => {
                if o.version == 0 {
                    o.version = OWNERSHIP_VERSION;
                }
                o
            }
            Err(e) => {
                crate::logger::info(format!(
                    "ownership: {} повреждён ({e}), считаю, что ничего не принадлежит нам",
                    path.display()
                ));
                Ownership::default()
            }
        },
        _ => Ownership::default(),
    }
}

pub fn save(dir: &Path, o: &Ownership) -> Result<()> {
    let path = ownership_path(dir);
    let mut o = o.clone();
    o.version = OWNERSHIP_VERSION;
    let data = serde_json::to_vec_pretty(&o)?;
    fsx::write_atomic(&path, &data)
        .with_context(|| format!("не удалось записать {}", path.display()))
}

// ───────────────────────── ownership ops ─────────────────────────

/// Record every process that appeared since `before` was sampled.
pub fn record_new(
    dir: &Path,
    be: &dyn ProcBackend,
    image: &str,
    before: &[ProcRecord],
) -> Result<Vec<ProcRecord>> {
    let now = be.list(image)?;
    let fresh: Vec<ProcRecord> = now
        .iter()
        .filter(|p| !before.iter().any(|b| b.pid == p.pid))
        .cloned()
        .collect();
    if !fresh.is_empty() {
        let mut o = load(dir);
        for p in &fresh {
            o.processes.retain(|r| r.pid != p.pid);
            o.processes.push(p.clone());
        }
        save(dir, &o)?;
    }
    Ok(fresh)
}

/// Drop records for an image once we stopped caring about them.
pub fn forget(dir: &Path, image: &str) -> Result<()> {
    let mut o = load(dir);
    let before = o.processes.len();
    o.processes.retain(|p| !p.image.eq_ignore_ascii_case(image));
    if o.processes.len() != before {
        save(dir, &o)?;
    }
    Ok(())
}

/// Processes we own that are still running with the same image path.
pub fn owned_alive(dir: &Path, be: &dyn ProcBackend, image: &str) -> Result<Vec<ProcRecord>> {
    let o = load(dir);
    let live = be.list(image)?;
    let mut out = Vec::new();
    for rec in o.processes.iter().filter(|p| p.image.eq_ignore_ascii_case(image)) {
        if let Some(p) = live.iter().find(|p| p.pid == rec.pid) {
            // Reused pid? Only trust it when the image path still matches.
            if same_exe(&p.exe, &rec.exe) {
                out.push(p.clone());
            }
        }
    }
    Ok(out)
}

/// Kill a pid only if the running image still matches the recorded path.
pub fn kill_owned(be: &dyn ProcBackend, image: &str, pid: u32, exe: &str) -> Result<()> {
    let live = be.list(image)?;
    let Some(p) = live.iter().find(|p| p.pid == pid) else {
        return Ok(()); // already gone
    };
    if !same_exe(&p.exe, exe) {
        anyhow::bail!(
            "процесс {pid} сейчас {} — это не тот, что мы запускали, не трогаю",
            p.exe
        );
    }
    be.kill(pid)
}

pub fn own_service(dir: &Path, name: &str) -> Result<()> {
    let mut o = load(dir);
    if !o.services.iter().any(|s| s.eq_ignore_ascii_case(name)) {
        o.services.push(name.to_string());
        save(dir, &o)?;
    }
    Ok(())
}

pub fn disown_service(dir: &Path, name: &str) -> Result<()> {
    let mut o = load(dir);
    let before = o.services.len();
    o.services.retain(|s| !s.eq_ignore_ascii_case(name));
    if o.services.len() != before {
        save(dir, &o)?;
    }
    Ok(())
}

pub fn service_owned(dir: &Path, name: &str) -> bool {
    load(dir)
        .services
        .iter()
        .any(|s| s.eq_ignore_ascii_case(name))
}

pub fn own_run_value(dir: &Path, rv: &RunValue) -> Result<()> {
    let mut o = load(dir);
    o.run_values
        .retain(|r| !(r.root.eq_ignore_ascii_case(&rv.root)
            && r.path.eq_ignore_ascii_case(&rv.path)
            && r.name.eq_ignore_ascii_case(&rv.name)));
    o.run_values.push(rv.clone());
    save(dir, &o)
}

pub fn forget_run_value(dir: &Path, name: &str) -> Result<()> {
    let mut o = load(dir);
    let before = o.run_values.len();
    o.run_values.retain(|r| !r.name.eq_ignore_ascii_case(name));
    if o.run_values.len() != before {
        save(dir, &o)?;
    }
    Ok(())
}

// ───────────────────────── real backend ─────────────────────────

/// `Get-CimInstance Win32_Process` based listing.
pub struct SystemProcs;

const PS_LIST: &str = r#"
$list = @()
foreach ($proc in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
  if ($proc.Name -eq $p.image) {
    $list += [pscustomobject]@{ pid = [int]$proc.ProcessId; exe = [string]$proc.ExecutablePath; image = [string]$proc.Name }
  }
}
ConvertTo-Json -InputObject @($list) -Depth 3 -Compress
"#;

impl ProcBackend for SystemProcs {
    fn list(&self, image: &str) -> Result<Vec<ProcRecord>> {
        if !valid_image(image) {
            anyhow::bail!("недопустимое имя процесса: {image}");
        }
        let payload = crate::util::b64_json(&serde_json::json!({ "image": image }));
        let v = match crate::util::powershell_json(PS_LIST, &[("OBHOD_P", &payload)]) {
            Ok(v) => v,
            Err(e) => {
                crate::logger::info(format!("proc list через CIM не удался: {e:#}"));
                return tasklist_fallback(image);
            }
        };
        let mut out = Vec::new();
        for item in v.as_array().cloned().unwrap_or_default() {
            let pid = item.get("pid").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            if pid == 0 {
                continue;
            }
            out.push(ProcRecord {
                pid,
                exe: item
                    .get("exe")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                image: image.to_string(),
                started: crate::util::now_unix(),
            });
        }
        Ok(out)
    }

    fn kill(&self, pid: u32) -> Result<()> {
        let out = crate::util::hidden_str("taskkill", &["/PID", &pid.to_string(), "/F"])?;
        if out.status.success() {
            return Ok(());
        }
        // Locale-independent check: if the pid is gone, the goal is met.
        if self.pid_alive(pid) {
            let msg = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("taskkill {pid}: {}", msg.trim());
        }
        Ok(())
    }
}

impl SystemProcs {
    fn pid_alive(&self, pid: u32) -> bool {
        crate::util::hidden_str("tasklist", &["/FI", &format!("PID eq {pid}"), "/NH"])
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .split_whitespace()
                    .any(|t| t == pid.to_string())
            })
            .unwrap_or(true)
    }
}

fn tasklist_fallback(image: &str) -> Result<Vec<ProcRecord>> {
    let out = crate::util::hidden_str(
        "tasklist",
        &["/FI", &format!("IMAGENAME eq {image}"), "/FO", "CSV", "/NH"],
    )?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut res = Vec::new();
    for line in text.lines() {
        let cols: Vec<String> = line
            .split("\",\"")
            .map(|c| c.trim_matches('"').to_string())
            .collect();
        if cols.len() < 2 {
            continue;
        }
        if let Ok(pid) = cols[1].trim().parse::<u32>() {
            res.push(ProcRecord {
                pid,
                exe: String::new(), // unknown: ownership check will refuse to kill
                image: image.to_string(),
                started: crate::util::now_unix(),
            });
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct MockProcs {
        alive: RefCell<Vec<ProcRecord>>,
        kills: RefCell<Vec<u32>>,
    }

    impl MockProcs {
        fn new(list: Vec<ProcRecord>) -> Self {
            Self {
                alive: RefCell::new(list),
                kills: RefCell::new(Vec::new()),
            }
        }
    }

    impl ProcBackend for MockProcs {
        fn list(&self, image: &str) -> Result<Vec<ProcRecord>> {
            Ok(self
                .alive
                .borrow()
                .iter()
                .filter(|p| p.image.eq_ignore_ascii_case(image))
                .cloned()
                .collect())
        }

        fn kill(&self, pid: u32) -> Result<()> {
            self.kills.borrow_mut().push(pid);
            self.alive.borrow_mut().retain(|p| p.pid != pid);
            Ok(())
        }
    }

    fn p(pid: u32, exe: &str) -> ProcRecord {
        ProcRecord {
            pid,
            exe: exe.into(),
            image: "winws.exe".into(),
            started: 0,
        }
    }

    #[test]
    fn record_new_only_takes_the_diff() {
        let dir = tempfile::tempdir().unwrap();
        let be = MockProcs::new(vec![p(100, r"C:\other\winws.exe")]);
        let before = be.list("winws.exe").unwrap();
        be.alive.borrow_mut().push(p(200, r"C:\ours\winws.exe"));
        let fresh = record_new(dir.path(), &be, "winws.exe", &before).unwrap();
        assert_eq!(fresh.len(), 1);
        assert_eq!(fresh[0].pid, 200);
        assert!(!service_owned(dir.path(), "zapret"));
        let o = load(dir.path());
        assert_eq!(o.processes.len(), 1);
    }

    #[test]
    fn owned_alive_ignores_reused_pid_with_other_exe() {
        let dir = tempfile::tempdir().unwrap();
        let be = MockProcs::new(vec![p(7, r"C:\ours\winws.exe")]);
        record_new(dir.path(), &be, "winws.exe", &[]).unwrap();
        assert_eq!(owned_alive(dir.path(), &be, "winws.exe").unwrap().len(), 1);
        // Same pid, different image: not ours any more.
        be.alive.borrow_mut()[0].exe = r"C:\theirs\winws.exe".into();
        assert!(owned_alive(dir.path(), &be, "winws.exe").unwrap().is_empty());
    }

    #[test]
    fn kill_owned_refuses_foreign_image() {
        let be = MockProcs::new(vec![p(9, r"C:\theirs\winws.exe")]);
        let err = kill_owned(&be, "winws.exe", 9, r"C:\ours\winws.exe").unwrap_err();
        assert!(format!("{err:#}").contains("не тот"));
        assert!(be.kills.borrow().is_empty());
    }

    #[test]
    fn kill_owned_is_idempotent() {
        let be = MockProcs::new(vec![]);
        kill_owned(&be, "winws.exe", 42, r"C:\ours\winws.exe").unwrap();
        assert!(be.kills.borrow().is_empty());
    }

    #[test]
    fn ownership_roundtrip_and_corrupt_file() {
        let dir = tempfile::tempdir().unwrap();
        own_service(dir.path(), "zapret").unwrap();
        own_run_value(
            dir.path(),
            &RunValue {
                root: "HKCU".into(),
                path: r"Software\Microsoft\Windows\CurrentVersion\Run".into(),
                name: "TgWsProxy".into(),
                value: r#""C:\x\TgWsProxy.exe""#.into(),
            },
        )
        .unwrap();
        let o = load(dir.path());
        assert_eq!(o.services, vec!["zapret".to_string()]);
        assert_eq!(o.run_values.len(), 1);
        assert!(service_owned(dir.path(), "ZAPRET"));
        disown_service(dir.path(), "zapret").unwrap();
        assert!(!service_owned(dir.path(), "zapret"));
        std::fs::write(ownership_path(dir.path()), b"{not json").unwrap();
        assert!(load(dir.path()).processes.is_empty());
    }

    #[test]
    fn image_name_validation_blocks_injection() {
        assert!(valid_image("winws.exe"));
        assert!(!valid_image("winws.exe' ; Remove-Item C:\\ -Recurse"));
        assert!(!valid_image(""));
        assert!(!valid_image("winws exe"));
    }

    /// Read-only check of the real CIM listing:
    /// `cargo test --release -- --ignored --nocapture system_procs_lists_processes`
    #[test]
    #[ignore = "read-only check against the real machine"]
    fn system_procs_lists_processes() {
        // explorer.exe exists on every interactive Windows session.
        let list = SystemProcs.list("explorer.exe").expect("CIM listing");
        println!("explorer.exe processes: {}", list.len());
        for p in &list {
            println!("  pid {} -> {}", p.pid, p.exe);
        }
    }
}
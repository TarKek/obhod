use std::path::{Path, PathBuf};

use crate::util;

pub struct Found {
    pub key: &'static str,
    pub ru: String,
    pub en: String,
    pub detail: String,
    /// When true the user keeps the existing installation untouched.
    pub keep: bool,
}

pub fn scan() -> Vec<Found> {
    let mut out = Vec::new();

    for app in installed() {
        let (ru, en) = match app.key {
            "zapret" => (
                "Обход для YouTube/Discord (zapret)",
                "YouTube/Discord bypass (zapret)",
            ),
            "tgws" => (
                "Запасной мост для Telegram (TgWsProxy)",
                "Telegram fallback bridge (TgWsProxy)",
            ),
            "client_hiddify" => ("Приложение Hiddify", "Hiddify app"),
            "client_v2rayn" => ("Приложение v2rayN", "v2rayN app"),
            "client_happ" => ("Приложение Happ", "Happ app"),
            _ => continue,
        };
        let mut parts = vec![app
            .path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "установлено".into())];
        if let Some(v) = &app.version {
            parts.push(format!("версия {v}"));
        }
        if app.key == "zapret" {
            parts.push(format!("служба: {}", yes_no(service_exists("zapret"))));
            parts.push(format!("процесс: {}", yes_no(proc_running("winws.exe"))));
        }
        out.push(Found {
            key: app.key,
            ru: ru.into(),
            en: en.into(),
            detail: parts.join(" · "),
            keep: true,
        });
    }

    // --- Telegram (informational only) -----------------------------------
    let tg = [
        PathBuf::from(r"E:\fromdiskD\vaznuye_faily_ne_ydalat\Ayugram\AyuGram.exe"),
        dir_appdata().join("Telegram Desktop").join("Telegram.exe"),
        PathBuf::from(r"C:\Program Files\Telegram Desktop\Telegram.exe"),
    ]
    .into_iter()
    .find(|p| p.exists());
    if let Some(p) = tg {
        out.push(Found {
            key: "telegram",
            ru: "Telegram".into(),
            en: "Telegram".into(),
            detail: p.display().to_string(),
            keep: true,
        });
    }

    out
}

/// A program we found on this machine, wherever the user installed it.
pub struct Installed {
    pub key: &'static str,
    pub name: String,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    pub running: bool,
}

struct RegApp {
    name: String,
    version: Option<String>,
    location: Option<PathBuf>,
}

/// Finds zapret, TgWsProxy, Hiddify, v2rayN and Happ in the registry,
/// in the services database and in common portable locations.
pub fn installed() -> Vec<Installed> {
    let regs = reg_apps();
    let mut raw: Vec<(&'static str, String, Option<PathBuf>, Option<String>, bool)> = Vec::new();

    // --- zapret -----------------------------------------------------------
    let mut zpath = service_image("zapret");
    if zpath.is_none() {
        if let Some(r) = regs.iter().find(|r| r.name.to_lowercase().contains("zapret")) {
            zpath = r
                .location
                .as_deref()
                .and_then(|d| find_exe_in(d, "winws.exe", 4));
        }
    }
    if zpath.is_none() {
        zpath = first_existing(&[
            PathBuf::from(r"C:\zapret\bin\winws.exe"),
            dir_local_appdata()
                .join("Programs")
                .join("zapret")
                .join("bin")
                .join("winws.exe"),
            util::exe_dir()
                .join("data")
                .join("zapret")
                .join("bin")
                .join("winws.exe"),
        ]);
    }
    let zrun = proc_running("winws.exe");
    if service_exists("zapret") || zrun || zpath.is_some() {
        let ver = zpath.as_deref().and_then(zapret_version);
        raw.push(("zapret", "zapret".into(), zpath, ver, zrun));
    }

    // --- TgWsProxy --------------------------------------------------------
    let tpath = find_tgws();
    let trun = proc_running("TgWsProxy.exe");
    if tpath.is_some() || trun {
        raw.push(("tgws", "TgWsProxy".into(), tpath, None, trun));
    }

    // --- clients ----------------------------------------------------------
    let client_defs: [(&'static str, &'static str, &str, &str, Vec<PathBuf>); 3] = [
        (
            "client_hiddify",
            "Hiddify",
            "hiddify",
            "Hiddify.exe",
            vec![
                dir_local_appdata().join("Programs").join("Hiddify"),
                util::exe_dir().join("data").join("clients").join("hiddify"),
                PathBuf::from(r"C:\Program Files\Hiddify"),
            ],
        ),
        (
            "client_v2rayn",
            "v2rayN",
            "v2rayn",
            "v2rayN.exe",
            vec![
                dir_appdata().join("v2rayN"),
                util::exe_dir().join("data").join("clients").join("v2rayn"),
                PathBuf::from(r"C:\Program Files\v2rayN"),
            ],
        ),
        (
            "client_happ",
            "Happ",
            "happ",
            "Happ.exe",
            vec![
                dir_local_appdata().join("Programs").join("Happ"),
                dir_local_appdata().join("Happ"),
            ],
        ),
    ];
    for (key, disp, matcher, exe, dirs) in client_defs {
        let reg = regs.iter().find(|r| r.name.to_lowercase().contains(matcher));
        let mut path = reg
            .and_then(|r| r.location.as_deref())
            .and_then(|d| find_exe_in(d, exe, 5));
        if path.is_none() {
            for d in &dirs {
                if let Some(p) = find_exe_in(d, exe, 4) {
                    path = Some(p);
                    break;
                }
            }
        }
        if path.is_some() || reg.is_some() {
            raw.push((key, disp.into(), path, reg.and_then(|r| r.version.clone()), false));
        }
    }

    // Read versions from the files for entries the registry did not describe.
    let need: Vec<PathBuf> = raw
        .iter()
        .filter(|(_, _, p, v, _)| v.is_none() && p.is_some())
        .filter_map(|(_, _, p, _, _)| p.clone())
        .collect();
    let versions = file_versions(&need);
    let mut vi = 0usize;
    let mut out = Vec::new();
    for (key, name, path, regver, running) in raw {
        let version = match regver {
            Some(v) => Some(v),
            None => {
                if path.is_some() {
                    let v = versions.get(vi).cloned().flatten();
                    vi += 1;
                    v
                } else {
                    None
                }
            }
        };
        out.push(Installed {
            key,
            name,
            path,
            version,
            running,
        });
    }
    out
}

fn first_existing(paths: &[PathBuf]) -> Option<PathBuf> {
    paths.iter().find(|p| p.exists()).cloned()
}

fn zapret_version(exe: &Path) -> Option<String> {
    let mut dirs = Vec::new();
    if let Some(p) = exe.parent() {
        dirs.push(p.to_path_buf());
        if let Some(p2) = p.parent() {
            dirs.push(p2.to_path_buf());
        }
    }
    for d in &dirs {
        if let Ok(s) = std::fs::read_to_string(d.join("service.bat")) {
            if let Some(v) = bat_var(&s, "LOCAL_VERSION") {
                if !v.is_empty() {
                    return Some(v);
                }
            }
        }
        for name in ["version.txt", "VERSION.txt", "version", "ver.txt"] {
            if let Ok(s) = std::fs::read_to_string(d.join(name)) {
                let s = s.trim();
                if !s.is_empty() {
                    return Some(s.lines().next().unwrap_or(s).trim().to_string());
                }
            }
        }
    }
    None
}

/// Reads `set "NAME=value"` from a Windows .bat file.
pub fn bat_var(text: &str, name: &str) -> Option<String> {
    for line in text.lines() {
        let l = line.trim();
        let rest = if let Some(r) = l.strip_prefix("set \"") {
            r
        } else if let Some(r) = l.strip_prefix("set ") {
            r.trim_matches('"')
        } else {
            continue;
        };
        if let Some(eq) = rest.find('=') {
            let key = rest[..eq].trim().trim_matches('"');
            if key.eq_ignore_ascii_case(name) {
                let v = rest[eq + 1..].trim().trim_end_matches('"').trim();
                if !v.is_empty() {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

pub fn find_tgws() -> Option<PathBuf> {
    let dirs = [
        dir_userprofile().join("Desktop"),
        dir_userprofile().join("Downloads"),
        dir_local_appdata().join("Programs"),
        util::exe_dir(),
        util::exe_dir().join("data").join("tgws"),
        dir_userprofile(),
    ];
    for d in &dirs {
        if let Some(p) = find_exe_in(d, "TgWsProxy.exe", 3) {
            return Some(p);
        }
        if let Some(p) = find_file(std::slice::from_ref(d), "tgwsproxy", ".exe") {
            return Some(p);
        }
    }
    None
}

/// Reads ProductVersion/FileVersion for a list of executables in one
/// PowerShell call. Returns one entry per input path.
pub fn file_versions(paths: &[PathBuf]) -> Vec<Option<String>> {
    if paths.is_empty() {
        return Vec::new();
    }
    let arr = paths
        .iter()
        .map(|p| format!("'{}'", p.display().to_string().replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(",");
    let ps = format!(
        "$ErrorActionPreference='SilentlyContinue'; $paths=@({arr}); $r=@(); foreach($p in $paths){{ $v=(Get-Item -LiteralPath $p -ErrorAction SilentlyContinue).VersionInfo; if($v){{ $r += (@($v.ProductVersion,$v.FileVersion) -join '|') }} else {{ $r += '|' }} }}; $r -join '~'"
    );
    let text = util::hidden_str(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    )
    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    .unwrap_or_default();
    let mut out: Vec<Option<String>> = text
        .split('~')
        .map(|chunk| {
            let mut it = chunk.split('|');
            let pv = it.next().unwrap_or("").trim();
            let fv = it.next().unwrap_or("").trim();
            let good = |s: &str| !s.is_empty() && s != "0.0.0.0";
            if good(pv) {
                Some(pv.to_string())
            } else if good(fv) {
                Some(fv.to_string())
            } else {
                None
            }
        })
        .collect();
    out.resize(paths.len(), None);
    out
}

fn reg_apps() -> Vec<RegApp> {
    let ps = r#"$ErrorActionPreference='SilentlyContinue'; $k=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'); Get-ItemProperty $k | Where-Object { $_.DisplayName -match 'Happ|zapret|TgWsProxy|Hiddify|v2rayN' } | ForEach-Object { @($_.DisplayName,$_.DisplayVersion,$_.InstallLocation) -join '|' }"#;
    let text = util::hidden_str(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", ps],
    )
    .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
    .unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let mut it = line.splitn(3, '|');
        let name = it.next().unwrap_or("").trim().to_string();
        if name.is_empty() {
            continue;
        }
        let version = it.next().map(str::trim).filter(|s| !s.is_empty()).map(str::to_string);
        let loc = it.next().map(str::trim).filter(|s| !s.is_empty()).map(PathBuf::from);
        out.push(RegApp {
            name,
            version,
            location: loc,
        });
    }
    out
}

/// Path from a Windows service's ImagePath (e.g. zapret).
pub fn service_image(name: &str) -> Option<PathBuf> {
    let key = format!(r"HKLM:\SYSTEM\CurrentControlSet\Services\{name}");
    let ps = format!(
        "(Get-ItemProperty '{}' -ErrorAction SilentlyContinue).ImagePath",
        key
    );
    let s = util::hidden_str(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    )
    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    .unwrap_or_default();
    if s.is_empty() {
        return None;
    }
    let lower = s.to_lowercase();
    let end = lower.find(".exe")? + 4;
    let p = s[..end].trim().trim_matches('"').trim_start_matches(r"\??\");
    Some(PathBuf::from(p))
}

pub fn keep_flag(items: &[Found], key: &str) -> bool {
    items.iter().find(|f| f.key == key).map(|f| f.keep).unwrap_or(false)
}

fn yes_no(v: bool) -> &'static str {
    if v {
        "да"
    } else {
        "нет"
    }
}

pub fn dir_userprofile() -> PathBuf {
    std::env::var("USERPROFILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\Users\Default"))
}

pub fn dir_appdata() -> PathBuf {
    std::env::var("APPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir_userprofile().join("AppData").join("Roaming"))
}

pub fn dir_local_appdata() -> PathBuf {
    std::env::var("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| dir_userprofile().join("AppData").join("Local"))
}

pub fn service_exists(name: &str) -> bool {
    // Locale-independent: a missing service produces no stdout at all.
    util::hidden_str("sc", &["query", name])
        .map(|o| !String::from_utf8_lossy(&o.stdout).trim().is_empty())
        .unwrap_or(false)
}

pub fn proc_running(exe: &str) -> bool {
    util::hidden_str("tasklist", &["/FI", &format!("IMAGENAME eq {exe}")])
        .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains(&exe.to_lowercase()))
        .unwrap_or(false)
}

pub fn find_exe_in(dir: &Path, exe: &str, depth: usize) -> Option<PathBuf> {
    if depth == 0 || !dir.exists() {
        return None;
    }
    let rd = std::fs::read_dir(dir).ok()?;
    let mut subdirs = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        if p.is_file() {
            if p.file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.eq_ignore_ascii_case(exe))
                .unwrap_or(false)
            {
                return Some(p);
            }
        } else if p.is_dir() {
            subdirs.push(p);
        }
    }
    for d in subdirs {
        if let Some(p) = find_exe_in(&d, exe, depth - 1) {
            return Some(p);
        }
    }
    None
}

pub fn find_file(dirs: &[PathBuf], prefix: &str, ext: &str) -> Option<PathBuf> {
    for d in dirs {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if let Some(n) = p.file_name().and_then(|n| n.to_str()) {
                    let l = n.to_lowercase();
                    if l.starts_with(prefix) && l.ends_with(ext) {
                        return Some(p);
                    }
                }
            }
        }
    }
    None
}

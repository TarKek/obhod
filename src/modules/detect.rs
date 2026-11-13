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
    if let Some(p) = telegram_path() {
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

/// Finds Telegram without hard-coded personal paths: registry first (App Paths
/// and the `tg://` protocol handler), then the usual install locations.
pub fn telegram_path() -> Option<PathBuf> {
    if let Some(p) = app_path("Telegram.exe") {
        return Some(p);
    }
    if let Some(p) = protocol_handler_exe("tg") {
        return Some(p);
    }
    first_existing(&[
        dir_local_appdata()
            .join("Telegram Desktop")
            .join("Telegram.exe"),
        dir_appdata().join("Telegram Desktop").join("Telegram.exe"),
        dir_local_appdata()
            .join("Programs")
            .join("Telegram Desktop")
            .join("Telegram.exe"),
        PathBuf::from(r"C:\Program Files\Telegram Desktop\Telegram.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Telegram Desktop\Telegram.exe"),
    ])
}

/// Path from `…\CurrentVersion\App Paths\<exe>` (HKLM, then HKCU).
fn app_path(exe: &str) -> Option<PathBuf> {
    let key = format!(r"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe}");
    for root in ["HKLM:", "HKCU:"] {
        let ps = format!(
            "$ErrorActionPreference='SilentlyContinue'; (Get-ItemProperty '{root}\\{key}').'(default)'"
        );
        let s = util::hidden_str(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", &ps],
        )
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
        let p = PathBuf::from(s.trim_matches('"'));
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Resolves `HKCU\Software\Classes\<scheme>\shell\open\command` to an exe.
fn protocol_handler_exe(scheme: &str) -> Option<PathBuf> {
    let ps = format!(
        "$ErrorActionPreference='SilentlyContinue'; (Get-ItemProperty 'HKCU:\\Software\\Classes\\{scheme}\\shell\\open\\command').'(default)'"
    );
    let s = util::hidden_str(
        "powershell",
        &["-NoProfile", "-NonInteractive", "-Command", &ps],
    )
    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    .unwrap_or_default();
    parse_service_image(&s).filter(|p| p.is_file())
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
    /// `DisplayIcon` or App Paths default value: often the exe itself.
    icon: Option<PathBuf>,
}

/// Word-aware name match: `Happ` must not match `Happy` or `WhatsApp`, while
/// CamelCase products such as `TgWsProxy` still match `tgws`.
fn name_matches(name: &str, needle: &str) -> bool {
    let needle = needle.trim();
    if needle.is_empty() {
        return false;
    }
    for token in name.split(|c: char| !c.is_ascii_alphanumeric()) {
        if token.is_empty() {
            continue;
        }
        if token.eq_ignore_ascii_case(needle) {
            return true;
        }
        // CamelCase concatenation: "TgWsProxy" starts with "TgWs" and the next
        // character is uppercase; "Happy" must not match "happ".
        if token.len() > needle.len()
            && token.is_char_boundary(needle.len())
            && token[..needle.len()].eq_ignore_ascii_case(needle)
            && token[needle.len()..]
                .chars()
                .next()
                .map(|c| c.is_ascii_uppercase())
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

fn icon_path(raw: &str) -> Option<PathBuf> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let s = if s.starts_with('"') {
        s.trim_start_matches('"').split('"').next().unwrap_or("")
    } else {
        s.split(',').next().unwrap_or(s)
    };
    let s = s.trim();
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

/// Uses a DisplayIcon/App Paths value as an executable hint.
fn exe_near(icon: &Path, exe: &str) -> Option<PathBuf> {
    if icon
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.eq_ignore_ascii_case(exe))
        .unwrap_or(false)
        && icon.is_file()
    {
        return Some(icon.to_path_buf());
    }
    find_exe_in(icon.parent().unwrap_or(icon), exe, 2)
}

/// One entry while `installed()` is collecting data.
type RawApp = (&'static str, String, Option<PathBuf>, Option<String>, bool);

/// Finds zapret, TgWsProxy, Hiddify, v2rayN and Happ in the registry,
/// in the services database and in common portable locations.
pub fn installed() -> Vec<Installed> {
    let regs = reg_apps();
    let mut raw: Vec<RawApp> = Vec::new();

    // --- zapret -----------------------------------------------------------
    let zapret_reg = regs.iter().find(|r| name_matches(&r.name, "zapret"));
    let mut zpath = service_image("zapret");
    if zpath.is_none() {
        if let Some(r) = zapret_reg {
            zpath = r
                .location
                .as_deref()
                .and_then(|d| find_exe_in(d, "winws.exe", 4))
                .or_else(|| r.icon.as_deref().and_then(|p| exe_near(p, "winws.exe")));
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
    if service_exists("zapret") || zrun || zpath.is_some() || zapret_reg.is_some() {
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
        let reg = regs.iter().find(|r| name_matches(&r.name, matcher));
        let mut path = reg
            .and_then(|r| r.location.as_deref())
            .and_then(|d| find_exe_in(d, exe, 5))
            .or_else(|| {
                reg.and_then(|r| r.icon.as_deref())
                    .and_then(|p| exe_near(p, exe))
            });
        if path.is_none() {
            for d in &dirs {
                if let Some(p) = find_exe_in(d, exe, 4) {
                    path = Some(p);
                    break;
                }
            }
        }
        if path.is_some() || reg.is_some() {
            raw.push((
                key,
                disp.into(),
                path,
                reg.and_then(|r| r.version.clone()),
                false,
            ));
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
    // One PowerShell call: installed programs (Uninstall keys, 32/64-bit and
    // per-user) plus App Paths entries. `\bhapp\b` avoids Happy/WhatsApp.
    let ps = r#"$ErrorActionPreference='SilentlyContinue';
$keys=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*');
Get-ItemProperty $keys | Where-Object { $_.DisplayName -match 'zapret|tgws|hiddify|v2rayn|\bhapp\b' } | ForEach-Object { 'U|' + (@($_.DisplayName,$_.DisplayVersion,$_.InstallLocation,$_.DisplayIcon) -join '|') };
$ap=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\*');
Get-ItemProperty $ap | Where-Object { $_.PSChildName -match 'zapret|tgws|hiddify|v2rayn|happ|telegram' } | ForEach-Object { 'A|' + $_.PSChildName + '|' + $_.'(default)' }"#;
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
        if let Some(rest) = line.strip_prefix("U|") {
            let mut it = rest.splitn(4, '|');
            let name = it.next().unwrap_or("").trim().to_string();
            if name.is_empty() {
                continue;
            }
            let version = it
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string);
            let loc = it
                .next()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(PathBuf::from);
            let icon = it.next().and_then(icon_path);
            out.push(RegApp {
                name,
                version,
                location: loc,
                icon,
            });
        } else if let Some(rest) = line.strip_prefix("A|") {
            let mut it = rest.splitn(2, '|');
            let name = it.next().unwrap_or("").trim().to_string();
            let path = it.next().map(str::trim).unwrap_or("");
            if name.is_empty() || path.is_empty() {
                continue;
            }
            let p = PathBuf::from(path.trim_matches('"'));
            if !p.is_file() {
                continue;
            }
            out.push(RegApp {
                name,
                version: None,
                location: p.parent().map(Path::to_path_buf),
                icon: Some(p),
            });
        }
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
    parse_service_image(&s).filter(|p| p.is_file())
}

/// Extracts the executable from an `ImagePath`/command line, handling quotes,
/// `\??\` prefixes and trailing arguments.
pub fn parse_service_image(raw: &str) -> Option<PathBuf> {
    let s = raw.trim();
    if s.is_empty() {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    let end = lower.find(".exe")? + 4;
    let p = s[..end]
        .trim()
        .trim_matches('"')
        .trim_start_matches(r"\??\")
        .trim();
    if p.is_empty() {
        None
    } else {
        Some(PathBuf::from(p))
    }
}

pub fn keep_flag(items: &[Found], key: &str) -> bool {
    items
        .iter()
        .find(|f| f.key == key)
        .map(|f| f.keep)
        .unwrap_or(false)
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
    // `sc query <missing>` prints nothing to stdout; the key name SERVICE_NAME
    // is not localized, so this works on any Windows language.
    util::hidden_str("sc", &["query", name])
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .to_ascii_uppercase()
                    .contains("SERVICE_NAME")
        })
        .unwrap_or(false)
}

pub fn proc_running(exe: &str) -> bool {
    util::hidden_str("tasklist", &["/FI", &format!("IMAGENAME eq {exe}")])
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .to_lowercase()
                .contains(&exe.to_lowercase())
        })
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_matching_avoids_whatsapp_happy_false_positives() {
        assert!(name_matches("Happ", "happ"));
        assert!(name_matches("Happ-proxy desktop", "happ"));
        assert!(name_matches("zapret-discord-youtube", "zapret"));
        assert!(name_matches("Hiddify Next", "hiddify"));
        assert!(name_matches("v2rayN", "v2rayn"));
        assert!(name_matches("TgWsProxy", "tgws"));

        assert!(!name_matches("WhatsApp", "happ"));
        assert!(!name_matches("Happy Tools", "happ"));
        assert!(!name_matches("Happening", "happ"));
        assert!(!name_matches("Random app", "zapret"));
        assert!(!name_matches("", "happ"));
    }

    #[test]
    fn display_icon_paths_are_parsed() {
        assert_eq!(
            icon_path(r#""C:\Program Files\Happ\Happ.exe",0"#),
            Some(PathBuf::from(r"C:\Program Files\Happ\Happ.exe"))
        );
        assert_eq!(
            icon_path(r"C:\Apps\v2rayN\v2rayN.exe,0"),
            Some(PathBuf::from(r"C:\Apps\v2rayN\v2rayN.exe"))
        );
        assert_eq!(icon_path("   "), None);
    }

    #[test]
    fn service_image_parsing_handles_quotes_and_args() {
        assert_eq!(
            parse_service_image(r#""C:\zapret\bin\winws.exe" --wf-tcp=80,443"#),
            Some(PathBuf::from(r"C:\zapret\bin\winws.exe"))
        );
        assert_eq!(
            parse_service_image(r"\??\C:\zapret\bin\winws.exe --arg"),
            Some(PathBuf::from(r"C:\zapret\bin\winws.exe"))
        );
        assert_eq!(
            parse_service_image(r"C:\Program Files\zapret\winws.EXE"),
            Some(PathBuf::from(r"C:\Program Files\zapret\winws.EXE"))
        );
        assert_eq!(parse_service_image(""), None);
        assert_eq!(parse_service_image("no program here"), None);
    }

    #[test]
    fn exe_near_uses_the_icon_or_its_folder() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("Happ.exe");
        std::fs::write(&exe, b"MZ").unwrap();
        assert_eq!(exe_near(&exe, "Happ.exe").as_deref(), Some(exe.as_path()));
        // Icon is a .ico in the same folder as the exe.
        let ico = dir.path().join("app.ico");
        std::fs::write(&ico, b"ico").unwrap();
        assert_eq!(exe_near(&ico, "Happ.exe").as_deref(), Some(exe.as_path()));
        assert_eq!(exe_near(&ico, "Missing.exe"), None);
    }

    #[test]
    fn registry_and_service_helpers_do_not_panic() {
        // These read the real machine but must never panic and must agree on
        // a service that certainly does not exist.
        let _ = service_exists("obhod-definitely-not-a-service");
        assert!(!service_exists("obhod-definitely-not-a-service"));
        let _ = proc_running("obhod-not-running.exe");
    }
}

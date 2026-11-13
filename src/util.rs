use anyhow::{Context, Result};
use std::ffi::OsStr;
use std::fs;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[link(name = "kernel32")]
extern "system" {
    fn GetDiskFreeSpaceExW(
        dir: *const u16,
        free_to_caller: *mut u64,
        total: *mut u64,
        free_total: *mut u64,
    ) -> i32;
}

#[link(name = "shell32")]
extern "system" {
    fn IsUserAnAdmin() -> i32;
    fn ShellExecuteW(
        hwnd: isize,
        operation: *const u16,
        file: *const u16,
        parameters: *const u16,
        directory: *const u16,
        show_cmd: i32,
    ) -> isize;
}

pub fn is_admin() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Returns (free_percent, free_bytes, total_bytes) for the volume of `p`.
/// Walks up to an existing parent, so a not-yet-created data dir works too.
pub fn disk_stats(p: &Path) -> (f64, u64, u64) {
    let mut path = p.to_path_buf();
    let mut guard = 0;
    while !path.exists() && guard < 64 {
        match path.parent() {
            Some(parent) => path = parent.to_path_buf(),
            None => break,
        }
        guard += 1;
    }
    let w = wide(&path);
    let mut free_caller: u64 = 0;
    let mut total: u64 = 0;
    let mut free_total: u64 = 0;
    let ok = unsafe { GetDiskFreeSpaceExW(w.as_ptr(), &mut free_caller, &mut total, &mut free_total) };
    if ok == 0 || total == 0 {
        return (100.0, 0, 0);
    }
    let pct = free_total as f64 / total as f64 * 100.0;
    (pct, free_total, total)
}

pub fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

pub fn hidden(program: &str, args: &[&OsStr]) -> Result<Output> {
    let out = Command::new(program)
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .output()
        .with_context(|| format!("не удалось запустить {program}"))?;
    Ok(out)
}

pub fn hidden_str(program: &str, args: &[&str]) -> Result<Output> {
    let a: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    hidden(program, &a)
}

pub fn run_hidden_file(path: &Path) -> Result<()> {
    Command::new("cmd")
        .args(["/c", "start", "", "/min"])
        .arg(path)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("не удалось запустить {}", path.display()))?;
    Ok(())
}

pub fn http_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("obhod/0.1 (+https://github.com/)")
        .build()?)
}

pub fn get_text(client: &reqwest::blocking::Client, url: &str) -> Result<String> {
    let r = client.get(url).send()?;
    let status = r.status();
    let body = r.text().unwrap_or_default();
    if !status.is_success() {
        anyhow::bail!("HTTP {status} для {url}");
    }
    Ok(body)
}

pub fn download(client: &reqwest::blocking::Client, url: &str, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    // Large files need their own generous timeout regardless of the shared client.
    let dl = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(900))
        .user_agent("obhod/0.1")
        .build()?;
    let _ = client;
    let mut r = dl.get(url).send()?;
    if !r.status().is_success() {
        anyhow::bail!("HTTP {} для {url}", r.status());
    }
    let mut f = fs::File::create(dest)?;
    std::io::copy(&mut r, &mut f)?;
    f.flush()?;
    Ok(())
}

/// Latest GitHub release asset with the given extension.
/// Uses the API first, then falls back to scraping the releases page
/// (the API is rate-limited to 60 req/h per IP without a token).
pub fn github_asset(
    client: &reqwest::blocking::Client,
    repo: &str,
    ext: &str,
    out_dir: &Path,
) -> Result<PathBuf> {
    github_asset_filtered(client, repo, ext, "", out_dir)
}

/// Like `github_asset`, but the asset name must also contain `needle`.
pub fn github_asset_filtered(
    client: &reqwest::blocking::Client,
    repo: &str,
    ext: &str,
    needle: &str,
    out_dir: &Path,
) -> Result<PathBuf> {
    match github_asset_api(client, repo, ext, needle, out_dir) {
        Ok(p) => Ok(p),
        Err(api_err) => match github_asset_html(client, repo, ext, needle, out_dir) {
            Ok(p) => Ok(p),
            Err(html_err) => anyhow::bail!("API: {api_err:#}; HTML: {html_err:#}"),
        },
    }
}

fn name_matches(name: &str, ext: &str, needle: &str) -> bool {
    let l = name.to_lowercase();
    l.ends_with(ext) && (needle.is_empty() || l.contains(&needle.to_lowercase()))
}

fn github_asset_api(
    client: &reqwest::blocking::Client,
    repo: &str,
    ext: &str,
    needle: &str,
    out_dir: &Path,
) -> Result<PathBuf> {
    let api = format!("https://api.github.com/repos/{repo}/releases/latest");
    let resp = client
        .get(&api)
        .header("Accept", "application/vnd.github+json")
        .send()?;
    if !resp.status().is_success() {
        anyhow::bail!("GitHub API {}", resp.status());
    }
    let json: serde_json::Value = resp.json()?;
    let assets = json["assets"].as_array().cloned().unwrap_or_default();
    let asset = assets
        .iter()
        .find(|a| {
            a["name"]
                .as_str()
                .map(|n| name_matches(n, ext, needle))
                .unwrap_or(false)
        })
        .ok_or_else(|| anyhow::anyhow!("в релизе {repo} нет файла *{ext} {needle}"))?;
    let name = asset["name"].as_str().unwrap_or("asset");
    let url = asset["browser_download_url"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("нет ссылки на ассет"))?;
    let dest = out_dir.join(name);
    download(client, url, &dest)?;
    Ok(dest)
}

fn github_asset_html(
    client: &reqwest::blocking::Client,
    repo: &str,
    ext: &str,
    needle: &str,
    out_dir: &Path,
) -> Result<PathBuf> {
    let page = client
        .get(format!("https://github.com/{repo}/releases/latest"))
        .send()?
        .text()?;
    let tag = extract_until(&page, "expanded_assets/", &['"', '\\', '&', ' ', '\n'])
        .ok_or_else(|| anyhow::anyhow!("не найден тег релиза {repo}"))?;
    let assets = client
        .get(format!(
            "https://github.com/{repo}/releases/expanded_assets/{tag}"
        ))
        .send()?
        .text()?;
    let mut href: Option<String> = None;
    for part in assets.split("href=\"").skip(1) {
        let h = part.split('"').next().unwrap_or("");
        if h.contains("/releases/download/") {
            let name = h.rsplit('/').next().unwrap_or("");
            if name_matches(name, ext, needle) {
                href = Some(h.to_string());
                break;
            }
        }
    }
    let href = href.ok_or_else(|| anyhow::anyhow!("в релизе {repo} нет файла *{ext} {needle}"))?;
    let url = if href.starts_with("http") {
        href
    } else {
        format!("https://github.com{href}")
    };
    let name = url.rsplit('/').next().unwrap_or("asset");
    let dest = out_dir.join(name);
    download(client, &url, &dest)?;
    Ok(dest)
}

fn extract_until(s: &str, after: &str, stop: &[char]) -> Option<String> {
    let i = s.find(after)? + after.len();
    let rest = &s[i..];
    let end = rest.find(|c| stop.contains(&c)).unwrap_or(rest.len());
    let v = rest[..end].trim().to_string();
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

/// Latest release tag of a GitHub repo (works without the API rate limit).
pub fn github_latest_tag(client: &reqwest::blocking::Client, repo: &str) -> Result<String> {
    let page = client
        .get(format!("https://github.com/{repo}/releases/latest"))
        .send()?
        .text()?;
    extract_until(&page, "expanded_assets/", &['"', '\\', '&', ' ', '\n'])
        .ok_or_else(|| anyhow::anyhow!("не найден тег релиза {repo}"))
}

pub fn unzip(zip_path: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest)?;
    let f = fs::File::open(zip_path)?;
    let mut ar = zip::ZipArchive::new(f)?;
    ar.extract(dest)?;
    flatten_single_dir(dest)?;
    Ok(())
}

fn flatten_single_dir(dir: &Path) -> Result<()> {
    let entries: Vec<_> = fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    if entries.len() == 1 && entries[0].is_dir() {
        let inner = &entries[0];
        for e in fs::read_dir(inner)? {
            let e = e?;
            fs::rename(e.path(), dir.join(e.file_name()))?;
        }
        let _ = fs::remove_dir(inner);
    }
    Ok(())
}

/// Opens a URL/URI (http://, tg://, ...) with the default handler.
///
/// ShellExecuteW is used instead of `cmd /c start`: cmd splits the command
/// line on `&`, which silently cut `port` and `secret` off tg://proxy links
/// and made Telegram report "invalid proxy".
pub fn open_url(url: &str) -> Result<()> {
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let op = wide("open");
    let file = wide(url);
    let rc = unsafe {
        ShellExecuteW(
            0,
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
        )
    };
    if rc > 32 {
        return Ok(());
    }
    // Fallback for odd shells: rundll32 keeps `&` intact (no cmd parsing).
    Command::new("rundll32")
        .args(["url.dll,FileProtocolHandler", url])
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("не удалось открыть ссылку {url}"))?;
    Ok(())
}

pub fn reg_set_string(root: &str, path: &str, name: &str, value: &str) -> Result<()> {
    let out = hidden_str(
        "reg",
        &["add", &format!("{root}\\{path}"), "/v", name, "/t", "REG_SZ", "/d", value, "/f"],
    )?;
    if !out.status.success() {
        anyhow::bail!("reg add failed");
    }
    Ok(())
}

pub fn reg_delete_value(root: &str, path: &str, name: &str) -> Result<()> {
    let _ = hidden_str("reg", &["delete", &format!("{root}\\{path}"), "/v", name, "/f"]);
    Ok(())
}

pub fn set_clipboard(text: &str) -> bool {
    // Pass the value as base64 to avoid any quoting problems.
    let b64 = base64(text);
    let ps = format!(
        "Set-Clipboard -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{}')))",
        b64
    );
    hidden_str("powershell", &["-NoProfile", "-NonInteractive", "-Command", &ps])
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Standard base64 (with padding) for ASCII/UTF-8 input.
pub fn base64(s: &str) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.as_bytes();
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        out.push(if chunk.len() > 1 {
            T[((n >> 6) & 63) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[(n & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

pub fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.to_string()
}

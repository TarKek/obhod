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

/// Like [`hidden`], with extra environment variables for the child.
///
/// Used to hand data to PowerShell as a base64 JSON blob instead of
/// interpolating it into a command line: nothing a caller passes can be parsed
/// as PowerShell syntax.
pub fn hidden_env(program: &str, args: &[&OsStr], env: &[(&str, &str)]) -> Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .stdin(Stdio::null());
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .with_context(|| format!("не удалось запустить {program}"))
}

/// Run a command and fail unless it exits with code 0.
///
/// The error carries the child's stderr (or stdout, when stderr is empty), so
/// callers can show *why* something failed instead of a bare exit code.
pub fn run_checked(program: &str, args: &[&str]) -> Result<Output> {
    let out = hidden_str(program, args)?;
    if out.status.success() {
        return Ok(out);
    }
    let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    let detail = truncate(&detail, 400);
    anyhow::bail!(
        "{program} {} — код {}{}",
        args.join(" "),
        out.status.code().unwrap_or(-1),
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
        }
    )
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

/// Prelude shared by every PowerShell call: fail loudly, no progress noise and
/// UTF-8 on stdout (interface aliases are often non-ASCII).
const PS_PRELUDE: &str = "$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';\
[Console]::OutputEncoding=[Text.Encoding]::UTF8;\
if ($env:OBHOD_P) { $p=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:OBHOD_P))|ConvertFrom-Json };\n";

/// Run a PowerShell script hidden, with data passed through environment
/// variables. Scripts must use single quotes only (see [`powershell_json`]).
pub fn powershell(script: &str, env: &[(&str, &str)]) -> Result<Output> {
    let full = format!("{PS_PRELUDE}{script}");
    hidden_env(
        "powershell",
        &[
            OsStr::new("-NoProfile"),
            OsStr::new("-NonInteractive"),
            OsStr::new("-Command"),
            OsStr::new(&full),
        ],
        env,
    )
}

/// [`powershell`] that parses the script's output as JSON.
///
/// Everything before the first `[`/`{` is ignored (stray warnings), and the
/// exit code is checked. Requires the script to print exactly one JSON value.
pub fn powershell_json(script: &str, env: &[(&str, &str)]) -> Result<serde_json::Value> {
    let out = powershell(script, env)?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!(
            "PowerShell завершился с ошибкой: {}",
            truncate(if err.is_empty() { "без текста ошибки" } else { &err }, 400)
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    let start = text
        .find(['[', '{'])
        .ok_or_else(|| anyhow::anyhow!("PowerShell ничего не вернул"))?;
    serde_json::from_str::<serde_json::Value>(&text[start..])
        .with_context(|| format!("не удалось разобрать ответ PowerShell: {}", truncate(text, 200)))
}

/// Base64 of the JSON encoding of `v`, for [`powershell`] payloads.
pub fn b64_json(v: &serde_json::Value) -> String {
    base64(&serde_json::to_string(v).unwrap_or_else(|_| "null".into()))
}

/// Unix seconds.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Quote one argument exactly the way `CommandLineToArgvW` parses it.
///
/// Only for the rare places where a command line *string* is unavoidable
/// (`ShellExecuteW` parameters, `sc create binPath=`). Prefer
/// `Command::args` everywhere else.
pub fn quote_win_arg(arg: &str) -> String {
    let plain = !arg.is_empty()
        && !arg
            .chars()
            .any(|c| c == ' ' || c == '\t' || c == '\n' || c == '\u{b}' || c == '"');
    if plain {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut slashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(slashes));
                out.push(c);
                slashes = 0;
            }
        }
    }
    out.push_str(&"\\".repeat(slashes * 2));
    out.push('"');
    out
}

/// Split a command line into arguments using the `CommandLineToArgvW` rules.
///
/// Needed to turn a zapret `.bat` command line into `Command::args` without
/// going through `cmd /c` (which splits on `&` and mangles quotes).
pub fn split_windows_cmdline(cmd: &str) -> Vec<String> {
    let chars: Vec<char> = cmd.chars().collect();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        while i < chars.len() && matches!(chars[i], ' ' | '\t' | '\n' | '\r') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let mut arg = String::new();
        let mut in_quotes = false;
        while i < chars.len() {
            let c = chars[i];
            if !in_quotes && matches!(c, ' ' | '\t' | '\n' | '\r') {
                break;
            }
            if c == '\\' {
                let mut n = 0usize;
                while i < chars.len() && chars[i] == '\\' {
                    n += 1;
                    i += 1;
                }
                if i < chars.len() && chars[i] == '"' {
                    // 2n backslashes + quote => n backslashes, quote is a delimiter
                    // 2n+1 backslashes + quote => n backslashes and a literal quote
                    arg.push_str(&"\\".repeat(n / 2));
                    if n % 2 == 1 {
                        arg.push('"');
                        i += 1;
                    }
                } else {
                    arg.push_str(&"\\".repeat(n));
                }
                continue;
            }
            if c == '"' {
                if in_quotes && i + 1 < chars.len() && chars[i + 1] == '"' {
                    arg.push('"');
                    i += 2;
                    continue;
                }
                in_quotes = !in_quotes;
                i += 1;
                continue;
            }
            arg.push(c);
            i += 1;
        }
        out.push(arg);
    }
    out
}

/// `reg query` → the data of one value, or `None` when the value is absent.
pub fn parse_reg_query_value(stdout: &str, name: &str) -> Option<String> {
    for line in stdout.lines() {
        let l = line.trim();
        let Some(rest) = strip_prefix_ci(l, name) else {
            continue;
        };
        // "<name>    REG_SZ    <data>"
        let rest = rest.trim_start();
        let mut it = rest.splitn(2, char::is_whitespace);
        let kind = it.next().unwrap_or("").trim();
        if !kind.starts_with("REG_") {
            continue;
        }
        let data = it.next().unwrap_or("").trim_start();
        return Some(data.to_string());
    }
    None
}

fn strip_prefix_ci<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    if s.len() < prefix.len() || !s.is_char_boundary(prefix.len()) {
        return None;
    }
    if s[..prefix.len()].eq_ignore_ascii_case(prefix) {
        Some(&s[prefix.len()..])
    } else {
        None
    }
}

/// Read a registry string value; `Ok(None)` when it does not exist.
pub fn reg_get_string(root: &str, path: &str, name: &str) -> Result<Option<String>> {
    validate_reg_args(root, path, name)?;
    let out = hidden_str("reg", &["query", &format!("{root}\\{path}"), "/v", name])?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(parse_reg_query_value(&String::from_utf8_lossy(&out.stdout), name))
}

fn validate_reg_args(root: &str, path: &str, name: &str) -> Result<()> {
    for (what, v) in [("раздел", root), ("путь", path), ("значение", name)] {
        if v.is_empty() || v.contains('\0') || v.contains('\n') || v.contains('\r') {
            anyhow::bail!("reg: недопустимый {what}");
        }
    }
    Ok(())
}

/// Starts a file with its default handler, hidden.
///
/// ShellExecuteW instead of `cmd /c start` (no cmd parsing of `&`, no extra
/// console window, path never re-quoted by us).
pub fn run_hidden_file(path: &Path) -> Result<()> {
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let op = wide("open");
    let file = wide(&path.to_string_lossy());
    let dir = path
        .parent()
        .map(|p| wide(&p.to_string_lossy()))
        .unwrap_or_else(|| wide(""));
    let rc = unsafe {
        ShellExecuteW(
            0,
            op.as_ptr(),
            file.as_ptr(),
            std::ptr::null(),
            dir.as_ptr(),
            0, // SW_HIDE
        )
    };
    if rc > 32 {
        Ok(())
    } else {
        anyhow::bail!("не удалось запустить {} (код {rc})", path.display())
    }
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

/// Restarts the current exe elevated through the UAC prompt.
/// `Ok(())` means a new process was started and the caller should exit.
pub fn relaunch_elevated(extra: &[String]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().map(|p| p.to_path_buf()).unwrap_or_default();
    let params = extra
        .iter()
        .map(|a| quote_win_arg(a))
        .collect::<Vec<_>>()
        .join(" ");
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let op = wide("runas");
    let file = wide(&exe.to_string_lossy());
    let params = wide(&params);
    let dir = wide(&dir.to_string_lossy());
    let rc = unsafe {
        ShellExecuteW(
            0,
            op.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            dir.as_ptr(),
            1,
        )
    };
    if rc > 32 {
        return Ok(());
    }
    anyhow::bail!("UAC отменён или недоступен (код {rc})")
}

pub fn reveal(path: &Path) -> Result<()> {
    Command::new("explorer")
        .arg(format!("/select,{}", path.display()))
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .context("не удалось открыть проводник")?;
    Ok(())
}

pub fn reg_set_string(root: &str, path: &str, name: &str, value: &str) -> Result<()> {
    validate_reg_args(root, path, name)?;
    if value.contains('\0') {
        anyhow::bail!("reg: значение содержит NUL");
    }
    run_checked(
        "reg",
        &[
            "add",
            &format!("{root}\\{path}"),
            "/v",
            name,
            "/t",
            "REG_SZ",
            "/d",
            value,
            "/f",
        ],
    )
    .map(|_| ())
    .with_context(|| format!("не удалось записать {root}\\{path}\\{name}"))
}

/// Deletes a registry value. A value that is already absent is not an error
/// (delete is idempotent, `off` retries steps).
pub fn reg_delete_value(root: &str, path: &str, name: &str) -> Result<()> {
    validate_reg_args(root, path, name)?;
    let out = hidden_str("reg", &["delete", &format!("{root}\\{path}"), "/v", name, "/f"])?;
    if out.status.success() {
        return Ok(());
    }
    // Locale-independent: ask again instead of parsing the error text.
    match reg_get_string(root, path, name)? {
        None => Ok(()),
        Some(_) => {
            let err = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!(
                "не удалось удалить {root}\\{path}\\{name}: {}",
                truncate(err.trim(), 200)
            )
        }
    }
}

pub fn set_clipboard(text: &str) -> bool {
    // The value travels as base64 JSON through the environment, so no quoting
    // rule of PowerShell or cmd can break it.
    let payload = b64_json(&serde_json::json!({ "text": text }));
    powershell("Set-Clipboard -Value $p.text", &[("OBHOD_P", &payload)])
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

#[allow(dead_code)] // used by modules and tests; kept for callers that need a stamp
pub fn timestamp() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_and_split_roundtrip() {
        let cases = [
            "simple",
            "",
            "with space",
            r#"with"quote"#,
            r#"trailing slash\"#,
            r#"C:\path with spaces\file.exe"#,
            r#"--hostlist="C:\my lists\list.txt""#,
            "пробел в кириллице",
            "a\tb",
            r#"\\server\share\file"#,
            r#"ends with two\\"#,
            "quote\"inside",
        ];
        for c in cases {
            let q = quote_win_arg(c);
            let split = split_windows_cmdline(&q);
            assert_eq!(split, vec![c.to_string()], "arg {c:?} quoted as {q:?}");
        }
    }

    #[test]
    fn quote_leaves_simple_args_untouched() {
        assert_eq!(quote_win_arg("--filter-tcp=80"), "--filter-tcp=80");
        assert_eq!(quote_win_arg("C:\\zapret\\bin\\winws.exe"), "C:\\zapret\\bin\\winws.exe");
        assert_eq!(quote_win_arg("a b"), "\"a b\"");
    }

    #[test]
    fn split_parses_a_winws_command_line() {
        let cmd = r#""C:\my tools\bin\winws.exe" --wf-tcp=80,443 --wf-udp=443 --filter-tcp=80 --hostlist="C:\my tools\lists\list.txt" --new --filter-udp=443"#;
        let args = split_windows_cmdline(cmd);
        assert_eq!(
            args,
            vec![
                r"C:\my tools\bin\winws.exe",
                "--wf-tcp=80,443",
                "--wf-udp=443",
                "--filter-tcp=80",
                r"--hostlist=C:\my tools\lists\list.txt",
                "--new",
                "--filter-udp=443",
            ]
        );
    }

    #[test]
    fn split_handles_empty_quoted_argument() {
        assert_eq!(split_windows_cmdline(r#"a "" b"#), vec!["a", "", "b"]);
        assert_eq!(split_windows_cmdline("   "), Vec::<String>::new());
    }

    #[test]
    fn reg_query_output_is_parsed() {
        let out = "\r\nHKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\r\n    TgWsProxy    REG_SZ    \"C:\\tools\\TgWsProxy.exe\"\r\n\r\n";
        assert_eq!(
            parse_reg_query_value(out, "TgWsProxy").as_deref(),
            Some("\"C:\\tools\\TgWsProxy.exe\"")
        );
        assert_eq!(parse_reg_query_value(out, "tgwsproxy").as_deref(), Some("\"C:\\tools\\TgWsProxy.exe\""));
        assert_eq!(parse_reg_query_value(out, "obhod"), None);
        // A header line that merely contains the name must not match.
        assert_eq!(parse_reg_query_value("HKEY_CURRENT_USER\\Run\\TgWsProxy\r\n", "TgWsProxy"), None);
    }

    #[test]
    fn reg_value_kinds_are_not_data() {
        let out = "    Name    REG_EXPAND_SZ    %APPDATA%\\x.exe\r\n";
        assert_eq!(
            parse_reg_query_value(out, "Name").as_deref(),
            Some("%APPDATA%\\x.exe")
        );
    }

    #[test]
    fn checked_command_reports_nonzero_exit() {
        let err = run_checked("reg", &["query", r"HKLM\Software\__obhod_missing_key__"])
            .expect_err("missing registry key must fail");
        let msg = format!("{err:#}");
        assert!(msg.contains("код"), "message should mention the code: {msg}");
    }

    #[test]
    fn checked_command_accepts_success() {
        // `reg query HKLM /ve` is read-only and exists on every Windows.
        run_checked("reg", &["query", "HKLM\\Software", "/ve"]).unwrap();
    }

    #[test]
    fn invalid_reg_arguments_are_rejected_before_spawning() {
        assert!(reg_get_string("HKCU", "", "x").is_err());
        assert!(reg_set_string("HKCU", "Run", "bad\nname", "v").is_err());
        assert!(reg_delete_value("HKCU", "Run", "bad\rname").is_err());
        assert!(reg_set_string("HKCU", "Run", "x", "a\0b").is_err());
    }

    #[test]
    fn base64_helper_still_works() {
        assert_eq!(base64("abc"), "YWJj");
        assert_eq!(base64("a"), "YQ==");
        assert_eq!(base64(""), "");
    }

    #[test]
    fn now_unix_is_sane() {
        assert!(now_unix() > 1_600_000_000);
        assert!(timestamp().parse::<u64>().unwrap() > 1_600_000_000);
    }

    #[test]
    fn powershell_gets_the_payload_through_the_environment() {
        // End-to-end check of the payload channel: the script must see $p.text.
        let payload = b64_json(&serde_json::json!({ "text": "привет ' \" & </script>" }));
        let v = powershell_json("[pscustomobject]@{ ok = $p.text } | ConvertTo-Json -Compress", &[("OBHOD_P", &payload)])
            .expect("powershell payload");
        assert_eq!(
            v.get("ok").and_then(|x| x.as_str()),
            Some("привет ' \" & </script>")
        );
    }

    #[test]
    fn powershell_failure_is_reported() {
        let err = powershell_json("throw 'boom'", &[]).unwrap_err();
        assert!(format!("{err:#}").contains("PowerShell"));
    }
}

//! Self-update from GitHub Releases.
//!
//! On every normal launch we ask GitHub for the latest release and, if it is
//! newer than this build, download `obhod.exe`, swap it with the running file
//! and start the new copy. The old file is renamed (Windows allows renaming a
//! running exe) and removed on the next launch.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

/// Public repository that hosts releases. Must stay public: updates are
/// downloaded without a token.
pub const REPO: &str = "TarKek/obhod";
const ASSET: &str = "obhod.exe";

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches(['v', 'V']);
    let core = core.split(['-', '+']).next().unwrap_or(core);
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next().unwrap_or("0").parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    match (parse_version(latest), parse_version(current)) {
        (Some(l), Some(c)) => l > c,
        _ => false,
    }
}

struct Release {
    tag: String,
    url: String,
    size: u64,
}

/// Latest release, or `None` when the repo has no releases yet.
fn latest_release() -> Result<Option<Release>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(4))
        .connect_timeout(Duration::from_secs(2))
        .user_agent(format!("obhod/{}", current_version()))
        .build()?;
    let resp = client
        .get(format!(
            "https://api.github.com/repos/{REPO}/releases/latest"
        ))
        .header("Accept", "application/vnd.github+json")
        .send()?;
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !resp.status().is_success() {
        crate::logger::info(format!(
            "self-update: GitHub API {}, пробую страницу релизов",
            resp.status()
        ));
        return fallback_release(&client);
    }
    let json: serde_json::Value = resp.json()?;
    let tag = json["tag_name"]
        .as_str()
        .context("в ответе нет tag_name")?
        .to_string();
    let assets = json["assets"].as_array().cloned().unwrap_or_default();
    let asset = assets
        .iter()
        .find(|a| {
            a["name"]
                .as_str()
                .map(|n| n.eq_ignore_ascii_case(ASSET))
                .unwrap_or(false)
        })
        .context("в релизе нет obhod.exe")?;
    let url = asset["browser_download_url"]
        .as_str()
        .context("у файла нет ссылки")?
        .to_string();
    let size = asset["size"].as_u64().unwrap_or(0);
    Ok(Some(Release { tag, url, size }))
}

/// Used when the API is rate-limited or blocked: the releases page still
/// redirects to the latest tag, and assets follow a predictable URL.
fn fallback_release(client: &reqwest::blocking::Client) -> Result<Option<Release>> {
    let tag = crate::util::github_latest_tag(client, REPO)?;
    Ok(Some(Release {
        url: format!("https://github.com/{REPO}/releases/download/{tag}/{ASSET}"),
        tag,
        size: 0,
    }))
}

/// Checks for a newer release. Returns `Ok(Some(tag))` when one exists.
pub fn check() -> Result<Option<String>> {
    Ok(latest_release()?.and_then(|r| {
        if is_newer(&r.tag, current_version()) {
            Some(r.tag)
        } else {
            None
        }
    }))
}

/// Downloads and installs the latest release, then starts the new copy.
/// Returns `true` when the caller should exit (a new process was started).
pub fn check_and_apply(args: &[String]) -> Result<bool> {
    let exe = std::env::current_exe().context("не удалось определить путь к exe")?;
    let dir = exe
        .parent()
        .context("у exe нет родительской папки")?
        .to_path_buf();

    // Leftover from a previous update; the running file no longer uses it.
    let old = dir.join("obhod.old.exe");
    let _ = fs::remove_file(&old);

    let Some(rel) = latest_release()? else {
        return Ok(false);
    };
    if !is_newer(&rel.tag, current_version()) {
        return Ok(false);
    }

    crate::logger::info(format!(
        "self-update: {} -> {}",
        current_version(),
        rel.tag
    ));

    let new = dir.join("obhod.new.exe");
    let _ = fs::remove_file(&new);
    download(&rel.url, &new)?;

    let got = fs::metadata(&new)?.len();
    if rel.size > 0 && got != rel.size {
        let _ = fs::remove_file(&new);
        bail!("скачанный файл повреждён ({got} из {} байт)", rel.size);
    }
    let head = fs::read(&new).unwrap_or_default();
    if head.len() < 2 || &head[..2] != b"MZ" {
        let _ = fs::remove_file(&new);
        bail!("скачанный файл не является программой Windows");
    }

    fs::rename(&exe, &old).context("не удалось переименовать текущий exe")?;
    if let Err(e) = fs::rename(&new, &exe) {
        let _ = fs::rename(&old, &exe);
        return Err(e).context("не удалось заменить exe");
    }

    let mut cmd = Command::new(&exe);
    cmd.args(args).current_dir(&dir);
    let spawned = cmd.spawn();
    if spawned.is_err() {
        // Put the old file back so the user still has a working program.
        let _ = fs::remove_file(&exe);
        let _ = fs::rename(&old, &exe);
    }
    spawned.context("не удалось запустить новую версию")?;
    Ok(true)
}

fn download(url: &str, dest: &Path) -> Result<()> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(120))
        .connect_timeout(Duration::from_secs(5))
        .user_agent(format!("obhod/{}", current_version()))
        .build()?;
    let mut resp = client.get(url).send()?;
    if !resp.status().is_success() {
        bail!("скачивание: HTTP {}", resp.status());
    }
    let mut file = fs::File::create(dest)?;
    std::io::copy(&mut resp, &mut file)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_compare_ignores_prefix_and_suffix() {
        assert!(is_newer("v0.2.0", "0.1.0"));
        assert!(is_newer("0.1.2", "0.1.1"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0-beta", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
        assert!(!is_newer("мусор", "0.1.0"));
    }

    #[test]
    fn parses_missing_patch_as_zero() {
        assert_eq!(parse_version("v1.2"), Some((1, 2, 0)));
        assert_eq!(parse_version("1"), Some((1, 0, 0)));
    }
}
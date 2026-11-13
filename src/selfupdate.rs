//! Self-update from GitHub Releases.
//!
//! On every normal launch we ask GitHub for the latest release and, if it is
//! newer than this build, download `obhod.exe`, verify it, swap it with the
//! running file and start the new copy. The old file is renamed (Windows
//! allows renaming a running exe) and removed on the next launch.
//!
//! Verification (see [`crate::net::trust`]):
//! 1. GitHub API asset `digest` (sha256) when the API provided one;
//! 2. otherwise a signed `obhod-manifest.json` (`sha256`, `version`,
//!    `min_version`) with a detached `obhod-manifest.json.sig`;
//! 3. when neither exists, the update proceeds as `Unverified`: the hash and
//!    the file format are still checked, but nothing claims a signature.
//!
//! Any mismatch (hash, signature, downgrade, incompatible version) aborts the
//! update **before** the running exe is touched. If the post-swap check fails,
//! the previous exe is restored.

use anyhow::{bail, Context, Result};
use std::fs;
use std::io::Read;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

use crate::net::trust::{
    self, digest_matches, normalize_sha256, ManifestCheck, TrustLevel, MANIFEST_ASSET,
    SIGNATURE_ASSET,
};
use crate::net::sha256_file;

/// Public repository that hosts releases. Must stay public: updates are
/// downloaded without a token.
pub const REPO: &str = "TarKek/obhod";
const ASSET: &str = "obhod.exe";
/// Upper bounds for the small verification assets.
const MANIFEST_LIMIT: usize = 64 * 1024;
const SIGNATURE_LIMIT: usize = 8 * 1024;

pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[allow(dead_code)] // public helper, also used by unit tests
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    trust::parse_version(v)
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    trust::version_is_newer(latest, current)
}

#[derive(Debug)]
struct Release {
    tag: String,
    url: String,
    size: u64,
    /// `sha256:<hex>` from the GitHub API asset, when present.
    digest: Option<String>,
    manifest_url: Option<String>,
    signature_url: Option<String>,
}

fn api_client() -> Result<reqwest::blocking::Client> {
    Ok(reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(4))
        .connect_timeout(Duration::from_secs(2))
        .user_agent(format!("obhod/{}", current_version()))
        .build()?)
}

fn asset_url(assets: &[serde_json::Value], name: &str) -> Option<String> {
    assets
        .iter()
        .find(|a| {
            a["name"]
                .as_str()
                .map(|n| n.eq_ignore_ascii_case(name))
                .unwrap_or(false)
        })
        .and_then(|a| a["browser_download_url"].as_str())
        .map(str::to_string)
}

/// Latest release, or `None` when the repo has no releases yet.
fn latest_release() -> Result<Option<Release>> {
    let client = api_client()?;
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
    let digest = asset["digest"]
        .as_str()
        .map(str::to_string)
        .filter(|d| normalize_sha256(d).is_some());
    Ok(Some(Release {
        tag,
        url,
        size,
        digest,
        manifest_url: asset_url(&assets, MANIFEST_ASSET),
        signature_url: asset_url(&assets, SIGNATURE_ASSET),
    }))
}

/// Used when the API is rate-limited or blocked: the releases page still
/// redirects to the latest tag, and assets follow a predictable URL. No digest
/// or manifest is available in this path.
fn fallback_release(client: &reqwest::blocking::Client) -> Result<Option<Release>> {
    let tag = crate::util::github_latest_tag(client, REPO)?;
    Ok(Some(Release {
        url: format!("https://github.com/{REPO}/releases/download/{tag}/{ASSET}"),
        tag,
        size: 0,
        digest: None,
        manifest_url: None,
        signature_url: None,
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

    // Never proceed on a file that is not a complete Windows executable.
    let actual_sha = match verify_download(&new, rel.size) {
        Ok(h) => h,
        Err(e) => {
            let _ = fs::remove_file(&new);
            return Err(e);
        }
    };

    let trust_level = match verify_release(&rel, &actual_sha, MANIFEST_LIMIT, SIGNATURE_LIMIT) {
        Ok(level) => level,
        Err(e) => {
            let _ = fs::remove_file(&new);
            crate::logger::info(format!("self-update: обновление отклонено: {e:#}"));
            return Err(e.context("обновление отклонено, установленная версия сохранена"));
        }
    };
    crate::logger::info(format!(
        "self-update: {} ({}) · sha256 {}",
        trust_level.ru(),
        trust_level_reason(&trust_level),
        &actual_sha[..12]
    ));

    fs::rename(&exe, &old).context("не удалось переименовать текущий exe")?;
    if let Err(e) = fs::rename(&new, &exe) {
        let _ = fs::rename(&old, &exe);
        return Err(e).context("не удалось заменить exe");
    }

    // What actually landed on disk must be the verified bytes.
    match sha256_file(&exe) {
        Ok(h) if h == actual_sha => {}
        _ => {
            let _ = fs::remove_file(&exe);
            let _ = fs::rename(&old, &exe);
            bail!("после замены exe не совпадает с проверенным — вернул прежнюю версию");
        }
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

fn trust_level_reason(level: &TrustLevel) -> &'static str {
    match level {
        TrustLevel::Verified => "подпись проверена",
        TrustLevel::Unverified => "без подписи (ключ не настроен)",
        TrustLevel::Invalid => "проверка не пройдена",
    }
}

/// Checks the downloaded file before it is allowed to replace anything.
fn verify_download(path: &Path, expected_size: u64) -> Result<String> {
    let meta = fs::metadata(path).context("скачанный файл не найден")?;
    if meta.len() < 2 {
        bail!("скачанный файл пуст");
    }
    if expected_size > 0 && meta.len() != expected_size {
        bail!(
            "скачанный файл повреждён ({} из {} байт)",
            meta.len(),
            expected_size
        );
    }
    let mut head = [0u8; 2];
    {
        let mut f = fs::File::open(path)?;
        f.read_exact(&mut head)?;
    }
    if &head != b"MZ" {
        bail!("скачанный файл не является программой Windows");
    }
    sha256_file(path).context("не удалось посчитать sha256")
}

/// Verifies digest/signature/manifest and returns the achieved trust level.
fn verify_release(
    rel: &Release,
    actual_sha: &str,
    manifest_limit: usize,
    signature_limit: usize,
) -> Result<TrustLevel> {
    let client = api_client()?;

    // 1. GitHub API digest, when present.
    if let Some(digest) = rel.digest.as_deref() {
        match digest_matches(Some(digest), actual_sha) {
            Some(true) => crate::logger::info("self-update: sha256 совпадает с digest GitHub"),
            Some(false) => bail!("sha256 не совпадает с digest из GitHub API"),
            None => crate::logger::info("self-update: digest GitHub не разобран, пропускаю"),
        }
    }

    // 2. Signed manifest, when published.
    let Some(manifest_url) = rel.manifest_url.as_deref() else {
        crate::logger::info(
            "self-update: манифест не опубликован — подпись не проверена (Unverified)",
        );
        return Ok(TrustLevel::Unverified);
    };
    let manifest_bytes = download_text(&client, manifest_url, manifest_limit)
        .context("не удалось скачать obhod-manifest.json")?;
    let signature = match rel.signature_url.as_deref() {
        Some(url) => Some(
            download_text(&client, url, signature_limit)
                .context("не удалось скачать подпись манифеста")?,
        ),
        None => None,
    };
    let check: ManifestCheck = trust::verify_manifest_bytes(
        manifest_bytes.as_bytes(),
        signature.as_deref(),
        None,
        current_version(),
        ASSET,
        actual_sha,
    );
    if !check.accepted {
        bail!("{}", check.reason);
    }
    if let Some(m) = check.manifest.as_ref() {
        if !manifest_matches_tag(&m.version, &rel.tag) {
            bail!(
                "манифест описывает версию {}, а релиз — {}",
                m.version,
                rel.tag
            );
        }
    }
    crate::logger::info(format!(
        "self-update: {} · {}",
        check.trust.ru(),
        check.reason
    ));
    Ok(check.trust)
}

fn manifest_matches_tag(manifest_version: &str, tag: &str) -> bool {
    match (
        trust::parse_version(manifest_version),
        trust::parse_version(tag),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn download_text(
    client: &reqwest::blocking::Client,
    url: &str,
    limit: usize,
) -> Result<String> {
    let mut resp = client.get(url).send()?;
    if !resp.status().is_success() {
        bail!("HTTP {} для {url}", resp.status());
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = resp.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > limit {
            bail!("файл проверки больше {limit} байт");
        }
    }
    String::from_utf8(buf).context("файл проверки не является текстом UTF-8")
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

    #[test]
    fn verify_download_checks_size_and_format() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("obhod.exe");
        fs::write(&good, b"MZ payload").unwrap();
        let sha = verify_download(&good, 10).unwrap();
        assert_eq!(sha, crate::net::sha256_hex(b"MZ payload"));

        assert!(verify_download(&good, 999).is_err());

        let text = dir.path().join("text.exe");
        fs::write(&text, b"not a program").unwrap();
        assert!(verify_download(&text, 0).is_err());

        let empty = dir.path().join("empty.exe");
        fs::write(&empty, b"").unwrap();
        assert!(verify_download(&empty, 0).is_err());
    }

    #[test]
    fn manifest_must_match_the_release_tag() {
        assert!(manifest_matches_tag("v0.2.0", "v0.2.0"));
        assert!(manifest_matches_tag("0.2.0", "v0.2"));
        assert!(!manifest_matches_tag("0.3.0", "v0.2.0"));
        assert!(!manifest_matches_tag("мусор", "v0.2.0"));
    }

    #[test]
    fn missing_manifest_means_unverified_not_verified() {
        let rel = Release {
            tag: "v0.2.0".into(),
            url: String::new(),
            size: 0,
            digest: None,
            manifest_url: None,
            signature_url: None,
        };
        // No API call happens when there is no manifest URL.
        let level = verify_release(&rel, &"a".repeat(64), 1024, 1024).unwrap();
        assert_eq!(level, TrustLevel::Unverified);
    }
}
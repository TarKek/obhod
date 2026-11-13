//! `hosts` file editing: backups, idempotent markers, verified atomic replace.
//!
//! Safety rules baked into this module:
//! * **Read first, abort on failure.** If the current hosts file cannot be
//!   read, nothing is written — never replace a file we could not read with a
//!   file that contains only our block.
//! * **Backup before every change**, with a timestamped name; the backup is
//!   created before the write and its existence is verified.
//! * **Markers are idempotent.** Our block is delimited by
//!   [`MARK_START`]/[`MARK_END`]; a second run replaces it in place instead of
//!   appending a copy, and re-running with the same list is a no-op (no write,
//!   no new backup).
//! * **The user's lines are never touched.** Before writing, the result is
//!   re-parsed and compared: every non-block line must be byte-identical to the
//!   original, in the same order. Unbalanced markers abort instead of guessing.
//! * **BOM and line endings are preserved** (`\r\n` stays `\r\n`, UTF-8 BOM
//!   stays). A file with mixed endings is normalised to the dominant one —
//!   line *text* is never changed. UTF-16/undecodable files abort instead of
//!   being rewritten.
//! * **Atomic replace** (temp file + rename) and **verify after write**.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

use super::fsx::{self, FsIo};

pub const MARK_START: &str = "# >>> obhod-ads >>>";
pub const MARK_END: &str = "# <<< obhod-ads <<<";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Eol {
    Crlf,
    Lf,
}

impl Eol {
    pub fn as_str(self) -> &'static str {
        match self {
            Eol::Crlf => "\r\n",
            Eol::Lf => "\n",
        }
    }
}

/// A hosts file split into lines, remembering how to write it back unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostsText {
    pub bom: bool,
    pub eol: Eol,
    /// Lines without terminators.
    pub lines: Vec<String>,
    pub trailing_newline: bool,
}

impl HostsText {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(&[0xFF, 0xFE]) || bytes.starts_with(&[0xFE, 0xFF]) {
            anyhow::bail!("hosts в кодировке UTF-16 — не трогаю, чтобы не испортить");
        }
        let (bom, body) = match bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
            Some(rest) => (true, rest),
            None => (false, bytes),
        };
        let text = std::str::from_utf8(body)
            .map_err(|_| anyhow::anyhow!("hosts не в кодировке UTF-8 — не трогаю"))?;
        let eol = if text.contains("\r\n") {
            Eol::Crlf
        } else {
            Eol::Lf
        };
        let trailing_newline = text.ends_with('\n');
        let mut lines: Vec<String> = text
            .split('\n')
            .map(|l| l.trim_end_matches('\r').to_string())
            .collect();
        if trailing_newline {
            lines.pop();
        }
        if text.is_empty() {
            lines.clear();
        }
        Ok(Self {
            bom,
            eol,
            lines,
            trailing_newline,
        })
    }

    pub fn render(&self) -> Vec<u8> {
        let mut s = String::new();
        for (i, line) in self.lines.iter().enumerate() {
            if i > 0 {
                s.push_str(self.eol.as_str());
            }
            s.push_str(line);
        }
        if self.trailing_newline && !self.lines.is_empty() {
            s.push_str(self.eol.as_str());
        }
        let mut out = Vec::with_capacity(s.len() + 3);
        if self.bom {
            out.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
        }
        out.extend_from_slice(s.as_bytes());
        out
    }

    /// Byte range (inclusive) of our marked block, or `None` if absent.
    /// Unbalanced markers are an error: we refuse to guess what is ours.
    pub fn block_range(&self) -> Result<Option<(usize, usize)>> {
        let mut start = None;
        let mut end = None;
        for (i, line) in self.lines.iter().enumerate() {
            let t = line.trim();
            if t == MARK_START {
                if start.is_some() {
                    anyhow::bail!("в hosts два начала блока — правлю вручную не буду");
                }
                start = Some(i);
            } else if t == MARK_END {
                if start.is_none() {
                    anyhow::bail!("в hosts есть конец блока без начала — не трогаю");
                }
                if end.is_some() {
                    anyhow::bail!("в hosts два конца блока — не трогаю");
                }
                end = Some(i);
            } else if start.is_some() && end.is_none() && t.contains(MARK_START) {
                anyhow::bail!("в hosts вложенный маркер блока — не трогаю");
            }
        }
        match (start, end) {
            (None, None) => Ok(None),
            (Some(a), Some(b)) => {
                if b < a {
                    anyhow::bail!("маркеры блока hosts стоят в неверном порядке");
                }
                Ok(Some((a, b)))
            }
            (Some(_), None) => anyhow::bail!("блок в hosts не закрыт — не трогаю"),
            (None, Some(_)) => anyhow::bail!("в hosts есть конец блока без начала — не трогаю"),
        }
    }

    /// User lines only: everything outside our block.
    pub fn user_lines(&self) -> Result<Vec<String>> {
        match self.block_range()? {
            None => Ok(self.lines.clone()),
            Some((a, b)) => {
                let mut v = self.lines[..a].to_vec();
                v.extend_from_slice(&self.lines[b + 1..]);
                Ok(v)
            }
        }
    }

    pub fn has_block(&self) -> bool {
        matches!(self.block_range(), Ok(Some(_)))
    }
}

/// What actually happened, for logging and journaling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub changed: bool,
    pub backup: Option<PathBuf>,
    pub before_hash: String,
    pub after_hash: String,
    /// Number of entries in our block after the operation.
    pub entries: usize,
}

/// Read the hosts file. Missing/unreadable is an error: callers must abort.
pub fn read(io: &dyn FsIo, path: &Path) -> Result<HostsText> {
    let bytes = io
        .read(path)
        .with_context(|| format!("не удалось прочитать {} — hosts не изменён", path.display()))?;
    HostsText::parse(&bytes).with_context(|| format!("{} не разобран", path.display()))
}

fn validate_entries(entries: &[String]) -> Result<()> {
    for e in entries {
        if e.trim().is_empty() {
            anyhow::bail!("пустая строка в блоке hosts");
        }
        if e.contains('\n') || e.contains('\r') || e.contains('\0') {
            anyhow::bail!("строка блока hosts содержит перевод строки: {e:?}");
        }
        if e.trim() == MARK_START || e.trim() == MARK_END {
            anyhow::bail!("строка блока hosts совпадает с маркером");
        }
    }
    Ok(())
}

/// Unique timestamped backup path inside `dir`.
pub fn backup_path(io: &dyn FsIo, dir: &Path, stamp: &str) -> PathBuf {
    let base = format!("hosts.backup-{stamp}");
    let mut p = dir.join(&base);
    let mut n = 1;
    while io.exists(&p) {
        p = dir.join(format!("{base}-{n}"));
        n += 1;
        if n > 999 {
            break;
        }
    }
    p
}

/// Write our block into hosts (replacing an older one in place).
pub fn apply_block(
    io: &dyn FsIo,
    path: &Path,
    backup_dir: &Path,
    stamp: &str,
    entries: &[String],
) -> Result<Outcome> {
    let backup = backup_path(io, backup_dir, stamp);
    apply_block_to(io, path, &backup, entries)
}

/// Like [`apply_block`], but the caller decides the backup path. Used by the
/// transaction so the undo record can point at the backup *before* the write.
pub fn apply_block_to(
    io: &dyn FsIo,
    path: &Path,
    backup: &Path,
    entries: &[String],
) -> Result<Outcome> {
    validate_entries(entries)?;
    let original_bytes = io
        .read(path)
        .with_context(|| format!("не удалось прочитать {} — hosts не изменён", path.display()))?;
    let text = HostsText::parse(&original_bytes)
        .with_context(|| format!("{} не разобран — hosts не изменён", path.display()))?;
    let user = text.user_lines()?;

    let mut block = Vec::with_capacity(entries.len() + 2);
    block.push(MARK_START.to_string());
    block.extend(entries.iter().cloned());
    block.push(MARK_END.to_string());

    let mut lines = match text.block_range()? {
        Some((a, b)) => {
            let mut v = text.lines[..a].to_vec();
            v.extend(block.iter().cloned());
            v.extend_from_slice(&text.lines[b + 1..]);
            v
        }
        None => {
            let mut v = text.lines.clone();
            v.extend(block.iter().cloned());
            v
        }
    };
    if lines.is_empty() {
        lines = block.clone();
    }
    let updated = HostsText {
        lines,
        // A file without a final newline gets one: hosts entries need it.
        trailing_newline: true,
        ..text.clone()
    };

    // Pre-write verification: nothing of the user's was lost or reordered.
    let reparsed = HostsText::parse(&updated.render())?;
    if reparsed.user_lines()? != user {
        anyhow::bail!("внутренняя проверка: строки пользователя изменились — запись отменена");
    }
    let range = reparsed
        .block_range()?
        .ok_or_else(|| anyhow::anyhow!("внутренняя проверка: блок не найден"))?;
    let written: Vec<String> = reparsed.lines[range.0 + 1..range.1].to_vec();
    if written != entries {
        anyhow::bail!("внутренняя проверка: содержимое блока не совпало");
    }

    write_verified(
        io,
        path,
        backup,
        &original_bytes,
        &updated.render(),
        entries.len(),
    )
}

/// Remove only our block; every other line stays exactly as it was.
pub fn remove_our_block(
    io: &dyn FsIo,
    path: &Path,
    backup_dir: &Path,
    stamp: &str,
) -> Result<Outcome> {
    let backup = backup_path(io, backup_dir, stamp);
    remove_block_to(io, path, &backup)
}

/// Like [`remove_our_block`] with an explicit backup path.
pub fn remove_block_to(io: &dyn FsIo, path: &Path, backup: &Path) -> Result<Outcome> {
    let original_bytes = io
        .read(path)
        .with_context(|| format!("не удалось прочитать {} — hosts не изменён", path.display()))?;
    let text = HostsText::parse(&original_bytes)
        .with_context(|| format!("{} не разобран — hosts не изменён", path.display()))?;
    let Some((a, b)) = text.block_range()? else {
        return Ok(Outcome {
            changed: false,
            backup: None,
            before_hash: fsx::sha256_short(&original_bytes),
            after_hash: fsx::sha256_short(&original_bytes),
            entries: 0,
        });
    };
    let user = text.user_lines()?;
    let mut lines = text.lines[..a].to_vec();
    lines.extend_from_slice(&text.lines[b + 1..]);
    let updated = HostsText {
        lines,
        ..text.clone()
    };
    let rendered = updated.render();

    let reparsed = HostsText::parse(&rendered)?;
    if reparsed.block_range()?.is_some() {
        anyhow::bail!("внутренняя проверка: блок остался после удаления");
    }
    if reparsed.lines != user {
        anyhow::bail!("внутренняя проверка: строки пользователя изменились — запись отменена");
    }
    write_verified(io, path, backup, &original_bytes, &rendered, 0)
}

fn write_verified(
    io: &dyn FsIo,
    path: &Path,
    backup: &Path,
    original: &[u8],
    new_bytes: &[u8],
    entries: usize,
) -> Result<Outcome> {
    let before_hash = fsx::sha256_short(original);
    let after_hash = fsx::sha256_short(new_bytes);
    if original == new_bytes {
        // Idempotent: same content, no write, no extra backup files.
        return Ok(Outcome {
            changed: false,
            backup: None,
            before_hash,
            after_hash,
            entries,
        });
    }

    // 1. Backup first, always, before touching the file.
    if let Some(dir) = backup.parent() {
        io.create_dir_all(dir)
            .with_context(|| format!("не удалось создать {}", dir.display()))?;
    }
    fsx::backup_copy(io, path, backup)?;
    let backed_up = io
        .read(backup)
        .with_context(|| format!("резервная копия {} не читается", backup.display()))?;
    if backed_up != original {
        anyhow::bail!(
            "резервная копия {} не совпала с оригиналом — запись отменена",
            backup.display()
        );
    }

    // 2. Atomic replace.
    io.write_atomic(path, new_bytes)
        .with_context(|| format!("не удалось записать {}", path.display()))?;

    // 3. Verify the result on disk.
    let written = io
        .read(path)
        .with_context(|| format!("не удалось перечитать {} после записи", path.display()))?;
    if written != new_bytes {
        anyhow::bail!(
            "проверка после записи не прошла: содержимое {} не совпало",
            path.display()
        );
    }

    Ok(Outcome {
        changed: true,
        backup: Some(backup.to_path_buf()),
        before_hash,
        after_hash,
        entries,
    })
}

/// Re-read the file and confirm our block is exactly `entries` (verify phase).
pub fn verify_block(io: &dyn FsIo, path: &Path, entries: &[String]) -> Result<()> {
    let bytes = io
        .read(path)
        .with_context(|| format!("не удалось перечитать {}", path.display()))?;
    let text = HostsText::parse(&bytes)?;
    let (a, b) = text
        .block_range()?
        .ok_or_else(|| anyhow::anyhow!("блок не найден в hosts после записи"))?;
    let written: Vec<String> = text.lines[a + 1..b].to_vec();
    if written != entries {
        anyhow::bail!(
            "содержимое блока в hosts не совпало ({} строк вместо {})",
            written.len(),
            entries.len()
        );
    }
    Ok(())
}

/// Re-read the file and confirm our block is gone (verify phase of a restore).
pub fn verify_no_block(io: &dyn FsIo, path: &Path) -> Result<()> {
    let bytes = io
        .read(path)
        .with_context(|| format!("не удалось перечитать {}", path.display()))?;
    let text = HostsText::parse(&bytes)?;
    if text.block_range()?.is_some() {
        anyhow::bail!("наш блок всё ещё в hosts после удаления");
    }
    Ok(())
}

/// Turn an ad/tracker list (`0.0.0.0 example.com`) into hosts entries.
///
/// Keeps only blocking lines, lowercases the host, dedupes and drops the
/// OS-critical names. Deterministic output so re-runs produce identical files.
pub fn entries_from_list(text: &str) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let mut it = l.split_whitespace();
        let (Some(ip), Some(host)) = (it.next(), it.next()) else {
            continue;
        };
        if ip != "0.0.0.0" && ip != "127.0.0.1" {
            continue;
        }
        let host = host.to_ascii_lowercase();
        if host.is_empty() || host.contains('/') || host == "localhost" || host.ends_with(".local")
        {
            continue;
        }
        // A trailing inline comment is fine, but a bare name is what we want.
        if !host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '*'))
        {
            continue;
        }
        seen.insert(format!("0.0.0.0 {host}"));
    }
    seen.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::fsx::testing::MemFs;

    const HOSTS: &str = "127.0.0.1 localhost\r\n::1 localhost\r\n10.0.0.5 nas\r\n";

    fn entries() -> Vec<String> {
        vec![
            "0.0.0.0 ads.example".to_string(),
            "0.0.0.0 tracker.example".to_string(),
        ]
    }

    #[test]
    fn applies_block_and_keeps_every_user_line_and_crlf() {
        let fs = MemFs::new();
        let hosts = Path::new(r"C:\Windows\System32\drivers\etc\hosts");
        let data = Path::new(r"C:\tools\data");
        fs.put(hosts, HOSTS);
        let out = apply_block(&fs, hosts, data, "20260101-120000", &entries()).unwrap();
        assert!(out.changed);
        let text = fs.text(hosts).unwrap();
        assert!(text.starts_with("127.0.0.1 localhost\r\n::1 localhost\r\n10.0.0.5 nas\r\n"));
        assert!(text.contains(&format!("{MARK_START}\r\n0.0.0.0 ads.example\r\n")));
        assert!(text.ends_with(&format!("{MARK_END}\r\n")));
        assert!(
            !text.contains("\n0.0.0.0 ads.example\n"),
            "LF leaked into CRLF file"
        );
        let parsed = HostsText::parse(&fs.get(hosts).unwrap()).unwrap();
        assert_eq!(parsed.eol, Eol::Crlf);
        assert!(!parsed.bom);
        assert_eq!(
            parsed.user_lines().unwrap(),
            vec!["127.0.0.1 localhost", "::1 localhost", "10.0.0.5 nas"]
        );
        // Backup holds the untouched original.
        assert_eq!(
            fs.get(out.backup.as_ref().unwrap()).unwrap(),
            HOSTS.as_bytes()
        );
    }

    #[test]
    fn second_run_is_a_noop() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        let data = Path::new("data");
        fs.put(hosts, HOSTS);
        let first = apply_block(&fs, hosts, data, "stamp1", &entries()).unwrap();
        let writes = fs.write_count();
        let second = apply_block(&fs, hosts, data, "stamp2", &entries()).unwrap();
        assert!(!second.changed, "re-applying the same block must not write");
        assert!(second.backup.is_none());
        assert_eq!(fs.write_count(), writes, "no extra write");
        assert_ne!(first.after_hash, first.before_hash);
        assert_eq!(first.after_hash, second.after_hash);
        // No duplicate block.
        let text = fs.text(hosts).unwrap();
        assert_eq!(text.matches(MARK_START).count(), 1);
    }

    #[test]
    fn replacing_an_old_block_keeps_position_and_single_copy() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        let data = Path::new("data");
        fs.put(
            hosts,
            format!("# top\n127.0.0.1 localhost\n{MARK_START}\n0.0.0.0 old.example\n{MARK_END}\n# bottom\n10.0.0.9 nas\n"),
        );
        let out = apply_block(&fs, hosts, data, "s", &entries()).unwrap();
        assert!(out.changed);
        let text = fs.text(hosts).unwrap();
        assert_eq!(text.matches(MARK_START).count(), 1);
        assert!(!text.contains("old.example"));
        let parsed = HostsText::parse(&fs.get(hosts).unwrap()).unwrap();
        assert_eq!(
            parsed.user_lines().unwrap(),
            vec!["# top", "127.0.0.1 localhost", "# bottom", "10.0.0.9 nas"]
        );
        assert_eq!(parsed.lines[2], MARK_START, "block stayed in place");
    }

    #[test]
    fn restore_removes_only_our_block() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        let data = Path::new("data");
        fs.put(hosts, HOSTS);
        apply_block(&fs, hosts, data, "s1", &entries()).unwrap();
        let out = remove_our_block(&fs, hosts, data, "s2").unwrap();
        assert!(out.changed);
        let text = fs.text(hosts).unwrap();
        assert!(!text.contains(MARK_START));
        assert_eq!(text, HOSTS);
        // Nothing to remove the second time.
        let again = remove_our_block(&fs, hosts, data, "s3").unwrap();
        assert!(!again.changed);
        assert!(again.backup.is_none());
    }

    #[test]
    fn unreadable_hosts_aborts_without_writing() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        fs.deny_read(hosts);
        let err = apply_block(&fs, hosts, Path::new("data"), "s", &entries()).unwrap_err();
        assert!(format!("{err:#}").contains("не удалось прочитать"));
        assert_eq!(fs.write_count(), 0, "nothing may be written");
        assert!(fs.get(hosts).is_none());
    }

    #[test]
    fn missing_hosts_aborts_instead_of_writing_only_our_block() {
        let fs = MemFs::new();
        let err =
            apply_block(&fs, Path::new("hosts"), Path::new("data"), "s", &entries()).unwrap_err();
        assert!(format!("{err:#}").contains("не удалось прочитать"));
        assert_eq!(fs.write_count(), 0);
    }

    #[test]
    fn write_failure_leaves_file_untouched_and_backup_present() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        fs.put(hosts, HOSTS);
        fs.deny_write(hosts);
        let err = apply_block(&fs, hosts, Path::new("data"), "s", &entries()).unwrap_err();
        assert!(format!("{err:#}").contains("не удалось записать"));
        assert_eq!(fs.get(hosts).unwrap(), HOSTS.as_bytes());
        // The backup was made before the failed write, so nothing was lost.
        assert_eq!(fs.text(Path::new("data/hosts.backup-s")).unwrap(), HOSTS);
    }

    #[test]
    fn unbalanced_markers_abort() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        fs.put(
            hosts,
            format!("127.0.0.1 localhost\n{MARK_START}\n0.0.0.0 x\n"),
        );
        let err = apply_block(&fs, hosts, Path::new("data"), "s", &entries()).unwrap_err();
        assert!(format!("{err:#}").contains("не закрыт"));
        assert_eq!(fs.write_count(), 0);

        let fs2 = MemFs::new();
        fs2.put(hosts, format!("127.0.0.1 localhost\n{MARK_END}\n"));
        let err = remove_our_block(&fs2, hosts, Path::new("data"), "s").unwrap_err();
        assert!(format!("{err:#}").contains("без начала"));
        assert_eq!(fs2.write_count(), 0);
    }

    #[test]
    fn bom_is_preserved_and_utf16_is_refused() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        let mut with_bom = vec![0xEF, 0xBB, 0xBF];
        with_bom.extend_from_slice(b"127.0.0.1 localhost\n");
        fs.put(hosts, with_bom.clone());
        apply_block(&fs, hosts, Path::new("data"), "s", &entries()).unwrap();
        let after = fs.get(hosts).unwrap();
        assert!(after.starts_with(&[0xEF, 0xBB, 0xBF]));
        let parsed = HostsText::parse(&after).unwrap();
        assert!(parsed.bom);

        let fs2 = MemFs::new();
        fs2.put(hosts, vec![0xFF, 0xFE, b'a', 0]);
        let err = apply_block(&fs2, hosts, Path::new("data"), "s", &entries()).unwrap_err();
        assert!(format!("{err:#}").contains("UTF-16"));
        assert_eq!(fs2.write_count(), 0);
    }

    #[test]
    fn entries_are_sanitized_and_deduped() {
        let raw = "\
# comment
0.0.0.0 Ads.Example
127.0.0.1 tracker.example
0.0.0.0 ads.example
0.0.0.0 localhost
0.0.0.0 bad/name
1.2.3.4 notblocked.example
0.0.0.0 printer.local
";
        let e = entries_from_list(raw);
        assert_eq!(e, vec!["0.0.0.0 ads.example", "0.0.0.0 tracker.example"]);
        assert!(validate_entries(&e).is_ok());
        assert!(validate_entries(&[format!("0.0.0.0 x\n{MARK_END}")]).is_err());
    }

    #[test]
    fn backup_names_never_collide() {
        let fs = MemFs::new();
        let dir = Path::new("data");
        fs.put(Path::new("data/hosts.backup-20260101"), b"a");
        let p = backup_path(&fs, dir, "20260101");
        assert_eq!(p, Path::new("data/hosts.backup-20260101-1"));
        fs.put(&p, b"b");
        let p2 = backup_path(&fs, dir, "20260101");
        assert_eq!(p2, Path::new("data/hosts.backup-20260101-2"));
    }

    #[test]
    fn parse_render_roundtrip() {
        for raw in [
            "",
            "\n",
            "a",
            "a\n",
            "a\r\nb\r\n",
            "\r\n\r\n",
            "x\r\ny\r\nz",
        ] {
            let parsed = HostsText::parse(raw.as_bytes()).unwrap();
            assert_eq!(
                String::from_utf8(parsed.render()).unwrap(),
                raw,
                "roundtrip failed for {raw:?}"
            );
        }
    }

    #[test]
    fn mixed_line_endings_are_normalised_without_losing_text() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        fs.put(hosts, "a\r\nb\nc\r\n");
        apply_block(&fs, hosts, Path::new("data"), "s", &entries()).unwrap();
        let parsed = HostsText::parse(&fs.get(hosts).unwrap()).unwrap();
        assert_eq!(parsed.eol, Eol::Crlf);
        assert_eq!(parsed.user_lines().unwrap(), vec!["a", "b", "c"]);
    }

    #[test]
    fn no_trailing_newline_file_gets_one_after_block() {
        let fs = MemFs::new();
        let hosts = Path::new("hosts");
        fs.put(hosts, "127.0.0.1 localhost");
        apply_block(&fs, hosts, Path::new("data"), "s", &entries()).unwrap();
        let text = fs.text(hosts).unwrap();
        assert!(text.ends_with(&format!("{MARK_END}\n")));
        let parsed = HostsText::parse(&fs.get(hosts).unwrap()).unwrap();
        assert_eq!(parsed.user_lines().unwrap(), vec!["127.0.0.1 localhost"]);
    }
}

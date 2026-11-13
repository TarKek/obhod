//! Filesystem primitives for the system layer.
//!
//! Everything that matters goes through [`write_atomic`]: a temporary file in
//! the destination directory, `write_all` + `sync_all`, then `rename` over the
//! target. On Windows `std::fs::rename` maps to
//! `MoveFileExW(.., MOVEFILE_REPLACE_EXISTING)`, so the replacement itself is
//! atomic for files on the same volume. A crash therefore leaves either the old
//! or the new file, never a half-written one.
//!
//! All real IO is hidden behind [`FsIo`] so tests can inject failures (locked
//! files, permission denied, failing disks) without touching the machine.

use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Injectable filesystem. Implemented by [`RealFs`] in production and by
/// in-memory/faulty doubles in tests.
pub trait FsIo: Send + Sync {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>>;
    /// Replace `path` atomically with `data`.
    fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()>;
    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64>;
    fn exists(&self, path: &Path) -> bool;
    fn remove(&self, path: &Path) -> io::Result<()>;
    fn create_dir_all(&self, path: &Path) -> io::Result<()>;
}

/// The real Windows filesystem.
pub struct RealFs;

impl RealFs {
    pub fn read(path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
        write_atomic(path, data)
    }

    pub fn copy(from: &Path, to: &Path) -> io::Result<u64> {
        fs::copy(from, to)
    }

    pub fn exists(path: &Path) -> bool {
        path.exists()
    }

    pub fn remove(path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    pub fn create_dir_all(path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }
}

impl FsIo for RealFs {
    fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
        fs::read(path)
    }

    fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        write_atomic(path, data)
    }

    fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
        fs::copy(from, to)
    }

    fn exists(&self, path: &Path) -> bool {
        path.exists()
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    fn create_dir_all(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(path)
    }
}

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// A unique temporary sibling of `path` (same directory, therefore same volume).
pub fn temp_sibling(path: &Path) -> PathBuf {
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "tmp".to_string());
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    dir.join(format!(
        ".{name}.obhod-tmp-{}-{seq}",
        std::process::id()
    ))
}

/// Atomic file replace: temp file in the same directory, fsync, rename.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;
    let tmp = temp_sibling(path);
    let res = (|| -> io::Result<()> {
        {
            let mut f = File::create(&tmp)?;
            f.write_all(data)?;
            f.flush()?;
            // fsync: a crash right after rename must not leave zero bytes.
            f.sync_all()?;
        }
        fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res
}

/// Read a whole file, mapping "not found" into `Ok(None)`.
pub fn try_read(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn read_text(io: &dyn FsIo, path: &Path) -> Result<String> {
    let bytes = io
        .read(path)
        .with_context(|| format!("не удалось прочитать {}", path.display()))?;
    String::from_utf8(bytes)
        .with_context(|| format!("{} не в кодировке UTF-8", path.display()))
}

/// Copies `src` to `dst` without ever clobbering an existing backup.
///
/// Returns `dst` on success. `dst` must not exist; callers build unique names
/// with a timestamp, this just refuses to lose an older backup silently.
pub fn backup_copy(io: &dyn FsIo, src: &Path, dst: &Path) -> Result<PathBuf> {
    if io.exists(dst) {
        anyhow::bail!("резервная копия {} уже существует", dst.display());
    }
    if let Some(dir) = dst.parent() {
        io.create_dir_all(dir)
            .with_context(|| format!("не удалось создать {}", dir.display()))?;
    }
    io.copy(src, dst)
        .with_context(|| format!("не удалось сохранить копию {}", dst.display()))?;
    Ok(dst.to_path_buf())
}

/// Short, stable content hash used in journal entries and log lines.
pub fn sha256_short(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(16);
    for b in digest.iter().take(8) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory filesystem with fault injection, for tests only.
    #[derive(Default)]
    pub struct MemFs {
        pub files: Mutex<HashMap<PathBuf, Vec<u8>>>,
        /// Paths that will fail on read, with the error kind to return.
        pub fail_read: Mutex<HashMap<PathBuf, io::ErrorKind>>,
        /// Paths that will fail on write.
        pub fail_write: Mutex<HashMap<PathBuf, io::ErrorKind>>,
        pub writes: Mutex<usize>,
    }

    impl MemFs {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn put(&self, path: &Path, data: impl Into<Vec<u8>>) {
            self.files
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), data.into());
        }

        pub fn get(&self, path: &Path) -> Option<Vec<u8>> {
            self.files.lock().unwrap().get(path).cloned()
        }

        pub fn text(&self, path: &Path) -> Option<String> {
            self.get(path).map(|b| String::from_utf8_lossy(&b).to_string())
        }

        pub fn write_count(&self) -> usize {
            *self.writes.lock().unwrap()
        }

        pub fn deny_read(&self, path: &Path) {
            self.fail_read
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), io::ErrorKind::PermissionDenied);
        }

        pub fn deny_write(&self, path: &Path) {
            self.fail_write
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), io::ErrorKind::PermissionDenied);
        }
    }

    impl FsIo for MemFs {
        fn read(&self, path: &Path) -> io::Result<Vec<u8>> {
            if let Some(kind) = self.fail_read.lock().unwrap().get(path) {
                return Err(io::Error::new(*kind, "injected read failure"));
            }
            self.files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not found"))
        }

        fn write_atomic(&self, path: &Path, data: &[u8]) -> io::Result<()> {
            if let Some(kind) = self.fail_write.lock().unwrap().get(path) {
                return Err(io::Error::new(*kind, "injected write failure"));
            }
            *self.writes.lock().unwrap() += 1;
            self.files
                .lock()
                .unwrap()
                .insert(path.to_path_buf(), data.to_vec());
            Ok(())
        }

        fn copy(&self, from: &Path, to: &Path) -> io::Result<u64> {
            let data = self.read(from)?;
            let len = data.len() as u64;
            self.write_atomic(to, &data)?;
            Ok(len)
        }

        fn exists(&self, path: &Path) -> bool {
            self.files.lock().unwrap().contains_key(path)
        }

        fn remove(&self, path: &Path) -> io::Result<()> {
            self.files.lock().unwrap().remove(path);
            Ok(())
        }

        fn create_dir_all(&self, _path: &Path) -> io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_and_leaves_no_temp() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("cfg.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        let left: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n.contains("obhod-tmp"))
            .collect();
        assert!(left.is_empty(), "temporary files left behind: {left:?}");
    }

    #[test]
    fn atomic_write_creates_parent_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a").join("b").join("c.txt");
        write_atomic(&p, b"x").unwrap();
        assert_eq!(fs::read_to_string(&p).unwrap(), "x");
    }

    #[test]
    fn backup_copy_refuses_to_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("hosts");
        let dst = dir.path().join("hosts.backup");
        fs::write(&src, b"original").unwrap();
        fs::write(&dst, b"older").unwrap();
        let err = backup_copy(&RealFs, &src, &dst).unwrap_err();
        assert!(format!("{err:#}").contains("уже существует"));
        assert_eq!(fs::read(&dst).unwrap(), b"older");
    }

    #[test]
    fn short_hash_is_stable_and_short() {
        assert_eq!(sha256_short(b"abc"), sha256_short(b"abc"));
        assert_ne!(sha256_short(b"abc"), sha256_short(b"abd"));
        assert_eq!(sha256_short(b"abc").len(), 16);
    }

    #[test]
    fn mem_fs_injects_read_errors() {
        let fs = testing::MemFs::new();
        let p = Path::new("C:/fake/hosts");
        fs.deny_read(p);
        assert!(fs.read(p).is_err());
        assert_eq!(fs.write_count(), 0);
    }
}
use std::fs::{create_dir_all, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

static LOG_PATH: Mutex<Option<PathBuf>> = Mutex::new(None);

const MAX_LOG_BYTES: u64 = 2 * 1024 * 1024;

#[repr(C)]
struct SystemTime {
    year: u16,
    month: u16,
    day_of_week: u16,
    day: u16,
    hour: u16,
    minute: u16,
    second: u16,
    milliseconds: u16,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetLocalTime(out: *mut SystemTime);
}

/// Starts logging to the given file. Keeps one previous file around when the
/// current log grows past 2 MB.
pub fn init(path: PathBuf) {
    if let Some(dir) = path.parent() {
        let _ = create_dir_all(dir);
    }
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > MAX_LOG_BYTES {
            let backup = path.with_extension("log.1");
            let _ = std::fs::remove_file(&backup);
            let _ = std::fs::rename(&path, backup);
        }
    }
    if let Ok(mut guard) = LOG_PATH.lock() {
        *guard = Some(path);
    }
    info("================ obhod session ================");
}

pub fn path() -> Option<PathBuf> {
    LOG_PATH.lock().ok().and_then(|g| g.clone())
}

pub fn info(msg: impl AsRef<str>) {
    let Some(path) = path() else {
        return;
    };
    if let Ok(mut f) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(f, "[{}] {}", timestamp(), msg.as_ref());
    }
}

pub fn stamp() -> String {
    let mut st = SystemTime {
        year: 0,
        month: 0,
        day_of_week: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        milliseconds: 0,
    };
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        st.year, st.month, st.day, st.hour, st.minute, st.second
    )
}

fn timestamp() -> String {
    let mut st = SystemTime {
        year: 0,
        month: 0,
        day_of_week: 0,
        day: 0,
        hour: 0,
        minute: 0,
        second: 0,
        milliseconds: 0,
    };
    unsafe { GetLocalTime(&mut st) };
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        st.year, st.month, st.day, st.hour, st.minute, st.second, st.milliseconds
    )
}
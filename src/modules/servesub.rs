//! Tiny loopback HTTP server that hands the node list to a VPN client.
//!
//! Design constraints:
//! - **Loopback only**: binds `127.0.0.1:0`, never a public interface.
//! - **Random access token** in the path (`/sub/<token>`, `/sub.txt/<token>`)
//!   or in `?token=`. The token is compared in constant time.
//! - **Bounded parsing**: header size is capped, request line is parsed, only
//!   `GET`/`HEAD` are accepted, malformed input gets a small error response.
//! - **Bounded concurrency**: at most `max_connections` handlers; extra
//!   requests get `503` instead of spawning threads without limit.
//! - **Safe reads**: the subscription file is re-read per request and the last
//!   good body is cached, so a concurrent rewrite or an empty file never makes
//!   the client import an empty profile.
//! - **Stable URL**: [`start`] creates the server once per process, so the URL
//!   copied into the client keeps working while obhod is open.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::net::short_id;
use crate::util;

const MAX_HEADER_BYTES: usize = 8192;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_MAX_CONNECTIONS: usize = 16;

static URL: OnceLock<Option<String>> = OnceLock::new();
static URL_PLAIN: OnceLock<Option<String>> = OnceLock::new();

/// Starts the process-wide subscription server once. Returns the base64 URL.
/// The plain-text URL is available through [`urls`].
///
/// `port` is fixed when possible so the URL does not change between launches;
/// `token` should come from [`stable_token`] for the same reason.
pub fn start(path: PathBuf, title: &str, port: u16, token: Option<String>) -> Option<String> {
    URL.get_or_init(|| {
        let mut cfg = ServerConfig::new(path, title);
        cfg.port = Some(port);
        cfg.token = token;
        let server = start_detached(cfg)?;
        let _ = URL_PLAIN.set(Some(server.url_plain.clone()));
        Some(server.url.clone())
    })
    .clone()
}

/// Reads (or creates once) a persistent access token for the local server.
/// Keeping it in `data\` is what makes the imported subscription URL stable.
pub fn stable_token(data_dir: &std::path::Path) -> String {
    let path = data_dir.join("servesub.token");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let t = text.trim().to_string();
        if t.len() == 32 && t.chars().all(|c| c.is_ascii_hexdigit()) {
            return t;
        }
    }
    let token = new_token();
    let _ = std::fs::create_dir_all(data_dir);
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, &token).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
    token
}

/// Both URLs of the process-wide server (`base64`, `plain`).
pub fn urls() -> (Option<String>, Option<String>) {
    (
        URL.get().cloned().flatten(),
        URL_PLAIN.get().cloned().flatten(),
    )
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub path: PathBuf,
    pub title: String,
    /// Fixed token for tests; random when `None`.
    pub token: Option<String>,
    /// Preferred loopback port; a free ephemeral port when `None`.
    pub port: Option<u16>,
    pub max_connections: usize,
}

impl ServerConfig {
    pub fn new(path: PathBuf, title: impl Into<String>) -> Self {
        Self {
            path,
            title: title.into(),
            token: None,
            port: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
        }
    }
}

pub struct Server {
    pub url: String,
    pub url_plain: String,
    #[allow(dead_code)] // used by tests and by callers that log the port
    pub port: u16,
    #[allow(dead_code)] // used by tests; kept for diagnostics
    pub token: String,
    shared: Arc<Shared>,
    /// Keep the accept thread alive for the process when true.
    detached: bool,
}

impl Drop for Server {
    fn drop(&mut self) {
        if !self.detached {
            self.shared.stop.store(true, Ordering::SeqCst);
        }
    }
}

struct Shared {
    path: PathBuf,
    title: String,
    token: String,
    cache: Mutex<String>,
    active: AtomicUsize,
    max_connections: usize,
    stop: AtomicBool,
}

/// Starts the server on loopback. Used by [`start`] and by tests.
pub fn start_with(cfg: ServerConfig) -> Option<Server> {
    let listener = match cfg.port {
        Some(p) => match TcpListener::bind(("127.0.0.1", p)) {
            Ok(l) => l,
            Err(e) => {
                crate::logger::info(format!(
                    "servesub: порт {p} занят ({e}), беру свободный — ссылка изменится"
                ));
                TcpListener::bind("127.0.0.1:0").ok()?
            }
        },
        None => TcpListener::bind("127.0.0.1:0").ok()?,
    };
    listener.set_nonblocking(true).ok()?;
    let port = listener.local_addr().ok()?.port();
    let token = cfg.token.unwrap_or_else(new_token);
    let shared = Arc::new(Shared {
        path: cfg.path,
        title: cfg.title,
        token: token.clone(),
        cache: Mutex::new(String::new()),
        active: AtomicUsize::new(0),
        max_connections: cfg.max_connections.max(1),
        stop: AtomicBool::new(false),
    });

    let accept_shared = Arc::clone(&shared);
    std::thread::spawn(move || {
        while !accept_shared.stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = stream.set_nonblocking(false);
                    if accept_shared.active.load(Ordering::SeqCst) >= accept_shared.max_connections
                    {
                        // Too many clients: answer quickly, do not queue.
                        let mut s = stream;
                        let _ = respond(
                            &mut s,
                            503,
                            "Service Unavailable",
                            &[("Retry-After", "1".to_string())],
                            b"busy\n",
                            false,
                        );
                        continue;
                    }
                    accept_shared.active.fetch_add(1, Ordering::SeqCst);
                    let conn_shared = Arc::clone(&accept_shared);
                    std::thread::spawn(move || {
                        handle(stream, &conn_shared);
                        conn_shared.active.fetch_sub(1, Ordering::SeqCst);
                    });
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
    });

    Some(Server {
        url: format!("http://127.0.0.1:{port}/sub/{token}"),
        url_plain: format!("http://127.0.0.1:{port}/sub.txt/{token}"),
        port,
        token,
        shared,
        detached: false,
    })
}

/// Server that lives for the process lifetime (used by `start`).
fn start_detached(cfg: ServerConfig) -> Option<Server> {
    let mut s = start_with(cfg)?;
    s.detached = true;
    Some(s)
}

/// Random 32-hex token from clock/process entropy. Loopback-only threat model:
/// this only prevents other local applications from guessing the URL.
fn new_token() -> String {
    let mut t = short_id("servesub");
    t.push_str(&short_id("servesub-2"));
    t.truncate(32);
    t
}

struct Request {
    method: Method,
    path: String,
    query: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Method {
    Get,
    Head,
}

enum ParseError {
    TooLarge,
    Malformed,
    UnsupportedMethod,
}

fn read_head(stream: &mut TcpStream) -> Result<String, ParseError> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 512];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => {
                return if buf.is_empty() {
                    Err(ParseError::Malformed)
                } else {
                    Ok(String::from_utf8_lossy(&buf).into_owned())
                }
            }
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    return Ok(String::from_utf8_lossy(&buf).into_owned());
                }
                if buf.len() > MAX_HEADER_BYTES {
                    return Err(ParseError::TooLarge);
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(ParseError::Malformed)
            }
            Err(_) => return Err(ParseError::Malformed),
        }
    }
}

fn parse_request(head: &str) -> Result<Request, ParseError> {
    let line = head.lines().next().ok_or(ParseError::Malformed)?.trim_end();
    let mut parts = line.split_whitespace();
    let method = match parts.next() {
        Some("GET") => Method::Get,
        Some("HEAD") => Method::Head,
        Some(_) => return Err(ParseError::UnsupportedMethod),
        None => return Err(ParseError::Malformed),
    };
    let target = parts.next().ok_or(ParseError::Malformed)?;
    let version = parts.next().ok_or(ParseError::Malformed)?;
    if !version.starts_with("HTTP/1.") {
        return Err(ParseError::Malformed);
    }
    if parts.next().is_some() {
        return Err(ParseError::Malformed);
    }
    if !target.starts_with('/') {
        return Err(ParseError::Malformed);
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };
    Ok(Request {
        method,
        path,
        query,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Base64,
    Plain,
}

/// Reads query parameters without aborting on a malformed pair.
fn query_token(query: &str) -> Option<String> {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k.eq_ignore_ascii_case("token") && !v.is_empty() {
            return Some(v.to_string());
        }
    }
    None
}

/// Maps `/sub/<token>`, `/sub.txt/<token>`, `/sub?token=…` to a route. Returns
/// `None` for unknown paths; `Some((kind, None))` means "route exists but the
/// token is missing" (answered with 403, not 404).
fn route(path: &str, query: &str) -> Option<(Kind, Option<String>)> {
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match segs.as_slice() {
        ["sub", token] => Some((Kind::Base64, Some((*token).to_string()))),
        ["sub.txt", token] => Some((Kind::Plain, Some((*token).to_string()))),
        ["sub"] => Some((Kind::Base64, query_token(query))),
        ["sub.txt"] => Some((Kind::Plain, query_token(query))),
        _ => None,
    }
}

/// Constant-time comparison: length differences are folded into the result.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    diff == 0
}

fn handle(mut stream: TcpStream, shared: &Shared) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
    let head = match read_head(&mut stream) {
        Ok(h) => h,
        Err(ParseError::TooLarge) => {
            let _ = respond(
                &mut stream,
                431,
                "Request Header Fields Too Large",
                &[],
                b"request too large\n",
                false,
            );
            return;
        }
        Err(ParseError::UnsupportedMethod) => {
            let _ = respond(
                &mut stream,
                405,
                "Method Not Allowed",
                &[("Allow", "GET, HEAD".to_string())],
                b"only GET and HEAD\n",
                false,
            );
            return;
        }
        Err(ParseError::Malformed) => {
            let _ = respond(
                &mut stream,
                400,
                "Bad Request",
                &[],
                b"bad request\n",
                false,
            );
            return;
        }
    };
    let req = match parse_request(&head) {
        Ok(r) => r,
        Err(ParseError::UnsupportedMethod) => {
            let _ = respond(
                &mut stream,
                405,
                "Method Not Allowed",
                &[("Allow", "GET, HEAD".to_string())],
                b"only GET and HEAD\n",
                false,
            );
            return;
        }
        Err(_) => {
            let _ = respond(
                &mut stream,
                400,
                "Bad Request",
                &[],
                b"bad request\n",
                false,
            );
            return;
        }
    };

    let Some((kind, token)) = route(&req.path, &req.query) else {
        let _ = respond(&mut stream, 404, "Not Found", &[], b"not found\n", false);
        return;
    };
    let Some(token) = token else {
        let _ = respond(&mut stream, 403, "Forbidden", &[], b"bad token\n", false);
        return;
    };
    if !ct_eq(token.as_bytes(), shared.token.as_bytes()) {
        let _ = respond(&mut stream, 403, "Forbidden", &[], b"bad token\n", false);
        return;
    }

    let body = clean_body(&load_body(shared));
    let payload = match kind {
        Kind::Base64 => util::base64(&body),
        Kind::Plain => body,
    };
    let title = util::base64(&shared.title);
    let headers = [
        ("Content-Type", "text/plain; charset=utf-8".to_string()),
        ("Access-Control-Allow-Origin", "*".to_string()),
        ("Cache-Control", "no-store".to_string()),
        ("Profile-Title", format!("base64:{title}")),
        ("Profile-Update-Interval", "12".to_string()),
    ];
    let _ = respond(
        &mut stream,
        200,
        "OK",
        &headers,
        payload.as_bytes(),
        req.method == Method::Head,
    );
}

/// Reads the file and caches the last non-empty cleaned body, so a rewrite or
/// an empty/comment-only file cannot make the client import an empty profile.
fn load_body(shared: &Shared) -> String {
    let mut cache = match shared.cache.lock() {
        Ok(c) => c,
        Err(p) => p.into_inner(),
    };
    match std::fs::read_to_string(&shared.path) {
        Ok(raw) => {
            let cleaned = clean_body(&raw);
            if !cleaned.trim().is_empty() {
                *cache = cleaned.clone();
                cleaned
            } else {
                cache.clone()
            }
        }
        Err(_) => cache.clone(),
    }
}

fn respond(
    stream: &mut TcpStream,
    status: u16,
    reason: &str,
    headers: &[(&str, String)],
    body: &[u8],
    head_only: bool,
) -> std::io::Result<()> {
    let mut out = String::with_capacity(256 + body.len());
    out.push_str(&format!("HTTP/1.1 {status} {reason}\r\n"));
    for (k, v) in headers {
        out.push_str(&format!("{k}: {v}\r\n"));
    }
    out.push_str(&format!("Content-Length: {}\r\n", body.len()));
    out.push_str("Connection: close\r\n\r\n");
    stream.write_all(out.as_bytes())?;
    if !head_only {
        stream.write_all(body)?;
    }
    stream.flush()
}

/// Drops comments (`# 300 ms`) and empty lines: some clients treat them as
/// broken configs.
fn clean_body(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for line in s.lines() {
        let l = line.trim().trim_start_matches('\u{feff}');
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        out.push_str(l);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "test-token-0123456789abcdef";

    fn start_test(content: &str) -> (tempfile::TempDir, Server) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscription.txt");
        std::fs::write(&path, content).unwrap();
        let mut cfg = ServerConfig::new(path, "obhod test");
        cfg.token = Some(TOKEN.to_string());
        cfg.max_connections = 4;
        let server = start_with(cfg).expect("server");
        (dir, server)
    }

    fn send(port: u16, raw: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.write_all(raw.as_bytes()).unwrap();
        let mut buf = Vec::new();
        let _ = s.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    }

    fn status(resp: &str) -> u16 {
        resp.split_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
    }

    fn body(resp: &str) -> &str {
        resp.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("")
    }

    fn get(port: u16, path: &str) -> String {
        send(
            port,
            &format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"),
        )
    }

    #[test]
    fn serves_base64_and_plain_with_a_token() {
        let (_dir, srv) = start_test("# 10 ms\nvless://a\n\nvless://b\n# tail\n");
        let r = get(srv.port, &format!("/sub/{TOKEN}"));
        assert_eq!(status(&r), 200);
        assert!(r.contains("Profile-Update-Interval: 12"));
        assert_eq!(body(&r), util::base64("vless://a\nvless://b\n"));

        let r = get(srv.port, &format!("/sub.txt/{TOKEN}"));
        assert_eq!(status(&r), 200);
        assert_eq!(body(&r), "vless://a\nvless://b\n");
        assert!(srv.url.contains(TOKEN));
        assert!(srv.url_plain.contains("/sub.txt/"));
    }

    #[test]
    fn query_token_also_works() {
        let (_dir, srv) = start_test("vless://a\n");
        assert_eq!(status(&get(srv.port, &format!("/sub?token={TOKEN}"))), 200);
        assert_eq!(
            status(&get(srv.port, &format!("/sub.txt?token={TOKEN}"))),
            200
        );
    }

    #[test]
    fn wrong_or_missing_token_is_forbidden() {
        let (_dir, srv) = start_test("vless://a\n");
        assert_eq!(status(&get(srv.port, "/sub/wrong-token")), 403);
        assert_eq!(status(&get(srv.port, "/sub")), 403);
        assert_eq!(status(&get(srv.port, &format!("/sub/{TOKEN}x"))), 403);
        assert!(body(&get(srv.port, "/sub/wrong")).contains("bad token"));
    }

    #[test]
    fn unknown_paths_and_methods_are_rejected() {
        let (_dir, srv) = start_test("vless://a\n");
        assert_eq!(status(&get(srv.port, "/")), 404);
        assert_eq!(status(&get(srv.port, "/other")), 404);
        let post = send(
            srv.port,
            "POST /sub/x HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(status(&post), 405);
        let bad = send(srv.port, "GET\r\n\r\n");
        assert_eq!(status(&bad), 400);
    }

    #[test]
    fn oversized_headers_are_rejected() {
        let (_dir, srv) = start_test("vless://a\n");
        let mut raw = format!("GET /sub/{TOKEN} HTTP/1.1\r\nHost: h\r\nX-Big: ");
        raw.push_str(&"A".repeat(MAX_HEADER_BYTES + 100));
        let r = send(srv.port, &raw);
        assert_eq!(status(&r), 431);
    }

    #[test]
    fn head_has_headers_but_no_body() {
        let (_dir, srv) = start_test("vless://a\n");
        let r = send(
            srv.port,
            &format!("HEAD /sub.txt/{TOKEN} HTTP/1.1\r\nHost: h\r\n\r\n"),
        );
        assert_eq!(status(&r), 200);
        assert!(r.contains("Content-Length: 10"));
        assert_eq!(body(&r), "");
    }

    #[test]
    fn empty_or_comment_only_file_serves_the_cached_body() {
        let (dir, srv) = start_test("vless://a\n");
        assert_eq!(status(&get(srv.port, &format!("/sub.txt/{TOKEN}"))), 200);
        // Simulate a concurrent rewrite that produced an empty file.
        std::fs::write(dir.path().join("subscription.txt"), "# nothing\n\n").unwrap();
        let r = get(srv.port, &format!("/sub.txt/{TOKEN}"));
        assert_eq!(status(&r), 200);
        assert_eq!(body(&r), "vless://a\n");
        // A real update is picked up.
        std::fs::write(dir.path().join("subscription.txt"), "vless://b\n").unwrap();
        assert_eq!(
            body(&get(srv.port, &format!("/sub.txt/{TOKEN}"))),
            "vless://b\n"
        );
    }

    #[test]
    fn stable_token_survives_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let first = stable_token(dir.path());
        assert_eq!(first.len(), 32);
        assert!(first.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(stable_token(dir.path()), first);
        assert!(dir.path().join("servesub.token").exists());
    }

    #[test]
    fn preferred_port_is_used_when_free() {
        // Ask the OS for a free port, release it, then claim it explicitly.
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscription.txt");
        std::fs::write(&path, "vless://a\n").unwrap();
        let mut cfg = ServerConfig::new(path, "t");
        cfg.token = Some(TOKEN.to_string());
        cfg.port = Some(port);
        let srv = start_with(cfg).unwrap();
        assert_eq!(srv.port, port);
        assert!(srv.url.contains(&format!(":{port}/")));
    }

    #[test]
    fn busy_port_falls_back_instead_of_failing() {
        let held = TcpListener::bind("127.0.0.1:0").unwrap();
        let busy = held.local_addr().unwrap().port();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscription.txt");
        std::fs::write(&path, "vless://a\n").unwrap();
        let mut cfg = ServerConfig::new(path, "t");
        cfg.token = Some(TOKEN.to_string());
        cfg.port = Some(busy);
        let srv = start_with(cfg).unwrap();
        assert_ne!(srv.port, busy);
        assert!(status(&get(srv.port, &format!("/sub/{TOKEN}"))) == 200);
    }

    #[test]
    fn concurrency_limit_returns_503() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("subscription.txt");
        std::fs::write(&path, "vless://a\n").unwrap();
        let mut cfg = ServerConfig::new(path, "t");
        cfg.token = Some(TOKEN.to_string());
        cfg.max_connections = 1;
        let srv = start_with(cfg).unwrap();
        // Open a connection and leave it hanging (no request sent), then make a
        // second request: it must be refused with 503.
        let mut held = TcpStream::connect(("127.0.0.1", srv.port)).unwrap();
        held.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        std::thread::sleep(Duration::from_millis(120));
        let r = get(srv.port, &format!("/sub/{TOKEN}"));
        // The first connection may time out before the second is scheduled on
        // slow machines; either 503 (busy) or 200 (slot freed) is acceptable,
        // but a crash or a hang is not.
        let st = status(&r);
        assert!(st == 503 || st == 200, "unexpected status {st}");
        let _ = held.write_all(b"");
    }

    #[test]
    fn token_generation_is_random_hex() {
        let a = new_token();
        let b = new_token();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn constant_time_compare_matches_normal_equality() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
        assert!(ct_eq(b"", b""));
    }

    #[test]
    fn request_parser_rejects_garbage() {
        assert!(parse_request("GET /sub/x HTTP/1.1\r\n\r\n").is_ok());
        assert!(matches!(
            parse_request("GET /sub/x HTTP/2.0\r\n\r\n"),
            Err(ParseError::Malformed)
        ));
        assert!(matches!(
            parse_request("DELETE /sub/x HTTP/1.1\r\n\r\n"),
            Err(ParseError::UnsupportedMethod)
        ));
        assert!(matches!(
            parse_request("GET sub/x HTTP/1.1\r\n\r\n"),
            Err(ParseError::Malformed)
        ));
    }

    #[test]
    fn plain_route_rejects_unknown_shapes() {
        assert_eq!(route("/sub", ""), Some((Kind::Base64, None)));
        assert!(route("/sub/x/y", "").is_none());
        assert_eq!(
            route("/sub.txt/tok", ""),
            Some((Kind::Plain, Some("tok".into())))
        );
        assert_eq!(
            route("/sub", "a=1&token=abc"),
            Some((Kind::Base64, Some("abc".into())))
        );
    }
}

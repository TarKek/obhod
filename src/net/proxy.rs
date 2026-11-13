//! Honest reachability probes for proxy endpoints.
//!
//! Three separate facts are measured and never conflated:
//! 1. **DNS** — the host resolves.
//! 2. **TCP** — a socket connects (with latency and bounded retries).
//! 3. **TLS** — a real TLS ClientHello (with SNI) gets a ServerHello.
//!
//! What is *not* implemented: the VPN protocols themselves (VLESS/Trojan/VMess
//! authentication) and the MTProto handshake. A node whose TCP port is open is
//! therefore reported as `PortOpen` — "port open, protocol not verified" — and
//! never as a working proxy. A node that answers our TLS ClientHello is
//! reported as `TlsReachable`, which still does not prove the credentials are
//! valid.
//!
//! The TLS probe does not complete the handshake and does not verify a
//! certificate chain: it sends a syntactically valid ClientHello and parses
//! the server's first record (ServerHello, handshake or alert). That is enough
//! to tell "TLS service is listening" from "something else / nothing".

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::net::links::{self, LinkInfo, Protocol};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TlsPolicy {
    /// Never speak TLS (MTProto, plain TCP).
    Skip,
    /// Probe TLS only when the link declares `security=tls|reality`.
    Auto,
    /// Always probe TLS using the host or declared SNI.
    Force,
}

#[derive(Clone, Debug)]
pub struct ProbeConfig {
    pub connect_timeout: Duration,
    pub read_timeout: Duration,
    /// Total connect attempts (>= 1). Retries only transient failures.
    pub attempts: u8,
    pub retry_backoff: Duration,
    pub tls: TlsPolicy,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(1500),
            read_timeout: Duration::from_millis(1500),
            attempts: 2,
            retry_backoff: Duration::from_millis(120),
            tls: TlsPolicy::Auto,
        }
    }
}

impl ProbeConfig {
    /// Single attempt: used for bulk lists where hundreds of nodes are probed.
    pub fn fast() -> Self {
        Self {
            attempts: 1,
            ..Self::default()
        }
    }

    /// Two attempts and a longer read window: used for the finalists.
    pub fn deep() -> Self {
        Self {
            connect_timeout: Duration::from_millis(2000),
            read_timeout: Duration::from_millis(2500),
            attempts: 2,
            ..Self::default()
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Parse,
    Resolve,
    Connect,
    Tls,
}

impl Stage {
    pub fn ru(self) -> &'static str {
        match self {
            Stage::Parse => "разбор ссылки",
            Stage::Resolve => "DNS",
            Stage::Connect => "соединение",
            Stage::Tls => "TLS",
        }
    }

    pub fn en(self) -> &'static str {
        match self {
            Stage::Parse => "parsing",
            Stage::Resolve => "DNS",
            Stage::Connect => "connect",
            Stage::Tls => "TLS",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    InvalidLink,
    Unsupported,
    Dns,
    Connect,
    Timeout,
    Tls,
    Closed,
    Protocol,
}

#[derive(Clone, Debug)]
pub struct Failure {
    pub kind: FailureKind,
    pub stage: Stage,
    pub detail: String,
}

impl Failure {
    fn new(kind: FailureKind, stage: Stage, detail: impl Into<String>) -> Self {
        Self {
            kind,
            stage,
            detail: detail.into(),
        }
    }

    pub fn invalid(e: &links::LinkError) -> Self {
        Self::new(
            FailureKind::InvalidLink,
            Stage::Parse,
            format!("{}: {}", e.field, e.detail),
        )
    }

    pub fn ru(&self) -> String {
        match self.kind {
            FailureKind::InvalidLink => format!("некорректная ссылка: {}", self.detail),
            FailureKind::Unsupported => format!("протокол не поддерживается: {}", self.detail),
            FailureKind::Dns => format!("DNS: {}", self.detail),
            FailureKind::Connect => format!("соединение: {}", self.detail),
            FailureKind::Timeout => format!("таймаут ({}): {}", self.stage.ru(), self.detail),
            FailureKind::Tls => format!("TLS: {}", self.detail),
            FailureKind::Closed => {
                format!("соединение закрыто ({}): {}", self.stage.ru(), self.detail)
            }
            FailureKind::Protocol => format!("ответ не по протоколу: {}", self.detail),
        }
    }

    pub fn en(&self) -> String {
        match self.kind {
            FailureKind::InvalidLink => format!("invalid link: {}", self.detail),
            FailureKind::Unsupported => format!("unsupported protocol: {}", self.detail),
            FailureKind::Dns => format!("DNS: {}", self.detail),
            FailureKind::Connect => format!("connect: {}", self.detail),
            FailureKind::Timeout => format!("timeout ({}): {}", self.stage.en(), self.detail),
            FailureKind::Tls => format!("TLS: {}", self.detail),
            FailureKind::Closed => format!("closed ({}): {}", self.stage.en(), self.detail),
            FailureKind::Protocol => format!("unexpected protocol reply: {}", self.detail),
        }
    }

    /// Retrying a refused connection or a malformed link cannot help.
    pub fn retryable(&self) -> bool {
        matches!(
            self.kind,
            FailureKind::Timeout | FailureKind::Closed | FailureKind::Connect
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsReply {
    ServerHello {
        version: u16,
    },
    /// A TLS handshake record that is not a ServerHello (e.g. HelloRequest).
    Handshake {
        kind: u8,
    },
    Alert {
        level: u8,
        description: u8,
    },
    /// Data came back but was not TLS at all (an HTTP port, a wrong service).
    NotTls {
        head: String,
    },
    Closed,
    Timeout,
}

impl TlsReply {
    pub fn speaks_tls(&self) -> bool {
        matches!(
            self,
            TlsReply::ServerHello { .. } | TlsReply::Handshake { .. }
        )
    }

    pub fn ru(&self) -> String {
        match self {
            TlsReply::ServerHello { version } => {
                format!("TLS ServerHello ({})", tls_version(*version))
            }
            TlsReply::Handshake { kind } => format!("TLS handshake, тип {kind:#04x}"),
            TlsReply::Alert { level, description } => format!(
                "TLS alert: {} ({description})",
                alert_ru(*level, *description)
            ),
            TlsReply::NotTls { head } => format!("не TLS, ответ: «{head}»"),
            TlsReply::Closed => "соединение закрыто без ответа".into(),
            TlsReply::Timeout => "TLS не ответил вовремя".into(),
        }
    }
}

fn tls_version(v: u16) -> String {
    match v {
        0x0304 => "TLS 1.3".to_string(),
        0x0303 => "TLS 1.2".to_string(),
        0x0302 => "TLS 1.1".to_string(),
        0x0301 => "TLS 1.0".to_string(),
        other => format!("0x{other:04x}"),
    }
}

fn alert_ru(level: u8, description: u8) -> String {
    let what = match description {
        0 => "close_notify",
        10 => "unexpected_message",
        20 => "bad_record_mac",
        22 => "record_overflow",
        40 => "handshake_failure",
        42 => "bad_certificate",
        47 => "illegal_parameter",
        50 => "decode_error",
        70 => "protocol_version",
        71 => "insufficient_security",
        80 => "internal_error",
        86 => "inappropriate_fallback",
        90 => "user_canceled",
        109 => "missing_extension",
        110 => "unsupported_extension",
        112 => "unrecognized_name (SNI)",
        116 => "certificate_required",
        _ => "unknown",
    };
    format!("{what}, {}", if level == 1 { "warning" } else { "fatal" })
}

#[derive(Clone, Debug)]
pub struct TlsOutcome {
    pub reply: TlsReply,
    pub sni: String,
    pub latency_ms: u64,
}

/// What the probe can honestly claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// TCP connected and a TLS ServerHello came back for the requested SNI.
    /// The VPN protocol/credentials are still not verified.
    TlsReachable,
    /// TCP connected; no protocol-level check happened or it was inconclusive.
    PortOpen,
    /// Link is valid, but this protocol needs a third-party client.
    ExternalRequired,
    Failed,
}

impl Verdict {
    pub fn alive(self) -> bool {
        matches!(
            self,
            Verdict::TlsReachable | Verdict::PortOpen | Verdict::ExternalRequired
        )
    }

    pub fn ru(self) -> &'static str {
        match self {
            Verdict::TlsReachable => "TLS отвечает, вход в узел не проверен",
            Verdict::PortOpen => "порт открыт, протокол не проверен",
            Verdict::ExternalRequired => "нужен внешний клиент — не проверено",
            Verdict::Failed => "не отвечает",
        }
    }

    pub fn en(self) -> &'static str {
        match self {
            Verdict::TlsReachable => "TLS responds, node auth not verified",
            Verdict::PortOpen => "port open, protocol not verified",
            Verdict::ExternalRequired => "external client required - not verified",
            Verdict::Failed => "unreachable",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ProbeResult {
    pub host: String,
    pub port: u16,
    pub protocol: Option<Protocol>,
    pub resolved: Vec<IpAddr>,
    pub endpoint_ip: Option<IpAddr>,
    pub tcp_ok: bool,
    pub tls: Option<TlsOutcome>,
    /// TCP connect latency in milliseconds (first successful attempt).
    pub latency_ms: Option<u64>,
    pub attempts: u8,
    pub verdict: Verdict,
    pub failure: Option<Failure>,
    /// TLS layer observed and answered. Always false when no TLS probe ran.
    pub tls_verified: bool,
    /// VLESS/Trojan/VMess authentication is not implemented: always false.
    pub protocol_verified: bool,
    pub warnings: Vec<String>,
}

impl ProbeResult {
    fn base(host: &str, port: u16, protocol: Option<Protocol>) -> Self {
        Self {
            host: host.to_string(),
            port,
            protocol,
            resolved: Vec::new(),
            endpoint_ip: None,
            tcp_ok: false,
            tls: None,
            latency_ms: None,
            attempts: 0,
            verdict: Verdict::Failed,
            failure: None,
            tls_verified: false,
            protocol_verified: false,
            warnings: Vec::new(),
        }
    }

    fn failed(
        host: &str,
        port: u16,
        protocol: Option<Protocol>,
        failure: Failure,
        attempts: u8,
    ) -> Self {
        let mut r = Self::base(host, port, protocol);
        r.failure = Some(failure);
        r.attempts = attempts;
        r
    }

    pub fn alive(&self) -> bool {
        self.verdict.alive()
    }

    /// Short reason for logs and the node manager: always states what was and
    /// was not verified.
    pub fn summary_ru(&self) -> String {
        match (&self.failure, self.verdict) {
            (Some(f), Verdict::Failed) => f.ru(),
            (_, Verdict::TlsReachable) => self.verdict.ru().to_string(),
            (Some(f), _) => format!("{} ({})", self.verdict.ru(), f.ru()),
            (None, _) => self.verdict.ru().to_string(),
        }
    }

    pub fn latency_ms(&self) -> Option<u64> {
        self.latency_ms
    }

    pub fn endpoint(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// Parses a link and probes it. Never panics, never touches the system.
pub fn probe_link(link: &str, cfg: &ProbeConfig) -> ProbeResult {
    let info = match links::parse(link) {
        Ok(i) => i,
        Err(e) => return ProbeResult::failed("", 0, None, Failure::invalid(&e), 0),
    };
    probe_info(&info, cfg)
}

/// Probes an already parsed link (avoids parsing twice in bulk lists).
pub fn probe_info(info: &LinkInfo, cfg: &ProbeConfig) -> ProbeResult {
    let tls_wanted = match cfg.tls {
        TlsPolicy::Skip => false,
        TlsPolicy::Force => true,
        TlsPolicy::Auto => info.tls,
    };
    let sni = if tls_wanted {
        info.tls_server_name().map(str::to_string).or_else(|| {
            if info.protocol.tls_capable() && !links::is_ip_literal(&info.host) {
                Some(info.host.clone())
            } else {
                None
            }
        })
    } else {
        None
    };
    let mut r = probe_target(&info.host, info.port, sni.as_deref(), cfg);
    r.protocol = Some(info.protocol);
    r.warnings = info.warnings.clone();
    if info.external {
        if r.tcp_ok {
            r.verdict = Verdict::ExternalRequired;
            r.failure = None;
            r.tls_verified = false;
            r.protocol_verified = false;
        }
        // A dead endpoint stays `Failed` even for external protocols.
        return r;
    }
    r
}

/// Low-level probe used by MTProto checks and tests: TCP first, then an
/// optional TLS ClientHello on the same socket.
pub fn probe_target(host: &str, port: u16, sni: Option<&str>, cfg: &ProbeConfig) -> ProbeResult {
    let mut result = ProbeResult::base(host, port, None);
    let addrs = match resolve(host, port) {
        Ok(a) => a,
        Err(f) => {
            result.failure = Some(f);
            return result;
        }
    };
    result.resolved = addrs.iter().map(|a| a.ip()).collect();

    let max_attempts = cfg.attempts.max(1);
    let mut last: Option<Failure> = None;
    for attempt in 1..=max_attempts {
        result.attempts = attempt;
        for addr in &addrs {
            let started = Instant::now();
            match TcpStream::connect_timeout(addr, cfg.connect_timeout) {
                Ok(mut stream) => {
                    result.tcp_ok = true;
                    result.endpoint_ip = Some(addr.ip());
                    result.latency_ms = Some(started.elapsed().as_millis() as u64);
                    let _ = stream.set_read_timeout(Some(cfg.read_timeout));
                    let _ = stream.set_write_timeout(Some(cfg.read_timeout));
                    match sni {
                        None => {
                            result.verdict = Verdict::PortOpen;
                            let _ = stream.shutdown(Shutdown::Both);
                        }
                        Some(name) => {
                            let tls = tls_handshake(&mut stream, name, cfg.read_timeout);
                            let _ = stream.shutdown(Shutdown::Both);
                            match &tls.reply {
                                TlsReply::ServerHello { .. } | TlsReply::Handshake { .. } => {
                                    result.tls_verified = true;
                                    result.verdict = Verdict::TlsReachable;
                                }
                                TlsReply::Alert { description, .. } => {
                                    result.verdict = Verdict::Failed;
                                    result.failure = Some(Failure::new(
                                        FailureKind::Tls,
                                        Stage::Tls,
                                        format!("сервер отклонил рукопожатие: {}", tls.reply.ru()),
                                    ));
                                    let _ = description;
                                }
                                TlsReply::NotTls { .. } => {
                                    result.verdict = Verdict::Failed;
                                    result.failure = Some(Failure::new(
                                        FailureKind::Protocol,
                                        Stage::Tls,
                                        tls.reply.ru(),
                                    ));
                                }
                                TlsReply::Closed | TlsReply::Timeout => {
                                    // The TCP port is open, but TLS says nothing:
                                    // report the weaker, honest verdict.
                                    result.verdict = Verdict::PortOpen;
                                    result.failure = Some(Failure::new(
                                        FailureKind::Tls,
                                        Stage::Tls,
                                        tls.reply.ru(),
                                    ));
                                }
                            }
                            result.tls = Some(tls);
                        }
                    }
                    return result;
                }
                Err(e) => {
                    let f = classify_connect(addr, &e);
                    let retry = f.retryable();
                    last = Some(f);
                    if !retry {
                        break;
                    }
                }
            }
        }
        if attempt < max_attempts {
            if let Some(f) = &last {
                if !f.retryable() {
                    break;
                }
            }
            std::thread::sleep(cfg.retry_backoff);
        }
    }
    result.failure = last;
    result
}

/// TCP-only check for MTProto proxies. The secret is format-checked by
/// [`links::normalize_mtproto_secret`]; the MTProto handshake is not
/// implemented, so the verdict is always `PortOpen`.
pub fn probe_mtproto(
    host: &str,
    port: u16,
    secret: Option<&str>,
    cfg: &ProbeConfig,
) -> ProbeResult {
    if let Some(s) = secret {
        if links::normalize_mtproto_secret(s).is_none() {
            return ProbeResult::failed(
                host,
                port,
                Some(Protocol::Mtproto),
                Failure::new(
                    FailureKind::InvalidLink,
                    Stage::Parse,
                    "секрет не 16 байт (hex/base64)",
                ),
                0,
            );
        }
    } else {
        return ProbeResult::failed(
            host,
            port,
            Some(Protocol::Mtproto),
            Failure::new(FailureKind::InvalidLink, Stage::Parse, "нет секрета"),
            0,
        );
    }
    let mut r = probe_target(host, port, None, cfg);
    r.protocol = Some(Protocol::Mtproto);
    r.protocol_verified = false;
    if r.tcp_ok {
        r.warnings
            .push("MTProto handshake не выполняется: проверен только TCP и формат секрета".into());
    }
    r
}

fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, Failure> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![SocketAddr::new(ip, port)]);
    }
    match (host, port).to_socket_addrs() {
        Ok(it) => {
            let addrs: Vec<SocketAddr> = it.collect();
            if addrs.is_empty() {
                Err(Failure::new(
                    FailureKind::Dns,
                    Stage::Resolve,
                    format!("{host} не имеет адресов"),
                ))
            } else {
                Ok(addrs)
            }
        }
        Err(e) => Err(Failure::new(
            FailureKind::Dns,
            Stage::Resolve,
            format!("не удалось определить {host}: {e}"),
        )),
    }
}

fn classify_connect(addr: &SocketAddr, e: &std::io::Error) -> Failure {
    match e.kind() {
        ErrorKind::ConnectionRefused => Failure::new(
            FailureKind::Connect,
            Stage::Connect,
            format!("{addr}: подключение отклонено"),
        ),
        ErrorKind::TimedOut => Failure::new(
            FailureKind::Timeout,
            Stage::Connect,
            format!("{addr}: нет ответа за отведённое время"),
        ),
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => Failure::new(
            FailureKind::Connect,
            Stage::Connect,
            format!("{addr}: сеть недоступна"),
        ),
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted => Failure::new(
            FailureKind::Connect,
            Stage::Connect,
            format!("{addr}: соединение сброшено"),
        ),
        _ => Failure::new(FailureKind::Connect, Stage::Connect, format!("{addr}: {e}")),
    }
}

// ---------------------------------------------------------------------------
// Minimal TLS ClientHello (no handshake completion)
// ---------------------------------------------------------------------------

/// Sends a TLS ClientHello with SNI and parses the first server record.
pub fn tls_handshake(stream: &mut TcpStream, sni: &str, read_timeout: Duration) -> TlsOutcome {
    let hello = build_client_hello(sni);
    let started = Instant::now();
    if stream.write_all(&hello).is_err() {
        return TlsOutcome {
            reply: TlsReply::Closed,
            sni: sni.to_string(),
            latency_ms: started.elapsed().as_millis() as u64,
        };
    }
    let _ = stream.flush();
    let _ = stream.set_read_timeout(Some(read_timeout));
    let mut buf = vec![0u8; 4096];
    let mut got = 0usize;
    let reply = loop {
        match stream.read(&mut buf[got..]) {
            Ok(0) => break TlsReply::Closed,
            Ok(n) => {
                got += n;
                if got >= 6 || got == buf.len() {
                    break parse_tls_reply(&buf[..got]);
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                break TlsReply::Timeout;
            }
            Err(_) => break TlsReply::Closed,
        }
    };
    TlsOutcome {
        reply,
        sni: sni.to_string(),
        latency_ms: started.elapsed().as_millis() as u64,
    }
}

pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let seed = format!(
        "{}:{}:{}",
        std::process::id(),
        crate::net::unix_now(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let digest = crate::net::sha256_hex(seed.as_bytes());
    let mut random = [0u8; 32];
    for (i, b) in random.iter_mut().enumerate() {
        let hi = digest.as_bytes()[i * 2];
        let lo = digest.as_bytes()[i * 2 + 1];
        let hex = [hi, lo];
        *b = u8::from_str_radix(std::str::from_utf8(&hex).unwrap_or("00"), 16).unwrap_or(0);
    }
    build_client_hello_with_random(sni, &random)
}

pub fn build_client_hello_with_random(sni: &str, random: &[u8; 32]) -> Vec<u8> {
    let mut ext = Vec::new();
    // server_name (0x0000)
    if !sni.is_empty() {
        let name = sni.as_bytes();
        let mut data = Vec::with_capacity(name.len() + 5);
        data.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        data.push(0);
        data.extend_from_slice(&(name.len() as u16).to_be_bytes());
        data.extend_from_slice(name);
        ext.extend_from_slice(&[0x00, 0x00]);
        ext.extend_from_slice(&(data.len() as u16).to_be_bytes());
        ext.extend_from_slice(&data);
    }
    // supported_versions (0x002b): TLS 1.3 and 1.2
    ext.extend_from_slice(&[0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03]);
    // signature_algorithms (0x000d)
    ext.extend_from_slice(&[
        0x00, 0x0d, 0x00, 0x0a, 0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x03,
    ]);
    // supported_groups (0x000a): x25519, secp256r1
    ext.extend_from_slice(&[0x00, 0x0a, 0x00, 0x06, 0x00, 0x04, 0x00, 0x1d, 0x00, 0x17]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy client version TLS 1.2
    body.extend_from_slice(random);
    body.push(0); // empty legacy session id (TLS 1.3 compatible)
    body.extend_from_slice(&[0x00, 0x0a]); // cipher suites length
    body.extend_from_slice(&[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2b, // ECDHE_ECDSA_AES128_GCM_SHA256
        0xc0, 0x2f, // ECDHE_RSA_AES128_GCM_SHA256
    ]);
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);

    let mut hs = Vec::with_capacity(body.len() + 4);
    hs.push(0x01); // ClientHello
    hs.extend_from_slice(&((body.len() as u32).to_be_bytes()[1..])); // 24-bit length
    hs.extend_from_slice(&body);

    let mut record = Vec::with_capacity(hs.len() + 5);
    record.push(0x16); // handshake
    record.extend_from_slice(&[0x03, 0x01]); // record version TLS 1.0 (compat)
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

/// Parses the first bytes of a server response. Pure, used by unit tests.
pub fn parse_tls_reply(buf: &[u8]) -> TlsReply {
    if buf.is_empty() {
        return TlsReply::Closed;
    }
    if buf.starts_with(b"HTTP/") {
        return TlsReply::NotTls {
            head: "HTTP".to_string(),
        };
    }
    if buf.len() < 6 {
        return TlsReply::NotTls {
            head: hex_head(buf),
        };
    }
    match buf[0] {
        0x16 | 0x14 => match buf[5] {
            0x02 => {
                let version = if buf.len() >= 11 {
                    u16::from_be_bytes([buf[9], buf[10]])
                } else {
                    0x0303
                };
                TlsReply::ServerHello { version }
            }
            other => TlsReply::Handshake { kind: other },
        },
        0x15 => TlsReply::Alert {
            level: buf.get(5).copied().unwrap_or(2),
            description: buf.get(6).copied().unwrap_or(0),
        },
        _ => TlsReply::NotTls {
            head: hex_head(buf),
        },
    }
}

fn hex_head(buf: &[u8]) -> String {
    buf.iter()
        .take(8)
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Mock TLS/TCP server: accepts one connection, optionally reads the
    /// ClientHello, writes `reply`, then closes. No internet involved.
    fn mock_server(reply: Vec<u8>) -> (u16, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let h = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let _ = s.set_read_timeout(Some(Duration::from_secs(2)));
            let mut hello = vec![0u8; 1024];
            let n = s.read(&mut hello).unwrap_or(0);
            hello.truncate(n);
            let _ = s.write_all(&reply);
            let _ = s.flush();
            hello
        });
        (port, h)
    }

    fn server_hello() -> Vec<u8> {
        vec![
            0x16, 0x03, 0x03, 0x00, 0x04, // record header
            0x02, 0x00, 0x00, 0x00, // handshake header (ServerHello)
            0x03, 0x03, // TLS 1.2 legacy version
        ]
    }

    #[test]
    fn tls_probe_sees_server_hello() {
        let (port, h) = mock_server(server_hello());
        let cfg = ProbeConfig::default();
        let r = probe_target("127.0.0.1", port, Some("example.org"), &cfg);
        let hello = h.join().unwrap();
        assert!(r.tcp_ok);
        assert_eq!(r.verdict, Verdict::TlsReachable);
        assert!(r.tls_verified);
        assert!(!r.protocol_verified);
        assert!(r.latency_ms.is_some());
        // ClientHello must be a TLS record carrying the requested SNI.
        assert_eq!(hello[0], 0x16);
        assert!(hello
            .windows("example.org".len())
            .any(|w| w == b"example.org"));
    }

    #[test]
    fn tls_alert_is_a_tls_failure_not_port_open() {
        // fatal handshake_failure (40)
        let (port, h) = mock_server(vec![0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28]);
        let r = probe_target("127.0.0.1", port, Some("x"), &ProbeConfig::default());
        h.join().unwrap();
        assert!(r.tcp_ok);
        assert_eq!(r.verdict, Verdict::Failed);
        let f = r.failure.unwrap();
        assert_eq!(f.kind, FailureKind::Tls);
        assert!(f.ru().contains("handshake_failure"));
    }

    #[test]
    fn non_tls_banner_is_reported_honestly() {
        let (port, h) = mock_server(b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec());
        let r = probe_target("127.0.0.1", port, Some("x"), &ProbeConfig::default());
        h.join().unwrap();
        assert_eq!(r.verdict, Verdict::Failed);
        assert_eq!(r.failure.unwrap().kind, FailureKind::Protocol);
    }

    #[test]
    fn silent_tls_server_stays_port_open() {
        let (port, h) = mock_server(Vec::new());
        let r = probe_target(
            "127.0.0.1",
            port,
            Some("x"),
            &ProbeConfig {
                read_timeout: Duration::from_millis(300),
                ..ProbeConfig::default()
            },
        );
        h.join().unwrap();
        assert_eq!(r.verdict, Verdict::PortOpen);
        assert!(!r.tls_verified);
    }

    #[test]
    fn plain_tcp_probe_reports_port_open() {
        let (port, h) = mock_server(Vec::new());
        let r = probe_target(
            "127.0.0.1",
            port,
            None,
            &ProbeConfig {
                read_timeout: Duration::from_millis(300),
                ..ProbeConfig::default()
            },
        );
        h.join().unwrap();
        assert_eq!(r.verdict, Verdict::PortOpen);
        assert!(r.latency_ms.unwrap() < 5000);
        assert!(!r.tls_verified);
        assert!(!r.protocol_verified);
    }

    #[test]
    fn closed_port_fails_with_connect_reason() {
        // Grab a free port, then release it.
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let r = probe_target(
            "127.0.0.1",
            port,
            None,
            &ProbeConfig {
                connect_timeout: Duration::from_millis(200),
                attempts: 2,
                ..ProbeConfig::default()
            },
        );
        assert!(!r.tcp_ok);
        assert_eq!(r.verdict, Verdict::Failed);
        let f = r.failure.unwrap();
        // Windows may report a closed local port as "refused" or as a timeout.
        assert!(
            matches!(f.kind, FailureKind::Connect | FailureKind::Timeout),
            "{f:?}"
        );
        assert_eq!(f.stage, Stage::Connect);
        assert!(r.attempts >= 1);
    }

    #[test]
    fn invalid_link_fails_before_any_network() {
        let r = probe_link("vless://not-a-link", &ProbeConfig::fast());
        assert_eq!(r.verdict, Verdict::Failed);
        assert_eq!(r.failure.unwrap().kind, FailureKind::InvalidLink);
        assert_eq!(r.attempts, 0);
    }

    #[test]
    fn external_protocol_is_never_marked_verified() {
        let (port, h) = mock_server(Vec::new());
        let link = format!("hysteria2://pw@127.0.0.1:{port}#x");
        let r = probe_link(
            &link,
            &ProbeConfig {
                tls: TlsPolicy::Skip,
                ..ProbeConfig::fast()
            },
        );
        h.join().unwrap();
        assert_eq!(r.verdict, Verdict::ExternalRequired);
        assert!(!r.tls_verified);
        assert!(!r.protocol_verified);
        assert!(r.summary_ru().contains("внешний клиент"));
    }

    #[test]
    fn mtproto_secret_is_validated_and_never_called_working() {
        let bad = probe_mtproto("127.0.0.1", 1, Some("zz"), &ProbeConfig::fast());
        assert_eq!(bad.verdict, Verdict::Failed);
        assert_eq!(bad.failure.unwrap().kind, FailureKind::InvalidLink);

        let (port, h) = mock_server(Vec::new());
        let ok = probe_mtproto(
            "127.0.0.1",
            port,
            Some("0123456789abcdef0123456789abcdef"),
            &ProbeConfig {
                read_timeout: Duration::from_millis(200),
                ..ProbeConfig::fast()
            },
        );
        h.join().unwrap();
        assert_eq!(ok.verdict, Verdict::PortOpen);
        assert!(!ok.protocol_verified);
        assert!(ok.summary_ru().contains("протокол не проверен"));
    }

    #[test]
    fn client_hello_is_well_formed() {
        let random = [7u8; 32];
        let hello = build_client_hello_with_random("host.example", &random);
        assert_eq!(hello[0], 0x16);
        let rec_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(rec_len + 5, hello.len());
        assert_eq!(hello[5], 0x01); // ClientHello
                                    // 24-bit handshake length
        let hs_len = ((hello[6] as usize) << 16) | ((hello[7] as usize) << 8) | hello[8] as usize;
        assert_eq!(hs_len + 9, hello.len());
        assert!(hello.windows(12).any(|w| w == b"host.example"));
    }

    #[test]
    fn tls_reply_parser_classifies_records() {
        assert!(matches!(
            parse_tls_reply(&server_hello()),
            TlsReply::ServerHello { version: 0x0303 }
        ));
        assert!(matches!(
            parse_tls_reply(&[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x70]),
            TlsReply::Alert {
                description: 112,
                ..
            }
        ));
        assert!(matches!(
            parse_tls_reply(b"HTTP/1.0 404"),
            TlsReply::NotTls { .. }
        ));
        assert_eq!(parse_tls_reply(&[]), TlsReply::Closed);
        assert!(matches!(
            parse_tls_reply(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            TlsReply::NotTls { .. }
        ));
    }
}

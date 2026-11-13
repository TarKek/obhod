//! Structural parsing and validation of proxy links.
//!
//! This module never contacts the network. It answers "is this link a
//! well-formed config for a known protocol, and where does it point?".
//! Protocol-level *verification* lives in [`crate::net::proxy`].
//!
//! Supported schemes:
//! - `vless://`, `trojan://`, `vmess://` — full structural validation.
//! - `ss://`, `hysteria2://` (`hy2://`), `tuic://` — validation only; these
//!   need their own client and are marked `external` (we do not implement
//!   Shadowsocks/Hysteria2/TUIC handshakes from scratch).
//! - `tg://proxy` and `https://t.me/proxy` — MTProto proxies; the secret is
//!   format-checked (16/17-byte hex or base64), the MTProto handshake itself
//!   is not implemented.
//!
//! Secrets never leave this module: [`LinkInfo`] stores only a hashed key,
//! so debug output and logs cannot leak passwords or UUIDs.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::net::{b64_decode, b64_decode_text, sha256_hex};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Vless,
    Trojan,
    Vmess,
    Shadowsocks,
    Hysteria2,
    Tuic,
    Mtproto,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Vless => "vless",
            Protocol::Trojan => "trojan",
            Protocol::Vmess => "vmess",
            Protocol::Shadowsocks => "ss",
            Protocol::Hysteria2 => "hysteria2",
            Protocol::Tuic => "tuic",
            Protocol::Mtproto => "mtproto",
        }
    }

    pub fn label_ru(self) -> &'static str {
        match self {
            Protocol::Vless => "VLESS",
            Protocol::Trojan => "Trojan",
            Protocol::Vmess => "VMess",
            Protocol::Shadowsocks => "Shadowsocks",
            Protocol::Hysteria2 => "Hysteria2",
            Protocol::Tuic => "TUIC",
            Protocol::Mtproto => "MTProto",
        }
    }

    /// True when a dedicated client is required and obhod has no
    /// implementation of that protocol's handshake.
    pub fn external(self) -> bool {
        matches!(
            self,
            Protocol::Shadowsocks | Protocol::Hysteria2 | Protocol::Tuic
        )
    }

    /// Protocols whose transport normally runs over TLS, so `security=tls`
    /// is meaningful for them.
    pub fn tls_capable(self) -> bool {
        matches!(
            self,
            Protocol::Vless | Protocol::Trojan | Protocol::Vmess | Protocol::Hysteria2 | Protocol::Tuic
        )
    }

    pub fn from_scheme(scheme: &str) -> Option<Self> {
        match scheme.to_ascii_lowercase().as_str() {
            "vless" => Some(Protocol::Vless),
            "trojan" => Some(Protocol::Trojan),
            "vmess" => Some(Protocol::Vmess),
            "ss" => Some(Protocol::Shadowsocks),
            "hysteria2" | "hy2" => Some(Protocol::Hysteria2),
            "tuic" => Some(Protocol::Tuic),
            "tg" => Some(Protocol::Mtproto),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkError {
    pub field: &'static str,
    pub detail: String,
}

impl LinkError {
    fn new(field: &'static str, detail: impl Into<String>) -> Self {
        Self {
            field,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.field, self.detail)
    }
}

/// A structurally valid config. Contains no secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkInfo {
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub name: String,
    pub tls: bool,
    pub sni: Option<String>,
    pub transport: String,
    /// No client implemented for this protocol; only structure was checked.
    pub external: bool,
    /// Credential looked like a UUID (normal for VLESS/VMess).
    pub id_is_uuid: bool,
    /// Stable dedupe key: protocol + host + port + hash(credential).
    pub key: String,
    pub warnings: Vec<String>,
}

impl LinkInfo {
    pub fn endpoint(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]:{}", self.host, self.port)
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    pub fn tls_server_name(&self) -> Option<&str> {
        if !self.tls {
            return None;
        }
        match &self.sni {
            Some(s) if !s.is_empty() => Some(s),
            _ => {
                if is_ip_literal(&self.host) {
                    None
                } else {
                    Some(&self.host)
                }
            }
        }
    }
}

/// Parses and structurally validates one link.
pub fn parse(link: &str) -> Result<LinkInfo, LinkError> {
    let link = link.trim().trim_start_matches('\u{feff}').trim();
    if link.is_empty() {
        return Err(LinkError::new("link", "пустая строка"));
    }
    if link.len() > 8192 {
        return Err(LinkError::new("link", "слишком длинная ссылка"));
    }
    if link.chars().any(|c| c.is_control()) {
        return Err(LinkError::new("link", "управляющие символы в ссылке"));
    }
    let idx = link
        .find("://")
        .ok_or_else(|| LinkError::new("scheme", "нет схемы вида scheme://"))?;
    let scheme = link[..idx].to_ascii_lowercase();
    let rest = &link[idx + 3..];
    match scheme.as_str() {
        "vless" => parse_vless(rest),
        "trojan" => parse_trojan(rest),
        "vmess" => parse_vmess(rest),
        "ss" => parse_ss(rest),
        "hysteria2" | "hy2" => parse_hysteria2(rest),
        "tuic" => parse_tuic(rest),
        "tg" => parse_tg(rest),
        "https" | "http" => parse_tme(rest),
        other => Err(LinkError::new(
            "scheme",
            format!("неизвестная схема «{other}»"),
        )),
    }
}

/// Normalized dedupe key for a link; `None` when the link is not parseable.
pub fn normalized_key(link: &str) -> Option<String> {
    parse(link).ok().map(|l| l.key)
}

// ---------------------------------------------------------------------------
// Generic URI splitting
// ---------------------------------------------------------------------------

struct UriParts {
    userinfo: String,
    host: String,
    port: u16,
    query: HashMap<String, String>,
    fragment: String,
}

fn split_uri(rest: &str, default_port: Option<u16>) -> Result<UriParts, LinkError> {
    let (before_frag, fragment) = match rest.split_once('#') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let (authority_path, query_raw) = match before_frag.split_once('?') {
        Some((a, b)) => (a, b),
        None => (before_frag, ""),
    };
    let authority = authority_path.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(LinkError::new("host", "не указан сервер"));
    }
    let (userinfo, hostport) = match authority.rsplit_once('@') {
        Some((u, h)) => (percent_decode(u), h),
        None => (String::new(), authority),
    };
    let (host, port) = split_host_port(hostport, default_port)?;
    Ok(UriParts {
        userinfo,
        host,
        port,
        query: parse_query(query_raw),
        fragment: percent_decode(fragment),
    })
}

fn split_host_port(hostport: &str, default_port: Option<u16>) -> Result<(String, u16), LinkError> {
    if hostport.is_empty() {
        return Err(LinkError::new("host", "не указан сервер"));
    }
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| LinkError::new("host", "незакрытый IPv6-адрес"))?;
        let h = &stripped[..end];
        let tail = &stripped[end + 1..];
        let p = match tail.strip_prefix(':') {
            Some(p) => Some(p),
            None if tail.is_empty() => None,
            None => return Err(LinkError::new("port", "мусор после IPv6-адреса")),
        };
        (h.to_string(), p)
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (hostport.to_string(), None),
        }
    };
    validate_host(&host)?;
    let port = match port {
        Some(p) => parse_port(p)?,
        None => default_port.ok_or_else(|| LinkError::new("port", "не указан порт"))?,
    };
    Ok((host, port))
}

fn parse_port(raw: &str) -> Result<u16, LinkError> {
    let p: u16 = raw
        .trim()
        .parse()
        .map_err(|_| LinkError::new("port", format!("«{raw}» не является портом")))?;
    if p == 0 {
        return Err(LinkError::new("port", "порт 0 недопустим"));
    }
    Ok(p)
}

fn validate_host(host: &str) -> Result<(), LinkError> {
    if host.is_empty() {
        return Err(LinkError::new("host", "пустой сервер"));
    }
    if host.len() > 253 {
        return Err(LinkError::new("host", "слишком длинное имя сервера"));
    }
    if host
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '/' | '\\' | '@' | '#' | '?'))
    {
        return Err(LinkError::new("host", "недопустимые символы в имени сервера"));
    }
    Ok(())
}

fn parse_query(raw: &str) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some(kv) => kv,
            None => (pair, ""),
        };
        let k = percent_decode(k).to_ascii_lowercase();
        if k.is_empty() {
            continue;
        }
        out.insert(k, percent_decode(v));
    }
    out
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(h) = std::str::from_utf8(&b[i + 1..i + 3]) {
                if let Ok(v) = u8::from_str_radix(h, 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

// ---------------------------------------------------------------------------
// Per-protocol parsers
// ---------------------------------------------------------------------------

const TRANSPORTS: &[&str] = &[
    "tcp",
    "raw",
    "ws",
    "grpc",
    "http",
    "h2",
    "http2",
    "quic",
    "kcp",
    "mkcp",
    "xhttp",
    "splithttp",
    "httpupgrade",
    "hysteria",
];

fn check_transport(name: &str) -> Result<String, LinkError> {
    let t = name.trim().to_ascii_lowercase();
    let t = if t.is_empty() { "tcp".to_string() } else { t };
    if !TRANSPORTS.contains(&t.as_str()) {
        return Err(LinkError::new(
            "type",
            format!("неизвестный транспорт «{t}»"),
        ));
    }
    Ok(t)
}

fn security_tls(q: &HashMap<String, String>, default: bool) -> Result<bool, LinkError> {
    let raw = q
        .get("security")
        .map(|s| s.trim().to_ascii_lowercase())
        .unwrap_or_default();
    match raw.as_str() {
        "" => Ok(default),
        "none" | "false" => Ok(false),
        "tls" | "reality" | "xtls" => Ok(true),
        other => Err(LinkError::new(
            "security",
            format!("неизвестный режим «{other}»"),
        )),
    }
}

fn pick_name(fragment: &str, fallback: &str) -> String {
    let n = fragment.trim();
    if n.is_empty() {
        fallback.to_string()
    } else {
        n.chars().take(120).collect()
    }
}

fn sni_from(
    q: &HashMap<String, String>,
    host: &str,
    tls: bool,
) -> (Option<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut sni = q
        .get("sni")
        .or_else(|| q.get("server_name"))
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().to_string());
    if sni.is_none() {
        if let Some(h) = q.get("host").filter(|s| !s.trim().is_empty()) {
            // WS/HTTP `host` header is usually the same as SNI.
            sni = Some(h.split(',').next().unwrap_or(h).trim().to_string());
        }
    }
    if tls && sni.is_none() && !is_ip_literal(host) {
        sni = Some(host.to_string());
        warnings.push("SNI не указан — использую имя сервера".into());
    }
    (sni, warnings)
}

fn credential_key(protocol: Protocol, host: &str, port: u16, secret: &str) -> String {
    let h = sha256_hex(secret.as_bytes());
    format!(
        "{}|{}|{}|{}",
        protocol.as_str(),
        host.to_ascii_lowercase(),
        port,
        &h[..16]
    )
}

fn parse_vless(rest: &str) -> Result<LinkInfo, LinkError> {
    let p = split_uri(rest, Some(443))?;
    if p.userinfo.trim().is_empty() {
        return Err(LinkError::new("id", "пустой идентификатор пользователя"));
    }
    let tls = security_tls(&p.query, false)?;
    let transport = check_transport(p.query.get("type").map(String::as_str).unwrap_or("tcp"))?;
    let (sni, mut warnings) = sni_from(&p.query, &p.host, tls);
    if tls
        && p.query
            .get("security")
            .map(|s| s.eq_ignore_ascii_case("reality"))
            .unwrap_or(false)
        && !p.query.contains_key("pbk")
    {
        warnings.push("reality без pbk (публичного ключа)".into());
    }
    let id_is_uuid = is_uuid(&p.userinfo);
    if !id_is_uuid {
        warnings.push("id не похож на UUID".into());
    }
    if let Some(enc) = p.query.get("encryption") {
        if !enc.trim().is_empty() && !enc.eq_ignore_ascii_case("none") {
            warnings.push(format!("encryption={enc}"));
        }
    }
    Ok(LinkInfo {
        protocol: Protocol::Vless,
        host: p.host.clone(),
        port: p.port,
        name: pick_name(&p.fragment, &format!("vless {}:{}", p.host, p.port)),
        tls,
        sni,
        transport,
        external: false,
        id_is_uuid,
        key: credential_key(Protocol::Vless, &p.host, p.port, &p.userinfo),
        warnings,
    })
}

fn parse_trojan(rest: &str) -> Result<LinkInfo, LinkError> {
    let p = split_uri(rest, Some(443))?;
    if p.userinfo.trim().is_empty() {
        return Err(LinkError::new("password", "пустой пароль"));
    }
    // Trojan is TLS by default; `security=none` is the explicit opt-out.
    let tls = security_tls(&p.query, true)?;
    let transport = check_transport(p.query.get("type").map(String::as_str).unwrap_or("tcp"))?;
    let (sni, warnings) = sni_from(&p.query, &p.host, tls);
    Ok(LinkInfo {
        protocol: Protocol::Trojan,
        host: p.host.clone(),
        port: p.port,
        name: pick_name(&p.fragment, &format!("trojan {}:{}", p.host, p.port)),
        tls,
        sni,
        transport,
        external: false,
        id_is_uuid: false,
        key: credential_key(Protocol::Trojan, &p.host, p.port, &p.userinfo),
        warnings,
    })
}

fn parse_vmess(rest: &str) -> Result<LinkInfo, LinkError> {
    let raw = rest.trim();
    let json = b64_decode_text(raw)
        .ok_or_else(|| LinkError::new("body", "vmess: тело не декодируется из base64"))?;
    let v: serde_json::Value = serde_json::from_str(json.trim())
        .map_err(|e| LinkError::new("json", format!("vmess: {e}")))?;
    let obj = v
        .as_object()
        .ok_or_else(|| LinkError::new("json", "vmess: ожидался JSON-объект"))?;
    let s = |k: &str| -> Option<&str> {
        obj.get(k)
            .and_then(|x| x.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };
    let add = s("add").ok_or_else(|| LinkError::new("add", "vmess: не указан адрес"))?;
    validate_host(add)?;
    let port = match obj.get("port") {
        Some(serde_json::Value::Number(n)) => n
            .as_u64()
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p > 0)
            .ok_or_else(|| LinkError::new("port", "vmess: некорректный порт"))?,
        Some(serde_json::Value::String(s)) => parse_port(s)?,
        _ => return Err(LinkError::new("port", "vmess: не указан порт")),
    };
    let id = s("id").ok_or_else(|| LinkError::new("id", "vmess: не указан id"))?;
    let transport = check_transport(s("net").unwrap_or("tcp"))?;
    let mut warnings = Vec::new();
    let id_is_uuid = is_uuid(id);
    if !id_is_uuid {
        warnings.push("id не похож на UUID".into());
    }
    let tls_raw = s("tls").unwrap_or("").to_ascii_lowercase();
    let tls = matches!(tls_raw.as_str(), "tls" | "reality" | "xtls");
    if !tls_raw.is_empty() && !tls && tls_raw != "none" {
        warnings.push(format!("tls={tls_raw}"));
    }
    let sni = s("sni")
        .or_else(|| s("host"))
        .map(|h| h.split(',').next().unwrap_or(h).trim().to_string())
        .or_else(|| {
            if tls && !is_ip_literal(add) {
                Some(add.to_string())
            } else {
                None
            }
        });
    let name = s("ps")
        .map(str::to_string)
        .unwrap_or_else(|| format!("vmess {add}:{port}"));
    Ok(LinkInfo {
        protocol: Protocol::Vmess,
        host: add.to_string(),
        port,
        name,
        tls,
        sni,
        transport,
        external: false,
        id_is_uuid,
        key: credential_key(Protocol::Vmess, add, port, id),
        warnings,
    })
}

fn parse_ss(rest: &str) -> Result<LinkInfo, LinkError> {
    let (before_frag, fragment) = match rest.split_once('#') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let (cred, hostport) = if let Some((u, h)) = before_frag.rsplit_once('@') {
        (
            b64_decode_text(u)
                .ok_or_else(|| LinkError::new("userinfo", "ss: логин не base64"))?,
            h.to_string(),
        )
    } else {
        let decoded = b64_decode_text(before_frag)
            .ok_or_else(|| LinkError::new("body", "ss: тело не декодируется из base64"))?;
        let (u, h) = decoded
            .rsplit_once('@')
            .ok_or_else(|| LinkError::new("body", "ss: нет «пароль@сервер»"))?;
        (u.to_string(), h.to_string())
    };
    let (method, password) = cred
        .split_once(':')
        .ok_or_else(|| LinkError::new("userinfo", "ss: ожидался «шифр:пароль»"))?;
    if method.trim().is_empty() {
        return Err(LinkError::new("method", "ss: пустой шифр"));
    }
    if password.is_empty() {
        return Err(LinkError::new("password", "ss: пустой пароль"));
    }
    // Strip plugin query before parsing host:port.
    let hostport = hostport
        .split(['/', '?'])
        .next()
        .unwrap_or(&hostport)
        .to_string();
    let (host, port) = split_host_port(&hostport, None)?;
    let mut warnings = Vec::new();
    if !KNOWN_SS_CIPHERS.contains(&method.trim().to_ascii_lowercase().as_str()) {
        warnings.push(format!("неизвестный шифр «{}»", method.trim()));
    }
    warnings.push("Shadowsocks: нужен внешний клиент, проверка не выполнялась".into());
    Ok(LinkInfo {
        protocol: Protocol::Shadowsocks,
        host: host.clone(),
        port,
        name: pick_name(&percent_decode(fragment), &format!("ss {}:{port}", host)),
        tls: false,
        sni: None,
        transport: "tcp".into(),
        external: true,
        id_is_uuid: false,
        key: credential_key(Protocol::Shadowsocks, &host, port, &cred),
        warnings,
    })
}

const KNOWN_SS_CIPHERS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "chacha20-ietf",
    "rc4-md5",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "none",
    "plain",
];

fn parse_hysteria2(rest: &str) -> Result<LinkInfo, LinkError> {
    let p = split_uri(rest, Some(443))?;
    let mut warnings = vec!["Hysteria2: нужен внешний клиент, проверка не выполнялась".into()];
    let tls = security_tls(&p.query, true)?;
    if !tls {
        warnings.push("hysteria2 без TLS — нетипичная конфигурация".into());
    }
    let (sni, w) = sni_from(&p.query, &p.host, tls);
    warnings.extend(w);
    Ok(LinkInfo {
        protocol: Protocol::Hysteria2,
        host: p.host.clone(),
        port: p.port,
        name: pick_name(&p.fragment, &format!("hysteria2 {}:{}", p.host, p.port)),
        tls,
        sni,
        transport: "quic".into(),
        external: true,
        id_is_uuid: false,
        key: credential_key(Protocol::Hysteria2, &p.host, p.port, &p.userinfo),
        warnings,
    })
}

fn parse_tuic(rest: &str) -> Result<LinkInfo, LinkError> {
    let p = split_uri(rest, Some(443))?;
    if p.userinfo.trim().is_empty() {
        return Err(LinkError::new("userinfo", "tuic: нет uuid:пароль"));
    }
    let (uuid, password) = p
        .userinfo
        .split_once(':')
        .ok_or_else(|| LinkError::new("userinfo", "tuic: ожидался «uuid:пароль»"))?;
    if uuid.trim().is_empty() || password.is_empty() {
        return Err(LinkError::new("userinfo", "tuic: пустой uuid или пароль"));
    }
    let mut warnings =
        vec!["TUIC: нужен внешний клиент, проверка не выполнялась".to_string()];
    if !is_uuid(uuid) {
        warnings.push("uuid не похож на UUID".into());
    }
    Ok(LinkInfo {
        protocol: Protocol::Tuic,
        host: p.host.clone(),
        port: p.port,
        name: pick_name(&p.fragment, &format!("tuic {}:{}", p.host, p.port)),
        tls: true,
        sni: p.query.get("sni").cloned(),
        transport: "quic".into(),
        external: true,
        id_is_uuid: is_uuid(uuid),
        key: credential_key(Protocol::Tuic, &p.host, p.port, &p.userinfo),
        warnings,
    })
}

fn parse_tg(rest: &str) -> Result<LinkInfo, LinkError> {
    // tg://proxy?server=...&port=...&secret=...
    let (before_frag, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let query = before_frag
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("");
    parse_mtproto_fields(&parse_query(query), fragment)
}

fn parse_tme(rest: &str) -> Result<LinkInfo, LinkError> {
    // https://t.me/proxy?server=...&port=...&secret=...
    if !rest.starts_with("t.me/proxy") && !rest.starts_with("telegram.me/proxy") {
        return Err(LinkError::new("link", "поддерживается только t.me/proxy"));
    }
    let (before_frag, fragment) = rest.split_once('#').unwrap_or((rest, ""));
    let query = before_frag
        .split_once('?')
        .map(|(_, q)| q)
        .unwrap_or("");
    parse_mtproto_fields(&parse_query(query), fragment)
}

fn parse_mtproto_fields(
    q: &HashMap<String, String>,
    fragment: &str,
) -> Result<LinkInfo, LinkError> {
    let server = q
        .get("server")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| LinkError::new("server", "MTProto: не указан сервер"))?;
    validate_host(&server)?;
    let port = parse_port(
        q.get("port")
            .map(String::as_str)
            .ok_or_else(|| LinkError::new("port", "MTProto: не указан порт"))?,
    )?;
    let secret_raw = q
        .get("secret")
        .map(String::as_str)
        .ok_or_else(|| LinkError::new("secret", "MTProto: нет секрета"))?;
    let secret = normalize_mtproto_secret(secret_raw)
        .ok_or_else(|| LinkError::new("secret", "MTProto: секрет не 16 байт (hex/base64)"))?;
    Ok(LinkInfo {
        protocol: Protocol::Mtproto,
        host: server.clone(),
        port,
        name: pick_name(&percent_decode(fragment), "MTProto"),
        tls: secret.starts_with("ee"),
        sni: None,
        transport: "tcp".into(),
        external: false,
        id_is_uuid: false,
        key: credential_key(Protocol::Mtproto, &server, port, &secret),
        warnings: Vec::new(),
    })
}

/// Telegram accepts a 16-byte secret as 32 hex chars, a 17-byte `dd`/`ee`
/// prefixed secret as 34 hex chars, or base64 that decodes to >= 16 bytes.
/// Returns the normalized form (hex stays hex, base64 becomes hex) so links
/// can be rebuilt without duplicates.
pub fn normalize_mtproto_secret(raw: &str) -> Option<String> {
    let s = percent_decode(raw).trim().to_string();
    if s.is_empty() {
        return None;
    }
    if s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(s.to_ascii_lowercase());
    }
    if s.len() == 34 {
        let low = s.to_ascii_lowercase();
        if (low.starts_with("dd") || low.starts_with("ee"))
            && low[2..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Some(low);
        }
    }
    let bytes = b64_decode(&s)?;
    if bytes.len() >= 16 {
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            hex.push_str(&format!("{b:02x}"));
        }
        return Some(hex);
    }
    None
}

/// True for a canonical UUID (any version) or 32 bare hex chars.
pub fn is_uuid(s: &str) -> bool {
    let s = s.trim();
    if s.len() == 32 {
        return s.bytes().all(|b| b.is_ascii_hexdigit());
    }
    if s.len() != 36 {
        return false;
    }
    let b = s.as_bytes();
    for (i, c) in b.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if *c != b'-' {
                    return false;
                }
            }
            _ => {
                if !c.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

pub fn is_ip_literal(host: &str) -> bool {
    host.parse::<std::net::IpAddr>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

    #[test]
    fn parses_valid_vless() {
        let link = format!(
            "vless://{UUID}@Example.ORG:2053?security=tls&sni=cdn.example.org&type=ws&path=%2Fws#Node%20One"
        );
        let l = parse(&link).unwrap();
        assert_eq!(l.protocol, Protocol::Vless);
        assert_eq!(l.host, "Example.ORG");
        assert_eq!(l.port, 2053);
        assert!(l.tls);
        assert_eq!(l.sni.as_deref(), Some("cdn.example.org"));
        assert_eq!(l.transport, "ws");
        assert_eq!(l.name, "Node One");
        assert!(l.id_is_uuid);
        assert!(!l.external);
    }

    #[test]
    fn vless_rejects_broken_structure() {
        assert_eq!(
            parse("vless://@host:443").unwrap_err().field,
            "id"
        );
        assert_eq!(
            parse(&format!("vless://{UUID}@host:0")).unwrap_err().field,
            "port"
        );
        assert_eq!(
            parse(&format!("vless://{UUID}@host:443?security=bogus"))
                .unwrap_err()
                .field,
            "security"
        );
        assert_eq!(
            parse(&format!("vless://{UUID}@host:443?type=carrier-pigeon"))
                .unwrap_err()
                .field,
            "type"
        );
    }

    #[test]
    fn trojan_defaults_to_tls_and_warns_variant() {
        let l = parse("trojan://pass@example.org:443#t").unwrap();
        assert!(l.tls);
        assert_eq!(l.protocol, Protocol::Trojan);
        let plain = parse("trojan://pass@example.org:80?security=none").unwrap();
        assert!(!plain.tls);
        assert_eq!(
            parse("trojan://@example.org:443").unwrap_err().field,
            "password"
        );
    }

    #[test]
    fn vmess_validates_json_fields() {
        let json = format!(
            r#"{{"v":"2","ps":"n","add":"1.2.3.4","port":"443","id":"{UUID}","net":"ws","tls":"tls","host":"a.example"}}"#
        );
        let link = format!("vmess://{}", crate::util::base64(&json));
        let l = parse(&link).unwrap();
        assert_eq!(l.host, "1.2.3.4");
        assert_eq!(l.port, 443);
        assert_eq!(l.name, "n");
        assert!(l.tls);
        assert_eq!(l.sni.as_deref(), Some("a.example"));

        assert_eq!(parse("vmess://!!!").unwrap_err().field, "body");
        let bad_port = r#"{"add":"1.2.3.4","port":"0","id":"x"}"#;
        assert_eq!(
            parse(&format!("vmess://{}", crate::util::base64(bad_port)))
                .unwrap_err()
                .field,
            "port"
        );
    }

    #[test]
    fn parses_ss_both_forms() {
        let cred = crate::util::base64("aes-256-gcm:secret");
        let a = parse(&format!("ss://{cred}@1.2.3.4:8388#a")).unwrap();
        assert_eq!(a.protocol, Protocol::Shadowsocks);
        assert!(a.external);
        assert_eq!((a.host.as_str(), a.port), ("1.2.3.4", 8388));

        let whole = crate::util::base64("chacha20-ietf-poly1305:pw@example.org:443");
        let b = parse(&format!("ss://{whole}#b")).unwrap();
        assert_eq!((b.host.as_str(), b.port), ("example.org", 443));
        assert!(b.external);
    }

    #[test]
    fn external_protocols_are_marked() {
        let h = parse("hysteria2://pw@example.org:443?sni=x.example#h").unwrap();
        assert!(h.external);
        let t = parse("tuic://b831381d-6324-4d53-ad4f-8cda48b30811:pw@example.org:443#t").unwrap();
        assert!(t.external);
        assert!(t.tls);
    }

    #[test]
    fn mtproto_secret_formats() {
        assert!(normalize_mtproto_secret("0123456789abcdef0123456789abcdef").is_some());
        assert!(normalize_mtproto_secret("dd0123456789abcdef0123456789abcdef").is_some());
        assert!(normalize_mtproto_secret("ee0123456789abcdef0123456789abcdef").is_some());
        assert!(normalize_mtproto_secret("0123456789abcde").is_none());
        // 16 bytes base64 (standard alphabet)
        let b64 = crate::util::base64("\u{1}\u{2}\u{3}\u{4}\u{5}\u{6}\u{7}\u{8}\u{9}\u{10}\u{11}\u{12}\u{13}\u{14}\u{15}\u{16}");
        let norm = normalize_mtproto_secret(&b64).unwrap();
        assert_eq!(norm, "01020304050607080910111213141516");

        let l = parse(&format!(
            "tg://proxy?server=1.2.3.4&port=443&secret={}",
            "0123456789abcdef0123456789abcdef"
        ))
        .unwrap();
        assert_eq!(l.protocol, Protocol::Mtproto);
        assert_eq!((l.host.as_str(), l.port), ("1.2.3.4", 443));
        assert_eq!(
            parse("tg://proxy?server=1.2.3.4&port=443&secret=zz")
                .unwrap_err()
                .field,
            "secret"
        );
    }

    #[test]
    fn dedupe_key_ignores_fragment_and_param_order() {
        let a = parse(&format!(
            "vless://{UUID}@host.example:443?security=tls&sni=a#first"
        ))
        .unwrap();
        let b = parse(&format!(
            "vless://{UUID}@HOST.EXAMPLE:443?sni=a&security=tls#second"
        ))
        .unwrap();
        assert_eq!(a.key, b.key);
        let c = parse(&format!("vless://{UUID}@host.example:8443?security=tls")).unwrap();
        assert_ne!(a.key, c.key);
        // Different credentials must not collide.
        let d = parse("vless://11111111-2222-3333-4444-555555555555@host.example:443").unwrap();
        assert_ne!(a.key, d.key);
    }

    #[test]
    fn rejects_garbage_and_controls() {
        assert!(parse("").is_err());
        assert!(parse("http://example.org/").is_err());
        assert!(parse("vless://id@host:443\u{0}").is_err());
        assert!(parse("not a link").is_err());
    }

    #[test]
    fn uuid_detection() {
        assert!(is_uuid(UUID));
        assert!(is_uuid("b831381d63244d53ad4f8cda48b30811"));
        assert!(!is_uuid("b831381d-6324-4d53-ad4f-8cda48b3081"));
        assert!(!is_uuid("not-a-uuid"));
    }
}
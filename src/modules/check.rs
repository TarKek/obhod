//! Quick "does it work?" screen.
//!
//! Each row distinguishes what was actually observed:
//! - HTTP probes for YouTube/Discord/Telegram;
//! - DNS resolution;
//! - the local bypass process;
//! - the prepared Telegram proxy list (TCP only, protocol **not** verified);
//! - the prepared VPN node list (checked when it was fetched, not now).

use std::net::ToSocketAddrs;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::modules::telegram;
use crate::net::proxy;
use crate::util;

pub struct CheckItem {
    pub ru: String,
    pub en: String,
    pub ok: bool,
    pub detail_ru: String,
    pub detail_en: String,
}

impl Clone for CheckItem {
    fn clone(&self) -> Self {
        Self {
            ru: self.ru.clone(),
            en: self.en.clone(),
            ok: self.ok,
            detail_ru: self.detail_ru.clone(),
            detail_en: self.detail_en.clone(),
        }
    }
}

pub fn run() -> Vec<CheckItem> {
    let data = crate::config::Config::load().data_dir();
    run_with_data(&data)
}

/// Same checks, but with an explicit data directory (used by tests/tools).
pub fn run_with_data(data: &Path) -> Vec<CheckItem> {
    let data = data.to_path_buf();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .connect_timeout(Duration::from_secs(4))
        .user_agent("obhod/0.1")
        .build()
        .ok();

    // Probes are independent: run them in parallel, so a blocked site costs
    // one timeout instead of three in a row.
    let yt = {
        let c = client.clone();
        std::thread::spawn(move || {
            probe_http(c.as_ref(), "https://www.youtube.com/generate_204", &[204, 200])
        })
    };
    let dc = {
        let c = client.clone();
        std::thread::spawn(move || {
            probe_http(c.as_ref(), "https://discord.com/api/v9/gateway", &[200])
        })
    };
    let tg = {
        let c = client.clone();
        std::thread::spawn(move || {
            probe_http(c.as_ref(), "https://api.telegram.org/", &[200, 404, 302])
        })
    };
    let dns = std::thread::spawn(|| {
        ("youtube.com", 443)
            .to_socket_addrs()
            .map(|mut a| a.next().is_some())
            .unwrap_or(false)
    });
    let zapret = std::thread::spawn(|| {
        util::hidden_str("tasklist", &["/FI", "IMAGENAME eq winws.exe"])
            .map(|o| String::from_utf8_lossy(&o.stdout).contains("winws.exe"))
            .unwrap_or(false)
    });

    let youtube = yt.join().unwrap_or(false);
    let discord = dc.join().unwrap_or(false);
    let tg = tg.join().unwrap_or(false);
    let dns = dns.join().unwrap_or(false);
    let zapret = zapret.join().unwrap_or(false);

    let mut items = Vec::new();

    items.push(CheckItem {
        ru: "YouTube".into(),
        en: "YouTube".into(),
        ok: youtube,
        detail_ru: if youtube {
            "открывается".into()
        } else {
            "не открывается — включите обход".into()
        },
        detail_en: if youtube {
            "reachable".into()
        } else {
            "blocked - enable bypass".into()
        },
    });

    items.push(CheckItem {
        ru: "Discord".into(),
        en: "Discord".into(),
        ok: discord,
        detail_ru: if discord {
            "открывается".into()
        } else {
            "не открывается — нужен обход".into()
        },
        detail_en: if discord {
            "reachable".into()
        } else {
            "blocked - bypass needed".into()
        },
    });

    items.push(CheckItem {
        ru: "Telegram".into(),
        en: "Telegram".into(),
        ok: tg,
        detail_ru: if tg {
            "сеть доступна".into()
        } else {
            "заблокирован — включите прокси в приложении Telegram".into()
        },
        detail_en: if tg {
            "network reachable".into()
        } else {
            "blocked - enable proxy inside Telegram".into()
        },
    });

    items.push(CheckItem {
        ru: "Интернет и DNS".into(),
        en: "Internet and DNS".into(),
        ok: dns,
        detail_ru: if dns {
            "имена сайтов определяются".into()
        } else {
            "проблема с DNS — нажмите «Включить всё»".into()
        },
        detail_en: if dns {
            "names resolve".into()
        } else {
            "DNS problem - run setup".into()
        },
    });

    items.push(CheckItem {
        ru: "Обход для YouTube/Discord".into(),
        en: "YouTube/Discord bypass".into(),
        ok: zapret,
        detail_ru: if zapret {
            "запущен".into()
        } else {
            "выключен".into()
        },
        detail_en: if zapret {
            "running".into()
        } else {
            "off".into()
        },
    });

    if let Some(item) = mtproto_item(&data) {
        items.push(item);
    }
    if let Some(item) = subs_item(&data) {
        items.push(item);
    }

    items
}

pub fn demo() -> Vec<CheckItem> {
    vec![
        CheckItem {
            ru: "YouTube".into(),
            en: "YouTube".into(),
            ok: true,
            detail_ru: "открывается (демо)".into(),
            detail_en: "reachable (demo)".into(),
        },
        CheckItem {
            ru: "Discord".into(),
            en: "Discord".into(),
            ok: true,
            detail_ru: "открывается (демо)".into(),
            detail_en: "reachable (demo)".into(),
        },
        CheckItem {
            ru: "Telegram".into(),
            en: "Telegram".into(),
            ok: false,
            detail_ru: "заблокирован — включите прокси в приложении Telegram (демо)".into(),
            detail_en: "blocked - enable proxy inside Telegram (demo)".into(),
        },
        CheckItem {
            ru: "Интернет и DNS".into(),
            en: "Internet and DNS".into(),
            ok: true,
            detail_ru: "имена сайтов определяются (демо)".into(),
            detail_en: "names resolve (demo)".into(),
        },
        CheckItem {
            ru: "Обход для YouTube/Discord".into(),
            en: "YouTube/Discord bypass".into(),
            ok: true,
            detail_ru: "запущен (демо)".into(),
            detail_en: "running (demo)".into(),
        },
        CheckItem {
            ru: "Прокси Telegram".into(),
            en: "Telegram proxy".into(),
            ok: true,
            detail_ru: "порт открыт у 2 из 3, протокол не проверен (демо)".into(),
            detail_en: "port open for 2 of 3, protocol not verified (demo)".into(),
        },
    ]
}

/// Probes the best few proxies from `mtproto.txt` (TCP only). Returns `None`
/// when the list does not exist yet: an empty row would be noise.
fn mtproto_item(data: &Path) -> Option<CheckItem> {
    let signals = proxy_signals(data)?;
    let total = signals.checked;
    let open = signals.tcp_ok;
    let ok = open > 0;
    Some(CheckItem {
        ru: "Прокси Telegram".into(),
        en: "Telegram proxy".into(),
        ok,
        detail_ru: if ok {
            format!("порт открыт у {open} из {total}, протокол не проверен")
        } else {
            "нет ответа по TCP — обновите список в «Обновить»".into()
        },
        detail_en: if ok {
            format!("port open for {open} of {total}, protocol not verified")
        } else {
            "no TCP response - refresh the list via Update".into()
        },
    })
}

/// Aggregate proxy signals for `core::health::Signals`.
///
/// `protocol_verified` is always `false`: the MTProto/VLESS handshakes are not
/// implemented. `tls_ok` counts nodes whose TLS layer answered (currently 0 for
/// MTProto because it speaks plain TCP; subscription TLS counts are stored in
/// `subs_state.json`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProxySignals {
    pub checked: usize,
    pub tcp_ok: usize,
    pub tls_ok: usize,
    pub protocol_verified: bool,
}

/// Probes up to three best proxies from `mtproto.txt`. No file → `None`.
pub fn proxy_signals(data: &Path) -> Option<ProxySignals> {
    let text = std::fs::read_to_string(data.join("mtproto.txt")).ok()?;
    let proxies: Vec<telegram::MtProxy> = text
        .lines()
        .filter_map(|l| {
            let i = l.find("tg://proxy")?;
            telegram::parse_link(&l[i..])
        })
        .take(3)
        .collect();
    if proxies.is_empty() {
        return None;
    }
    let checked = proxies.len();
    let cfg = telegram::default_probe_config();
    let handles: Vec<_> = proxies
        .into_iter()
        .map(|p| {
            let cfg = cfg.clone();
            std::thread::spawn(move || telegram::probe(&p.server, p.port, &p.secret, &cfg))
        })
        .collect();
    let results: Vec<proxy::ProbeResult> = handles
        .into_iter()
        .filter_map(|h| h.join().ok())
        .collect();
    Some(ProxySignals {
        checked,
        tcp_ok: results.iter().filter(|r| r.tcp_ok).count(),
        tls_ok: results.iter().filter(|r| r.tls_verified).count(),
        protocol_verified: false,
    })
}

/// The node list is validated during the subscription update, not here, so
/// this row only states how many nodes are ready.
fn subs_item(data: &Path) -> Option<CheckItem> {
    let path = data.join("subs_alive_plain.txt");
    let text = std::fs::read_to_string(&path).ok()?;
    let n = text
        .lines()
        .filter(|l| {
            let l = l.trim();
            !l.is_empty() && !l.starts_with('#')
        })
        .count();
    Some(CheckItem {
        ru: "Серверы для VPN-клиента".into(),
        en: "VPN client servers".into(),
        ok: n > 0,
        detail_ru: if n > 0 {
            format!("{n} узлов готово (проверены при обновлении)")
        } else {
            "список пуст — обновите подписку".into()
        },
        detail_en: if n > 0 {
            format!("{n} nodes ready (checked when fetched)")
        } else {
            "empty - refresh the subscription".into()
        },
    })
}

fn probe_http(
    client: Option<&reqwest::blocking::Client>,
    url: &str,
    ok_codes: &[u16],
) -> bool {
    let Some(c) = client else { return false };
    let started = Instant::now();
    match c.get(url).timeout(Duration::from_secs(6)).send() {
        Ok(r) => {
            let _ = started.elapsed();
            ok_codes.contains(&r.status().as_u16())
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_list_files_produce_no_extra_rows() {
        let dir = tempfile::tempdir().unwrap();
        assert!(mtproto_item(dir.path()).is_none());
        assert!(subs_item(dir.path()).is_none());
        std::fs::write(dir.path().join("mtproto.txt"), "# only comments\n").unwrap();
        assert!(mtproto_item(dir.path()).is_none());
    }

    #[test]
    fn empty_subscription_is_visible_as_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("subs_alive_plain.txt"), "# none\n\n").unwrap();
        let item = subs_item(dir.path()).unwrap();
        assert!(!item.ok);
        assert!(item.detail_ru.contains("список пуст"));
    }

    #[test]
    fn proxy_row_never_claims_the_protocol_is_verified() {
        // Point at a closed local port: the row must fail without claiming
        // anything about the protocol.
        let dir = tempfile::tempdir().unwrap();
        let port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        std::fs::write(
            dir.path().join("mtproto.txt"),
            format!(
                "10 ms  tg://proxy?server=127.0.0.1&port={port}&secret=0123456789abcdef0123456789abcdef\n"
            ),
        )
        .unwrap();
        let item = mtproto_item(dir.path()).unwrap();
        assert!(!item.ok);
        assert!(!item.detail_ru.contains("работает"));
    }
}
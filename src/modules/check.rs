use std::net::ToSocketAddrs;
use std::time::Duration;

use crate::util;

pub struct CheckItem {
    pub ru: String,
    pub en: String,
    pub ok: bool,
    pub detail_ru: String,
    pub detail_en: String,
}

pub fn run() -> Vec<CheckItem> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(8))
        .user_agent("obhod/0.1")
        .build()
        .ok();

    let mut items = Vec::new();

    let youtube = probe_http(
        client.as_ref(),
        "https://www.youtube.com/generate_204",
        &[204, 200],
    );
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

    let discord = probe_http(
        client.as_ref(),
        "https://discord.com/api/v9/gateway",
        &[200],
    );
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

    let tg = probe_http(client.as_ref(), "https://api.telegram.org/", &[200, 404, 302]);
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

    let dns = ("youtube.com", 443)
        .to_socket_addrs()
        .map(|mut a| a.next().is_some())
        .unwrap_or(false);
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

    let zapret = util::hidden_str("tasklist", &["/FI", "IMAGENAME eq winws.exe"])
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("winws.exe"))
        .unwrap_or(false);
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
    ]
}

fn probe_http(
    client: Option<&reqwest::blocking::Client>,
    url: &str,
    ok_codes: &[u16],
) -> bool {
    let Some(c) = client else { return false };
    match c.get(url).send() {
        Ok(r) => ok_codes.contains(&r.status().as_u16()),
        Err(_) => false,
    }
}

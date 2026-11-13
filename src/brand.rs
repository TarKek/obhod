//! One place for the whole "brand": name, tagline, server title template and
//! UI colors. Everything is read from `brand.json` next to the exe; if the
//! file is missing it is created with the default values on first real start.
//! Changes apply after restarting the app.

use ratatui::style::Color;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::util;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Colors {
    /// Main color: borders, titles, selection background.
    pub accent: String,
    /// Text drawn on top of `accent` (selection background).
    pub on_accent: String,
    /// Success / "yes" / working.
    pub ok: String,
    /// Warnings and demo mode.
    pub warn: String,
    /// Errors and failed checks.
    pub err: String,
    /// Very quiet text (borders, hints under items).
    pub muted: String,
    /// Secondary text (descriptions).
    pub secondary: String,
    /// Main text.
    pub text: String,
}

impl Default for Colors {
    fn default() -> Self {
        Self {
            accent: "cyan".into(),
            on_accent: "black".into(),
            ok: "green".into(),
            warn: "yellow".into(),
            err: "red".into(),
            muted: "darkgray".into(),
            secondary: "gray".into(),
            text: "white".into(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(default)]
pub struct Brand {
    /// Program name: window title, welcome text, subscription title.
    pub name: String,
    pub tagline_ru: String,
    pub tagline_en: String,
    /// Node name in the subscription. Placeholders: {flag} {country} {code} {name}
    pub server_name: String,
    /// Same, but when the country is unknown.
    pub server_name_no_country: String,
    pub colors: Colors,
}

impl Default for Brand {
    fn default() -> Self {
        Self {
            name: "obhod".into(),
            tagline_ru: "интернет без блокировок — просто и бесплатно".into(),
            tagline_en: "internet without blocks - simple and free".into(),
            server_name: "{flag} {country} | {name}".into(),
            server_name_no_country: "{flag} | {name}".into(),
            colors: Colors::default(),
        }
    }
}

impl Brand {
    /// Fills `{flag} {country} {code} {name}` placeholders.
    pub fn server_name(&self, flag: &str, code: &str, country: &str) -> String {
        let tpl = if country.is_empty() {
            &self.server_name_no_country
        } else {
            &self.server_name
        };
        tpl.replace("{flag}", flag)
            .replace("{country}", country)
            .replace("{code}", code)
            .replace("{name}", &self.name)
    }
}

#[derive(Clone, Debug)]
struct Palette {
    accent: Color,
    on_accent: Color,
    ok: Color,
    warn: Color,
    err: Color,
    muted: Color,
    secondary: Color,
    text: Color,
}

impl Palette {
    fn from(c: &Colors) -> Self {
        Self {
            accent: parse_color(&c.accent).unwrap_or(Color::Cyan),
            on_accent: parse_color(&c.on_accent).unwrap_or(Color::Black),
            ok: parse_color(&c.ok).unwrap_or(Color::Green),
            warn: parse_color(&c.warn).unwrap_or(Color::Yellow),
            err: parse_color(&c.err).unwrap_or(Color::Red),
            muted: parse_color(&c.muted).unwrap_or(Color::DarkGray),
            secondary: parse_color(&c.secondary).unwrap_or(Color::Gray),
            text: parse_color(&c.text).unwrap_or(Color::White),
        }
    }
}

static BRAND: OnceLock<Brand> = OnceLock::new();
static PALETTE: OnceLock<Palette> = OnceLock::new();

pub fn path() -> PathBuf {
    util::exe_dir().join("brand.json")
}

/// Creates `brand.json` with the default brand if it does not exist yet.
pub fn ensure_file() {
    let p = path();
    if p.exists() {
        return;
    }
    let _ = fs::write(&p, format!("\u{feff}{}", default_json()));
}

fn load() -> Brand {
    let Ok(raw) = fs::read_to_string(path()) else {
        return Brand::default();
    };
    // Notepad may save with a BOM — drop it before parsing.
    let text = raw.trim_start_matches('\u{feff}');
    match serde_json::from_str(text) {
        Ok(b) => b,
        Err(e) => {
            crate::logger::info(format!(
                "brand.json: не удалось прочитать ({e}), использую стандартный бренд"
            ));
            Brand::default()
        }
    }
}

fn brand() -> &'static Brand {
    BRAND.get_or_init(|| {
        let b = load();
        let _ = PALETTE.set(Palette::from(&b.colors));
        b
    })
}

fn pal() -> &'static Palette {
    let _ = brand();
    PALETTE.get().expect("palette initialized with brand")
}

pub fn name() -> &'static str {
    &brand().name
}

/// Name suitable for file names: lowercase letters/digits, `-`/`_` kept.
pub fn slug() -> String {
    let mut out = String::new();
    for c in brand().name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if (c == '-' || c == '_') && !out.is_empty() {
            out.push(c);
        }
    }
    if out.is_empty() {
        "obhod".into()
    } else {
        out
    }
}

pub fn tagline(lang: &str) -> &'static str {
    let b = brand();
    if lang == "ru" {
        &b.tagline_ru
    } else {
        &b.tagline_en
    }
}

/// Example node name for the UI ("Серверы будут вида «…»").
pub fn sample(lang: &str) -> String {
    let country = if lang == "ru" {
        "Германия"
    } else {
        "Germany"
    };
    brand().server_name("🇩🇪", "DE", country)
}

pub fn server_name(flag: &str, code: &str, country: &str) -> String {
    brand().server_name(flag, code, country)
}

pub fn accent() -> Color {
    pal().accent
}
pub fn on_accent() -> Color {
    pal().on_accent
}
pub fn ok() -> Color {
    pal().ok
}
pub fn warn() -> Color {
    pal().warn
}
pub fn err() -> Color {
    pal().err
}
pub fn muted() -> Color {
    pal().muted
}
pub fn secondary() -> Color {
    pal().secondary
}
pub fn text() -> Color {
    pal().text
}

/// Accepts `cyan`, `darkgray`, `lightblue`, `#00d7ff` or `45` (xterm index).
fn parse_color(s: &str) -> Option<Color> {
    let t = s.trim();
    match t.to_ascii_lowercase().as_str() {
        "reset" => Some(Color::Reset),
        "black" => Some(Color::Black),
        "red" => Some(Color::Red),
        "green" => Some(Color::Green),
        "yellow" => Some(Color::Yellow),
        "blue" => Some(Color::Blue),
        "magenta" => Some(Color::Magenta),
        "cyan" => Some(Color::Cyan),
        "gray" | "grey" => Some(Color::Gray),
        "darkgray" | "darkgrey" => Some(Color::DarkGray),
        "white" => Some(Color::White),
        "lightred" => Some(Color::LightRed),
        "lightgreen" => Some(Color::LightGreen),
        "lightyellow" => Some(Color::LightYellow),
        "lightblue" => Some(Color::LightBlue),
        "lightmagenta" => Some(Color::LightMagenta),
        "lightcyan" => Some(Color::LightCyan),
        _ => {
            if let Some(hex) = t.strip_prefix('#') {
                if hex.len() == 6 {
                    let r = u8::from_str_radix(&hex[0..2], 16).ok()?;
                    let g = u8::from_str_radix(&hex[2..4], 16).ok()?;
                    let b = u8::from_str_radix(&hex[4..6], 16).ok()?;
                    return Some(Color::Rgb(r, g, b));
                }
                None
            } else {
                t.parse::<u8>().ok().map(Color::Indexed)
            }
        }
    }
}

const HELP: [&str; 11] = [
    "Меняйте значения ниже и перезапустите программу — этого достаточно.",
    "name — название программы (заголовок, приветствие, название подписки).",
    "tagline_ru / tagline_en — подпись под заголовком.",
    "server_name — как называются серверы в подписке.",
    "  Подстановки: {flag} флаг, {country} страна, {code} код страны, {name} название.",
    "server_name_no_country — то же, когда страна не определилась.",
    "colors — цвета: имя (cyan, darkgray, lightblue...), #RRGGBB или номер 0-255.",
    "  accent — главный цвет, on_accent — текст на нём, ok/warn/err — статусы,",
    "  muted — тихий текст, secondary — описания, text — основной текст.",
    "Цвета можно проверить без запуска: obhod.exe --demo-static",
    "Неизвестные поля игнорируются, отсутствующие берутся по умолчанию.",
];

fn default_json() -> String {
    let mut v = serde_json::to_value(Brand::default()).unwrap_or_default();
    if let Some(o) = v.as_object_mut() {
        o.insert("_help".into(), serde_json::json!(HELP));
    }
    serde_json::to_string_pretty(&v).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_server_name_is_flag_country_and_brand() {
        let b = Brand::default();
        assert_eq!(b.server_name("🇩🇪", "DE", "Германия"), "🇩🇪 Германия | obhod");
        assert_eq!(b.server_name("🌐", "ZZ", ""), "🌐 | obhod");
    }

    #[test]
    fn custom_template_placeholders() {
        let b = Brand {
            name: "MyVPN".into(),
            server_name: "{name} · {country} ({code}) {flag}".into(),
            ..Brand::default()
        };
        assert_eq!(
            b.server_name("🇫🇮", "FI", "Финляндия"),
            "MyVPN · Финляндия (FI) 🇫🇮"
        );
    }

    #[test]
    fn colors_parse_names_hex_and_index() {
        assert_eq!(parse_color("cyan"), Some(Color::Cyan));
        assert_eq!(parse_color("#00D7FF"), Some(Color::Rgb(0, 215, 255)));
        assert_eq!(parse_color("45"), Some(Color::Indexed(45)));
        assert_eq!(parse_color("nope"), None);
    }

    #[test]
    fn default_json_round_trips_and_accepts_bom_and_partial_files() {
        let d: Brand = serde_json::from_str(&default_json()).expect("default json");
        assert_eq!(d.name, "obhod");
        assert_eq!(d.colors.accent, "cyan");

        let bom = "\u{feff}{\"name\": \"X\"}";
        let b: Brand = serde_json::from_str(bom.trim_start_matches('\u{feff}')).expect("bom json");
        assert_eq!(b.name, "X");
        assert_eq!(b.colors.ok, "green");
        assert_eq!(b.server_name_no_country, "{flag} | {name}");
    }
}

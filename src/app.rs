use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use crate::config::{Components, Config};
use crate::core::background::{self, Tick};
use crate::core::health::{self, HealthReport, Signals};
use crate::core::history::{History, HistoryEntry};
use crate::core::profiles::{self, Change, Current, Profile, ProfileStore};
use crate::core::state::{Component, CoreState, Phase};
use crate::modules::{detect, RunOptions};
use crate::net::manager::{self, FailoverPolicy, Filter, Node, NodeStore, Ranking, Role};
use crate::util;
use crate::worker::{self, Msg};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    /// Minimal UI for a normal person: only what is needed.
    Normal,
    /// Same UI, but the core does nothing to the real system.
    Demo,
    /// Everything is visible; actions are real.
    Dev,
}

impl Mode {
    pub fn parse(s: &str) -> Option<Mode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "normal" | "n" | "default" => Some(Mode::Normal),
            "demo" | "d" => Some(Mode::Demo),
            "dev" | "debug" => Some(Mode::Dev),
            _ => None,
        }
    }

    pub fn is_demo(self) -> bool {
        self == Mode::Demo
    }

    pub fn is_dev(self) -> bool {
        self == Mode::Dev
    }

    pub fn name(self) -> &'static str {
        match self {
            Mode::Normal => "normal",
            Mode::Demo => "demo",
            Mode::Dev => "dev",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Health {
    On,
    Partial,
    Off,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HomeItem {
    Setup,
    Off,
    Profiles,
    Check,
    Update,
    More,
    Exit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdvItem {
    Health,
    Proxies,
    Components,
    History,
    Diagnostics,
    Settings,
    Wizard,
    Back,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SetItem {
    Lang,
    Autoupdate,
    Telemetry,
    Repo,
    OpenFolder,
    Save,
}

#[derive(Clone, Copy, PartialEq)]
pub enum Screen {
    Welcome,
    Home,
    Prelude,
    Simple,
    Progress,
    Result,
    Check,
    Advanced,
    Components,
    Wizard,
    Status,
    Settings,
    Update,
    Off,
    Profiles,
    Proxies,
    ProfilePlan,
    ProfileEdit,
    History,
}

pub enum StepKind {
    YesNo(bool),
    Choice(usize, Vec<&'static str>),
    Text(String),
    Apply,
}

pub struct Step {
    pub ru: &'static str,
    pub en: &'static str,
    pub kind: StepKind,
}

pub struct App {
    pub cfg: Config,
    pub screen: Screen,
    pub mode: Mode,
    /// Last known state of the real system, refreshed on start and after actions.
    pub svc_on: bool,
    pub tg_on: bool,
    /// The current background run is "turn off / roll back".
    pub off_run: bool,
    /// Where the update screen returns on Esc (Home or Advanced).
    pub update_back: Screen,
    pub home_idx: usize,
    pub comp_cursor: usize,
    pub prelude_idx: usize,
    pub found: Vec<detect::Found>,
    pub steps: Vec<Step>,
    pub step_i: usize,
    pub logs: Vec<String>,
    pub progress: u8,
    pub progress_label: String,
    pub running: bool,
    pub rx: Option<Receiver<Msg>>,
    pub status: Vec<String>,
    pub set_idx: usize,
    pub editing_repo: bool,
    pub quit: bool,
    pub show_logs: bool,
    pub adv_idx: usize,
    pub update_idx: usize,
    pub update_mode: Option<worker::UpdateMode>,
    /// Result of the last update: (success, mode). Shown above the update menu.
    pub update_status: Option<(bool, worker::UpdateMode)>,
    pub check_rx: Option<Receiver<Vec<crate::modules::check::CheckItem>>>,
    pub check_items: Option<Vec<crate::modules::check::CheckItem>>,
    /// Result of the last setup/off run: whether all steps succeeded.
    pub last_ok: bool,
    /// Single source of truth for component phases.
    pub core: CoreState,
    pub profiles: ProfileStore,
    pub profile_idx: usize,
    /// Selected profile and the changes the user must confirm.
    pub profile_plan: Option<(Profile, Vec<Change>)>,
    pub editing_profile: Option<Profile>,
    pub profile_edit_row: usize,
    pub health_report: Option<HealthReport>,
    pub history: History,
    /// Short status line for profile import/export and similar actions.
    pub status_msg: Option<String>,
    /// Heartbeat from the background monitor (health refresh, update nudge).
    pub bg_rx: Option<Receiver<Tick>>,
    /// Nodes collected from subscriptions; shown in the proxy manager.
    pub proxies: NodeStore,
    pub proxy_idx: usize,
    pub proxy_rank: Ranking,
    pub proxy_msg: Option<String>,
}

pub fn node_title(n: &Node) -> String {
    let where_ = if n.country.is_empty() {
        n.country_code.clone()
    } else {
        n.country.clone()
    };
    let ms = n
        .latency_ms
        .map(|v| format!("{v} мс"))
        .unwrap_or_else(|| "—".into());
    format!("{} · {} · {ms}", n.protocol.as_str(), where_)
}

pub fn tr<'a>(lang: &str, ru: &'a str, en: &'a str) -> &'a str {
    if lang == "en" {
        en
    } else {
        ru
    }
}

pub const PROFILE_ROWS: usize = 9;

impl App {
    pub fn new(mode: Mode) -> Self {
        let cfg = Config::load();
        let screen = if cfg.first_run {
            Screen::Welcome
        } else {
            Screen::Home
        };
        let data_dir = cfg.data_dir();
        let mut app = Self {
            cfg,
            screen,
            mode,
            svc_on: false,
            tg_on: false,
            off_run: false,
            update_back: Screen::Home,
            home_idx: 0,
            comp_cursor: 0,
            prelude_idx: 0,
            found: Vec::new(),
            steps: Vec::new(),
            step_i: 0,
            logs: Vec::new(),
            progress: 0,
            progress_label: String::new(),
            running: false,
            rx: None,
            status: Vec::new(),
            set_idx: 0,
            editing_repo: false,
            quit: false,
            show_logs: false,
            adv_idx: 0,
            update_idx: 0,
            update_mode: None,
            update_status: None,
            check_rx: None,
            check_items: None,
            last_ok: true,
            core: CoreState::new(),
            profiles: ProfileStore::load(&data_dir),
            profile_idx: 0,
            profile_plan: None,
            editing_profile: None,
            profile_edit_row: 0,
            health_report: None,
            history: History::default(),
            status_msg: None,
            bg_rx: None,
            proxies: NodeStore::default(),
            proxy_idx: 0,
            proxy_rank: Ranking::Balanced,
            proxy_msg: None,
        };
        if let Ok(()) = app.cfg.ensure_dirs() {
            app.profiles = ProfileStore::load(&data_dir);
            app.history = History::load(&data_dir, 200);
        }
        if !app.mode.is_demo() {
            let rep = crate::sys::recover_pending_quiet(&data_dir);
            if !rep.is_clean() {
                app.status_msg = Some(format!(
                    "{}: {}",
                    tr(&app.cfg.lang, "Восстановлено после сбоя", "Recovered after a crash"),
                    rep.log.len()
                ));
            }
            let (tx, rx) = std::sync::mpsc::channel();
            let _ = background::spawn(
                std::time::Duration::from_secs(3600),
                std::time::Duration::from_secs(300),
                tx,
            );
            app.bg_rx = Some(rx);
        }
        app.refresh_health();
        app.proxies = NodeStore::load(&data_dir.join("proxy-nodes.json")).0;
        app
    }

    fn persist(&self) {
        if !self.mode.is_demo() {
            let _ = self.cfg.save();
        }
    }

    /// Reads the real system state (service + Telegram proxy list) once.
    pub fn refresh_health(&mut self) {
        self.svc_on = crate::modules::zapret::service_running()
            || crate::modules::detect::proc_running("winws.exe");
        self.tg_on = self.cfg.data_dir().join("mtproto.txt").exists();
        let demo = self.mode.is_demo();
        self.core.set(
            Component::Bypass,
            if demo || self.svc_on {
                Phase::Running
            } else {
                Phase::Disabled
            },
            if demo || self.svc_on {
                "обход запущен"
            } else {
                "обход выключен"
            },
            None,
        );
        self.core.set(
            Component::Mtproto,
            if demo {
                Phase::Running
            } else if !self.cfg.components.mtproto || !self.tg_on {
                Phase::Disabled
            } else {
                Phase::Configured
            },
            if demo {
                "демо: прокси готов"
            } else if self.tg_on {
                "прокси сохранён"
            } else {
                "прокси не настроен"
            },
            None,
        );
        let tgws = demo || crate::modules::detect::proc_running("TgWsProxy.exe");
        self.core.set(
            Component::Tgws,
            if !self.cfg.components.tgws && !demo {
                Phase::Disabled
            } else if tgws {
                Phase::Running
            } else {
                Phase::Configured
            },
            if tgws {
                "мост запущен"
            } else {
                "мост не запущен"
            },
            None,
        );
        let subs = self.cfg.data_dir().join("subs_alive_plain.txt").exists();
        self.core.set(
            Component::Subscriptions,
            if subs {
                Phase::Configured
            } else {
                Phase::Disabled
            },
            if subs {
                "список серверов есть"
            } else {
                "подписок нет"
            },
            None,
        );
    }

    pub fn health(&self) -> Health {
        if self.mode.is_demo() {
            return Health::On;
        }
        match (self.svc_on, self.tg_on) {
            (true, true) => Health::On,
            (false, false) => Health::Off,
            _ => Health::Partial,
        }
    }

    /// One short line for the main screen: what is on right now.
    pub fn health_text(&self, lang: &str) -> String {
        if self.mode.is_demo() {
            return tr(
                lang,
                "Демо: «включено» только на экране, система не изменена",
                "Demo: \"on\" on screen only, the system is untouched",
            )
            .to_string();
        }
        match self.health() {
            Health::On => tr(
                lang,
                "Включено — можно пользоваться",
                "On - you are good to go",
            )
            .to_string(),
            Health::Partial => {
                let gap = if !self.svc_on && self.tg_on {
                    tr(lang, "обход выключен, Telegram готов", "bypass off, Telegram ready")
                } else {
                    tr(lang, "обход работает, Telegram без прокси", "bypass on, no Telegram proxy")
                };
                format!("{}{}", tr(lang, "Включено частично — ", "Partly on - "), gap)
            }
            Health::Off => tr(
                lang,
                "Сейчас выключено",
                "Currently off",
            )
            .to_string(),
        }
    }

    pub fn home_items(&self) -> Vec<HomeItem> {
        vec![
            HomeItem::Setup,
            HomeItem::Off,
            HomeItem::Profiles,
            HomeItem::Check,
            HomeItem::Update,
            HomeItem::More,
            HomeItem::Exit,
        ]
    }

    pub fn adv_items(&self) -> Vec<AdvItem> {
        let mut v = vec![
            AdvItem::Health,
            AdvItem::Proxies,
            AdvItem::Components,
            AdvItem::History,
            AdvItem::Diagnostics,
            AdvItem::Settings,
        ];
        if self.mode.is_dev() {
            v.push(AdvItem::Wizard);
        }
        v.push(AdvItem::Back);
        v
    }

    pub fn settings_items(&self) -> Vec<SetItem> {
        if self.mode.is_dev() {
            vec![
                SetItem::Lang,
                SetItem::Autoupdate,
                SetItem::Telemetry,
                SetItem::Repo,
                SetItem::OpenFolder,
                SetItem::Save,
            ]
        } else {
            vec![
                SetItem::Lang,
                SetItem::Autoupdate,
                SetItem::OpenFolder,
                SetItem::Save,
            ]
        }
    }

    /// True when the configured auto-update interval has elapsed.
    pub fn update_due(&self) -> bool {
        if self.cfg.autoupdate_days == 0 {
            return false;
        }
        let period = self.cfg.autoupdate_days as u64 * 86_400;
        crate::state::now_secs().saturating_sub(self.cfg.last_update_check) >= period
    }

    pub fn screen_name(&self) -> &'static str {
        match self.screen {
            Screen::Welcome => "Welcome",
            Screen::Home => "Home",
            Screen::Prelude => "Prelude",
            Screen::Simple => "Simple",
            Screen::Progress => "Progress",
            Screen::Result => "Result",
            Screen::Check => "Check",
            Screen::Advanced => "Advanced",
            Screen::Components => "Components",
            Screen::Wizard => "Wizard",
            Screen::Status => "Status",
            Screen::Settings => "Settings",
            Screen::Update => "Update",
            Screen::Off => "Off",
            Screen::Profiles => "Profiles",
            Screen::Proxies => "Proxies",
            Screen::ProfilePlan => "ProfilePlan",
            Screen::ProfileEdit => "ProfileEdit",
            Screen::History => "History",
        }
    }

    pub fn on_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode as K;
        match self.screen {
            Screen::Welcome => {
                if matches!(code, K::Enter | K::Char(' ') | K::Esc) {
                    self.cfg.first_run = false;
                    self.persist();
                    self.screen = Screen::Home;
                }
            }
            Screen::Home => match code {
                K::Up => self.home_idx = self.home_idx.saturating_sub(1),
                K::Down => self.home_idx = (self.home_idx + 1).min(self.home_items().len() - 1),
                K::Char('q') => self.quit = true,
                K::Enter => match self.home_items().get(self.home_idx).copied() {
                    Some(HomeItem::Setup) => self.begin_setup(),
                    Some(HomeItem::Check) => self.start_check(),
                    Some(HomeItem::Profiles) => {
                        self.profile_idx = 0;
                        self.status_msg = None;
                        self.screen = Screen::Profiles;
                    }
                    Some(HomeItem::Update) => {
                        self.update_back = Screen::Home;
                        self.update_idx = 0;
                        self.screen = Screen::Update;
                    }
                    Some(HomeItem::Off) => self.screen = Screen::Off,
                    Some(HomeItem::More) => {
                        self.adv_idx = 0;
                        self.screen = Screen::Advanced;
                    }
                    _ => self.quit = true,
                },
                _ => {}
            },
            Screen::Prelude => match code {
                K::Up => self.prelude_idx = self.prelude_idx.saturating_sub(1),
                K::Down => {
                    self.prelude_idx = (self.prelude_idx + 1).min(self.found.len().saturating_sub(1))
                }
                K::Char(' ') | K::Left | K::Right => {
                    if let Some(f) = self.found.get_mut(self.prelude_idx) {
                        // Telegram is informational: there is nothing to keep or redo.
                        if f.key != "telegram" {
                            f.keep = !f.keep;
                        }
                    }
                }
                K::Enter | K::Esc => {
                    self.steps = build_simple(&self.cfg);
                    self.step_i = 0;
                    self.screen = Screen::Simple;
                }
                _ => {}
            },
            Screen::Simple => self.steps_key(code, true),
            Screen::Progress => {
                if code == K::Char('l') {
                    self.show_logs = !self.show_logs;
                }
            }
            Screen::Result => match code {
                K::Char('r') | K::Char('R') => self.collect_report(),
                K::Enter | K::Esc | K::Char(' ') => {
                    self.off_run = false;
                    self.refresh_health();
                    self.screen = Screen::Home;
                }
                _ => {}
            },
            Screen::Off => match code {
                K::Enter | K::Char(' ') => self.start_off(),
                K::Esc => self.screen = Screen::Home,
                _ => {}
            },
            Screen::Check => match code {
                K::Char('r') | K::Char('R') => {
                    if self.check_rx.is_none() {
                        self.collect_report();
                    }
                }
                K::Esc | K::Enter => {
                    // Keep the screen while the probe is running: leaving now
                    // would silently drop its result.
                    if self.check_rx.is_none() {
                        self.screen = Screen::Home;
                    }
                }
                _ => {}
            },
            Screen::Advanced => match code {
                K::Up => self.adv_idx = self.adv_idx.saturating_sub(1),
                K::Down => self.adv_idx = (self.adv_idx + 1).min(self.adv_items().len() - 1),
                K::Enter => match self.adv_items().get(self.adv_idx).copied() {
                    Some(AdvItem::Health) => {
                        self.start_check();
                    }
                    Some(AdvItem::Proxies) => {
                        self.load_proxies();
                        self.proxy_idx = 0;
                        self.screen = Screen::Proxies;
                    }
                    Some(AdvItem::Components) => {
                        self.comp_cursor = 0;
                        self.screen = Screen::Components;
                    }
                    Some(AdvItem::History) => {
                        self.history = History::load(&self.cfg.data_dir(), 200);
                        self.screen = Screen::History;
                    }
                    Some(AdvItem::Diagnostics) => {
                        self.status = build_status(&self.cfg);
                        self.screen = Screen::Status;
                    }
                    Some(AdvItem::Settings) => {
                        self.set_idx = 0;
                        self.screen = Screen::Settings;
                    }
                    Some(AdvItem::Wizard) => {
                        self.steps = build_steps(&self.cfg);
                        self.step_i = 0;
                        self.screen = Screen::Wizard;
                    }
                    _ => self.screen = Screen::Home,
                },
                K::Esc => self.screen = Screen::Home,
                _ => {}
            },
            Screen::Components => match code {
                K::Up => self.comp_cursor = self.comp_cursor.saturating_sub(1),
                K::Down => self.comp_cursor = (self.comp_cursor + 1).min(5),
                K::Char(' ') => toggle_component(&mut self.cfg.components, self.comp_cursor),
                K::Enter => {
                    self.steps = build_steps(&self.cfg);
                    self.step_i = 0;
                    self.screen = Screen::Wizard;
                }
                K::Esc => self.screen = Screen::Advanced,
                _ => {}
            },
            Screen::Wizard => self.steps_key(code, false),
            Screen::Profiles => self.profiles_key(code),
            Screen::Proxies => self.proxies_key(code),
            Screen::ProfilePlan => match code {
                K::Enter | K::Char(' ') => self.apply_profile(),
                K::Esc => {
                    self.profile_plan = None;
                    self.screen = Screen::Profiles;
                }
                _ => {}
            },
            Screen::ProfileEdit => self.profile_edit_key(code),
            Screen::History => {
                if matches!(code, K::Esc | K::Enter) {
                    self.screen = Screen::Advanced;
                }
            }
            Screen::Status => {
                if matches!(code, K::Esc | K::Enter) {
                    self.screen = Screen::Advanced;
                }
            }
            Screen::Settings => self.settings_key(code),
            Screen::Update => match code {
                K::Up => self.update_idx = self.update_idx.saturating_sub(1),
                K::Down => self.update_idx = (self.update_idx + 1).min(3),
                K::Enter => match self.update_idx {
                    0 => self.start_update(worker::UpdateMode::Proxy),
                    1 => self.start_update(worker::UpdateMode::Subs),
                    2 => self.start_update(worker::UpdateMode::Tools),
                    _ => self.screen = self.update_back,
                },
                K::Esc => self.screen = self.update_back,
                _ => {}
            },
        }
    }

    fn begin_setup(&mut self) {
        if self.mode.is_demo() {
            self.found = demo_found();
        } else {
            self.found = detect::scan();
        }
        if self.found.is_empty() {
            self.steps = build_simple(&self.cfg);
            self.step_i = 0;
            self.screen = Screen::Simple;
        } else {
            self.prelude_idx = 0;
            self.screen = Screen::Prelude;
        }
    }

    fn load_proxies(&mut self) {
        let path = self.cfg.data_dir().join("proxy-nodes.json");
        let (mut store, _) = NodeStore::load(&path);
        if store.nodes.is_empty() {
            let links: Vec<String> = std::fs::read_to_string(
                self.cfg.data_dir().join("subs_alive_plain.txt"),
            )
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.starts_with('#'))
            .map(str::to_string)
            .collect();
            if !links.is_empty() {
                let stats = store.import(&links, "subs_alive_plain.txt", crate::state::now_secs());
                self.proxy_msg = Some(format!(
                    "{}: {} / {}",
                    tr(&self.cfg.lang, "Загружено узлов", "Nodes imported"),
                    stats.imported,
                    stats.seen
                ));
                if !self.mode.is_demo() {
                    let _ = store.save(&path);
                }
            }
        }
        self.proxies = store;
    }

    fn save_proxies(&mut self) {
        if self.mode.is_demo() {
            return;
        }
        let path = self.cfg.data_dir().join("proxy-nodes.json");
        if let Err(e) = self.proxies.save(&path) {
            crate::logger::info(format!("proxies: не сохранено: {e:#}"));
        }
    }

    fn proxy_ids(&self) -> Vec<String> {
        self.proxies
            .ranked(self.proxy_rank, &Filter::default(), crate::state::now_secs())
            .iter()
            .map(|n| n.id.clone())
            .collect()
    }

    fn proxies_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode as K;
        let ids = self.proxy_ids();
        let Some(id) = ids.get(self.proxy_idx).cloned() else {
            if code == K::Esc {
                self.screen = Screen::Advanced;
            }
            return;
        };
        match code {
            K::Up => self.proxy_idx = self.proxy_idx.saturating_sub(1),
            K::Down => self.proxy_idx = (self.proxy_idx + 1).min(ids.len().saturating_sub(1)),
            K::Char('f') | K::Char('F') => {
                let fav = self.proxies.get(&id).map(|n| n.favorite).unwrap_or(false);
                self.proxies.set_favorite(&id, !fav);
                self.save_proxies();
            }
            K::Char('b') | K::Char('B') => {
                self.proxies.set_role(&id, Role::Backup);
                self.save_proxies();
            }
            K::Char('r') | K::Char('R') => {
                self.proxy_rank = match self.proxy_rank {
                    Ranking::Balanced => Ranking::BestLatency,
                    Ranking::BestLatency => Ranking::MostStable,
                    Ranking::MostStable => Ranking::Balanced,
                };
                self.proxy_msg = Some(self.proxy_rank.ru().to_string());
                self.proxy_idx = 0;
            }
            K::Enter | K::Char(' ') | K::Char('p') | K::Char('P') => {
                self.proxies.set_role(&id, Role::Primary);
                self.proxies.previous = self.proxies.active.clone();
                self.proxies.active = Some(id.clone());
                self.proxies.active_since = crate::state::now_secs();
                let name = self
                    .proxies
                    .get(&id)
                    .map(|n| node_title(n))
                    .unwrap_or_else(|| id.clone());
                self.proxy_msg = Some(format!(
                    "{}: {name}",
                    tr(&self.cfg.lang, "Основной сервер", "Primary server")
                ));
                self.record(
                    "proxy",
                    format!("Основной сервер: {name}"),
                    format!("Primary server: {name}"),
                    true,
                );
                self.save_proxies();
            }
            K::Char('o') | K::Char('O') => {
                let decision = manager::decide(
                    &self.proxies,
                    &FailoverPolicy::default(),
                    &Filter::default(),
                    crate::state::now_secs(),
                );
                self.proxy_msg = Some(decision.reason().to_string());
                if decision.switched() {
                    self.proxies
                        .apply_decision(&decision, crate::state::now_secs());
                    self.record(
                        "proxy",
                        format!("Переключение: {}", decision.reason()),
                        format!("Switched: {}", decision.reason()),
                        true,
                    );
                    self.save_proxies();
                }
            }
            K::Esc => self.screen = Screen::Advanced,
            _ => {}
        }
    }

    fn profiles_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode as K;
        let n = self.profiles.profiles.len();
        match code {
            K::Up => self.profile_idx = self.profile_idx.saturating_sub(1),
            K::Down => self.profile_idx = (self.profile_idx + 1).min(n.saturating_sub(1)),
            K::Enter => {
                if let Some(p) = self.profiles.profiles.get(self.profile_idx).cloned() {
                    let changes = profiles::plan(&p, &self.current_profile());
                    self.profile_plan = Some((p, changes));
                    self.screen = Screen::ProfilePlan;
                }
            }
            K::Char('n') | K::Char('N') => {
                let base = self.current_profile();
                let id = self.next_custom_id();
                let p = Profile {
                    id,
                    name_ru: "Свой профиль".into(),
                    name_en: "Custom profile".into(),
                    description_ru: "Создан из текущих настроек".into(),
                    description_en: "Created from the current settings".into(),
                    bypass: base.bypass,
                    dns: base.dns,
                    hosts: base.hosts,
                    mtproto: base.mtproto,
                    tgws: base.tgws,
                    subscriptions: base.subscriptions,
                    client: base.client,
                    autostart: base.autostart,
                };
                self.editing_profile = Some(p);
                self.profile_edit_row = 0;
                self.status_msg = None;
                self.screen = Screen::ProfileEdit;
            }
            K::Char('e') | K::Char('E') => {
                if let Some(mut p) = self.profiles.profiles.get(self.profile_idx).cloned() {
                    // Built-ins are read-only: editing creates a custom copy.
                    let builtin = profiles::builtins().iter().any(|b| b.id == p.id);
                    if builtin {
                        p.id = self.next_custom_id();
                        p.name_ru = format!("{} (копия)", p.name_ru);
                        p.name_en = format!("{} (copy)", p.name_en);
                    }
                    self.editing_profile = Some(p);
                    self.profile_edit_row = 0;
                    self.status_msg = None;
                    self.screen = Screen::ProfileEdit;
                }
            }
            K::Char('x') | K::Char('X') => {
                if let Some(p) = self.profiles.profiles.get(self.profile_idx).cloned() {
                    let dir = self.cfg.data_dir().join("profiles");
                    if self.mode.is_demo() {
                        self.status_msg = Some(tr(
                            &self.cfg.lang,
                            "Демо: экспорт не выполняется",
                            "Demo: export is skipped",
                        )
                        .to_string());
                    } else {
                        match self.profiles.export(&p, &dir) {
                            Ok(path) => {
                                self.status_msg = Some(format!(
                                    "{}: {}",
                                    tr(&self.cfg.lang, "Сохранено", "Saved"),
                                    path.display()
                                ));
                            }
                            Err(e) => {
                                self.status_msg = Some(format!(
                                    "{}: {e:#}",
                                    tr(&self.cfg.lang, "Ошибка экспорта", "Export failed")
                                ))
                            }
                        }
                    }
                }
            }
            K::Char('i') | K::Char('I') => {
                let path = self.cfg.data_dir().join("profiles").join("import.json");
                let lang = self.cfg.lang.clone();
                if self.mode.is_demo() {
                    self.status_msg = Some(tr(&lang, "Демо: импорт не выполняется", "Demo: import is skipped").to_string());
                } else {
                    match std::fs::read_to_string(&path)
                        .map_err(anyhow::Error::from)
                        .and_then(|t| self.profiles.import_str(&t))
                    {
                        Ok(p) => {
                            let _ = self.profiles.save(&self.cfg.data_dir());
                            self.status_msg = Some(format!(
                                "{}: {}",
                                tr(&lang, "Импортирован профиль", "Imported profile"),
                                p.name(&lang)
                            ));
                            self.profile_idx = self
                                .profiles
                                .profiles
                                .iter()
                                .position(|x| x.id == p.id)
                                .unwrap_or(0);
                        }
                        Err(e) => {
                            self.status_msg = Some(format!(
                                "{} {}: {e:#}",
                                tr(&lang, "Положите файл", "Put the file"),
                                path.display()
                            ))
                        }
                    }
                }
            }
            K::Esc => self.screen = Screen::Advanced,
            _ => {}
        }
    }

    fn profile_edit_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode as K;
        let Some(p) = self.editing_profile.as_mut() else {
            self.screen = Screen::Profiles;
            return;
        };
        match code {
            K::Up => self.profile_edit_row = self.profile_edit_row.saturating_sub(1),
            K::Down => {
                self.profile_edit_row = (self.profile_edit_row + 1).min(PROFILE_ROWS - 1)
            }
            K::Left | K::Right | K::Char(' ') => match self.profile_edit_row {
                0 => p.bypass = !p.bypass,
                1 => p.dns = !p.dns,
                2 => p.hosts = !p.hosts,
                3 => p.mtproto = !p.mtproto,
                4 => p.tgws = !p.tgws,
                5 => p.subscriptions = !p.subscriptions,
                6 => {
                    p.client = match p.client.as_str() {
                        "none" => "hiddify".into(),
                        "hiddify" => "v2rayn".into(),
                        "v2rayn" => "happ".into(),
                        _ => "none".into(),
                    }
                }
                7 => p.autostart = !p.autostart,
                _ => {}
            },
            K::Enter => {
                if self.profile_edit_row + 1 < PROFILE_ROWS {
                    self.profile_edit_row += 1;
                } else {
                    let p = self.editing_profile.take().unwrap_or_default();
                    match self.profiles.upsert(p.clone()).and_then(|_| {
                        self.profiles.save(&self.cfg.data_dir())
                    }) {
                        Ok(()) => {
                            self.status_msg = Some(format!(
                                "{}: {}",
                                tr(&self.cfg.lang, "Профиль сохранён", "Profile saved"),
                                p.name(&self.cfg.lang)
                            ));
                            self.profile_idx = self
                                .profiles
                                .profiles
                                .iter()
                                .position(|x| x.id == p.id)
                                .unwrap_or(0);
                            self.screen = Screen::Profiles;
                        }
                        Err(e) => {
                            self.status_msg = Some(format!(
                                "{}: {e:#}",
                                tr(&self.cfg.lang, "Не сохранено", "Not saved")
                            ));
                            self.editing_profile = Some(p);
                        }
                    }
                }
            }
            K::Esc => {
                self.editing_profile = None;
                self.screen = Screen::Profiles;
            }
            _ => {}
        }
    }

    fn next_custom_id(&self) -> String {
        for n in 1..10_000 {
            let id = format!("custom-{n}");
            if self.profiles.get(&id).is_none() {
                return id;
            }
        }
        "custom".into()
    }

    pub fn current_profile(&self) -> Current {
        let c = &self.cfg.components;
        Current {
            bypass: c.zapret,
            dns: c.dns,
            hosts: c.hosts,
            mtproto: c.mtproto,
            tgws: c.tgws,
            subscriptions: c.subs,
            client: self.cfg.client.clone(),
            autostart: self.cfg.autostart,
        }
    }

    fn apply_profile(&mut self) {
        let Some((p, _)) = self.profile_plan.take() else {
            self.screen = Screen::Profiles;
            return;
        };
        self.cfg.components = Components {
            zapret: p.bypass,
            mtproto: p.mtproto,
            tgws: p.tgws,
            hosts: p.hosts,
            subs: p.subscriptions,
            dns: p.dns,
        };
        self.cfg.client = p.client.clone();
        self.cfg.autostart = p.autostart;
        self.cfg.service_mode = true;
        self.persist();
        self.record(
            "profile",
            format!("Применён профиль «{}»", p.name_ru),
            format!("Applied profile \"{}\"", p.name_en),
            true,
        );
        self.spawn_run();
    }

    fn record(&mut self, kind: &str, ru: impl Into<String>, en: impl Into<String>, ok: bool) {
        if self.mode.is_demo() {
            return;
        }
        let entry = HistoryEntry::new(kind, ru, en, ok);
        if History::append(&self.cfg.data_dir(), entry.clone(), 200).is_ok() {
            self.history.entries.push(entry);
            if self.history.entries.len() > 200 {
                self.history.entries.remove(0);
            }
        }
    }

    fn collect_report(&mut self) {
        self.refresh_health();
        let checks = self.check_items.clone().unwrap_or_default();
        match crate::modules::report::write_diagnostics(
            &self.cfg,
            self.mode.name(),
            &checks,
            self.svc_on,
            self.tg_on,
        ) {
            Ok(path) => {
                crate::logger::info(format!("отчёт: {}", path.display()));
                if !self.mode.is_demo() {
                    let _ = crate::util::reveal(&path);
                }
            }
            Err(e) => crate::logger::info(format!("отчёт не создан: {e:#}")),
        }
    }

    fn start_check(&mut self) {
        let (tx, rx) = std::sync::mpsc::channel();
        let demo = self.mode.is_demo();
        std::thread::spawn(move || {
            let items = if demo {
                std::thread::sleep(std::time::Duration::from_millis(900));
                crate::modules::check::demo()
            } else {
                crate::modules::check::run()
            };
            let _ = tx.send(items);
        });
        self.check_rx = Some(rx);
        self.check_items = None;
        self.screen = Screen::Check;
    }

    fn check_value(&self, needle: &str) -> Option<bool> {
        self.check_items
            .as_ref()?
            .iter()
            .find(|i| i.ru.contains(needle))
            .map(|i| i.ok)
    }

    /// Projects raw check results into the core state and a staged diagnosis.
    fn apply_checks_to_core(&mut self) {
        let dns = self.check_value("DNS").or_else(|| self.check_value("Интернет"));
        let youtube = self.check_value("YouTube");
        let discord = self.check_value("Discord");
        let telegram = self.check_value("Telegram");
        let bypass = self.check_value("Обход");
        let target = match (youtube, discord) {
            (Some(a), Some(b)) => Some(a && b),
            _ => None,
        };
        let tgws_running = self.mode.is_demo()
            || detect::proc_running("TgWsProxy.exe");
        let subs_present = self.cfg.data_dir().join("subs_alive_plain.txt").exists();
        let ps = crate::modules::check::proxy_signals(&self.cfg.data_dir());
        let proxy_tls = ps
            .as_ref()
            .filter(|p| p.checked > 0)
            .map(|p| p.tls_ok > 0);
        let proxy_tcp = ps
            .as_ref()
            .filter(|p| p.checked > 0)
            .map(|p| p.tcp_ok > 0);
        let signals = Signals {
            dns_ok: dns,
            // A failed name lookup makes later TCP/TLS results meaningless.
            tcp_ok: if dns == Some(false) {
                None
            } else {
                proxy_tcp.or(target)
            },
            // TLS is checked only for proxies where it is applicable.
            tls_ok: proxy_tls,
            // The probes never speak the proxy protocol, so never claim it.
            protocol_ok: None,
            proxy_configured: self.cfg.components.mtproto || self.cfg.components.tgws,
            proxy_running: self.tg_on,
            proxy_verified: self.tg_on && telegram == Some(true),
            bypass_running: self.svc_on,
            mtproto_ready: self.tg_on,
            tgws_running,
            subscriptions_present: subs_present,
            client_installed: !self.cfg.client.is_empty() && self.cfg.client != "none",
            target_ok: target,
            admin: util::is_admin(),
        };
        let report = health::evaluate(&signals, crate::state::now_secs());

        self.core.set(
            Component::Dns,
            match dns {
                Some(true) => Phase::Operational,
                Some(false) => Phase::Failed,
                None => Phase::Unknown,
            },
            match dns {
                Some(true) => "имена определяются",
                Some(false) => "DNS не отвечает",
                None => "не проверялось",
            },
            None,
        );
        self.core.set(
            Component::Bypass,
            match (self.svc_on, bypass, target) {
                (false, _, _) => Phase::Disabled,
                (true, Some(false), _) => Phase::Failed,
                (true, _, Some(false)) => Phase::Degraded,
                (true, _, Some(true)) => Phase::Operational,
                _ => Phase::Running,
            },
            if self.svc_on {
                "обход запущен"
            } else {
                "обход выключен"
            },
            None,
        );
        self.core.set(
            Component::Mtproto,
            match (self.cfg.components.mtproto, self.tg_on, telegram) {
                (false, _, _) => Phase::Disabled,
                (true, false, _) => Phase::Disabled,
                (true, true, Some(false)) => Phase::Degraded,
                (true, true, Some(true)) => Phase::Operational,
                (true, true, None) => Phase::Configured,
            },
            if self.tg_on {
                "прокси сохранён"
            } else {
                "прокси не настроен"
            },
            None,
        );
        self.core.set(
            Component::Tgws,
            if !self.cfg.components.tgws {
                Phase::Disabled
            } else if tgws_running {
                Phase::Running
            } else {
                Phase::Configured
            },
            if tgws_running {
                "мост запущен"
            } else {
                "мост не запущен"
            },
            None,
        );
        self.core.set(
            Component::Subscriptions,
            if subs_present {
                Phase::Configured
            } else {
                Phase::Disabled
            },
            if subs_present {
                "список серверов есть"
            } else {
                "подписки не настроены"
            },
            None,
        );
        self.core.set(
            Component::Client,
            if signals.client_installed {
                Phase::Installed
            } else {
                Phase::Disabled
            },
            if signals.client_installed {
                "приложение выбрано"
            } else {
                "приложение не нужно"
            },
            None,
        );
        self.core.set(
            Component::Update,
            Phase::Configured,
            if self.update_due() {
                "пора обновить"
            } else {
                "обновления по расписанию"
            },
            None,
        );

        self.health_report = Some(report);
        let total = self.check_items.as_ref().map(|i| i.len()).unwrap_or(0);
        let ok = self
            .check_items
            .as_ref()
            .map(|i| i.iter().filter(|x| x.ok).count())
            .unwrap_or(0);
        self.record(
            "check",
            format!("Проверка сети: {ok} из {total}"),
            format!("Network check: {ok} of {total}"),
            ok == total,
        );
    }

    fn settings_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode as K;
        if self.editing_repo {
            match code {
                K::Enter | K::Esc => {
                    self.editing_repo = false;
                    self.persist();
                }
                K::Backspace => {
                    self.cfg.repo.pop();
                }
                K::Char(c) => self.cfg.repo.push(c),
                _ => {}
            }
            return;
        }
        let item = self.settings_items().get(self.set_idx).copied();
        match code {
            K::Up => self.set_idx = self.set_idx.saturating_sub(1),
            K::Down => {
                self.set_idx = (self.set_idx + 1).min(self.settings_items().len().saturating_sub(1))
            }
            K::Left | K::Right | K::Char(' ') => match item {
                Some(SetItem::Lang) => self.cycle_lang(),
                Some(SetItem::Autoupdate) => self.cycle_autoupdate(),
                Some(SetItem::Telemetry) => {
                    self.cfg.telemetry = !self.cfg.telemetry;
                    self.persist();
                }
                _ => {}
            },
            K::Enter => match item {
                Some(SetItem::Lang) => self.cycle_lang(),
                Some(SetItem::Autoupdate) => self.cycle_autoupdate(),
                Some(SetItem::Telemetry) => {
                    self.cfg.telemetry = !self.cfg.telemetry;
                    self.persist();
                }
                Some(SetItem::Repo) => self.editing_repo = true,
                Some(SetItem::OpenFolder) => self.open_data_folder(),
                _ => {
                    self.persist();
                    self.screen = Screen::Home;
                }
            },
            K::Esc => {
                self.persist();
                self.screen = Screen::Home;
            }
            _ => {}
        }
    }

    fn cycle_lang(&mut self) {
        self.cfg.lang = if self.cfg.lang == "ru" {
            "en".into()
        } else {
            "ru".into()
        };
        self.persist();
    }

    fn cycle_autoupdate(&mut self) {
        self.cfg.autoupdate_days = match self.cfg.autoupdate_days {
            0 => 1,
            1 => 3,
            3 => 7,
            _ => 0,
        };
        self.persist();
    }

    fn open_data_folder(&mut self) {
        let _ = self.cfg.ensure_dirs();
        let path = self.cfg.data_dir();
        if let Err(e) = util::open_url(&path.to_string_lossy()) {
            crate::logger::info(format!("data dir: не удалось открыть: {e:#}"));
        }
    }

    fn steps_key(&mut self, code: crossterm::event::KeyCode, simple: bool) {
        use crossterm::event::KeyCode as K;
        if self.steps.is_empty() {
            self.screen = if simple { Screen::Home } else { Screen::Components };
            return;
        }
        if simple {
            self.simple_key(code);
            return;
        }
        match code {
            K::Esc => self.screen = Screen::Components,
            K::Up => self.step_i = self.step_i.saturating_sub(1),
            K::Down => self.step_i = (self.step_i + 1).min(self.steps.len() - 1),
            K::Left | K::Right | K::Char(' ') => {
                let step = &mut self.steps[self.step_i];
                match &mut step.kind {
                    StepKind::YesNo(v) => *v = !*v,
                    StepKind::Choice(idx, opts) => {
                        if !opts.is_empty() {
                            *idx = (*idx + 1) % opts.len();
                        }
                    }
                    StepKind::Text(s) => {
                        if code == K::Char(' ') {
                            s.push(' ');
                        }
                    }
                    StepKind::Apply => {}
                }
            }
            K::Backspace => {
                if let StepKind::Text(s) = &mut self.steps[self.step_i].kind {
                    s.pop();
                }
            }
            K::Char(c) => {
                if let StepKind::Text(s) = &mut self.steps[self.step_i].kind {
                    s.push(c);
                }
            }
            K::Enter => {
                let is_apply = matches!(self.steps[self.step_i].kind, StepKind::Apply);
                if is_apply || self.step_i == self.steps.len() - 1 {
                    self.apply_advanced();
                } else {
                    self.step_i += 1;
                }
            }
            _ => {}
        }
    }

    /// Rows of a simple form: ↑/↓ move between questions, ←/→ (or Space)
    /// change the answer, Enter goes on and starts setup on the last row.
    fn simple_key(&mut self, code: crossterm::event::KeyCode) {
        use crossterm::event::KeyCode as K;
        match code {
            K::Esc => self.screen = Screen::Home,
            K::Up => self.step_i = self.step_i.saturating_sub(1),
            K::Down => self.step_i = (self.step_i + 1).min(self.steps.len() - 1),
            K::Left | K::Right | K::Char(' ') => {
                let step = &mut self.steps[self.step_i];
                match &mut step.kind {
                    StepKind::YesNo(v) => *v = !*v,
                    StepKind::Choice(idx, opts) => {
                        if !opts.is_empty() {
                            let n = opts.len();
                            *idx = if code == K::Right || code == K::Char(' ') {
                                (*idx + 1) % n
                            } else {
                                (*idx + n - 1) % n
                            };
                        }
                    }
                    StepKind::Text(s) => {
                        if code == K::Char(' ') {
                            s.push(' ');
                        }
                    }
                    StepKind::Apply => {}
                }
            }
            K::Backspace => {
                if let StepKind::Text(s) = &mut self.steps[self.step_i].kind {
                    s.pop();
                }
            }
            K::Char(c) => {
                if let StepKind::Text(s) = &mut self.steps[self.step_i].kind {
                    s.push(c);
                }
            }
            K::Enter => {
                let is_apply = matches!(self.steps[self.step_i].kind, StepKind::Apply);
                if is_apply || self.step_i == self.steps.len() - 1 {
                    self.apply_simple();
                } else {
                    self.step_i += 1;
                }
            }
            _ => {}
        }
    }

    fn apply_simple(&mut self) {
        let mode = find_choice(&self.steps, "What should work?").unwrap_or(0);
        let client_idx = find_choice(&self.steps, "Install a servers app?").unwrap_or(0);
        let folder = find_text(&self.steps, "Folder for apps");
        let autostart = find_yes(&self.steps, "Start automatically with Windows?").unwrap_or(true);
        let full_probe = find_yes(&self.steps, "Pick the best proxy for me?").unwrap_or(true);

        let mut c = match mode {
            1 => Components {
                zapret: true,
                mtproto: false,
                tgws: false,
                hosts: false,
                subs: false,
                dns: true,
            },
            2 => Components {
                zapret: false,
                mtproto: true,
                tgws: true,
                hosts: false,
                subs: false,
                dns: true,
            },
            _ => Components {
                zapret: true,
                mtproto: true,
                tgws: true,
                hosts: false,
                subs: false,
                dns: true,
            },
        };

        let client = match client_idx {
            1 => "hiddify",
            2 => "v2rayn",
            3 => "happ",
            _ => "none",
        };
        if client != "none" {
            c.subs = true;
        }

        self.cfg.components = c;
        self.cfg.client = client.into();
        if let Some(f) = folder {
            self.cfg.client_dir = f.trim().to_string();
        }
        self.cfg.autostart = autostart;
        self.cfg.service_mode = true;
        self.cfg.telemetry = false;
        self.cfg.reminders = false;
        self.cfg.hosts_block_ads = false;
        self.cfg.autoupdate_days = if full_probe { 7 } else { 0 };
        // Setup just fetched fresh lists; do not nag about updates right away.
        self.cfg.last_update_check = crate::state::now_secs();
        if self.cfg.data_dir.is_empty() {
            self.cfg.data_dir = util::exe_dir().join("data").display().to_string();
        }
        let _ = self.cfg.ensure_dirs();
        self.persist();
        self.spawn_run();
    }

    fn apply_advanced(&mut self) {
        for st in &self.steps {
            match &st.kind {
                StepKind::YesNo(v) => match st.en {
                    "Autostart with Windows?" => self.cfg.autostart = *v,
                    "Install zapret as a Windows service?" => self.cfg.service_mode = *v,
                    "Show reminders?" => self.cfg.reminders = *v,
                    "Send anonymous report?" => self.cfg.telemetry = *v,
                    "Add ad/tracker blocklist to hosts?" => self.cfg.hosts_block_ads = *v,
                    _ => {}
                },
                StepKind::Choice(idx, _) => {
                    if st.en == "Auto-update interval" {
                        self.cfg.autoupdate_days =
                            [0u32, 1, 3, 7, 30].get(*idx).copied().unwrap_or(0);
                    } else if st.en == "Servers app" {
                        self.cfg.client = match idx {
                            1 => "hiddify".into(),
                            2 => "v2rayn".into(),
                            3 => "happ".into(),
                            _ => "none".into(),
                        };
                    }
                }
                StepKind::Text(s) => {
                    if st.en == "Folder for data" {
                        self.cfg.data_dir = s.trim().to_string();
                    } else if st.en == "Folder for apps" {
                        self.cfg.client_dir = s.trim().to_string();
                    }
                }
                StepKind::Apply => {}
            }
        }
        if self.cfg.data_dir.is_empty() {
            self.cfg.data_dir = util::exe_dir().join("data").display().to_string();
        }
        let _ = self.cfg.ensure_dirs();
        self.persist();
        self.spawn_run();
    }

    fn run_options(&self) -> RunOptions {
        let keep_zapret = detect::keep_flag(&self.found, "zapret");
        let keep_tgws = detect::keep_flag(&self.found, "tgws");
        let keep_client = detect::keep_flag(&self.found, "client_hiddify")
            || detect::keep_flag(&self.found, "client_v2rayn")
            || detect::keep_flag(&self.found, "client_happ");

        RunOptions {
            components: self.cfg.components.clone(),
            data_dir: self.cfg.data_dir(),
            autostart: self.cfg.autostart,
            service_mode: self.cfg.service_mode,
            hosts_block_ads: self.cfg.hosts_block_ads,
            autoupdate_days: self.cfg.autoupdate_days,
            reminders: self.cfg.reminders,
            telemetry: self.cfg.telemetry,
            repo: self.cfg.repo.clone(),
            keep_zapret,
            keep_tgws,
            keep_client,
            client: self.cfg.client.clone(),
            client_dir: PathBuf::from(&self.cfg.client_dir),
        }
    }

    fn start_update(&mut self, mode: worker::UpdateMode) {
        let opts = self.run_options();
        crate::logger::info(format!(
            "update start · mode={:?} · client={} · data={}",
            mode,
            self.cfg.client,
            opts.data_dir.display()
        ));
        self.logs.clear();
        self.progress = 0;
        self.progress_label = String::new();
        self.running = true;
        self.show_logs = false;
        self.update_status = None;
        self.update_mode = Some(mode);
        self.off_run = false;
        self.rx = Some(if self.mode.is_demo() {
            worker::spawn_update_demo(mode)
        } else {
            worker::spawn_update(opts, mode)
        });
        self.screen = Screen::Progress;
    }

    /// Stops the bypass and returns the system to its normal state.
    fn start_off(&mut self) {
        let opts = self.run_options();
        crate::logger::info("off start · rollback requested");
        self.logs.clear();
        self.progress = 0;
        self.progress_label.clear();
        self.running = true;
        self.show_logs = false;
        self.update_status = None;
        self.update_mode = None;
        self.off_run = true;
        self.rx = Some(if self.mode.is_demo() {
            worker::spawn_off_demo()
        } else {
            worker::spawn_off(opts)
        });
        self.screen = Screen::Progress;
    }

    fn spawn_run(&mut self) {
        let opts = self.run_options();
        crate::logger::info(format!(
            "setup start · components={:?} · client={} · keep(z/t/c)={}/{}/{} · mode={}",
            opts.components,
            opts.client,
            opts.keep_zapret,
            opts.keep_tgws,
            opts.keep_client,
            self.mode.name()
        ));
        self.logs.clear();
        self.progress = 0;
        self.progress_label = String::new();
        self.running = true;
        self.show_logs = false;
        self.update_mode = None;
        self.off_run = false;
        self.rx = Some(if self.mode.is_demo() {
            worker::spawn_demo()
        } else {
            worker::spawn(opts)
        });
        self.screen = Screen::Progress;
    }

    pub fn poll(&mut self) {
        let mut done = None;
        if let Some(rx) = &self.rx {
            while let Ok(msg) = rx.try_recv() {
                match msg {
                    Msg::Log(s) => {
                        crate::logger::info(&s);
                        self.logs.push(s);
                        if self.logs.len() > 400 {
                            self.logs.remove(0);
                        }
                    }
                    Msg::Progress(p, s) => {
                        self.progress = p;
                        self.progress_label = s;
                    }
                    Msg::Done(ok) => {
                        crate::logger::info(format!("worker done · ok={ok}"));
                        done = Some(ok);
                    }
                }
            }
        }
        if let Some(ok) = done {
            self.running = false;
            self.rx = None;
            self.progress = 100;
            self.logs.push(if ok {
                "✓ Готово.".into()
            } else {
                "⚠ Завершено с ошибками (см. лог выше).".into()
            });
            match self.update_mode.take() {
                Some(mode) => {
                    // Back to the simple update menu: the same three actions
                    // stay one keypress away.
                    self.update_status = Some((ok, mode));
                    self.update_idx = 0;
                    self.screen = Screen::Update;
                    if !self.mode.is_demo() {
                        self.cfg.last_update_check = crate::state::now_secs();
                        self.persist();
                    }
                }
                None => {
                    self.last_ok = ok;
                    self.refresh_health();
                    let (ru, en) = if self.off_run {
                        (
                            if ok { "Выключено, настройки возвращены" } else { "Выключено частично" },
                            if ok { "Turned off, settings restored" } else { "Partially turned off" },
                        )
                    } else {
                        (
                            if ok { "Включено: настройка завершена" } else { "Настройка завершилась с ошибками" },
                            if ok { "Turned on: setup finished" } else { "Setup finished with errors" },
                        )
                    };
                    self.record(if self.off_run { "off" } else { "setup" }, ru, en, ok);
                    self.screen = Screen::Result;
                }
            }
        }

        if let Some(rx) = &self.check_rx {
            if let Ok(items) = rx.try_recv() {
                self.check_items = Some(items);
                self.check_rx = None;
                self.apply_checks_to_core();
            }
        }

        let mut health_tick = false;
        let mut update_tick = false;
        if let Some(rx) = &self.bg_rx {
            while let Ok(t) = rx.try_recv() {
                match t {
                    Tick::HealthDue => health_tick = true,
                    Tick::UpdateDue => update_tick = true,
                }
            }
        }
        if health_tick {
            self.refresh_health();
        }
        if update_tick && self.update_due() {
            self.status_msg = Some(
                tr(
                    &self.cfg.lang,
                    "Пора обновить подписки — пункт «Обновить»",
                    "Subscriptions are due - see \"Update\"",
                )
                .to_string(),
            );
        }
    }
}

fn find_choice(steps: &[Step], en: &str) -> Option<usize> {
    steps.iter().find_map(|s| match &s.kind {
        StepKind::Choice(i, _) if s.en == en => Some(*i),
        _ => None,
    })
}

fn find_yes(steps: &[Step], en: &str) -> Option<bool> {
    steps.iter().find_map(|s| match &s.kind {
        StepKind::YesNo(v) if s.en == en => Some(*v),
        _ => None,
    })
}

fn find_text(steps: &[Step], en: &str) -> Option<String> {
    steps.iter().find_map(|s| match &s.kind {
        StepKind::Text(t) if s.en == en => Some(t.clone()),
        _ => None,
    })
}

/// Human-friendly description of the current stage (no jargon).
pub fn friendly_stage(label: &str, lang: &str) -> String {
    let l = label.to_lowercase();
    let ru = if l.contains("zapret") {
        "Настраиваю обход для YouTube и Discord"
    } else if l.contains("mtproto") || l.contains("telegram") {
        "Подбираю быстрый прокси для Telegram"
    } else if l.contains("dns") {
        "Проверяю интернет и DNS"
    } else if l.contains("подпис") {
        "Ищу бесплатные серверы"
    } else if l.contains("hosts") {
        "Убираю рекламу"
    } else if l.contains("tgws") {
        "Готовлю запасной способ для Telegram"
    } else if l.contains("приложение") {
        "Готовлю приложение и подписку"
    } else if l.contains("обнов") {
        "Проверяю и обновляю"
    } else if l.contains("готов") {
        "Почти готово"
    } else if l.contains("выключ") || l.contains("откат") {
        "Выключаю и возвращаю всё как было"
    } else {
        "Настраиваю"
    };
    let en = if l.contains("zapret") {
        "Setting up YouTube and Discord"
    } else if l.contains("mtproto") || l.contains("telegram") {
        "Finding a fast proxy for Telegram"
    } else if l.contains("dns") {
        "Checking internet and DNS"
    } else if l.contains("подпис") {
        "Looking for free servers"
    } else if l.contains("hosts") {
        "Removing ads"
    } else if l.contains("tgws") {
        "Preparing a backup for Telegram"
    } else if l.contains("приложение") {
        "Preparing the app and subscription"
    } else if l.contains("обнов") {
        "Checking and updating"
    } else if l.contains("готов") {
        "Almost done"
    } else if l.contains("выключ") || l.contains("откат") {
        "Turning it off and restoring your system"
    } else {
        "Setting up"
    };
    tr(lang, ru, en).to_string()
}

fn toggle_component(c: &mut Components, i: usize) {
    match i {
        0 => c.zapret = !c.zapret,
        1 => c.mtproto = !c.mtproto,
        2 => c.tgws = !c.tgws,
        3 => c.hosts = !c.hosts,
        4 => c.subs = !c.subs,
        5 => c.dns = !c.dns,
        _ => {}
    }
}

pub fn comp_rows() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("zapret (обход DPI)", "zapret (DPI bypass)", "YouTube, Discord и другие сайты"),
        ("Прокси для Telegram", "Telegram proxy", "автоподбор самого быстрого"),
        ("Запасной мост TgWsProxy", "TgWsProxy fallback", "если прокси не сработал"),
        ("hosts (реклама)", "hosts (ads)", "резервная копия + блок рекламы"),
        ("Бесплатные серверы (VLESS)", "Free servers (VLESS)", "поиск живых узлов"),
        ("DNS / DoH", "DNS / DoH", "чинит определение сайтов"),
    ]
}

fn client_index(cfg: &Config) -> usize {
    match cfg.client.as_str() {
        "hiddify" => 1,
        "v2rayn" => 2,
        "happ" => 3,
        _ => 0,
    }
}

fn default_client_dir(cfg: &Config) -> String {
    if !cfg.client_dir.is_empty() {
        cfg.client_dir.clone()
    } else {
        detect::dir_local_appdata()
            .join("Programs")
            .display()
            .to_string()
    }
}

fn build_simple(cfg: &Config) -> Vec<Step> {
    let mode = if cfg.components.zapret && cfg.components.mtproto {
        0
    } else if cfg.components.zapret {
        1
    } else {
        2
    };
    let mut v = vec![
        Step {
            ru: "Что должно работать?",
            en: "What should work?",
            kind: StepKind::Choice(
                mode,
                vec![
                    "Всё сразу (рекомендую)",
                    "Только YouTube и Discord",
                    "Только Telegram",
                ],
            ),
        },
        Step {
            ru: "Установить приложение для серверов?",
            en: "Install a servers app?",
            kind: StepKind::Choice(
                client_index(cfg),
                vec!["Не нужно", "Hiddify (рекомендую)", "v2rayN", "Happ"],
            ),
        },
    ];
    let (pct, _, _) = util::disk_stats(&util::exe_dir());
    if pct < 10.0 {
        v.push(Step {
            ru: "Мало места на диске",
            en: "Folder for apps",
            kind: StepKind::Text(default_client_dir(cfg)),
        });
    }
    v.push(Step {
        ru: "Запускать при старте Windows?",
        en: "Start automatically with Windows?",
        kind: StepKind::YesNo(cfg.autostart),
    });
    v.push(Step {
        ru: "Настроить прокси для Telegram?",
        en: "Pick the best proxy for me?",
        kind: StepKind::YesNo(true),
    });
    v.push(Step {
        ru: "Готово — включить?",
        en: "Ready - turn it on?",
        kind: StepKind::Apply,
    });
    v
}

fn build_steps(cfg: &Config) -> Vec<Step> {
    let mut v = Vec::new();
    let (pct, _, _) = util::disk_stats(&util::exe_dir());
    if pct < 10.0 {
        v.push(Step {
            ru: "Мало места на диске. Куда скачивать данные?",
            en: "Folder for data",
            kind: StepKind::Text(util::exe_dir().join("data").display().to_string()),
        });
    }
    v.push(Step {
        ru: "Ставить в автозагрузку?",
        en: "Autostart with Windows?",
        kind: StepKind::YesNo(cfg.autostart),
    });
    if cfg.components.zapret {
        v.push(Step {
            ru: "Ставить обход службой Windows?",
            en: "Install zapret as a Windows service?",
            kind: StepKind::YesNo(cfg.service_mode),
        });
    }
    v.push(Step {
        ru: "Автообновление (проверять раз в N дней)",
        en: "Auto-update interval",
        kind: StepKind::Choice(
            [0u32, 1, 3, 7, 30]
                .iter()
                .position(|x| *x == cfg.autoupdate_days)
                .unwrap_or(0),
            vec!["выкл", "1 день", "3 дня", "7 дней", "30 дней"],
        ),
    });
    v.push(Step {
        ru: "Показывать напоминания?",
        en: "Show reminders?",
        kind: StepKind::YesNo(cfg.reminders),
    });
    v.push(Step {
        ru: "Отправлять анонимный отчёт на GitHub?",
        en: "Send anonymous report?",
        kind: StepKind::YesNo(cfg.telemetry),
    });
    if cfg.components.hosts {
        v.push(Step {
            ru: "Добавить блок-лист рекламы в hosts?",
            en: "Add ad/tracker blocklist to hosts?",
            kind: StepKind::YesNo(cfg.hosts_block_ads),
        });
    }
    v.push(Step {
        ru: "Приложение для серверов",
        en: "Servers app",
        kind: StepKind::Choice(
            client_index(cfg),
            vec!["не нужно", "Hiddify", "v2rayN", "Happ"],
        ),
    });
    v.push(Step {
        ru: "Применить и запустить?",
        en: "Apply and run?",
        kind: StepKind::Apply,
    });
    v
}

pub fn build_steps_demo(cfg: &Config) -> Vec<Step> {
    build_steps(cfg)
}

pub fn build_simple_demo(cfg: &Config) -> Vec<Step> {
    build_simple(cfg)
}

/// Plain-language list of what the current answers will change.
pub fn simple_summary(steps: &[Step], lang: &str) -> Vec<String> {
    let mode = find_choice(steps, "What should work?").unwrap_or(0);
    let client = find_choice(steps, "Install a servers app?").unwrap_or(0);
    let autostart = find_yes(steps, "Start automatically with Windows?").unwrap_or(true);
    let what = match mode {
        1 => tr(lang, "обход YouTube и Discord", "YouTube and Discord bypass"),
        2 => tr(lang, "прокси для Telegram", "Telegram proxy"),
        _ => tr(
            lang,
            "обход YouTube/Discord и прокси Telegram",
            "YouTube/Discord bypass and Telegram proxy",
        ),
    };
    let mut v = vec![format!("{}: {what}", tr(lang, "Будет включено", "Will be turned on"))];
    if client != 0 {
        let app = match client {
            1 => "Hiddify",
            2 => "v2rayN",
            _ => "Happ",
        };
        v.push(format!(
            "{}: {app}",
            tr(lang, "Приложение для серверов", "Servers app")
        ));
    }
    v.push(format!(
        "{}: {}",
        tr(lang, "Автозапуск", "Autostart"),
        if autostart {
            tr(lang, "да", "yes")
        } else {
            tr(lang, "нет", "no")
        }
    ));
    v.push(
        tr(
            lang,
            "Ничего не устанавливается без вашего Enter.",
            "Nothing is installed without your Enter.",
        )
        .to_string(),
    );
    v
}

pub fn demo_found() -> Vec<detect::Found> {
    vec![
        detect::Found {
            key: "zapret",
            ru: "Обход для YouTube/Discord (zapret)".into(),
            en: "YouTube/Discord bypass (zapret)".into(),
            detail: "служба: да · процесс: да · C:\\zapret: да".into(),
            keep: true,
        },
        detect::Found {
            key: "tgws",
            ru: "Запасной мост для Telegram (TgWsProxy)".into(),
            en: "Telegram fallback bridge (TgWsProxy)".into(),
            detail: "C:\\Users\\You\\Desktop\\TgWsProxy.exe".into(),
            keep: true,
        },
        detect::Found {
            key: "client_hiddify",
            ru: "Приложение Hiddify".into(),
            en: "Hiddify app".into(),
            detail: "%LOCALAPPDATA%\\Programs\\Hiddify\\Hiddify.exe".into(),
            keep: true,
        },
        detect::Found {
            key: "telegram",
            ru: "Telegram".into(),
            en: "Telegram".into(),
            detail: "Telegram.exe".into(),
            keep: true,
        },
    ]
}

pub(crate) fn build_status(cfg: &Config) -> Vec<String> {
    let d = cfg.data_dir();
    let (pct, free, total) = util::disk_stats(&d);
    let mut v = vec![
        format!(
            "Права администратора: {}",
            if util::is_admin() { "да" } else { "нет" }
        ),
        format!("Папка данных: {}", d.display()),
        if total == 0 {
            "Свободно на диске: не удалось определить (проверьте путь данных)".to_string()
        } else {
            format!(
                "Свободно на диске: {:.1}% ({:.1} ГБ из {:.1} ГБ)",
                pct,
                free as f64 / 1e9,
                total as f64 / 1e9
            )
        },
        format!("Приложение для серверов: {}",
            if cfg.client.is_empty() { "не выбрано" } else { cfg.client.as_str() }
        ),
        format!("Файл лога: {}", cfg.data_dir().join("obhod.log").display()),
        format!("Папка приложений: {}", default_client_dir(cfg)),
    ];
    let opts = RunOptions {
        components: cfg.components.clone(),
        data_dir: d.clone(),
        autostart: cfg.autostart,
        service_mode: cfg.service_mode,
        hosts_block_ads: cfg.hosts_block_ads,
        autoupdate_days: cfg.autoupdate_days,
        reminders: cfg.reminders,
        telemetry: cfg.telemetry,
        repo: cfg.repo.clone(),
        keep_zapret: false,
        keep_tgws: false,
        keep_client: false,
        client: cfg.client.clone(),
        client_dir: PathBuf::from(default_client_dir(cfg)),
    };
    let (tx, _rx) = std::sync::mpsc::channel();
    let ctx = crate::modules::Ctx {
        data: d.clone(),
        opts,
        tx,
        admin: util::is_admin(),
    };
    v.extend(crate::modules::zapret::status(&ctx));
    let mt = d.join("mtproto.txt");
    v.push(format!(
        "Список прокси Telegram: {}",
        if mt.exists() { "есть" } else { "нет" }
    ));
    let subs = d.join("subs_alive_plain.txt");
    v.push(format!(
        "Живые VLESS-узлы: {}",
        if subs.exists() { "есть" } else { "нет" }
    ));
    v
}

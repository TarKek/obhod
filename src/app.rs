use std::path::PathBuf;
use std::sync::mpsc::Receiver;

use crate::config::{Components, Config};
use crate::modules::{detect, RunOptions};
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
    Check,
    Update,
    Settings,
    More,
    Exit,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AdvItem {
    Components,
    Wizard,
    Status,
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
}

pub fn tr<'a>(lang: &str, ru: &'a str, en: &'a str) -> &'a str {
    if lang == "en" {
        en
    } else {
        ru
    }
}

impl App {
    pub fn new(mode: Mode) -> Self {
        let cfg = Config::load();
        let screen = if cfg.first_run {
            Screen::Welcome
        } else {
            Screen::Home
        };
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
        };
        app.refresh_health();
        app
    }

    fn persist(&self) {
        if !self.mode.is_demo() {
            let _ = self.cfg.save();
        }
    }

    /// Reads the real system state (service + Telegram proxy list) once.
    pub fn refresh_health(&mut self) {
        self.svc_on = crate::modules::zapret::service_running();
        self.tg_on = self.cfg.data_dir().join("mtproto.txt").exists();
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
        let mut v = vec![
            HomeItem::Setup,
            HomeItem::Off,
            HomeItem::Check,
            HomeItem::Update,
            HomeItem::Settings,
        ];
        if self.mode.is_dev() {
            v.push(HomeItem::More);
        }
        v.push(HomeItem::Exit);
        v
    }

    pub fn adv_items(&self) -> Vec<AdvItem> {
        if self.mode.is_dev() {
            vec![
                AdvItem::Components,
                AdvItem::Wizard,
                AdvItem::Status,
                AdvItem::Back,
            ]
        } else {
            vec![AdvItem::Back]
        }
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
                    Some(HomeItem::Update) => {
                        self.update_back = Screen::Home;
                        self.update_idx = 0;
                        self.screen = Screen::Update;
                    }
                    Some(HomeItem::Off) => self.screen = Screen::Off,
                    Some(HomeItem::Settings) => {
                        self.set_idx = 0;
                        self.screen = Screen::Settings;
                    }
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
                        f.keep = !f.keep;
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
            Screen::Result => {
                if matches!(code, K::Enter | K::Esc | K::Char(' ')) {
                    self.off_run = false;
                    self.refresh_health();
                    self.screen = Screen::Home;
                }
            }
            Screen::Off => match code {
                K::Enter | K::Char(' ') => self.start_off(),
                K::Esc => self.screen = Screen::Home,
                _ => {}
            },
            Screen::Check => {
                if matches!(code, K::Esc | K::Enter) {
                    self.screen = Screen::Home;
                }
            }
            Screen::Advanced => match code {
                K::Up => self.adv_idx = self.adv_idx.saturating_sub(1),
                K::Down => self.adv_idx = (self.adv_idx + 1).min(self.adv_items().len() - 1),
                K::Enter => match self.adv_items().get(self.adv_idx).copied() {
                    Some(AdvItem::Components) => {
                        self.comp_cursor = 0;
                        self.screen = Screen::Components;
                    }
                    Some(AdvItem::Wizard) => {
                        self.steps = build_steps(&self.cfg);
                        self.step_i = 0;
                        self.screen = Screen::Wizard;
                    }
                    Some(AdvItem::Status) => {
                        self.status = build_status(&self.cfg);
                        self.screen = Screen::Status;
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
                    self.refresh_health();
                    self.screen = Screen::Result;
                }
            }
        }

        if let Some(rx) = &self.check_rx {
            if let Ok(items) = rx.try_recv() {
                self.check_items = Some(items);
                self.check_rx = None;
            }
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
            ru: "Приложение для серверов?",
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
        ru: "Подобрать лучший прокси?",
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

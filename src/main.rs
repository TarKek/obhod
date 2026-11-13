mod app;
mod brand;
mod config;
mod logger;
mod modules;
mod selfupdate;
mod state;
mod ui;
mod util;
mod worker;

use std::time::Duration;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("obhod {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let mode = match parse_mode(&args) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("obhod: {e}");
            std::process::exit(2);
        }
    };

    init_logging(&args);

    if args.iter().any(|a| a == "--log-path") {
        if let Some(p) = logger::path() {
            println!("{}", p.display());
        }
        return;
    }
    if args.iter().any(|a| a == "--open-log") {
        if let Some(p) = logger::path() {
            let _ = std::process::Command::new("notepad").arg(&p).spawn();
        }
        return;
    }
    if args.iter().any(|a| a == "--brand") {
        brand::ensure_file();
        println!("{}", brand::path().display());
        return;
    }
    if args.iter().any(|a| a == "--selftest") {
        selftest();
        return;
    }
    if args.iter().any(|a| a == "--check-updates") {
        check_updates_cli();
        return;
    }
    if args.iter().any(|a| a == "--demo-static") {
        let explicit = args
            .iter()
            .any(|a| a == "-m" || a == "--mode" || a == "--demo" || a == "--dev");
        demo_static(if explicit { mode } else { app::Mode::Demo });
        return;
    }
    if args.iter().any(|a| a == "--self-update") {
        match selfupdate::check() {
            Ok(Some(tag)) => println!("доступна версия {tag} (сейчас {})", selfupdate::current_version()),
            Ok(None) => println!("обновлений нет ({})", selfupdate::current_version()),
            Err(e) => eprintln!("obhod: не удалось проверить обновления: {e:#}"),
        }
        return;
    }
    if args.iter().any(|a| a == "--update-now") {
        match selfupdate::check_and_apply(&["--version".to_string()]) {
            Ok(true) => return,
            Ok(false) => println!("обновлений нет ({})", selfupdate::current_version()),
            Err(e) => eprintln!("obhod: обновление не удалось: {e:#}"),
        }
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--parse-bat") {
        if let Some(path) = args.get(pos + 1) {
            let p = std::path::PathBuf::from(path);
            let text = std::fs::read_to_string(&p).unwrap_or_default();
            let dir = p.parent().map(|x| x.to_path_buf()).unwrap_or_default();
            match modules::zapret::bat_to_cmdline(&text, &dir) {
                Some(cmd) => println!("{cmd}"),
                None => println!("не удалось разобрать {}", p.display()),
            }
        }
        return;
    }

    if !mode.is_demo() && !util::is_admin() && !args.iter().any(|a| a == "--elevated" || a == "--no-elevate") {
        let mut extra = args.clone();
        extra.push("--elevated".to_string());
        match util::relaunch_elevated(&extra) {
            Ok(()) => return,
            Err(e) => {
                logger::info(format!("запуск без прав администратора: {e:#}"));
                eprintln!("obhod: без прав администратора часть действий будет недоступна");
            }
        }
    }

    if !args.iter().any(|a| a == "--no-update") {
        match selfupdate::check_and_apply(&args) {
            Ok(true) => return,
            Ok(false) => {}
            Err(e) => logger::info(format!("self-update: {e:#}")),
        }
    }

    let mut terminal = ratatui::init();
    let res = run(&mut terminal, mode);
    ratatui::restore();
    if let Err(e) = res {
        eprintln!("obhod: {e:#}");
        std::process::exit(1);
    }
}

/// `-m/--mode normal|demo|dev`; `--demo` / `--dev` are short aliases.
fn parse_mode(args: &[String]) -> Result<app::Mode, String> {
    let mut mode = app::Mode::Normal;
    if let Some(pos) = args.iter().position(|a| a == "-m" || a == "--mode") {
        let raw = args
            .get(pos + 1)
            .ok_or_else(|| "--mode: нужно значение normal|demo|dev".to_string())?;
        mode = app::Mode::parse(raw)
            .ok_or_else(|| format!("--mode: неизвестное значение «{raw}» (normal|demo|dev)"))?;
    }
    if args.iter().any(|a| a == "--demo") {
        mode = app::Mode::Demo;
    }
    if args.iter().any(|a| a == "--dev") {
        mode = app::Mode::Dev;
    }
    Ok(mode)
}

fn init_logging(args: &[String]) {
    let cfg = config::Config::load();
    logger::init(cfg.data_dir().join("obhod.log"));
    logger::info(format!(
        "obhod {} · exe={} · admin={} · data={}",
        env!("CARGO_PKG_VERSION"),
        util::exe_dir().display(),
        util::is_admin(),
        cfg.data_dir().display()
    ));
    logger::info(format!("args: {args:?}"));
}

fn demo_static(mode: app::Mode) {
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    let backend = TestBackend::new(100, 30);
    let mut term = Terminal::new(backend).expect("terminal");
    let mut app = app::App::new(mode);
    app.cfg.first_run = false;

    let screens = [
        ("HOME", app::Screen::Home),
        ("WELCOME", app::Screen::Welcome),
        ("PRELUDE", app::Screen::Prelude),
        ("SIMPLE", app::Screen::Simple),
        ("RESULT", app::Screen::Result),
        ("CHECK", app::Screen::Check),
        ("STATUS", app::Screen::Status),
        ("COMPONENTS", app::Screen::Components),
        ("WIZARD", app::Screen::Wizard),
        ("OFF", app::Screen::Off),
        ("UPDATE", app::Screen::Update),
        ("SETTINGS", app::Screen::Settings),
        ("ADVANCED", app::Screen::Advanced),
        ("PROGRESS", app::Screen::Progress),
    ];
    for (name, screen) in screens {
        app.screen = screen;
        if matches!(screen, app::Screen::Prelude) {
            app.found = app::demo_found();
            app.prelude_idx = 0;
        }
        if matches!(screen, app::Screen::Simple) {
            app.steps = app::build_simple_demo(&app.cfg);
            app.step_i = app.steps.len().saturating_sub(1);
        }
        if matches!(screen, app::Screen::Check) {
            app.check_items = Some(crate::modules::check::demo());
        }
        if matches!(screen, app::Screen::Status) {
            app.status = app::build_status(&app.cfg);
        }
        if matches!(screen, app::Screen::Wizard) {
            app.steps = app::build_simple_demo(&app.cfg);
        }
        if matches!(screen, app::Screen::Update) {
            app.update_idx = 1;
            app.update_status = Some((true, worker::UpdateMode::Subs));
        }
        if matches!(screen, app::Screen::Settings) {
            app.set_idx = 4;
        }
        app.logs = vec!["скачиваю zapret...".into(), "✓ готово".into()];
        app.progress = 62;
        app.progress_label = "MTProto".into();
        app.home_idx = 0;
        term.draw(|f| ui::draw(f, &app)).expect("draw");
        let buf = term.backend().buffer().clone();
        println!("======== {name} ========");
        for y in 0..buf.area.height {
            let mut line = String::new();
            for x in 0..buf.area.width {
                line.push_str(buf[(x, y)].symbol());
            }
            println!("{}", line.trim_end());
        }
    }
}

fn check_updates_cli() {
    let cfg = config::Config::load();
    let opts = match modules::prepare(&cfg) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("obhod: {e:#}");
            return;
        }
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let ctx = modules::Ctx {
        data: cfg.data_dir(),
        opts,
        tx: tx.clone(),
        admin: util::is_admin(),
    };
    let _ = modules::update::check(&ctx);
    drop(ctx);
    drop(tx);
    for msg in rx {
        if let worker::Msg::Log(s) = msg {
            logger::info(&s);
            println!("{s}");
        }
    }
}

fn selftest() {
    let cfg = config::Config::load();
    let dir = util::exe_dir();
    let (pct, free, total) = util::disk_stats(&dir);
    println!("obhod {}", env!("CARGO_PKG_VERSION"));
    println!("exe dir      : {}", dir.display());
    println!("admin        : {}", util::is_admin());
    println!("data dir     : {}", cfg.data_dir().display());
    println!(
        "disk free    : {:.1}% ({:.1} GB / {:.1} GB)",
        pct,
        free as f64 / 1e9,
        total as f64 / 1e9
    );
    println!("components   : {:?}", cfg.components);
    let ctx = modules::Ctx {
        data: cfg.data_dir(),
        opts: modules::RunOptions {
            components: cfg.components.clone(),
            data_dir: cfg.data_dir(),
            autostart: cfg.autostart,
            service_mode: cfg.service_mode,
            hosts_block_ads: cfg.hosts_block_ads,
            autoupdate_days: cfg.autoupdate_days,
            reminders: cfg.reminders,
            telemetry: cfg.telemetry,
            repo: cfg.repo.clone(),
            keep_zapret: false,
            keep_tgws: false,
            keep_client: true,
            client: cfg.client.clone(),
            client_dir: std::path::PathBuf::from(&cfg.client_dir),
        },
        tx: {
            let (tx, _rx) = std::sync::mpsc::channel();
            tx
        },
        admin: util::is_admin(),
    };
    for line in modules::zapret::status(&ctx) {
        println!("{line}");
    }
    println!("--- обнаружено в системе ---");
    let found = modules::detect::scan();
    if found.is_empty() {
        println!("(ничего не найдено)");
    }
    for f in found {
        println!("{:<10} {}  [{}]", f.key, f.ru, f.detail);
    }
    println!("config file  : {}", config::Config::path().display());
    println!("brand file   : {}", brand::path().display());
    println!("brand name   : {}", brand::name());
    println!("brand server : {}", brand::sample("ru"));
}

fn run(terminal: &mut ratatui::DefaultTerminal, mode: app::Mode) -> anyhow::Result<()> {
    logger::info(format!("UI start · mode={}", mode.name()));
    if mode.is_demo() {
        let _ = brand::name();
    } else {
        brand::ensure_file();
    }
    let mut app = app::App::new(mode);
    let mut last_screen = app.screen_name();
    logger::info(format!("screen: {last_screen}"));
    loop {
        app.poll();
        terminal.draw(|f| ui::draw(f, &app))?;

        if crossterm::event::poll(Duration::from_millis(120))? {
            if let crossterm::event::Event::Key(key) = crossterm::event::read()? {
                if key.kind == crossterm::event::KeyEventKind::Press {
                    logger::info(format!(
                        "key {:?} @ {}",
                        key.code,
                        app.screen_name()
                    ));
                    app.on_key(key.code);
                    let now = app.screen_name();
                    if now != last_screen {
                        logger::info(format!("screen: {last_screen} -> {now}"));
                        last_screen = now;
                    }
                }
            }
        }
        if app.quit {
            break;
        }
    }
    logger::info("UI exit");
    Ok(())
}

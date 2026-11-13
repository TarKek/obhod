use ratatui::prelude::*;
use ratatui::widgets::*;

use crate::app::{
    comp_rows, friendly_stage, simple_summary, tr, AdvItem, App, Health, HomeItem, Screen, SetItem,
    StepKind,
};
use crate::brand;
use crate::worker::UpdateMode;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Min(0),
        Constraint::Length(2),
    ])
    .split(f.area());

    draw_header(f, chunks[0], app);

    match app.screen {
        Screen::Welcome => draw_welcome(f, chunks[1], app),
        Screen::Home => draw_home(f, chunks[1], app),
        Screen::Prelude => draw_prelude(f, chunks[1], app),
        Screen::Simple => draw_simple(f, chunks[1], app),
        Screen::Progress => draw_progress(f, chunks[1], app),
        Screen::Result => draw_result(f, chunks[1], app),
        Screen::Check => draw_check(f, chunks[1], app),
        Screen::Advanced => draw_advanced(f, chunks[1], app),
        Screen::Components => draw_components(f, chunks[1], app),
        Screen::Wizard => draw_wizard(f, chunks[1], app),
        Screen::Status => draw_status(f, chunks[1], app),
        Screen::Settings => draw_settings(f, chunks[1], app),
        Screen::Update => draw_update(f, chunks[1], app),
        Screen::Off => draw_off(f, chunks[1], app),
    }

    draw_footer(f, chunks[2], app);
}

fn draw_header(f: &mut Frame, area: Rect, app: &App) {
    let name = brand::name();
    let title = match app.mode {
        crate::app::Mode::Demo => format!(" {name} v{} · ДЕМО ", crate::selfupdate::current_version()),
        crate::app::Mode::Dev => format!(" {name} v{} · DEV ", crate::selfupdate::current_version()),
        crate::app::Mode::Normal => format!(" {name} v{} ", crate::selfupdate::current_version()),
    };
    let border = if app.mode.is_demo() {
        brand::warn()
    } else {
        brand::accent()
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(border))
        .title(Span::styled(
            title,
            Style::default().fg(border).bold(),
        ));
    let hint = if app.mode.is_demo() {
        tr(
            &app.cfg.lang,
            "демо-режим: ничего не устанавливается и не меняется",
            "demo mode: nothing is installed or changed",
        )
    } else if !crate::util::is_admin() {
        tr(
            &app.cfg.lang,
            "ограниченный режим: нет прав администратора — часть действий не сработает",
            "limited mode: not an administrator - some actions will be skipped",
        )
    } else {
        brand::tagline(&app.cfg.lang)
    };
    let no_admin = !app.mode.is_demo() && !crate::util::is_admin();
    f.render_widget(
        Paragraph::new(hint)
            .block(block)
            .alignment(Alignment::Center)
            .style(Style::default().fg(if app.mode.is_demo() || no_admin {
                brand::warn()
            } else {
                brand::text()
            })),
        area,
    );
}

fn draw_footer(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let hints = match app.screen {
        Screen::Welcome => tr(lang, "Enter — начать", "Enter to start"),
        Screen::Home => {
            if app.update_due() {
                tr(
                    lang,
                    "↑/↓ — выбрать, Enter — открыть · пора проверить обновления (пункт «Обновить»)",
                    "↑/↓ select, Enter open · time to check updates (\"Update\" item)",
                )
            } else {
                tr(
                    lang,
                    "↑/↓ — выбрать, Enter — открыть, q — выход",
                    "↑/↓ select, Enter open, q quit",
                )
            }
        }
        Screen::Prelude => tr(
            lang,
            "↑/↓ — программа, ←/→ или Space — оставить/настроить заново, Enter — дальше",
            "↑/↓ program, ←/→ or Space keep/redo, Enter next",
        ),
        Screen::Simple => tr(
            lang,
            "↑/↓ — вопрос, ←/→ или Space — ответ, Enter — далее, Esc — отмена",
            "↑/↓ question, ←/→ or Space answer, Enter next, Esc cancel",
        ),
        Screen::Progress => tr(
            lang,
            "подождите, идёт настройка...  (L — подробности)",
            "please wait, working...  (L details)",
        ),
        Screen::Result => tr(
            lang,
            "Enter — в меню · R — собрать отчёт",
            "Enter back to menu · R collect report",
        ),
        Screen::Check => tr(
            lang,
            "Enter — в меню · R — собрать отчёт для тестера",
            "Enter back to menu · R collect a report",
        ),
        Screen::Advanced => tr(lang, "↑/↓, Enter — открыть, Esc — назад", "↑/↓, Enter open, Esc back"),
        Screen::Components => tr(
            lang,
            "Space — вкл/выкл, Enter — далее, Esc — назад",
            "Space toggle, Enter next, Esc back",
        ),
        Screen::Wizard => tr(lang, "↑/↓ шаг, ←/→ значение, Enter далее", "↑/↓ step, ←/→ value, Enter next"),
        Screen::Status => tr(lang, "Esc — назад", "Esc back"),
        Screen::Settings => tr(lang, "↑/↓, ←/→, Enter, Esc — назад", "↑/↓, ←/→, Enter, Esc back"),
        Screen::Update => tr(
            lang,
            "↑/↓ — выбрать, Enter — выполнить, Esc — назад",
            "↑/↓ select, Enter run, Esc back",
        ),
        Screen::Off => tr(
            lang,
            "Enter — выключить и вернуть как было, Esc — отмена",
            "Enter to turn off and restore, Esc to cancel",
        ),
    };
    f.render_widget(
        Paragraph::new(hints)
            .style(Style::default().fg(brand::muted()))
            .alignment(Alignment::Center),
        area,
    );
}

fn block(title: &str) -> Block<'_> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(brand::muted()))
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(brand::text()),
        ))
}

/// Shared description column: per-list, so long titles never push it away.
fn menu_col<'a>(titles: impl IntoIterator<Item = &'a str>) -> usize {
    let max = titles
        .into_iter()
        .map(|t| t.chars().count())
        .max()
        .unwrap_or(0);
    max.clamp(18, 30) + 2
}

/// One menu row shared by every list: `▶ Title   description`, the selected
/// row is filled to the full width so it reads as a real menu.
fn menu_row(title: &str, desc: &str, selected: bool, width: usize, col: usize) -> ListItem<'static> {
    let base = if selected {
        Style::default()
            .fg(brand::on_accent())
            .bg(brand::accent())
    } else {
        Style::default()
    };
    let title_style = if selected {
        base.bold()
    } else {
        Style::default().fg(brand::accent()).bold()
    };
    let desc_style = if selected {
        base
    } else {
        Style::default().fg(brand::secondary())
    };
    let marker = if selected { "▶ " } else { "  " };
    let pad = col.saturating_sub(title.chars().count()) + 2;
    let head_len = 1 + marker.chars().count() + title.chars().count() + pad;
    let tail = width.saturating_sub(head_len + desc.chars().count());
    ListItem::new(Line::from(vec![
        Span::styled(format!(" {marker}"), base),
        Span::styled(title.to_string(), title_style),
        Span::styled(" ".repeat(pad), base),
        Span::styled(desc.to_string(), desc_style),
        Span::styled(" ".repeat(tail), base),
    ]))
}

fn inner_width(area: Rect) -> usize {
    area.width.saturating_sub(2) as usize
}

fn draw_welcome(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let text = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!(
                "  {} {}",
                tr(lang, "Привет! Это", "Hi! This is"),
                brand::name()
            ),
            Style::default().fg(brand::accent()).bold(),
        )),
        Line::from(""),
        Line::from(tr(
            lang,
            "  Он вернёт доступ к YouTube, Discord и Telegram. Без регистрации и оплаты.",
            "  It brings YouTube, Discord and Telegram back. No sign-up, no payment.",
        )),
        Line::from(""),
        Line::from(tr(
            lang,
            "  Всё хранится рядом с программой. Ничего не ставится без вашего нажатия.",
            "  Everything lives next to the app. Nothing is installed without your OK.",
        )),
        Line::from(""),
        Line::from(Span::styled(
            tr(
                lang,
                "  Нажмите Enter, чтобы начать.",
                "  Press Enter to begin.",
            ),
            Style::default().fg(brand::ok()).bold(),
        )),
    ];
    f.render_widget(
        Paragraph::new(text).block(block(tr(lang, "Добро пожаловать", "Welcome"))),
        area,
    );
}

fn draw_home(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let mut items: Vec<ListItem> = Vec::new();

    // What is on right now, in one line.
    let (mark, color) = match app.health() {
        Health::On => ("✓", brand::ok()),
        Health::Partial => ("•", brand::warn()),
        Health::Off => ("○", brand::secondary()),
    };
    items.push(ListItem::new(Line::from(vec![
        Span::raw(" "),
        Span::styled(
            format!(" {mark} {} ", app.health_text(lang)),
            Style::default().fg(brand::on_accent()).bg(color).bold(),
        ),
    ])));
    items.push(ListItem::new(Line::from("")));

    let width = inner_width(area);
    let rows: Vec<(&str, &str)> = app
        .home_items()
        .iter()
        .map(|item| match item {
            HomeItem::Setup => (
                tr(lang, "Включить всё", "Turn everything on"),
                tr(
                    lang,
                    "YouTube, Discord, Telegram — одна кнопка",
                    "YouTube, Discord, Telegram - one button",
                ),
            ),
            HomeItem::Check => (
                tr(lang, "Проверить", "Check"),
                tr(
                    lang,
                    "за пару секунд покажет, что не так",
                    "shows what is wrong in a few seconds",
                ),
            ),
            HomeItem::Update => (
                tr(lang, "Обновить", "Update"),
                tr(
                    lang,
                    "прокси, подписка и программы",
                    "proxy, subscription and programs",
                ),
            ),
            HomeItem::Off => (
                tr(lang, "Выключить", "Turn off"),
                tr(
                    lang,
                    "остановить обход, вернуть DNS и hosts",
                    "stop the bypass, restore DNS and hosts",
                ),
            ),
            HomeItem::More => (
                tr(lang, "Ещё", "More"),
                tr(lang, "компоненты и диагностика", "components and diagnostics"),
            ),
            HomeItem::Settings => (
                tr(lang, "Настройки", "Settings"),
                tr(lang, "язык, папка данных, напоминания", "language, data folder, reminders"),
            ),
            HomeItem::Exit => (tr(lang, "Выход", "Exit"), ""),
        })
        .collect();
    let col = menu_col(rows.iter().map(|(t, _)| *t));
    for (i, (title, desc)) in rows.iter().enumerate() {
        items.push(menu_row(title, desc, i == app.home_idx, width, col));
    }

    f.render_widget(
        List::new(items).block(block(tr(lang, "Главное меню", "Main menu"))),
        area,
    );
}

fn draw_prelude(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let mut items: Vec<ListItem> = Vec::new();

    items.push(ListItem::new(Line::from(Span::styled(
        tr(
            lang,
            "Мы нашли уже установленные программы — ничего не перезапишем без вашего согласия.",
            "We found some programs already installed - nothing is overwritten without your consent.",
        ),
        Style::default().fg(brand::text()),
    ))));
    items.push(ListItem::new(Line::from("")));

    let keep = tr(lang, "оставить как есть", "keep as is");
    let again = tr(lang, "настроить заново", "set up again");

    let width = inner_width(area);
    let names: Vec<&str> = app
        .found
        .iter()
        .map(|f| tr(lang, &f.ru, &f.en))
        .collect();
    let col = menu_col(names.iter().copied());

    for (i, fnd) in app.found.iter().enumerate() {
        let selected = i == app.prelude_idx;
        items.push(menu_row(names[i], &fnd.detail, selected, width, col));
        if fnd.key == "telegram" {
            items.push(ListItem::new(Line::from(Span::styled(
                tr(lang, "     только информация", "     informational only"),
                Style::default().fg(brand::muted()),
            ))));
        } else {
            items.push(ListItem::new(choice_line(
                &[(keep, fnd.keep), (again, !fnd.keep)],
                selected,
                width,
            )));
        }
        items.push(ListItem::new(Line::from("")));
    }

    items.push(ListItem::new(Line::from(Span::styled(
        tr(
            lang,
            "Enter — продолжить настройку",
            "Enter to continue setup",
        ),
        Style::default().fg(brand::ok()).bold(),
    ))));

    f.render_widget(
        List::new(items).block(block(tr(lang, "Уже установлено", "Already installed"))),
        area,
    );
}

fn draw_simple(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let total = app.steps.len().max(1);
    let current = app.step_i.min(total - 1);

    let mut items: Vec<ListItem> = Vec::new();
    let width = inner_width(area);
    let mut current_row = 0usize;
    for (i, st) in app.steps.iter().enumerate() {
        let selected = i == current;
        let title = tr(lang, st.ru, st.en);
        if selected {
            current_row = items.len();
        }

        items.push(menu_row(title, "", selected, width, 18));

        let row_style = if selected {
            Style::default().fg(brand::on_accent()).bg(brand::accent())
        } else {
            Style::default().fg(brand::secondary())
        };

        match &st.kind {
            StepKind::YesNo(v) => {
                let opts = [(tr(lang, "Да", "Yes"), *v), (tr(lang, "Нет", "No"), !*v)];
                items.push(ListItem::new(choice_line(&opts, selected, width)));
            }
            StepKind::Choice(idx, opts) => {
                let opts: Vec<(&str, bool)> = opts
                    .iter()
                    .enumerate()
                    .map(|(n, o)| (*o, n == *idx))
                    .collect();
                items.push(ListItem::new(choice_line(&opts, selected, width)));
            }
            StepKind::Text(s) => {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("     ", row_style),
                    Span::styled(format!("{s}_"), row_style),
                ])));
            }
            StepKind::Apply => {
                let hint = tr(
                    lang,
                    "нажмите Enter — и всё заработает",
                    "press Enter and it will work",
                );
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("     ", row_style),
                    Span::styled(hint, Style::default().fg(brand::ok()).bold()),
                ])));
                if selected {
                    for line in simple_summary(&app.steps, lang) {
                        items.push(ListItem::new(Line::from(Span::styled(
                            format!("       {line}"),
                            Style::default().fg(brand::secondary()),
                        ))));
                    }
                }
            }
        }

        if i + 1 < app.steps.len() {
            items.push(ListItem::new(Line::from("")));
        }
    }

    let title = format!(
        "{} · {} {} / {}",
        tr(lang, "Включить всё", "Turn everything on"),
        tr(lang, "вопрос", "question"),
        current + 1,
        total
    );
    let mut state = ListState::default();
    state.select(Some(current_row));
    f.render_stateful_widget(List::new(items).block(block(&title)), area, &mut state);
}

/// One row of answer options: `● chosen   ○ other   ○ other`.
fn choice_line(opts: &[(&str, bool)], selected: bool, width: usize) -> Line<'static> {
    let base = if selected {
        Style::default().fg(brand::on_accent()).bg(brand::accent())
    } else {
        Style::default().fg(brand::secondary())
    };
    const INDENT: usize = 5;
    let mut spans: Vec<Span<'static>> = vec![Span::styled(" ".repeat(INDENT), base)];
    let mut used = INDENT;
    for (n, (label, active)) in opts.iter().enumerate() {
        let style = if *active {
            if selected {
                Style::default().fg(brand::on_accent()).bg(brand::ok()).bold()
            } else {
                Style::default().fg(brand::ok()).bold()
            }
        } else {
            base
        };
        let mark = if *active { "●" } else { "○" };
        let text = format!("{mark} {label}");
        used += text.chars().count();
        spans.push(Span::styled(text, style));
        if n + 1 < opts.len() {
            spans.push(Span::styled("   ", base));
            used += 3;
        }
    }
    if selected {
        spans.push(Span::styled(" ".repeat(width.saturating_sub(used)), base));
    }
    Line::from(spans)
}

fn draw_progress(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let chunks = Layout::vertical([Constraint::Length(3), Constraint::Length(3), Constraint::Min(0)])
        .split(area);
    let pct = app.progress as f64 / 100.0;
    let gauge = Gauge::default()
        .block(block(tr(lang, "Прогресс", "Progress")))
        .gauge_style(Style::default().fg(brand::ok()))
        .ratio(pct)
        .label(format!("{}%", app.progress));
    f.render_widget(gauge, chunks[0]);

    let stage = friendly_stage(&app.progress_label, lang);
    f.render_widget(
        Paragraph::new(stage)
            .block(block(tr(lang, "Что происходит", "What is happening")))
            .style(Style::default().fg(brand::accent()).bold()),
        chunks[1],
    );

    if app.show_logs {
        let tail: Vec<Line> = app
            .logs
            .iter()
            .rev()
            .take(16)
            .rev()
            .map(|s| Line::from(s.clone()))
            .collect();
        f.render_widget(
            Paragraph::new(tail).block(block("log")).wrap(Wrap { trim: true }),
            chunks[2],
        );
    } else {
        let text = tr(
            lang,
            "Это может занять 1–2 минуты. Ничего не закрывайте.",
            "This can take 1-2 minutes. Please keep the window open.",
        );
        f.render_widget(
            Paragraph::new(text)
                .block(block(tr(lang, "Совет", "Tip")))
                .style(Style::default().fg(brand::secondary())),
            chunks[2],
        );
    }
}

fn draw_result(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    if app.off_run {
        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled(
                if app.last_ok {
                    tr(lang, "  Готово — выключено.", "  Done - it is off.")
                } else {
                    tr(
                        lang,
                        "  Выключено, но не всё удалось.",
                        "  Turned off, but not everything succeeded.",
                    )
                },
                Style::default()
                    .fg(if app.last_ok { brand::ok() } else { brand::warn() })
                    .bold(),
            )),
            Line::from(""),
            Line::from(tr(
                lang,
                "  Обход остановлен, DNS и hosts возвращены как было.",
                "  The bypass is stopped, DNS and hosts are restored.",
            )),
            Line::from(tr(
                lang,
                "  Файлы программы остались на месте: включить можно снова.",
                "  Program files stay in place: you can turn it on again.",
            )),
            Line::from(""),
        ];
        if !app.last_ok {
            lines.push(Line::from(Span::styled(
                tr(
                    lang,
                    "  R — собрать отчёт для проверки.",
                    "  R - collect a report for support.",
                ),
                Style::default().fg(brand::warn()),
            )));
            lines.push(Line::from(""));
        }
        lines.push(Line::from(Span::styled(
            tr(lang, "  Enter — в меню.", "  Enter to return to the menu."),
            Style::default().fg(brand::muted()),
        )));
        f.render_widget(
            Paragraph::new(lines)
                .block(block(tr(lang, "Результат", "Result")))
                .wrap(Wrap { trim: false }),
            area,
        );
        return;
    }
    let c = &app.cfg.components;
    let has_warn = !app.last_ok;
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            if has_warn {
                tr(
                    lang,
                    "  Готово, но что-то не получилось.",
                    "  Done, but something failed.",
                )
            } else {
                tr(lang, "  Готово!", "  Done!")
            },
            Style::default()
                .fg(if has_warn { brand::warn() } else { brand::ok() })
                .bold(),
        )),
        Line::from(""),
    ];
    if app.last_ok {
        if c.zapret {
            lines.push(Line::from(tr(
                lang,
                "  ✓ YouTube и Discord должны открываться.",
                "  ✓ YouTube and Discord should open.",
            )));
        }
        if c.mtproto {
            lines.push(Line::from(tr(
                lang,
                "  ✓ Telegram: откройте его — должно появиться окно «Включить прокси»,",
                "  ✓ Telegram: open it - a proxy prompt should appear,",
            )));
            lines.push(Line::from(tr(
                lang,
                "    нажмите «Включить».",
                "    press \"Enable\".",
            )));
        }
        if c.tgws {
            lines.push(Line::from(tr(
                lang,
                "  ✓ Запасной способ для Telegram подготовлен (если понадобится).",
                "  ✓ A backup path for Telegram is ready (if needed).",
            )));
        }
        let client = app.cfg.client.as_str();
        if client != "none" && !client.is_empty() {
            let name = match client {
                "hiddify" => "Hiddify",
                "v2rayn" => "v2rayN",
                "happ" => "Happ",
                _ => "приложение",
            };
            lines.push(Line::from(format!(
                "  ✓ {name} установлен и запущен."
            )));
            lines.push(Line::from(tr(
                lang,
                "  Ссылка на подписку скопирована в буфер обмена.",
                "  The subscription link is copied to the clipboard.",
            )));
            lines.push(Line::from(tr(
                lang,
                "  В приложении: «Добавить подписку» → вставить (Ctrl+V) → «Добавить».",
                "  In the app: \"Add subscription\" -> paste (Ctrl+V) -> \"Add\".",
            )));
            lines.push(Line::from(format!(
                "  {} «{}» {}",
                tr(lang, "Серверы будут вида", "Servers look like"),
                brand::sample(lang),
                tr(lang, "— по 2 быстрых на страну.", "- 2 fastest per country.")
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            tr(lang, "  Что не удалось:", "  What failed:"),
            Style::default().fg(brand::err()).bold(),
        )));
        for line in app
            .logs
            .iter()
            .filter(|l| l.contains('⚠'))
            .take(3)
        {
            lines.push(Line::from(Span::styled(
                format!("  • {}", line.trim_start_matches(['⚠', ' '])),
                Style::default().fg(brand::secondary()),
            )));
        }
    }
    lines.push(Line::from(""));
    if has_warn {
        lines.push(Line::from(Span::styled(
            tr(
                lang,
                "  Что-то не получилось. Нажмите R — соберём отчёт для проверки.",
                "  Something failed. Press R to collect a report for support.",
            ),
            Style::default().fg(brand::warn()).bold(),
        )));
        lines.push(Line::from(""));
    }
    lines.push(Line::from(Span::styled(
        tr(
            lang,
            "  Если что-то не работает — вернитесь и нажмите «Проверить».",
            "  If something does not work - go back and press \"Check\".",
        ),
        Style::default().fg(brand::warn()),
    )));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        tr(
            lang,
            "  Нажмите Enter, чтобы вернуться в меню.",
            "  Press Enter to return to the menu.",
        ),
        Style::default().fg(brand::muted()),
    )));

    f.render_widget(
        Paragraph::new(lines)
            .block(block(tr(lang, "Результат", "Result")))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn draw_check(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    match &app.check_items {
        None => {
            f.render_widget(
                Paragraph::new(tr(lang, "  Проверяю доступ...", "  Checking access..."))
                    .block(block(tr(lang, "Проверка", "Check")))
                    .style(Style::default().fg(brand::accent())),
                area,
            );
        }
        Some(items) => {
            let names: Vec<&str> = items
                .iter()
                .map(|it| tr(lang, &it.ru, &it.en))
                .collect();
            let col = menu_col(names.iter().copied());
            let ok_n = items.iter().filter(|i| i.ok).count();
            let total = items.len();
            let (summary, summary_color) = if ok_n == total {
                (
                    format!(
                        "{} {} / {}",
                        tr(lang, "Работает всё:", "Everything works:"),
                        ok_n,
                        total
                    ),
                    brand::ok(),
                )
            } else {
                (
                    format!(
                        "{} {} / {}",
                        tr(lang, "Работает:", "Working:"),
                        ok_n,
                        total
                    ),
                    brand::warn(),
                )
            };
            let mut lines: Vec<Line> = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("  {summary}"),
                    Style::default().fg(summary_color).bold(),
                )),
                Line::from(""),
            ];
            for (n, it) in items.iter().enumerate() {
                let (mark, style) = if it.ok {
                    ("✓", Style::default().fg(brand::ok()).bold())
                } else {
                    ("✗", Style::default().fg(brand::err()).bold())
                };
                let name = names[n];
                let detail = tr(lang, &it.detail_ru, &it.detail_en);
                let pad = col.saturating_sub(name.chars().count()) + 2;
                lines.push(Line::from(vec![
                    Span::styled(format!("   {mark}  "), style),
                    Span::styled(name.to_string(), Style::default().bold()),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(detail.to_string(), Style::default().fg(brand::secondary())),
                ]));
            }
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled(
                tr(
                    lang,
                    "  Если что-то не работает — нажмите «Включить всё»: это исправит.",
                    "  If something is wrong - press \"Turn everything on\" to fix it.",
                ),
                Style::default().fg(brand::warn()),
            )));
            lines.push(Line::from(Span::styled(
                tr(
                    lang,
                    "  R — собрать отчёт (файл откроется в проводнике).",
                    "  R - collect a report (opens in Explorer).",
                ),
                Style::default().fg(brand::muted()),
            )));
            f.render_widget(
                Paragraph::new(lines).block(block(tr(lang, "Проверка", "Check"))),
                area,
            );
        }
    }
}

fn draw_advanced(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let width = inner_width(area);
    let rows: Vec<(&str, &str)> = app
        .adv_items()
        .iter()
        .map(|item| match item {
            AdvItem::Components => (
                tr(lang, "Компоненты", "Components"),
                tr(lang, "что включать", "what to turn on"),
            ),
            AdvItem::Wizard => (
                tr(lang, "Мастер настройки", "Setup wizard"),
                tr(lang, "пошагово", "step by step"),
            ),
            AdvItem::Status => (
                tr(lang, "Диагностика", "Diagnostics"),
                tr(lang, "права, пути, версии", "rights, paths, versions"),
            ),
            AdvItem::Back => (tr(lang, "Назад", "Back"), ""),
        })
        .collect();
    let col = menu_col(rows.iter().map(|(t, _)| *t));
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, (title, desc))| menu_row(title, desc, i == app.adv_idx, width, col))
        .collect();
    let title = if app.mode.is_dev() {
        tr(lang, "Тонкая настройка", "Advanced")
    } else {
        tr(lang, "Ещё", "More")
    };
    f.render_widget(List::new(items).block(block(title)), area);
}

fn draw_components(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let c = &app.cfg.components;
    let on = [c.zapret, c.mtproto, c.tgws, c.hosts, c.subs, c.dns];
    let rows = comp_rows();
    let width = inner_width(area);
    let titles: Vec<String> = rows
        .iter()
        .enumerate()
        .map(|(i, (ru, en, _))| {
            let name = tr(lang, ru, en);
            format!("{} {name}", if on[i] { "[x]" } else { "[ ]" })
        })
        .collect();
    let col = menu_col(titles.iter().map(String::as_str));
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, (_, _, desc))| {
            menu_row(&titles[i], desc, i == app.comp_cursor, width, col)
        })
        .collect();
    f.render_widget(
        List::new(items).block(block(tr(lang, "Компоненты", "Components"))),
        area,
    );
}

fn draw_wizard(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let width = inner_width(area);
    let rows: Vec<(&str, String)> = app
        .steps
        .iter()
        .map(|st| {
            let label = tr(lang, st.ru, st.en);
            let value = match &st.kind {
                StepKind::YesNo(v) => {
                    if *v {
                        tr(lang, "да", "yes").to_string()
                    } else {
                        tr(lang, "нет", "no").to_string()
                    }
                }
                StepKind::Choice(idx, opts) => opts.get(*idx).copied().unwrap_or("").to_string(),
                StepKind::Text(s) => format!("{s}_"),
                StepKind::Apply => tr(lang, "применить", "apply").to_string(),
            };
            (label, value)
        })
        .collect();
    let col = menu_col(rows.iter().map(|(t, _)| *t));
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, (label, value))| menu_row(label, value, i == app.step_i, width, col))
        .collect();
    f.render_widget(
        List::new(items).block(block(tr(lang, "Мастер", "Wizard"))),
        area,
    );
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let items: Vec<ListItem> = app
        .status
        .iter()
        .map(|s| {
            ListItem::new(Line::from(Span::styled(
                format!(" {s}"),
                Style::default().fg(brand::text()),
            )))
        })
        .collect();
    f.render_widget(
        List::new(items).block(block(tr(lang, "Диагностика", "Diagnostics"))),
        area,
    );
}

fn draw_update(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let rows = [
        (
            tr(lang, "Прокси Telegram", "Telegram proxy"),
            tr(
                lang,
                "найти быстрый и включить в Telegram",
                "find a fast one and enable it in Telegram",
            ),
        ),
        (
            tr(lang, "Подписка в клиенте", "Client subscription"),
            tr(
                lang,
                "перепроверить серверы и обновить подписку",
                "recheck servers and refresh the subscription",
            ),
        ),
        (
            tr(lang, "Программы", "Programs"),
            tr(
                lang,
                "zapret, TgWsProxy, приложение",
                "zapret, TgWsProxy, app",
            ),
        ),
        (tr(lang, "Назад", "Back"), ""),
    ];

    let mut items: Vec<ListItem> = Vec::new();
    if let Some((ok, mode)) = app.update_status {
        let color = if ok { brand::ok() } else { brand::err() };
        let text = if ok {
            format!(
                "  ✓ {}: {}",
                tr(lang, "Готово", "Done"),
                mode.label_lang(lang)
            )
        } else {
            format!(
                "  ⚠ {}: {} · {} data\\obhod.log",
                tr(lang, "С ошибками", "Finished with errors"),
                mode.label_lang(lang),
                tr(lang, "подробности в", "details in")
            )
        };
        items.push(ListItem::new(Line::from(Span::styled(
            text,
            Style::default().fg(color).bold(),
        ))));
        if ok && mode == UpdateMode::Subs {
            items.push(ListItem::new(Line::from(Span::styled(
                tr(
                    lang,
                    "  Ссылка скопирована в буфер — вставьте её в VPN-приложение (Ctrl+V).",
                    "  Link copied to clipboard - paste it into the VPN app (Ctrl+V).",
                ),
                Style::default().fg(brand::secondary()),
            ))));
        }
        items.push(ListItem::new(Line::from("")));
    }

    let width = inner_width(area);
    let col = menu_col(rows.iter().map(|(t, _)| *t));
    for (i, (title, desc)) in rows.iter().enumerate() {
        items.push(menu_row(title, desc, i == app.update_idx, width, col));
    }

    f.render_widget(
        List::new(items).block(block(tr(lang, "Обновления", "Updates"))),
        area,
    );
}

fn draw_off(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let mut lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            tr(
                lang,
                "  Выключить обход и вернуть систему как было?",
                "  Turn the bypass off and restore your system?",
            ),
            Style::default().fg(brand::accent()).bold(),
        )),
        Line::from(""),
        Line::from(tr(
            lang,
            "  • служба обхода будет остановлена и удалена",
            "  • the bypass service will be stopped and removed",
        )),
        Line::from(tr(
            lang,
            "  • блок рекламы уберём из hosts, остальные записи не тронем",
            "  • our ad block is removed from hosts, your lines stay",
        )),
        Line::from(tr(
            lang,
            "  • DNS снова будет получаться автоматически",
            "  • DNS goes back to automatic",
        )),
        Line::from(tr(
            lang,
            "  • автозапуск будет выключен",
            "  • autostart will be turned off",
        )),
        Line::from(""),
        Line::from(tr(
            lang,
            "  Файлы программы останутся — включить можно снова.",
            "  Program files stay in place - you can turn it on again.",
        )),
    ];
    if app.mode.is_demo() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            tr(
                lang,
                "  Демо: на самом деле ничего не изменится.",
                "  Demo: nothing will actually change.",
            ),
            Style::default().fg(brand::warn()),
        )));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        tr(
            lang,
            "  Enter — выключить, Esc — отмена.",
            "  Enter to turn off, Esc to cancel.",
        ),
        Style::default().fg(brand::ok()).bold(),
    )));
    f.render_widget(
        Paragraph::new(lines).block(block(tr(lang, "Выключить", "Turn off"))),
        area,
    );
}

fn draw_settings(f: &mut Frame, area: Rect, app: &App) {
    let lang = app.cfg.lang.as_str();
    let width = inner_width(area);
    let rows: Vec<(&str, String)> = app
        .settings_items()
        .iter()
        .map(|item| match item {
            SetItem::Lang => (
                tr(lang, "Язык", "Language"),
                if app.cfg.lang == "ru" { "Русский" } else { "English" }.to_string(),
            ),
            SetItem::Autoupdate => (
                tr(lang, "Напоминать об обновлениях", "Update reminder"),
                match app.cfg.autoupdate_days {
                    0 => tr(lang, "выкл", "off").to_string(),
                    1 => tr(lang, "1 день", "1 day").to_string(),
                    3 => tr(lang, "3 дня", "3 days").to_string(),
                    7 => tr(lang, "7 дней", "7 days").to_string(),
                    _ => tr(lang, "30 дней", "30 days").to_string(),
                },
            ),
            SetItem::Telemetry => (
                tr(lang, "Телеметрия", "Telemetry"),
                if app.cfg.telemetry { "on" } else { "off" }.to_string(),
            ),
            SetItem::Repo => (
                "GitHub repo",
                format!(
                    "{}{}",
                    if app.cfg.repo.is_empty() {
                        "—"
                    } else {
                        &app.cfg.repo
                    },
                    if app.editing_repo { "_" } else { "" }
                ),
            ),
            SetItem::OpenFolder => (
                tr(lang, "Открыть папку данных", "Open data folder"),
                tr(lang, "где лежат файлы", "where the files are").to_string(),
            ),
            SetItem::Save => (tr(lang, "Готово — назад", "Done - back"), String::new()),
        })
        .collect();
    let col = menu_col(rows.iter().map(|(t, _)| *t));
    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .map(|(i, (title, value))| menu_row(title, value, i == app.set_idx, width, col))
        .collect();
    f.render_widget(
        List::new(items).block(block(tr(lang, "Настройки", "Settings"))),
        area,
    );
}

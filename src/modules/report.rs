use anyhow::Result;

use crate::modules::Ctx;
use crate::util;

pub fn run(ctx: &Ctx) -> Result<()> {
    if !ctx.opts.telemetry {
        ctx.log("Телеметрия выключена — ничего не отправляю.");
        return Ok(());
    }
    if ctx.opts.repo.trim().is_empty() {
        ctx.log("⚠ Телеметрия включена, но не задан GitHub-репозиторий в настройках.");
        return Ok(());
    }

    let mut body = String::new();
    body.push_str(&format!("### {} report\n\n", crate::brand::name()));
    body.push_str(&format!("- version: {}\n", env!("CARGO_PKG_VERSION")));
    body.push_str(&format!("- os: {}\n", std::env::consts::OS));
    body.push_str(&format!(
        "- admin: {}\n",
        if ctx.admin { "yes" } else { "no" }
    ));
    body.push_str(&format!("- data_dir: {}\n", ctx.data.display()));
    body.push_str(&format!(
        "- components: zapret={} mtproto={} tgws={} hosts={} subs={} dns={}\n",
        ctx.opts.components.zapret,
        ctx.opts.components.mtproto,
        ctx.opts.components.tgws,
        ctx.opts.components.hosts,
        ctx.opts.components.subs,
        ctx.opts.components.dns
    ));
    body.push_str("\n_Отправлено добровольно, без идентификаторов._\n");

    let path = ctx.data.join("report.txt");
    std::fs::write(&path, &body)?;

    let url = format!(
        "https://github.com/{}/issues/new?title={}&body={}",
        ctx.opts.repo,
        enc("obhod report"),
        enc(&body)
    );
    ctx.log("Открываю GitHub с готовым отчётом (вы можете его не отправлять).");
    if let Err(e) = util::open_url(&url) {
        ctx.log(format!("⚠ не удалось открыть браузер: {e}"));
    }
    Ok(())
}

fn enc(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

//! DNS snapshot / restore, per network interface.
//!
//! Policy:
//! * Before any DNS change we snapshot **every** adapter: GUID, alias, DHCP vs
//!   static per address family, the exact IPv4/IPv6 server lists, and the DoH
//!   templates Windows exposes (`Get-DnsClientDohServerAddress`, Windows 11).
//! * Restore puts the *exact* previous lists back per interface and per family,
//!   not just "automatic". Interfaces are matched by GUID, so a renamed adapter
//!   is still restored.
//! * The snapshot is written atomically with `complete: true`. A crash while
//!   writing leaves `complete: false`, which
//!   [`SnapshotState::Incomplete`] reports on the next start; no DNS change can
//!   have happened at that point, so the stale file is simply discarded.
//!
//! All process calls go through [`DnsBackend`], so tests never touch the real
//! system.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::fsx;

pub const SNAPSHOT_FILE: &str = "dns-snapshot.json";
pub const SNAPSHOT_VERSION: u32 = 1;

/// Address family used by the backend primitives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::V4 => "V4",
            Family::V6 => "V6",
        }
    }
}

/// A DoH template Windows knows about (global, not per interface).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct DohEntry {
    #[serde(default)]
    pub server: String,
    #[serde(default)]
    pub template: String,
    #[serde(default)]
    pub autoupgrade: bool,
}

/// Whether this Windows build exposes DoH at all, plus its templates.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct DohState {
    #[serde(default)]
    pub supported: bool,
    #[serde(default)]
    pub entries: Vec<DohEntry>,
}

/// Public resolvers used for the bypass. Kept here so apply and restore always
/// agree on what "ours" means.
pub const PUBLIC_V4: [&str; 2] = ["1.1.1.1", "8.8.8.8"];
pub const PUBLIC_DOH: [(&str, &str); 2] = [
    ("1.1.1.1", "https://cloudflare-dns.com/dns-query"),
    ("8.8.8.8", "https://dns.google/dns-query"),
];

/// DNS configuration of one adapter, as read before the change.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IfaceDns {
    #[serde(default)]
    pub guid: String,
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub index: u32,
    /// Adapter is up.
    #[serde(default)]
    pub connected: bool,
    /// Virtual adapter (VPN/TUN/tunnel) rather than a physical NIC.
    #[serde(default)]
    pub virtual_adapter: bool,
    /// Has an IPv4 default gateway (the "active" interface).
    #[serde(default)]
    pub gateway: bool,
    #[serde(default)]
    pub dhcp_v4: bool,
    #[serde(default)]
    pub dhcp_v6: bool,
    #[serde(default)]
    pub servers_v4: Vec<String>,
    #[serde(default)]
    pub servers_v6: Vec<String>,
}

impl IfaceDns {
    pub fn servers(&self, family: Family) -> &[String] {
        match family {
            Family::V4 => &self.servers_v4,
            Family::V6 => &self.servers_v6,
        }
    }

    pub fn dhcp(&self, family: Family) -> bool {
        match family {
            Family::V4 => self.dhcp_v4,
            Family::V6 => self.dhcp_v6,
        }
    }

    pub fn label(&self) -> String {
        if self.alias.is_empty() {
            self.guid.clone()
        } else {
            self.alias.clone()
        }
    }
}

/// Everything needed to undo a DNS change.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct DnsSnapshot {
    pub version: u32,
    pub created: u64,
    /// False while capture is in progress or after a crash. Never applied.
    #[serde(default)]
    pub complete: bool,
    #[serde(default)]
    pub tx: String,
    #[serde(default)]
    pub interfaces: Vec<IfaceDns>,
    #[serde(default)]
    pub doh: DohState,
    /// Why DoH could not be read (old Windows), if so.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub doh_error: Option<String>,
}

impl DnsSnapshot {
    pub fn empty(tx: &str) -> Self {
        Self {
            version: SNAPSHOT_VERSION,
            created: crate::util::now_unix(),
            complete: false,
            tx: tx.to_string(),
            interfaces: Vec::new(),
            doh: DohState::default(),
            doh_error: None,
        }
    }

    /// Adapters we consider "in use": physical ones with a default gateway first,
    /// then any gateway adapter, then anything that is up.
    ///
    /// Virtual adapters (VPN/TUN) come last on purpose: changing DNS on a tunnel
    /// can break the VPN, and the physical link is what actually resolves names
    /// for the rest of the system.
    pub fn active(&self) -> Vec<&IfaceDns> {
        let physical: Vec<&IfaceDns> = self
            .interfaces
            .iter()
            .filter(|i| i.connected && i.gateway && !i.virtual_adapter)
            .collect();
        if !physical.is_empty() {
            return physical;
        }
        let gated: Vec<&IfaceDns> = self
            .interfaces
            .iter()
            .filter(|i| i.connected && i.gateway)
            .collect();
        if !gated.is_empty() {
            return gated;
        }
        self.interfaces.iter().filter(|i| i.connected).collect()
    }

    pub fn find(&self, guid: &str) -> Option<&IfaceDns> {
        self.interfaces
            .iter()
            .find(|i| i.guid.eq_ignore_ascii_case(guid))
    }
}

/// Mockable system DNS access.
pub trait DnsBackend {
    /// All adapters with their current DNS state.
    fn read_all(&self) -> Result<Vec<IfaceDns>>;
    /// DoH templates and whether this build supports them.
    fn read_doh(&self) -> Result<DohState> {
        Ok(DohState::default())
    }
    fn set_servers(&self, iface: &IfaceDns, family: Family, servers: &[String]) -> Result<()>;
    /// Both families back to DHCP-provided servers.
    fn reset_all(&self, iface: &IfaceDns) -> Result<()>;
    fn flush(&self) -> Result<()>;
    fn add_doh(&self, server: &str, template: &str, autoupgrade: bool) -> Result<()> {
        let _ = (server, template, autoupgrade);
        Ok(())
    }
    fn remove_doh(&self, server: &str) -> Result<()> {
        let _ = server;
        Ok(())
    }
}

// ───────────────────────── capture ─────────────────────────

/// Read the current state and persist a complete snapshot atomically.
///
/// If a complete snapshot already exists it is kept and returned: it describes
/// the state *before* the first change, which is what "turn it off and give it
/// back as it was" must restore. Re-running "enable" therefore never overwrites
/// the original with our own public-DNS state.
///
/// Step 1 writes an `complete: false` placeholder, so a crash during capture is
/// visible later instead of being mistaken for a usable snapshot.
pub fn capture_and_save(dir: &Path, be: &dyn DnsBackend, tx: &str) -> Result<DnsSnapshot> {
    if let Ok(SnapshotState::Complete(existing)) = read_state(dir) {
        return Ok(*existing);
    }
    let path = snapshot_path(dir);
    let placeholder = DnsSnapshot::empty(tx);
    write_snapshot(&path, &placeholder).context("не удалось записать заготовку снимка DNS")?;

    let mut snap = DnsSnapshot::empty(tx);
    snap.interfaces = be
        .read_all()
        .context("не удалось прочитать настройки DNS")?;
    match be.read_doh() {
        Ok(state) => snap.doh = state,
        Err(e) => snap.doh_error = Some(format!("{e:#}")),
    }
    snap.complete = true;
    write_snapshot(&path, &snap)?;
    Ok(snap)
}

pub fn snapshot_path(dir: &Path) -> PathBuf {
    dir.join(SNAPSHOT_FILE)
}

pub fn write_snapshot(path: &Path, snap: &DnsSnapshot) -> Result<()> {
    let data = serde_json::to_vec_pretty(snap)?;
    fsx::write_atomic(path, &data)
        .with_context(|| format!("не удалось записать {}", path.display()))
}

pub fn read_snapshot_file(path: &Path) -> Result<Option<DnsSnapshot>> {
    let Some(bytes) = fsx::try_read(path)? else {
        return Ok(None);
    };
    let snap = serde_json::from_slice::<DnsSnapshot>(&bytes)
        .with_context(|| format!("снимок DNS {} повреждён", path.display()))?;
    Ok(Some(snap))
}

#[derive(Debug, Clone, PartialEq)]
pub enum SnapshotState {
    /// No snapshot on disk.
    Missing,
    /// Capture started but never finished (crash); harmless, discard it.
    Incomplete,
    Complete(Box<DnsSnapshot>),
}

pub fn read_state(dir: &Path) -> Result<SnapshotState> {
    match read_snapshot_file(&snapshot_path(dir))? {
        None => Ok(SnapshotState::Missing),
        Some(s) if !s.complete => Ok(SnapshotState::Incomplete),
        Some(s) => Ok(SnapshotState::Complete(Box::new(s))),
    }
}

pub fn remove_snapshot(dir: &Path) -> Result<bool> {
    let p = snapshot_path(dir);
    if p.exists() {
        fsx::RealFs::remove(&p)?;
        Ok(true)
    } else {
        Ok(false)
    }
}

// ───────────────────────── apply / verify ─────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionOutcome {
    pub alias: String,
    pub what: String,
    pub ok: bool,
    pub detail: String,
}

impl ActionOutcome {
    fn ok(alias: impl Into<String>, what: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
            what: what.into(),
            ok: true,
            detail: detail.into(),
        }
    }
    fn fail(alias: impl Into<String>, what: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            alias: alias.into(),
            what: what.into(),
            ok: false,
            detail: detail.into(),
        }
    }
}

/// Point the active adapters at `v4`. Returns one outcome per interface; a
/// single failure does not abort the others (the caller verifies later).
pub fn apply_v4(be: &dyn DnsBackend, snap: &DnsSnapshot, v4: &[String]) -> Vec<ActionOutcome> {
    let mut out = Vec::new();
    for iface in snap.active() {
        match be.set_servers(iface, Family::V4, v4) {
            Ok(()) => out.push(ActionOutcome::ok(
                iface.label(),
                "dns-v4",
                format!("стало: {}", v4.join(", ")),
            )),
            Err(e) => out.push(ActionOutcome::fail(
                iface.label(),
                "dns-v4",
                format!("{e:#}"),
            )),
        }
    }
    out
}

/// Verify that `iface.alias` now uses exactly `want` for IPv4.
pub fn verify_v4(be: &dyn DnsBackend, iface: &IfaceDns, want: &[String]) -> Result<bool> {
    let current = be.read_all()?;
    let got = current
        .iter()
        .find(|i| i.guid.eq_ignore_ascii_case(&iface.guid) || i.alias == iface.alias);
    Ok(match got {
        Some(i) => same_servers(&i.servers_v4, want),
        None => false,
    })
}

fn same_servers(a: &[String], b: &[String]) -> bool {
    let norm = |v: &[String]| -> Vec<String> {
        let mut v: Vec<String> = v
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        v.sort();
        v
    };
    norm(a) == norm(b)
}

/// Put every snapshotted interface back: DHCP where it was DHCP, the exact
/// static lists where it was static.
pub fn restore(be: &dyn DnsBackend, snap: &DnsSnapshot) -> Vec<ActionOutcome> {
    let mut out = Vec::new();
    // Re-read to translate GUID → the alias the adapter has *now*.
    let current = match be.read_all() {
        Ok(v) => v,
        Err(e) => {
            out.push(ActionOutcome::fail("-", "read", format!("{e:#}")));
            return out;
        }
    };

    for saved in &snap.interfaces {
        if let Some(live) = current
            .iter()
            .find(|i| i.guid.eq_ignore_ascii_case(&saved.guid))
            .or_else(|| current.iter().find(|i| i.alias == saved.alias))
        {
            // Skip adapters we never changed: touching an untouched interface
            // (especially a VPN one) would add risk for nothing.
            let mut needs_work = false;
            for family in [Family::V4, Family::V6] {
                let differs = saved.dhcp(family) != live.dhcp(family)
                    || (!saved.dhcp(family)
                        && !same_servers(live.servers(family), saved.servers(family)));
                if differs {
                    needs_work = true;
                }
            }
            if !needs_work {
                out.push(ActionOutcome::ok(live.label(), "skip", "без изменений"));
                continue;
            }

            // 1. Back to DHCP first, then 2. re-apply the static families.
            //    `Set-DnsClientServerAddress -ResetServerAddresses` covers both
            //    families, and a later static list only touches its own family.
            match be.reset_all(live) {
                Ok(()) => out.push(ActionOutcome::ok(
                    live.label(),
                    "reset",
                    "получение адресов серверов автоматически",
                )),
                Err(e) => out.push(ActionOutcome::fail(live.label(), "reset", format!("{e:#}"))),
            }
            for family in [Family::V4, Family::V6] {
                let list = saved.servers(family);
                // Static-with-no-servers is not representable; treat as automatic.
                if saved.dhcp(family) || list.is_empty() {
                    continue;
                }
                match be.set_servers(live, family, list) {
                    Ok(()) => out.push(ActionOutcome::ok(
                        live.label(),
                        format!("static-{}", family.as_str().to_ascii_lowercase()),
                        list.join(", "),
                    )),
                    Err(e) => out.push(ActionOutcome::fail(
                        live.label(),
                        format!("static-{}", family.as_str().to_ascii_lowercase()),
                        format!("{e:#}"),
                    )),
                }
            }
        } else {
            out.push(ActionOutcome::fail(
                saved.label(),
                "skip",
                "интерфейс больше не существует",
            ));
        }
    }
    out
}

/// Restore from a snapshot file (used by crash recovery and `off`).
pub fn restore_from_file(path: &Path, be: &dyn DnsBackend) -> Result<()> {
    let snap = read_snapshot_file(path)?
        .ok_or_else(|| anyhow::anyhow!("снимок DNS {} не найден", path.display()))?;
    if !snap.complete {
        // Nothing was applied from an incomplete snapshot.
        return Ok(());
    }
    let mut failed: Vec<String> = restore(be, &snap)
        .iter()
        .filter(|o| !o.ok)
        .map(|o| format!("{} {}: {}", o.alias, o.what, o.detail))
        .collect();
    if snap.doh.supported {
        let ours: Vec<String> = PUBLIC_V4.iter().map(|s| s.to_string()).collect();
        failed.extend(
            restore_doh(be, &snap.doh.entries, &ours)
                .iter()
                .filter(|o| !o.ok)
                .map(|o| format!("DoH {}: {}", o.alias, o.detail)),
        );
    }
    if failed.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("DNS восстановлен не полностью: {}", failed.join("; "))
    }
}

/// Compare the live state with the snapshot. Returns human-readable problems.
///
/// DHCP interfaces are checked by their DHCP flag (the servers themselves come
/// from the network and cannot be predicted); static ones by their exact list.
pub fn verify_restored(be: &dyn DnsBackend, snap: &DnsSnapshot) -> Result<Vec<String>> {
    let current = be.read_all()?;
    let mut problems = Vec::new();
    for saved in &snap.interfaces {
        let Some(live) = current
            .iter()
            .find(|i| i.guid.eq_ignore_ascii_case(&saved.guid))
        else {
            continue; // adapter removed by the user: nothing to verify
        };
        for family in [Family::V4, Family::V6] {
            if saved.dhcp(family) {
                if !live.dhcp(family) {
                    problems.push(format!(
                        "{}: {} не вернулся на автоматический режим",
                        saved.label(),
                        family.as_str()
                    ));
                }
            } else if !same_servers(live.servers(family), saved.servers(family)) {
                problems.push(format!(
                    "{}: {} сейчас {}, ожидались {}",
                    saved.label(),
                    family.as_str(),
                    live.servers(family).join(", "),
                    saved.servers(family).join(", ")
                ));
            }
        }
    }
    Ok(problems)
}

/// Restore the DoH templates that the change touched.
///
/// `before` is the snapshot list. Servers present before get their old template
/// and autoupgrade flag back; servers that were not there before are removed.
pub fn restore_doh(
    be: &dyn DnsBackend,
    before: &[DohEntry],
    touched: &[String],
) -> Vec<ActionOutcome> {
    let mut out = Vec::new();
    for server in touched {
        match before.iter().find(|d| d.server == *server) {
            Some(old) => match be.add_doh(&old.server, &old.template, old.autoupgrade) {
                Ok(()) => out.push(ActionOutcome::ok(
                    &old.server,
                    "doh",
                    format!("возвращён шаблон {}", old.template),
                )),
                Err(e) => out.push(ActionOutcome::fail(&old.server, "doh", format!("{e:#}"))),
            },
            None => match be.remove_doh(server) {
                Ok(()) => out.push(ActionOutcome::ok(server, "doh", "удалён")),
                Err(e) => out.push(ActionOutcome::fail(server, "doh", format!("{e:#}"))),
            },
        }
    }
    out
}

// ───────────────────────── real backend ─────────────────────────

/// PowerShell/netsh implementation. Every value is passed as base64-encoded
/// JSON in an environment variable, so no interface name is ever interpolated
/// into a command line.
pub struct SystemDns;

const PS_READ: &str = r#"
$rows = @()
foreach ($a in @(Get-NetAdapter -ErrorAction Stop)) {
  $idx = [int]$a.ifIndex
  $v4 = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
  $v6 = @(Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
  $dhcp4 = $true; $dhcp6 = $true
  $i4 = @(Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue)
  if ($i4.Count -gt 0) { $dhcp4 = ($i4[0].Dhcp -eq 'Enabled') }
  $i6 = @(Get-NetIPInterface -InterfaceIndex $idx -AddressFamily IPv6 -ErrorAction SilentlyContinue)
  if ($i6.Count -gt 0) { $dhcp6 = ($i6[0].Dhcp -eq 'Enabled') }
  $cfg = @(Get-NetIPConfiguration -InterfaceIndex $idx -ErrorAction SilentlyContinue)
  $gw = $false
  if ($cfg.Count -gt 0) { $gw = ($null -ne $cfg[0].IPv4DefaultGateway) }
  $rows += [pscustomobject]@{
    guid = [string]$a.InterfaceGuid
    alias = [string]$a.Name
    index = $idx
    connected = ($a.Status -eq 'Up')
    virtual_adapter = [bool]$a.Virtual
    gateway = [bool]$gw
    dhcp_v4 = [bool]$dhcp4
    dhcp_v6 = [bool]$dhcp6
    servers_v4 = @($v4)
    servers_v6 = @($v6)
  }
}
ConvertTo-Json -InputObject @($rows) -Depth 4 -Compress
"#;

const PS_READ_DOH: &str = r#"
$supported = $false
$list = @()
if (Get-Command Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
  $supported = $true
  $list = @(Get-DnsClientDohServerAddress -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ server = [string]$_.ServerAddress; template = [string]$_.DohTemplate; autoupgrade = [bool]$_.AutoUpgrade }
  })
}
ConvertTo-Json -InputObject @{ supported = [bool]$supported; entries = @($list) } -Depth 4 -Compress
"#;

const PS_SET: &str = r#"
Set-DnsClientServerAddress -InterfaceAlias $p.alias -ServerAddresses @($p.servers)
"#;

const PS_RESET: &str = r#"
Set-DnsClientServerAddress -InterfaceAlias $p.alias -ResetServerAddresses
"#;

const PS_DOH_SET: &str = r#"
if (Get-Command Set-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
  $has = Get-DnsClientDohServerAddress -ServerAddress $p.server -ErrorAction SilentlyContinue
  if ($has) {
    Set-DnsClientDohServerAddress -ServerAddress $p.server -DohTemplate $p.template -AutoUpgrade:$([bool]$p.auto)
  } else {
    Add-DnsClientDohServerAddress -ServerAddress $p.server -DohTemplate $p.template -AllowFallbackToUdp -AutoUpgrade:$([bool]$p.auto)
  }
} else {
  netsh dns add encryption server=$($p.server) dohtemplate=$($p.template) autoupgrade=yes | Out-Null
}
"#;

const PS_DOH_REMOVE: &str = r#"
if (Get-Command Remove-DnsClientDohServerAddress -ErrorAction SilentlyContinue) {
  Remove-DnsClientDohServerAddress -ServerAddress $p.server -ErrorAction SilentlyContinue | Out-Null
} else {
  netsh dns delete encryption server=$($p.server) | Out-Null
}
"#;

impl DnsBackend for SystemDns {
    fn read_all(&self) -> Result<Vec<IfaceDns>> {
        let v = crate::util::powershell_json(PS_READ, &[])?;
        let raw = v.as_array().cloned().unwrap_or_default();
        let mut out = Vec::with_capacity(raw.len());
        for item in raw {
            let iface: IfaceDns = serde_json::from_value(item)
                .context("не удалось разобрать ответ PowerShell про DNS")?;
            if iface.guid.is_empty() && iface.alias.is_empty() {
                continue;
            }
            out.push(iface);
        }
        Ok(out)
    }

    fn read_doh(&self) -> Result<DohState> {
        let v = crate::util::powershell_json(PS_READ_DOH, &[])?;
        let supported = v
            .get("supported")
            .and_then(|x| x.as_bool())
            .unwrap_or(false);
        let mut entries = Vec::new();
        for item in v
            .get("entries")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
        {
            if let Ok(e) = serde_json::from_value::<DohEntry>(item) {
                if !e.server.is_empty() {
                    entries.push(e);
                }
            }
        }
        Ok(DohState { supported, entries })
    }

    fn set_servers(&self, iface: &IfaceDns, family: Family, servers: &[String]) -> Result<()> {
        if servers.is_empty() {
            anyhow::bail!("пустой список серверов для {}", iface.label());
        }
        let payload = serde_json::json!({
            "alias": iface.alias,
            "family": family.as_str(),
            "servers": servers,
        });
        crate::util::powershell_json(PS_SET, &[("OBHOD_P", &crate::util::b64_json(&payload))])?;
        Ok(())
    }

    fn reset_all(&self, iface: &IfaceDns) -> Result<()> {
        let payload = serde_json::json!({ "alias": iface.alias });
        crate::util::powershell_json(PS_RESET, &[("OBHOD_P", &crate::util::b64_json(&payload))])?;
        Ok(())
    }

    fn flush(&self) -> Result<()> {
        crate::util::run_checked("ipconfig", &["/flushdns"])?;
        Ok(())
    }

    fn add_doh(&self, server: &str, template: &str, autoupgrade: bool) -> Result<()> {
        let payload = serde_json::json!({
            "server": server,
            "template": template,
            "auto": autoupgrade,
        });
        crate::util::powershell_json(PS_DOH_SET, &[("OBHOD_P", &crate::util::b64_json(&payload))])?;
        Ok(())
    }

    fn remove_doh(&self, server: &str) -> Result<()> {
        let payload = serde_json::json!({ "server": server });
        crate::util::powershell_json(
            PS_DOH_REMOVE,
            &[("OBHOD_P", &crate::util::b64_json(&payload))],
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct MockDns {
        state: RefCell<Vec<IfaceDns>>,
        doh: RefCell<DohState>,
        /// Fail `read_all` after the first N calls (to simulate a crash).
        pub calls: RefCell<usize>,
        pub fail_read_all: RefCell<bool>,
        pub flush_count: RefCell<usize>,
        pub log: RefCell<Vec<String>>,
    }

    impl MockDns {
        fn with(ifaces: Vec<IfaceDns>) -> Self {
            Self {
                state: RefCell::new(ifaces),
                ..Default::default()
            }
        }

        fn servers_of(&self, alias: &str) -> (Vec<String>, Vec<String>, bool) {
            let st = self.state.borrow();
            let i = st.iter().find(|i| i.alias == alias).expect("iface");
            (i.servers_v4.clone(), i.servers_v6.clone(), i.dhcp_v4)
        }
    }

    impl DnsBackend for MockDns {
        fn read_all(&self) -> Result<Vec<IfaceDns>> {
            *self.calls.borrow_mut() += 1;
            if *self.fail_read_all.borrow() {
                anyhow::bail!("PowerShell недоступен");
            }
            Ok(self.state.borrow().clone())
        }

        fn read_doh(&self) -> Result<DohState> {
            Ok(self.doh.borrow().clone())
        }

        fn set_servers(&self, iface: &IfaceDns, family: Family, servers: &[String]) -> Result<()> {
            self.log.borrow_mut().push(format!(
                "set {} {} {}",
                iface.alias,
                family.as_str(),
                servers.join(",")
            ));
            let mut st = self.state.borrow_mut();
            let i = st
                .iter_mut()
                .find(|i| i.alias == iface.alias)
                .expect("iface exists");
            match family {
                Family::V4 => {
                    i.servers_v4 = servers.to_vec();
                    i.dhcp_v4 = false;
                }
                Family::V6 => {
                    i.servers_v6 = servers.to_vec();
                    i.dhcp_v6 = false;
                }
            }
            Ok(())
        }

        fn reset_all(&self, iface: &IfaceDns) -> Result<()> {
            self.log.borrow_mut().push(format!("reset {}", iface.alias));
            let mut st = self.state.borrow_mut();
            let i = st
                .iter_mut()
                .find(|i| i.alias == iface.alias)
                .expect("iface exists");
            i.servers_v4.clear();
            i.servers_v6.clear();
            i.dhcp_v4 = true;
            i.dhcp_v6 = true;
            Ok(())
        }

        fn flush(&self) -> Result<()> {
            *self.flush_count.borrow_mut() += 1;
            Ok(())
        }

        fn add_doh(&self, server: &str, template: &str, autoupgrade: bool) -> Result<()> {
            self.log
                .borrow_mut()
                .push(format!("doh {server} {template} {autoupgrade}"));
            let mut d = self.doh.borrow_mut();
            let e = &mut d.entries;
            match e.iter_mut().find(|e| e.server == server) {
                Some(e) => {
                    e.template = template.to_string();
                    e.autoupgrade = autoupgrade;
                }
                None => e.push(DohEntry {
                    server: server.to_string(),
                    template: template.to_string(),
                    autoupgrade,
                }),
            }
            Ok(())
        }

        fn remove_doh(&self, server: &str) -> Result<()> {
            self.log.borrow_mut().push(format!("doh-rm {server}"));
            self.doh.borrow_mut().entries.retain(|e| e.server != server);
            Ok(())
        }
    }

    fn iface(alias: &str, guid: &str, v4: &[&str], dhcp: bool) -> IfaceDns {
        IfaceDns {
            guid: guid.to_string(),
            alias: alias.to_string(),
            index: 1,
            connected: true,
            virtual_adapter: false,
            gateway: true,
            dhcp_v4: dhcp,
            dhcp_v6: dhcp,
            servers_v4: v4.iter().map(|s| s.to_string()).collect(),
            servers_v6: Vec::new(),
        }
    }

    #[test]
    fn capture_persists_complete_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let be = MockDns::with(vec![iface("Ethernet", "{A}", &["10.0.0.1"], true)]);
        be.doh.borrow_mut().supported = true;
        be.doh.borrow_mut().entries.push(DohEntry {
            server: "1.1.1.1".into(),
            template: "https://cloudflare-dns.com/dns-query".into(),
            autoupgrade: false,
        });
        let snap = capture_and_save(dir.path(), &be, "tx-1").unwrap();
        assert!(snap.complete);
        assert_eq!(snap.interfaces.len(), 1);
        assert!(snap.doh.supported);
        assert_eq!(snap.doh.entries.len(), 1);
        match read_state(dir.path()).unwrap() {
            SnapshotState::Complete(s) => {
                assert_eq!(s.interfaces[0].guid, "{A}");
                assert_eq!(s.interfaces[0].servers_v4, vec!["10.0.0.1"]);
            }
            other => panic!("unexpected state {other:?}"),
        }
    }

    #[test]
    fn interrupted_capture_is_detectable_and_never_rooted() {
        let dir = tempfile::tempdir().unwrap();
        let be = MockDns::with(vec![iface("Ethernet", "{A}", &["10.0.0.1"], true)]);
        *be.fail_read_all.borrow_mut() = true;
        let err = capture_and_save(dir.path(), &be, "tx-1").unwrap_err();
        assert!(format!("{err:#}").contains("PowerShell"));
        // Placeholder is on disk but marked incomplete: recovery can ignore it.
        assert_eq!(read_state(dir.path()).unwrap(), SnapshotState::Incomplete);
        let snap = read_snapshot_file(&snapshot_path(dir.path()))
            .unwrap()
            .unwrap();
        assert!(!snap.complete && snap.interfaces.is_empty());
        // Restoring from it is a no-op, not a DNS reset.
        assert!(restore_from_file(&snapshot_path(dir.path()), &be).is_ok());
        assert!(be.log.borrow().is_empty());
    }

    #[test]
    fn apply_then_restore_returns_exact_previous_lists() {
        let dir = tempfile::tempdir().unwrap();
        let be = MockDns::with(vec![
            iface("Ethernet", "{A}", &["10.0.0.1", "10.0.0.2"], false),
            iface("Wi-Fi", "{B}", &[], true),
        ]);
        let snap = capture_and_save(dir.path(), &be, "tx-1").unwrap();
        let public = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        let applied = apply_v4(&be, &snap, &public);
        assert!(applied.iter().all(|o| o.ok));
        assert_eq!(be.servers_of("Ethernet").0, public);
        assert_eq!(be.servers_of("Wi-Fi").0, public);
        assert!(verify_v4(&be, &snap.interfaces[0], &public).unwrap());

        let outcomes = restore(&be, &snap);
        assert!(outcomes.iter().all(|o| o.ok), "{outcomes:?}");
        let (v4, _v6, dhcp) = be.servers_of("Ethernet");
        assert_eq!(v4, vec!["10.0.0.1", "10.0.0.2"]);
        assert!(!dhcp);
        let (v4, _v6, dhcp) = be.servers_of("Wi-Fi");
        assert!(v4.is_empty());
        assert!(dhcp, "Wi-Fi was DHCP before and must be DHCP again");
    }

    #[test]
    fn restore_handles_mixed_families() {
        let be = MockDns::with(vec![IfaceDns {
            guid: "{C}".into(),
            alias: "Eth".into(),
            index: 2,
            connected: true,
            virtual_adapter: false,
            gateway: true,
            dhcp_v4: false,
            dhcp_v6: true,
            servers_v4: vec!["192.168.1.1".into()],
            servers_v6: vec!["fec0::1".into()],
        }]);
        let snap = capture_and_save(tempfile::tempdir().unwrap().path(), &be, "t").unwrap();
        // Pretend we changed things.
        be.set_servers(&snap.interfaces[0], Family::V4, &["9.9.9.9".into()])
            .unwrap();
        let outcomes = restore(&be, &snap);
        assert!(outcomes.iter().all(|o| o.ok), "{outcomes:?}");
        let st = be.state.borrow();
        assert_eq!(st[0].servers_v4, vec!["192.168.1.1"]);
        assert!(st[0].dhcp_v6, "v6 was DHCP and must be reset");
    }

    #[test]
    fn restore_skips_vanished_interface_but_reports_it() {
        let be = MockDns::with(vec![iface("Ethernet", "{A}", &["10.0.0.1"], false)]);
        let dir = tempfile::tempdir().unwrap();
        let snap = capture_and_save(dir.path(), &be, "t").unwrap();
        be.state.borrow_mut().clear();
        let outcomes = restore(&be, &snap);
        assert_eq!(outcomes.len(), 1);
        assert!(!outcomes[0].ok);
        assert!(outcomes[0].detail.contains("не существует"));
    }

    #[test]
    fn restore_matches_interface_by_guid_when_renamed() {
        let be = MockDns::with(vec![iface("Old name", "{G}", &["10.0.0.1"], false)]);
        let dir = tempfile::tempdir().unwrap();
        let snap = capture_and_save(dir.path(), &be, "t").unwrap();
        be.state.borrow_mut()[0].alias = "New name".into();
        be.state.borrow_mut()[0].servers_v4 = vec!["1.1.1.1".into()];
        let outcomes = restore(&be, &snap);
        assert!(outcomes.iter().all(|o| o.ok), "{outcomes:?}");
        assert_eq!(
            be.servers_of("New name").0,
            vec!["10.0.0.1"],
            "restore must use the current alias but the saved list"
        );
    }

    #[test]
    fn verify_detects_mismatch() {
        let be = MockDns::with(vec![iface("Ethernet", "{A}", &["10.0.0.1"], false)]);
        let snap = IfaceDns {
            ..iface("Ethernet", "{A}", &[], false)
        };
        assert!(!verify_v4(&be, &snap, &["1.1.1.1".into()]).unwrap());
        assert!(verify_v4(&be, &snap, &["10.0.0.1".into()]).unwrap());
    }

    #[test]
    fn doh_restore_removes_new_and_restores_old() {
        let be = MockDns::with(vec![]);
        {
            let mut d = be.doh.borrow_mut();
            d.supported = true;
            d.entries.push(DohEntry {
                server: "1.1.1.1".into(),
                template: "https://old/dns-query".into(),
                autoupgrade: false,
            });
        }
        let before = be.doh.borrow().entries.clone();
        be.add_doh("1.1.1.1", "https://new/dns-query", true)
            .unwrap();
        be.add_doh("9.9.9.9", "https://quad9/dns-query", true)
            .unwrap();
        let outcomes = restore_doh(&be, &before, &["1.1.1.1".into(), "9.9.9.9".into()]);
        assert!(outcomes.iter().all(|o| o.ok), "{outcomes:?}");
        let doh = be.doh.borrow();
        let cf = doh.entries.iter().find(|d| d.server == "1.1.1.1").unwrap();
        assert_eq!(cf.template, "https://old/dns-query");
        assert!(!cf.autoupgrade);
        assert!(!doh.entries.iter().any(|d| d.server == "9.9.9.9"));
    }

    #[test]
    fn restore_is_a_noop_when_nothing_changed() {
        let be = MockDns::with(vec![
            iface("Ethernet", "{A}", &["10.0.0.1"], false),
            iface("Wi-Fi", "{B}", &[], true),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let snap = capture_and_save(dir.path(), &be, "t").unwrap();
        be.log.borrow_mut().clear();
        let outcomes = restore(&be, &snap);
        assert!(outcomes.iter().all(|o| o.ok), "{outcomes:?}");
        assert!(
            be.log.borrow().is_empty(),
            "untouched interfaces must not be reset: {:?}",
            be.log.borrow()
        );
    }

    #[test]
    fn verify_restored_reports_dhcp_and_static_mismatches() {
        let be = MockDns::with(vec![
            iface("Static", "{S}", &["10.0.0.1"], false),
            iface("Auto", "{D}", &[], true),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let snap = capture_and_save(dir.path(), &be, "t").unwrap();
        assert!(verify_restored(&be, &snap).unwrap().is_empty());
        // Break the static one and make the DHCP one static.
        be.set_servers(&snap.interfaces[0], Family::V4, &["9.9.9.9".into()])
            .unwrap();
        let problems = verify_restored(&be, &snap).unwrap();
        assert!(problems.iter().any(|p| p.contains("Static")));
    }

    #[test]
    fn restore_from_file_also_restores_doh_when_supported() {
        let dir = tempfile::tempdir().unwrap();
        let be = MockDns::with(vec![iface("Ethernet", "{A}", &["10.0.0.1"], false)]);
        {
            let mut d = be.doh.borrow_mut();
            d.supported = true;
            d.entries.push(DohEntry {
                server: "1.1.1.1".into(),
                template: "https://old/dns-query".into(),
                autoupgrade: false,
            });
        }
        let snap = capture_and_save(dir.path(), &be, "t").unwrap();
        be.add_doh("1.1.1.1", "https://new/dns-query", true)
            .unwrap();
        be.add_doh("8.8.8.8", "https://dns.google/dns-query", true)
            .unwrap();
        restore_from_file(&snapshot_path(dir.path()), &be).unwrap();
        let d = be.doh.borrow();
        assert_eq!(
            d.entries
                .iter()
                .find(|e| e.server == "1.1.1.1")
                .unwrap()
                .template,
            "https://old/dns-query"
        );
        assert!(!d.entries.iter().any(|e| e.server == "8.8.8.8"));
        let _ = snap;
    }

    #[test]
    fn snapshot_state_missing_when_no_file() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(read_state(dir.path()).unwrap(), SnapshotState::Missing);
        assert!(!remove_snapshot(dir.path()).unwrap());
    }

    #[test]
    fn second_capture_keeps_the_original_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let be = MockDns::with(vec![iface("Ethernet", "{A}", &["10.0.0.1"], false)]);
        let first = capture_and_save(dir.path(), &be, "tx-1").unwrap();
        assert_eq!(first.interfaces[0].servers_v4, vec!["10.0.0.1"]);
        // Now the machine is on public DNS (that is what we set).
        be.set_servers(&first.interfaces[0], Family::V4, &["1.1.1.1".into()])
            .unwrap();
        let second = capture_and_save(dir.path(), &be, "tx-2").unwrap();
        assert_eq!(
            second.interfaces[0].servers_v4,
            vec!["10.0.0.1"],
            "re-enabling must keep the state from before the first change"
        );
        assert!(second.complete);
    }

    #[test]
    fn active_prefers_physical_adapters() {
        let mut snap = DnsSnapshot::empty("t");
        snap.interfaces = vec![
            IfaceDns {
                virtual_adapter: true,
                gateway: true,
                alias: "tun0".into(),
                guid: "{V}".into(),
                connected: true,
                ..iface("tun0", "{V}", &[], true)
            },
            iface("Ethernet", "{P}", &[], true),
        ];
        let active = snap.active();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].alias, "Ethernet");
    }

    #[test]
    fn active_falls_back_to_a_virtual_gateway() {
        let mut snap = DnsSnapshot::empty("t");
        snap.interfaces = vec![IfaceDns {
            virtual_adapter: true,
            ..iface("tun0", "{V}", &[], true)
        }];
        assert_eq!(snap.active().len(), 1);
    }

    /// Read-only end-to-end check of the real PowerShell backend.
    ///
    /// Not part of the normal suite: it queries the live machine (no changes)
    /// and is meant for manual verification:
    /// `cargo test --release -- --ignored --nocapture system_backend_reads_real_dns`
    #[test]
    #[ignore = "read-only check against the real machine"]
    fn system_backend_reads_real_dns() {
        let ifaces = SystemDns.read_all().expect("read_all via PowerShell");
        assert!(!ifaces.is_empty(), "at least one adapter expected");
        for i in &ifaces {
            println!(
                "{} ({}) up={} gw={} dhcp4={} v4=[{}] dhcp6={} v6=[{}]",
                i.alias,
                i.guid,
                i.connected,
                i.gateway,
                i.dhcp_v4,
                i.servers_v4.join(","),
                i.dhcp_v6,
                i.servers_v6.join(",")
            );
        }
        let doh = SystemDns.read_doh().expect("read_doh");
        println!(
            "DoH supported: {} entries: {}",
            doh.supported,
            doh.entries.len()
        );
    }
}

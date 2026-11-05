//! Outils du domaine security : l'audit de sécurité, qui réunit des contrôles indépendants.

use super::firewall::analyze_rules;
use super::shared::{fetch_config_json, ConfigOptions};
use crate::client::RequestOptions;
use crate::error::{ErrorType, OpnError, Result};
use crate::model::{fetch_all, FETCH_ALL_MAX};
use crate::tool::{read_tool, BoxFut, Ctx, Domain, ToolDef};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::{Arc, LazyLock};

type Finding = Map<String, Value>;
type Check = fn(Arc<Ctx>) -> BoxFut<Result<Vec<Finding>>>;

const DANGEROUS_FORWARD_PORTS: [(&str, &str); 12] = [
    ("22", "SSH"),
    ("23", "Telnet"),
    ("139", "NetBIOS"),
    ("445", "SMB"),
    ("1433", "MSSQL"),
    ("3306", "MySQL"),
    ("3389", "RDP"),
    ("5432", "PostgreSQL"),
    ("5900", "VNC"),
    ("6379", "Redis"),
    ("9200", "Elasticsearch"),
    ("27017", "MongoDB"),
];

/// Mots qui désignent une cryptographie obsolète dans une proposition IPsec, comparés sur des mots entiers.
static WEAK_PROPOSAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)(^|[-_,\s])(md5|sha1|3des|des|modp768|modp1024|modp1536)($|[-_,\s])").unwrap()
});
static PORT_RANGE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d+)[-:](\d+)$").unwrap());
static GATEWAY_DOWN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)down|force_down").unwrap());

const CERT_WARNING_DAYS: i64 = 30;

/// Comme `String(v)` de JavaScript pour une valeur JSON.
fn js(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// `String(v ?? default)`.
fn js_or(v: Option<&Value>, default: &str) -> String {
    match v {
        None | Some(Value::Null) => default.into(),
        other => js(other),
    }
}

/// Vérité au sens de JavaScript.
fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Number(n)) => n.as_f64().is_some_and(|f| f != 0.0 && !f.is_nan()),
        Some(_) => true,
    }
}

fn on(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => s == "1",
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        _ => false,
    }
}

fn obj(v: Option<&Value>) -> Option<&Map<String, Value>> {
    v.and_then(Value::as_object)
}

/// Les lignes de recherche sont aplaties avec des clés pointées ; d'autres versions imbriquent les mêmes champs.
fn field(row: &Map<String, Value>, group: &str, name: &str) -> String {
    if let Some(flat) = row.get(&format!("{group}.{name}")) {
        return js(Some(flat));
    }
    match obj(row.get(group)).and_then(|n| n.get(name)) {
        Some(v) => js(Some(v)),
        None => String::new(),
    }
}

fn finding(
    severity: &str,
    section: &str,
    check: &str,
    message: impl Into<String>,
    recommendation: Option<&str>,
) -> Finding {
    let mut f = Map::new();
    f.insert("severity".into(), json!(severity));
    f.insert("section".into(), json!(section));
    f.insert("check".into(), json!(check));
    f.insert("message".into(), json!(message.into()));
    if let Some(r) = recommendation {
        f.insert("recommendation".into(), json!(r));
    }
    f
}

/// Ajoute un champ sauf s'il est absent (JSON.stringify omet `undefined`).
fn with(mut f: Finding, key: &str, v: Option<&Value>) -> Finding {
    if let Some(v) = v {
        f.insert(key.into(), v.clone());
    }
    f
}

async fn rows(ctx: &Ctx, path: &str) -> Result<Vec<Map<String, Value>>> {
    Ok(fetch_all(&ctx.api, path, None, FETCH_ALL_MAX)
        .await?
        .into_iter()
        .map(|r| r.as_object().cloned().unwrap_or_default())
        .collect())
}

async fn check_firmware(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    let res = ctx.api.get_("core/firmware/status").await?;
    let status = res.as_object().cloned().unwrap_or_default();
    let mut out = Vec::new();
    let s = status.get("status").and_then(Value::as_str);
    if s == Some("update") || s == Some("upgrade") {
        out.push(finding("medium", "firmware", "updates_available", "Updates are available.", Some("Review the changelog and update from the web interface. This server cannot install updates.")));
    }
    if matches!(status.get("needs_reboot"), Some(Value::String(s)) if s == "1")
        || status.get("needs_reboot").and_then(Value::as_f64) == Some(1.0)
    {
        out.push(finding(
            "low",
            "firmware",
            "reboot_needed",
            "A pending update needs a reboot to take effect.",
            None,
        ));
    }
    if truthy(status.get("upgrade_major_version")) {
        out.push(finding(
            "info",
            "firmware",
            "major_upgrade",
            format!(
                "A new major version is available: {}.",
                js(status.get("upgrade_major_version"))
            ),
            None,
        ));
    }
    Ok(out)
}

async fn check_rules(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    let rows = fetch_all(&ctx.api, "firewall/filter/search_rule", None, FETCH_ALL_MAX).await?;
    let stats_res = ctx.api.get_("firewall/filter_util/rule_stats").await.ok();
    let stats = stats_res.as_ref().and_then(|r| obj(r.get("stats")));
    let rule_rows: Vec<_> = rows.iter().filter_map(|r| r.as_object().cloned()).collect();
    let analysis = analyze_rules(&rule_rows, stats);
    let findings = analysis
        .get("findings")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(findings
        .into_iter()
        .map(|f| {
            let mut m = f.as_object().cloned().unwrap_or_default();
            m.insert("section".into(), json!("firewall_rules"));
            m
        })
        .collect())
}

async fn check_nat(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    let mut out = Vec::new();
    for row in rows(&ctx, "firewall/d_nat/search_rule").await? {
        if on(row.get("disabled")) {
            continue;
        }
        let mut source = field(&row, "source", "network");
        if source.is_empty() {
            source = "any".into();
        }
        let port = field(&row, "destination", "port");
        let target = js_or(row.get("target"), "?");
        if let Some((_, service)) = DANGEROUS_FORWARD_PORTS.iter().find(|(p, _)| *p == port) {
            if source.to_lowercase() == "any" {
                let f = finding(
                    "high",
                    "nat",
                    "dangerous_port_forward",
                    format!("{service} (port {port}) is forwarded to {target} from any source."),
                    Some("Restrict the source, or reach this service through a VPN."),
                );
                out.push(with(
                    with(f, "uuid", row.get("uuid")),
                    "rule",
                    row.get("descr"),
                ));
            }
        }
        if let Some(c) = PORT_RANGE.captures(&port) {
            let (lo, hi) = (
                c[1].parse::<f64>().unwrap_or(0.0),
                c[2].parse::<f64>().unwrap_or(0.0),
            );
            if hi - lo >= 100.0 {
                let f = finding(
                    "medium",
                    "nat",
                    "broad_port_forward",
                    format!("Port range {port} is forwarded to {target}."),
                    None,
                );
                out.push(with(
                    with(f, "uuid", row.get("uuid")),
                    "rule",
                    row.get("descr"),
                ));
            }
        }
    }
    Ok(out)
}

async fn check_dns(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    let res = ctx.api.get_("unbound/settings/get").await?;
    let Some(general) = obj(res.get("unbound")).and_then(|u| obj(u.get("general"))) else {
        return Err(OpnError::new(
            ErrorType::BadResponse,
            "Unexpected answer from unbound/settings/get.",
        ));
    };
    if !on(general.get("enabled")) {
        return Ok(vec![finding(
            "info",
            "dns",
            "unbound_disabled",
            "Unbound is not enabled, so its checks do not apply.",
            None,
        )]);
    }
    Ok(if on(general.get("dnssec")) {
        vec![]
    } else {
        vec![finding(
            "low",
            "dns",
            "dnssec_disabled",
            "DNSSEC validation is off in Unbound.",
            Some("Enable it unless a forwarder breaks it."),
        )]
    })
}

async fn check_hardening(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    let config = fetch_config_json(&ctx, &ConfigOptions::default()).await?;
    let mut out = Vec::new();
    let empty = Map::new();
    let system = obj(config.get("system")).unwrap_or(&empty);
    let webgui = obj(system.get("webgui")).unwrap_or(&empty);
    if webgui.get("protocol").and_then(Value::as_str) == Some("http") {
        out.push(finding("high", "system", "webgui_http", "The web interface uses plain HTTP: credentials and API keys cross the network in clear text.", Some("Switch to HTTPS in System > Settings > Administration.")));
    }

    let ssh = obj(system.get("ssh")).unwrap_or(&empty);
    if ssh.get("enabled").and_then(Value::as_str) == Some("enabled") {
        if on(ssh.get("permitrootlogin")) {
            out.push(finding(
                "medium",
                "system",
                "ssh_root_login",
                "SSH allows root to log in.",
                Some("Log in as a normal user and use sudo."),
            ));
        }
        if on(ssh.get("passwordauth")) {
            out.push(finding(
                "medium",
                "system",
                "ssh_password_auth",
                "SSH accepts passwords.",
                Some("Use keys only."),
            ));
        }
        if js_or(ssh.get("port"), "22") == "22" {
            out.push(finding(
                "info",
                "system",
                "ssh_default_port",
                "SSH listens on the default port 22.",
                None,
            ));
        }
    }

    let legacy = obj(config.get("syslog")).unwrap_or(&empty);
    let syslog = obj(obj(config.get("OPNsense")).and_then(|o| o.get("Syslog"))).unwrap_or(&empty);
    let has_destination = match obj(syslog.get("destinations")).and_then(|d| d.get("destination")) {
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(_)) => true,
        _ => false,
    };
    if !truthy(legacy.get("remoteserver"))
        && !truthy(legacy.get("remoteserver2"))
        && !truthy(legacy.get("remoteserver3"))
        && !has_destination
    {
        out.push(finding(
            "low",
            "system",
            "no_remote_logging",
            "Logs stay on the firewall only: an attacker who gets in can erase them.",
            Some("Add a destination in System > Settings > Logging."),
        ));
    }
    Ok(out)
}

async fn check_services(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    Ok(rows(&ctx, "core/service/search")
        .await?
        .iter()
        .filter(|s| js(s.get("running")) == "0")
        .map(|s| {
            let label = if matches!(s.get("description"), None | Some(Value::Null)) {
                js(s.get("name"))
            } else {
                js(s.get("description"))
            };
            with(
                finding(
                    "medium",
                    "services",
                    "service_stopped",
                    format!("{label} is enabled but not running."),
                    None,
                ),
                "service",
                s.get("name"),
            )
        })
        .collect())
}

/// `Date.parse` pour les formats qu'un certificat renvoie, en millisecondes.
fn parse_date_ms(s: &str) -> Option<f64> {
    use chrono::{DateTime, NaiveDate, NaiveDateTime};
    let s = s.trim();
    if let Ok(d) = DateTime::parse_from_rfc3339(s).or_else(|_| DateTime::parse_from_rfc2822(s)) {
        return Some(d.timestamp_millis() as f64);
    }
    if let Ok(d) = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S") {
        return Some(d.and_utc().timestamp_millis() as f64);
    }
    NaiveDate::parse_from_str(s, "%Y-%m-%d")
        .ok()
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|d| d.and_utc().timestamp_millis() as f64)
}

/// Jours avant l'échéance (négatif : expiré). `valid_to` est en secondes, ou une date.
fn days_left(valid_to: Option<&Value>, now_ms: f64) -> Option<i64> {
    let text = js_or(valid_to, "");
    let seconds = if text.trim().is_empty() {
        0.0
    } else {
        text.trim().parse::<f64>().unwrap_or(f64::NAN)
    };
    let time = if seconds.is_finite() && seconds > 0.0 {
        seconds * 1000.0
    } else {
        parse_date_ms(&js(valid_to))?
    };
    Some(((time - now_ms) / 86_400_000.0).floor() as i64)
}

async fn check_certificates(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    let now_ms = chrono::Utc::now().timestamp_millis() as f64;
    let mut out = Vec::new();
    for cert in rows(&ctx, "trust/cert/search").await? {
        let Some(days) = days_left(cert.get("valid_to"), now_ms) else {
            continue;
        };
        let name = js(cert.get("descr"));
        if days < 0 {
            out.push(with(
                finding(
                    "high",
                    "certificates",
                    "certificate_expired",
                    format!("Certificate \"{name}\" expired {} day(s) ago.", -days),
                    None,
                ),
                "uuid",
                cert.get("uuid"),
            ));
        } else if days <= CERT_WARNING_DAYS {
            out.push(with(
                finding(
                    "medium",
                    "certificates",
                    "certificate_expiring",
                    format!("Certificate \"{name}\" expires in {days} day(s)."),
                    None,
                ),
                "uuid",
                cert.get("uuid"),
            ));
        }
    }
    Ok(out)
}

async fn check_vpn(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    Ok(rows(&ctx, "ipsec/connections/search_connection")
        .await?
        .iter()
        .filter(|c| WEAK_PROPOSAL.is_match(&js_or(c.get("proposals"), "")))
        .map(|c| {
            let label = if matches!(c.get("description"), None | Some(Value::Null)) {
                js(c.get("uuid"))
            } else {
                js(c.get("description"))
            };
            let f = finding(
                "medium",
                "vpn",
                "weak_ipsec_proposal",
                format!(
                    "IPsec connection \"{label}\" allows obsolete algorithms: {}.",
                    js(c.get("proposals"))
                ),
                None,
            );
            with(f, "uuid", c.get("uuid"))
        })
        .collect())
}

async fn check_gateways(ctx: Arc<Ctx>) -> Result<Vec<Finding>> {
    let res = ctx
        .api
        .get("routes/gateway/status", RequestOptions::new())
        .await?;
    let items = res
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    Ok(items
        .iter()
        .filter(|g| GATEWAY_DOWN.is_match(&js(g.get("status"))))
        .map(|g| {
            let translated = if matches!(g.get("status_translated"), None | Some(Value::Null)) {
                js(g.get("status"))
            } else {
                js(g.get("status_translated"))
            };
            finding(
                "medium",
                "gateways",
                "gateway_down",
                format!("Gateway {} is down ({translated}).", js(g.get("name"))),
                None,
            )
        })
        .collect())
}

macro_rules! check {
    ($f:ident) => {
        |c| Box::pin($f(c))
    };
}

fn checks() -> [(&'static str, Check); 9] {
    [
        ("firmware", check!(check_firmware)),
        ("firewall_rules", check!(check_rules)),
        ("nat", check!(check_nat)),
        ("dns", check!(check_dns)),
        ("system", check!(check_hardening)),
        ("services", check!(check_services)),
        ("certificates", check!(check_certificates)),
        ("vpn", check!(check_vpn)),
        ("gateways", check!(check_gateways)),
    ]
}

const MANUAL_REVIEW: [&str; 4] = [
    "Who has accounts and API keys, and whether each one is still needed: this server does not read them.",
    "Whether the web interface is reachable only from a management network.",
    "Whether configuration backups are stored off the firewall.",
    "Whether what the rules allow matches what the business needs: only a person can tell.",
];

fn severity_order(f: &Finding) -> u8 {
    match f.get("severity").and_then(Value::as_str) {
        Some("high") => 0,
        Some("medium") => 1,
        Some("low") => 2,
        _ => 3,
    }
}

pub async fn run_audit(ctx: Arc<Ctx>) -> Value {
    let list = checks();
    let results = futures::future::join_all(list.iter().map(|(_, c)| c(ctx.clone()))).await;
    let mut findings: Vec<Finding> = Vec::new();
    let mut checked = Vec::new();
    let mut skipped = Map::new();
    for ((name, _), r) in list.iter().zip(results) {
        match r {
            Ok(f) => {
                checked.push(*name);
                findings.extend(f);
            }
            Err(e) => {
                skipped.insert(
                    (*name).into(),
                    json!(format!("{}: {}", e.kind.as_str(), e.message)),
                );
            }
        }
    }
    findings.sort_by_key(severity_order);
    let mut summary = json!({ "high": 0, "medium": 0, "low": 0, "info": 0 });
    for f in &findings {
        if let Some(n) = f
            .get("severity")
            .and_then(Value::as_str)
            .and_then(|s| summary.get_mut(s))
        {
            *n = json!(n.as_u64().unwrap_or(0) + 1);
        }
    }
    let note = if skipped.is_empty() {
        "These are automated checks on the configuration: no finding does not mean the firewall is secure."
    } else {
        "Some sections could not be checked: a clean result covers only the sections under coverage.checked."
    };
    json!({
        "summary": summary,
        "findings": findings,
        "coverage": { "checked": checked, "skipped": skipped },
        "manual_review": MANUAL_REVIEW,
        "note": note,
    })
}

pub fn tools() -> Vec<ToolDef> {
    vec![read_tool(
        "opn_security_audit",
        "Security audit",
        "Checks firmware, firewall rules, port forwards, DNS, system hardening, services, certificates, VPN and gateways, and lists the findings by severity. Sections the API user cannot read are listed under coverage.skipped rather than passed silently. Read-only.",
        Domain::Security,
    )
    .run(|_args, ctx| async move { Ok(run_audit(ctx).await) })]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_proposals_match_whole_tokens() {
        assert!(WEAK_PROPOSAL.is_match("aes256-sha1-modp2048"));
        assert!(WEAK_PROPOSAL.is_match("3des-sha256"));
        assert!(!WEAK_PROPOSAL.is_match("aes256gcm16-sha256-modp2048"));
        assert!(!WEAK_PROPOSAL.is_match("aes256-sha1024"));
    }

    #[test]
    fn certificate_days() {
        let now = 1_000_000_000_000.0;
        assert_eq!(days_left(Some(&json!("1000864000")), now), Some(10));
        assert_eq!(days_left(Some(&json!(999_827_200)), now), Some(-2));
        assert_eq!(days_left(Some(&json!("garbage")), now), None);
    }

    #[test]
    fn field_reads_flat_and_nested() {
        let flat = json!({"destination.port": "22"});
        let nested = json!({"destination": {"port": "22"}});
        assert_eq!(
            field(flat.as_object().unwrap(), "destination", "port"),
            "22"
        );
        assert_eq!(
            field(nested.as_object().unwrap(), "destination", "port"),
            "22"
        );
        assert_eq!(field(&Map::new(), "destination", "port"), "");
    }
}

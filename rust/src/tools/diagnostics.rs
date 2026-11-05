//! Outils du domaine diagnostics.

use crate::client::RequestOptions;
use crate::error::{ErrorType, OpnError, Result};
use crate::model::{assert_write_ok, fetch_all, paginate_array, Obj, FETCH_ALL_MAX};
use crate::schema::{self, Field};
use crate::tool::{gather, read_tool, tool, BoxFut, Ctx, Domain, ToolAccess, ToolDef};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use std::time::{Duration, Instant};

use super::simulate::match_literal;

const PING_TIMEOUT: Duration = Duration::from_secs(30);
const PING_POLL: Duration = Duration::from_secs(1);

fn hostname() -> Field {
    schema::string("hostname")
        .regex(r"^[A-Za-z0-9.:_-]+$", "Expected a host name or an address")
        .check(|v| !v.starts_with('-'), "Expected a host name or an address")
        .desc("Host name or IP address.")
}

fn family() -> Field {
    schema::enumeration("family", &["inet", "inet6"]).opt().desc("inet = IPv4 (default), inet6 = IPv6.")
}

fn address(name: &'static str) -> Field {
    schema::string(name).ip()
}

fn source_address(desc: &str) -> Field {
    address("source_address").opt().desc(desc)
}

/// Comme `String(v)` de JavaScript pour les valeurs d'une réponse JSON.
fn js(v: Option<&Value>) -> String {
    match v {
        None => "undefined".into(),
        Some(Value::Null) => "null".into(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    }
}

/// Comme `Number(v)` de JavaScript.
fn num(v: &Value) -> f64 {
    match v {
        Value::Number(n) => n.as_f64().unwrap_or(f64::NAN),
        Value::String(s) if s.trim().is_empty() => 0.0,
        Value::String(s) => s.trim().parse().unwrap_or(f64::NAN),
        Value::Bool(b) => f64::from(u8::from(*b)),
        Value::Null => 0.0,
        _ => f64::NAN,
    }
}

fn rows_of(v: Option<&Value>) -> Vec<Value> {
    match v {
        Some(Value::Object(o)) => o.get("rows").and_then(Value::as_array).cloned().unwrap_or_default(),
        _ => Vec::new(),
    }
}

fn pick<'a>(row: &'a Value, keys: &[&str]) -> Option<&'a Value> {
    keys.iter().filter_map(|k| row.get(*k)).find(|v| !v.is_null())
}

/// Un ping est une tâche du pare-feu : la créer, la démarrer, lire ses compteurs, l'arrêter et la retirer.
async fn run_ping(ctx: &Ctx, hostname: &str, count: i64, family: Option<&str>, source: Option<&str>) -> Result<Value> {
    let mut settings = Map::new();
    settings.insert("hostname".into(), json!(hostname));
    if let Some(f) = family {
        settings.insert("fam".into(), json!(if f == "inet6" { "ip6" } else { "ip" }));
    }
    if let Some(s) = source {
        settings.insert("source_address".into(), json!(s));
    }
    let created = assert_write_ok(&ctx.api.post("diagnostics/ping/set", Some(json!({ "ping": { "settings": settings } })), RequestOptions::new()).await?, "Creating the ping")?;
    let job_id = match created.get("uuid") {
        None | Some(Value::Null) => String::new(),
        v => js(v),
    };
    if job_id.is_empty() {
        return Err(OpnError::new(ErrorType::BadResponse, "The firewall did not return a ping job id.").details(Value::Object(created)));
    }

    let outcome: Result<Value> = async {
        assert_write_ok(&ctx.api.post("diagnostics/ping/start", None, RequestOptions::new().param(&job_id)).await?, "Starting the ping")?;
        let deadline = Instant::now() + PING_TIMEOUT;
        let mut job: Option<Value> = None;
        while Instant::now() < deadline {
            tokio::time::sleep(PING_POLL).await;
            let jobs = fetch_all(&ctx.api, "diagnostics/ping/search_jobs", None, FETCH_ALL_MAX).await?;
            job = jobs.into_iter().find(|j| js(pick(j, &["id", "uuid"])) == job_id);
            let Some(j) = &job else { break };
            let sent = pick(j, &["send", "transmitted"]).map_or(0.0, num);
            let status_done = matches!(j.get("status"), Some(Value::String(s)) if !s.is_empty() && s != "running");
            if sent >= count as f64 || status_done {
                break;
            }
        }
        let mut out = Map::new();
        out.insert("hostname".into(), json!(hostname));
        match job {
            Some(Value::Object(o)) => out.extend(o),
            _ => {
                out.insert("status".into(), json!("finished, no counters returned"));
            }
        }
        Ok(Value::Object(out))
    }
    .await;

    // Ne laisser aucune tâche derrière soi : rien d'autre ne l'arrête. Un échec ici ne doit pas cacher le résultat.
    let _ = ctx.api.post("diagnostics/ping/stop", None, RequestOptions::new().param(&job_id)).await;
    let _ = ctx.api.post("diagnostics/ping/remove", None, RequestOptions::new().param(&job_id)).await;
    outcome
}

fn post_src(ctx: &Arc<Ctx>, path: &'static str, body: Value) -> BoxFut<Result<Value>> {
    let c = ctx.clone();
    Box::pin(async move { c.api.post(path, Some(body), RequestOptions::new()).await })
}

fn get_src(ctx: &Arc<Ctx>, path: &'static str, query: Vec<(&'static str, String)>) -> BoxFut<Result<Value>> {
    let c = ctx.clone();
    Box::pin(async move {
        let mut o = RequestOptions::new();
        for (k, v) in query {
            o = o.query(k, v);
        }
        c.api.get(path, o).await
    })
}

fn with_source(mut settings: Map<String, Value>, source: Option<&str>) -> Value {
    if let Some(s) = source {
        settings.insert("source_address".into(), json!(s));
    }
    Value::Object(settings)
}

pub fn tools() -> Vec<ToolDef> {
    vec![
        tool("opn_ping", "Ping from the firewall", "Pings a host from the firewall and returns the counters. Sends packets, but changes nothing on the firewall.", Domain::Diagnostics, ToolAccess::Read)
            .open_world()
            .input(vec![
                hostname(),
                schema::integer("count").opt().min(1).max(20).desc("Packets to send (default 3)."),
                family(),
                source_address("Local address to send from."),
            ])
            .run(|args, ctx| async move { run_ping(&ctx, args.req("hostname"), args.i64("count").unwrap_or(3), args.str("family"), args.str("source_address")).await }),
        tool("opn_traceroute", "Traceroute from the firewall", "Traces the path from the firewall to a host. Can take up to a minute.", Domain::Diagnostics, ToolAccess::Read)
            .open_world()
            .input(vec![
                hostname(),
                schema::enumeration("protocol", &["udp", "icmp"]).opt().desc("Default icmp."),
                family(),
                source_address("Local address to send from."),
            ])
            .run(|args, ctx| async move {
                let mut s = Map::new();
                s.insert("hostname".into(), json!(args.req("hostname")));
                s.insert("protocol".into(), json!(args.str("protocol").unwrap_or("icmp")));
                s.insert("ipproto".into(), json!(args.str("family").unwrap_or("inet")));
                let body = json!({ "traceroute": { "settings": with_source(s, args.str("source_address")) } });
                let res = ctx.api.post("diagnostics/traceroute/set", Some(body), RequestOptions::new().timeout_ms(90_000)).await?;
                Ok(Value::Object(assert_write_ok(&res, "The traceroute")?))
            }),
        tool(
            "opn_dns_lookup",
            "DNS lookup from the firewall",
            "Resolves a name as the firewall sees it, through its own resolver or a given server. Useful to compare with what a client gets.",
            Domain::Diagnostics,
            ToolAccess::Read,
        )
        .open_world()
        .input(vec![hostname(), address("server").opt().desc("IP address of the DNS server to ask. Default: the resolver of the firewall.")])
        .run(|args, ctx| async move {
            let mut s = Map::new();
            s.insert("hostname".into(), json!(args.req("hostname")));
            if let Some(server) = args.str("server") {
                s.insert("server".into(), json!(server));
            }
            let res = ctx.api.post("diagnostics/dns_diagnostics/set", Some(json!({ "dns": { "settings": s } })), RequestOptions::new().timeout_ms(60_000)).await?;
            Ok(Value::Object(assert_write_ok(&res, "The DNS lookup")?))
        }),
        tool("opn_reverse_dns", "Reverse DNS lookup", "Finds the names of IP addresses, through the resolver of the firewall.", Domain::Diagnostics, ToolAccess::Read)
            .open_world()
            .input(vec![schema::array_of("addresses", schema::Ty::Str { regex: None, check: Some((Arc::new(|v| v.parse::<std::net::IpAddr>().is_ok()), "Expected an IP address")) }).desc("IP addresses.")])
            .run(|args, ctx| async move {
                // shortcut: le schéma n'a pas de bornes de longueur de liste ; 1 à 50 adresses vérifiées ici.
                let addresses = args.strs("addresses");
                if addresses.is_empty() || addresses.len() > 50 {
                    return Err(OpnError::new(ErrorType::InvalidInput, "addresses: expected between 1 and 50 IP addresses."));
                }
                // PHP lit « address[] » de la chaîne de requête comme une liste.
                let mut o = RequestOptions::new();
                for (i, a) in addresses.iter().enumerate() {
                    o = o.query(format!("address[{i}]"), a);
                }
                ctx.api.get("diagnostics/dns/reverse_lookup", o).await
            }),
        tool(
            "opn_port_probe",
            "Test a TCP port from the firewall",
            "Tries to open a TCP connection from the firewall to a host and port. Sends packets, but changes nothing on the firewall.",
            Domain::Diagnostics,
            ToolAccess::Read,
        )
        .open_world()
        .input(vec![hostname(), schema::integer("port").min(1).max(65535).desc("TCP port."), family(), source_address("Local address to connect from.")])
        .run(|args, ctx| async move {
            let mut s = Map::new();
            s.insert("hostname".into(), json!(args.req("hostname")));
            s.insert("port".into(), json!(args.i64("port").unwrap_or(0).to_string()));
            s.insert("ipproto".into(), json!(args.str("family").unwrap_or("inet")));
            let body = json!({ "portprobe": { "settings": with_source(s, args.str("source_address")) } });
            let res = ctx.api.post("diagnostics/portprobe/set", Some(body), RequestOptions::new().timeout_ms(60_000)).await?;
            Ok(Value::Object(assert_write_ok(&res, "The port probe")?))
        }),
        read_tool(
            "opn_investigate_host",
            "Everything known about a host",
            "Brings together what the firewall knows about an IP address: neighbor table, DHCP lease, active connections, aliases containing it, recent log entries and reverse DNS. Sources the API user cannot read are listed under unavailable. Sends a reverse DNS query, nothing else.",
            Domain::Diagnostics,
        )
        .open_world()
        .input(vec![address("ip").desc("IP address to look up."), schema::integer("log_scan").opt().min(100).max(20000).desc("Newest firewall log lines to scan (default 2000).")])
        .run(|args, ctx| async move {
            let ip = args.req("ip").to_string();
            let page = |n: u32| json!({ "current": 1, "rowCount": n, "searchPhrase": ip });
            let (data, unavailable) = gather(vec![
                ("arp", post_src(&ctx, "diagnostics/interface/search_arp", page(20))),
                ("ndp", post_src(&ctx, "diagnostics/interface/search_ndp", page(20))),
                ("kea_leases", post_src(&ctx, "kea/leases4/search", page(20))),
                ("dnsmasq_leases", post_src(&ctx, "dnsmasq/leases/search", page(20))),
                ("states", post_src(&ctx, "diagnostics/firewall/query_states", json!({ "current": 1, "rowCount": 50, "searchPhrase": ip, "sort": {} }))),
                ("aliases", post_src(&ctx, "firewall/alias_util/find_references", json!({ "ip": ip.to_lowercase() }))),
                ("reverse_dns", get_src(&ctx, "diagnostics/dns/reverse_lookup", vec![("address[0]", ip.clone())])),
                ("log", get_src(&ctx, "diagnostics/firewall/log", vec![("limit", args.i64("log_scan").unwrap_or(2000).to_string())])),
            ])
            .await;

            let log_rows: Vec<Value> = match data.get("log") {
                Some(Value::Array(a)) => a.clone(),
                other => rows_of(other),
            };
            // Correspondance exacte : une recherche par sous-chaîne renverrait aussi 10.0.0.10 pour 10.0.0.1.
            let matches = |v: Option<&Value>| {
                let text = match v {
                    None | Some(Value::Null) => String::new(),
                    other => js(other),
                };
                match_literal(&ip, &text) == Some(true)
            };
            let field = |row: &Value, k: &str| matches(row.get(k));
            let log: Vec<Value> = log_rows.iter().filter(|r| field(r, "src") || field(r, "dst")).cloned().collect();
            let neighbors: Vec<Value> = rows_of(data.get("arp")).into_iter().chain(rows_of(data.get("ndp"))).filter(|r| field(r, "ip")).collect();
            let tagged = |source: &str, key: &str| -> Vec<Value> {
                rows_of(data.get(key))
                    .into_iter()
                    .map(|r| {
                        let mut m = Map::new();
                        m.insert("source".into(), json!(source));
                        if let Value::Object(o) = r {
                            m.extend(o);
                        }
                        Value::Object(m)
                    })
                    .collect()
            };
            let leases: Vec<Value> = tagged("kea", "kea_leases")
                .into_iter()
                .chain(tagged("dnsmasq", "dnsmasq_leases"))
                .filter(|r| matches(pick(r, &["address", "ip_address", "ip"])))
                .collect();
            let active: Vec<Value> = rows_of(data.get("states")).into_iter().filter(|r| field(r, "src_addr") || field(r, "dst_addr")).collect();
            let aliases = match data.get("aliases") {
                Some(Value::Object(o)) => o.get("matches").cloned().unwrap_or_else(|| json!([])),
                _ => json!([]),
            };

            let mut firewall_log = match paginate_array(&log, Some(50), Some(0)).to_value() {
                Value::Object(o) => o,
                _ => Obj::new(),
            };
            firewall_log.insert("scanned".into(), json!(log_rows.len()));
            Ok(json!({
                "ip": ip,
                "neighbors": neighbors,
                "leases": leases,
                "active_connections": active,
                "aliases": aliases,
                "reverse_dns": data.get("reverse_dns").cloned().unwrap_or(Value::Null),
                "firewall_log": firewall_log,
                "unavailable": unavailable,
                "note": "No log entry does not prove there was no traffic: only rules with logging enabled write to the log.",
            }))
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_rejects_option_like_and_spaces() {
        let s = crate::schema::Schema::new(vec![hostname()]);
        assert!(s.validate(&json!({"hostname": "example.com"})).is_ok());
        assert!(s.validate(&json!({"hostname": "-c1"})).is_err());
        assert!(s.validate(&json!({"hostname": "a b"})).is_err());
    }

    #[test]
    fn js_number_and_string_conversions() {
        assert_eq!(num(&json!("3")), 3.0);
        assert!(num(&json!("x")).is_nan());
        assert_eq!(js(Some(&json!(5))), "5");
        assert_eq!(js(None), "undefined");
    }
}

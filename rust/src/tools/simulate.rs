//! Évaluation hors ligne du jeu de règles, avec la sémantique de pf : chaque règle est examinée dans
//! l'ordre, la dernière qui correspond gagne, et une correspondance « quick » arrête l'évaluation.
//!
//! Elle répond à « ce paquet passerait-il, et quelle règle décide ? » sans envoyer de trafic, et sert
//! au contrôle de verrouillage sur les règles en attente. Ce qu'elle ne peut pas déterminer (alias
//! introuvable, horaire) est rapporté comme incertain, jamais deviné.

use crate::client::{OpnsenseClient, RequestOptions};
use crate::error::{ErrorType, OpnError, Result};
use crate::model::{fetch_all, Obj, FETCH_ALL_MAX};
use regex::Regex;
use serde::Serialize;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Tri {
    Yes,
    No,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub destination_port: Option<u32>,
    pub source_port: Option<u32>,
    pub interface: String,
    /// "in" ou "out".
    pub direction: String,
}

/// Une règle telle que l'API la renvoie : un objet JSON libre.
pub type Rule = Obj;

#[derive(Clone, Debug, Default)]
pub struct NetworkContext {
    pub interfaces: Vec<InterfaceInfo>,
    /// Pour chaque adresse évaluée, les tables pf (alias) qui la contiennent, en minuscules. Absent si la recherche a échoué.
    pub alias_membership: HashMap<String, HashSet<String>>,
    /// Tous les alias connus, en minuscules : ne pas figurer dans l'un d'eux est un vrai « non ».
    pub known_aliases: HashSet<String>,
    /// Définition des alias de ports, par nom en minuscules.
    pub port_aliases: HashMap<String, Vec<String>>,
    /// Nom de groupe d'interfaces (minuscules) vers ses membres.
    pub groups: HashMap<String, Vec<String>>,
    /// Contenu des alias d'hôtes et de réseaux, par nom en minuscules : ce que charge une application, modifications en attente comprises.
    pub defined_aliases: Option<HashMap<String, Vec<String>>>,
    /// Les groupes n'ont pas pu être lus : une règle sur un nom d'interface inconnu ici peut quand même s'appliquer.
    pub groups_unreadable: bool,
    /// Interfaces sans affectation, comme la plupart des tunnels VPN.
    pub unassigned: Vec<InterfaceInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct InterfaceInfo {
    pub identifier: String,
    pub device: String,
    pub description: String,
    /// Adresse avec longueur de préfixe, comme 192.168.1.1/24.
    pub addresses: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    Definite,
    Possible,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleHit {
    pub uuid: String,
    pub description: String,
    pub action: String,
    pub interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sort_order: Option<String>,
    pub quick: bool,
    #[serde(rename = "match")]
    pub r#match: MatchKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// La règle envoie aussi le trafic par cette passerelle (routage par politique).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SimulationResult {
    /// "pass", "block", "reject" ou "none" (l'action de la règle décisive, telle quelle).
    pub verdict: String,
    /// "definite" ou "uncertain".
    pub certainty: String,
    pub deciding_rule: Option<RuleHit>,
    pub matched_rules: Vec<RuleHit>,
    pub rules_evaluated: usize,
    pub explanation: String,
}

const WELL_KNOWN_PORTS: &[(&str, u64)] = &[
    ("ftp", 21),
    ("ssh", 22),
    ("telnet", 23),
    ("smtp", 25),
    ("domain", 53),
    ("dns", 53),
    ("http", 80),
    ("www", 80),
    ("kerberos", 88),
    ("pop3", 110),
    ("ntp", 123),
    ("imap", 143),
    ("snmp", 161),
    ("ldap", 389),
    ("https", 443),
    ("smb", 445),
    ("smtps", 465),
    ("submission", 587),
    ("ldaps", 636),
    ("imaps", 993),
    ("pop3s", 995),
    ("mssql", 1433),
    ("openvpn", 1194),
    ("mysql", 3306),
    ("rdp", 3389),
    ("postgresql", 5432),
    ("vnc", 5900),
    ("http-alt", 8080),
];

static CIDR_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+)/([0-9]{1,3})$").unwrap());
static RANGE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(.+)-(.+)$").unwrap());
static PORT_RANGE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^([0-9]+)\s*[-:]\s*([0-9]+)$").unwrap());
static ZONE_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"%[^/]*").unwrap());

fn is_ipv4(ip: &str) -> bool {
    ip.parse::<Ipv4Addr>().is_ok()
}

/// (famille v4 ?, valeur numérique) : v4 et v6 se comparent sur le même entier.
fn ip_num(ip: &str) -> Option<(bool, u128)> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) => Some((true, u32::from(a) as u128)),
        IpAddr::V6(a) => Some((false, u128::from(a))),
    }
}

/// Compare une adresse à une IP, un CIDR ou une plage. `None` : le jeton n'est rien de cela.
pub fn match_literal(token: &str, ip: &str) -> Option<bool> {
    let t = token.trim();
    let target = ip_num(ip);
    if let Some((v4, n)) = ip_num(t) {
        return Some(target == Some((v4, n)));
    }
    if let Some(c) = CIDR_RE.captures(t) {
        let (v4, base) = ip_num(&c[1])?;
        let bits: u32 = c[2].parse().ok()?;
        let total = if v4 { 32 } else { 128 };
        if bits > total {
            return None;
        }
        let mask = if bits == 0 {
            0
        } else {
            (u128::MAX >> (128 - bits)) << (total - bits)
        };
        return Some(matches!(target, Some((tv4, n)) if tv4 == v4 && n & mask == base & mask));
    }
    if let Some(c) = RANGE_RE.captures(t) {
        let (Some((v4, lo)), Some((v4b, hi))) = (ip_num(&c[1]), ip_num(&c[2])) else {
            return None;
        };
        // Node refuse une plage dont le début dépasse la fin.
        if v4 != v4b || lo > hi {
            return None;
        }
        return Some(matches!(target, Some((tv4, n)) if tv4 == v4 && (lo..=hi).contains(&n)));
    }
    None
}

/// `String(v)` de JavaScript, avec undefined/null en chaîne vide.
fn str_of(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => b.to_string(),
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if n.is_f64() && f.fract() == 0.0 && f.abs() < 1e15 => format!("{}", f as i64),
            _ => n.to_string(),
        },
        Some(Value::Array(a)) => a
            .iter()
            .map(|x| str_of(Some(x)))
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".into(),
    }
}

fn flag(v: Option<&Value>) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        Some(Value::String(s)) => matches!(s.as_str(), "1" | "yes" | "on"),
        _ => false,
    }
}

fn find_interface<'a>(token: &str, ctx: &'a NetworkContext) -> Option<&'a InterfaceInfo> {
    let t = token.to_lowercase();
    ctx.interfaces.iter().find(|i| {
        i.identifier.to_lowercase() == t
            || i.device.to_lowercase() == t
            || i.description.to_lowercase() == t
    })
}

fn address_only(cidr: &str) -> &str {
    cidr.split('/').next().unwrap_or("")
}

fn match_address_token(token: &str, ip: &str, ctx: &NetworkContext) -> Tri {
    let t = token.trim();
    let lower = t.to_lowercase();
    if t.is_empty() || lower == "any" {
        return Tri::Yes;
    }
    if t == "(self)" || lower == "self" || lower == "this firewall" {
        return yes_no(
            ctx.interfaces
                .iter()
                .any(|i| i.addresses.iter().any(|a| address_only(a) == ip)),
        );
    }
    if let Some(literal) = match_literal(t, ip) {
        return yes_no(literal);
    }
    // « wanip » est l'adresse de l'interface, « wan » le réseau derrière elle.
    if let Some(name) = lower.strip_suffix("ip") {
        if let Some(iface) = find_interface(name, ctx) {
            return yes_no(iface.addresses.iter().any(|a| address_only(a) == ip));
        }
    }
    if let Some(iface) = find_interface(&lower, ctx) {
        return yes_no(
            iface
                .addresses
                .iter()
                .any(|a| match_literal(a, ip).is_some_and(|m| m)),
        );
    }
    if let Some(defined) = ctx.defined_aliases.as_ref().and_then(|d| d.get(&lower)) {
        return match_defined_alias(&lower, defined, ip, ctx, 0);
    }
    live_membership(&lower, ip, ctx)
}

fn yes_no(b: bool) -> Tri {
    if b {
        Tri::Yes
    } else {
        Tri::No
    }
}

/// Ce que pf contient maintenant, sans rien de ce qui est en attente.
fn live_membership(name: &str, ip: &str, ctx: &NetworkContext) -> Tri {
    let Some(membership) = ctx.alias_membership.get(ip) else {
        return Tri::Unknown;
    };
    if membership.contains(name) {
        return Tri::Yes;
    }
    if ctx.known_aliases.contains(name) {
        Tri::No
    } else {
        Tri::Unknown
    }
}

/// La table vivante manquerait une modification en attente (ajout dans un alias de blocage, retrait d'un alias de passage) :
/// la définition décide, et la table ne répond que pour ce que le pare-feu seul sait résoudre, comme un nom d'hôte.
fn match_defined_alias(
    name: &str,
    entries: &[String],
    ip: &str,
    ctx: &NetworkContext,
    depth: u32,
) -> Tri {
    any_of(entries.iter().map(|entry| {
        if let Some(literal) = match_literal(entry, ip) {
            return yes_no(literal);
        }
        let lower = entry.to_lowercase();
        if let Some(nested) = ctx.defined_aliases.as_ref().and_then(|d| d.get(&lower)) {
            if depth < 8 {
                return match_defined_alias(&lower, nested, ip, ctx, depth + 1);
            }
        }
        live_membership(
            if ctx.known_aliases.contains(&lower) {
                &lower
            } else {
                name
            },
            ip,
            ctx,
        )
    }))
}

fn any_of(results: impl IntoIterator<Item = Tri>) -> Tri {
    let all: Vec<Tri> = results.into_iter().collect();
    if all.contains(&Tri::Yes) {
        Tri::Yes
    } else if all.contains(&Tri::Unknown) {
        Tri::Unknown
    } else {
        Tri::No
    }
}

fn invert(t: Tri) -> Tri {
    match t {
        Tri::Yes => Tri::No,
        Tri::No => Tri::Yes,
        Tri::Unknown => Tri::Unknown,
    }
}

/// Les règles automatiques peuvent lister des valeurs séparées par des espaces une fois les accolades retirées.
fn tokens_of(value: Option<&Value>) -> Vec<String> {
    str_of(value)
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn has_port_condition(value: Option<&Value>) -> bool {
    tokens_of(value).iter().any(|t| t.to_lowercase() != "any")
}

pub fn match_address_field(
    value: Option<&Value>,
    not: Option<&Value>,
    ip: &str,
    ctx: &NetworkContext,
) -> Tri {
    let tokens = tokens_of(value);
    let result = if tokens.is_empty() {
        Tri::Yes
    } else {
        any_of(tokens.iter().map(|t| match_address_token(t, ip, ctx)))
    };
    if flag(not) {
        invert(result)
    } else {
        result
    }
}

fn match_port_token(token: &str, port: u32, ctx: &NetworkContext, depth: u32) -> Tri {
    let t = token.trim().to_lowercase();
    let port = port as u64;
    if t.is_empty() || t == "any" {
        return Tri::Yes;
    }
    if t.bytes().all(|b| b.is_ascii_digit()) {
        return yes_no(t.parse::<u64>().is_ok_and(|n| n == port));
    }
    if let Some(c) = PORT_RANGE_RE.captures(&t) {
        let (lo, hi) = (
            c[1].parse::<u64>().unwrap_or(u64::MAX),
            c[2].parse::<u64>().unwrap_or(u64::MAX),
        );
        return yes_no(port >= lo && port <= hi);
    }
    if let Some((_, known)) = WELL_KNOWN_PORTS.iter().find(|(name, _)| *name == t) {
        return yes_no(*known == port);
    }
    if let Some(alias) = ctx.port_aliases.get(&t) {
        if depth < 8 {
            return any_of(
                alias
                    .iter()
                    .map(|entry| match_port_token(entry, port as u32, ctx, depth + 1)),
            );
        }
    }
    Tri::Unknown
}

pub fn match_port_field(value: Option<&Value>, port: Option<u32>, ctx: &NetworkContext) -> Tri {
    if !has_port_condition(value) {
        return Tri::Yes;
    }
    let Some(port) = port else {
        return Tri::Unknown;
    };
    any_of(
        tokens_of(value)
            .iter()
            .map(|t| match_port_token(t, port, ctx, 0)),
    )
}

fn match_protocol(rule_protocol: Option<&Value>, protocol: &str) -> Tri {
    let rp = str_of(rule_protocol).trim().to_lowercase();
    let p = protocol.to_lowercase();
    if rp.is_empty() || rp == "any" {
        return Tri::Yes;
    }
    if rp == "tcp/udp" || rp == "tcp,udp" {
        return yes_no(p == "tcp" || p == "udp");
    }
    if matches!(rp.as_str(), "ipv6-icmp" | "icmpv6" | "icmp6")
        && (p == "ipv6-icmp" || p == "icmpv6")
    {
        return Tri::Yes;
    }
    yes_no(rp == p)
}

fn match_interface(rule: &Rule, packet: &Packet, ctx: &NetworkContext) -> Tri {
    let tokens: Vec<String> = str_of(rule.get("interface"))
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    // Pas d'interface : règle flottante, qui s'applique partout.
    if tokens.is_empty() {
        return Tri::Yes;
    }
    let mut names = HashSet::from([packet.interface.to_lowercase()]);
    if let Some(target) = find_interface(&packet.interface, ctx) {
        names.insert(target.identifier.to_lowercase());
        names.insert(target.device.to_lowercase());
        names.insert(target.description.to_lowercase());
    }
    let matched = tokens.iter().any(|t| {
        names.contains(t)
            || ctx
                .groups
                .get(t)
                .is_some_and(|g| g.iter().any(|m| names.contains(&m.to_lowercase())))
    });
    let result = if matched {
        Tri::Yes
    } else if ctx.groups_unreadable && tokens.iter().any(|t| find_interface(t, ctx).is_none()) {
        Tri::Unknown
    } else {
        Tri::No
    };
    if flag(rule.get("interfacenot")) {
        invert(result)
    } else {
        result
    }
}

fn is_enabled(rule: &Rule) -> bool {
    match rule.get("enabled") {
        None => !flag(rule.get("disabled")),
        v => flag(v),
    }
}

fn is_quick(rule: &Rule) -> bool {
    match rule.get("quick") {
        Some(q) if q != &Value::Null && q != &json!("") => flag(Some(q)),
        // Une ancienne règle flottante sans l'option n'est pas quick ; toutes les autres le sont.
        _ => {
            !matches!(rule.get("floating"), Some(Value::Bool(true)))
                && rule.get("floating") != Some(&json!("yes"))
        }
    }
}

/// Conditions dont cette évaluation hors ligne ne connaît pas l'état.
fn conditional_fields(rule: &Rule) -> Vec<&'static str> {
    let set = |k: &str| !str_of(rule.get(k)).is_empty();
    let mut out = Vec::new();
    if set("sched") {
        out.push("schedule");
    }
    if set("tagged") {
        out.push("tagged");
    }
    if set("received-on") {
        out.push("received-on");
    }
    if set("tcpflags1") || set("tcpflags2") {
        out.push("TCP flags");
    }
    if set("icmptype") || set("icmp6type") {
        out.push("ICMP type");
    }
    if set("tos") {
        out.push("TOS");
    }
    out
}

pub fn match_rule(rule: &Rule, packet: &Packet, ctx: &NetworkContext) -> (Tri, Option<String>) {
    let on_interface = match_interface(rule, packet, ctx);
    if on_interface == Tri::No {
        return (Tri::No, None);
    }
    let direction = str_of(rule.get("direction")).to_lowercase();
    if !direction.is_empty() && direction != "any" && direction != packet.direction {
        return (Tri::No, None);
    }
    let ipp = str_of(rule.get("ipprotocol")).to_lowercase();
    let fam = if is_ipv4(&packet.source) {
        "inet"
    } else {
        "inet6"
    };
    if !ipp.is_empty() && ipp != "inet46" && ipp != fam {
        return (Tri::No, None);
    }

    let is_port_protocol = matches!(packet.protocol.to_lowercase().as_str(), "tcp" | "udp");
    if (has_port_condition(rule.get("source_port"))
        || has_port_condition(rule.get("destination_port")))
        && !is_port_protocol
    {
        return (Tri::No, None);
    }
    let checks = [
        ("interface", on_interface),
        (
            "protocol",
            match_protocol(rule.get("protocol"), &packet.protocol),
        ),
        (
            "source",
            match_address_field(
                rule.get("source_net"),
                rule.get("source_not"),
                &packet.source,
                ctx,
            ),
        ),
        (
            "destination",
            match_address_field(
                rule.get("destination_net"),
                rule.get("destination_not"),
                &packet.destination,
                ctx,
            ),
        ),
        (
            "source port",
            match_port_field(rule.get("source_port"), packet.source_port, ctx),
        ),
        (
            "destination port",
            match_port_field(rule.get("destination_port"), packet.destination_port, ctx),
        ),
    ];
    if checks.iter().any(|(_, r)| *r == Tri::No) {
        return (Tri::No, None);
    }
    let unknown: Vec<&str> = checks
        .iter()
        .filter(|(_, r)| *r == Tri::Unknown)
        .map(|(n, _)| *n)
        .collect();
    let conditional = conditional_fields(rule);
    if !unknown.is_empty() || !conditional.is_empty() {
        let mut parts = Vec::new();
        if !unknown.is_empty() {
            parts.push(format!("could not resolve: {}", unknown.join(", ")));
        }
        if !conditional.is_empty() {
            parts.push(format!("depends on: {}", conditional.join(", ")));
        }
        return (Tri::Unknown, Some(parts.join("; ")));
    }
    (Tri::Yes, None)
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

fn describe_hit(rule: &Rule, kind: MatchKind, reason: Option<String>) -> RuleHit {
    let description = match rule.get("description") {
        Some(v) if !v.is_null() => str_of(Some(v)),
        _ => str_of(rule.get("descr")),
    };
    RuleHit {
        uuid: str_of(rule.get("uuid")),
        description,
        action: str_of(rule.get("action")).to_lowercase(),
        interface: str_of(rule.get("interface")),
        sort_order: non_empty(str_of(rule.get("sort_order"))),
        quick: is_quick(rule),
        r#match: kind,
        reason: reason.filter(|r| !r.is_empty()),
        gateway: non_empty(str_of(rule.get("gateway"))),
    }
}

pub fn simulate(rules: &[Rule], packet: &Packet, ctx: &NetworkContext) -> SimulationResult {
    let enabled: Vec<&Rule> = rules.iter().filter(|r| is_enabled(r)).collect();
    let mut hits: Vec<RuleHit> = Vec::new();
    let mut decided: Option<RuleHit> = None;

    for rule in &enabled {
        let (m, reason) = match_rule(rule, packet, ctx);
        if m == Tri::No {
            continue;
        }
        if m == Tri::Unknown {
            hits.push(describe_hit(rule, MatchKind::Possible, reason));
            continue;
        }
        let hit = describe_hit(rule, MatchKind::Definite, None);
        hits.push(hit.clone());
        if hit.action == "match" {
            continue;
        }
        let quick = hit.quick;
        decided = Some(hit);
        if quick {
            break;
        }
    }

    let verdict = decided
        .as_ref()
        .map_or("none".to_string(), |d| d.action.clone());
    // Une correspondance possible ne compte que si elle pouvait changer l'issue.
    let uncertain = hits
        .iter()
        .any(|h| h.r#match == MatchKind::Possible && h.action != "match" && h.action != verdict);
    let certainty = if uncertain { "uncertain" } else { "definite" };

    let explanation = if let Some(d) = &decided {
        let label = [d.description.as_str(), d.uuid.as_str(), "unnamed rule"]
            .into_iter()
            .find(|s| !s.is_empty())
            .unwrap_or("unnamed rule");
        format!(
            "{verdict} by \"{label}\"{}.",
            if uncertain {
                ", unless one of the possible matches above it applies"
            } else {
                ""
            }
        )
    } else if hits.iter().any(|h| h.r#match == MatchKind::Possible) {
        "No rule matches for certain: the outcome depends on the possible matches listed."
            .to_string()
    } else {
        "No listed rule matches. OPNsense blocks by default what no rule passes.".to_string()
    };
    hits.truncate(25);
    SimulationResult {
        verdict,
        certainty: certainty.into(),
        deciding_rule: decided,
        matched_rules: hits,
        rules_evaluated: enabled.len(),
        explanation,
    }
}

pub const SIMULATION_LIMITS: &str = "Offline estimate from the configuration, which includes staged rules that are not live yet. Existing connections keep their state and are not re-evaluated. Destination NAT happens before filtering, so give the translated destination. Only the requested direction on the given interface is evaluated, and shaping and policy routing are ignored.";

#[derive(Clone, Debug)]
pub struct Ruleset {
    pub rules: Vec<Rule>,
    pub context: NetworkContext,
    /// Faux sur les versions dont search_rule omet les règles automatiques et héritées.
    pub complete: bool,
    pub warnings: Vec<String>,
}

fn addresses_of(row: &Obj) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |s: &str| {
        if !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    };
    for key in ["addr4", "addr6"] {
        if let Some(Value::String(s)) = row.get(key) {
            if !s.is_empty() {
                add(s);
            }
        }
    }
    for key in ["ipv4", "ipv6"] {
        if let Some(Value::Array(list)) = row.get(key) {
            for entry in list {
                if let Some(Value::String(s)) = entry.get("ipaddr") {
                    add(s);
                }
            }
        }
    }
    // Les adresses link-local portent une zone ("fe80::1%igb0") que les listes d'adresses n'acceptent pas.
    out.iter()
        .map(|a| ZONE_RE.replace(a, "").into_owned())
        .collect()
}

fn interface_info(r: &Obj) -> InterfaceInfo {
    InterfaceInfo {
        identifier: str_of(r.get("identifier")),
        device: str_of(r.get("device")),
        description: str_of(r.get("description")),
        addresses: addresses_of(r),
    }
}

fn split_list(s: &str, seps: fn(char) -> bool) -> Vec<String> {
    s.split(seps)
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect()
}

fn objects(rows: Vec<Value>) -> Vec<Obj> {
    rows.into_iter()
        .filter_map(|v| {
            if let Value::Object(o) = v {
                Some(o)
            } else {
                None
            }
        })
        .collect()
}

/// Assemble le jeu de règles et son contexte à partir des réponses brutes (séparé de la lecture pour être testable).
fn build_ruleset(
    rules: Vec<Obj>,
    interface_rows: &[Obj],
    alias_rows: &[Obj],
    group_rows: &[Obj],
    tables: &Value,
    groups_unreadable: bool,
    mut warnings: Vec<String>,
) -> Ruleset {
    let mut defined: HashMap<String, Vec<String>> = HashMap::new();
    let mut context = NetworkContext {
        interfaces: interface_rows
            .iter()
            .filter(|r| !str_of(r.get("identifier")).is_empty())
            .map(interface_info)
            .collect(),
        unassigned: interface_rows
            .iter()
            .filter(|r| str_of(r.get("identifier")).is_empty())
            .map(interface_info)
            .collect(),
        groups_unreadable,
        ..Default::default()
    };
    for row in alias_rows {
        let name = str_of(row.get("name")).to_lowercase();
        let content = split_list(&str_of(row.get("content")), |c| {
            c == ',' || c.is_whitespace()
        });
        let kind = str_of(row.get("type"));
        context.known_aliases.insert(name.clone());
        if kind == "port" {
            context.port_aliases.insert(name.clone(), content.clone());
        }
        // Un alias désactivé ne charge aucune table.
        if matches!(kind.as_str(), "host" | "network" | "networkgroup") {
            let disabled = row.get("enabled").is_some() && !flag(row.get("enabled"));
            defined.insert(name, if disabled { vec![] } else { content });
        }
    }
    context.defined_aliases = Some(defined);
    if let Value::Array(list) = tables {
        for t in list {
            context.known_aliases.insert(str_of(Some(t)).to_lowercase());
        }
    }
    for g in group_rows {
        context.groups.insert(
            str_of(g.get("ifname")).to_lowercase(),
            str_of(g.get("members"))
                .split(',')
                .map(|m| m.trim())
                .filter(|m| !m.is_empty())
                .map(String::from)
                .collect(),
        );
    }
    let complete = rules.iter().any(|r| {
        r.get("legacy") == Some(&Value::Bool(true))
            || r.get("is_automatic") == Some(&Value::Bool(true))
    });
    if !complete {
        warnings.push("This firewall returned only MVC rules: automatic and legacy rules are not part of this evaluation, so the real outcome can differ. search_rule includes them on recent OPNsense versions.".into());
    }
    Ruleset {
        rules,
        context,
        complete,
        warnings,
    }
}

/// Charge les règles configurées et ce qu'il faut pour les interpréter, sauf les adresses.
pub async fn load_ruleset(client: &OpnsenseClient) -> Result<Ruleset> {
    let (rules, interface_rows, aliases, groups, tables) = futures::join!(
        fetch_all(client, "firewall/filter/search_rule", None, FETCH_ALL_MAX),
        fetch_all(
            client,
            "interfaces/overview/interfaces_info",
            None,
            FETCH_ALL_MAX
        ),
        fetch_all(client, "firewall/alias/search_item", None, FETCH_ALL_MAX),
        fetch_all(client, "firewall/group/search_item", None, FETCH_ALL_MAX),
        // Toutes les tables pf, y compris internes comme bogons et virusprot.
        client.get("firewall/alias_util/aliases", RequestOptions::new()),
    );
    let (rules, interface_rows) = (rules?, interface_rows?);
    let mut warnings = Vec::new();
    let alias_rows = aliases.unwrap_or_else(|e| {
        warnings.push(format!(
            "Aliases could not be read ({}), so rules using them are uncertain.",
            e.message
        ));
        vec![]
    });
    let mut groups_unreadable = false;
    let group_rows = groups.unwrap_or_else(|e| {
        groups_unreadable = true;
        warnings.push(format!("Interface groups could not be read ({}), so rules on interfaces not known here count as possible matches.", e.message));
        vec![]
    });
    let tables = tables.unwrap_or_else(|_| json!([]));
    Ok(build_ruleset(
        objects(rules),
        &objects(interface_rows),
        &objects(alias_rows),
        &objects(group_rows),
        &tables,
        groups_unreadable,
        warnings,
    ))
}

/// Demande à pf quelles tables contiennent une adresse : moins cher et plus exact que de télécharger toutes les tables
/// (les bogons seuls en comptent plus de cent mille).
pub async fn load_alias_membership(
    client: &OpnsenseClient,
    ruleset: &mut Ruleset,
    addresses: &[String],
) {
    let mut seen = HashSet::new();
    for ip in addresses.iter().filter(|a| seen.insert(a.as_str())) {
        match client.post("firewall/alias_util/find_references", Some(json!({ "ip": ip.to_lowercase() })), RequestOptions::new()).await {
            Ok(res) => match res.get("matches").and_then(Value::as_array) {
                Some(m) => {
                    ruleset.context.alias_membership.insert(ip.clone(), m.iter().map(|x| str_of(Some(x)).to_lowercase()).collect());
                }
                None => ruleset.warnings.push(format!("The alias lookup for {ip} returned no usable answer, so rules using aliases are uncertain.")),
            },
            Err(e) => ruleset.warnings.push(format!("The alias lookup for {ip} failed ({}), so rules using aliases are uncertain.", e.message)),
        }
    }
}

pub fn interface_for_address<'a>(
    ip: &str,
    interfaces: &'a [InterfaceInfo],
) -> Option<&'a InterfaceInfo> {
    interfaces.iter().find(|i| {
        i.addresses
            .iter()
            .any(|a| match_literal(a, ip) == Some(true))
    })
}

struct Forward {
    row: Obj,
    definite: bool,
}

/// Une redirection de port sur le port de l'API retire les connexions au pare-feu avant que toute règle de filtre les voie.
async fn find_port_forward(
    client: &OpnsenseClient,
    ruleset: &mut Ruleset,
    packet: &Packet,
) -> Option<Forward> {
    let rows = match fetch_all(client, "firewall/d_nat/search_rule", None, FETCH_ALL_MAX).await {
        Ok(rows) => objects(rows),
        Err(e) => {
            ruleset.warnings.push(format!(
                "Port forwards could not be read ({}), so they were not checked.",
                e.message
            ));
            vec![]
        }
    };
    find_forward_in(&rows, ruleset, packet)
}

fn find_forward_in(rows: &[Obj], ruleset: &Ruleset, packet: &Packet) -> Option<Forward> {
    let mut possible = None;
    for row in rows {
        if flag(row.get("disabled")) || flag(row.get("nordr")) || flag(row.get("is_automatic")) {
            continue;
        }
        let mut rule = Rule::new();
        for (to, from) in [
            ("interface", "interface"),
            ("ipprotocol", "ipprotocol"),
            ("protocol", "protocol"),
            ("source_net", "source.network"),
            ("source_not", "source.not"),
            ("source_port", "source.port"),
            ("destination_net", "destination.network"),
            ("destination_not", "destination.not"),
            ("destination_port", "destination.port"),
        ] {
            if let Some(v) = row.get(from) {
                rule.insert(to.into(), v.clone());
            }
        }
        match match_rule(&rule, packet, &ruleset.context).0 {
            Tri::Yes => {
                return Some(Forward {
                    row: row.clone(),
                    definite: true,
                })
            }
            Tri::Unknown if possible.is_none() => {
                possible = Some(Forward {
                    row: row.clone(),
                    definite: false,
                })
            }
            _ => {}
        }
    }
    possible
}

#[derive(Clone, Debug, Serialize)]
pub struct ManagementPath {
    pub source: Option<String>,
    pub destination: Option<String>,
    pub port: u16,
    pub interface: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct LockoutReport {
    /// "none", "possible", "high" ou "unknown".
    pub risk: String,
    pub management_path: ManagementPath,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub simulation: Option<SimulationResult>,
    pub message: String,
    pub warnings: Vec<String>,
}

fn strip_mapped(s: &str) -> String {
    s.strip_prefix("::ffff:").unwrap_or(s).to_string()
}

fn unknown_report(
    path: ManagementPath,
    message: impl Into<String>,
    warnings: Vec<String>,
) -> LockoutReport {
    LockoutReport {
        risk: "unknown".into(),
        management_path: path,
        simulation: None,
        message: message.into(),
        warnings,
    }
}

/// Le jeu de règles configuré laisse-t-il encore ce serveur joindre l'API du pare-feu ?
pub async fn check_lockout(client: &OpnsenseClient) -> Result<LockoutReport> {
    let url = url::Url::parse(&client.config.url).map_err(|_| {
        OpnError::new(
            ErrorType::ConfigError,
            format!("{} is not a valid URL.", client.config.url),
        )
    })?;
    let port = url
        .port()
        .unwrap_or(if url.scheme() == "https" { 443 } else { 80 });
    let source = client
        .config
        .management_source
        .clone()
        .or_else(|| client.local_address());
    // host_str garde les crochets d'une IPv6 : comme Node, elle n'est alors pas reconnue comme une IP.
    let destination = client.remote_address().or_else(|| {
        url.host_str()
            .filter(|h| h.parse::<IpAddr>().is_ok())
            .map(String::from)
    });
    let mut path = ManagementPath {
        source: source.clone(),
        destination: destination.clone(),
        port,
        interface: None,
    };

    let (Some(source), Some(destination)) = (
        source.filter(|s| !s.is_empty()),
        destination.filter(|d| !d.is_empty()),
    ) else {
        return Ok(unknown_report(path, "The address of this server or of the firewall is not known yet, so the management path could not be checked.", vec![]));
    };
    let (src, dst) = (strip_mapped(&source), strip_mapped(&destination));
    if src == dst || src == "127.0.0.1" || src == "::1" {
        return Ok(unknown_report(path, "The connection goes through a local address (SSH tunnel or proxy?), so the path the firewall really sees is unknown. Set OPNSENSE_MANAGEMENT_SOURCE to enable this check.", vec![]));
    }

    let mut ruleset = load_ruleset(client).await?;
    // Sans source directement connectée, le trafic entre par l'interface à laquelle appartient l'adresse du pare-feu.
    let direct = interface_for_address(&src, &ruleset.context.interfaces).cloned();
    let tunnel = if direct.is_some() {
        None
    } else {
        interface_for_address(&src, &ruleset.context.unassigned)
    };
    if let Some(tunnel) = tunnel {
        path.interface = Some(tunnel.device.clone());
        let message = format!("This server arrives through {}, an interface with no assignment (a VPN tunnel?) whose rules cannot be evaluated here, so the management path could not be checked.", tunnel.device);
        return Ok(unknown_report(path, message, ruleset.warnings));
    }
    let Some(iface) = direct
        .clone()
        .or_else(|| interface_for_address(&dst, &ruleset.context.interfaces).cloned())
    else {
        return Ok(unknown_report(
            path,
            "No interface of the firewall matches the management path, so it could not be checked.",
            ruleset.warnings,
        ));
    };
    path.interface = Some(iface.identifier.clone());
    if direct.is_none() {
        ruleset.warnings.push(format!("{src} is not on a network attached to the firewall, so it is assumed to enter on {}. A VPN or a routed path can enter elsewhere, where other rules apply.", iface.identifier));
    }

    load_alias_membership(client, &mut ruleset, &[src.clone(), dst.clone()]).await;
    let packet = Packet {
        source: src.clone(),
        destination: dst.clone(),
        protocol: "tcp".into(),
        destination_port: Some(port as u32),
        source_port: None,
        interface: iface.identifier.clone(),
        direction: "in".into(),
    };
    let simulation = simulate(&ruleset.rules, &packet, &ruleset.context);
    let denied = matches!(simulation.verdict.as_str(), "block" | "reject" | "none");
    let (mut risk, mut message);
    if denied && simulation.certainty == "definite" && ruleset.complete {
        risk = "high";
        let what = if simulation.verdict == "none" {
            "not pass"
        } else {
            simulation.verdict.as_str()
        };
        message = format!("The ruleset would {what} new connections from this server ({src}) to the API ({dst}:{port}) on {}.", iface.identifier);
    } else if denied || simulation.certainty == "uncertain" {
        risk = "possible";
        message = format!("The ruleset might cut this server off from the API ({dst}:{port}). See the possible matches in the simulation.");
    } else {
        risk = "none";
        message = format!(
            "The ruleset keeps the management path open: {}",
            simulation.explanation
        );
        if let Some(gateway) = simulation
            .deciding_rule
            .as_ref()
            .and_then(|r| r.gateway.as_deref())
        {
            risk = "possible";
            message = format!("The rule that passes this path also sends its traffic through gateway {gateway}, which can divert what is meant for the firewall itself.");
        }
    }
    if let Some(forward) = find_port_forward(client, &mut ruleset, &packet).await {
        if forward.definite || risk == "none" {
            risk = if forward.definite { "high" } else { "possible" };
            let label = match forward.row.get("description") {
                Some(v) if !v.is_null() => str_of(Some(v)),
                _ => str_of(forward.row.get("descr")),
            };
            let label = if label.is_empty() {
                str_of(forward.row.get("uuid"))
            } else {
                label
            };
            let target = non_empty(str_of(forward.row.get("target")))
                .unwrap_or_else(|| "another host".into());
            message = format!("A port forward (\"{label}\") {} connections to the API ({dst}:{port}) to {target}.", if forward.definite { "would send" } else { "may send" });
        }
    }
    Ok(LockoutReport {
        risk: risk.into(),
        management_path: path,
        simulation: Some(simulation),
        message,
        warnings: ruleset.warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(id: &str, dev: &str, desc: &str, addr: &str) -> InterfaceInfo {
        InterfaceInfo {
            identifier: id.into(),
            device: dev.into(),
            description: desc.into(),
            addresses: vec![addr.into()],
        }
    }

    fn ctx() -> NetworkContext {
        NetworkContext {
            interfaces: vec![
                iface("lan", "igb1", "LAN", "192.168.1.1/24"),
                iface("wan", "igb0", "WAN", "203.0.113.2/24"),
            ],
            ..Default::default()
        }
    }

    fn packet() -> Packet {
        Packet {
            source: "192.168.1.50".into(),
            destination: "8.8.8.8".into(),
            protocol: "tcp".into(),
            destination_port: Some(443),
            source_port: None,
            interface: "lan".into(),
            direction: "in".into(),
        }
    }

    fn rule(over: Value) -> Rule {
        let mut r = json!({"enabled": "1", "interface": "lan", "action": "pass", "quick": "1", "protocol": "any", "source_net": "any", "destination_net": "any"});
        r.as_object_mut()
            .unwrap()
            .extend(over.as_object().unwrap().clone());
        r.as_object().unwrap().clone()
    }

    fn sim(rules: Vec<Rule>) -> SimulationResult {
        simulate(&rules, &packet(), &ctx())
    }

    fn port(v: &str, p: u32, c: &NetworkContext) -> Tri {
        match_port_field(Some(&json!(v)), Some(p), c)
    }

    #[test]
    fn literals() {
        assert_eq!(match_literal("10.0.0.1", "10.0.0.1"), Some(true));
        assert_eq!(match_literal("10.0.0.1", "10.0.0.10"), Some(false));
        assert_eq!(match_literal("10.0.0.0/24", "10.0.0.200"), Some(true));
        assert_eq!(match_literal("10.0.0.0/24", "10.0.1.1"), Some(false));
        assert_eq!(match_literal("10.0.0.5-10.0.0.9", "10.0.0.7"), Some(true));
        assert_eq!(match_literal("2001:db8::/32", "2001:db8::1"), Some(true));
        assert_eq!(match_literal("0.0.0.0/0", "9.9.9.9"), Some(true));
        assert_eq!(match_literal("10.0.0.0/24", "2001:db8::1"), Some(false));
    }

    #[test]
    fn literals_never_guess() {
        assert_eq!(match_literal("myalias", "10.0.0.1"), None);
        assert_eq!(match_literal("10.0.0.0/99", "10.0.0.1"), None);
        assert_eq!(match_literal("10.0.0.9-10.0.0.5", "10.0.0.7"), None);
    }

    #[test]
    fn ports() {
        let mut c = ctx();
        c.port_aliases
            .insert("web".into(), vec!["80".into(), "443".into()]);
        c.port_aliases.insert("sshports".into(), vec!["22".into()]);
        assert_eq!(port("443", 443, &c), Tri::Yes);
        assert_eq!(port("80,443", 443, &c), Tri::Yes);
        assert_eq!(port("80 443", 443, &c), Tri::Yes);
        assert_eq!(port("1000-2000", 1500, &c), Tri::Yes);
        assert_eq!(port("1000:2000", 2500, &c), Tri::No);
        assert_eq!(port("https", 443, &c), Tri::Yes);
        assert_eq!(port("web", 443, &c), Tri::Yes);
        assert_eq!(port("any", 443, &c), Tri::Yes);
        assert_eq!(port("unknown_alias", 443, &c), Tri::Unknown);
        assert_eq!(port("sshports", 22, &c), Tri::Yes);
        assert_eq!(port("sshports", 443, &c), Tri::No);
        assert_eq!(
            match_port_field(Some(&json!("443")), None, &c),
            Tri::Unknown
        );
    }

    #[test]
    fn first_quick_match_stops() {
        let r = sim(vec![
            rule(json!({"action": "block", "uuid": "a"})),
            rule(json!({"action": "pass", "uuid": "b"})),
        ]);
        assert_eq!(r.verdict, "block");
        assert_eq!(r.deciding_rule.unwrap().uuid, "a");
        assert_eq!(r.certainty, "definite");
    }

    #[test]
    fn last_non_quick_match_wins() {
        let r = sim(vec![
            rule(json!({"action": "block", "quick": "0", "uuid": "a"})),
            rule(json!({"action": "pass", "quick": "0", "uuid": "b"})),
        ]);
        assert_eq!(r.verdict, "pass");
        assert_eq!(r.deciding_rule.unwrap().uuid, "b");
    }

    #[test]
    fn skips_disabled_and_other_interfaces() {
        let r = sim(vec![
            rule(json!({"action": "block", "enabled": "0"})),
            rule(json!({"action": "block", "interface": "wan"})),
            rule(json!({"action": "pass", "uuid": "c"})),
        ]);
        assert_eq!(r.deciding_rule.unwrap().uuid, "c");
    }

    #[test]
    fn no_match_means_none() {
        let r = sim(vec![rule(json!({"interface": "wan"}))]);
        assert_eq!(r.verdict, "none");
        assert!(r.explanation.contains("blocks by default"));
    }

    #[test]
    fn inversion() {
        assert_eq!(
            sim(vec![rule(
                json!({"source_net": "192.168.1.0/24", "source_not": "1"})
            )])
            .verdict,
            "none"
        );
        assert_eq!(
            sim(vec![rule(
                json!({"source_net": "10.0.0.0/8", "source_not": "1"})
            )])
            .verdict,
            "pass"
        );
    }

    #[test]
    fn port_condition_never_matches_icmp() {
        let p = Packet {
            protocol: "icmp".into(),
            destination_port: None,
            ..packet()
        };
        assert_eq!(
            simulate(&[rule(json!({"destination_port": "443"}))], &p, &ctx()).verdict,
            "none"
        );
    }

    #[test]
    fn interface_network_vs_address() {
        assert_eq!(
            sim(vec![rule(json!({"source_net": "lan"}))]).verdict,
            "pass"
        );
        assert_eq!(
            sim(vec![rule(json!({"source_net": "lanip"}))]).verdict,
            "none"
        );
        let p = Packet {
            source: "192.168.1.1".into(),
            ..packet()
        };
        assert_eq!(
            simulate(&[rule(json!({"source_net": "lanip"}))], &p, &ctx()).verdict,
            "pass"
        );
    }

    #[test]
    fn floating_rule_applies_everywhere() {
        assert_eq!(
            sim(vec![rule(json!({"interface": "", "action": "block"}))]).verdict,
            "block"
        );
    }

    #[test]
    fn interface_groups() {
        let mut c = ctx();
        c.groups.insert("internal".into(), vec!["lan".into()]);
        assert_eq!(
            simulate(&[rule(json!({"interface": "internal"}))], &packet(), &c).verdict,
            "pass"
        );
    }

    #[test]
    fn address_family() {
        assert_eq!(
            sim(vec![rule(json!({"ipprotocol": "inet6"}))]).verdict,
            "none"
        );
        assert_eq!(
            sim(vec![rule(json!({"ipprotocol": "inet46"}))]).verdict,
            "pass"
        );
    }

    #[test]
    fn unresolved_alias_is_uncertain() {
        let r = sim(vec![
            rule(json!({"source_net": "mystery", "action": "block"})),
            rule(json!({"action": "pass"})),
        ]);
        assert_eq!(r.verdict, "pass");
        assert_eq!(r.certainty, "uncertain");
        assert_eq!(r.matched_rules[0].r#match, MatchKind::Possible);
    }

    #[test]
    fn alias_through_live_table() {
        let mut member = ctx();
        member
            .alias_membership
            .insert(packet().source, HashSet::from(["trusted".to_string()]));
        member.known_aliases.insert("trusted".into());
        let r = simulate(
            &[rule(json!({"source_net": "trusted"}))],
            &packet(),
            &member,
        );
        assert_eq!(
            (r.certainty.as_str(), r.verdict.as_str()),
            ("definite", "pass")
        );

        let mut not_member = ctx();
        not_member
            .alias_membership
            .insert(packet().source, HashSet::new());
        not_member.known_aliases.insert("trusted".into());
        assert_eq!(
            simulate(
                &[rule(json!({"source_net": "trusted"}))],
                &packet(),
                &not_member
            )
            .verdict,
            "none"
        );
    }

    #[test]
    fn staged_alias_definition_wins_over_live_table() {
        let mut c = ctx();
        c.defined_aliases = Some(HashMap::from([(
            "blocked".to_string(),
            vec!["192.168.1.0/24".to_string()],
        )]));
        assert_eq!(
            simulate(
                &[rule(json!({"source_net": "blocked", "action": "block"}))],
                &packet(),
                &c
            )
            .verdict,
            "block"
        );
    }

    #[test]
    fn schedule_is_uncertain() {
        let r = sim(vec![
            rule(json!({"sched": "office", "action": "block"})),
            rule(json!({"action": "pass"})),
        ]);
        assert_eq!(r.certainty, "uncertain");
        assert!(r.matched_rules[0]
            .reason
            .as_deref()
            .unwrap()
            .contains("schedule"));
    }

    #[test]
    fn possible_match_that_changes_nothing_stays_definite() {
        let r = sim(vec![
            rule(json!({"source_net": "mystery", "action": "pass"})),
            rule(json!({"action": "pass"})),
        ]);
        assert_eq!(r.certainty, "definite");
    }

    #[test]
    fn legacy_floating_rule_is_not_quick() {
        assert!(!is_quick(&rule(json!({"quick": "", "floating": "yes"}))));
        assert!(is_quick(&rule(json!({"quick": "", "floating": "no"}))));
        assert!(is_quick(&rule(json!({"quick": ""}))));
    }

    #[test]
    fn ruleset_is_built_from_raw_rows() {
        let o = |v: Value| v.as_object().unwrap().clone();
        let ifaces = [
            o(
                json!({"identifier": "lan", "device": "igb1", "description": "LAN", "addr4": "192.168.1.1/24", "ipv6": [{"ipaddr": "fe80::1%igb1/64"}]}),
            ),
            o(
                json!({"identifier": "", "device": "wg0", "description": "wg", "addr4": "10.9.0.1/24"}),
            ),
        ];
        let aliases = [
            o(
                json!({"name": "Hosts", "type": "host", "content": "10.0.0.1\n10.0.0.2", "enabled": "0"}),
            ),
            o(json!({"name": "Web", "type": "port", "content": "80,443"})),
        ];
        let groups = [o(json!({"ifname": "Internal", "members": "lan, opt1"}))];
        let rs = build_ruleset(
            vec![],
            &ifaces,
            &aliases,
            &groups,
            &json!(["Bogons"]),
            false,
            vec![],
        );
        assert_eq!(
            rs.context.interfaces[0].addresses,
            vec!["192.168.1.1/24", "fe80::1/64"]
        );
        assert_eq!(rs.context.unassigned[0].device, "wg0");
        assert_eq!(
            rs.context.defined_aliases.as_ref().unwrap()["hosts"],
            Vec::<String>::new()
        );
        assert_eq!(rs.context.port_aliases["web"], vec!["80", "443"]);
        assert!(rs.context.known_aliases.contains("bogons"));
        assert_eq!(rs.context.groups["internal"], vec!["lan", "opt1"]);
        assert!(!rs.complete);
        assert_eq!(rs.warnings.len(), 1);
    }

    #[test]
    fn port_forward_on_api_port_is_found() {
        let row = json!({"interface": "lan", "protocol": "tcp", "source.network": "any", "destination.network": "8.8.8.8", "destination.port": "443", "target": "10.0.0.5"});
        let rows = [row.as_object().unwrap().clone()];
        let rs = build_ruleset(vec![], &[], &[], &[], &json!([]), false, vec![]);
        let f = find_forward_in(
            &rows,
            &Ruleset {
                context: ctx(),
                ..rs
            },
            &packet(),
        )
        .unwrap();
        assert!(f.definite);
    }
}

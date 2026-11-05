//! Politique d'accès, appliquée par le client HTTP pour qu'aucun outil ne puisse la contourner.
//!
//! Le verbe HTTP ne prouve rien sur OPNsense : certains GET modifient l'état et beaucoup de POST
//! ne font que lire. L'accès se décide donc d'après le nom de la commande, sous forme canonique
//! (le routeur d'OPNsense accepte `core/system/re_boot` comme `core/system/reboot`), et une
//! commande inconnue compte comme une écriture : la politique échoue côté sûr.

use crate::error::{ErrorType, OpnError, Result};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
}

#[derive(Clone, Debug)]
pub struct Decision {
    pub access: Access,
    /// La réponse peut contenir des secrets que la rédaction par nom de clé ne voit pas.
    pub sensitive: bool,
    pub blocked: Option<String>,
}

impl Decision {
    fn new(access: Access, sensitive: bool) -> Self {
        Self { access, sensitive, blocked: None }
    }
    fn blocked(access: Access, reason: String) -> Self {
        Self { access, sensitive: false, blocked: Some(reason) }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct AuthorizeOptions {
    /// Posé par les outils qui rédigent eux-mêmes une réponse sensible (téléchargement de config).
    pub redacted_by_caller: bool,
    /// Posé par les outils dédiés, par opposition à opn_api_read / opn_api_write.
    pub curated: bool,
    /// Posé pour les outils annoncés en lecture seule : tout ce qui n'est pas prouvé lecture est refusé.
    pub read_only: bool,
}

static SAFE_SEGMENT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.,:-]+$").unwrap());
static ALL_DOTS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\.+$").unwrap());
static READ_PREFIX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(get|search|list|show|query|find|count|dump|status|stats|statistics|view)").unwrap());
static SENSITIVE_COMMAND: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(download|export|rawdump|generatefile|keypair|genkeypair|psk|genkey|newotpseed)").unwrap());

pub fn canonical_segment(segment: &str) -> String {
    segment.to_lowercase().replace('_', "")
}

/// Refuse tout ce qui pourrait faire sortir la requête du point d'accès voulu.
pub fn assert_safe_path(path: &str) -> Result<Vec<&str>> {
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 3 {
        return Err(OpnError::new(ErrorType::InvalidPath, format!("\"{path}\" is not an API path: expected module/controller/command.")));
    }
    for segment in &segments {
        if !SAFE_SEGMENT.is_match(segment) || ALL_DOTS.is_match(segment) {
            return Err(OpnError::new(ErrorType::InvalidPath, format!("Invalid path segment \"{segment}\" in \"{path}\".")).hint("Path segments may only contain letters, digits and _ . , : -"));
        }
    }
    Ok(segments)
}

pub fn canonical_path(path: &str) -> String {
    path.split('/').take(3).map(canonical_segment).collect::<Vec<_>>().join("/")
}

fn canon(paths: &[&'static str]) -> HashMap<String, &'static str> {
    paths.iter().map(|p| (canonical_path(p), *p)).collect()
}

/// Jamais joignable, quel que soit l'outil, sauf si l'opérateur le liste dans OPNSENSE_UNBLOCK.
static BLOCKED: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| {
    canon(&[
        // Arrêt et mises à jour : le pare-feu tomberait avec la session qui l'a demandé.
        "core/system/halt",
        "core/system/reboot",
        "core/firmware/poweroff",
        "core/firmware/reboot",
        "core/firmware/update",
        "core/firmware/upgrade",
        "core/firmware/install",
        "core/firmware/reinstall",
        "core/firmware/remove",
        "core/firmware/lock",
        "core/firmware/unlock",
        "core/firmware/resync_plugins",
        "core/firmware/sync_plugins",
        "core/firmware/set",
        // Retour aux réglages d'usine et environnements de démarrage.
        "core/defaults/factory_defaults",
        "core/defaults/reset",
        "core/snapshots/activate",
        "core/snapshots/del",
        // Comptes et clés d'API : un agent ne doit pas pouvoir s'octroyer des droits.
        "auth/user/add",
        "auth/user/del",
        "auth/user/set",
        "auth/user/upload",
        "auth/user/download",
        "auth/user/add_api_key",
        "auth/user/del_api_key",
        "auth/user/new_otp_seed",
        "auth/group/add",
        "auth/group/del",
        "auth/group/set",
        "auth/priv/set",
        "auth/priv/set_item",
        // Une tâche planifiée peut lancer une action configd, y compris un redémarrage.
        "cron/settings/add_job",
        "cron/settings/set_job",
        "cron/settings/set",
        // Coupent d'un coup toutes les connexions qui traversent la machine.
        "diagnostics/firewall/flush_states",
        "diagnostics/firewall/flush_sources",
        // Son filtre perd "/" et ":" en route, et "." correspond à tout état IPv4 : opn_kill_states est la voie.
        "diagnostics/firewall/kill_states",
        // Supprime définitivement les anciennes règles.
        "firewall/migration/flush",
        "firewall/migration/flush_outbound",
        // Détruit l'historique sur lequel s'appuie le rollback.
        "core/backup/delete_backup",
        // Enregistre du trafic réseau à la demande.
        "diagnostics/packet_capture/set",
        "diagnostics/packet_capture/start",
        "diagnostics/packet_capture/download",
        "diagnostics/packet_capture/view",
    ])
});

/// Joignable seulement par un outil dédié qui ajoute ses propres garde-fous, jamais par les outils génériques.
static CURATED_ONLY: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| {
    canon(&[
        "core/backup/revert_backup",
        // Lignes de config.xml, secrets compris, que la rédaction par clé ne voit pas.
        "core/backup/diff",
    ])
});

/// Points POST qui ne touchent pas à la configuration.
static READ_ONLY_POSTS: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| {
    canon(&[
        // Ces modèles sont montés ":memory:" sur le pare-feu : rien n'est écrit dans config.xml.
        "diagnostics/ping/set",
        "diagnostics/ping/start",
        "diagnostics/ping/stop",
        "diagnostics/ping/remove",
        "diagnostics/traceroute/set",
        "diagnostics/dns_diagnostics/set",
        "diagnostics/portprobe/set",
        "firewall/alias_util/find_references",
        "unbound/diagnostics/test_blocklist",
        "core/firmware/changelog",
        "core/firmware/details",
        "core/firmware/license",
    ])
});

/// Commandes entières qui ne font que lire, tirées d'un audit du catalogue d'API.
static READ_COMMANDS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "accesses", "accounts", "aliases", "backups", "bfdcounters", "bfdneighbors", "bfdstaticroute", "bfdsummary",
        "bgpneighbors", "bgpsummary", "cachestats", "caddyfile", "cainfo", "calist", "certdiff", "checkclamav", "checkredis",
        "chronyauthdata", "chronysources", "chronysourcestats", "chronytracking", "circuits", "config", "configtest",
        "connectionexists", "counters", "daily", "diff", "dirty", "errors", "generalrunningconfig", "gps", "hourly", "index", "info",
        "interface", "interfacelist", "interfacesinfo", "ip", "isblocklistenabled", "isenabled", "issupported", "logfilters",
        "macinfo", "memory", "meta", "monthly", "neighbor", "net", "ospfdatabase", "ospfinterface", "ospfoverview",
        "ospfv3interface", "ospfv3overview", "pending", "pfstates", "pfstatistics", "picture", "pools", "powerstatus",
        "productinfofeed", "providers", "remoteservice", "report", "reverselookup", "rolling", "rulestats", "running",
        "services", "streams", "sum", "swanctl", "systemdisk", "systeminformation", "systemmbuf", "systemresources",
        "systemswap", "systemtemperature", "systemtime", "tables", "templates", "testconfig", "timeserie", "tlshandshakes",
        "top", "totals", "tree", "upgradestatus", "upsstatus", "userlist", "version", "vts", "yearly", "zones", "zoneshow",
        "zonetest",
    ]
    .into_iter()
    .collect()
});

/// Chemins dont la commande est ambiguë seule : core/firmware/log prend un paramètre "clear".
static READ_PATHS: LazyLock<HashMap<String, &'static str>> = LazyLock::new(|| canon(&["diagnostics/firewall/log"]));

fn explain_blocked(path: &str) -> String {
    format!("{path} is blocked: it can take the firewall down, grant access or destroy recovery data.")
}

pub fn decide(path: &str, method_is_get: bool, unblocked: &[String], curated: bool) -> Decision {
    let canonical = canonical_path(path);
    let mut parts = canonical.split('/');
    let module = parts.next().unwrap_or("");
    let controller = parts.next().unwrap_or("");
    let command = parts.next().unwrap_or("");

    let unblocked_set: HashSet<String> = unblocked.iter().map(|p| canonical_path(p)).collect();
    if let Some(original) = BLOCKED.get(&canonical) {
        if !unblocked_set.contains(&canonical) {
            return Decision::blocked(Access::Write, explain_blocked(original));
        }
    }
    if let Some(original) = CURATED_ONLY.get(&canonical) {
        if !curated && !unblocked_set.contains(&canonical) {
            return Decision::blocked(Access::Write, format!("{original} is only available through its dedicated tool."));
        }
    }
    // Les flux d'évènements ne finissent jamais : l'appel resterait suspendu jusqu'au délai.
    if command.starts_with("stream") {
        return Decision::blocked(Access::Read, format!("{path} is a live event stream, which tool calls cannot consume."));
    }

    // Les lectures de journaux sont des POST à portée dynamique : diagnostics/log/<module>/<scope>[/clear|export|live].
    if module == "diagnostics" && controller == "log" {
        let action = path.split('/').nth(4).map(str::to_lowercase);
        match action.as_deref() {
            Some("clear") => return Decision::blocked(Access::Write, "Clearing logs is blocked: it destroys evidence.".into()),
            Some("live") => return Decision::blocked(Access::Read, "Live log streams cannot be consumed by a tool call.".into()),
            _ => return Decision::new(Access::Read, false),
        }
    }

    let sensitive = SENSITIVE_COMMAND.is_match(command);
    if READ_ONLY_POSTS.contains_key(&canonical) || READ_PATHS.contains_key(&canonical) {
        return Decision::new(Access::Read, sensitive);
    }
    if sensitive && method_is_get {
        return Decision::new(Access::Read, sensitive);
    }
    if READ_PREFIX.is_match(command) || READ_COMMANDS.contains(command) {
        return Decision::new(Access::Read, sensitive);
    }
    Decision::new(Access::Write, sensitive)
}

/// Ce que la politique doit savoir de l'instance.
pub struct PolicySubject<'a> {
    pub name: &'a str,
    pub allow_writes: bool,
    pub allow_sensitive: bool,
    pub dry_run: bool,
}

/// Échoue sauf si l'appel est permis. Renvoie la décision pour le journal et le mode simulation.
pub fn authorize(subject: &PolicySubject, path: &str, method_is_get: bool, unblocked: &[String], opts: AuthorizeOptions) -> Result<Decision> {
    assert_safe_path(path)?;
    let decision = decide(path, method_is_get, unblocked, opts.curated);
    if let Some(reason) = &decision.blocked {
        return Err(OpnError::new(ErrorType::BlockedEndpoint, reason.clone()).hint("Do not retry. A human can do this in the OPNsense web interface, or the operator can list the endpoint in OPNSENSE_UNBLOCK."));
    }
    if opts.read_only && decision.access == Access::Write {
        return Err(OpnError::new(ErrorType::NotReadOnly, format!("{path} is not known to be read-only, so a read tool refuses it: nothing was sent."))
            .hint("If it does change something, opn_api_write is the tool for it, provided writes are enabled. If it only reads and this classification is wrong, a human can check it in the web interface."));
    }
    if decision.access == Access::Write && !subject.allow_writes && !subject.dry_run {
        return Err(OpnError::new(ErrorType::WriteDisabled, format!("Instance \"{}\" is read-only: {path} was not sent.", subject.name))
            .hint("Do not retry. The operator can enable writes with OPNSENSE_ALLOW_WRITES=true (or allow_writes on the instance), or preview with OPNSENSE_DRY_RUN=true."));
    }
    if decision.sensitive && !subject.allow_sensitive && !opts.redacted_by_caller {
        return Err(OpnError::new(ErrorType::SensitiveDisabled, format!("{path} can return key material or raw exports, which are off by default."))
            .hint("Do not retry. The operator can allow it with OPNSENSE_ALLOW_SENSITIVE=true. To read the configuration, use opn_get_config_section, which redacts secrets."));
    }
    Ok(decision)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocklist_resists_case_and_underscore() {
        for p in ["core/system/re_boot", "core/system/REBOOT", "core/system/Reboot"] {
            assert!(decide(p, false, &[], true).blocked.is_some(), "{p}");
        }
    }

    #[test]
    fn unknown_command_is_a_write() {
        assert_eq!(decide("foo/bar/doSomething", false, &[], false).access, Access::Write);
        assert_eq!(decide("firewall/filter/search_rule", false, &[], false).access, Access::Read);
    }

    #[test]
    fn carp_status_is_not_a_read() {
        assert_eq!(decide("diagnostics/interface/carp_status", false, &[], false).access, Access::Write);
    }

    #[test]
    fn unblock_lifts_the_block() {
        let unblocked = vec!["core/firmware/update".to_string()];
        assert!(decide("core/firmware/update", false, &unblocked, false).blocked.is_none());
    }

    #[test]
    fn traversal_is_refused() {
        assert!(assert_safe_path("core/../system/halt").is_err());
        assert!(assert_safe_path("core/system").is_err());
    }

    #[test]
    fn curated_only_needs_a_dedicated_tool() {
        assert!(decide("core/backup/revert_backup", false, &[], false).blocked.is_some());
        assert!(decide("core/backup/revert_backup", false, &[], true).blocked.is_none());
    }
}

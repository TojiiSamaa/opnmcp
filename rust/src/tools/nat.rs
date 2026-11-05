//! Outils du domaine nat : redirections de port, NAT sortant, 1:1 et NPTv6.
#![allow(clippy::result_large_err)] // OpnError est l'erreur commune du crate

use crate::changes::ChangeScope;
use crate::model::{compact_grid, flatten_model, model_fields, search_grid, Obj};
use crate::schema::{self, Field};
use crate::tool::{crud_tools, paging, read_tool, Commands, CrudSpec, Ctx, Domain, ToolDef};
use serde_json::{json, Value};
use std::sync::Arc;

const ADDRESS_HELP: &str =
    "any, an address, a CIDR, an alias name, an interface network (lan) or address (wanip).";

/// Les modes où le pare-feu charge les règles sortantes manuelles.
const MANUAL_OUTBOUND_MODES: [&str; 2] = ["hybrid", "advanced"];

/// Le modèle de NAT de destination imbrique source et destination, et ses champs diffèrent de ceux du filtre
/// (target, local-port, descr, un « disabled » inversé), ce qui est facile à mal faire.
fn port_forward_fields() -> Vec<Field> {
    vec![
        schema::string("interface").opt().desc("Interface the traffic arrives on, usually wan. Comma-separated for several."),
        schema::enumeration("ip_protocol", &["inet", "inet6"]).opt().desc("inet = IPv4, inet6 = IPv6."),
        schema::string("protocol").opt().desc("TCP, UDP, TCP/UDP..."),
        schema::string("source_net").opt().desc(&format!("Who may connect: {ADDRESS_HELP} Leaving it open exposes the service to everyone.")),
        schema::string("source_port").opt().desc("Source port. Rarely needed."),
        schema::boolean("source_not").opt().desc("Invert the source match."),
        schema::string("destination_net").opt().desc(&format!("Address the traffic is sent to: {ADDRESS_HELP} Usually wanip.")),
        schema::string("destination_port").opt().desc("Public port or range."),
        schema::boolean("destination_not").opt().desc("Invert the destination match."),
        schema::string("target").opt().desc("Internal address or alias to forward to."),
        schema::string("target_port").opt().desc("Internal port. Default: the same as destination_port."),
        schema::string("description").opt().desc("Free-text description."),
        schema::boolean("enabled").opt().desc("Default true on creation."),
        schema::boolean("log").opt().desc("Log matching packets."),
        schema::enumeration("pass", &["", "pass", "rule"]).opt().desc("Filter rule association: \"\" = manual, you add the rule yourself; pass = pass matching traffic directly; rule = register a linked filter rule."),
        schema::enumeration("natreflection", &["", "purenat", "disable"]).opt().desc("NAT reflection for internal clients. \"\" = system default, purenat = enable."),
    ]
}

/// Sous-objet {network, port, not} de la source ou de la destination, absent s'il est vide.
fn nested(input: &Obj, net: &str, port: &str, not: &str) -> Option<Value> {
    let probe: Obj = [("network", net), ("port", port), ("not", not)]
        .into_iter()
        .filter_map(|(out, key)| input.get(key).map(|v| (out.to_string(), v.clone())))
        .collect();
    let out = model_fields(&probe);
    (!out.is_empty()).then_some(Value::Object(out))
}

fn to_port_forward_model(args: &Obj) -> Obj {
    let renamed = [
        ("ip_protocol", "ipprotocol"),
        ("target_port", "local-port"),
        ("description", "descr"),
    ];
    let consumed = [
        "source_net",
        "source_port",
        "source_not",
        "destination_net",
        "destination_port",
        "destination_not",
        "enabled",
    ];
    let mut plain = Obj::new();
    for (k, v) in args {
        if consumed.contains(&k.as_str()) {
            continue;
        }
        let name = renamed
            .iter()
            .find(|(from, _)| from == k)
            .map_or(k.as_str(), |(_, to)| *to);
        plain.insert(name.to_string(), v.clone());
    }
    if let Some(Value::Bool(enabled)) = args.get("enabled") {
        plain.insert("disabled".into(), json!(!enabled));
    }
    let mut out = model_fields(&plain);
    if let Some(source) = nested(args, "source_net", "source_port", "source_not") {
        out.insert("source".into(), source);
    }
    if let Some(destination) = nested(
        args,
        "destination_net",
        "destination_port",
        "destination_not",
    ) {
        out.insert("destination".into(), destination);
    }
    out
}

fn outbound_fields() -> Vec<Field> {
    vec![
        schema::string("interface")
            .opt()
            .desc("Outgoing interface, usually wan."),
        schema::enumeration("ip_protocol", &["inet", "inet6"])
            .opt()
            .desc("inet = IPv4, inet6 = IPv6."),
        schema::string("protocol").opt().desc("any, TCP, UDP..."),
        schema::string("source_net")
            .opt()
            .desc(&format!("Internal source: {ADDRESS_HELP}")),
        schema::boolean("source_not")
            .opt()
            .desc("Invert the source match."),
        schema::string("source_port").opt().desc("Source port."),
        schema::string("destination_net")
            .opt()
            .desc(&format!("Destination: {ADDRESS_HELP}")),
        schema::boolean("destination_not")
            .opt()
            .desc("Invert the destination match."),
        schema::string("destination_port")
            .opt()
            .desc("Destination port."),
        schema::string("target")
            .opt()
            .desc("Address to translate to, for example wanip."),
        schema::string("target_port")
            .opt()
            .desc("Port to translate to."),
        schema::boolean("nonat")
            .opt()
            .desc("Exempt this traffic from NAT."),
        schema::boolean("staticnatport")
            .opt()
            .desc("Keep the source port."),
        schema::boolean("log").opt().desc("Log matching packets."),
        schema::string("description")
            .opt()
            .desc("Free-text description."),
        schema::boolean("enabled")
            .opt()
            .desc("Default true on creation."),
    ]
}

fn to_outbound_model(args: &Obj) -> Obj {
    let renamed: Obj = args
        .iter()
        .map(|(k, v)| {
            (
                if k == "ip_protocol" {
                    "ipprotocol".to_string()
                } else {
                    k.clone()
                },
                v.clone(),
            )
        })
        .collect();
    model_fields(&renamed)
}

async fn read_outbound_mode(ctx: &Ctx) -> crate::error::Result<String> {
    let res = flatten_model(&ctx.api.get_("firewall/source_nat/get").await?);
    let mode = res.pointer("/filter/settings/nat/snat_mode");
    Ok(match mode {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(other) => other.to_string(),
    })
}

fn manual_rules_active(mode: &str) -> bool {
    MANUAL_OUTBOUND_MODES.contains(&mode)
}

pub fn tools() -> Vec<ToolDef> {
    let mut defs = Vec::new();

    let mut dnat = CrudSpec::new(
        Domain::Nat,
        "nat_rule",
        "nat_rules",
        "port forward (destination NAT) rule",
        "firewall/d_nat",
        "rule",
        Commands {
            search: "search_rule",
            get: "get_rule",
            add: Some("add_rule"),
            set: Some("set_rule"),
            del: Some("del_rule"),
            toggle: Some("toggle_rule"),
        },
    );
    dnat.fields = port_forward_fields();
    dnat.required = vec!["interface", "protocol", "destination_port", "target"];
    dnat.to_model = Some(Arc::new(to_port_forward_model));
    dnat.inverted_toggle = true;
    dnat.staged = Some(ChangeScope::Nat);
    dnat.list_note = Some("Automatic rules have is_automatic=true.");
    dnat.write_note = Some("Staged: nothing changes until opn_apply_firewall_changes. A forward also needs traffic to be passed: use the pass field or add a filter rule.");
    defs.extend(crud_tools(dnat));

    let mut snat = CrudSpec::new(
        Domain::Nat,
        "outbound_nat_rule",
        "outbound_nat_rules",
        "outbound (source NAT) rule",
        "firewall/source_nat",
        "rule",
        Commands {
            search: "search_rule",
            get: "get_rule",
            add: Some("add_rule"),
            set: Some("set_rule"),
            del: Some("del_rule"),
            toggle: Some("toggle_rule"),
        },
    );
    snat.fields = outbound_fields();
    snat.required = vec!["interface"];
    snat.to_model = Some(Arc::new(to_outbound_model));
    // Même modèle que les règles de filtre : le point de sauvegarde natif le couvre.
    snat.staged = Some(ChangeScope::Filter);
    snat.list_note = Some(
        "Manual rules only take effect in hybrid or advanced mode: see opn_get_outbound_nat_mode.",
    );
    snat.warn_on_write = Some(Arc::new(|ctx| {
        Box::pin(async move {
            // Les pare-feu anciens n'ont pas ce point d'accès : se taire plutôt que faire échouer une écriture réussie.
            let mode = read_outbound_mode(&ctx).await.unwrap_or_default();
            if mode.is_empty() || manual_rules_active(&mode) {
                return Ok(None);
            }
            Ok(Some(format!("Outbound NAT is in {mode} mode, where manual rules are not loaded: this rule has no effect until the mode is hybrid or advanced.")))
        })
    }));
    defs.extend(crud_tools(snat));

    defs.push(
        read_tool(
            "opn_get_outbound_nat_mode",
            "Outbound NAT mode",
            "How outbound NAT is generated: automatic, hybrid, advanced (manual) or disabled. Manual rules only take effect in hybrid and advanced mode. Not available on older versions.",
            Domain::Nat,
        )
        .run(|_args, ctx| async move {
            let mode = read_outbound_mode(&ctx).await?;
            Ok(if mode.is_empty() { json!({ "mode": null, "manual_rules_active": null }) } else { json!({ "mode": mode, "manual_rules_active": manual_rules_active(&mode) }) })
        }),
    );
    defs.push(
        read_tool(
            "opn_list_one_to_one_nat_rules",
            "List 1:1 NAT rules",
            "List 1:1 NAT rules. To change one, see opn_search_api and opn_api_write.",
            Domain::Nat,
        )
        .input(paging())
        .run(|args, ctx| async move {
            Ok(compact_grid(
                &search_grid(&ctx.api, "firewall/one_to_one/search_rule", &args.grid()).await?,
            ))
        }),
    );
    defs.push(
        read_tool("opn_list_npt_rules", "List NPTv6 rules", "List NPTv6 (IPv6 prefix translation) rules. To change one, see opn_search_api and opn_api_write.", Domain::Nat)
            .input(paging())
            .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "firewall/npt/search_rule", &args.grid()).await?)) }),
    );
    defs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obj(v: Value) -> Obj {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn port_forward_model_nests_and_renames() {
        let m = to_port_forward_model(&obj(json!({
            "interface": "wan", "protocol": "TCP", "ip_protocol": "inet", "destination_net": "wanip", "destination_port": "443",
            "target": "10.0.0.5", "target_port": "8443", "description": "web", "enabled": true, "source_not": true
        })));
        assert_eq!(m["ipprotocol"], "inet");
        assert_eq!(m["local-port"], "8443");
        assert_eq!(m["descr"], "web");
        assert_eq!(m["disabled"], "0");
        assert_eq!(
            m["destination"],
            json!({ "network": "wanip", "port": "443" })
        );
        assert_eq!(m["source"], json!({ "not": "1" }));
        assert!(m.get("target_port").is_none() && m.get("enabled").is_none());
        assert_eq!(
            to_port_forward_model(&obj(json!({ "enabled": false })))["disabled"],
            "1"
        );
        assert!(to_port_forward_model(&obj(json!({ "target": "x" })))
            .get("source")
            .is_none());
    }

    #[test]
    fn outbound_model_renames_protocol_family_and_stringifies() {
        let m = to_outbound_model(&obj(
            json!({ "ip_protocol": "inet6", "nonat": true, "interface": "wan" }),
        ));
        assert_eq!(
            Value::Object(m),
            json!({ "ipprotocol": "inet6", "nonat": "1", "interface": "wan" })
        );
    }

    #[test]
    fn manual_rules_modes() {
        assert!(manual_rules_active("hybrid") && manual_rules_active("advanced"));
        assert!(!manual_rules_active("automatic") && !manual_rules_active("disabled"));
    }

    #[test]
    fn nat_rule_tools_follow_inverted_staged_spec() {
        let t = tools();
        let names: Vec<&str> = t.iter().map(|d| d.name.as_str()).collect();
        for n in [
            "opn_add_nat_rule",
            "opn_toggle_nat_rule",
            "opn_delete_outbound_nat_rule",
            "opn_get_outbound_nat_mode",
            "opn_list_npt_rules",
        ] {
            assert!(names.contains(&n), "missing {n}");
        }
        let add = t.iter().find(|d| d.name == "opn_add_nat_rule").unwrap();
        assert_eq!(
            add.input.to_json_schema()["required"],
            json!(["interface", "protocol", "destination_port", "target"])
        );
    }
}

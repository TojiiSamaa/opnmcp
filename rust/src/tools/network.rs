//! Outils du domaine network.

use super::system::{all_src, js_str, pick, rows_of};
use crate::model::{compact_grid, model_fields, paginate_array, search_grid, Obj};
use crate::schema;
use crate::tool::{crud_tools, paging, read_tool, sparse, Commands, CrudSpec, Domain, ToolDef};
use serde_json::{json, Value};
use std::sync::Arc;

const INTERFACE_FIELDS: [&str; 16] = [
    "identifier", "device", "description", "status", "enabled", "link_type", "link_typev6", "addr4", "addr6", "ipv4", "ipv6", "macaddr", "mtu", "vlan_tag", "gateways", "routes",
];

/// Ce modèle appelle la description « descr ».
fn route_model(args: &Obj) -> Obj {
    let mut rest = args.clone();
    if let Some(d) = rest.shift_remove("description") {
        rest.insert("descr".into(), d);
    }
    model_fields(&rest)
}

/// Les lignes de la table de routage, filtrées par le texte cherché (sans tenir compte de la casse).
fn filter_routes(rows: Vec<Value>, search: Option<&str>) -> Vec<Value> {
    match search.map(str::to_lowercase).filter(|q| !q.is_empty()) {
        Some(q) => rows.into_iter().filter(|r| r.to_string().to_lowercase().contains(&q)).collect(),
        None => rows,
    }
}

fn ipv6_summary(rows: &[Value]) -> Value {
    let interfaces: Vec<Value> = rows
        .iter()
        .filter(|r| r.get("identifier").is_some_and(|v| !matches!(v, Value::Null | Value::Bool(false)) && v.as_str() != Some("")))
        .map(|r| {
            let method = r.get("link_typev6").filter(|v| !v.is_null()).cloned().unwrap_or_else(|| json!("none"));
            let mut m = pick(r, &["identifier", "description"]);
            m["method"] = method;
            if let Some(v) = r.get("addr6") {
                m["address"] = v.clone();
            }
            if let Some(v) = r.get("ipv6") {
                m["addresses"] = v.clone();
            }
            sparse(&m)
        })
        .collect();
    let with_ipv6 = interfaces.iter().filter(|i| i.get("method").is_some_and(|m| js_str(Some(m)) != "none")).count();
    json!({ "interfaces": interfaces, "summary": { "total": interfaces.len(), "with_ipv6": with_ipv6, "without_ipv6": interfaces.len() - with_ipv6 } })
}

pub fn tools() -> Vec<ToolDef> {
    let mut defs = vec![
        read_tool(
            "opn_list_interfaces",
            "List interfaces",
            "All interfaces, mapping configuration ids (opt2) to devices (vlan0.30) and names (DMZ), with state, addresses, gateways and VLAN tag. Call this first when a question spans several tools: rules use ids, logs and states use devices or names.",
            Domain::Network,
        )
        .input(paging())
        .run(|args, ctx| async move {
            let grid = search_grid(&ctx.api, "interfaces/overview/interfaces_info", &args.grid()).await?;
            Ok(crate::model::GridResult { rows: grid.rows.iter().map(|r| sparse(&pick(r, &INTERFACE_FIELDS))).collect(), ..grid }.to_value())
        }),
        read_tool("opn_get_interface", "Get interface details", "Every detail the firewall has about one interface, by device name (from opn_list_interfaces).", Domain::Network)
            .input(vec![schema::string("device").regex(r"^[A-Za-z0-9_.:-]+$", "Invalid").desc("Device name, such as igb0 or vlan0.30.")])
            .run(|args, ctx| async move { ctx.api.get("interfaces/overview/get_interface", crate::client::RequestOptions::new().param(args.req("device"))).await }),
        read_tool("opn_interface_stats", "Interface statistics", "Traffic and error counters per interface, since the interface came up.", Domain::Network)
            .run(|_args, ctx| async move { ctx.api.get_("diagnostics/interface/get_interface_statistics").await }),
        read_tool(
            "opn_arp_table",
            "ARP table",
            "IPv4 neighbors: which MAC address and hostname holds which address, on which interface. Search by address, MAC or name.",
            Domain::Network,
        )
        .input(paging())
        .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "diagnostics/interface/search_arp", &args.grid()).await?)) }),
        read_tool("opn_ndp_table", "NDP table", "IPv6 neighbors: which MAC address holds which address, on which interface. Search by address or MAC.", Domain::Network)
            .input(paging())
            .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "diagnostics/interface/search_ndp", &args.grid()).await?)) }),
        read_tool(
            "opn_routing_table",
            "Routing table",
            "The kernel routing table, as it is now: connected, static and dynamic routes. For what is configured, see opn_list_static_routes.",
            Domain::Network,
        )
        .input(paging())
        .run(|args, ctx| async move {
            let res = ctx.api.get_("diagnostics/interface/get_routes").await?;
            let rows = match &res {
                Value::Array(a) => a.clone(),
                other => rows_of(other.get("rows")),
            };
            Ok(paginate_array(&filter_routes(rows, args.str("search")), args.i64("limit"), args.i64("offset")).to_value())
        }),
        read_tool(
            "opn_ipv6_status",
            "IPv6 status",
            "IPv6 per interface: how it is configured (static, dhcp6, slaac, track6) and the addresses in use.",
            Domain::Network,
        )
        .run(|_args, ctx| async move {
            let rows = all_src(&ctx.api, "interfaces/overview/interfaces_info").await?;
            Ok(ipv6_summary(&rows_of(Some(&rows))))
        }),
        read_tool("opn_list_gateways", "List configured gateways", "Gateways as configured: interface, address, monitoring. For their live state, see opn_gateway_status.", Domain::Network)
            .input(paging())
            .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "routing/settings/search_gateway", &args.grid()).await?)) }),
        read_tool("opn_list_vlans", "List VLANs", "Configured VLAN devices, with parent interface and tag.", Domain::Network)
            .input(paging())
            .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "interfaces/vlan_settings/search_item", &args.grid()).await?)) }),
        read_tool(
            "opn_list_virtual_ips",
            "List virtual IPs",
            "Configured virtual IPs (CARP, IP alias, proxy ARP). For the CARP state, see opn_api_read with diagnostics/interface/get_vip_status.",
            Domain::Network,
        )
        .input(paging())
        .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "interfaces/vip_settings/search_item", &args.grid()).await?)) }),
    ];
    let mut routes = CrudSpec::new(
        Domain::Network,
        "static_route",
        "static_routes",
        "static route",
        "routes/routes",
        "route",
        Commands { search: "searchroute", get: "getroute", add: Some("addroute"), set: Some("setroute"), del: Some("delroute"), toggle: Some("toggleroute") },
    );
    routes.fields = vec![
        schema::string("network").opt().desc("Destination network, in CIDR form."),
        schema::string("gateway").opt().desc("Gateway name, from opn_list_gateways."),
        schema::string("description").opt().desc("Free-text description."),
        schema::boolean("enabled").opt().desc("Default true on creation."),
    ];
    routes.required = vec!["network", "gateway"];
    routes.to_model = Some(Arc::new(route_model));
    routes.reconfigure = vec!["routes/routes/reconfigure"];
    routes.write_note = Some("Takes effect on reconfigure, with no rollback timer. A wrong route can cut access to the firewall.");
    defs.extend(crud_tools(routes));
    defs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_access_and_domains() {
        let d = tools();
        let names: Vec<&str> = d.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(&names[..10], ["opn_list_interfaces", "opn_get_interface", "opn_interface_stats", "opn_arp_table", "opn_ndp_table", "opn_routing_table", "opn_ipv6_status", "opn_list_gateways", "opn_list_vlans", "opn_list_virtual_ips"]);
        assert!(names.contains(&"opn_add_static_route") && names.contains(&"opn_toggle_static_route") && names.contains(&"opn_delete_static_route"));
        assert!(d.iter().all(|t| t.domain == Domain::Network));
        let add = d.iter().find(|t| t.name == "opn_add_static_route").unwrap();
        assert!(add.input.validate(&json!({ "network": "10.0.0.0/8" })).is_err());
        assert!(add.input.validate(&json!({ "network": "10.0.0.0/8", "gateway": "WAN_GW" })).is_ok());
    }

    #[test]
    fn route_model_renames_description() {
        let args = json!({ "network": "10.0.0.0/8", "description": "lab", "enabled": true });
        let m = route_model(args.as_object().unwrap());
        assert_eq!(Value::Object(m), json!({ "network": "10.0.0.0/8", "descr": "lab", "enabled": "1" }));
    }

    #[test]
    fn routing_table_search_ignores_case() {
        let rows = vec![json!({ "destination": "10.0.0.0/8", "netif": "LAN" }), json!({ "destination": "default", "netif": "wan" })];
        assert_eq!(filter_routes(rows.clone(), Some("lan")).len(), 1);
        assert_eq!(filter_routes(rows.clone(), Some("")).len(), 2);
        assert_eq!(filter_routes(rows, None).len(), 2);
    }

    #[test]
    fn ipv6_summary_counts_methods() {
        let rows = vec![
            json!({ "identifier": "wan", "link_typev6": "dhcp6", "addr6": "fe80::1" }),
            json!({ "identifier": "lan" }),
            json!({ "description": "no id" }),
        ];
        let out = ipv6_summary(&rows);
        assert_eq!(out["summary"], json!({ "total": 2, "with_ipv6": 1, "without_ipv6": 1 }));
        assert_eq!(out["interfaces"][1]["method"], "none");
    }
}

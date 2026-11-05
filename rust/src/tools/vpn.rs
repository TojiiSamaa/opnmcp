//! Outils du domaine vpn.

use super::system::{all_src, get_src, js_str, rows_of};
use crate::client::RequestOptions;
use crate::error::Result;
use crate::model::{compact_grid, fetch_all, search_grid, Obj, FETCH_ALL_MAX};
use crate::schema;
use crate::tool::{crud_tools, flip_to, gather, paging, read_tool, service_write, tool, Commands, CrudSpec, Domain, ToolAccess, ToolDef};
use serde_json::{json, Map, Value};

/// Une ligne de phase 1 sans nom est ignorée : `String(row.name ?? '')`.
fn phase1_names(rows: &[Value]) -> Vec<String> {
    rows.iter().filter_map(|r| r.get("name").filter(|v| !v.is_null())).map(|v| js_str(Some(v))).filter(|n| !n.is_empty()).collect()
}

pub fn tools() -> Vec<ToolDef> {
    let mut defs = vec![
        read_tool(
            "opn_wireguard_status",
            "WireGuard status",
            "WireGuard tunnels and peers as they run now: last handshake, endpoint and traffic. Needs os-wireguard on older firewalls.",
            Domain::Vpn,
        )
        .run(|_args, ctx| async move { ctx.api.get_("wireguard/service/show").await }),
        read_tool("opn_list_wireguard_servers", "List WireGuard instances", "Configured WireGuard instances (local tunnel ends). Private keys are redacted.", Domain::Vpn)
            .input(paging())
            .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "wireguard/server/search_server", &args.grid()).await?)) }),
        read_tool("opn_list_wireguard_peers", "List WireGuard peers", "Configured WireGuard peers. For whether they are connected, see opn_wireguard_status.", Domain::Vpn)
            .input(paging())
            .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "wireguard/client/search_client", &args.grid()).await?)) }),
        tool(
            "opn_toggle_wireguard_peer",
            "Enable or disable WireGuard peer",
            "Enables or disables one WireGuard peer, for example to cut off a lost device. Goes live right away, with no rollback timer. Disabling the peer this server connects through cuts its access.",
            Domain::Vpn,
            ToolAccess::Write,
        )
        .idempotent()
        .input(vec![
            schema::string("uuid").regex(r"^[0-9a-fA-F-]{36}$", "Expected a uuid").desc("Peer uuid, from opn_list_wireguard_peers."),
            schema::boolean("enabled").desc("The state wanted."),
        ])
        // set_client sans son champ servers détacherait le pair de toutes les instances : on utilise toggle_client, qui inverse.
        .run(|args, ctx| async move {
            let uuid = args.req("uuid").to_string();
            let write = ctx.api.post("wireguard/client/toggle_client", None, RequestOptions::new().param(&uuid));
            let reconfigure = ["wireguard/service/reconfigure".to_string()];
            let flip = service_write(&ctx, write, "Changing the peer", &reconfigure, true);
            flip_to(&ctx, "wireguard/client/get_client", "client", &uuid, args.bool("enabled").unwrap_or(false), "Changing the peer", flip).await
        }),
        read_tool("opn_ipsec_status", "IPsec status", "IPsec tunnels as they run now: phase 1 and phase 2 state, with the service status.", Domain::Vpn).run(|_args, ctx| async move {
            let (mut data, unavailable) = gather(vec![get_src(&ctx.api, "service", "ipsec/service/status"), ("phase1", all_src(&ctx.api, "ipsec/sessions/search_phase1"))]).await;
            // search_phase2 répond par tunnel : il prend le nom de la ligne de phase 1.
            let names = phase1_names(&rows_of(data.get("phase1")));
            let results: Vec<Result<Vec<Value>>> = futures::future::join_all(names.iter().map(|name| {
                let api = ctx.api.clone();
                let extra: Obj = Map::from_iter([("id".to_string(), json!(name))]);
                async move { fetch_all(&api, "ipsec/sessions/search_phase2", Some(extra), FETCH_ALL_MAX).await }
            }))
            .await;
            let mut phase2 = Map::new();
            let mut unavailable = unavailable;
            for (name, r) in names.into_iter().zip(results) {
                match r {
                    Ok(rows) => {
                        phase2.insert(name, Value::Array(rows));
                    }
                    Err(e) => {
                        unavailable.insert(format!("phase2:{name}"), json!(format!("{}: {}", e.kind.as_str(), e.message)));
                    }
                }
            }
            data.insert("phase2".into(), Value::Object(phase2));
            data.insert("unavailable".into(), Value::Object(unavailable));
            Ok(Value::Object(data))
        }),
        read_tool(
            "opn_list_ipsec_connections",
            "List IPsec connections",
            "Configured IPsec connections. For whether they are up, see opn_ipsec_status. Legacy tunnels made on the old IPsec page do not appear here: see opn_get_config_section with section ipsec.",
            Domain::Vpn,
        )
        .input(paging())
        .run(|args, ctx| async move { Ok(compact_grid(&search_grid(&ctx.api, "ipsec/connections/search_connection", &args.grid()).await?)) }),
        read_tool(
            "opn_openvpn_status",
            "OpenVPN status",
            "OpenVPN as it runs now: connected sessions, with their addresses and traffic, and the routes.",
            Domain::Vpn,
        )
        .run(|_args, ctx| async move {
            let (mut data, unavailable) = gather(vec![("sessions", all_src(&ctx.api, "openvpn/service/search_sessions")), ("routes", all_src(&ctx.api, "openvpn/service/search_routes"))]).await;
            data.insert("unavailable".into(), Value::Object(unavailable));
            Ok(Value::Object(data))
        }),
    ];
    let mut openvpn = CrudSpec::new(
        Domain::Vpn,
        "openvpn_instance",
        "openvpn_instances",
        "OpenVPN instance",
        "openvpn/instances",
        "instance",
        Commands { search: "search", get: "get", ..Default::default() },
    );
    openvpn.list_note = Some("Legacy instances made on the old OpenVPN pages do not appear here: see opn_get_config_section with section openvpn.");
    defs.extend(crud_tools(openvpn));
    defs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::BoxFut;

    #[test]
    fn names_access_and_domains() {
        let d = tools();
        let names: Vec<&str> = d.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(
            names,
            [
                "opn_wireguard_status", "opn_list_wireguard_servers", "opn_list_wireguard_peers", "opn_toggle_wireguard_peer", "opn_ipsec_status", "opn_list_ipsec_connections", "opn_openvpn_status",
                "opn_list_openvpn_instances", "opn_get_openvpn_instance"
            ]
        );
        assert!(d.iter().all(|t| t.domain == Domain::Vpn));
        let toggle = d.iter().find(|t| t.name == "opn_toggle_wireguard_peer").unwrap();
        assert_eq!(toggle.access, ToolAccess::Write);
        assert!(toggle.input.validate(&json!({ "uuid": "not-a-uuid", "enabled": true })).is_err());
        assert!(toggle.input.validate(&json!({ "uuid": "123e4567-e89b-12d3-a456-426614174000", "enabled": false })).is_ok());
    }

    #[test]
    fn phase1_names_skip_blank() {
        let rows = vec![json!({ "name": "con1" }), json!({ "name": null }), json!({}), json!({ "name": "" }), json!({ "name": 7 })];
        assert_eq!(phase1_names(&rows), ["con1", "7"]);
    }

    #[tokio::test]
    async fn gather_keeps_failures_apart() {
        let ok: BoxFut<Result<Value>> = Box::pin(async { Ok(json!(1)) });
        let (data, unavailable) = gather(vec![("a", ok)]).await;
        assert_eq!(data["a"], 1);
        assert!(unavailable.is_empty());
    }
}

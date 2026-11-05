//! Outils du domaine dhcp : baux (Kea, Dnsmasq, ISC), plages, hôtes et réservations.

use crate::error::{ErrorType, OpnError};
use crate::model::{
    assert_applied, compact_grid, fetch_all, paginate_array, search_grid, Obj, FETCH_ALL_MAX,
};
use crate::schema::{self, Field};
use crate::tool::{
    crud_tools, paging, read_tool, sparse, tool, Commands, CrudSpec, Domain, ToolAccess, ToolDef,
};
use serde_json::{json, Value};

struct LeaseSource {
    source: &'static str,
    path: &'static str,
}

const LEASE_SOURCES: [LeaseSource; 5] = [
    LeaseSource {
        source: "kea-dhcp4",
        path: "kea/leases4/search",
    },
    LeaseSource {
        source: "kea-dhcp6",
        path: "kea/leases6/search",
    },
    LeaseSource {
        source: "dnsmasq",
        path: "dnsmasq/leases/search",
    },
    LeaseSource {
        source: "isc-dhcp4",
        path: "dhcpv4/leases/search_lease",
    },
    LeaseSource {
        source: "isc-dhcp6",
        path: "dhcpv6/leases/search_lease",
    },
];

fn host_fields() -> Vec<Field> {
    vec![
        schema::string("host").opt().desc("Host name."),
        schema::string("domain").opt().desc("Domain."),
        schema::strings("ip").opt().desc("Addresses of this host."),
        schema::strings("hwaddr")
            .opt()
            .desc("MAC addresses that get this address over DHCP."),
        schema::string("client_id").opt().desc("DHCP client id."),
        schema::integer("lease_time")
            .opt()
            .min(0)
            .desc("Lease time in seconds."),
        schema::boolean("ignore")
            .opt()
            .desc("Ignore DHCP requests from this host."),
        schema::strings("cnames")
            .opt()
            .desc("Extra names for this host."),
        schema::string("descr").opt().desc("Free-text description."),
    ]
}

fn range_fields() -> Vec<Field> {
    vec![
        schema::string("interface")
            .opt()
            .desc("Interface id. Empty means all."),
        schema::string("start_addr")
            .opt()
            .desc("First address, or a prefix for IPv6."),
        schema::string("end_addr").opt().desc("Last address."),
        schema::integer("prefix_len")
            .opt()
            .min(1)
            .max(64)
            .desc("IPv6 prefix length."),
        schema::string("ra_mode")
            .opt()
            .desc("IPv6 router advertisement mode."),
        schema::integer("lease_time")
            .opt()
            .min(0)
            .desc("Lease time in seconds."),
        schema::string("description")
            .opt()
            .desc("Free-text description."),
    ]
}

fn reservation_fields() -> Vec<Field> {
    vec![
        schema::string("subnet")
            .opt()
            .desc("Subnet uuid, from opn_list_kea_subnets."),
        schema::string("ip_address")
            .opt()
            .desc("Address to reserve."),
        schema::string("hw_address").opt().desc("MAC address."),
        schema::string("client_id")
            .opt()
            .desc("DHCP client id, as an alternative to the MAC address."),
        schema::string("hostname")
            .opt()
            .desc("Host name given to the client."),
        schema::string("description")
            .opt()
            .desc("Free-text description."),
    ]
}

fn reconfigure_tool(
    name: &str,
    title: &str,
    desc: &str,
    path: &'static str,
    what: &'static str,
) -> ToolDef {
    tool(name, title, desc, Domain::Dhcp, ToolAccess::Write)
        .idempotent()
        .run(move |_args, ctx| async move {
            Ok(Value::Object(assert_applied(
                &ctx.api.post_(path).await?,
                what,
                false,
            )?))
        })
}

#[allow(clippy::too_many_arguments)]
fn crud(
    singular: &'static str,
    plural: &'static str,
    label: &'static str,
    base: &'static str,
    commands: Commands,
    wrapper: &'static str,
    fields: Vec<Field>,
    required: &[&'static str],
    reconfigure: &'static str,
    list_note: Option<&'static str>,
    write_note: &'static str,
) -> Vec<ToolDef> {
    let mut spec = CrudSpec::new(
        Domain::Dhcp,
        singular,
        plural,
        label,
        base,
        wrapper,
        commands,
    );
    spec.fields = fields;
    spec.required = required.to_vec();
    spec.reconfigure = vec![reconfigure];
    spec.list_note = list_note;
    spec.write_note = Some(write_note);
    crud_tools(spec)
}

fn cmds(suffix: &'static str) -> Commands {
    let (search, get, add, set, del) = match suffix {
        "range" => (
            "search_range",
            "get_range",
            "add_range",
            "set_range",
            "del_range",
        ),
        "host" => (
            "search_host",
            "get_host",
            "add_host",
            "set_host",
            "del_host",
        ),
        _ => (
            "search_reservation",
            "get_reservation",
            "add_reservation",
            "set_reservation",
            "del_reservation",
        ),
    };
    Commands {
        search,
        get,
        add: Some(add),
        set: Some(set),
        del: Some(del),
        toggle: None,
    }
}

pub fn tools() -> Vec<ToolDef> {
    let mut defs = Vec::new();
    defs.push(
        read_tool(
            "opn_list_dhcp_leases",
            "List DHCP leases",
            "Active leases across every DHCP server of the firewall (Kea, Dnsmasq, ISC), each marked with its source. Search by address, MAC or host name. Sources that are not installed are listed under sources_unavailable.",
            Domain::Dhcp,
        )
        .input(paging())
        .run(|args, ctx| async move {
            let extra = args.str("search").filter(|s| !s.is_empty()).map(|s| Obj::from_iter([("searchPhrase".to_string(), json!(s))]));
            let results = futures::future::join_all(LEASE_SOURCES.iter().map(|s| fetch_all(&ctx.api, s.path, extra.clone(), FETCH_ALL_MAX))).await;
            let mut rows: Vec<Value> = Vec::new();
            let mut unavailable = Obj::new();
            for (s, r) in LEASE_SOURCES.iter().zip(results) {
                match r {
                    Ok(found) => rows.extend(found.iter().map(|row| {
                        let mut out = Obj::new();
                        out.insert("source".into(), json!(s.source));
                        if let Value::Object(o) = sparse(row) {
                            out.extend(o);
                        }
                        Value::Object(out)
                    })),
                    Err(e) => {
                        unavailable.insert(s.source.into(), json!(e.kind.as_str()));
                    }
                }
            }
            if rows.is_empty() && unavailable.len() == LEASE_SOURCES.len() {
                return Err(OpnError::new(ErrorType::NotFound, "No DHCP lease source answered.")
                    .details(json!({ "sources_unavailable": unavailable }))
                    .hint("If every source says forbidden, the API user lacks the DHCP privileges."));
            }
            let mut out = match paginate_array(&rows, args.i64("limit"), args.i64("offset")).to_value() {
                Value::Object(o) => o,
                _ => Obj::new(),
            };
            out.insert("sources_unavailable".into(), Value::Object(unavailable));
            Ok(Value::Object(out))
        }),
    );
    defs.push(
        read_tool(
            "opn_list_kea_leases",
            "List Kea leases",
            "Leases from the Kea DHCP server, IPv4 by default.",
            Domain::Dhcp,
        )
        .input({
            let mut f = paging();
            f.push(
                schema::enumeration("ip_version", &["4", "6"])
                    .opt()
                    .desc("Default 4."),
            );
            f
        })
        .run(|args, ctx| async move {
            let path = format!("kea/leases{}/search", args.str("ip_version").unwrap_or("4"));
            Ok(compact_grid(
                &search_grid(&ctx.api, &path, &args.grid()).await?,
            ))
        }),
    );
    defs.push(
        read_tool(
            "opn_list_dnsmasq_leases",
            "List Dnsmasq leases",
            "Leases from the Dnsmasq DHCP server.",
            Domain::Dhcp,
        )
        .input(paging())
        .run(|args, ctx| async move {
            Ok(compact_grid(
                &search_grid(&ctx.api, "dnsmasq/leases/search", &args.grid()).await?,
            ))
        }),
    );
    defs.extend(crud(
        "dnsmasq_range",
        "dnsmasq_ranges",
        "Dnsmasq DHCP range",
        "dnsmasq/settings",
        cmds("range"),
        "range",
        range_fields(),
        &["start_addr"],
        "dnsmasq/service/reconfigure",
        None,
        "Goes live when Dnsmasq reconfigures, with no rollback timer.",
    ));
    defs.extend(crud(
        "dnsmasq_host",
        "dnsmasq_hosts",
        "Dnsmasq host",
        "dnsmasq/settings",
        cmds("host"),
        "host",
        host_fields(),
        &[],
        "dnsmasq/service/reconfigure",
        Some("A host with a MAC address is a DHCP reservation, and also a DNS entry."),
        "Goes live when Dnsmasq reconfigures, with no rollback timer.",
    ));
    defs.push(reconfigure_tool(
        "opn_reconfigure_dnsmasq",
        "Reconfigure Dnsmasq",
        "Regenerates the Dnsmasq configuration and restarts it: applies changes saved with apply=false.",
        "dnsmasq/service/reconfigure",
        "Reconfiguring Dnsmasq",
    ));
    defs.push(
        read_tool(
            "opn_list_kea_subnets",
            "List Kea subnets",
            "IPv4 subnets served by Kea, with their pools.",
            Domain::Dhcp,
        )
        .input(paging())
        .run(|args, ctx| async move {
            Ok(compact_grid(
                &search_grid(&ctx.api, "kea/dhcpv4/search_subnet", &args.grid()).await?,
            ))
        }),
    );
    defs.extend(crud(
        "kea_reservation",
        "kea_reservations",
        "Kea IPv4 reservation",
        "kea/dhcpv4",
        cmds("reservation"),
        "reservation",
        reservation_fields(),
        &["subnet", "ip_address"],
        "kea/service/reconfigure",
        None,
        "Goes live when Kea reconfigures, with no rollback timer.",
    ));
    defs.push(reconfigure_tool(
        "opn_reconfigure_kea",
        "Reconfigure Kea",
        "Regenerates the Kea configuration and restarts it: applies changes saved with apply=false.",
        "kea/service/reconfigure",
        "Reconfiguring Kea",
    ));
    defs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_have_expected_names_and_access() {
        let t = tools();
        let names: Vec<&str> = t.iter().map(|d| d.name.as_str()).collect();
        for n in [
            "opn_list_dhcp_leases",
            "opn_add_dnsmasq_range",
            "opn_update_dnsmasq_host",
            "opn_delete_kea_reservation",
            "opn_reconfigure_kea",
        ] {
            assert!(names.contains(&n), "missing {n}");
        }
        assert!(!names.contains(&"opn_toggle_dnsmasq_host"));
        let find = |n: &str| t.iter().find(|d| d.name == n).unwrap();
        assert_eq!(
            find("opn_delete_kea_reservation").access,
            ToolAccess::Destructive
        );
        assert_eq!(find("opn_reconfigure_dnsmasq").access, ToolAccess::Write);
    }

    #[test]
    fn reservation_requires_subnet_and_ip() {
        let t = tools();
        let add = t
            .iter()
            .find(|d| d.name == "opn_add_kea_reservation")
            .unwrap();
        let j = add.input.to_json_schema();
        assert_eq!(j["required"], json!(["subnet", "ip_address"]));
    }
}

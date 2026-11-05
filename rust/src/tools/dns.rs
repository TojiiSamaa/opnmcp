//! Outils du domaine dns : résolveur Unbound et listes de blocage.
#![allow(clippy::result_large_err)] // OpnError est l'erreur commune du crate

use crate::client::RequestOptions;
use crate::error::{ErrorType, OpnError, Result};
use crate::model::{
    assert_applied, assert_write_ok, compact_grid, flatten_model, model_fields, search_grid, Obj,
};
use crate::schema::{self, Field, Ty};
use crate::tool::{
    crud_tools, paging, read_tool, service_write, tool, uuid, Args, Commands, CrudSpec, Ctx,
    Domain, ToolAccess, ToolDef,
};
use serde_json::{json, Value};
use std::sync::Arc;

const RECONFIGURE: [&str; 1] = ["unbound/service/reconfigure"];

/// Un changement de liste de blocage demande de régénérer les listes avant que Unbound les recharge.
const DNSBL_RECONFIGURE: [&str; 2] = ["unbound/service/dnsbl", "unbound/service/reconfigure"];

const MAX_DOMAIN_LEN: usize = 253;

fn domain_list() -> Field {
    let item = Ty::Str {
        regex: Some((
            regex::Regex::new(r"^[A-Za-z0-9*._-]+$").expect("regex"),
            "Expected a domain name".to_string(),
        )),
        check: Some((
            Arc::new(|v: &str| v.chars().count() <= MAX_DOMAIN_LEN),
            "Too long: at most 253 characters",
        )),
    };
    schema::array_of("domains", item).desc("Domain names.")
}

fn dnsbl_fields() -> Vec<Field> {
    vec![
        schema::boolean("enabled").opt().desc("Enable this blocklist policy."),
        schema::strings("type").opt().desc("Predefined list ids to use. opn_describe_model on unbound/settings/get_dnsbl lists them."),
        schema::strings("lists").opt().desc("URLs of extra blocklists."),
        schema::strings("allowlists").opt().desc("Domains never to block. opn_add_dnsbl_allowlist keeps what is already there, this replaces it."),
        schema::strings("blocklists").opt().desc("Domains to block in addition to the lists."),
        schema::strings("wildcards").opt().desc("Domains to block along with all their subdomains."),
        schema::strings("source_nets").opt().desc("Networks this policy applies to. Empty means all."),
        schema::string("address").opt().desc("Address to answer with for blocked names. Empty means the default."),
        schema::boolean("nxdomain").opt().desc("Answer NXDOMAIN rather than an address."),
        schema::integer("cache_ttl").opt().min(0).desc("TTL of block answers, in seconds."),
        schema::string("description").opt().desc("Free-text description."),
    ]
}

fn forward_fields() -> Vec<Field> {
    vec![
        schema::string("domain")
            .opt()
            .desc("Domain to forward. Empty forwards everything."),
        schema::string("server")
            .opt()
            .desc("Address of the upstream server."),
        schema::integer("port")
            .opt()
            .min(1)
            .max(65535)
            .desc("Upstream port."),
        schema::boolean("forward_tcp_upstream")
            .opt()
            .desc("Use TCP to reach this server."),
        schema::boolean("forward_first")
            .opt()
            .desc("Fall back to direct resolution when the forward fails."),
        schema::string("description")
            .opt()
            .desc("Free-text description."),
        schema::boolean("enabled")
            .opt()
            .desc("Default true on creation."),
    ]
}

fn split_list(value: &Value) -> Vec<String> {
    let text = match value {
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    text.split(['\n', ','])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn require_domains(args: &Args) -> Result<Vec<String>> {
    let domains = args.strs("domains");
    if domains.is_empty() {
        return Err(OpnError::new(
            ErrorType::InvalidInput,
            "domains: at least one domain is required.",
        ));
    }
    Ok(domains)
}

async fn read_allowlist(ctx: &Ctx, id: &str) -> Result<Vec<String>> {
    let res = ctx
        .api
        .get(
            "unbound/settings/get_dnsbl",
            RequestOptions::new().param(id),
        )
        .await?;
    let Some(form) = res.get("blocklist").filter(|v| v.is_object()) else {
        return Err(OpnError::new(
            ErrorType::NotFound,
            format!("DNSBL policy {id} was not found."),
        )
        .hint("opn_list_dnsbl lists the policies."));
    };
    // Un CSVListField revient sous forme de table d'options, en texte simple sur les versions plus anciennes.
    Ok(split_list(&flatten_model(
        form.get("allowlists").unwrap_or(&Value::Null),
    )))
}

async fn write_allowlist(ctx: &Ctx, id: &str, entries: &[String], what: &str) -> Result<Value> {
    // Ce sont des CSVListField : un saut de ligne ferait échouer tout le champ à son masque par élément.
    let write = ctx.api.post(
        "unbound/settings/set_dnsbl",
        Some(json!({ "blocklist": { "allowlists": entries.join(",") } })),
        RequestOptions::new().param(id),
    );
    service_write(ctx, write, what, &DNSBL_RECONFIGURE.map(String::from), true).await
}

fn merged(base: Value, extra: Value) -> Value {
    let mut out = match base {
        Value::Object(o) => o,
        _ => Obj::new(),
    };
    if let Value::Object(e) = extra {
        out.extend(e);
    }
    Value::Object(out)
}

/// Liste paginée sans autre argument que la pagination.
fn grid_list(name: &str, title: &str, desc: &str, path: &'static str) -> ToolDef {
    read_tool(name, title, desc, Domain::Dns)
        .input(paging())
        .run(move |args, ctx| async move {
            Ok(compact_grid(
                &search_grid(&ctx.api, path, &args.grid()).await?,
            ))
        })
}

/// Les commandes portent toutes le même suffixe (host_override, forward, dot).
macro_rules! cmds {
    ($s:literal) => {
        Commands {
            search: concat!("search_", $s),
            get: concat!("get_", $s),
            add: Some(concat!("add_", $s)),
            set: Some(concat!("set_", $s)),
            del: Some(concat!("del_", $s)),
            toggle: Some(concat!("toggle_", $s)),
        }
    };
}

#[allow(clippy::too_many_arguments)]
fn crud(
    singular: &'static str,
    plural: &'static str,
    label: &'static str,
    commands: Commands,
    wrapper: &'static str,
    fields: Vec<Field>,
    required: &[&'static str],
    list_note: Option<&'static str>,
    write_note: &'static str,
) -> Vec<ToolDef> {
    let mut spec = CrudSpec::new(
        Domain::Dns,
        singular,
        plural,
        label,
        "unbound/settings",
        wrapper,
        commands,
    );
    spec.fields = fields;
    spec.required = required.to_vec();
    spec.reconfigure = RECONFIGURE.to_vec();
    spec.list_note = list_note;
    spec.write_note = Some(write_note);
    crud_tools(spec)
}

pub fn tools() -> Vec<ToolDef> {
    let mut defs = Vec::new();
    defs.extend(crud(
        "dns_override",
        "dns_overrides",
        "DNS host override",
        cmds!("host_override"),
        "host",
        vec![
            schema::string("hostname")
                .opt()
                .desc("Host part. Use * for a wildcard."),
            schema::string("domain").opt().desc("Domain part."),
            schema::enumeration("rr", &["A", "AAAA", "MX", "TXT"])
                .opt()
                .desc("Record type."),
            schema::string("server")
                .opt()
                .desc("Address to answer with, for A and AAAA."),
            schema::string("mx").opt().desc("Mail host, for MX."),
            schema::integer("mxprio")
                .opt()
                .min(0)
                .desc("Priority, for MX."),
            schema::string("txtdata").opt().desc("Content, for TXT."),
            schema::integer("ttl").opt().min(0).desc("TTL in seconds."),
            schema::boolean("addptr")
                .opt()
                .desc("Also answer the reverse lookup."),
            schema::string("description")
                .opt()
                .desc("Free-text description."),
            schema::boolean("enabled")
                .opt()
                .desc("Default true on creation."),
        ],
        &["domain", "rr"],
        None,
        "Goes live when Unbound reconfigures, with no rollback timer.",
    ));
    defs.extend(crud(
        "dns_forward",
        "dns_forwards",
        "DNS forward",
        cmds!("forward"),
        "dot",
        forward_fields(),
        &["server"],
        Some("DNS over TLS servers are listed separately: see opn_list_dot_servers."),
        "Goes live when Unbound reconfigures, with no rollback timer. A wrong forward can break name resolution for the whole network.",
    ));
    // Même modèle que les forwards : le pare-feu les distingue par le point d'accès utilisé, et chacun fixe le type.
    let mut dot_fields = forward_fields();
    dot_fields.push(
        schema::string("verify")
            .opt()
            .desc("Name to verify on the certificate of the server."),
    );
    defs.extend(crud(
        "dot_server",
        "dot_servers",
        "DNS over TLS server",
        cmds!("dot"),
        "dot",
        dot_fields,
        &["server"],
        None,
        "Goes live when Unbound reconfigures, with no rollback timer. A wrong server can break name resolution for the whole network.",
    ));
    defs.push(grid_list(
        "opn_list_dns_host_aliases",
        "List DNS host aliases",
        "Additional names pointing at a DNS host override.",
        "unbound/settings/search_host_alias",
    ));
    defs.push(grid_list(
        "opn_list_dns_acls",
        "List DNS access lists",
        "Unbound access lists: which networks may query the resolver.",
        "unbound/settings/search_acl",
    ));
    defs.push(
        read_tool("opn_dns_stats", "DNS resolver statistics", "Unbound counters: queries, cache hits, answers by type. They restart from zero when Unbound restarts.", Domain::Dns)
            .run(|_args, ctx| async move { ctx.api.get_("unbound/diagnostics/stats").await }),
    );
    defs.push(
        read_tool(
            "opn_dns_top_domains",
            "Top DNS domains",
            "Query totals and the most queried and most blocked domains. Needs Unbound reporting to be enabled in Reporting > Settings.",
            Domain::Dns,
        )
        .input(vec![schema::integer("count").opt().min(1).max(1000).desc("Domains per list (default 10).")])
        .run(|args, ctx| async move { ctx.api.get("unbound/overview/totals", RequestOptions::new().param(args.i64("count").unwrap_or(10))).await }),
    );
    defs.push(
        read_tool(
            "opn_dns_query_log",
            "DNS query log",
            "Queries with client, domain, answer and whether they were blocked: the latest 1000, or those of one client over a time window. Needs Unbound reporting to be enabled. No entry does not prove a name was not queried: clients can cache, and other resolvers exist.",
            Domain::Dns,
        )
        .input({
            let mut f = paging();
            f.push(schema::string("client").ip().opt().desc("Only this client IP address."));
            f.push(schema::integer("since_hours").opt().min(1).max(8760).desc("With client: how far back to look, in hours (default 24)."));
            f
        })
        .run(|args, ctx| async move {
            // Le pare-feu ignore client s'il ne reçoit pas aussi une fenêtre de temps, en entiers JSON.
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs() as i64);
            let mut extra = Obj::new();
            if let Some(client) = args.str("client").filter(|c| !c.is_empty()) {
                extra.insert("client".into(), json!(client));
                extra.insert("timeStart".into(), json!(now - args.i64("since_hours").unwrap_or(24) * 3600));
                extra.insert("timeEnd".into(), json!(now));
            }
            Ok(compact_grid(&search_grid(&ctx.api, "unbound/overview/search_queries", &args.grid().extra(extra)).await?))
        }),
    );
    defs.push(
        tool(
            "opn_reconfigure_unbound",
            "Reconfigure Unbound",
            "Regenerates the Unbound configuration and restarts it: applies changes saved with apply=false. DNS can be briefly unavailable, and the cache is lost.",
            Domain::Dns,
            ToolAccess::Write,
        )
        .idempotent()
        .run(|_args, ctx| async move { Ok(Value::Object(assert_applied(&ctx.api.post_("unbound/service/reconfigure").await?, "Reconfiguring Unbound", false)?)) }),
    );

    // ---- Listes de blocage DNS ----
    defs.push(grid_list(
        "opn_list_dnsbl",
        "List DNS blocklists",
        "DNS blocklist policies, with the lists they use and the networks they apply to.",
        "unbound/settings/search_dnsbl",
    ));
    defs.push(
        read_tool(
            "opn_get_dnsbl",
            "Get DNS blocklist",
            "Every field of one DNS blocklist policy, including its allowlist.",
            Domain::Dns,
        )
        .input(vec![uuid()])
        .run(|args, ctx| async move {
            let res = ctx
                .api
                .get(
                    "unbound/settings/get_dnsbl",
                    RequestOptions::new().param(args.req("uuid")),
                )
                .await?;
            let form = res
                .get("blocklist")
                .filter(|v| !v.is_null())
                .cloned()
                .unwrap_or(res);
            Ok(json!({ "uuid": args.req("uuid"), "blocklist": flatten_model(&form) }))
        }),
    );
    defs.push(
        read_tool(
            "opn_test_dnsbl",
            "Test a domain against the blocklists",
            "Checks whether a DNS blocklist would block a domain, and because of which list. Use this before allowlisting.",
            Domain::Dns,
        )
        .input(vec![
            schema::string("domain").regex(r"^[A-Za-z0-9._-]+$", "Expected a domain name").desc("Domain to test."),
            schema::string("source").opt().desc("Client address, since policies can apply to some networks only."),
        ])
        .run(|args, ctx| async move {
            let mut body = json!({ "domain": args.req("domain") });
            if let Some(src) = args.str("source").filter(|s| !s.is_empty()) {
                body["src"] = json!(src);
            }
            ctx.api.post("unbound/diagnostics/test_blocklist", Some(body), RequestOptions::new()).await
        }),
    );
    defs.push(
        tool(
            "opn_set_dnsbl",
            "Update DNS blocklist",
            "Changes a blocklist policy. Fields left out keep their value; a list given here replaces the existing one. Regenerates the lists and reloads Unbound, which flushes the DNS cache.",
            Domain::Dns,
            ToolAccess::Write,
        )
        .idempotent()
        .input({
            let mut f = vec![uuid()];
            f.extend(dnsbl_fields());
            f
        })
        .run(|args, ctx| async move {
            let mut rest = args.obj().clone();
            rest.remove("uuid");
            let fields = model_fields(&rest);
            if fields.is_empty() {
                return Err(OpnError::new(ErrorType::InvalidInput, "Updating the blocklist: no field to change was given."));
            }
            let write = ctx.api.post("unbound/settings/set_dnsbl", Some(json!({ "blocklist": fields })), RequestOptions::new().param(args.req("uuid")));
            service_write(&ctx, write, "Updating the blocklist", &DNSBL_RECONFIGURE.map(String::from), true).await
        }),
    );
    defs.push(
        tool(
            "opn_add_dnsbl_allowlist",
            "Allow domains in a DNS blocklist",
            "Adds domains to the allowlist of a policy, keeping what is already there. Regenerates the lists and reloads Unbound, which flushes the DNS cache.",
            Domain::Dns,
            ToolAccess::Write,
        )
        .idempotent()
        .input(vec![uuid(), domain_list()])
        .run(|args, ctx| async move {
            let domains = require_domains(&args)?;
            let existing = read_allowlist(&ctx, args.req("uuid")).await?;
            let mut added: Vec<String> = Vec::new();
            for d in domains {
                if !existing.contains(&d) {
                    added.push(d);
                }
            }
            if added.is_empty() {
                return Ok(json!({ "status": "unchanged", "added": [], "allowlist": existing }));
            }
            let all: Vec<String> = existing.iter().chain(added.iter()).cloned().collect();
            let written = write_allowlist(&ctx, args.req("uuid"), &all, "Updating the allowlist").await?;
            Ok(merged(written, json!({ "added": added, "allowlist": all })))
        }),
    );
    defs.push(
        tool(
            "opn_remove_dnsbl_allowlist",
            "Remove domains from a DNS allowlist",
            "Removes domains from the allowlist of a policy, so they can be blocked again. Regenerates the lists and reloads Unbound, which flushes the DNS cache.",
            Domain::Dns,
            ToolAccess::Destructive,
        )
        .idempotent()
        .input(vec![uuid(), domain_list()])
        .confirm(|a| format!("Remove {} from the DNS allowlist?", a.strs("domains").join(", ")))
        .run(|args, ctx| async move {
            let domains = require_domains(&args)?;
            let existing = read_allowlist(&ctx, args.req("uuid")).await?;
            let kept: Vec<String> = existing.iter().filter(|d| !domains.contains(d)).cloned().collect();
            let removed: Vec<String> = existing.iter().filter(|d| domains.contains(d)).cloned().collect();
            if removed.is_empty() {
                return Ok(json!({ "status": "unchanged", "removed": [], "allowlist": existing }));
            }
            let written = write_allowlist(&ctx, args.req("uuid"), &kept, "Updating the allowlist").await?;
            Ok(merged(written, json!({ "removed": removed, "allowlist": kept })))
        }),
    );
    defs.push(
        tool(
            "opn_update_dnsbl",
            "Refresh DNS blocklists",
            "Downloads and regenerates the blocklists, then reloads Unbound. This flushes the DNS cache. Changes no setting.",
            Domain::Dns,
            ToolAccess::Write,
        )
        .idempotent()
        .open_world()
        .run(|_args, ctx| async move {
            let slow = RequestOptions { timeout_ms: Some(300_000), ..RequestOptions::new() };
            let dnsbl = assert_write_ok(&ctx.api.post("unbound/service/dnsbl", None, slow).await?, "Regenerating the blocklists")?;
            let service = assert_applied(&ctx.api.post_("unbound/service/reconfigure").await?, "Reloading Unbound", false)?;
            let status = |o: Obj| o.get("status").filter(|v| !v.is_null()).cloned().unwrap_or(Value::Object(o));
            Ok(json!({ "dnsbl_status": status(dnsbl), "service_status": status(service) }))
        }),
    );
    defs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_handles_commas_newlines_and_empty() {
        assert_eq!(
            split_list(&json!("a.com, b.com\nc.com,,")),
            vec!["a.com", "b.com", "c.com"]
        );
        assert!(split_list(&Value::Null).is_empty());
    }

    #[test]
    fn domains_are_validated() {
        let s = crate::schema::Schema::new(vec![domain_list()]);
        assert!(s
            .validate(&json!({ "domains": ["a.example.com", "*.x.org"] }))
            .is_ok());
        assert!(s.validate(&json!({ "domains": ["bad domain"] })).is_err());
        assert!(s
            .validate(&json!({ "domains": ["a".repeat(254)] }))
            .is_err());
    }

    #[test]
    fn tool_names_and_access() {
        let t = tools();
        let find = |n: &str| {
            t.iter()
                .find(|d| d.name == n)
                .unwrap_or_else(|| panic!("missing {n}"))
        };
        assert_eq!(
            find("opn_remove_dnsbl_allowlist").access,
            ToolAccess::Destructive
        );
        assert!(find("opn_update_dnsbl").open_world);
        assert_eq!(find("opn_toggle_dot_server").access, ToolAccess::Write);
        assert!(find("opn_dns_query_log").input.has("client"));
    }
}

//! Outils du domaine api : découverte et appel générique de l'API pour ce qu'aucun outil dédié ne couvre.

use crate::client::RequestOptions;
use crate::error::{ErrorType, OpnError};
use crate::model::describe_model;
use crate::policy::{decide, Access};
use crate::schema::{self, Field, Ty};
use crate::tool::{read_tool, tool, Args, Domain, ToolAccess, ToolDef};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::LazyLock;

#[derive(Deserialize)]
struct CatalogEntry {
    method: String,
    path: String,
    #[serde(default)]
    params: Vec<String>,
    source: String,
}

#[derive(Deserialize)]
struct CatalogFile {
    endpoints: Vec<CatalogEntry>,
}

/// Le catalogue vient de la documentation OPNsense ; il est lu une seule fois, au premier besoin.
static CATALOG: LazyLock<Vec<CatalogEntry>> =
    LazyLock::new(|| serde_json::from_str::<CatalogFile>(include_str!("../../endpoints.json")).expect("rust/endpoints.json invalide").endpoints);

fn path_field() -> Field {
    schema::string("path")
        .regex(r"^[A-Za-z0-9_.,:/-]+$", "Expected a path such as firewall/filter/search_rule")
        .desc("Path below /api, such as firewall/filter/search_rule. Extra segments (a uuid) go at the end.")
}

fn query_field() -> Field {
    schema::record("query", vec![schema::plain_str(), Ty::Num { min: None }, Ty::Bool]).opt().desc("Query string parameters.")
}

fn body_field() -> Field {
    schema::unknown_record("body").opt().desc("JSON body, for POST.")
}

fn request_options(args: &Args) -> RequestOptions {
    let mut opts = RequestOptions::new();
    if let Some(Value::Object(q)) = args.get("query") {
        for (k, v) in q {
            opts = opts.query(k, v.as_str().map_or_else(|| v.to_string(), String::from));
        }
    }
    opts
}

/// Certains points d'accès répondent par une liste nue ou un scalaire : le résultat d'un outil est toujours un objet.
fn wrap(res: Value) -> Value {
    if res.is_object() {
        res
    } else {
        json!({ "result": res })
    }
}

fn access_name(a: Access) -> &'static str {
    match a {
        Access::Read => "read",
        Access::Write => "write",
    }
}

fn search(query: &str, source: Option<&str>, limit: usize) -> Value {
    let query = query.to_lowercase();
    let words: Vec<&str> = query.split_whitespace().collect();
    let hits: Vec<&CatalogEntry> = CATALOG
        .iter()
        .filter(|e| {
            if source.is_some_and(|s| e.source != s) {
                return false;
            }
            let haystack = format!("{} {}", e.path, e.source).to_lowercase();
            words.iter().all(|w| haystack.contains(w))
        })
        .collect();
    let results: Vec<Value> = hits
        .iter()
        .take(limit)
        .map(|e| {
            let decision = decide(&e.path, !e.method.contains("POST"), &[], false);
            let mut m = Map::new();
            m.insert("path".into(), json!(e.path));
            m.insert("method".into(), json!(e.method));
            if !e.params.is_empty() {
                m.insert("params".into(), json!(e.params));
            }
            m.insert("source".into(), json!(e.source));
            m.insert("access".into(), json!(if decision.blocked.is_some() { "blocked" } else { access_name(decision.access) }));
            if decision.sensitive {
                m.insert("sensitive".into(), json!(true));
            }
            Value::Object(m)
        })
        .collect();
    json!({ "total": hits.len(), "truncated": hits.len() > limit, "results": results })
}

pub fn tools() -> Vec<ToolDef> {
    vec![
        read_tool(
            "opn_search_api",
            "Search the OPNsense API",
            format!(
                "Searches the catalog of {} OPNsense endpoints, core and plugins, for what no dedicated tool covers. Each result says how this server treats it: read, write or blocked. Prefer a dedicated tool when one exists. The catalog comes from the documentation: an endpoint may be missing on this firewall, or need a plugin.",
                CATALOG.len()
            ),
            Domain::Api,
        )
        .input(vec![
            schema::string("query").check(|s| s.chars().count() >= 2, "String must contain at least 2 character(s)").desc("Words that must all appear in the path, such as \"wireguard client\" or \"vip\"."),
            schema::string("source").opt().desc("Only \"core\", or one plugin such as \"plugin:haproxy\"."),
            schema::integer("limit").opt().min(1).max(200).desc("Results (default 40)."),
        ])
        .run(|args, _ctx| async move { Ok(search(args.req("query"), args.str("source").filter(|s| !s.is_empty()), args.i64("limit").unwrap_or(40) as usize)) }),
        read_tool(
            "opn_describe_model",
            "Describe a model",
            "Shows which fields an object accepts, with the allowed values of each enum, as this firewall reports them. Point it at a get endpoint without uuid to get a blank form: firewall/filter/get_rule, unbound/settings/get_host_override. Use this before a write that failed validation.",
            Domain::Api,
        )
        .input(vec![path_field().desc("A get endpoint, such as firewall/filter/get_rule.")])
        .run(|args, ctx| async move {
            let path = args.req("path");
            let res = ctx.generic.get_(path).await?;
            if !res.is_object() {
                return Err(OpnError::new(ErrorType::BadResponse, format!("{path} did not return a model.")).hint("Point this at a get endpoint such as firewall/filter/get_rule."));
            }
            let mut out = Map::new();
            out.insert("path".into(), json!(path));
            if let Value::Object(d) = describe_model(&res) {
                out.extend(d);
            }
            Ok(Value::Object(out))
        }),
        tool(
            "opn_api_read",
            "Read any API endpoint",
            "Calls an endpoint that only reads, for what no dedicated tool covers. Find it with opn_search_api. Endpoints this server cannot prove to be read-only are refused, whatever the HTTP method: use opn_api_write for those. Secrets are redacted.",
            Domain::Api,
            ToolAccess::Read,
        )
        .input(vec![
            path_field(),
            schema::enumeration("method", &["GET", "POST"]).opt().desc("Default GET. Search endpoints take POST with paging fields in the body."),
            query_field(),
            body_field(),
        ])
        .run(|args, ctx| async move {
            let opts = request_options(&args);
            let path = args.req("path");
            let res = if args.str("method") == Some("POST") { ctx.generic.post(path, args.get("body").cloned(), opts).await? } else { ctx.generic.get(path, opts).await? };
            Ok(wrap(res))
        }),
        tool(
            "opn_api_write",
            "Write to any API endpoint",
            "Calls an endpoint that changes something, for what no dedicated tool covers. Find it with opn_search_api. IMMEDIATE: it is outside the staged change workflow, has no rollback timer and no lockout check, and most endpoints also need their reconfigure call. Blocked endpoints stay blocked. Prefer a dedicated tool whenever one exists.",
            Domain::Api,
            ToolAccess::Destructive,
        )
        .input(vec![path_field(), schema::enumeration("method", &["GET", "POST"]).opt().desc("Default POST."), query_field(), body_field()])
        .confirm(|a| format!("Call {} {} on the firewall? There is no rollback for this.", a.str("method").unwrap_or("POST"), a.req("path")))
        .run(|args, ctx| async move {
            let opts = request_options(&args);
            let path = args.req("path");
            let res = if args.str("method") == Some("GET") { ctx.generic.get(path, opts).await? } else { ctx.generic.post(path, args.get("body").cloned(), opts).await? };
            Ok(wrap(res))
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_loads_and_search_classifies() {
        assert!(CATALOG.len() > 1000);
        let r = search("firewall filter search_rule", None, 5);
        let first = &r["results"][0];
        assert_eq!(first["access"], "read");
        let r = search("core system reboot", Some("core"), 40);
        assert!(r["results"].as_array().unwrap().iter().any(|e| e["access"] == "blocked"));
        assert_eq!(search("zzzz-no-such", None, 5)["total"], 0);
    }

    #[test]
    fn four_tools_with_the_expected_access() {
        let t = tools();
        let names: Vec<&str> = t.iter().map(|d| d.name.as_str()).collect();
        assert_eq!(names, ["opn_search_api", "opn_describe_model", "opn_api_read", "opn_api_write"]);
        assert_eq!(t[3].access, ToolAccess::Destructive);
        assert!(!t[2].idempotent);
        let msg = (t[3].confirmation.as_ref().unwrap())(&Args(json!({"path": "a/b/c"}).as_object().unwrap().clone()));
        assert_eq!(msg, "Call POST a/b/c on the firewall? There is no rollback for this.");
    }

    #[test]
    fn wrap_keeps_objects_and_boxes_the_rest() {
        assert_eq!(wrap(json!({"a": 1})), json!({"a": 1}));
        assert_eq!(wrap(json!([1])), json!({"result": [1]}));
    }
}

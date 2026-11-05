//! Outils du domaine haproxy.
//!
//! Les modèles HAProxy ont des dizaines de champs, presque tous facultatifs : les outils prennent les champs
//! du modèle tels quels (opn_describe_model les liste).

use crate::error::Result;
use crate::model::{assert_applied, model_fields, Obj};
use crate::schema::{self, Field, Ty};
use crate::tool::{
    crud_tools, gather, read_tool, tool, BoxFut, Commands, CrudSpec, Ctx, Domain, ToolAccess,
    ToolDef,
};
use serde_json::Value;
use std::sync::Arc;

const HAPROXY: [&str; 2] = ["haproxy/service/configtest", "haproxy/service/reconfigure"];

fn fields_input() -> Field {
    schema::record("fields", vec![schema::plain_str(), Ty::Num { min: None }, Ty::Bool, Ty::Array(Box::new(schema::plain_str()))])
        .opt()
        .desc("Model fields to set. opn_describe_model with the matching get endpoint lists names and accepted values.")
}

/// (singulier, pluriel, libellé, enveloppe, bascule)
const ENTITIES: [(&str, &str, &str, &str, Option<&str>); 6] = [
    (
        "frontend",
        "frontends",
        "HAProxy frontend",
        "frontend",
        Some("toggle_frontend"),
    ),
    (
        "backend",
        "backends",
        "HAProxy backend",
        "backend",
        Some("toggle_backend"),
    ),
    (
        "server",
        "servers",
        "HAProxy server",
        "server",
        Some("toggle_server"),
    ),
    (
        "action",
        "actions",
        "HAProxy rule",
        "action",
        Some("toggle_action"),
    ),
    ("acl", "acls", "HAProxy condition", "acl", None),
    (
        "healthcheck",
        "healthchecks",
        "HAProxy health check",
        "healthcheck",
        None,
    ),
];

/// Les noms sont construits une seule fois au démarrage : les fuites sont bornées.
fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn entity_tools(
    (singular, plural, label, wrapper, toggle): (
        &str,
        &str,
        &'static str,
        &'static str,
        Option<&str>,
    ),
) -> Vec<ToolDef> {
    let mut spec = CrudSpec::new(
        Domain::Haproxy,
        leak(format!("haproxy_{singular}")),
        leak(format!("haproxy_{plural}")),
        label,
        "haproxy/settings",
        wrapper,
        Commands {
            search: leak(format!("search_{plural}")),
            get: leak(format!("get_{singular}")),
            add: Some(leak(format!("add_{singular}"))),
            set: Some(leak(format!("set_{singular}"))),
            del: Some(leak(format!("del_{singular}"))),
            toggle: toggle.map(|t| leak(t.to_string())),
        },
    );
    spec.fields = vec![fields_input()];
    spec.required = vec!["fields"];
    spec.to_model = Some(Arc::new(|args: &Obj| match args.get("fields") {
        Some(Value::Object(o)) => model_fields(o),
        _ => Obj::new(),
    }));
    spec.reconfigure = HAPROXY.to_vec();
    spec.write_note = Some("HAProxy reloads right after a valid change, with no rollback timer. The configuration test runs first.");
    // Ces points d'accès déclarent tous $enabled mais aucun ne le transmet : ils inversent.
    spec.toggle_flips = true;
    crud_tools(spec)
}

fn get(ctx: &Arc<Ctx>, path: &'static str) -> BoxFut<Result<Value>> {
    let c = ctx.clone();
    Box::pin(async move { c.api.get_(path).await })
}

pub fn tools() -> Vec<ToolDef> {
    let mut defs = vec![
        read_tool(
            "opn_haproxy_status",
            "HAProxy status",
            "Whether HAProxy runs, with its live statistics per frontend, backend and server. Needs the os-haproxy plugin.",
            Domain::Haproxy,
        )
        .run(|_args, ctx| async move {
            let (data, unavailable) = gather(vec![
                ("service", get(&ctx, "haproxy/service/status")),
                ("info", get(&ctx, "haproxy/statistics/info")),
                ("counters", get(&ctx, "haproxy/statistics/counters")),
            ])
            .await;
            let mut out = data;
            out.insert("unavailable".into(), Value::Object(unavailable));
            Ok(Value::Object(out))
        }),
        read_tool("opn_haproxy_configtest", "Test HAProxy configuration", "Checks the saved HAProxy configuration without reloading anything.", Domain::Haproxy)
            .run(|_args, ctx| async move { ctx.api.get_("haproxy/service/configtest").await }),
        tool(
            "opn_reconfigure_haproxy",
            "Reconfigure HAProxy",
            "Reloads HAProxy with the saved configuration: applies changes saved with apply=false.",
            Domain::Haproxy,
            ToolAccess::Write,
        )
        .idempotent()
        .run(|_args, ctx| async move {
            assert_applied(&ctx.api.get_("haproxy/service/configtest").await?, "Testing the configuration", false)?;
            Ok(Value::Object(assert_applied(&ctx.api.post_("haproxy/service/reconfigure").await?, "Reconfiguring HAProxy", false)?))
        }),
    ];
    defs.extend(ENTITIES.into_iter().flat_map(entity_tools));
    defs
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn tool_names_match_the_typescript_server() {
        let names: Vec<String> = tools().into_iter().map(|t| t.name).collect();
        assert_eq!(names.len(), 3 + 4 * 6 + 4 + 2 * 3);
        for n in [
            "opn_add_haproxy_frontend",
            "opn_toggle_haproxy_server",
            "opn_delete_haproxy_acl",
            "opn_list_haproxy_healthchecks",
            "opn_get_haproxy_action",
            "opn_update_haproxy_backend",
        ] {
            assert!(names.iter().any(|x| x == n), "{n}");
        }
        assert!(!names.iter().any(|x| x == "opn_toggle_haproxy_acl"));
    }

    #[test]
    fn add_requires_fields_and_update_does_not() {
        let defs = tools();
        let add = defs
            .iter()
            .find(|t| t.name == "opn_add_haproxy_backend")
            .unwrap();
        assert!(add.input.to_json_schema()["required"]
            .as_array()
            .unwrap()
            .contains(&json!("fields")));
        let upd = defs
            .iter()
            .find(|t| t.name == "opn_update_haproxy_backend")
            .unwrap();
        assert_eq!(upd.input.to_json_schema()["required"], json!(["uuid"]));
    }
}

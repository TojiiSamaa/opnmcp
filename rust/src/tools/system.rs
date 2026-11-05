//! Outils du domaine system.

use super::Info;
use crate::tool::{read_tool, Domain, ToolDef};
use serde_json::{json, Value};

pub fn tools(info: Info) -> Vec<ToolDef> {
    vec![read_tool(
        "opn_mcp_info",
        "About this server",
        "Start here. This MCP server and the firewall: write mode, dry-run, detected OPNsense version, which rollback protection firewall changes get, and any pending change.",
        Domain::System,
    )
    .run(move |_args, ctx| {
        let info = info.clone();
        async move {
            let caps = ctx.client.capabilities().await;
            let (opnsense, native) = match &caps {
                Ok(c) => (c.to_json(), c.native_savepoints),
                Err(e) => (json!({ "error": e.message }), None),
            };
            let protection = match native {
                Some(true) => "firewall-side: this OPNsense version has its own 60-second rollback timer, which fires even if this server loses the connection.",
                Some(false) => "server-side: OPNsense 26.7 removed the native rollback timer. This server restores a configuration backup if a change is not confirmed in time, which needs a working connection. A lockout check runs before each apply.",
                None => "unknown until the first firewall change: the API user cannot read the OPNsense version.",
            };
            let mut out = match info() {
                Value::Object(o) => o,
                _ => Default::default(),
            };
            out.insert("instance".into(), json!(ctx.instance.name));
            out.insert("firewall".into(), json!(ctx.instance.url));
            out.insert("writes_enabled".into(), json!(ctx.instance.allow_writes));
            out.insert("dry_run".into(), json!(ctx.instance.dry_run));
            out.insert("sensitive_allowed".into(), json!(ctx.instance.allow_sensitive));
            out.insert("opnsense".into(), opnsense);
            out.insert("firewall_change_protection".into(), json!(protection));
            out.insert("pending_change".into(), ctx.changes.status());
            Ok(Value::Object(out))
        }
    })]
}

//! Ressources `opnsense://<instance>/{status,interfaces,aliases,rules}` : les mêmes lectures que les outils,
//! pour les clients qui laissent l'utilisateur joindre du contexte directement.

use crate::client::RequestOptions;
use crate::error::{ErrorType, OpnError, Result};
use crate::model::{fetch_all, FETCH_ALL_MAX};
use crate::runtime::Runtime;
use serde_json::{json, Value};

const RESOURCES: &[(&str, &str)] = &[
    ("status", "System status reported by the firewall"),
    ("interfaces", "Interfaces, with the ids, devices and names they map to"),
    ("aliases", "Firewall aliases as configured"),
    ("rules", "Firewall rules in evaluation order, without automatic rules"),
];

pub fn list(runtime: &Runtime) -> Value {
    let mut out = Vec::new();
    for rt in runtime.instances() {
        for (name, description) in RESOURCES {
            out.push(json!({
                "uri": format!("opnsense://{}/{}", rt.config.name, name),
                "name": format!("{}-{}", rt.config.name, name),
                "title": format!("{} ({})", description, rt.config.name),
                "description": format!("{description}. Untrusted data from the firewall."),
                "mimeType": "application/json",
            }));
        }
    }
    json!({ "resources": out })
}

pub async fn read(runtime: &Runtime, uri: &str) -> Result<Value> {
    let bad = || OpnError::new(ErrorType::InvalidInput, format!("Unknown resource \"{uri}\"."));
    let rest = uri.strip_prefix("opnsense://").ok_or_else(bad)?;
    let (instance, name) = rest.split_once('/').ok_or_else(bad)?;
    let rt = runtime.instances().find(|i| i.config.name == instance).ok_or_else(bad)?;
    let client = &*rt.client;
    let data = match name {
        "status" => client.get("core/system/status", RequestOptions::new()).await?,
        "interfaces" => Value::Array(fetch_all(client, "interfaces/overview/interfaces_info", None, FETCH_ALL_MAX).await?),
        "aliases" => Value::Array(fetch_all(client, "firewall/alias/search_item", None, FETCH_ALL_MAX).await?),
        "rules" => {
            let rows = fetch_all(client, "firewall/filter/search_rule", None, FETCH_ALL_MAX).await?;
            Value::Array(rows.into_iter().filter(|r| !is_truthy(r.get("is_automatic"))).collect())
        }
        _ => return Err(bad()),
    };
    Ok(json!({ "contents": [{ "uri": uri, "mimeType": "application/json", "text": data.to_string() }] }))
}

fn is_truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(_) => true,
    }
}

//! Lecture de la configuration complète (config.xml), partagée par plusieurs domaines.

use crate::client::RequestOptions;
use crate::error::{ErrorType, OpnError, Result};
use crate::redact::{config_xml_to_json, redact_config_xml};
use crate::tool::Ctx;
use serde_json::Value;

#[derive(Default, Clone)]
pub struct ConfigOptions {
    /// Une sauvegarde précise, sinon la configuration actuelle.
    pub backup: Option<String>,
    pub include_sensitive: bool,
}

fn assert_sensitive_allowed(ctx: &Ctx, opts: &ConfigOptions) -> Result<()> {
    if opts.include_sensitive && !ctx.instance.allow_sensitive {
        return Err(OpnError::new(
            ErrorType::SensitiveDisabled,
            "include_sensitive requires the operator to set OPNSENSE_ALLOW_SENSITIVE=true.",
        )
        .hint("Do not retry. Without it, passwords and keys stay redacted."));
    }
    Ok(())
}

async fn download_raw(ctx: &Ctx, opts: &ConfigOptions) -> Result<String> {
    let mut params = vec!["this".to_string()];
    if let Some(b) = &opts.backup {
        params.push(b.clone());
    }
    // Le corps brut ne sort du client que parce que les deux appelants ci-dessous le masquent d'abord.
    let xml = ctx
        .api
        .get(
            "core/backup/download",
            RequestOptions::new()
                .params(params)
                .text()
                .redacted_by_caller(),
        )
        .await?;
    Ok(match xml {
        Value::String(s) => s,
        other => other.to_string(),
    })
}

pub async fn fetch_config_xml(ctx: &Ctx, opts: &ConfigOptions) -> Result<String> {
    assert_sensitive_allowed(ctx, opts)?;
    let xml = download_raw(ctx, opts).await?;
    if opts.include_sensitive {
        Ok(xml)
    } else {
        redact_config_xml(&xml)
    }
}

pub async fn fetch_config_json(ctx: &Ctx, opts: &ConfigOptions) -> Result<Value> {
    assert_sensitive_allowed(ctx, opts)?;
    config_xml_to_json(&download_raw(ctx, opts).await?, !opts.include_sensitive)
}

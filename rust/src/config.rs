//! Configuration : variables d'environnement ou fichier OPNSENSE_CONFIG (plusieurs pare-feu).
//! Une faute de frappe dans une option de sécurité arrête le serveur au lieu d'appliquer un défaut.

use crate::error::{ErrorType, OpnError, Result};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Table ordonnée : l'ordre des instances définit l'instance par défaut.
#[derive(Clone, Debug)]
pub struct OrderedMap<V> {
    items: Vec<(String, V)>,
}

impl<V> Default for OrderedMap<V> {
    fn default() -> Self {
        Self { items: Vec::new() }
    }
}

impl<V> OrderedMap<V> {
    pub fn insert(&mut self, key: String, value: V) {
        if let Some(slot) = self.items.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.items.push((key, value));
        }
    }
    pub fn get(&self, key: &str) -> Option<&V> {
        self.items.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
    pub fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.items.iter().map(|(k, _)| k)
    }
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.items.iter().map(|(_, v)| v)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&String, &V)> {
        self.items.iter().map(|(k, v)| (k, v))
    }
}

#[derive(Clone, Debug)]
pub struct InstanceConfig {
    pub name: String,
    /// URL de base, sans barre finale et sans le suffixe /api.
    pub url: String,
    pub api_key: String,
    pub api_secret: String,
    pub verify_ssl: bool,
    /// Lot PEM à qui faire confiance (certificat auto-signé avec vérification gardée).
    pub ca: Option<String>,
    pub allow_writes: bool,
    pub allow_sensitive: bool,
    pub dry_run: bool,
    pub description: Option<String>,
    /// Adresse source vue par le pare-feu, quand un NAT ou un VPN masque l'adresse locale.
    pub management_source: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub instances: OrderedMap<InstanceConfig>,
    pub default_instance: String,
    /// None = tous les domaines.
    pub toolsets: Option<HashSet<String>>,
    pub rollback_seconds: u64,
    pub audit_log: Option<String>,
    /// Points d'API que l'opérateur a explicitement retirés de la liste de blocage.
    pub unblocked: Vec<String>,
    pub elicit: bool,
    pub max_response_chars: usize,
}

pub type Env = HashMap<String, String>;

pub fn process_env() -> Env {
    std::env::vars().collect()
}

static INSTANCE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,32}$").unwrap());
static VAR_REF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}").unwrap());

fn config_error(message: impl Into<String>, hint: Option<&str>) -> OpnError {
    let e = OpnError::new(ErrorType::ConfigError, message);
    match hint {
        Some(h) => e.hint(h),
        None => e,
    }
}

fn parse_bool(name: &str, value: Option<&str>, fallback: bool) -> Result<bool> {
    let Some(v) = value else { return Ok(fallback) };
    match v.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" | "" => Ok(false),
        _ => Err(config_error(
            format!("{name}: \"{v}\" is not a boolean (use true or false)."),
            None,
        )),
    }
}

fn parse_integer(
    name: &str,
    value: Option<&str>,
    fallback: u64,
    min: u64,
    max: u64,
) -> Result<u64> {
    let Some(v) = value else { return Ok(fallback) };
    if v.is_empty() {
        return Ok(fallback);
    }
    match v.trim().parse::<u64>() {
        Ok(n) if n >= min && n <= max => Ok(n),
        _ => Err(config_error(
            format!("{name}: \"{v}\" must be an integer between {min} and {max}."),
            None,
        )),
    }
}

fn normalize_url(raw: &str, label: &str) -> Result<String> {
    let url = url::Url::parse(raw).map_err(|_| {
        config_error(
            format!("{label}: \"{raw}\" is not a valid URL."),
            Some("Example: https://192.168.1.1 or https://fw.example.com:10443"),
        )
    })?;
    if url.scheme() != "https" && url.scheme() != "http" {
        return Err(config_error(
            format!("{label}: only http and https URLs are supported."),
            None,
        ));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(config_error(
            format!("{label}: do not put credentials in the URL."),
            None,
        ));
    }
    let path = url.path().trim_end_matches('/');
    let path = path.strip_suffix("/api").unwrap_or(path);
    let host = url.host_str().unwrap_or_default();
    // host_str() garde déjà les crochets d'une adresse IPv6.
    let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();
    Ok(format!("{}://{}{}{}", url.scheme(), host, port, path))
}

struct Credentials {
    key: Option<String>,
    secret: Option<String>,
}

/// Lit le fichier apikey.txt qu'OPNsense propose à la création d'une clé (key=... / secret=...).
fn read_credentials_file(path: &str) -> Result<Credentials> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| config_error(format!("Cannot read credentials file {path}: {e}"), None))?;
    let mut out = Credentials {
        key: None,
        secret: None,
    };
    for line in text.lines() {
        if let Some((name, value)) = line.split_once('=') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            match name.trim() {
                "key" => out.key = Some(value.to_string()),
                "secret" => out.secret = Some(value.to_string()),
                _ => {}
            }
        }
    }
    Ok(out)
}

fn read_ca(path: Option<&str>) -> Result<Option<String>> {
    match path {
        None => Ok(None),
        Some(p) => std::fs::read_to_string(p)
            .map(Some)
            .map_err(|e| config_error(format!("Cannot read CA file {p}: {e}"), None)),
    }
}

/// Développe ${VAR} pour qu'instances.json n'ait jamais à contenir de secret en clair.
fn expand(value: &str, env: &Env, wher: &str) -> Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut last = 0;
    for caps in VAR_REF.captures_iter(value) {
        let m = caps.get(0).unwrap();
        out.push_str(&value[last..m.start()]);
        let name = &caps[1];
        match env.get(name) {
            Some(v) => out.push_str(v),
            None => {
                return Err(config_error(
                    format!("{wher}: environment variable {name} is not set."),
                    None,
                ))
            }
        }
        last = m.end();
    }
    out.push_str(&value[last..]);
    Ok(out)
}

struct Defaults {
    allow_writes: bool,
    allow_sensitive: bool,
    dry_run: bool,
    timeout_ms: u64,
}

fn text_of(raw: &Value, key: &str, env: Option<&Env>, wher: &str) -> Result<Option<String>> {
    match raw.get(key) {
        Some(Value::String(s)) => {
            let v = match env {
                Some(e) => expand(s, e, wher)?,
                None => s.clone(),
            };
            Ok(if v.is_empty() { None } else { Some(v) })
        }
        _ => Ok(None),
    }
}

fn bool_of(
    raw: &Value,
    key: &str,
    env: Option<&Env>,
    wher: &str,
    label: &str,
    fallback: bool,
) -> Result<bool> {
    match raw.get(key) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(Value::String(_)) => {
            let s = text_of(raw, key, env, wher)?;
            parse_bool(label, s.as_deref(), fallback)
        }
        _ => Ok(fallback),
    }
}

fn build_instance(
    name: &str,
    raw: &Value,
    env: Option<&Env>,
    defaults: &Defaults,
) -> Result<InstanceConfig> {
    if !INSTANCE_NAME.is_match(name) {
        return Err(config_error(format!("Invalid instance name \"{name}\": use letters, digits, - and _ (32 characters at most)."), None));
    }
    let wher = format!("instance \"{name}\"");
    let url_raw = text_of(raw, "url", env, &wher)?
        .ok_or_else(|| config_error(format!("{wher}: url is required."), None))?;
    let from_file = match text_of(raw, "credentials_file", env, &wher)? {
        Some(f) => read_credentials_file(&f)?,
        None => Credentials {
            key: None,
            secret: None,
        },
    };
    let api_key = text_of(raw, "api_key", env, &wher)?.or(from_file.key);
    let api_secret = text_of(raw, "api_secret", env, &wher)?.or(from_file.secret);
    let (Some(api_key), Some(api_secret)) = (api_key, api_secret) else {
        return Err(config_error(format!("{wher}: API key and secret are required."), Some("Set api_key/api_secret, or credentials_file pointing at the apikey.txt downloaded from OPNsense.")));
    };
    let url = normalize_url(&url_raw, &wher)?;
    let timeout_ms = match raw.get("timeout_seconds") {
        None | Some(Value::Null) => defaults.timeout_ms,
        Some(v) => {
            let s = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            parse_integer(&format!("{wher} timeout_seconds"), Some(&s), 30, 1, 600)? * 1000
        }
    };
    Ok(InstanceConfig {
        name: name.to_string(),
        url,
        api_key,
        api_secret,
        verify_ssl: bool_of(
            raw,
            "verify_ssl",
            env,
            &wher,
            &format!("{wher} verify_ssl"),
            true,
        )?,
        ca: read_ca(text_of(raw, "ca_file", env, &wher)?.as_deref())?,
        allow_writes: bool_of(
            raw,
            "allow_writes",
            env,
            &wher,
            &format!("{wher} allow_writes"),
            defaults.allow_writes,
        )?,
        allow_sensitive: bool_of(
            raw,
            "allow_sensitive",
            env,
            &wher,
            &format!("{wher} allow_sensitive"),
            defaults.allow_sensitive,
        )?,
        dry_run: bool_of(
            raw,
            "dry_run",
            env,
            &wher,
            &format!("{wher} dry_run"),
            defaults.dry_run,
        )?,
        description: text_of(raw, "description", env, &wher)?,
        management_source: text_of(raw, "management_source", env, &wher)?,
        timeout_ms,
    })
}

pub fn load_config(env: &Env) -> Result<ServerConfig> {
    let get = |k: &str| env.get(k).map(String::as_str);
    let defaults = Defaults {
        allow_writes: parse_bool("OPNSENSE_ALLOW_WRITES", get("OPNSENSE_ALLOW_WRITES"), false)?,
        allow_sensitive: parse_bool(
            "OPNSENSE_ALLOW_SENSITIVE",
            get("OPNSENSE_ALLOW_SENSITIVE"),
            false,
        )?,
        dry_run: parse_bool("OPNSENSE_DRY_RUN", get("OPNSENSE_DRY_RUN"), false)?,
        timeout_ms: parse_integer(
            "OPNSENSE_TIMEOUT_SECONDS",
            get("OPNSENSE_TIMEOUT_SECONDS"),
            30,
            1,
            600,
        )? * 1000,
    };

    let mut instances: OrderedMap<InstanceConfig> = OrderedMap::default();
    let mut default_instance: Option<String> = None;

    if let Some(path) = get("OPNSENSE_CONFIG").filter(|p| !p.is_empty()) {
        let parsed: Value = std::fs::read_to_string(path)
            .map_err(|e| e.to_string())
            .and_then(|t| serde_json::from_str(&t).map_err(|e| e.to_string()))
            .map_err(|e| {
                config_error(format!("Cannot read OPNSENSE_CONFIG ({path}): {e}"), None)
            })?;
        if let Some(map) = parsed.get("instances").and_then(Value::as_object) {
            for (name, raw) in map {
                instances.insert(
                    name.clone(),
                    build_instance(name, raw, Some(env), &defaults)?,
                );
            }
        }
        if instances.is_empty() {
            return Err(config_error("OPNSENSE_CONFIG defines no instances.", None));
        }
        if let Some(d) = parsed.get("default").and_then(Value::as_str) {
            if !instances.contains_key(d) {
                return Err(config_error(
                    format!("Default instance \"{d}\" is not defined."),
                    None,
                ));
            }
            default_instance = Some(d.to_string());
        }
    } else {
        let Some(url) = get("OPNSENSE_URL").filter(|u| !u.is_empty()) else {
            return Err(config_error("OPNSENSE_URL is not set.", Some("Set OPNSENSE_URL, OPNSENSE_API_KEY and OPNSENSE_API_SECRET, or OPNSENSE_CONFIG for several firewalls.")));
        };
        let mut raw = serde_json::Map::new();
        raw.insert("url".into(), Value::String(url.to_string()));
        for (field, var) in [
            ("api_key", "OPNSENSE_API_KEY"),
            ("api_secret", "OPNSENSE_API_SECRET"),
            ("credentials_file", "OPNSENSE_API_CREDENTIALS_FILE"),
            ("verify_ssl", "OPNSENSE_VERIFY_SSL"),
            ("ca_file", "OPNSENSE_CA_FILE"),
            ("management_source", "OPNSENSE_MANAGEMENT_SOURCE"),
        ] {
            if let Some(v) = get(var) {
                raw.insert(field.into(), Value::String(v.to_string()));
            }
        }
        // Valeurs issues de l'environnement : ce ne sont pas des modèles ${VAR}.
        instances.insert(
            "default".into(),
            build_instance("default", &Value::Object(raw), None, &defaults)?,
        );
    }

    let toolsets = get("OPNSENSE_TOOLSETS").filter(|s| !s.is_empty()).map(|s| {
        s.split(',')
            .map(|x| x.trim().to_lowercase())
            .filter(|x| !x.is_empty())
            .collect::<HashSet<_>>()
    });
    let default_instance =
        default_instance.unwrap_or_else(|| instances.keys().next().cloned().unwrap_or_default());
    Ok(ServerConfig {
        instances,
        default_instance,
        toolsets,
        rollback_seconds: parse_integer(
            "OPNSENSE_ROLLBACK_SECONDS",
            get("OPNSENSE_ROLLBACK_SECONDS"),
            120,
            30,
            3600,
        )?,
        unblocked: get("OPNSENSE_UNBLOCK")
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        elicit: parse_bool("OPNSENSE_ELICIT", get("OPNSENSE_ELICIT"), true)?,
        max_response_chars: parse_integer(
            "OPNSENSE_MAX_RESPONSE_CHARS",
            get("OPNSENSE_MAX_RESPONSE_CHARS"),
            120_000,
            2_000,
            5_000_000,
        )? as usize,
        audit_log: get("OPNSENSE_AUDIT_LOG")
            .filter(|s| !s.is_empty())
            .map(String::from),
    })
}

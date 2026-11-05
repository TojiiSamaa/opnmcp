//! Client HTTP de l'API OPNsense : le point de passage unique. Chaque appel au pare-feu traverse
//! la politique d'accès (`policy::authorize`) avant de partir.

use crate::config::InstanceConfig;
use crate::error::{ErrorType, OpnError, Result};
use crate::model::PostClient;
use crate::policy::{authorize, Access, AuthorizeOptions, Decision, PolicySubject};
use crate::redact::{assert_no_redacted_value, redact_json, scrub_text};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
}

impl Method {
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// Requête simulée par un essai à blanc.
#[derive(Clone, Debug)]
pub struct DryRunEntry {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
}

impl DryRunEntry {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("method".into(), json!(self.method.as_str()));
        m.insert("path".into(), json!(self.path));
        if let Some(b) = &self.body {
            m.insert("body".into(), b.clone());
        }
        Value::Object(m)
    }
}

pub type DryRunLog = Arc<Mutex<Vec<DryRunEntry>>>;

/// Écriture réellement envoyée, pour le journal d'audit.
#[derive(Clone, Debug)]
pub struct WriteRecord {
    pub method: Method,
    pub path: String,
    pub body: Option<Value>,
    pub status: String,
}

impl WriteRecord {
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("method".into(), json!(self.method.as_str()));
        m.insert("path".into(), json!(self.path));
        if let Some(b) = &self.body {
            m.insert("body".into(), b.clone());
        }
        m.insert("status".into(), json!(self.status));
        Value::Object(m)
    }
}

pub type WriteHook = Arc<dyn Fn(WriteRecord) + Send + Sync>;

#[derive(Clone, Debug, Default)]
pub struct RequestOptions {
    pub body: Option<Value>,
    pub query: Vec<(String, String)>,
    /// Segments de chemin en plus (uuid, nom de service...), validés un par un.
    pub params: Vec<String>,
    /// Renvoyer le corps en texte plutôt qu'en JSON.
    pub text: bool,
    /// Garder les secrets dans la réponse. Seulement si l'instance autorise les données sensibles.
    pub include_sensitive: bool,
    pub timeout_ms: Option<u64>,
    /// Ouvrir une nouvelle connexion : une connexion gardée survit au rechargement de pf et ne prouve rien.
    pub fresh_connection: bool,
    /// Simuler cette écriture au lieu de l'envoyer.
    pub dry_run: bool,
    /// Rempli avec les requêtes qu'un essai à blanc aurait envoyées.
    pub dry_run_log: Option<DryRunLog>,
    pub auth: AuthorizeOptions,
}

impl RequestOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn param(mut self, p: impl ToString) -> Self {
        self.params.push(p.to_string());
        self
    }
    pub fn params<I, S>(mut self, ps: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: ToString,
    {
        self.params.extend(ps.into_iter().map(|p| p.to_string()));
        self
    }
    pub fn query(mut self, k: impl ToString, v: impl ToString) -> Self {
        self.query.push((k.to_string(), v.to_string()));
        self
    }
    pub fn text(mut self) -> Self {
        self.text = true;
        self
    }
    pub fn timeout_ms(mut self, ms: u64) -> Self {
        self.timeout_ms = Some(ms);
        self
    }
    pub fn fresh(mut self) -> Self {
        self.fresh_connection = true;
        self
    }
    pub fn curated(mut self) -> Self {
        self.auth.curated = true;
        self
    }
    pub fn redacted_by_caller(mut self) -> Self {
        self.auth.redacted_by_caller = true;
        self
    }
    pub fn include_sensitive(mut self, yes: bool) -> Self {
        self.include_sensitive = yes;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApiStyle {
    SnakeCase,
    CamelCase,
}

#[derive(Clone, Debug)]
pub struct Capabilities {
    /// None si la version n'a pas pu être lue (l'utilisateur d'API n'a pas le privilège firmware).
    pub version: Option<String>,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub api_style: ApiStyle,
    /// Minuteur de rollback natif côté pare-feu. Supprimé en amont dans OPNsense 26.7.
    pub native_savepoints: Option<bool>,
}

impl Capabilities {
    /// Même forme que la version TypeScript (clés en camelCase).
    pub fn to_json(&self) -> Value {
        json!({
            "version": self.version,
            "major": self.major,
            "minor": self.minor,
            "apiStyle": if self.api_style == ApiStyle::SnakeCase { "snake_case" } else { "camelCase" },
            "nativeSavepoints": self.native_savepoints,
        })
    }
}

/// Identifiant factice renvoyé par les créations simulées, pour que les étapes suivantes tournent encore.
pub const DRY_RUN_UUID: &str = "00000000-0000-4000-8000-000000000000";

const MAX_RETRIES: u32 = 2;
const MAX_CONCURRENCY: usize = 4;

static VERSION_RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\d+)\.(\d+)").unwrap());
static HTML_TYPE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)text/html").unwrap());
static HTML_BODY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^\s*<(!doctype|html)").unwrap());

/// Action en snake_case vers camelCase, comme les pare-feu antérieurs à 25.7 l'attendent.
pub fn to_camel_action(action: &str) -> String {
    let mut out = String::with_capacity(action.len());
    let mut upper_next = false;
    for c in action.chars() {
        if c == '_' {
            upper_next = true;
        } else if upper_next && c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_uppercase());
            upper_next = false;
        } else {
            if upper_next {
                out.push('_');
                upper_next = false;
            }
            out.push(c);
        }
    }
    if upper_next {
        out.push('_');
    }
    out
}

pub fn parse_version(version: &str) -> Option<(u32, u32)> {
    let c = VERSION_RE.captures(version)?;
    Some((c[1].parse().ok()?, c[2].parse().ok()?))
}

fn at_least(major: u32, minor: u32, want_major: u32, want_minor: u32) -> bool {
    major > want_major || (major == want_major && minor >= want_minor)
}

struct RawResponse {
    status: u16,
    content_type: String,
    body: String,
}

pub struct OpnsenseClient {
    pub config: Arc<InstanceConfig>,
    unblocked: Vec<String>,
    on_write: Option<WriteHook>,
    http: reqwest::Client,
    base: url::Url,
    semaphore: Semaphore,
    caps: Mutex<Option<Capabilities>>,
    caps_init: tokio::sync::Mutex<()>,
    addresses: Mutex<(Option<String>, Option<String>)>,
}

fn build_http(config: &InstanceConfig, keep_alive: bool) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("osmcp/", env!("CARGO_PKG_VERSION")));
    if !keep_alive {
        builder = builder.pool_max_idle_per_host(0);
    } else {
        builder = builder
            .pool_max_idle_per_host(MAX_CONCURRENCY)
            .tcp_keepalive(Duration::from_secs(30));
    }
    if config.url.starts_with("https:") {
        builder = builder.danger_accept_invalid_certs(!config.verify_ssl);
        if let Some(ca) = &config.ca {
            let certs = reqwest::Certificate::from_pem_bundle(ca.as_bytes()).map_err(|e| {
                OpnError::new(
                    ErrorType::ConfigError,
                    format!("OPNSENSE_CA_FILE: the CA bundle is not valid PEM: {e}"),
                )
            })?;
            // Comme l'option `ca` de Node : seules ces autorités sont de confiance.
            builder = builder.tls_built_in_root_certs(false);
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
    }
    builder.build().map_err(|e| {
        OpnError::new(
            ErrorType::ConfigError,
            format!("Cannot build the HTTP client: {e}"),
        )
    })
}

impl OpnsenseClient {
    pub fn new(
        config: Arc<InstanceConfig>,
        unblocked: Vec<String>,
        on_write: Option<WriteHook>,
    ) -> Result<Self> {
        let base = url::Url::parse(&config.url).map_err(|_| {
            OpnError::new(
                ErrorType::ConfigError,
                format!("{} is not a valid URL.", config.url),
            )
        })?;
        let http = build_http(&config, true)?;
        Ok(Self {
            config,
            unblocked,
            on_write,
            http,
            base,
            semaphore: Semaphore::new(MAX_CONCURRENCY),
            caps: Mutex::new(None),
            caps_init: tokio::sync::Mutex::new(()),
            addresses: Mutex::new((None, None)),
        })
    }

    /// Dernière adresse locale vue pour la connexion au pare-feu, pour le contrôle de verrouillage.
    pub fn local_address(&self) -> Option<String> {
        self.addresses.lock().unwrap().0.clone()
    }
    pub fn remote_address(&self) -> Option<String> {
        self.addresses.lock().unwrap().1.clone()
    }

    pub async fn get(&self, path: &str, opts: RequestOptions) -> Result<Value> {
        self.request(Method::Get, path, opts).await
    }

    pub async fn post(
        &self,
        path: &str,
        body: Option<Value>,
        mut opts: RequestOptions,
    ) -> Result<Value> {
        opts.body = body;
        self.request(Method::Post, path, opts).await
    }

    /// Le point de passage : tout appel au pare-feu passe ici, et par la politique.
    pub async fn request(&self, method: Method, path: &str, opts: RequestOptions) -> Result<Value> {
        let mut full_path = path.to_string();
        for p in &opts.params {
            full_path.push('/');
            full_path.push_str(p);
        }
        let subject = PolicySubject {
            name: &self.config.name,
            allow_writes: self.config.allow_writes,
            allow_sensitive: self.config.allow_sensitive,
            dry_run: self.config.dry_run,
        };
        let decision = authorize(
            &subject,
            &full_path,
            method == Method::Get,
            &self.unblocked,
            opts.auth,
        )?;
        if let Some(body) = &opts.body {
            assert_no_redacted_value(body, path)?;
        }

        if decision.access == Access::Write && (opts.dry_run || self.config.dry_run) {
            return Ok(self.simulate_write(method, &full_path, &opts));
        }

        let caps = self.capabilities().await?;
        let styled = styled_path(&full_path, caps.api_style);
        let mut response = match self.send(method, &styled, &opts).await {
            Ok(r) => r,
            Err(e) => {
                self.audit_write(
                    &decision,
                    method,
                    &full_path,
                    opts.body.as_ref(),
                    format!("error: {}", e.message),
                );
                return Err(e);
            }
        };
        // Version inconnue : un 404 en snake_case peut venir d'un pare-feu antérieur à 25.7.
        if response.status == 404 && caps.version.is_none() && caps.api_style == ApiStyle::SnakeCase
        {
            let camel = styled_path(&full_path, ApiStyle::CamelCase);
            if camel != full_path {
                let retried = self.send(method, &camel, &opts).await?;
                if retried.status != 404 {
                    if let Some(c) = self.caps.lock().unwrap().as_mut() {
                        c.api_style = ApiStyle::CamelCase;
                    }
                    response = retried;
                }
            }
        }
        self.audit_write(
            &decision,
            method,
            &full_path,
            opts.body.as_ref(),
            response.status.to_string(),
        );
        self.parse(&response, &full_path, method, &decision, &opts)
    }

    /// Détecte la version une fois. Ne lève rien d'autre qu'une panne de connexion : une version inconnue veut dire « sonder plus tard ».
    pub async fn capabilities(&self) -> Result<Capabilities> {
        if let Some(c) = self.caps.lock().unwrap().clone() {
            return Ok(c);
        }
        let _guard = self.caps_init.lock().await;
        if let Some(c) = self.caps.lock().unwrap().clone() {
            return Ok(c);
        }
        let caps = self.detect_capabilities().await?;
        *self.caps.lock().unwrap() = Some(caps.clone());
        Ok(caps)
    }

    /// Appelé quand le point de savepoint manque sur une version inconnue.
    pub fn note_no_native_savepoints(&self) {
        if let Some(c) = self.caps.lock().unwrap().as_mut() {
            c.native_savepoints = Some(false);
        }
    }

    async fn detect_capabilities(&self) -> Result<Capabilities> {
        let unknown = Capabilities {
            version: None,
            major: None,
            minor: None,
            api_style: ApiStyle::SnakeCase,
            native_savepoints: None,
        };
        let response = match self
            .send(Method::Get, "core/firmware/status", &RequestOptions::new())
            .await
        {
            Ok(r) => r,
            // Les pannes de connexion et de TLS concernent tous les appels : l'appelant doit les voir tout de suite.
            Err(e)
                if e.is_any(&[
                    ErrorType::Unreachable,
                    ErrorType::Timeout,
                    ErrorType::TlsError,
                ]) =>
            {
                return Err(e)
            }
            Err(_) => return Ok(unknown),
        };
        if response.status == 401 {
            return Err(self.status_error(&response, "core/firmware/status"));
        }
        if response.status != 200 {
            return Ok(unknown);
        }
        let Ok(body) = serde_json::from_str::<Value>(&response.body) else {
            return Ok(unknown);
        };
        // OPNsense 26.x l'imbrique sous "product" ; les versions plus anciennes l'ont au niveau supérieur.
        let version = body
            .pointer("/product/product_version")
            .or_else(|| body.get("product_version"))
            .and_then(Value::as_str);
        let Some(version) = version else {
            return Ok(unknown);
        };
        let Some((major, minor)) = parse_version(version) else {
            return Ok(Capabilities {
                version: Some(version.to_string()),
                ..unknown
            });
        };
        Ok(Capabilities {
            version: Some(version.to_string()),
            major: Some(major),
            minor: Some(minor),
            // Les motifs d'ACL sont sensibles à la casse et suivent cette convention : un utilisateur restreint
            // reçoit un 403 avec le mauvais style même si le routeur accepterait les deux.
            api_style: if at_least(major, minor, 25, 7) {
                ApiStyle::SnakeCase
            } else {
                ApiStyle::CamelCase
            },
            native_savepoints: Some(!at_least(major, minor, 26, 7)),
        })
    }

    fn simulate_write(&self, method: Method, path: &str, opts: &RequestOptions) -> Value {
        if let Some(log) = &opts.dry_run_log {
            log.lock().unwrap().push(DryRunEntry {
                method,
                path: path.to_string(),
                body: opts.body.as_ref().map(redact_json),
            });
        }
        json!({ "result": "saved", "status": "ok", "uuid": DRY_RUN_UUID, "dry_run": true })
    }

    fn audit_write(
        &self,
        decision: &Decision,
        method: Method,
        path: &str,
        body: Option<&Value>,
        status: String,
    ) {
        if decision.access != Access::Write {
            return;
        }
        if let Some(hook) = &self.on_write {
            hook(WriteRecord {
                method,
                path: path.to_string(),
                body: body.map(redact_json),
                status,
            });
        }
    }

    fn parse(
        &self,
        response: &RawResponse,
        path: &str,
        method: Method,
        decision: &Decision,
        opts: &RequestOptions,
    ) -> Result<Value> {
        if !(200..300).contains(&response.status) {
            return Err(self.status_error(response, path));
        }
        let keep_secrets = opts.include_sensitive && self.config.allow_sensitive;
        if opts.text {
            let text = if keep_secrets || opts.auth.redacted_by_caller {
                response.body.clone()
            } else {
                scrub_text(&response.body)
            };
            return Ok(Value::String(text));
        }
        if HTML_TYPE.is_match(&response.content_type) || HTML_BODY.is_match(&response.body) {
            return Err(OpnError::new(ErrorType::BadResponse, format!("The firewall answered {path} with an HTML page instead of JSON."))
                .hint("Check OPNSENSE_URL: it should point at the OPNsense web interface, without a reverse proxy login page in front. A session redirect also produces this."));
        }
        let json: Value = if response.body.is_empty() {
            json!({})
        } else {
            match serde_json::from_str(&response.body) {
                Ok(v) => v,
                Err(_) => {
                    // Les exports répondent en CSV ou en texte brut même sans l'option text.
                    if decision.sensitive || method == Method::Get {
                        let text = if keep_secrets {
                            response.body.clone()
                        } else {
                            scrub_text(&response.body)
                        };
                        return Ok(json!({ "text": text }));
                    }
                    return Err(OpnError::new(
                        ErrorType::BadResponse,
                        format!("The firewall returned invalid JSON for {path}."),
                    ));
                }
            }
        };
        Ok(if keep_secrets {
            json
        } else {
            redact_json(&json)
        })
    }

    fn status_error(&self, response: &RawResponse, path: &str) -> OpnError {
        let status = response.status;
        let message = serde_json::from_str::<Value>(&response.body)
            .ok()
            .and_then(|b| {
                b.get("message")
                    .or_else(|| b.get("errorMessage"))
                    .and_then(Value::as_str)
                    .map(scrub_text)
            });
        let detail = message.map(|m| format!(" ({m})")).unwrap_or_default();
        match status {
            401 => OpnError::new(ErrorType::AuthFailed, format!("The firewall rejected the API credentials{detail}."))
                .status(status)
                .hint("Check the API key and secret, and that the user is not disabled. Do not retry with the same credentials."),
            403 => OpnError::new(ErrorType::Forbidden, format!("The API user has no privilege for {path}{detail}."))
                .status(status)
                .hint("The credentials are fine: this is a missing privilege on this endpoint. Do not retry. Add the matching privilege to the user in System > Access, or use another tool."),
            404 => OpnError::new(ErrorType::NotFound, format!("{path} does not exist on this firewall{detail}."))
                .status(status)
                .hint("The plugin that provides it may not be installed (see opn_list_plugins), or this OPNsense version does not have this endpoint. With a uuid, the item may no longer exist."),
            400 => OpnError::new(ErrorType::BadRequest, format!("The firewall rejected the request to {path}{detail}.")).status(status),
            _ => {
                let e = OpnError::new(ErrorType::UpstreamError, format!("The firewall answered {path} with HTTP {status}{detail}.")).status(status);
                if status >= 500 {
                    e.hint("A server-side error. opn_system_log may tell why.")
                } else {
                    e
                }
            }
        }
    }

    async fn send(&self, method: Method, path: &str, opts: &RequestOptions) -> Result<RawResponse> {
        let _permit =
            self.semaphore.acquire().await.map_err(|_| {
                OpnError::new(ErrorType::InternalError, "the request queue was closed")
            })?;
        // Seules les lectures sont rejouées : répéter une écriture peut-être passée n'est pas sûr.
        let attempts = if method == Method::Get {
            MAX_RETRIES + 1
        } else {
            1
        };
        let mut attempt = 1;
        loop {
            match self.send_once(method, path, opts).await {
                Ok(r) => {
                    if attempt < attempts && matches!(r.status, 502..=504) {
                        tokio::time::sleep(Duration::from_millis(attempt as u64 * 300)).await;
                        attempt += 1;
                        continue;
                    }
                    return Ok(r);
                }
                Err(e) => {
                    let retryable = e.is_any(&[ErrorType::Unreachable, ErrorType::Timeout]);
                    if attempt >= attempts || !retryable {
                        return Err(e);
                    }
                    tokio::time::sleep(Duration::from_millis(attempt as u64 * 300)).await;
                    attempt += 1;
                }
            }
        }
    }

    async fn send_once(
        &self,
        method: Method,
        path: &str,
        opts: &RequestOptions,
    ) -> Result<RawResponse> {
        let mut url = self.base.clone();
        let base_path = self.base.path().trim_end_matches('/');
        url.set_path(&format!("{base_path}/api/{path}"));
        if !opts.query.is_empty() {
            url.query_pairs_mut()
                .extend_pairs(opts.query.iter().map(|(k, v)| (k.as_str(), v.as_str())));
        }
        let timeout = Duration::from_millis(opts.timeout_ms.unwrap_or(self.config.timeout_ms));
        let fresh;
        let http = if opts.fresh_connection {
            fresh = build_http(&self.config, false)?;
            &fresh
        } else {
            &self.http
        };
        let mut req = match method {
            Method::Get => http.get(url),
            Method::Post => http.post(url),
        }
        .basic_auth(&self.config.api_key, Some(&self.config.api_secret))
        .header("Accept", "application/json")
        .timeout(timeout);
        if method == Method::Post {
            // Un type JSON avec un corps vide fait répondre 400 « Invalid JSON syntax » à OPNsense.
            let payload = serde_json::to_string(opts.body.as_ref().unwrap_or(&json!({})))
                .unwrap_or_else(|_| "{}".into());
            req = req.header("Content-Type", "application/json").body(payload);
        }
        let response = req
            .send()
            .await
            .map_err(|e| self.network_error(&e, path, timeout))?;
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let remote = response.remote_addr();
        let bytes = response
            .bytes()
            .await
            .map_err(|e| self.network_error(&e, path, timeout))?;
        if let Some(remote) = remote {
            let local = local_address_towards(remote);
            *self.addresses.lock().unwrap() = (
                local.or_else(|| self.addresses.lock().unwrap().0.clone()),
                Some(remote.ip().to_string()),
            );
        }
        Ok(RawResponse {
            status,
            content_type,
            body: String::from_utf8_lossy(&bytes).into_owned(),
        })
    }

    fn network_error(&self, err: &reqwest::Error, path: &str, timeout: Duration) -> OpnError {
        if err.is_timeout() {
            return OpnError::new(ErrorType::Timeout, format!("The firewall did not answer {path} within {} s.", timeout.as_secs()))
                .hint("If a firewall change was just applied, it may have cut this connection: see opn_pending_changes.");
        }
        let mut chain = vec![err.to_string()];
        let mut source = std::error::Error::source(err);
        while let Some(s) = source {
            chain.push(s.to_string());
            source = s.source();
        }
        let joined = chain.join(": ").to_lowercase();
        let leaf = chain.last().cloned().unwrap_or_default();
        if [
            "certificate",
            "tls",
            "ssl",
            "handshake",
            "unknownissuer",
            "invalid peer",
        ]
        .iter()
        .any(|k| joined.contains(k))
        {
            return OpnError::new(ErrorType::TlsError, format!("The TLS certificate of {} was refused ({leaf}).", self.config.url))
                .hint("OPNsense uses a self-signed certificate by default. Point OPNSENSE_CA_FILE at the certificate to keep verification on, or set OPNSENSE_VERIFY_SSL=false on a trusted network.");
        }
        OpnError::new(ErrorType::Unreachable, format!("Cannot reach the firewall for {path} ({}).", scrub_text(&leaf)))
            .hint("Check the URL and port, and that this host may access the web interface (System > Settings > Administration). If a firewall change was just applied, see opn_pending_changes.")
    }
}

impl PostClient for OpnsenseClient {
    async fn post_json(&self, path: &str, body: Option<Value>) -> Result<Value> {
        self.post(path, body, RequestOptions::new()).await
    }
}

/// Adresse locale que le système choisirait pour joindre `remote` (aucun paquet n'est envoyé).
fn local_address_towards(remote: SocketAddr) -> Option<String> {
    let bind = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).ok()?;
    socket.connect(remote).ok()?;
    Some(socket.local_addr().ok()?.ip().to_string())
}

fn styled_path(path: &str, style: ApiStyle) -> String {
    if style == ApiStyle::SnakeCase {
        return path.to_string();
    }
    let mut segments: Vec<String> = path.split('/').map(String::from).collect();
    // Seule l'action est renommée : les contrôleurs gardent leur snake_case (firewall/d_nat).
    if let Some(action) = segments.get_mut(2) {
        if !action.is_empty() {
            *action = to_camel_action(action);
        }
    }
    segments.join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn camel_action() {
        assert_eq!(to_camel_action("search_rule"), "searchRule");
        assert_eq!(to_camel_action("get"), "get");
        assert_eq!(to_camel_action("a_b_c"), "aBC");
    }

    #[test]
    fn version_parsing() {
        assert_eq!(parse_version("25.7.3_1"), Some((25, 7)));
        assert_eq!(parse_version("x"), None);
        assert!(at_least(26, 7, 26, 7) && !at_least(26, 1, 26, 7) && at_least(27, 0, 26, 7));
    }

    #[test]
    fn styled_only_renames_the_action() {
        assert_eq!(
            styled_path("firewall/d_nat/search_rule", ApiStyle::CamelCase),
            "firewall/d_nat/searchRule"
        );
        assert_eq!(
            styled_path("firewall/d_nat/search_rule", ApiStyle::SnakeCase),
            "firewall/d_nat/search_rule"
        );
    }
}

//! Définition des outils MCP et aides communes aux domaines : contexte d'appel, écritures préparées,
//! écritures de service, jeu CRUD standard.

use crate::changes::{ChangeManager, ChangeScope, Protection};
use crate::client::{DryRunLog, OpnsenseClient, RequestOptions};
use crate::config::{InstanceConfig, ServerConfig};
use crate::error::{ErrorType, OpnError, Result};
use crate::model::{
    assert_applied, assert_write_ok, compact_grid, flatten_model, model_fields, search_grid,
    GridArgs, Obj, PostClient,
};
use crate::schema::{self, Field, Schema};
use serde_json::{json, Map, Value};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

pub type BoxFut<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// Les outils sont groupés par domaine, un fichier par domaine, filtrables avec OPNSENSE_TOOLSETS.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Domain {
    System,
    Network,
    Firewall,
    Nat,
    Dns,
    Dhcp,
    Vpn,
    Services,
    Haproxy,
    Diagnostics,
    Security,
    Api,
}

impl Domain {
    pub const ALL: [Domain; 12] = [
        Domain::System,
        Domain::Network,
        Domain::Firewall,
        Domain::Nat,
        Domain::Dns,
        Domain::Dhcp,
        Domain::Vpn,
        Domain::Services,
        Domain::Haproxy,
        Domain::Diagnostics,
        Domain::Security,
        Domain::Api,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Domain::System => "system",
            Domain::Network => "network",
            Domain::Firewall => "firewall",
            Domain::Nat => "nat",
            Domain::Dns => "dns",
            Domain::Dhcp => "dhcp",
            Domain::Vpn => "vpn",
            Domain::Services => "services",
            Domain::Haproxy => "haproxy",
            Domain::Diagnostics => "diagnostics",
            Domain::Security => "security",
            Domain::Api => "api",
        }
    }
    pub fn parse(s: &str) -> Option<Domain> {
        Domain::ALL.into_iter().find(|d| d.as_str() == s)
    }
}

/// read : ne change rien. write : ajoute ou change de façon réversible. destructive : supprime ou coupe du trafic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolAccess {
    Read,
    Write,
    Destructive,
}

/// Vue du client propre à un appel d'outil : ajoute l'essai à blanc et marque l'appel comme venant d'un outil dédié.
#[derive(Clone)]
pub struct ScopedApi {
    client: Arc<OpnsenseClient>,
    curated: bool,
    read_only: bool,
    dry_run: Option<DryRunLog>,
}

impl ScopedApi {
    pub fn new(
        client: Arc<OpnsenseClient>,
        curated: bool,
        read_only: bool,
        dry_run: Option<DryRunLog>,
    ) -> Self {
        Self {
            client,
            curated,
            read_only,
            dry_run,
        }
    }

    fn apply(&self, mut o: RequestOptions) -> RequestOptions {
        o.auth.curated |= self.curated;
        o.auth.read_only |= self.read_only;
        if let Some(log) = &self.dry_run {
            o.dry_run = true;
            o.dry_run_log = Some(log.clone());
        }
        o
    }

    pub async fn get(&self, path: &str, opts: RequestOptions) -> Result<Value> {
        self.client.get(path, self.apply(opts)).await
    }
    pub async fn post(
        &self,
        path: &str,
        body: Option<Value>,
        opts: RequestOptions,
    ) -> Result<Value> {
        self.client.post(path, body, self.apply(opts)).await
    }
    pub async fn get_(&self, path: &str) -> Result<Value> {
        self.get(path, RequestOptions::new()).await
    }
    pub async fn post_(&self, path: &str) -> Result<Value> {
        self.post(path, None, RequestOptions::new()).await
    }
}

impl PostClient for ScopedApi {
    async fn post_json(&self, path: &str, body: Option<Value>) -> Result<Value> {
        self.post(path, body, RequestOptions::new()).await
    }
}

pub struct Ctx {
    /// Pour les outils dédiés : leurs chemins sont écrits dans le code.
    pub api: ScopedApi,
    /// Pour les outils qui reçoivent le chemin en argument : les points d'accès réservés aux outils dédiés restent hors d'atteinte.
    pub generic: ScopedApi,
    pub client: Arc<OpnsenseClient>,
    pub instance: Arc<InstanceConfig>,
    pub server: Arc<ServerConfig>,
    pub changes: Arc<ChangeManager>,
    pub dry_run: bool,
    pub dry_run_log: DryRunLog,
}

/// Arguments validés d'un appel (clés inconnues déjà retirées).
#[derive(Clone, Default)]
pub struct Args(pub Map<String, Value>);

impl Args {
    pub fn get(&self, k: &str) -> Option<&Value> {
        self.0.get(k)
    }
    pub fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    pub fn str(&self, k: &str) -> Option<&str> {
        self.0.get(k).and_then(Value::as_str)
    }
    /// Pour les champs obligatoires : le schéma a déjà garanti leur présence.
    pub fn req(&self, k: &str) -> &str {
        self.str(k).unwrap_or("")
    }
    pub fn i64(&self, k: &str) -> Option<i64> {
        self.0
            .get(k)
            .and_then(|v| v.as_i64().or_else(|| v.as_f64().map(|f| f as i64)))
    }
    pub fn f64(&self, k: &str) -> Option<f64> {
        self.0.get(k).and_then(Value::as_f64)
    }
    pub fn bool(&self, k: &str) -> Option<bool> {
        self.0.get(k).and_then(Value::as_bool)
    }
    pub fn strs(&self, k: &str) -> Vec<String> {
        self.0
            .get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn obj(&self) -> &Obj {
        &self.0
    }
    pub fn to_value(&self) -> Value {
        Value::Object(self.0.clone())
    }
    pub fn grid(&self) -> GridArgs {
        GridArgs::from_args(&self.to_value())
    }
}

pub type Handler = Arc<dyn Fn(Args, Arc<Ctx>) -> BoxFut<Result<Value>> + Send + Sync>;
pub type Confirmation = Arc<dyn Fn(&Args) -> String + Send + Sync>;

pub struct ToolDef {
    pub name: String,
    pub title: String,
    pub description: String,
    pub domain: Domain,
    pub access: ToolAccess,
    pub idempotent: bool,
    /// L'outil sort du pare-feu lui-même (ping, DNS...).
    pub open_world: bool,
    /// Autres domaines qui ont besoin de cet outil, pour OPNSENSE_TOOLSETS.
    pub also: Vec<Domain>,
    pub input: Schema,
    /// Message pour l'humain quand l'accès est destructif et que le client sait demander.
    pub confirmation: Option<Confirmation>,
    pub handler: Handler,
}

pub struct ToolBuilder {
    def: ToolDef,
}

pub fn tool(
    name: impl Into<String>,
    title: impl Into<String>,
    description: impl Into<String>,
    domain: Domain,
    access: ToolAccess,
) -> ToolBuilder {
    ToolBuilder {
        def: ToolDef {
            name: name.into(),
            title: title.into(),
            description: description.into(),
            domain,
            access,
            idempotent: false,
            open_world: false,
            also: Vec::new(),
            input: Schema::default(),
            confirmation: None,
            handler: Arc::new(|_, _| {
                Box::pin(async {
                    Err(OpnError::new(
                        ErrorType::InternalError,
                        "tool without handler",
                    ))
                })
            }),
        },
    }
}

/// Outil de lecture idempotent, le cas le plus courant.
pub fn read_tool(
    name: impl Into<String>,
    title: impl Into<String>,
    description: impl Into<String>,
    domain: Domain,
) -> ToolBuilder {
    tool(name, title, description, domain, ToolAccess::Read).idempotent()
}

impl ToolBuilder {
    pub fn idempotent(mut self) -> Self {
        self.def.idempotent = true;
        self
    }
    pub fn open_world(mut self) -> Self {
        self.def.open_world = true;
        self
    }
    pub fn also(mut self, domains: &[Domain]) -> Self {
        self.def.also = domains.to_vec();
        self
    }
    pub fn input(mut self, fields: Vec<Field>) -> Self {
        self.def.input = Schema::new(fields);
        self
    }
    pub fn confirm(mut self, f: impl Fn(&Args) -> String + Send + Sync + 'static) -> Self {
        self.def.confirmation = Some(Arc::new(f));
        self
    }
    pub fn run<F, Fut>(mut self, f: F) -> ToolDef
    where
        F: Fn(Args, Arc<Ctx>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Value>> + Send + 'static,
    {
        self.def.handler = Arc::new(move |a, c| Box::pin(f(a, c)));
        self.def
    }
}

/// Champs de pagination des listes.
pub fn paging() -> Vec<Field> {
    vec![
        schema::string("search")
            .opt()
            .desc("Text to look for in any field."),
        schema::integer("limit")
            .opt()
            .min(1)
            .max(500)
            .desc("Rows per page (default 50, at most 500)."),
        schema::integer("offset")
            .opt()
            .min(0)
            .desc("Rows to skip. Use next_offset from the previous page."),
    ]
}

pub fn uuid() -> Field {
    schema::string("uuid")
        .regex(r"^[0-9a-fA-F-]{36}$", "Expected a uuid")
        .desc("Item uuid, from the matching list tool.")
}

pub fn require_fields(values: &Obj, what: &str) -> Result<()> {
    if values.is_empty() {
        return Err(OpnError::new(
            ErrorType::InvalidInput,
            format!("{what}: no field to change was given."),
        ));
    }
    Ok(())
}

/// Retire les valeurs vides, pour que les listes ne gaspillent pas le contexte.
pub fn sparse(row: &Value) -> Value {
    match row {
        Value::Array(a) => Value::Array(a.iter().map(sparse).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .filter(|(_, v)| match v {
                    Value::String(s) => !s.is_empty(),
                    Value::Null => false,
                    Value::Array(a) => !a.is_empty(),
                    _ => true,
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn merge(base: Obj, extra: Value) -> Value {
    let mut out = base;
    if let Value::Object(o) = extra {
        out.extend(o);
    }
    Value::Object(out)
}

/// Exécute une écriture du pare-feu dans le changement en cours. La base est prise avant la première écriture,
/// sinon elle contiendrait déjà le changement.
pub async fn staged_write<F, Fut>(
    ctx: &Ctx,
    scope: ChangeScope,
    action: &str,
    summary: &str,
    write: F,
    what: &str,
) -> Result<Value>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Value>>,
{
    if !ctx.dry_run {
        ctx.changes.begin_if_needed().await?;
    }
    let outcome: Result<Value> = async {
        let raw = if ctx.dry_run { write().await? } else { ctx.changes.track_write(write).await? };
        let res = assert_write_ok(&raw, what)?;
        if !ctx.dry_run {
            let uuid = res.get("uuid").and_then(Value::as_str).map(String::from);
            ctx.changes.record(action, scope, summary, uuid);
        }
        let protection = if ctx.dry_run { "dry-run".to_string() } else { ctx.changes.protection_available().as_str().to_string() };
        Ok(merge(res, json!({ "applied": false, "next_step": "Staged, not live yet. When all changes are staged, call opn_apply_firewall_changes.", "protection": protection })))
    }
    .await;
    if outcome.is_err() {
        ctx.changes.discard_if_empty();
    }
    outcome
}

/// Écriture vers un service sans minuteur de retour : elle devient active au rechargement du service.
pub async fn service_write<Fut>(
    ctx: &Ctx,
    write: Fut,
    what: &str,
    reconfigure: &[String],
    apply: bool,
) -> Result<Value>
where
    Fut: Future<Output = Result<Value>>,
{
    let before = if ctx.dry_run {
        None
    } else {
        ctx.changes.latest_backup().await.ok().flatten()
    };
    let raw = write.await?;
    let res = assert_write_ok(&raw, what)?;
    let mut out = res;
    if reconfigure.is_empty() {
        // L'appel lui-même a pris effet : pas d'étape séparée.
        out.insert("applied".into(), json!(true));
    } else if apply {
        for path in reconfigure {
            let r = ctx.api.post_(path).await?;
            assert_applied(&r, &format!("{what}: {path}"), false)?;
        }
        out.insert("applied".into(), json!(true));
    } else {
        out.insert("applied".into(), json!(false));
        out.insert(
            "next_step".into(),
            json!(format!(
                "Saved, not live yet. Reconfigure with: {}",
                reconfigure.join(", ")
            )),
        );
    }
    if let Some(b) = before {
        out.insert("revert_with".into(), json!({ "tool": "opn_restore_config_backup", "backup": b, "note": "This change has no automatic rollback. This backup is the configuration just before it." }));
    }
    Ok(Value::Object(out))
}

/// Pour les bascules qui ne prennent pas d'état : lit l'état actuel et ne bascule que s'il diffère.
pub async fn flip_to<Fut>(
    ctx: &Ctx,
    get_path: &str,
    wrapper: &str,
    uuid: &str,
    enabled: bool,
    what: &str,
    flip: Fut,
) -> Result<Value>
where
    Fut: Future<Output = Result<Value>>,
{
    let res = ctx
        .api
        .get(get_path, RequestOptions::new().param(uuid))
        .await?;
    let Some(item) = res.get(wrapper).filter(|v| v.is_object()) else {
        return Err(OpnError::new(
            ErrorType::NotFound,
            format!("{what}: the item was not found, so nothing was changed."),
        )
        .hint("List the items again to get a current uuid."));
    };
    let current = match item.get("enabled") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    if current != "0" && current != "1" {
        return Err(OpnError::new(
            ErrorType::BadResponse,
            format!("{what}: the current state is unreadable, so nothing was changed."),
        )
        .details(json!({ "enabled": item.get("enabled").cloned().unwrap_or(Value::Null) })));
    }
    if (current == "1") == enabled {
        return Ok(
            json!({ "changed": false, "enabled": enabled, "note": "Already in this state: nothing was sent." }),
        );
    }
    let mut out = Map::new();
    out.insert("changed".into(), json!(true));
    out.insert("enabled".into(), json!(enabled));
    if let Value::Object(o) = flip.await? {
        out.extend(o);
    }
    Ok(Value::Object(out))
}

/// Lit plusieurs points d'accès dont chacun peut manquer ou être interdit, et dit lesquels.
pub async fn gather(
    sources: Vec<(&'static str, BoxFut<Result<Value>>)>,
) -> (Obj, Map<String, Value>) {
    let (names, futs): (Vec<_>, Vec<_>) = sources.into_iter().unzip();
    let results = futures::future::join_all(futs).await;
    let mut data = Map::new();
    let mut unavailable = Map::new();
    for (name, r) in names.into_iter().zip(results) {
        match r {
            Ok(v) => {
                data.insert(name.into(), v);
            }
            Err(e) => {
                unavailable.insert(
                    name.into(),
                    json!(format!("{}: {}", e.kind.as_str(), e.message)),
                );
            }
        }
    }
    (data, unavailable)
}

pub type ToModel = Arc<dyn Fn(&Obj) -> Obj + Send + Sync>;
pub type WarnOnWrite = Arc<dyn Fn(Arc<Ctx>) -> BoxFut<Result<Option<String>>> + Send + Sync>;

#[derive(Default)]
pub struct Commands {
    pub search: &'static str,
    pub get: &'static str,
    pub add: Option<&'static str>,
    pub set: Option<&'static str>,
    pub del: Option<&'static str>,
    pub toggle: Option<&'static str>,
}

pub struct CrudSpec {
    pub domain: Domain,
    pub singular: &'static str,
    pub plural: &'static str,
    pub label: &'static str,
    pub base: &'static str,
    pub commands: Commands,
    /// Nom de l'objet qui enveloppe les champs dans les corps POST, comme « host » dans {"host": {...}}.
    pub wrapper: &'static str,
    /// Champs modifiables. Tout est facultatif ici : `required` s'applique à l'ajout.
    pub fields: Vec<Field>,
    pub required: Vec<&'static str>,
    /// Traduit les arguments en champs du modèle. Par défaut : les booléens deviennent "1"/"0".
    pub to_model: Option<ToModel>,
    /// Les objets du pare-feu sont préparés et deviennent actifs avec opn_apply_firewall_changes.
    pub staged: Option<ChangeScope>,
    /// Points d'accès de rechargement du service, appelés après chaque écriture sauf apply=false.
    pub reconfigure: Vec<&'static str>,
    pub list_note: Option<&'static str>,
    pub write_note: Option<&'static str>,
    /// La bascule prend « disabled » au lieu de « enabled ».
    pub inverted_toggle: bool,
    /// Le point de bascule ignore tout état donné et inverse : voir flip_to.
    pub toggle_flips: bool,
    /// Champs que l'outil de mise à jour doit aussi recevoir, car le contrôleur comprend mal leur absence.
    pub update_requires: Vec<&'static str>,
    pub warn_on_write: Option<WarnOnWrite>,
}

impl CrudSpec {
    pub fn new(
        domain: Domain,
        singular: &'static str,
        plural: &'static str,
        label: &'static str,
        base: &'static str,
        wrapper: &'static str,
        commands: Commands,
    ) -> Self {
        Self {
            domain,
            singular,
            plural,
            label,
            base,
            commands,
            wrapper,
            fields: Vec::new(),
            required: Vec::new(),
            to_model: None,
            staged: None,
            reconfigure: Vec::new(),
            list_note: None,
            write_note: None,
            inverted_toggle: false,
            toggle_flips: false,
            update_requires: Vec::new(),
            warn_on_write: None,
        }
    }
}

fn pick_fields(args: &Args, fields: &[Field]) -> Obj {
    fields
        .iter()
        .filter_map(|f| args.get(f.name).map(|v| (f.name.to_string(), v.clone())))
        .collect()
}

fn short(v: &Obj, n: usize) -> String {
    let s = serde_json::to_string(v).unwrap_or_default();
    s.chars().take(n).collect()
}

/// Le jeu usuel liste/lecture/ajout/mise à jour/suppression/bascule pour un type d'objet : un outil par requête.
pub fn crud_tools(spec: CrudSpec) -> Vec<ToolDef> {
    let spec = Arc::new(spec);
    let mut defs = Vec::new();
    let label = spec.label;
    let domain = spec.domain;
    let has_apply = !spec.reconfigure.is_empty();
    let apply_field = || -> Vec<Field> {
        if has_apply {
            vec![schema::boolean("apply")
                .opt()
                .desc("Reconfigure the service right away (default true).")]
        } else {
            Vec::new()
        }
    };
    let write_note = match (spec.write_note, spec.staged) {
        (Some(n), _) => format!(" {n}"),
        (None, Some(_)) => " Staged: nothing changes until opn_apply_firewall_changes.".to_string(),
        _ => String::new(),
    };

    async fn commit(
        spec: &CrudSpec,
        ctx: Arc<Ctx>,
        args: &Args,
        action: &'static str,
        summary: String,
        write: impl Future<Output = Result<Value>>,
        what: String,
    ) -> Result<Value> {
        let out = if let Some(scope) = spec.staged {
            staged_write(&ctx, scope, action, &summary, || write, &what).await?
        } else {
            let reconfigure: Vec<String> = spec.reconfigure.iter().map(|s| s.to_string()).collect();
            let apply = args.bool("apply") != Some(false) && !spec.reconfigure.is_empty();
            service_write(&ctx, write, &what, &reconfigure, apply).await?
        };
        let warning = match &spec.warn_on_write {
            Some(w) => w(ctx.clone()).await?,
            None => None,
        };
        Ok(match (warning, out) {
            (Some(w), Value::Object(mut o)) => {
                o.insert("warning".into(), json!(w));
                Value::Object(o)
            }
            (_, out) => out,
        })
    }

    let c = &spec.commands;
    {
        let s = spec.clone();
        let search = c.search;
        defs.push(
            read_tool(
                format!("opn_list_{}", spec.plural),
                format!("List {label}s"),
                format!(
                    "List {label}s, with pagination.{}",
                    spec.list_note.map(|n| format!(" {n}")).unwrap_or_default()
                ),
                domain,
            )
            .input(paging())
            .run(move |args, ctx| {
                let s = s.clone();
                async move {
                    let grid =
                        search_grid(&ctx.api, &format!("{}/{}", s.base, search), &args.grid())
                            .await?;
                    Ok(compact_grid(&grid))
                }
            }),
        );
    }
    {
        let s = spec.clone();
        let get = c.get;
        defs.push(
            read_tool(
                format!("opn_get_{}", spec.singular),
                format!("Get {label}"),
                format!(
                    "Get every field of one {label}, by uuid. Enum fields show the selected value."
                ),
                domain,
            )
            .input(vec![uuid()])
            .run(move |args, ctx| {
                let s = s.clone();
                async move {
                    let res = ctx
                        .api
                        .get(
                            &format!("{}/{}", s.base, get),
                            RequestOptions::new().param(args.req("uuid")),
                        )
                        .await?;
                    let item = res.get(s.wrapper).cloned().unwrap_or(res);
                    Ok(json!({ "uuid": args.req("uuid"), "item": flatten_model(&item) }))
                }
            }),
        );
    }
    if let (Some(add), false) = (c.add, spec.fields.is_empty()) {
        let s = spec.clone();
        let mut input: Vec<Field> = spec
            .fields
            .iter()
            .cloned()
            .map(|mut f| {
                f.optional = !spec.required.contains(&f.name);
                f
            })
            .collect();
        input.extend(apply_field());
        defs.push(
            tool(
                format!("opn_add_{}", spec.singular),
                format!("Add {label}"),
                format!("Create a {label}.{write_note}"),
                domain,
                ToolAccess::Write,
            )
            .input(input)
            .run(move |args, ctx| {
                let s = s.clone();
                async move {
                    let fields = s.to_model.as_ref().map_or_else(
                        || model_fields(&pick_fields(&args, &s.fields)),
                        |f| f(&pick_fields(&args, &s.fields)),
                    );
                    let path = format!("{}/{}", s.base, add);
                    let body = json!({ s.wrapper: fields.clone() });
                    let c2 = ctx.clone();
                    let write =
                        async move { c2.api.post(&path, Some(body), RequestOptions::new()).await };
                    commit(
                        &s,
                        ctx,
                        &args,
                        "add",
                        format!("add {}: {}", s.label, short(&fields, 200)),
                        write,
                        format!("Creating the {}", s.label),
                    )
                    .await
                }
            }),
        );
    }
    if let (Some(set), false) = (c.set, spec.fields.is_empty()) {
        let s = spec.clone();
        let mut input = vec![uuid()];
        input.extend(spec.fields.iter().cloned().map(|mut f| {
            f.optional = !spec.update_requires.contains(&f.name);
            f
        }));
        input.extend(apply_field());
        defs.push(
            tool(
                format!("opn_update_{}", spec.singular),
                format!("Update {label}"),
                format!(
                    "Change fields of a {label}. Fields left out keep their value.{write_note}"
                ),
                domain,
                ToolAccess::Write,
            )
            .idempotent()
            .input(input)
            .run(move |args, ctx| {
                let s = s.clone();
                async move {
                    let fields = s.to_model.as_ref().map_or_else(
                        || model_fields(&pick_fields(&args, &s.fields)),
                        |f| f(&pick_fields(&args, &s.fields)),
                    );
                    require_fields(&fields, &format!("Updating the {}", s.label))?;
                    let uuid = args.req("uuid").to_string();
                    let path = format!("{}/{}", s.base, set);
                    let body = json!({ s.wrapper: fields.clone() });
                    let c2 = ctx.clone();
                    let u2 = uuid.clone();
                    let write = async move {
                        c2.api
                            .post(&path, Some(body), RequestOptions::new().param(u2))
                            .await
                    };
                    commit(
                        &s,
                        ctx,
                        &args,
                        "update",
                        format!("update {} {}: {}", s.label, uuid, short(&fields, 200)),
                        write,
                        format!("Updating the {}", s.label),
                    )
                    .await
                }
            }),
        );
    }
    if let Some(del) = c.del {
        let s = spec.clone();
        let mut input = vec![uuid()];
        input.extend(apply_field());
        defs.push(
            tool(
                format!("opn_delete_{}", spec.singular),
                format!("Delete {label}"),
                format!("Delete a {label}.{write_note}"),
                domain,
                ToolAccess::Destructive,
            )
            .idempotent()
            .input(input)
            .confirm(move |a| format!("Delete {label} {}?", a.req("uuid")))
            .run(move |args, ctx| {
                let s = s.clone();
                async move {
                    let uuid = args.req("uuid").to_string();
                    let path = format!("{}/{}", s.base, del);
                    let c2 = ctx.clone();
                    let u2 = uuid.clone();
                    let write = async move {
                        c2.api
                            .post(&path, None, RequestOptions::new().param(u2))
                            .await
                    };
                    commit(
                        &s,
                        ctx,
                        &args,
                        "delete",
                        format!("delete {} {}", s.label, uuid),
                        write,
                        format!("Deleting the {}", s.label),
                    )
                    .await
                }
            }),
        );
    }
    if let Some(toggle) = c.toggle {
        let s = spec.clone();
        let mut input = vec![uuid(), schema::boolean("enabled").desc("The state wanted.")];
        input.extend(apply_field());
        defs.push(
            tool(
                format!("opn_toggle_{}", spec.singular),
                format!("Enable or disable {label}"),
                format!("Enable or disable a {label}. The state is explicit: repeating the call changes nothing.{write_note}"),
                domain,
                ToolAccess::Write,
            )
            .idempotent()
            .input(input)
            .run(move |args, ctx| {
                let s = s.clone();
                async move {
                    let enabled = args.bool("enabled").unwrap_or(false);
                    let uuid = args.req("uuid").to_string();
                    let summary = format!("{} {} {}", if enabled { "enable" } else { "disable" }, s.label, uuid);
                    let what = format!("Changing the {}", s.label);
                    let path = format!("{}/{}", s.base, toggle);
                    if s.toggle_flips {
                        let (c2, p2, u2) = (ctx.clone(), path.clone(), uuid.clone());
                        let flip = async {
                            let write = async move { c2.api.post(&p2, None, RequestOptions::new().param(u2)).await };
                            commit(&s, ctx.clone(), &args, "toggle", summary, write, what.clone()).await
                        };
                        return flip_to(&ctx, &format!("{}/{}", s.base, s.commands.get), s.wrapper, &uuid, enabled, &what, flip).await;
                    }
                    let value = if enabled != s.inverted_toggle { "1" } else { "0" };
                    let c2 = ctx.clone();
                    let u2 = uuid.clone();
                    let write = async move { c2.api.post(&path, None, RequestOptions::new().param(u2).param(value)).await };
                    commit(&s, ctx, &args, "toggle", summary, write, what).await
                }
            }),
        );
    }
    defs
}

pub fn protection_name(p: Protection) -> &'static str {
    p.as_str()
}

//! Aides sur les modèles OPNsense : formulaires, grilles paginées, contrôle des réponses d'écriture.

use crate::error::{ErrorType, OpnError, Result};
use serde_json::{json, Map, Value};

pub type Obj = Map<String, Value>;

pub fn is_object(v: &Value) -> bool {
    v.is_object()
}

fn is_option(v: &Value) -> bool {
    matches!(v, Value::Object(o) if o.contains_key("selected") && o.contains_key("value"))
}

/// Un champ énuméré d'un formulaire : {"pass": {"value": "Pass", "selected": 1}, ...}.
fn is_option_map(o: &Obj) -> bool {
    !o.is_empty() && o.values().all(is_option)
}

fn selected_is_one(v: &Value) -> bool {
    match v.get("selected") {
        Some(Value::Number(n)) => n.as_f64() == Some(1.0),
        Some(Value::String(s)) => s.trim().parse::<f64>().ok() == Some(1.0),
        Some(Value::Bool(b)) => *b,
        _ => false,
    }
}

/// Remplace les tables d'options par les clés sélectionnées, séparées par des virgules, comme l'API les attend en retour.
pub fn flatten_model(node: &Value) -> Value {
    match node {
        Value::Array(a) => Value::Array(a.iter().map(flatten_model).collect()),
        Value::Object(o) if is_option_map(o) => Value::String(
            o.iter()
                .filter(|(_, v)| selected_is_one(v))
                .map(|(k, _)| k.as_str())
                .collect::<Vec<_>>()
                .join(","),
        ),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), flatten_model(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

const MAX_OPTIONS: usize = 60;

/// Transforme un formulaire vierge en schéma : quels champs existent et quelles valeurs ils acceptent.
pub fn describe_model(node: &Value) -> Value {
    match node {
        Value::Object(o) if is_option_map(o) => {
            let options: Vec<Value> = o
                .iter()
                .take(MAX_OPTIONS)
                .map(|(value, opt)| {
                    let label = match opt.get("value") {
                        Some(Value::String(s)) => s.clone(),
                        Some(other) => other.to_string(),
                        None => String::new(),
                    };
                    json!({ "value": value, "label": label })
                })
                .collect();
            let mut out = Map::new();
            let selected = flatten_model(node);
            if selected.as_str().is_some_and(|s| !s.is_empty()) {
                out.insert("current".into(), selected);
            }
            out.insert("options".into(), Value::Array(options));
            if o.len() > MAX_OPTIONS {
                out.insert("options_truncated".into(), json!(o.len() - MAX_OPTIONS));
            }
            Value::Object(out)
        }
        Value::Object(o) => {
            let fields: Obj = o
                .iter()
                .map(|(k, v)| (k.clone(), describe_model(v)))
                .collect();
            json!({ "fields": fields })
        }
        Value::Null => json!({}),
        Value::String(s) if s.is_empty() => json!({}),
        other => json!({ "current": other }),
    }
}

pub const DEFAULT_LIMIT: i64 = 50;
pub const MAX_LIMIT: i64 = 500;

pub fn clamp_limit(limit: Option<i64>) -> i64 {
    limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
}

#[derive(Clone, Debug, Default)]
pub struct GridArgs {
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Champs POST supplémentaires, comme show_all ou interface sur firewall/filter/search_rule.
    pub extra: Option<Obj>,
}

impl GridArgs {
    /// Lit search / limit / offset dans les arguments d'un outil.
    pub fn from_args(args: &Value) -> Self {
        Self {
            search: args.get("search").and_then(Value::as_str).map(String::from),
            limit: args.get("limit").and_then(Value::as_i64),
            offset: args.get("offset").and_then(Value::as_i64),
            extra: None,
        }
    }
    pub fn extra(mut self, extra: Obj) -> Self {
        self.extra = Some(extra);
        self
    }
}

#[derive(Clone, Debug)]
pub struct GridResult {
    pub rows: Vec<Value>,
    pub total: u64,
    pub offset: i64,
    pub limit: i64,
}

impl GridResult {
    pub fn count(&self) -> usize {
        self.rows.len()
    }
    pub fn has_more(&self) -> bool {
        self.offset as u64 + self.rows.len() as u64 > 0
            && (self.offset as u64 + self.rows.len() as u64) < self.total
    }
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("rows".into(), Value::Array(self.rows.clone()));
        m.insert("total".into(), json!(self.total));
        m.insert("count".into(), json!(self.rows.len()));
        m.insert("offset".into(), json!(self.offset));
        m.insert("limit".into(), json!(self.limit));
        let more = (self.offset as u64 + self.rows.len() as u64) < self.total;
        m.insert("has_more".into(), json!(more));
        if more {
            m.insert(
                "next_offset".into(),
                json!(self.offset + self.rows.len() as i64),
            );
        }
        Value::Object(m)
    }
}

/// Tout ce qui sait envoyer un POST : le client brut ou sa vue d'outil.
pub trait PostClient {
    fn post_json(
        &self,
        path: &str,
        body: Option<Value>,
    ) -> impl std::future::Future<Output = Result<Value>> + Send;
}

/// Appelle un point de recherche et normalise l'enveloppe bootgrid en pagination par décalage.
pub async fn search_grid(
    client: &impl PostClient,
    path: &str,
    args: &GridArgs,
) -> Result<GridResult> {
    let limit = clamp_limit(args.limit);
    let offset = args.offset.unwrap_or(0).max(0);
    // Les pages sont alignées sur rowCount : un décalage qui n'est pas un multiple demande une lecture plus large.
    let aligned = offset % limit == 0;
    let row_count = if aligned { limit } else { offset + limit };
    let current = if aligned { offset / limit + 1 } else { 1 };
    let mut body = Map::new();
    body.insert("current".into(), json!(current));
    body.insert("rowCount".into(), json!(row_count));
    body.insert(
        "searchPhrase".into(),
        json!(args.search.clone().unwrap_or_default()),
    );
    body.insert("sort".into(), json!({}));
    if let Some(extra) = &args.extra {
        for (k, v) in extra {
            body.insert(k.clone(), v.clone());
        }
    }
    let raw = client.post_json(path, Some(Value::Object(body))).await?;
    Ok(paginate(
        &raw,
        offset,
        limit,
        if aligned { 0 } else { offset as usize },
    ))
}

fn raw_rows(raw: &Value) -> Vec<Value> {
    match raw {
        Value::Array(a) => a.clone(),
        Value::Object(o) => o
            .get("rows")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
        _ => vec![],
    }
}

pub fn paginate(raw: &Value, offset: i64, limit: i64, skip: usize) -> GridResult {
    let all = raw_rows(raw);
    let limit_u = limit as usize;
    let rows: Vec<Value> = if skip > 0 {
        all.iter().skip(skip).take(limit_u).cloned().collect()
    } else {
        all.iter().take(limit_u).cloned().collect()
    };
    let total = match raw {
        Value::Object(o) => o
            .get("total")
            .and_then(Value::as_u64)
            .or_else(|| o.get("rowCount").and_then(Value::as_u64))
            .unwrap_or(all.len() as u64),
        _ => all.len() as u64,
    };
    GridResult {
        rows,
        total,
        offset,
        limit,
    }
}

/// Pagination côté client, pour les points qui renvoient tout d'un coup.
pub fn paginate_array(items: &[Value], limit: Option<i64>, offset: Option<i64>) -> GridResult {
    let l = clamp_limit(limit);
    let o = offset.unwrap_or(0).max(0);
    let rows: Vec<Value> = items
        .iter()
        .skip(o as usize)
        .take(l as usize)
        .cloned()
        .collect();
    GridResult {
        rows,
        total: items.len() as u64,
        offset: o,
        limit: l,
    }
}

/// Lit toutes les pages d'un point de recherche, pour les analyses qui ont besoin de l'ensemble.
pub async fn fetch_all(
    client: &impl PostClient,
    path: &str,
    extra: Option<Obj>,
    max_rows: u64,
) -> Result<Vec<Value>> {
    let mut body = Map::new();
    body.insert("current".into(), json!(1));
    body.insert("rowCount".into(), json!(max_rows));
    body.insert("searchPhrase".into(), json!(""));
    body.insert("sort".into(), json!({}));
    if let Some(extra) = extra {
        body.extend(extra);
    }
    let raw = client.post_json(path, Some(Value::Object(body))).await?;
    Ok(raw_rows(&raw))
}

pub const FETCH_ALL_MAX: u64 = 20_000;

fn looks_like_uuid(s: &str) -> bool {
    s.len() >= 36
        && s.chars()
            .take(36)
            .all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Retire les champs d'affichage pour qu'une liste ne dépense pas le contexte.
pub fn compact_row(row: &Value) -> Value {
    let Value::Object(o) = row else {
        return row.clone();
    };
    let mut out = Map::new();
    for (k, v) in o {
        if k.starts_with("alias_meta_") || k == "category_colors" {
            continue;
        }
        if let Some(raw_key) = k.strip_prefix('%') {
            // On garde l'étiquette lisible seulement quand elle en dit plus que la valeur brute (un uuid, par exemple).
            if let (Some(label), Some(Value::String(raw))) = (v.as_str(), o.get(raw_key)) {
                if !label.is_empty() && looks_like_uuid(raw) {
                    out.insert(format!("{raw_key}_label"), Value::String(label.to_string()));
                }
            }
            continue;
        }
        out.insert(k.clone(), v.clone());
    }
    Value::Object(out)
}

pub fn compact_grid(grid: &GridResult) -> Value {
    let compact = GridResult {
        rows: grid.rows.iter().map(compact_row).collect(),
        total: grid.total,
        offset: grid.offset,
        limit: grid.limit,
    };
    compact.to_value()
}

fn str_field<'a>(o: &'a Obj, key: &str) -> Option<&'a str> {
    o.get(key).and_then(Value::as_str)
}

/// OPNsense signale un échec de validation par HTTP 200 et {"result":"failed"} : une écriture se juge sur son contenu.
pub fn assert_write_ok(result: &Value, what: &str) -> Result<Obj> {
    let empty = Obj::new();
    let obj = result.as_object().unwrap_or(&empty);
    let status = str_field(obj, "result")
        .or_else(|| str_field(obj, "status"))
        .unwrap_or("")
        .to_lowercase();
    let validations = obj.get("validations");
    if status == "failed"
        || status == "error"
        || matches!(validations, Some(Value::Object(_)) | Some(Value::Array(_)))
    {
        let details = match validations {
            Some(v) => json!({ "validations": v }),
            None => Value::Object(obj.clone()),
        };
        return Err(OpnError::new(ErrorType::ValidationFailed, format!("{what} was refused by the firewall.")).details(details).hint("Nothing was changed. Fix the fields listed in validations and try again. opn_describe_model lists the accepted values."));
    }
    // Une UserException côté pare-feu (supprimer un alias utilisé par une règle, par exemple).
    if let Some(msg) = str_field(obj, "errorMessage") {
        return Err(OpnError::new(
            ErrorType::ValidationFailed,
            format!("{what} was refused by the firewall: {msg}"),
        )
        .details(Value::Object(obj.clone())));
    }
    if status == "not found" {
        return Err(OpnError::new(
            ErrorType::NotFound,
            format!("{what}: the item was not found."),
        )
        .hint("List the items again to get a current uuid."));
    }
    Ok(obj.clone())
}

/// Les actions reconfigure répondent {"status":"ok"}, ou la sortie d'un appel de fond en échec.
pub fn assert_applied(result: &Value, what: &str, allow_empty: bool) -> Result<Obj> {
    let empty = Obj::new();
    let obj = result.as_object().unwrap_or(&empty);
    if let Some(msg) = str_field(obj, "errorMessage") {
        return Err(OpnError::new(
            ErrorType::UpstreamError,
            format!("{what} did not complete: {msg}"),
        )
        .details(Value::Object(obj.clone())));
    }
    let raw = obj.get("status").or_else(|| obj.get("result"));
    let status = match raw {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(other) => other.to_string(),
    };
    let lower = status.to_lowercase();
    if !status.is_empty() && (lower.contains("error") || lower.contains("fail")) {
        return Err(OpnError::new(
            ErrorType::UpstreamError,
            format!("{what} did not complete: {}", status.trim()),
        )
        .details(Value::Object(obj.clone())));
    }
    // Le backend répond par une chaîne vide quand il échoue ou dépasse le délai.
    if raw.is_some()
        && !matches!(raw, Some(Value::Null))
        && status.trim().is_empty()
        && !allow_empty
    {
        return Err(OpnError::new(
            ErrorType::UpstreamError,
            format!("{what} did not complete: the firewall backend gave no answer."),
        )
        .details(Value::Object(obj.clone())));
    }
    Ok(obj.clone())
}

/// Pour les actions qui doivent annoncer le succès en toutes lettres : tout le reste, même sans erreur, est un échec.
pub fn assert_ok(result: &Value, what: &str) -> Result<Obj> {
    let empty = Obj::new();
    let obj = result.as_object().unwrap_or(&empty);
    let status = obj
        .get("status")
        .or_else(|| obj.get("result"))
        .map(|v| match v {
            Value::String(s) => s.clone(),
            Value::Null => String::new(),
            other => other.to_string(),
        })
        .unwrap_or_default();
    let status = status.trim();
    if !status.eq_ignore_ascii_case("ok") {
        let shown = if status.is_empty() {
            "the firewall backend gave no answer"
        } else {
            status
        };
        return Err(OpnError::new(
            ErrorType::UpstreamError,
            format!("{what} did not report success: {shown}."),
        )
        .details(Value::Object(obj.clone())));
    }
    Ok(obj.clone())
}

/// Booléens en "1"/"0" comme les modèles les attendent ; les champs absents sont écartés.
pub fn model_fields(input: &Obj) -> Obj {
    let mut out = Obj::new();
    for (k, v) in input {
        let s = match v {
            Value::Null => continue,
            Value::Bool(b) => (if *b { "1" } else { "0" }).to_string(),
            Value::Array(a) => a
                .iter()
                .map(|x| x.as_str().map_or_else(|| x.to_string(), String::from))
                .collect::<Vec<_>>()
                .join(","),
            Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        out.insert(k.clone(), Value::String(s));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flatten_selects_ones() {
        let v = json!({"proto": {"tcp": {"value": "TCP", "selected": 1}, "udp": {"value": "UDP", "selected": 0}}});
        assert_eq!(flatten_model(&v), json!({"proto": "tcp"}));
    }

    #[test]
    fn write_failures_are_detected() {
        assert!(
            assert_write_ok(&json!({"result": "failed", "validations": {"a": "x"}}), "t").is_err()
        );
        assert!(assert_write_ok(&json!({"result": "saved", "uuid": "u"}), "t").is_ok());
        assert!(assert_write_ok(&json!({"result": "not found"}), "t").is_err());
    }

    #[test]
    fn apply_checks() {
        assert!(assert_applied(&json!({"status": "ok"}), "t", false).is_ok());
        assert!(assert_applied(&json!({"status": ""}), "t", false).is_err());
        assert!(assert_applied(&json!({"status": ""}), "t", true).is_ok());
        assert!(assert_applied(&json!({"status": "Error: x"}), "t", false).is_err());
        assert!(assert_ok(&json!({"status": "OK "}), "t").is_ok());
        assert!(assert_ok(&json!({}), "t").is_err());
    }

    #[test]
    fn pagination_aligned_and_not() {
        let raw = json!({"rows": [1, 2, 3], "total": 10});
        let g = paginate(&raw, 0, 3, 0);
        assert_eq!(g.to_value()["next_offset"], 3);
        let g = paginate(&json!({"rows": [1,2,3,4,5], "total": 5}), 2, 2, 2);
        assert_eq!(g.rows, vec![json!(3), json!(4)]);
        assert_eq!(g.to_value()["has_more"], true);
    }

    #[test]
    fn model_fields_stringifies() {
        let o = json!({"a": true, "b": ["x", "y"], "c": 5, "d": null});
        let f = model_fields(o.as_object().unwrap());
        assert_eq!(Value::Object(f), json!({"a": "1", "b": "x,y", "c": "5"}));
    }
}

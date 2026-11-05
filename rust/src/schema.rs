//! Schéma d'entrée des outils : un petit constructeur qui produit le JSON Schema annoncé aux clients MCP
//! et valide les arguments reçus (équivalent du sous-ensemble de zod utilisé par le serveur TypeScript).

use serde_json::{json, Map, Value};
use std::net::IpAddr;
use std::sync::Arc;

#[derive(Clone)]
pub enum Ty {
    Str { regex: Option<(regex::Regex, String)>, check: Option<(Arc<dyn Fn(&str) -> bool + Send + Sync>, &'static str)> },
    Int { min: Option<i64>, max: Option<i64> },
    Num { min: Option<f64> },
    Bool,
    Enum(Vec<String>),
    Array(Box<Ty>),
    /// Objet libre dont les valeurs sont de ces types (le premier qui convient gagne).
    Record(Vec<Ty>),
    Unknown,
}

#[derive(Clone)]
pub struct Field {
    pub name: &'static str,
    pub ty: Ty,
    pub desc: Option<String>,
    pub optional: bool,
}

impl Field {
    fn new(name: &'static str, ty: Ty) -> Self {
        Field { name, ty, desc: None, optional: false }
    }
    pub fn desc(mut self, d: &str) -> Self {
        self.desc = Some(d.to_string());
        self
    }
    pub fn opt(mut self) -> Self {
        self.optional = true;
        self
    }
    pub fn required(mut self) -> Self {
        self.optional = false;
        self
    }
    pub fn min(mut self, m: i64) -> Self {
        match &mut self.ty {
            Ty::Int { min, .. } => *min = Some(m),
            Ty::Num { min } => *min = Some(m as f64),
            _ => {}
        }
        self
    }
    pub fn max(mut self, m: i64) -> Self {
        if let Ty::Int { max, .. } = &mut self.ty {
            *max = Some(m);
        }
        self
    }
    pub fn regex(mut self, pattern: &str, message: &str) -> Self {
        if let Ty::Str { regex, .. } = &mut self.ty {
            *regex = Some((regex::Regex::new(pattern).expect("regex d'outil invalide"), message.to_string()));
        }
        self
    }
    pub fn check(mut self, f: impl Fn(&str) -> bool + Send + Sync + 'static, message: &'static str) -> Self {
        if let Ty::Str { check, .. } = &mut self.ty {
            *check = Some((Arc::new(f), message));
        }
        self
    }
    /// Adresse IP (v4 ou v6), comme `isIP(v) !== 0` côté Node.
    pub fn ip(self) -> Self {
        self.check(|v| v.parse::<IpAddr>().is_ok(), "Expected an IP address")
    }
}

pub fn string(name: &'static str) -> Field {
    Field::new(name, Ty::Str { regex: None, check: None })
}
pub fn integer(name: &'static str) -> Field {
    Field::new(name, Ty::Int { min: None, max: None })
}
pub fn number(name: &'static str) -> Field {
    Field::new(name, Ty::Num { min: None })
}
pub fn boolean(name: &'static str) -> Field {
    Field::new(name, Ty::Bool)
}
pub fn enumeration(name: &'static str, values: &[&str]) -> Field {
    Field::new(name, Ty::Enum(values.iter().map(|v| v.to_string()).collect()))
}
pub fn array_of(name: &'static str, item: Ty) -> Field {
    Field::new(name, Ty::Array(Box::new(item)))
}
pub fn strings(name: &'static str) -> Field {
    array_of(name, Ty::Str { regex: None, check: None })
}
pub fn record(name: &'static str, values: Vec<Ty>) -> Field {
    Field::new(name, Ty::Record(values))
}
pub fn unknown_record(name: &'static str) -> Field {
    Field::new(name, Ty::Record(vec![Ty::Unknown]))
}
pub fn plain_str() -> Ty {
    Ty::Str { regex: None, check: None }
}

/// Liste ordonnée de champs : l'ordre est celui annoncé dans le JSON Schema.
#[derive(Clone, Default)]
pub struct Schema(pub Vec<Field>);

impl Schema {
    pub fn new(fields: Vec<Field>) -> Self {
        Schema(fields)
    }
    pub fn and(mut self, more: impl IntoIterator<Item = Field>) -> Self {
        self.0.extend(more);
        self
    }
    pub fn push(&mut self, f: Field) {
        self.0.push(f);
    }
    pub fn has(&self, name: &str) -> bool {
        self.0.iter().any(|f| f.name == name)
    }

    pub fn to_json_schema(&self) -> Value {
        let mut props = Map::new();
        let mut required = Vec::new();
        for f in &self.0 {
            let mut p = ty_schema(&f.ty);
            if let (Some(d), Some(o)) = (&f.desc, p.as_object_mut()) {
                o.insert("description".into(), json!(d));
            }
            props.insert(f.name.to_string(), p);
            if !f.optional {
                required.push(json!(f.name));
            }
        }
        let mut out = Map::new();
        out.insert("type".into(), json!("object"));
        out.insert("properties".into(), Value::Object(props));
        if !required.is_empty() {
            out.insert("required".into(), Value::Array(required));
        }
        out.insert("additionalProperties".into(), json!(false));
        Value::Object(out)
    }

    /// Valide les arguments. Les clés inconnues sont ignorées, comme le fait zod par défaut.
    pub fn validate(&self, args: &Value) -> Result<Map<String, Value>, String> {
        let obj = match args {
            Value::Object(o) => o,
            Value::Null => &Map::new(),
            _ => return Err("arguments must be an object".into()),
        };
        let mut out = Map::new();
        let mut problems = Vec::new();
        for f in &self.0 {
            match obj.get(f.name) {
                None | Some(Value::Null) => {
                    if !f.optional {
                        problems.push(format!("{}: required", f.name));
                    }
                }
                Some(v) => match check_ty(&f.ty, v) {
                    Ok(()) => {
                        out.insert(f.name.to_string(), v.clone());
                    }
                    Err(e) => problems.push(format!("{}: {e}", f.name)),
                },
            }
        }
        if problems.is_empty() {
            Ok(out)
        } else {
            Err(problems.join("; "))
        }
    }
}

fn ty_schema(ty: &Ty) -> Value {
    match ty {
        Ty::Str { regex, .. } => {
            let mut m = Map::new();
            m.insert("type".into(), json!("string"));
            if let Some((r, _)) = regex {
                m.insert("pattern".into(), json!(r.as_str()));
            }
            Value::Object(m)
        }
        Ty::Int { min, max } => {
            let mut m = Map::new();
            m.insert("type".into(), json!("integer"));
            if let Some(v) = min {
                m.insert("minimum".into(), json!(v));
            }
            if let Some(v) = max {
                m.insert("maximum".into(), json!(v));
            }
            Value::Object(m)
        }
        Ty::Num { min } => {
            let mut m = Map::new();
            m.insert("type".into(), json!("number"));
            if let Some(v) = min {
                m.insert("minimum".into(), json!(v));
            }
            Value::Object(m)
        }
        Ty::Bool => json!({ "type": "boolean" }),
        Ty::Enum(v) => json!({ "type": "string", "enum": v }),
        Ty::Array(item) => json!({ "type": "array", "items": ty_schema(item) }),
        Ty::Record(values) => {
            let ap = match values.as_slice() {
                [Ty::Unknown] => json!({}),
                [one] => ty_schema(one),
                many => json!({ "anyOf": many.iter().map(ty_schema).collect::<Vec<_>>() }),
            };
            json!({ "type": "object", "additionalProperties": ap })
        }
        Ty::Unknown => json!({}),
    }
}

fn check_ty(ty: &Ty, v: &Value) -> Result<(), String> {
    match ty {
        Ty::Str { regex, check } => {
            let s = v.as_str().ok_or("expected a string")?;
            if let Some((r, msg)) = regex {
                if !r.is_match(s) {
                    return Err(msg.clone());
                }
            }
            if let Some((f, msg)) = check {
                if !f(s) {
                    return Err((*msg).to_string());
                }
            }
            Ok(())
        }
        Ty::Int { min, max } => {
            let n = v.as_i64().or_else(|| v.as_f64().filter(|f| f.fract() == 0.0).map(|f| f as i64)).ok_or("expected an integer")?;
            if min.is_some_and(|m| n < m) {
                return Err(format!("must be at least {}", min.unwrap()));
            }
            if max.is_some_and(|m| n > m) {
                return Err(format!("must be at most {}", max.unwrap()));
            }
            Ok(())
        }
        Ty::Num { min } => {
            let n = v.as_f64().ok_or("expected a number")?;
            if min.is_some_and(|m| n < m) {
                return Err(format!("must be at least {}", min.unwrap()));
            }
            Ok(())
        }
        Ty::Bool => v.is_boolean().then_some(()).ok_or_else(|| "expected a boolean".into()),
        Ty::Enum(values) => {
            let s = v.as_str().ok_or("expected a string")?;
            if values.iter().any(|x| x == s) {
                Ok(())
            } else {
                Err(format!("expected one of {}", values.join(", ")))
            }
        }
        Ty::Array(item) => {
            let a = v.as_array().ok_or("expected an array")?;
            for (i, x) in a.iter().enumerate() {
                check_ty(item, x).map_err(|e| format!("[{i}] {e}"))?;
            }
            Ok(())
        }
        Ty::Record(values) => {
            let o = v.as_object().ok_or("expected an object")?;
            for (k, x) in o {
                if !values.iter().any(|t| check_ty(t, x).is_ok()) {
                    return Err(format!("{k}: unexpected value type"));
                }
            }
            Ok(())
        }
        Ty::Unknown => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_types_and_required() {
        let s = Schema::new(vec![string("a").desc("x"), integer("n").opt().min(1).max(5), enumeration("e", &["x", "y"]).opt(), string("ip").ip().opt()]);
        assert!(s.validate(&json!({"a": "v"})).is_ok());
        assert!(s.validate(&json!({})).is_err());
        assert!(s.validate(&json!({"a": "v", "n": 0})).is_err());
        assert!(s.validate(&json!({"a": "v", "n": 6})).is_err());
        assert!(s.validate(&json!({"a": "v", "e": "z"})).is_err());
        assert!(s.validate(&json!({"a": "v", "ip": "10.0.0.1"})).is_ok());
        assert!(s.validate(&json!({"a": "v", "ip": "nope"})).is_err());
        assert!(s.validate(&json!({"a": "v", "extra": 1})).unwrap().get("extra").is_none());
    }

    #[test]
    fn json_schema_shape() {
        let s = Schema::new(vec![string("a").desc("d"), boolean("b").opt()]);
        let j = s.to_json_schema();
        assert_eq!(j["required"], json!(["a"]));
        assert_eq!(j["properties"]["a"]["description"], "d");
        assert_eq!(j["properties"]["b"]["type"], "boolean");
    }

    #[test]
    fn records_accept_mixed() {
        let s = Schema::new(vec![record("q", vec![plain_str(), Ty::Int { min: None, max: None }, Ty::Bool]).opt()]);
        assert!(s.validate(&json!({"q": {"a": "x", "b": 1, "c": true}})).is_ok());
        assert!(s.validate(&json!({"q": {"a": [1]}})).is_err());
    }
}

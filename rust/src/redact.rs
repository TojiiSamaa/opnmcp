// NO_SECRET_CHECK : les clés PEM de ce fichier sont des exemples de test.
//! Rédaction des secrets : par nom de clé (JSON, XML), par motif (clés privées PEM) et nettoyage des
//! caractères de contrôle que des journaux ou des noms d'hôtes choisis par un attaquant pourraient porter.

use crate::error::{ErrorType, OpnError, Result};
use quick_xml::events::{BytesEnd, BytesStart, BytesText, Event};
use quick_xml::{Reader, Writer};
use regex::{Captures, Regex};
use serde_json::{Map, Value};
use std::collections::HashSet;
use std::sync::LazyLock;

pub const REDACTED: &str = "[REDACTED]";

static EXACT: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "password",
        "bcrypt-hash",
        "sha512-hash",
        "md5-hash",
        "nt-hash",
        "key",
        "secret",
        "pre-shared-key",
        "privatekey",
        "privkey",
        "certdata",
        "shared_secret",
        "authorizedkeys",
        "otp_seed",
        "tls",
        "keys",
        "keydata",
        "simpin",
        "community",
        "rocommunity",
        "rwcommunity",
        "eab_hmac",
        "basicauthpass",
        "dns_kas_authdata",
        "apikeys",
        "cookie",
    ]
    .into_iter()
    .collect()
});

const SUBSTRINGS: [&str; 17] = [
    "password",
    "passwd",
    "secret",
    "credential",
    "token",
    "apikey",
    "api_key",
    "authkey",
    "presharedkey",
    "pre-shared",
    "psk",
    "passphrase",
    "prv",
    "private_key",
    "privatekey",
    "bindpw",
    "hmac",
];

/// Clés qui correspondent à un motif ci-dessus sans porter de secret.
static NOT_SECRET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    [
        "passwordauth",
        "nopasswd",
        "pubkey",
        "publickey",
        "public-key",
        "public_key",
        "password_policy_length",
        "authtype",
        "sortkey",
        "ssh_pubkey",
        "tokens_max",
    ]
    .into_iter()
    .collect()
});

pub fn is_sensitive_key(key: &str) -> bool {
    let k = key.to_lowercase();
    if NOT_SECRET.contains(k.as_str()) {
        return false;
    }
    if EXACT.contains(k.as_str()) {
        return true;
    }
    // otp_seed, et otp_uri dont le paramètre secret= est cette même graine.
    if k.starts_with("otp") {
        return true;
    }
    if SUBSTRINGS.iter().any(|s| k.contains(s)) {
        return true;
    }
    if k.ends_with("_pass") || k.ends_with("pw") {
        return true;
    }
    k.ends_with("key") && !k.contains("pub") && !k.contains("sort")
}

static PEM_PRIVATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)",
    )
    .unwrap()
});
static CONTROL_CHARS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]").unwrap());

/// Retire le matériel de clé de tout texte libre et supprime les caractères de contrôle.
pub fn scrub_text(text: &str) -> String {
    let no_pem = PEM_PRIVATE.replace_all(text, REDACTED);
    CONTROL_CHARS.replace_all(&no_pem, "").into_owned()
}

/// Une option d'énumération d'un formulaire de modèle : {"psk": {"value": "...", "selected": 0}}. Ce n'est pas un secret.
fn is_model_option(value: &Value) -> bool {
    matches!(value, Value::Object(o) if o.contains_key("selected") && o.contains_key("value"))
}

/// Les valeurs vides restent vides, pour qu'on voie encore « aucun mot de passe défini ».
fn is_empty(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::String(s) => s.is_empty(),
        Value::Array(a) => a.is_empty(),
        Value::Object(o) => o.is_empty(),
        _ => false,
    }
}

pub fn redact_json(value: &Value) -> Value {
    match value {
        Value::String(s) => Value::String(scrub_text(s)),
        Value::Array(a) => Value::Array(a.iter().map(redact_json).collect()),
        Value::Object(o) => {
            let mut out = Map::with_capacity(o.len());
            for (k, v) in o {
                let redacted = if is_sensitive_key(k) && !is_empty(v) && !is_model_option(v) {
                    Value::String(REDACTED.into())
                } else {
                    redact_json(v)
                };
                out.insert(k.clone(), redacted);
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn decode_entities(line: &str) -> String {
    line.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#039;", "'")
        .replace("&#39;", "'")
}

static LEADING_TEXT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\s*)[^<\s][^<]*").unwrap());
static OPEN_TAG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"<([A-Za-z0-9_.:-]+)(\s[^<>]*)?>([^<]*)").unwrap());
static DIFF_HEADER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(---|\+\+\+|@@)").unwrap());

fn first_char_len(s: &str) -> usize {
    s.chars().next().map_or(0, char::len_utf8)
}

/// Masque les secrets dans des lignes de config.xml, comme celles d'un diff unifié. Un élément
/// sensible peut s'étendre sur plusieurs lignes (clé d'un certificat) : l'état passe d'une ligne à l'autre.
pub fn redact_xml_lines(lines: &[String]) -> Vec<String> {
    let mut open_secret: Option<String> = None;
    lines
        .iter()
        .map(|raw| {
            let line = decode_entities(raw);
            let lead = first_char_len(&line);
            if let Some(tag) = &open_secret {
                if line.contains(&format!("</{tag}>")) {
                    open_secret = None;
                }
                return format!("{}{}", &line[..lead], REDACTED);
            }
            if DIFF_HEADER.is_match(&line) {
                return scrub_text(&line);
            }
            // Le texte avant la première balise appartient à une valeur sur plusieurs lignes, peut-être commencée plus haut.
            let rest = LEADING_TEXT
                .replace(&line[lead..], |c: &Captures| {
                    format!("{}{}", &c[1], REDACTED)
                })
                .into_owned();
            let body = format!("{}{}", &line[..lead], rest);

            let mut out = String::with_capacity(body.len());
            let mut pos = 0;
            while pos < body.len() {
                let Some(c) = OPEN_TAG.captures_at(&body, pos) else {
                    break;
                };
                let m = c.get(0).unwrap();
                out.push_str(&body[pos..m.start()]);
                let tag = &c[1];
                let attrs = c.get(2).map_or("", |a| a.as_str());
                let value = &c[3];
                let close_tag = format!("</{tag}>");
                let has_close = body[m.end()..].starts_with(&close_tag);
                let end = if has_close {
                    m.end() + close_tag.len()
                } else {
                    m.end()
                };
                if !is_sensitive_key(tag) || (value.is_empty() && has_close) {
                    out.push_str(&body[m.start()..end]);
                } else {
                    if !has_close {
                        open_secret = Some(tag.to_string());
                    }
                    out.push_str(&format!(
                        "<{tag}{attrs}>{REDACTED}{}",
                        if has_close { close_tag.as_str() } else { "" }
                    ));
                }
                pos = end;
            }
            out.push_str(&body[pos.min(body.len())..]);
            scrub_text(&out)
        })
        .collect()
}

/// Un marqueur de rédaction ne doit jamais être réécrit comme vraie valeur sur le pare-feu.
pub fn assert_no_redacted_value(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::String(s) if s == REDACTED => Err(OpnError::new(
            ErrorType::InvalidInput,
            format!("The request to {path} contains the placeholder {REDACTED}, which would overwrite a real secret."),
        )
        .hint("Leave the field out to keep its current value.")),
        Value::Array(a) => a.iter().try_for_each(|v| assert_no_redacted_value(v, path)),
        Value::Object(o) => o.values().try_for_each(|v| assert_no_redacted_value(v, path)),
        _ => Ok(()),
    }
}

fn bad_xml(message: &str) -> OpnError {
    OpnError::new(ErrorType::BadResponse, message)
}

/// Vérifie que le document est bien formé : un texte qui ne s'analyse pas ne peut pas être rédigé, donc pas transmis.
fn validate_xml(xml: &str, message: &str) -> Result<()> {
    let mut reader = Reader::from_str(xml);
    let mut depth = 0i64;
    loop {
        match reader.read_event() {
            Ok(Event::Eof) => break,
            Ok(Event::Start(_)) => depth += 1,
            Ok(Event::End(_)) => depth -= 1,
            Ok(_) => {}
            Err(_) => return Err(bad_xml(message)),
        }
    }
    if depth != 0 {
        return Err(bad_xml(message));
    }
    Ok(())
}

/// Vide tous les éléments sensibles d'un config.xml, enfants et attributs compris.
pub fn redact_config_xml(xml: &str) -> Result<String> {
    let message = "The configuration returned by the firewall is not valid XML, so it cannot be redacted and was not returned.";
    validate_xml(xml, message)?;
    let mut reader = Reader::from_str(xml);
    let mut writer = Writer::new(Vec::with_capacity(xml.len()));
    let bad = |_| bad_xml(message);

    loop {
        match reader.read_event().map_err(bad)? {
            Event::Eof => break,
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                if is_sensitive_key(&name) {
                    let span = reader.read_to_end(e.name()).map_err(bad)?;
                    if span.start == span.end {
                        // Élément vide : conservé tel quel, attributs compris.
                        writer
                            .write_event(Event::Start(e))
                            .map_err(|_| bad_xml(message))?;
                    } else {
                        writer
                            .write_event(Event::Start(BytesStart::new(name.clone())))
                            .map_err(|_| bad_xml(message))?;
                        writer
                            .write_event(Event::Text(BytesText::from_escaped(REDACTED)))
                            .map_err(|_| bad_xml(message))?;
                    }
                    writer
                        .write_event(Event::End(BytesEnd::new(name)))
                        .map_err(|_| bad_xml(message))?;
                } else {
                    writer
                        .write_event(Event::Start(e))
                        .map_err(|_| bad_xml(message))?;
                }
            }
            Event::Empty(e) => {
                // fast-xml-parser reconstruit un élément vide en paire ouvrante/fermante.
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                writer
                    .write_event(Event::Start(e))
                    .map_err(|_| bad_xml(message))?;
                writer
                    .write_event(Event::End(BytesEnd::new(name)))
                    .map_err(|_| bad_xml(message))?;
            }
            Event::Text(t) => {
                let raw = String::from_utf8_lossy(t.as_ref()).into_owned();
                writer
                    .write_event(Event::Text(BytesText::from_escaped(scrub_text(&raw))))
                    .map_err(|_| bad_xml(message))?;
            }
            other => writer.write_event(other).map_err(|_| bad_xml(message))?,
        }
    }
    String::from_utf8(writer.into_inner()).map_err(|_| bad_xml(message))
}

struct Node {
    name: String,
    children: Vec<(String, Value)>,
    text: String,
}

fn finish(node: Node) -> Value {
    if node.children.is_empty() {
        return Value::String(node.text.trim().to_string());
    }
    let mut map = Map::new();
    for (k, v) in node.children {
        match map.get_mut(&k) {
            None => {
                map.insert(k, v);
            }
            // Les valeurs d'un élément sont des chaînes ou des objets, jamais des tableaux : un tableau est donc un groupe de doublons.
            Some(Value::Array(a)) => a.push(v),
            Some(existing) => {
                let first = existing.take();
                *existing = Value::Array(vec![first, v]);
            }
        }
    }
    Value::Object(map)
}

/// Analyse un config.xml en JSON simple, avec rédaction par défaut.
pub fn config_xml_to_json(xml: &str, redact: bool) -> Result<Value> {
    let message = "The configuration returned by the firewall is not valid XML.";
    validate_xml(xml, message)?;
    let mut reader = Reader::from_str(xml);
    let mut stack: Vec<Node> = vec![Node {
        name: String::new(),
        children: vec![],
        text: String::new(),
    }];
    loop {
        match reader.read_event().map_err(|_| bad_xml(message))? {
            Event::Eof => break,
            Event::Start(e) => stack.push(Node {
                name: String::from_utf8_lossy(e.name().as_ref()).into_owned(),
                children: vec![],
                text: String::new(),
            }),
            Event::Empty(e) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                stack
                    .last_mut()
                    .ok_or_else(|| bad_xml(message))?
                    .children
                    .push((name, Value::String(String::new())));
            }
            Event::End(_) => {
                let node = stack.pop().ok_or_else(|| bad_xml(message))?;
                let name = node.name.clone();
                stack
                    .last_mut()
                    .ok_or_else(|| bad_xml(message))?
                    .children
                    .push((name, finish(node)));
            }
            Event::Text(t) => stack
                .last_mut()
                .ok_or_else(|| bad_xml(message))?
                .text
                .push_str(&String::from_utf8_lossy(t.as_ref())),
            Event::CData(t) => stack
                .last_mut()
                .ok_or_else(|| bad_xml(message))?
                .text
                .push_str(&String::from_utf8_lossy(t.as_ref())),
            _ => {}
        }
    }
    let doc = finish(stack.pop().ok_or_else(|| bad_xml(message))?);
    let root = match &doc {
        Value::Object(o) => o
            .get("opnsense")
            .or_else(|| o.get("pfsense"))
            .cloned()
            .unwrap_or_else(|| doc.clone()),
        _ => doc.clone(),
    };
    Ok(if redact { redact_json(&root) } else { root })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sensitive_keys() {
        for k in [
            "password",
            "api_secret",
            "psk",
            "pre-shared-key",
            "otp_uri",
            "bindpw",
            "admin_pass",
            "hmac_key",
        ] {
            assert!(is_sensitive_key(k), "{k}");
        }
        for k in [
            "pubkey",
            "description",
            "sortkey",
            "passwordauth",
            "interface",
        ] {
            assert!(!is_sensitive_key(k), "{k}");
        }
    }

    #[test]
    fn json_redaction_keeps_empty_and_options() {
        let v = json!({"password": "x", "secret": "", "psk": {"value": "Pre", "selected": 0}, "note": "a"});
        let r = redact_json(&v);
        assert_eq!(r["password"], REDACTED);
        assert_eq!(r["secret"], "");
        assert_eq!(r["psk"]["value"], "Pre");
        assert_eq!(r["note"], "a");
    }

    #[test]
    fn pem_and_control_chars() {
        let s = scrub_text(
            "a\u{0007}b -----BEGIN RSA PRIVATE KEY-----\nAAA\n-----END RSA PRIVATE KEY----- c",
        );
        assert_eq!(s, format!("ab {REDACTED} c"));
    }

    #[test]
    fn placeholder_is_refused() {
        assert!(assert_no_redacted_value(&json!({"a": [REDACTED]}), "x/y/z").is_err());
        assert!(assert_no_redacted_value(&json!({"a": "ok"}), "x/y/z").is_ok());
    }

    #[test]
    fn xml_redaction() {
        let xml = "<opnsense><system><password>hunter2</password><hostname>fw</hostname><key/></system></opnsense>";
        let out = redact_config_xml(xml).unwrap();
        assert!(out.contains("<password>[REDACTED]</password>"), "{out}");
        assert!(out.contains("<hostname>fw</hostname>"));
        assert!(!out.contains("hunter2"));
        assert!(redact_config_xml("<a><b></a>").is_err());
    }

    #[test]
    fn xml_subtree_is_blanked() {
        let xml = "<r><keys><k>one</k><k>two</k></keys><x>1</x></r>";
        let out = redact_config_xml(xml).unwrap();
        assert!(out.contains("<keys>[REDACTED]</keys>"), "{out}");
        assert!(out.contains("<x>1</x>"));
    }

    #[test]
    fn xml_to_json() {
        let xml = "<opnsense><a>1</a><b><c>x</c><c>y</c></b><password>p</password></opnsense>";
        let v = config_xml_to_json(xml, true).unwrap();
        assert_eq!(v["a"], "1");
        assert_eq!(v["b"]["c"], json!(["x", "y"]));
        assert_eq!(v["password"], REDACTED);
    }

    #[test]
    fn diff_lines() {
        let lines = vec![
            "+      <password>secret</password>".to_string(),
            "+      <hostname>fw</hostname>".to_string(),
        ];
        let out = redact_xml_lines(&lines);
        assert!(
            out[0].contains(REDACTED) && !out[0].contains("secret"),
            "{out:?}"
        );
        assert!(out[1].contains("<hostname>fw</hostname>"));
    }
}

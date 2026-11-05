//! Ce qui survit à une connexion MCP : les clients du pare-feu, et les changements en attente avec
//! leurs minuteurs de retour. En mode HTTP, chaque requête a son propre serveur MCP au-dessus.

use crate::changes::{ChangeManager, Notify};
use crate::client::{OpnsenseClient, WriteHook, WriteRecord};
use crate::config::{InstanceConfig, ServerConfig};
use crate::error::{ErrorType, OpnError, Result};
use serde_json::{json, Map, Value};
use std::io::Write;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);

pub struct InstanceRuntime {
    pub config: Arc<InstanceConfig>,
    pub client: Arc<OpnsenseClient>,
    pub changes: Arc<ChangeManager>,
}

pub type WriteLog = Arc<Mutex<Vec<WriteRecord>>>;

tokio::task_local! {
    /// Écritures collectées pendant un appel d'outil, pour le journal d'audit.
    static WRITE_SCOPE: WriteLog;
}

type Listener = (u64, Notify);

pub struct Runtime {
    pub config: Arc<ServerConfig>,
    instances: Vec<(String, Arc<InstanceRuntime>)>,
    listeners: Mutex<(u64, Vec<Listener>)>,
}

impl Runtime {
    pub fn new(config: ServerConfig) -> Result<Arc<Self>> {
        if let Some(path) = &config.audit_log {
            Self::assert_audit_writable(path)?;
        }
        let config = Arc::new(config);
        let mut error = None;
        let runtime = Arc::new_cyclic(|me: &Weak<Runtime>| {
            let mut instances = Vec::new();
            for (name, instance) in config.instances.iter() {
                let instance = Arc::new(instance.clone());
                let hook: WriteHook = {
                    let (me, name) = (me.clone(), name.clone());
                    Arc::new(move |entry| {
                        if let Some(rt) = me.upgrade() {
                            rt.on_write(&name, entry);
                        }
                    })
                };
                let client = match OpnsenseClient::new(instance.clone(), config.unblocked.clone(), Some(hook)) {
                    Ok(c) => Arc::new(c),
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                };
                let notify: Notify = {
                    let (me, name) = (me.clone(), name.clone());
                    Arc::new(move |level, message| {
                        if let Some(rt) = me.upgrade() {
                            rt.notify(level, &format!("[{name}] {message}"));
                        }
                    })
                };
                let changes = ChangeManager::new(client.clone(), notify, None);
                instances.push((name.clone(), Arc::new(InstanceRuntime { config: instance, client, changes })));
            }
            Runtime { config: config.clone(), instances, listeners: Mutex::new((0, Vec::new())) }
        });
        match error {
            Some(e) => Err(e),
            None => Ok(runtime),
        }
    }

    pub fn instance_names(&self) -> Vec<String> {
        self.instances.iter().map(|(n, _)| n.clone()).collect()
    }

    pub fn instances(&self) -> impl Iterator<Item = &Arc<InstanceRuntime>> {
        self.instances.iter().map(|(_, i)| i)
    }

    pub fn instance(&self, name: Option<&str>) -> Result<Arc<InstanceRuntime>> {
        let key = name.unwrap_or(&self.config.default_instance);
        self.instances.iter().find(|(n, _)| n == key).map(|(_, i)| i.clone()).ok_or_else(|| {
            OpnError::new(ErrorType::InvalidInput, format!("Unknown instance \"{key}\".")).hint(format!("Known instances: {}", self.instance_names().join(", ")))
        })
    }

    /// Abonne un écouteur aux avis du serveur ; renvoie l'identifiant à passer à `remove_listener`.
    pub fn add_listener(&self, listener: Notify) -> u64 {
        let mut guard = self.listeners.lock().unwrap();
        guard.0 += 1;
        let id = guard.0;
        guard.1.push((id, listener));
        id
    }

    pub fn remove_listener(&self, id: u64) {
        self.listeners.lock().unwrap().1.retain(|(i, _)| *i != id);
    }

    /// Exécute un outil en collectant les requêtes qui changent quelque chose, pour le journal d'audit.
    pub async fn collect_writes<T>(&self, writes: WriteLog, run: impl std::future::Future<Output = T>) -> T {
        WRITE_SCOPE.scope(writes, run).await
    }

    pub fn audit(&self, entry: Value) {
        let Some(path) = &self.config.audit_log else { return };
        let mut line = Map::new();
        line.insert("ts".into(), json!(chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)));
        if let Value::Object(o) = entry {
            line.extend(o);
        }
        let text = format!("{}\n", Value::Object(line));
        let result = std::fs::OpenOptions::new().create(true).append(true).open(path).and_then(|mut f| f.write_all(text.as_bytes()));
        if let Err(e) = result {
            eprintln!("[osmcp] could not write the audit log: {e}");
        }
    }

    pub async fn shutdown(&self) {
        let all = futures::future::join_all(self.instances.iter().map(|(_, i)| i.changes.shutdown()));
        let _ = tokio::time::timeout(SHUTDOWN_TIMEOUT, all).await;
    }

    fn notify(&self, level: &str, message: &str) {
        eprintln!("[osmcp] {level}: {message}");
        let listeners: Vec<Notify> = self.listeners.lock().unwrap().1.iter().map(|(_, l)| l.clone()).collect();
        for l in listeners {
            l(level, message);
        }
    }

    fn on_write(&self, instance: &str, entry: WriteRecord) {
        if WRITE_SCOPE.try_with(|scope| scope.lock().unwrap().push(entry.clone())).is_err() {
            // Hors d'un appel d'outil, c'est le minuteur de retour qui agit seul.
            self.audit(json!({ "instance": instance, "tool": "(background)", "writes": [entry.to_json()] }));
        }
    }

    /// Un journal impossible à écrire doit arrêter le serveur maintenant, pas échouer sans bruit plus tard.
    fn assert_audit_writable(path: &str) -> Result<()> {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map(|_| ())
            .map_err(|e| OpnError::new(ErrorType::ConfigError, format!("OPNSENSE_AUDIT_LOG: cannot write to {path}: {e}")))
    }
}

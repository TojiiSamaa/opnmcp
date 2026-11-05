//! Changements sûrs du pare-feu : préparer, vérifier, appliquer, confirmer ou annuler.
//!
//! OPNsense 26.7 a retiré l'API savepoint/apply(revision)/cancelRollback : le minuteur de 60 s côté
//! pare-feu n'existe plus en amont. Deux protections :
//!  - côté pare-feu (< 26.7) : le minuteur natif, qui joue même si ce serveur perd la connexion ;
//!  - côté serveur (26.7+) : avant la première écriture on note la dernière sauvegarde de configuration
//!    (identique à la configuration active) ; sans confirmation à temps, ce processus la restaure.

use crate::client::{OpnsenseClient, RequestOptions};
use crate::error::{ErrorType, OpnError, Result};
use crate::model::{assert_applied, assert_ok};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::sync::{Arc, Mutex, Weak};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::task::JoinHandle;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protection {
    FirewallSide,
    ServerSide,
    None,
}

impl Protection {
    pub fn as_str(self) -> &'static str {
        match self {
            Protection::FirewallSide => "firewall-side",
            Protection::ServerSide => "server-side",
            Protection::None => "none",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeState {
    Staged,
    Armed,
    RollbackBlocked,
    RollbackFailed,
}

impl ChangeState {
    fn as_str(self) -> &'static str {
        match self {
            ChangeState::Staged => "staged",
            ChangeState::Armed => "armed",
            ChangeState::RollbackBlocked => "rollback_blocked",
            ChangeState::RollbackFailed => "rollback_failed",
        }
    }
}

/// Ce qu'un changement a touché : le savepoint natif ne couvre que le modèle de filtre.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangeScope {
    Filter,
    Nat,
    Alias,
    Other,
}

impl ChangeScope {
    fn as_str(self) -> &'static str {
        match self {
            ChangeScope::Filter => "filter",
            ChangeScope::Nat => "nat",
            ChangeScope::Alias => "alias",
            ChangeScope::Other => "other",
        }
    }
}

#[derive(Clone, Debug)]
pub struct ChangeEntry {
    pub at: String,
    pub action: String,
    pub scope: ChangeScope,
    pub summary: String,
    pub uuid: Option<String>,
}

impl ChangeEntry {
    fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("at".into(), json!(self.at));
        m.insert("action".into(), json!(self.action));
        m.insert("scope".into(), json!(self.scope.as_str()));
        m.insert("summary".into(), json!(self.summary));
        if let Some(u) = &self.uuid {
            m.insert("uuid".into(), json!(u));
        }
        Value::Object(m)
    }
}

struct ChangeSet {
    id: u64,
    started_at: String,
    state: ChangeState,
    entries: Vec<ChangeEntry>,
    baseline_backup: Option<String>,
    native_revision: Option<String>,
    protection: Option<Protection>,
    expires_at_ms: Option<i64>,
    last_error: Option<String>,
    timer: Option<JoinHandle<()>>,
    retries: u32,
    /// Révisions enregistrées par les écritures de ce changement : toute autre depuis la base n'est pas à nous.
    own_revisions: HashSet<String>,
    /// Le rechargement est parti et n'a pas encore répondu.
    applying: bool,
    /// Des appels d'outils peuvent tourner en parallèle : l'échec de l'un ne doit pas abandonner un changement que l'autre fait encore.
    writes_in_flight: u32,
}

#[derive(Default)]
struct Inner {
    current: Option<ChangeSet>,
    history: Vec<(String, String)>,
    notices: Vec<String>,
    next_id: u64,
}

pub type Notify = Arc<dyn Fn(&str, &str) + Send + Sync>;

const NATIVE_TIMER_SECONDS: i64 = 60;
/// configd laisse 120 s à un rechargement, bien plus que le délai de requête usuel.
const RELOAD_TIMEOUT_MS: u64 = 130_000;
const DEFAULT_RETRY_INTERVAL_MS: u64 = 10_000;
const MAX_RETRIES: u32 = 18;

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn now_iso() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn is_endpoint_missing(e: &OpnError) -> bool {
    e.is(ErrorType::NotFound)
}

/// Ces erreurs prouvent que la requête a été refusée. Après toute autre, le rechargement a pu avoir lieu.
fn was_refused(e: &OpnError) -> bool {
    e.is_any(&[
        ErrorType::Forbidden,
        ErrorType::NotFound,
        ErrorType::BadRequest,
        ErrorType::AuthFailed,
        ErrorType::BlockedEndpoint,
        ErrorType::WriteDisabled,
    ])
}

#[derive(Clone, Debug)]
struct BackupItem {
    id: String,
    username: Option<String>,
    description: Option<String>,
}

pub struct ChangeManager {
    client: Arc<OpnsenseClient>,
    notify: Notify,
    retry_interval_ms: u64,
    inner: Mutex<Inner>,
    me: Weak<ChangeManager>,
    /// Les appels parallèles partagent une seule base.
    begin_lock: tokio::sync::Mutex<()>,
    /// Une seule restauration à la fois.
    rollback_lock: tokio::sync::Mutex<()>,
    rollback_running: Mutex<bool>,
}

impl ChangeManager {
    pub fn new(
        client: Arc<OpnsenseClient>,
        notify: Notify,
        retry_interval_ms: Option<u64>,
    ) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            client,
            notify,
            retry_interval_ms: retry_interval_ms.unwrap_or(DEFAULT_RETRY_INTERVAL_MS),
            inner: Mutex::new(Inner::default()),
            me: me.clone(),
            begin_lock: tokio::sync::Mutex::new(()),
            rollback_lock: tokio::sync::Mutex::new(()),
            rollback_running: Mutex::new(false),
        })
    }

    fn rollback_in_flight(&self) -> bool {
        *self.rollback_running.lock().unwrap()
    }

    /// À appeler avant la première écriture d'un changement : la base doit la précéder.
    pub async fn begin_if_needed(&self) -> Result<()> {
        if self.rollback_in_flight() {
            return Err(OpnError::new(
                ErrorType::ChangeInProgress,
                "A rollback is running, so this was not sent.",
            )
            .hint("See opn_pending_changes, and try again once it has finished."));
        }
        let _guard = self.begin_lock.lock().await;
        {
            let inner = self.inner.lock().unwrap();
            if let Some(set) = &inner.current {
                if set.state == ChangeState::Staged {
                    return Ok(());
                }
                // Il ne ferait pas partie de ce qui a été appliqué, et confirmer le dirait quand même permanent.
                return Err(OpnError::new(ErrorType::ChangeInProgress, "The last firewall change is still waiting to be confirmed or rolled back, so this was not sent.")
                    .hint("Call opn_confirm_changes or opn_rollback_changes first. See opn_pending_changes."));
            }
        }
        self.begin().await
    }

    async fn begin(&self) -> Result<()> {
        let caps = self.client.capabilities().await?;
        let mut native_revision = None;
        if caps.native_savepoints != Some(false) {
            match self
                .client
                .post(
                    "firewall/filter/savepoint",
                    None,
                    RequestOptions::new().curated(),
                )
                .await
            {
                Ok(res) => {
                    if let Some(r) = res
                        .get("revision")
                        .and_then(Value::as_str)
                        .filter(|r| !r.is_empty())
                    {
                        native_revision = Some(r.to_string());
                    }
                }
                Err(e) if is_endpoint_missing(&e) => self.client.note_no_native_savepoints(),
                Err(e) => return Err(e),
            }
        }
        let baseline = self.latest_backup().await?;
        let mut inner = self.inner.lock().unwrap();
        inner.next_id += 1;
        let id = inner.next_id;
        inner.current = Some(ChangeSet {
            id,
            started_at: now_iso(),
            state: ChangeState::Staged,
            entries: Vec::new(),
            baseline_backup: baseline,
            native_revision,
            protection: None,
            expires_at_ms: None,
            last_error: None,
            timer: None,
            retries: 0,
            own_revisions: HashSet::new(),
            applying: false,
            writes_in_flight: 0,
        });
        Ok(())
    }

    /// Exécute une écriture du changement en cours et note les révisions qu'elle a enregistrées.
    pub async fn track_write<T, F, Fut>(&self, write: F) -> Result<T>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let (id, has_baseline) = {
            let mut inner = self.inner.lock().unwrap();
            match inner.current.as_mut() {
                None => (None, false),
                Some(set) => {
                    set.writes_in_flight += 1;
                    (Some(set.id), set.baseline_backup.is_some())
                }
            }
        };
        let Some(id) = id else { return write().await };
        let outcome = async {
            if !has_baseline {
                return write().await;
            }
            let before = self.latest_backup().await.ok().flatten();
            let result = write().await?;
            // Sans cette liste la révision compte comme celle de quelqu'un d'autre : l'annulation s'arrête et demande.
            let items = if before.is_some() {
                self.list_backups().await.unwrap_or_default()
            } else {
                Vec::new()
            };
            if let Some(index) = items.iter().position(|i| Some(&i.id) == before.as_ref()) {
                let mut inner = self.inner.lock().unwrap();
                if let Some(set) = inner.current.as_mut().filter(|s| s.id == id) {
                    for item in &items[..index] {
                        set.own_revisions.insert(item.id.clone());
                    }
                }
            }
            Ok(result)
        }
        .await;
        let mut inner = self.inner.lock().unwrap();
        if let Some(set) = inner.current.as_mut().filter(|s| s.id == id) {
            set.writes_in_flight = set.writes_in_flight.saturating_sub(1);
        }
        outcome
    }

    pub fn record(&self, action: &str, scope: ChangeScope, summary: &str, uuid: Option<String>) {
        if let Some(set) = self.inner.lock().unwrap().current.as_mut() {
            set.entries.push(ChangeEntry {
                at: now_iso(),
                action: action.into(),
                scope,
                summary: summary.into(),
                uuid,
            });
        }
    }

    /// Si la première écriture d'un changement a échoué, il n'y a encore rien à protéger.
    pub fn discard_if_empty(&self) {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .current
            .as_ref()
            .is_some_and(|s| s.entries.is_empty() && s.writes_in_flight == 0)
        {
            inner.current = None;
        }
    }

    pub fn protection_available(&self) -> Protection {
        match self.inner.lock().unwrap().current.as_ref() {
            None => Protection::None,
            Some(set) => Self::protection_of(set),
        }
    }

    fn protection_of(set: &ChangeSet) -> Protection {
        if Self::can_use_native(set) {
            Protection::FirewallSide
        } else if set.baseline_backup.is_some() {
            Protection::ServerSide
        } else {
            Protection::None
        }
    }

    /// Le retour natif ne restaure que le modèle de filtre : le reste passe par la sauvegarde.
    fn can_use_native(set: &ChangeSet) -> bool {
        set.native_revision.is_some() && set.entries.iter().all(|e| e.scope == ChangeScope::Filter)
    }

    pub async fn apply(&self, rollback_seconds: i64) -> Result<Value> {
        let snapshot = {
            let inner = self.inner.lock().unwrap();
            inner.current.as_ref().map(|s| {
                (
                    s.id,
                    s.state,
                    s.native_revision.clone(),
                    s.entries.iter().any(|e| e.scope == ChangeScope::Alias),
                    s.baseline_backup.clone(),
                    Self::protection_of(s),
                )
            })
        };
        let Some((id, state, native_revision, has_alias, baseline, protection)) = snapshot else {
            let res = self
                .client
                .post(
                    "firewall/filter/apply",
                    None,
                    RequestOptions::new()
                        .curated()
                        .timeout_ms(RELOAD_TIMEOUT_MS),
                )
                .await?;
            assert_ok(&res, "Reloading the firewall")?;
            return Ok(
                json!({ "status": "applied", "protection": "none", "message": "No change tracked by this server: the firewall was reloaded with its current configuration. Nothing to confirm." }),
            );
        };
        if self.rollback_in_flight() || state != ChangeState::Staged {
            return Err(OpnError::new(
                ErrorType::ChangeInProgress,
                "These changes were already applied: there is nothing new to apply.",
            )
            .hint("Call opn_confirm_changes or opn_rollback_changes. See opn_pending_changes."));
        }

        let seconds = if protection == Protection::FirewallSide {
            NATIVE_TIMER_SECONDS
        } else {
            rollback_seconds
        };
        // Le minuteur démarre d'abord : un rechargement peut durer plus que la requête, et le changement serait actif sans rien pour l'annuler.
        // Le natif démarre sur le pare-feu à l'arrivée de la requête, le nôtre ne doit pas durer plus.
        match protection {
            Protection::FirewallSide => self.arm(id, protection, seconds),
            Protection::ServerSide => {
                self.arm(id, protection, (RELOAD_TIMEOUT_MS / 1000) as i64 + seconds)
            }
            Protection::None => {}
        }
        self.with_set(id, |s| s.applying = true);

        let mut live = false;
        let result: Result<()> = self
            .track_write(|| async {
                if protection == Protection::FirewallSide {
                    let rev = native_revision.clone().unwrap_or_default();
                    let res = self
                        .client
                        .post(
                            "firewall/filter/apply",
                            None,
                            RequestOptions::new()
                                .curated()
                                .timeout_ms(RELOAD_TIMEOUT_MS)
                                .param(rev),
                        )
                        .await?;
                    assert_ok(&res, "Applying the changes")?;
                    return Ok(());
                }
                if has_alias {
                    // Cet appel recharge déjà le filtre : à partir de là le changement est actif.
                    let res = self
                        .client
                        .post(
                            "firewall/alias/reconfigure",
                            None,
                            RequestOptions::new()
                                .curated()
                                .timeout_ms(RELOAD_TIMEOUT_MS),
                        )
                        .await?;
                    assert_applied(&res, "Loading the aliases", false)?;
                    live = true;
                }
                let res = self
                    .client
                    .post(
                        "firewall/filter/apply",
                        None,
                        RequestOptions::new()
                            .curated()
                            .timeout_ms(RELOAD_TIMEOUT_MS),
                    )
                    .await?;
                assert_ok(&res, "Applying the changes")?;
                Ok(())
            })
            .await;
        self.with_set(id, |s| s.applying = false);

        if let Err(err) = result {
            if protection == Protection::None {
                return Err(err);
            }
            if was_refused(&err) && !live {
                self.disarm(id);
                return Err(err);
            }
            if protection == Protection::ServerSide {
                self.arm(id, protection, seconds);
            }
            let (expires, baseline) = self
                .with_set(id, |s| (s.expires_at_ms, s.baseline_backup.clone()))
                .unwrap_or((None, baseline));
            return Ok(json!({
                "status": "apply_outcome_unknown",
                "protection": protection.as_str(),
                "error": err.message,
                "rollback_in_seconds": ((expires.unwrap_or_else(now_ms) - now_ms()) as f64 / 1000.0).round().max(0.0) as i64,
                "confirm_with": "opn_confirm_changes",
                "rollback_with": "opn_rollback_changes",
                "baseline_backup": baseline,
                "message": "The firewall did not report a successful reload, so the changes may or may not be live. The rollback timer is running: without opn_confirm_changes, the previous configuration comes back.",
            }));
        }

        if protection == Protection::None {
            // Appliqué sans retour possible : plus rien à confirmer.
            self.finish(id, "applied without rollback protection");
            return Ok(
                json!({ "status": "applied", "protection": "none", "message": "The changes are live and permanent. No automatic rollback was possible." }),
            );
        }
        if !self.is_current(id) {
            return Ok(
                json!({ "status": "reverted", "protection": protection.as_str(), "message": "The reload took longer than the rollback timer of the firewall, which has reverted the changes." }),
            );
        }
        if protection == Protection::ServerSide {
            self.arm(id, protection, seconds);
        }

        let reachable = self.check_reachable().await;
        let (expires, baseline, lockout) = self
            .with_set(id, |s| {
                (
                    s.expires_at_ms,
                    s.baseline_backup.clone(),
                    lockout_message(s.baseline_backup.as_deref()),
                )
            })
            .unwrap_or((None, None, String::new()));
        let left = ((expires.unwrap_or_else(now_ms) - now_ms()) as f64 / 1000.0)
            .round()
            .max(0.0) as i64;
        let message = if protection == Protection::FirewallSide {
            format!("The changes are live. The firewall itself reverts them in {left} s unless opn_confirm_changes is called.")
        } else {
            format!("The changes are live. This server reverts them in {left} s unless opn_confirm_changes is called. This timer runs here, not on the firewall: it cannot help if the connection to the firewall is lost and stays lost.")
        };
        let mut out = json!({
            "status": "pending_confirmation",
            "protection": protection.as_str(),
            "reachable_after_apply": reachable,
            "rollback_in_seconds": left,
            "confirm_with": "opn_confirm_changes",
            "rollback_with": "opn_rollback_changes",
            "baseline_backup": baseline,
            "message": message,
        });
        if !reachable {
            out["warning"] = json!(lockout);
        }
        Ok(out)
    }

    fn with_set<R>(&self, id: u64, f: impl FnOnce(&mut ChangeSet) -> R) -> Option<R> {
        let mut inner = self.inner.lock().unwrap();
        inner.current.as_mut().filter(|s| s.id == id).map(f)
    }

    fn is_current(&self, id: u64) -> bool {
        self.inner
            .lock()
            .unwrap()
            .current
            .as_ref()
            .is_some_and(|s| s.id == id)
    }

    fn arm(&self, id: u64, protection: Protection, seconds: i64) {
        let me = self.me.clone();
        let handle = tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(seconds.max(0) as u64)).await;
            if let Some(me) = me.upgrade() {
                me.on_deadline(id).await;
            }
        });
        self.with_set(id, |s| {
            if let Some(t) = s.timer.take() {
                t.abort();
            }
            s.protection = Some(protection);
            s.state = ChangeState::Armed;
            s.expires_at_ms = Some(now_ms() + seconds * 1000);
            s.timer = Some(handle);
        });
    }

    fn disarm(&self, id: u64) {
        self.with_set(id, |s| {
            if let Some(t) = s.timer.take() {
                t.abort();
            }
            s.state = ChangeState::Staged;
            s.protection = None;
            s.expires_at_ms = None;
        });
    }

    async fn on_deadline(self: Arc<Self>, id: u64) {
        let protection = self.with_set(id, |s| s.protection).flatten();
        if !self.is_current(id) {
            return;
        }
        if protection == Some(Protection::FirewallSide) {
            // Le pare-feu a déjà annulé de lui-même, rien à envoyer.
            self.finish(id, "reverted by the firewall timer");
            self.announce(
                "warning",
                "The firewall changes were not confirmed in time, and the firewall reverted them.",
            );
            return;
        }
        self.auto_rollback(id).await;
    }

    fn auto_rollback(
        self: Arc<Self>,
        id: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
        Box::pin(async move {
            match self.rollback(false, Some("not confirmed in time")).await {
            Ok(_) => self.announce("warning", "The firewall changes were not confirmed in time, so this server restored the previous configuration."),
            Err(err) => {
                if !self.is_current(id) {
                    return;
                }
                let blocked = err.is(ErrorType::RollbackBlocked);
                let retries = self.with_set(id, |s| s.retries).unwrap_or(MAX_RETRIES);
                if !blocked && retries < MAX_RETRIES {
                    let me = self.me.clone();
                    let delay = self.retry_interval_ms;
                    let handle = tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        if let Some(me) = me.upgrade() {
                            me.auto_rollback(id).await;
                        }
                    });
                    self.with_set(id, |s| {
                        s.retries += 1;
                        s.state = ChangeState::RollbackFailed;
                        s.last_error = Some(err.message.clone());
                        s.timer = Some(handle);
                    });
                    return;
                }
                let lockout = self
                    .with_set(id, |s| {
                        s.state = if blocked { ChangeState::RollbackBlocked } else { ChangeState::RollbackFailed };
                        s.last_error = Some(err.message.clone());
                        lockout_message(s.baseline_backup.as_deref())
                    })
                    .unwrap_or_default();
                self.announce("error", &format!("Automatic rollback did not complete: {}. The change is still live. {lockout}", err.message));
            }
        }
        })
    }

    pub async fn confirm(&self) -> Result<Value> {
        let snapshot = {
            let inner = self.inner.lock().unwrap();
            inner.current.as_ref().map(|s| {
                (
                    s.id,
                    s.state,
                    s.applying,
                    s.protection,
                    s.native_revision.clone(),
                    s.entries.len(),
                )
            })
        };
        let Some((id, state, applying, protection, native_revision, entries)) = snapshot else {
            return Err(OpnError::new(
                ErrorType::NoPendingChange,
                "There is no pending firewall change to confirm.",
            ));
        };
        if self.rollback_in_flight() {
            return Err(OpnError::new(
                ErrorType::ChangeInProgress,
                "A rollback is running, so this change can no longer be confirmed.",
            )
            .hint("See opn_pending_changes for the outcome."));
        }
        if applying {
            return Err(OpnError::new(
                ErrorType::ChangeInProgress,
                "The firewall is still applying this change, so there is nothing to confirm yet.",
            )
            .hint("Wait for the answer of opn_apply_firewall_changes."));
        }
        if state == ChangeState::Staged {
            return Err(OpnError::new(
                ErrorType::NoPendingChange,
                "The changes are staged but not applied yet, so there is nothing to confirm.",
            )
            .hint("Call opn_apply_firewall_changes first."));
        }
        let native = protection == Some(Protection::FirewallSide);
        if native {
            // Le script derrière n'affiche rien, qu'il marche ou non : la réponse ne prouve rien.
            let rev = native_revision.unwrap_or_default();
            let res = self
                .client
                .post(
                    "firewall/filter/cancel_rollback",
                    None,
                    RequestOptions::new().curated().param(rev),
                )
                .await?;
            assert_applied(&res, "Cancelling the firewall timer", true)?;
            if !self.is_current(id) {
                return Err(OpnError::new(
                    ErrorType::NoPendingChange,
                    "The delay ran out in the meantime, and the firewall reverted the changes.",
                ));
            }
        }
        self.finish(id, "confirmed");
        let mut out = json!({ "status": "confirmed", "changes": entries, "message": "The changes are permanent." });
        if native {
            out["note"] = json!("The firewall does not report whether its timer was cancelled. Check that the change is still there once the delay has passed.");
        }
        Ok(out)
    }

    /// Un minuteur et un appel d'outil peuvent le demander : une seule restauration à la fois.
    pub async fn rollback(&self, force: bool, reason: Option<&str>) -> Result<Value> {
        let _guard = self.rollback_lock.lock().await;
        *self.rollback_running.lock().unwrap() = true;
        let result = self.run_rollback(force, reason).await;
        *self.rollback_running.lock().unwrap() = false;
        result
    }

    async fn run_rollback(&self, force: bool, reason: Option<&str>) -> Result<Value> {
        let snapshot = {
            let inner = self.inner.lock().unwrap();
            inner.current.as_ref().map(|s| {
                (
                    s.id,
                    Self::can_use_native(s),
                    s.native_revision.clone(),
                    s.baseline_backup.clone(),
                    s.entries.iter().any(|e| e.scope == ChangeScope::Alias),
                    s.entries.len(),
                    s.own_revisions.clone(),
                )
            })
        };
        let Some((id, native, native_revision, baseline, has_alias, undone, own)) = snapshot else {
            return Err(OpnError::new(ErrorType::NoPendingChange, "There is no pending firewall change to roll back.").hint("To go back to an older configuration, use opn_list_config_backups and opn_restore_config_backup."));
        };
        let method;
        if native {
            let rev = native_revision.unwrap_or_default();
            let res = self
                .client
                .post(
                    "firewall/filter/revert",
                    None,
                    RequestOptions::new()
                        .curated()
                        .timeout_ms(RELOAD_TIMEOUT_MS)
                        .param(rev),
                )
                .await?;
            assert_ok(&res, "Reverting the firewall changes")?;
            method = "native revert";
        } else if let Some(baseline) = baseline {
            self.assert_no_foreign_changes(&baseline, &own, force)
                .await?;
            // Suivi, car une nouvelle tentative ne doit pas prendre cet enregistrement pour celui d'un autre.
            let b = baseline.clone();
            let res = self
                .track_write(|| async {
                    self.client
                        .post(
                            "core/backup/revert_backup",
                            None,
                            RequestOptions::new().curated().param(b),
                        )
                        .await
                })
                .await?;
            let status = res
                .get("status")
                .map(|v| {
                    v.as_str()
                        .map(String::from)
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default();
            if status != "reverted" {
                return Err(OpnError::new(
                    ErrorType::RollbackFailed,
                    format!(
                        "The firewall did not restore backup {baseline} (status: {}).",
                        if status.is_empty() {
                            "unknown"
                        } else {
                            &status
                        }
                    ),
                )
                .details(res));
            }
            // revert_backup ne réécrit que config.xml : rien n'atteint pf avant le rechargement.
            let res = self
                .client
                .post(
                    "firewall/filter/apply",
                    None,
                    RequestOptions::new()
                        .curated()
                        .timeout_ms(RELOAD_TIMEOUT_MS),
                )
                .await?;
            assert_ok(&res, "Reloading the firewall")?;
            if has_alias {
                let res = self
                    .client
                    .post(
                        "firewall/alias/reconfigure",
                        None,
                        RequestOptions::new()
                            .curated()
                            .timeout_ms(RELOAD_TIMEOUT_MS),
                    )
                    .await?;
                assert_applied(&res, "Reloading the aliases", false)?;
            }
            method = "configuration restore";
        } else {
            return Err(OpnError::new(ErrorType::RollbackFailed, "No baseline is available for this change: it cannot be rolled back automatically.")
                .hint("Undo the changes by hand, or use opn_restore_config_backup with a backup from before the change."));
        }
        let suffix = reason.map(|r| format!(": {r}")).unwrap_or_default();
        self.finish(id, &format!("rolled back ({method}){suffix}"));
        Ok(json!({ "status": "rolled_back", "method": method, "changes_undone": undone }))
    }

    /// Restaurer une sauvegarde remplace tout config.xml : cela jetterait aussi ce qui a été enregistré entre-temps.
    /// Seules les révisions de ce changement peuvent partir.
    async fn assert_no_foreign_changes(
        &self,
        baseline: &str,
        own: &HashSet<String>,
        force: bool,
    ) -> Result<()> {
        let items = self.list_backups().await?;
        let Some(index) = items.iter().position(|i| i.id == baseline) else {
            return Err(OpnError::new(ErrorType::RollbackFailed, format!("Backup {baseline} is no longer on the firewall."))
                .hint("The backup count may be too low for the number of changes. Pick another backup with opn_list_config_backups."));
        };
        let foreign: Vec<&BackupItem> = items[..index]
            .iter()
            .filter(|i| !own.contains(&i.id))
            .collect();
        if !foreign.is_empty() && !force {
            let revisions: Vec<Value> = foreign
                .iter()
                .map(
                    |f| json!({ "id": f.id, "username": f.username, "description": f.description }),
                )
                .collect();
            return Err(OpnError::new(
                ErrorType::RollbackBlocked,
                format!("The configuration was also saved outside this change since the baseline ({} revision(s)), by someone else or by a service write: restoring it would discard that too.", foreign.len()),
            )
            .details(json!({ "revisions": revisions }))
            .hint("Review the revisions with opn_diff_config_backups, then undo the change by hand or call opn_rollback_changes with force=true."));
        }
        Ok(())
    }

    pub fn status(&self) -> Value {
        let inner = self.inner.lock().unwrap();
        let recent: Vec<Value> = inner
            .history
            .iter()
            .rev()
            .take(5)
            .rev()
            .map(|(at, event)| json!({ "at": at, "event": event }))
            .collect();
        let Some(set) = inner.current.as_ref() else {
            return json!({ "pending": false, "recent": recent });
        };
        let remaining = set
            .expires_at_ms
            .map(|e| ((e - now_ms()) as f64 / 1000.0).round().max(0.0) as i64);
        let mut out = json!({
            "pending": true,
            "state": set.state.as_str(),
            "started_at": set.started_at,
            "protection": set.protection.unwrap_or_else(|| Self::protection_of(set)).as_str(),
            "rollback_in_seconds": if set.state == ChangeState::Armed { json!(remaining) } else { Value::Null },
            "baseline_backup": set.baseline_backup,
            "native_revision": set.native_revision,
            "changes": set.entries.iter().map(ChangeEntry::to_json).collect::<Vec<_>>(),
            "recent": recent,
        });
        if set.state == ChangeState::Staged {
            out["note"] = json!("Staged changes are saved in the configuration but not live yet. Any later firewall reload, including one started from the web interface, makes them live.");
        }
        if let Some(e) = &set.last_error {
            out["last_error"] = json!(e);
            out["recovery"] = json!(lockout_message(set.baseline_backup.as_deref()));
        }
        out
    }

    /// Appelé à l'arrêt : par contrat, un changement jamais confirmé ne survit pas.
    pub async fn shutdown(&self) {
        let snapshot = {
            let inner = self.inner.lock().unwrap();
            inner.current.as_ref().map(|s| (s.state, s.protection))
        };
        let Some((state, protection)) = snapshot else {
            return;
        };
        if state == ChangeState::Armed && protection == Some(Protection::ServerSide) {
            match self
                .rollback(false, Some("server shutting down before confirmation"))
                .await
            {
                Ok(_) => eprintln!("[osmcp] unconfirmed firewall change rolled back on shutdown"),
                Err(e) => eprintln!(
                    "[osmcp] could not roll back the unconfirmed change on shutdown: {}",
                    e.message
                ),
            }
        } else if state == ChangeState::Staged {
            eprintln!("[osmcp] warning: firewall changes are staged but not applied; the next firewall reload will make them live.");
        }
        if let Some(set) = self.inner.lock().unwrap().current.as_mut() {
            if let Some(t) = set.timer.take() {
                t.abort();
            }
        }
    }

    /// Messages pour l'agent sur ce qui s'est passé entre deux appels d'outils.
    pub fn drain_notices(&self) -> Vec<String> {
        std::mem::take(&mut self.inner.lock().unwrap().notices)
    }

    fn announce(&self, level: &str, message: &str) {
        self.inner.lock().unwrap().notices.push(message.to_string());
        (self.notify)(level, message);
    }

    fn finish(&self, id: u64, event: &str) {
        let mut inner = self.inner.lock().unwrap();
        if inner.current.as_ref().is_some_and(|s| s.id == id) {
            if let Some(set) = inner.current.take() {
                // Le minuteur peut être celui qui nous appelle : on ne l'interrompt que s'il est ailleurs.
                if let Some(t) = set.timer {
                    if !t.is_finished() {
                        t.abort();
                    }
                }
            }
        }
        inner.history.push((now_iso(), event.to_string()));
    }

    async fn check_reachable(&self) -> bool {
        match self
            .client
            .get(
                "core/system/status",
                RequestOptions::new().timeout_ms(8_000).fresh(),
            )
            .await
        {
            Ok(_) => true,
            // Un 403 ou un 404 prouve quand même que le pare-feu a répondu.
            Err(e) => !e.is_any(&[
                ErrorType::Unreachable,
                ErrorType::Timeout,
                ErrorType::TlsError,
            ]),
        }
    }

    async fn list_backups(&self) -> Result<Vec<BackupItem>> {
        let res = self
            .client
            .get("core/backup/backups", RequestOptions::new().param("this"))
            .await?;
        let items = res
            .get("items")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(items
            .iter()
            .filter_map(|i| {
                Some(BackupItem {
                    id: i.get("id")?.as_str()?.to_string(),
                    username: i.get("username").and_then(Value::as_str).map(String::from),
                    description: i
                        .get("description")
                        .and_then(Value::as_str)
                        .map(String::from),
                })
            })
            .collect())
    }

    /// La sauvegarde à laquelle revenir, ou None quand l'utilisateur d'API ne peut pas les lister.
    pub async fn latest_backup(&self) -> Result<Option<String>> {
        match self.list_backups().await {
            Ok(items) => Ok(items.into_iter().next().map(|i| i.id)),
            // Pas de privilège sur les sauvegardes n'est pas fatal : cela apparaîtra plus tard comme « aucune protection ».
            Err(e) if e.is_any(&[ErrorType::Forbidden, ErrorType::NotFound]) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

fn lockout_message(baseline: Option<&str>) -> String {
    let backup = match baseline {
        Some(b) => format!(" Restore backup {b}"),
        None => " Restore the last good configuration".to_string(),
    };
    format!("If the firewall stays unreachable, the rollback cannot be sent.{backup} from the console (opnsense-shell, option 13 \"Restore a backup\") or from any path that still reaches the web interface.")
}

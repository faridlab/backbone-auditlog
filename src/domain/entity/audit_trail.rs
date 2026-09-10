use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use super::AuditEventType;
use super::AuditStatus;

/// Strongly-typed ID for AuditTrail
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AuditTrailId(pub Uuid);

impl AuditTrailId {
    pub fn new(id: Uuid) -> Self { Self(id) }
    pub fn generate() -> Self { Self(Uuid::new_v4()) }
    pub fn into_inner(self) -> Uuid { self.0 }
}

impl std::fmt::Display for AuditTrailId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for AuditTrailId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

impl From<Uuid> for AuditTrailId {
    fn from(id: Uuid) -> Self { Self(id) }
}

impl From<AuditTrailId> for Uuid {
    fn from(id: AuditTrailId) -> Self { id.0 }
}

impl AsRef<Uuid> for AuditTrailId {
    fn as_ref(&self) -> &Uuid { &self.0 }
}

impl std::ops::Deref for AuditTrailId {
    type Target = Uuid;
    fn deref(&self) -> &Self::Target { &self.0 }
}

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct AuditTrail {
    pub id: Uuid,
    pub occurred_at: DateTime<Utc>,
    pub event_type: AuditEventType,
    pub action: String,
    pub actor: String,
    pub subject_type: Option<String>,
    pub subject_id: Option<String>,
    pub changed: Option<serde_json::Value>,
    pub reason: Option<String>,
    pub status: AuditStatus,
    pub correlation_id: Option<String>,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub http_method: Option<String>,
    pub resource_path: Option<String>,
    pub txid: String,
}

impl AuditTrail {
    /// Create a builder for AuditTrail
    pub fn builder() -> AuditTrailBuilder {
        <AuditTrailBuilder as Default>::default()
    }

    /// Create a new AuditTrail with required fields
    pub fn new(occurred_at: DateTime<Utc>, event_type: AuditEventType, action: String, actor: String, status: AuditStatus, txid: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            occurred_at,
            event_type,
            action,
            actor,
            subject_type: None,
            subject_id: None,
            changed: None,
            reason: None,
            status,
            correlation_id: None,
            client_ip: None,
            user_agent: None,
            http_method: None,
            resource_path: None,
            txid,
        }
    }

    /// Get the entity's unique identifier
    pub fn id(&self) -> &Uuid {
        &self.id
    }

    /// Get a strongly-typed ID for this entity
    pub fn typed_id(&self) -> AuditTrailId {
        AuditTrailId(self.id)
    }

    /// Get the current status
    pub fn status(&self) -> &AuditStatus {
        &self.status
    }


    // ==========================================================
    // Fluent Setters (with_* for optional fields)
    // ==========================================================

    /// Set the subject_type field (chainable)
    pub fn with_subject_type(mut self, value: String) -> Self {
        self.subject_type = Some(value);
        self
    }

    /// Set the subject_id field (chainable)
    pub fn with_subject_id(mut self, value: String) -> Self {
        self.subject_id = Some(value);
        self
    }

    /// Set the changed field (chainable)
    pub fn with_changed(mut self, value: serde_json::Value) -> Self {
        self.changed = Some(value);
        self
    }

    /// Set the reason field (chainable)
    pub fn with_reason(mut self, value: String) -> Self {
        self.reason = Some(value);
        self
    }

    /// Set the correlation_id field (chainable)
    pub fn with_correlation_id(mut self, value: String) -> Self {
        self.correlation_id = Some(value);
        self
    }

    /// Set the client_ip field (chainable)
    pub fn with_client_ip(mut self, value: String) -> Self {
        self.client_ip = Some(value);
        self
    }

    /// Set the user_agent field (chainable)
    pub fn with_user_agent(mut self, value: String) -> Self {
        self.user_agent = Some(value);
        self
    }

    /// Set the http_method field (chainable)
    pub fn with_http_method(mut self, value: String) -> Self {
        self.http_method = Some(value);
        self
    }

    /// Set the resource_path field (chainable)
    pub fn with_resource_path(mut self, value: String) -> Self {
        self.resource_path = Some(value);
        self
    }

    // ==========================================================
    // Partial Update
    // ==========================================================

    /// Apply partial updates from a map of field name to JSON value
    pub fn apply_patch(&mut self, fields: std::collections::HashMap<String, serde_json::Value>) {
        for (key, value) in fields {
            match key.as_str() {
                "occurred_at" => {
                    if let Ok(v) = serde_json::from_value(value) { self.occurred_at = v; }
                }
                "event_type" => {
                    if let Ok(v) = serde_json::from_value(value) { self.event_type = v; }
                }
                "action" => {
                    if let Ok(v) = serde_json::from_value(value) { self.action = v; }
                }
                "actor" => {
                    if let Ok(v) = serde_json::from_value(value) { self.actor = v; }
                }
                "subject_type" => {
                    if let Ok(v) = serde_json::from_value(value) { self.subject_type = v; }
                }
                "subject_id" => {
                    if let Ok(v) = serde_json::from_value(value) { self.subject_id = v; }
                }
                "changed" => {
                    if let Ok(v) = serde_json::from_value(value) { self.changed = v; }
                }
                "reason" => {
                    if let Ok(v) = serde_json::from_value(value) { self.reason = v; }
                }
                "status" => {
                    if let Ok(v) = serde_json::from_value(value) { self.status = v; }
                }
                "correlation_id" => {
                    if let Ok(v) = serde_json::from_value(value) { self.correlation_id = v; }
                }
                "client_ip" => {
                    if let Ok(v) = serde_json::from_value(value) { self.client_ip = v; }
                }
                "user_agent" => {
                    if let Ok(v) = serde_json::from_value(value) { self.user_agent = v; }
                }
                "http_method" => {
                    if let Ok(v) = serde_json::from_value(value) { self.http_method = v; }
                }
                "resource_path" => {
                    if let Ok(v) = serde_json::from_value(value) { self.resource_path = v; }
                }
                "txid" => {
                    if let Ok(v) = serde_json::from_value(value) { self.txid = v; }
                }
                _ => {} // ignore unknown fields
            }
        }
    }

    // <<< CUSTOM METHODS START >>>
    // <<< CUSTOM METHODS END >>>
}

impl super::Entity for AuditTrail {
    type Id = Uuid;

    fn entity_id(&self) -> &Self::Id {
        &self.id
    }

    fn entity_type() -> &'static str {
        "AuditTrail"
    }
}

impl backbone_core::PersistentEntity for AuditTrail {
    fn entity_id(&self) -> String {
        self.id.to_string()
    }
    fn set_entity_id(&mut self, id: String) {
        if let Ok(uuid) = uuid::Uuid::parse_str(&id) {
            self.id = uuid;
        }
    }
    fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        None
    }
    fn set_created_at(&mut self, ts: chrono::DateTime<chrono::Utc>) {
        let _ = ts;
    }
    fn updated_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        None
    }
    fn set_updated_at(&mut self, ts: chrono::DateTime<chrono::Utc>) {
        let _ = ts;
    }
    fn deleted_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        None
    }
    fn set_deleted_at(&mut self, ts: Option<chrono::DateTime<chrono::Utc>>) {
        let _ = ts;
    }
}

impl backbone_orm::EntityRepoMeta for AuditTrail {
    fn column_types() -> std::collections::HashMap<String, String> {
        let mut m = std::collections::HashMap::new();
        m.insert("id".to_string(), "uuid".to_string());
        m.insert("event_type".to_string(), "audit_event_type".to_string());
        m.insert("status".to_string(), "audit_status".to_string());
        m
    }
    fn search_fields() -> &'static [&'static str] {
        &["action", "actor", "txid"]
    }
}

/// Builder for AuditTrail entity
///
/// Provides a fluent API for constructing AuditTrail instances.
/// System fields (id, metadata, timestamps) are auto-initialized.
#[derive(Debug, Clone, Default)]
pub struct AuditTrailBuilder {
    occurred_at: Option<DateTime<Utc>>,
    event_type: Option<AuditEventType>,
    action: Option<String>,
    actor: Option<String>,
    subject_type: Option<String>,
    subject_id: Option<String>,
    changed: Option<serde_json::Value>,
    reason: Option<String>,
    status: Option<AuditStatus>,
    correlation_id: Option<String>,
    client_ip: Option<String>,
    user_agent: Option<String>,
    http_method: Option<String>,
    resource_path: Option<String>,
    txid: Option<String>,
}

impl AuditTrailBuilder {
    /// Set the occurred_at field (default: `Utc::now()`)
    pub fn occurred_at(mut self, value: DateTime<Utc>) -> Self {
        self.occurred_at = Some(value);
        self
    }

    /// Set the event_type field (required)
    pub fn event_type(mut self, value: AuditEventType) -> Self {
        self.event_type = Some(value);
        self
    }

    /// Set the action field (required)
    pub fn action(mut self, value: String) -> Self {
        self.action = Some(value);
        self
    }

    /// Set the actor field (required)
    pub fn actor(mut self, value: String) -> Self {
        self.actor = Some(value);
        self
    }

    /// Set the subject_type field (optional)
    pub fn subject_type(mut self, value: String) -> Self {
        self.subject_type = Some(value);
        self
    }

    /// Set the subject_id field (optional)
    pub fn subject_id(mut self, value: String) -> Self {
        self.subject_id = Some(value);
        self
    }

    /// Set the changed field (optional)
    pub fn changed(mut self, value: serde_json::Value) -> Self {
        self.changed = Some(value);
        self
    }

    /// Set the reason field (optional)
    pub fn reason(mut self, value: String) -> Self {
        self.reason = Some(value);
        self
    }

    /// Set the status field (required)
    pub fn status(mut self, value: AuditStatus) -> Self {
        self.status = Some(value);
        self
    }

    /// Set the correlation_id field (optional)
    pub fn correlation_id(mut self, value: String) -> Self {
        self.correlation_id = Some(value);
        self
    }

    /// Set the client_ip field (optional)
    pub fn client_ip(mut self, value: String) -> Self {
        self.client_ip = Some(value);
        self
    }

    /// Set the user_agent field (optional)
    pub fn user_agent(mut self, value: String) -> Self {
        self.user_agent = Some(value);
        self
    }

    /// Set the http_method field (optional)
    pub fn http_method(mut self, value: String) -> Self {
        self.http_method = Some(value);
        self
    }

    /// Set the resource_path field (optional)
    pub fn resource_path(mut self, value: String) -> Self {
        self.resource_path = Some(value);
        self
    }

    /// Set the txid field (required)
    pub fn txid(mut self, value: String) -> Self {
        self.txid = Some(value);
        self
    }

    /// Build the AuditTrail entity
    ///
    /// Returns Err if any required field without a default is missing.
    pub fn build(self) -> Result<AuditTrail, String> {
        let event_type = self.event_type.ok_or_else(|| "event_type is required".to_string())?;
        let action = self.action.ok_or_else(|| "action is required".to_string())?;
        let actor = self.actor.ok_or_else(|| "actor is required".to_string())?;
        let status = self.status.ok_or_else(|| "status is required".to_string())?;
        let txid = self.txid.ok_or_else(|| "txid is required".to_string())?;

        Ok(AuditTrail {
            id: Uuid::new_v4(),
            occurred_at: self.occurred_at.unwrap_or(Utc::now()),
            event_type,
            action,
            actor,
            subject_type: self.subject_type,
            subject_id: self.subject_id,
            changed: self.changed,
            reason: self.reason,
            status,
            correlation_id: self.correlation_id,
            client_ip: self.client_ip,
            user_agent: self.user_agent,
            http_method: self.http_method,
            resource_path: self.resource_path,
            txid,
        })
    }
}

//! Same-transaction audit verbs (ADR-0025).
//!
//! These are the service-emitted lane of the hybrid capture design: the write
//! verbs a composing service calls when there is no row to diff — a refused
//! write, a security edge — plus the general verb for any service that wants
//! an explicit audit row inside its own transaction. Data-change rows are the
//! OTHER lane (the generator's audit triggers), not these verbs.
//!
//! The load-bearing property is same-transaction truth: every verb takes the
//! caller's executor (a transaction, a pooled connection — whatever is running
//! the mutation), so the audit row commits with the business write and dies
//! with it on rollback. An audit trail that survives rolled-back writes is
//! lying; calling these with a pool instead of the mutation's transaction
//! throws that property away and is a caller bug.
//!
//! The `_scoped` verbs are the one sanctioned exception: for a layer that runs
//! inside the request scope but holds no transaction of its own — a gate that
//! is refusing a write, where the refusal IS the event and there is no
//! business write to share a transaction with. They take a pool and route the
//! INSERT through the framework's request-dedicated connection when one is
//! bound, so the row sees the same session GUCs (actor, correlation, request
//! fields) the refused request carried. A plain `pool.acquire()` there would
//! land on a different, unbound connection and attribute the refusal to
//! `system` — which is a lie about who was refused.
//!
//! Actor and request context are read from the session GUCs inside the INSERT,
//! so verb rows and trigger rows attribute identically:
//!
//! | GUC                    | Set by                                         | Fallback          |
//! |------------------------|------------------------------------------------|-------------------|
//! | `app.actor`            | host request middleware (per request)          | `'system'`        |
//! | `app.correlation_id`   | host middleware (accept/generate + echo)       | NULL              |
//! | `app.client_ip`        | host middleware (X-Forwarded-For aware)        | NULL              |
//! | `app.user_agent`       | host middleware                                | NULL              |
//! | `app.http_method`      | host middleware                                | NULL              |
//! | `app.resource_path`    | host middleware                                | NULL              |
//!
//! Outside request scope (cron, migrations, psql) nothing is set and the row
//! records `system` with NULL request context — that is the honest attribution
//! for a non-request write. `reason` is an explicit parameter on these verbs
//! (the calling service knows why it is logging); the `app.audit_reason` GUC is
//! the trigger lane's channel for cascade attribution and is NOT read here.

use async_trait::async_trait;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

use crate::application::service::AuditTrailService;
use crate::domain::entity::{AuditEventType, AuditStatus};

/// One service-emitted audit row: everything the caller states, before the
/// session context (actor, request fields, txid) is folded in by the INSERT.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// The lane: `refusal` / `security_edge` for the convenience verbs, or
    /// `data_change` when a service audits an explicit write of its own.
    pub event_type: AuditEventType,
    /// Free text naming the event (`refused_write`, `maintenance_gate`, ...).
    pub action: String,
    /// The affected table's name — loose join key, never an FK (the promotion
    /// contract).
    pub subject_type: Option<String>,
    /// The affected row's key as text.
    pub subject_id: Option<String>,
    /// Diff-only payload `{field: {from, to}}`; NULL when there is no row to
    /// diff (the usual case for refusals).
    pub changed: Option<Value>,
    /// Why the event happened (cascade attribution, refusal reason).
    pub reason: Option<String>,
    /// `success` / `failure` — refusals are failure rows by definition.
    pub status: AuditStatus,
}

impl AuditEvent {
    /// A refused write: the capability/gate layer rejected it, so there is no
    /// row to diff — the refusal itself is the audited fact.
    pub fn refusal(
        action: impl Into<String>,
        subject_type: impl Into<String>,
        subject_id: impl ToString,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            event_type: AuditEventType::Refusal,
            action: action.into(),
            subject_type: Some(subject_type.into()),
            subject_id: Some(subject_id.to_string()),
            changed: None,
            reason: Some(reason.into()),
            status: AuditStatus::Failure,
        }
    }

    /// A security-relevant boundary event (tamper attempt, expired token
    /// path) — security edges are failures by definition.
    pub fn security_edge(
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            event_type: AuditEventType::SecurityEdge,
            action: action.into(),
            subject_type: None,
            subject_id: None,
            changed: None,
            reason: Some(reason.into()),
            status: AuditStatus::Failure,
        }
    }
}

/// The audit write verbs, as an extension trait on the generated service so a
/// composed service can call `audit.log_refusal(&mut *tx, ...)` on the
/// service it was handed.
///
/// The methods take the caller's executor — the same transaction running the
/// business mutation — never a fresh pool connection: same-transaction truth
/// is the point (see the module docs and ADR-0025 Decision 1).
#[async_trait]
pub trait AuditTrailWriter {
    /// Append one audit row in the caller's transaction. Returns the new row's
    /// id so callers (and tests) can point at the exact row.
    async fn log_event(
        &self,
        exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
        event: AuditEvent,
    ) -> Result<Uuid, sqlx::Error>;

    /// Record a refused write: `event_type=refusal`, `status=failure`, with
    /// its reason — the shape the module's contract pins.
    async fn log_refusal(
        &self,
        exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
        action: impl Into<String> + Send,
        subject_type: impl Into<String> + Send,
        subject_id: impl ToString + Send,
        reason: impl Into<String> + Send,
    ) -> Result<Uuid, sqlx::Error> {
        self.log_event(exec, AuditEvent::refusal(action, subject_type, subject_id, reason))
            .await
    }

    /// Record a security edge: `event_type=security_edge`, `status=failure`.
    async fn log_security_edge(
        &self,
        exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
        action: impl Into<String> + Send,
        reason: impl Into<String> + Send,
    ) -> Result<Uuid, sqlx::Error> {
        self.log_event(exec, AuditEvent::security_edge(action, reason)).await
    }

    /// Request-scoped twin of [`AuditTrailWriter::log_event`]: for layers that
    /// run inside the request scope but hold no transaction — a gate refusing
    /// a write, where the refusal is the event and there is no business write
    /// to share a transaction with.
    ///
    /// Routes the INSERT through the framework's request-dedicated connection
    /// when one is bound (so the row reads the actor/correlation/request GUCs
    /// the refused request carried) and falls back to a plain pooled
    /// connection otherwise (recording `system` — the honest attribution
    /// outside request scope). See the module docs for why a fresh pooled
    /// connection would misattribute here.
    async fn log_event_scoped(
        &self,
        pool: &sqlx::PgPool,
        event: AuditEvent,
    ) -> Result<Uuid, sqlx::Error> {
        let row = backbone_orm::org_scope::fetch_optional_row_scoped(pool, audit_insert(&event))
            .await?
            .ok_or(sqlx::Error::RowNotFound)?;
        row.try_get("id")
    }

    /// Request-scoped twin of [`AuditTrailWriter::log_refusal`] — the verb a
    /// capability/gate middleware calls when it refuses a write and wants the
    /// refusal attributed to the requester, not to `system`.
    async fn log_refusal_scoped(
        &self,
        pool: &sqlx::PgPool,
        action: impl Into<String> + Send,
        subject_type: impl Into<String> + Send,
        subject_id: impl ToString + Send,
        reason: impl Into<String> + Send,
    ) -> Result<Uuid, sqlx::Error> {
        self.log_event_scoped(pool, AuditEvent::refusal(action, subject_type, subject_id, reason))
            .await
    }
}

/// The GUC-reading audit INSERT as a bindable query — the single statement
/// behind every verb (executor-taking and request-scoped alike), so the two
/// lanes can never drift apart in what they record.
fn audit_insert<'q>(
    event: &'q AuditEvent,
) -> sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments> {
    sqlx::query(
        r#"
        INSERT INTO auditlog.audit_trails
            (occurred_at, event_type, action, actor, subject_type, subject_id,
             changed, reason, status,
             correlation_id, client_ip, user_agent, http_method, resource_path,
             txid)
        VALUES
            (NOW(), $1, $2,
             COALESCE(NULLIF(current_setting('app.actor', true), ''), 'system'),
             $3, $4, $5, $6, $7,
             NULLIF(current_setting('app.correlation_id', true), ''),
             NULLIF(current_setting('app.client_ip', true), ''),
             NULLIF(current_setting('app.user_agent', true), ''),
             NULLIF(current_setting('app.http_method', true), ''),
             NULLIF(current_setting('app.resource_path', true), ''),
             txid_current()::text)
        RETURNING id
        "#,
    )
    .bind(&event.event_type)
    .bind(&event.action)
    .bind(&event.subject_type)
    .bind(&event.subject_id)
    .bind(&event.changed)
    .bind(&event.reason)
    .bind(&event.status)
}

/// Append one audit row in the caller's transaction, without holding a service.
///
/// The same write [`AuditTrailWriter::log_event`] performs — it ignores `self`
/// entirely — exposed for the places that audit from a repository or a raw-sqlx
/// path and have a transaction but no service to reach for. Consolidating the
/// per-module `*_audit_log` tables onto this one needs exactly that: those
/// writes happen deep in repository code, and threading a service through them
/// would be a larger change than the consolidation itself.
///
/// Takes the caller's executor, so the audit row commits with the business
/// write and dies with it on rollback. Calling this with a pool instead of the
/// mutation's transaction throws that property away and is a caller bug.
pub async fn append(
    exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    event: AuditEvent,
) -> Result<Uuid, sqlx::Error> {
    let row = audit_insert(&event).fetch_one(exec).await?;
    row.try_get("id")
}

#[async_trait]
impl AuditTrailWriter for AuditTrailService {
    async fn log_event(
        &self,
        exec: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
        event: AuditEvent,
    ) -> Result<Uuid, sqlx::Error> {
        let row = audit_insert(&event).fetch_one(exec).await?;
        row.try_get("id")
    }
}

// ─── The history read ─────────────────────────────────────────────────────────

/// Serves one record's recorded changes to the generic CRUD router.
///
/// This is the READ side of the capture design the rest of this module writes.
/// It lives here rather than in `backbone-core` so the framework never learns
/// that an audit module exists: the composing service builds this and installs
/// it as an axum `Extension`, and a composition without auditlog simply serves
/// no history.
///
/// Reads ride the request-dedicated connection through the framework's scoped
/// helper, so the org fence on `auditlog.audit_trails` applies — a caller sees
/// only the trail rows their entitlement covers, on the same terms as every
/// other read.
pub struct AuditHistoryProvider {
    pool: sqlx::PgPool,
}

impl AuditHistoryProvider {
    pub fn new(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }

    /// Whether `table` has the capture trigger installed.
    ///
    /// Asked of `pg_trigger`, NOT of whether any trail rows exist. A table can
    /// be audited and genuinely untouched, and answering "not audited" for it
    /// would be a different — and wrong — statement. This is the whole reason
    /// the provider can distinguish the two cases the router reports.
    async fn is_audited(&self, table: &str) -> Result<bool, sqlx::Error> {
        let q = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS (
               SELECT 1 FROM pg_trigger t
               JOIN pg_class c ON c.oid = t.tgrelid
               JOIN pg_namespace n ON n.oid = c.relnamespace
               WHERE n.nspname || '.' || c.relname = $1
                 AND NOT t.tgisinternal
                 AND t.tgfoid = 'auditlog.capture_data_change'::regproc
             )",
        )
        .bind(table);
        backbone_orm::company_scope::fetch_one_scalar_scoped(&self.pool, q).await
    }
}

#[async_trait]
impl backbone_core::http::HistoryProvider for AuditHistoryProvider {
    async fn history(
        &self,
        table: &str,
        id: &str,
        limit: u32,
        offset: u32,
    ) -> Result<Option<Vec<backbone_core::http::HistoryEntry>>, String> {
        if !self.is_audited(table).await.map_err(|e| e.to_string())? {
            return Ok(None);
        }

        // Newest first: a history tab is read from the top. `subject_type` is
        // the schema-qualified table the capture trigger writes, which is the
        // same string the calling repository names itself by.
        let q = sqlx::query(
            "SELECT occurred_at, action, actor, changed, reason, correlation_id
               FROM auditlog.audit_trails
              WHERE subject_type = $1 AND subject_id = $2
              ORDER BY occurred_at DESC
              LIMIT $3 OFFSET $4",
        )
        .bind(table)
        .bind(id)
        .bind(limit as i64)
        .bind(offset as i64);

        let rows = backbone_orm::company_scope::fetch_all_rows_scoped(&self.pool, q)
            .await
            .map_err(|e| e.to_string())?;

        let entries = rows
            .iter()
            .map(|r| backbone_core::http::HistoryEntry {
                occurred_at: r
                    .try_get::<chrono::DateTime<chrono::Utc>, _>("occurred_at")
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_default(),
                action: r.try_get::<String, _>("action").unwrap_or_default(),
                actor: r.try_get::<String, _>("actor").unwrap_or_default(),
                changed: r
                    .try_get::<Value, _>("changed")
                    .unwrap_or(Value::Object(Default::default())),
                reason: r.try_get::<Option<String>, _>("reason").ok().flatten(),
                correlation_id: r.try_get::<Option<String>, _>("correlation_id").ok().flatten(),
            })
            .collect();

        Ok(Some(entries))
    }
}

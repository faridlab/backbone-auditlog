//! The module's behavior oracle (ADR-0025): same-transaction truth, the
//! refusal contract, append-only enforcement, and GUC attribution.
//!
//! Run with: `cargo test --package backbone-auditlog --test audit_trail_semantics`
//! against the module's dev database — `DATABASE_URL`, defaulting to
//! `postgres://postgres:postgres@localhost:5433/backbone_auditlog`. Migrations
//! are applied out-of-band (psql / the suite-regen script); when the database
//! is unreachable the tests SKIP (env), they do not FAIL.
//!
//! Every test runs inside one transaction and rolls back: audit rows are
//! append-only (the immutability trigger blocks DELETE), so there is no
//! cleanup path — leaving nothing behind is the only hygiene available.

use serde_json::json;
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use uuid::Uuid;

use backbone_auditlog::application::service::{
    AuditEvent, AuditTrailService, AuditTrailWriter,
};
use backbone_auditlog::domain::entity::{AuditEventType, AuditStatus};

async fn pool() -> Option<PgPool> {
    let dburl = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgres://postgres:postgres@localhost:5433/backbone_auditlog".to_string()
    });
    match PgPoolOptions::new().max_connections(2).connect(&dburl).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("SKIP: auditlog dev database unreachable ({e}); set DATABASE_URL");
            None
        }
    }
}

/// One committed-shape audit row, read back as text columns for asserting.
#[allow(clippy::type_complexity)]
async fn fetch_row(
    tx: &mut sqlx::PgConnection,
    id: Uuid,
) -> (
    String,            // event_type
    String,            // action
    String,            // actor
    Option<String>,    // reason
    Option<String>,    // correlation_id
    Option<String>,    // client_ip
    Option<String>,    // http_method
    String,            // txid
    Option<serde_json::Value>, // changed
) {
    let row = sqlx::query(
        r#"SELECT event_type::text, action, actor, reason, correlation_id,
                  client_ip, http_method, txid, changed
           FROM auditlog.audit_trails WHERE id = $1"#,
    )
    .bind(id)
    .fetch_one(&mut *tx)
    .await
    .expect("audit row must be visible inside its own transaction");
    (
        row.get("event_type"),
        row.get("action"),
        row.get("actor"),
        row.get("reason"),
        row.get("correlation_id"),
        row.get("client_ip"),
        row.get("http_method"),
        row.get("txid"),
        row.get("changed"),
    )
}

#[tokio::test]
async fn a_refusal_row_carries_the_refusal_contract() {
    let Some(pool) = pool().await else { return };
    let service = AuditTrailService::with_repository(std::sync::Arc::new(
        backbone_auditlog::infrastructure::persistence::AuditTrailRepository::new(pool.clone()),
    ));
    let mut tx = pool.begin().await.expect("begin");

    let id = service
        .log_refusal(
            &mut *tx,
            "refused_write",
            "selling.quotes",
            "0b9e6c9e-5c7b-4a44-9f7f-8f3a2f9a1d10",
            "capability gate: actor lacks quote.approve",
        )
        .await
        .expect("log_refusal writes inside the caller's transaction");

    let (event_type, action, actor, reason, correlation_id, client_ip, http_method, txid, changed) =
        fetch_row(&mut tx, id).await;

    // The contract #319 pins: refusal lane, failure status by definition, the
    // reason present, and the honest 'system' actor outside request scope.
    assert_eq!(event_type, "refusal");
    assert_eq!(action, "refused_write");
    assert_eq!(actor, "system", "no app.actor GUC set — attribution must be system");
    assert_eq!(reason.as_deref(), Some("capability gate: actor lacks quote.approve"));
    assert_eq!(status_of(&mut tx, id).await, "failure");
    assert!(correlation_id.is_none() && client_ip.is_none() && http_method.is_none(),
        "outside request scope the request-context columns are NULL");
    assert!(!txid.is_empty(), "txid ties the row to its transaction");
    assert!(changed.is_none(), "a refusal leaves no row to diff");

    tx.rollback().await.expect("rollback (append-only: no cleanup path)");
}

#[tokio::test]
async fn append_only_is_enforced_update_and_delete_are_attempted() {
    let Some(pool) = pool().await else { return };
    let service = AuditTrailService::with_repository(std::sync::Arc::new(
        backbone_auditlog::infrastructure::persistence::AuditTrailRepository::new(pool.clone()),
    ));

    // Attempted, not assumed: each mutation path gets its own live transaction
    // (a failed statement aborts the surrounding transaction, so a second
    // attempt in the same one would test 25P02, not the trigger). The
    // enforcement trigger is the arbiter under application bugs, for every
    // role, owner included.
    let mut tx = pool.begin().await.expect("begin (update attempt)");
    let id = service
        .log_event(
            &mut *tx,
            AuditEvent {
                event_type: AuditEventType::DataChange,
                action: "insert".into(),
                subject_type: Some("selling.quotes".into()),
                subject_id: Some(Uuid::new_v4().to_string()),
                changed: Some(json!({"status": {"from": "draft", "to": "approved"}})),
                reason: None,
                status: AuditStatus::Success,
            },
        )
        .await
        .expect("seed one row for the update attempt");

    let update = sqlx::query("UPDATE auditlog.audit_trails SET action = 'tampered' WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await;
    assert!(update.is_err(), "UPDATE on an audit row must be refused");
    assert!(
        update.unwrap_err().to_string().contains("append-only"),
        "the refusal must name the append-only contract"
    );
    tx.rollback().await.expect("rollback (update attempt)");

    let mut tx = pool.begin().await.expect("begin (delete attempt)");
    let id = service
        .log_event(
            &mut *tx,
            AuditEvent {
                event_type: AuditEventType::DataChange,
                action: "insert".into(),
                subject_type: Some("selling.quotes".into()),
                subject_id: Some(Uuid::new_v4().to_string()),
                changed: None,
                reason: None,
                status: AuditStatus::Success,
            },
        )
        .await
        .expect("seed one row for the delete attempt");

    let delete = sqlx::query("DELETE FROM auditlog.audit_trails WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await;
    assert!(delete.is_err(), "DELETE on an audit row must be refused");
    assert!(
        delete.unwrap_err().to_string().contains("append-only"),
        "the refusal must name the append-only contract"
    );
    tx.rollback().await.expect("rollback (delete attempt)");
}

#[tokio::test]
async fn a_rolled_back_transaction_leaves_no_audit_row() {
    let Some(pool) = pool().await else { return };
    let service = AuditTrailService::with_repository(std::sync::Arc::new(
        backbone_auditlog::infrastructure::persistence::AuditTrailRepository::new(pool.clone()),
    ));
    let mut tx = pool.begin().await.expect("begin");

    let id = service
        .log_event(
            &mut *tx,
            AuditEvent {
                event_type: AuditEventType::DataChange,
                action: "update".into(),
                subject_type: Some("inventory.stock_moves".into()),
                subject_id: Some(Uuid::new_v4().to_string()),
                changed: Some(json!({"qty": {"from": 5, "to": 3}})),
                reason: None,
                status: AuditStatus::Success,
            },
        )
        .await
        .expect("the verb writes inside the transaction");

    tx.rollback().await.expect("rollback the business write");

    // Asserted by querying after ROLLBACK, not by trusting the verb's return.
    let survived: Option<(Uuid,)> =
        sqlx::query_as("SELECT id FROM auditlog.audit_trails WHERE id = $1")
            .bind(id)
            .fetch_optional(&pool)
            .await
            .expect("post-rollback read");
    assert!(survived.is_none(),
        "an audit row that survives a rolled-back write is lying — the property an \
         independent-service design cannot offer (ADR-0025 Decision 1)");
}

#[tokio::test]
async fn subject_keys_carry_no_foreign_key() {
    let Some(pool) = pool().await else { return };
    let service = AuditTrailService::with_repository(std::sync::Arc::new(
        backbone_auditlog::infrastructure::persistence::AuditTrailRepository::new(pool.clone()),
    ));
    let mut tx = pool.begin().await.expect("begin");

    // A key that exists in no business table: the promotion contract says the
    // audit store holds loose text join keys (liftable to an independent
    // service without rewriting consumers), so this insert must land.
    let id = service
        .log_event(
            &mut *tx,
            AuditEvent::refusal(
                "refused_write",
                "nowhere.nonexistent_table",
                "ffffffff-ffff-ffff-ffff-ffffffffffff",
                "probe: dangling subject key",
            ),
        )
        .await
        .expect("no FK into business tables — a dangling key is legal");

    let (_, _, _, _, _, _, _, _, _) = fetch_row(&mut tx, id).await; // row exists
    tx.rollback().await.expect("rollback");
}

#[tokio::test]
async fn actor_and_request_context_come_from_the_session_gucs() {
    let Some(pool) = pool().await else { return };
    let service = AuditTrailService::with_repository(std::sync::Arc::new(
        backbone_auditlog::infrastructure::persistence::AuditTrailRepository::new(pool.clone()),
    ));
    let mut tx = pool.begin().await.expect("begin");

    // The composing service's middleware sets these per request; the test
    // stands in for it (the equity composition-proof precedent).
    for (name, value) in [
        ("app.actor", "11111111-2222-3333-4444-555555555555"),
        ("app.correlation_id", "corr-7f3a2b"),
        ("app.client_ip", "203.0.113.9"),
        ("app.user_agent", "probe-agent/1.0"),
        ("app.http_method", "POST"),
        ("app.resource_path", "/api/v1/selling/quotes/9/approve"),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .expect("set session GUC");
    }

    let id = service
        .log_event(
            &mut *tx,
            AuditEvent {
                event_type: AuditEventType::DataChange,
                action: "update".into(),
                subject_type: Some("selling.quotes".into()),
                subject_id: Some(Uuid::new_v4().to_string()),
                changed: Some(json!({"status": {"from": "draft", "to": "sent"}})),
                reason: None,
                status: AuditStatus::Success,
            },
        )
        .await
        .expect("log_event under a request-scoped session");

    let (_, _, actor, _, correlation_id, client_ip, http_method, _, changed) =
        fetch_row(&mut tx, id).await;

    assert_eq!(actor, "11111111-2222-3333-4444-555555555555");
    assert_eq!(correlation_id.as_deref(), Some("corr-7f3a2b"));
    assert_eq!(client_ip.as_deref(), Some("203.0.113.9"));
    assert_eq!(http_method.as_deref(), Some("POST"));
    assert_eq!(
        changed.expect("diff payload stored").pointer("/status/to"),
        Some(&json!("sent")),
        "changed is the diff-only payload {{field: {{from, to}}}}"
    );

    tx.rollback().await.expect("rollback");
}

async fn status_of(tx: &mut sqlx::PgConnection, id: Uuid) -> String {
    let row: (String,) = sqlx::query_as("SELECT status::text FROM auditlog.audit_trails WHERE id = $1")
        .bind(id)
        .fetch_one(&mut *tx)
        .await
        .expect("status read");
    row.0
}

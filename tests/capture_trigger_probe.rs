//! Capture-trigger probe (ADR-0025 data-change lane).
//!
//! Proves the trigger half of the hybrid capture against the module's dev
//! database: the shared capture function (`auditlog.capture_data_change`,
//! migration 20260911000200) attached to a fixture table by the exact
//! trigger shape the schema generator's `@audited` attribute emits
//! (tests/fixtures/capture/*). The load-bearing assertions are the ones
//! service-side audit always misses — a bare psql write with NO service
//! involved still lands in the trail, and a batch statement audits per
//! affected row, never once for the batch.
//!
//! Requires the module migrations (out-of-band, per the module docs); the
//! fixture table + trigger are applied in-band, idempotently. Everything
//! runs in ROLLBACK-only transactions, so re-runs leave no committed trail
//! rows. When the database is unreachable the tests SKIP (env), they do not
//! fail.

use sqlx::PgConnection;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

const FIXTURE_TABLE: &str = include_str!("fixtures/capture/audited_table_fixture.sql");
const FIXTURE_TRIGGER: &str = include_str!("fixtures/capture/data_change_audit_trigger.sql");

async fn db() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://postgres:postgres@localhost:5433/backbone_auditlog".to_string()
    });
    match PgPoolOptions::new().max_connections(2).connect(&url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("SKIP: auditlog dev database unreachable ({e}); prepare backbone_auditlog per the module docs");
            None
        }
    }
}

/// One trail row as the probe asserts it. Enums are cast to text in SQL —
/// the runtime query path has no generated enum mapping.
#[derive(Debug, sqlx::FromRow)]
struct TrailRow {
    action: String,
    actor: String,
    subject_type: Option<String>,
    subject_id: Option<String>,
    changed: Option<serde_json::Value>,
    reason: Option<String>,
    correlation_id: Option<String>,
    txid: String,
}

async fn trail_for(tx: &mut PgConnection, subject_id: &str) -> Vec<TrailRow> {
    sqlx::query_as::<_, TrailRow>(
        r#"
        SELECT action, actor, subject_type, subject_id, changed, reason,
               correlation_id, txid
        FROM auditlog.audit_trails
        WHERE subject_type = 'probes.gadgets' AND subject_id = $1
        ORDER BY occurred_at, id
        "#,
    )
    .bind(subject_id)
    .fetch_all(tx)
    .await
    .unwrap()
}

async fn trail_where(tx: &mut PgConnection, filter: &str) -> Vec<TrailRow> {
    sqlx::query_as::<_, TrailRow>(&format!(
        r#"
        SELECT action, actor, subject_type, subject_id, changed, reason,
               correlation_id, txid
        FROM auditlog.audit_trails
        WHERE subject_type = 'probes.gadgets' AND ({filter})
        ORDER BY occurred_at, id
        "#
    ))
    .fetch_all(tx)
    .await
    .unwrap()
}

async fn gadget_id(tx: &mut PgConnection, name: &str) -> String {
    sqlx::query_scalar::<_, uuid::Uuid>("SELECT id FROM probes.gadgets WHERE name = $1")
        .bind(name)
        .fetch_one(tx)
        .await
        .unwrap()
        .to_string()
}

/// A write with no service involved — the completeness-net case. No GUC is
/// set, so the row attributes honestly: actor 'system', NULL request
/// context, and the INSERT's full non-null image as the diff.
#[tokio::test]
async fn a_bare_psql_insert_audits_as_system_with_full_image() {
    let Some(pool) = db().await else { return };
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(FIXTURE_TABLE).execute(&mut *tx).await.unwrap();
    sqlx::raw_sql(FIXTURE_TRIGGER).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO probes.gadgets (name, qty, note) VALUES ('alpha', 3, NULL)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let id = gadget_id(&mut tx, "alpha").await;
    let rows = trail_for(&mut tx, &id).await;
    assert_eq!(rows.len(), 1, "one insert must write exactly one audit row");

    let row = &rows[0];
    assert_eq!(row.action, "insert");
    assert_eq!(row.actor, "system", "no GUC set → actor falls back to 'system'");
    assert_eq!(row.subject_type.as_deref(), Some("probes.gadgets"));
    assert_eq!(row.subject_id.as_deref(), Some(id.as_str()));
    assert_eq!(row.reason, None);
    assert_eq!(row.correlation_id, None);
    assert!(!row.txid.is_empty(), "the row must carry the writing transaction's id");

    let changed = row.changed.as_ref().expect("insert diff present");
    assert_eq!(changed["name"]["to"], "alpha", "full non-null image: name");
    assert_eq!(changed["qty"]["to"], 3, "full non-null image: qty");
    assert_eq!(changed["id"]["to"], id.as_str(), "full non-null image: the pk");
    assert!(
        changed.get("note").is_none(),
        "a NULL field carries no diff entry, got {changed}"
    );
    tx.rollback().await.unwrap();
}

/// Row-level, not statement-level: an UPDATE touching N rows writes N audit
/// rows, each carrying only the fields that actually changed.
#[tokio::test]
async fn a_batch_update_writes_one_audit_row_per_affected_row() {
    let Some(pool) = db().await else { return };
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(FIXTURE_TABLE).execute(&mut *tx).await.unwrap();
    sqlx::raw_sql(FIXTURE_TRIGGER).execute(&mut *tx).await.unwrap();

    for name in ["beta", "gamma"] {
        sqlx::query("INSERT INTO probes.gadgets (name, qty) VALUES ($1, 10)")
            .bind(name)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let updated = sqlx::query("UPDATE probes.gadgets SET qty = qty + 5 WHERE name IN ('beta', 'gamma')")
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(updated, 2, "fixture: the batch really touched two rows");

    let rows = trail_where(&mut tx, "action = 'update'").await;
    assert_eq!(rows.len(), 2, "two affected rows → two audit rows, not one for the batch");
    for row in &rows {
        let changed = row.changed.as_ref().expect("update diff present");
        assert_eq!(
            changed["qty"]["from"], 10,
            "diff-only: the unchanged fields must not appear"
        );
        assert_eq!(changed["qty"]["to"], 15);
        assert_eq!(
            changed.as_object().map(|o| o.len()),
            Some(1),
            "only qty changed, only qty may appear in the diff, got {changed}"
        );
    }
    tx.rollback().await.unwrap();
}

/// DELETE records the full prior image as {field: {from}} — the anchor the
/// history read re-anchors on when the subject no longer exists.
#[tokio::test]
async fn a_delete_records_the_full_prior_image() {
    let Some(pool) = db().await else { return };
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(FIXTURE_TABLE).execute(&mut *tx).await.unwrap();
    sqlx::raw_sql(FIXTURE_TRIGGER).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO probes.gadgets (name, qty, note) VALUES ('doomed', 1, 'keep me')")
        .execute(&mut *tx)
        .await
        .unwrap();
    let id = gadget_id(&mut tx, "doomed").await;
    sqlx::query("DELETE FROM probes.gadgets WHERE id = $1")
        .bind(uuid::Uuid::parse_str(&id).unwrap())
        .execute(&mut *tx)
        .await
        .unwrap();

    let rows = trail_for(&mut tx, &id).await;
    let deleted = rows.iter().find(|r| r.action == "delete").expect("delete row present");
    let changed = deleted.changed.as_ref().expect("delete diff present");
    assert_eq!(changed["name"]["from"], "doomed");
    assert_eq!(changed["qty"]["from"], 1);
    assert_eq!(changed["note"]["from"], "keep me", "non-null fields survive deletion in the image");
    assert_eq!(changed["id"]["from"], id.as_str());
    tx.rollback().await.unwrap();
}

/// Attribution: the trigger reads the same GUC contract as the verbs —
/// `app.actor`, `app.correlation_id` land on the row, and a cascade that
/// sets `app.audit_reason` gets the reason on every cascade-written row.
#[tokio::test]
async fn trigger_rows_carry_the_guc_context() {
    let Some(pool) = db().await else { return };
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(FIXTURE_TABLE).execute(&mut *tx).await.unwrap();
    sqlx::raw_sql(FIXTURE_TRIGGER).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO probes.gadgets (name, qty) VALUES ('attributed', 2)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let id = gadget_id(&mut tx, "attributed").await;

    for (key, val) in [
        ("app.actor", "11111111-1111-1111-1111-111111111111"),
        ("app.correlation_id", "corr-trigger-lane"),
        ("app.audit_reason", "cascade: order fulfillment"),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(key)
            .bind(val)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    sqlx::query("UPDATE probes.gadgets SET qty = 3 WHERE name = 'attributed'")
        .execute(&mut *tx)
        .await
        .unwrap();

    let rows = trail_for(&mut tx, &id).await;
    let updated = rows.iter().find(|r| r.action == "update").expect("update row present");
    assert_eq!(updated.actor, "11111111-1111-1111-1111-111111111111");
    assert_eq!(updated.correlation_id.as_deref(), Some("corr-trigger-lane"));
    assert_eq!(
        updated.reason.as_deref(),
        Some("cascade: order fulfillment"),
        "app.audit_reason is the trigger lane's cascade channel"
    );
    tx.rollback().await.unwrap();
}

/// An UPDATE that changes nothing still writes its audit row — the write
/// happened — with the honest empty diff `{}`.
#[tokio::test]
async fn a_no_op_update_still_audits_with_an_empty_diff() {
    let Some(pool) = db().await else { return };
    let mut tx = pool.begin().await.unwrap();
    sqlx::raw_sql(FIXTURE_TABLE).execute(&mut *tx).await.unwrap();
    sqlx::raw_sql(FIXTURE_TRIGGER).execute(&mut *tx).await.unwrap();

    sqlx::query("INSERT INTO probes.gadgets (name, qty) VALUES ('stable', 4)")
        .execute(&mut *tx)
        .await
        .unwrap();
    let id = gadget_id(&mut tx, "stable").await;
    let updated = sqlx::query("UPDATE probes.gadgets SET qty = 4 WHERE name = 'stable'")
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(updated, 1, "fixture: the statement still touched the row");

    let rows = trail_for(&mut tx, &id).await;
    let noop = rows.iter().find(|r| r.action == "update").expect("update row present");
    assert_eq!(
        noop.changed,
        Some(serde_json::json!({})),
        "nothing differed → the empty object, not NULL"
    );
    tx.rollback().await.unwrap();
}

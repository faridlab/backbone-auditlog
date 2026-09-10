//! Decorated composition probe (ADR-0025 acceptance / ADR-0029 posture).
//!
//! The module's OTHER test suites run against the undecorated dev database.
//! This one proves the composed shape: a scratch deployment of the module's
//! migrations PLUS the composition-installed tenancy decorator (emitted by
//! `metaphor schema tenancy` from `tests/fixtures/composition/tenancy.yaml`,
//! the stand-in for the composing service's descriptor) over a minimal org
//! spine. Against THAT database, as a minted non-superuser NOBYPASSRLS app
//! role — owner-role probes false-pass — the probe pins:
//!
//! - the fence admits exactly the entitled scope: a role scoped to unit A
//!   writes through the module's own verb (org_unit_id auto-stamped by the
//!   decorator's fill trigger) and sees only unit A's rows, never unit B's;
//! - the entitlement union spans multiple units when the scope lists them;
//! - a request with NO scope writes nothing and sees nothing (fail-closed);
//! - the kind guard rejects an acting unit that is not an org node, and
//!   accepts a branch node (audit rows may anchor below the company);
//! - the append-only trigger and the decorator coexist: an in-scope UPDATE
//!   attempt passes the fence and is refused by the immutability trigger.
//!
//! The decorated deployment is prepared out-of-band (the family Style-B
//! convention — tests assume a pre-migrated database):
//!
//! ```sh
//! createdb -h 127.0.0.1 -p 5433 -U postgres backbone_auditlog_decorated
//! for f in migrations/*.up.sql \
//!          tests/fixtures/composition/org_spine_fixture.sql \
//!          tests/fixtures/composition/*_tenancy_auditlog.up.sql; do
//!   psql -h 127.0.0.1 -p 5433 -U postgres -d backbone_auditlog_decorated -f "$f"
//! done
//! ```
//!
//! Requires a superuser-capable `DATABASE_URL` (it mints and tears down the
//! probe role); defaults to the decorated dev database on :5433. When that
//! database is unreachable the tests SKIP (env), they do not fail. The rows
//! the visibility matrix commits cannot be deleted (append-only) and are left
//! behind, tagged with a per-run prefix so re-runs never collide — the
//! accepted cost of a cross-connection fence proof.

use sqlx::PgPool;

use backbone_auditlog::application::service::{
    AuditEvent, AuditTrailService, AuditTrailWriter,
};
use backbone_auditlog::domain::entity::{AuditEventType, AuditStatus};

const ROLE: &str = "bbaud_decorated_probe";
const PWD: &str = "probe";

/// Role/catalog DDL serializes — tests minting the role concurrently hit
/// "tuple concurrently updated" in the system catalogs (the accounting
/// rls_probe pattern).
static ROLE_DDL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

const UNIT_A: &str = "00000000-0000-0000-0001-00000000000a"; // company
const UNIT_B: &str = "00000000-0000-0000-0001-00000000000b"; // company
const UNIT_BRANCH: &str = "00000000-0000-0000-0001-00000000000c"; // branch

async fn admin() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://postgres:postgres@localhost:5433/backbone_auditlog_decorated".to_string()
    });
    match PgPool::connect(&url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("SKIP: decorated auditlog dev database unreachable ({e}); prepare backbone_auditlog_decorated per the module docs");
            None
        }
    }
}

/// Mint the app role: USAGE + SELECT/INSERT on the trail (UPDATE too — not
/// because the surface grants it, but so the coexistence leg proves the
/// immutability TRIGGER is what refuses an in-scope UPDATE, not a missing
/// grant) and SELECT on the org spine (the decorator's kind guard reads it
/// as the invoking user).
async fn bootstrap_role(admin: &PgPool) -> PgPool {
    // Idempotent teardown: a role that never existed must not fail the mint.
    let _ = sqlx::query(&format!("DROP OWNED BY {ROLE}")).execute(admin).await;
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {ROLE}")).execute(admin).await;
    for stmt in [
        format!("CREATE ROLE {ROLE} LOGIN PASSWORD '{PWD}' NOSUPERUSER NOBYPASSRLS"),
        format!("GRANT USAGE ON SCHEMA auditlog TO {ROLE}"),
        format!("GRANT SELECT, INSERT, UPDATE ON auditlog.audit_trails TO {ROLE}"),
        format!("GRANT USAGE ON SCHEMA organization TO {ROLE}"),
        format!("GRANT SELECT ON organization.org_units TO {ROLE}"),
    ] {
        sqlx::query(&stmt).execute(admin).await.unwrap();
    }
    PgPool::connect(&format!(
        "postgresql://{ROLE}:{PWD}@localhost:5433/backbone_auditlog_decorated"
    ))
    .await
    .expect("connect probe role")
}

/// Bind one request's scope on a connection: the acting unit (write stamp)
/// and the entitlement union (read/write admission).
async fn bind_scope(tx: &mut sqlx::PgConnection, acting: &str, scope: &[&str]) {
    sqlx::query("SELECT set_config('app.acting_unit_id', $1, true)")
        .bind(acting)
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query("SELECT set_config('app.scope_unit_ids', $1, true)")
        .bind(scope.join(","))
        .execute(&mut *tx)
        .await
        .unwrap();
}

fn verb(pool: &PgPool) -> AuditTrailService {
    AuditTrailService::with_repository(std::sync::Arc::new(
        backbone_auditlog::infrastructure::persistence::AuditTrailRepository::new(pool.clone()),
    ))
}

fn event(subject_id: String) -> AuditEvent {
    AuditEvent {
        event_type: AuditEventType::DataChange,
        action: "insert".into(),
        subject_type: Some("probes.decorated".into()),
        subject_id: Some(subject_id),
        changed: None,
        reason: Some("decorated fence probe".into()),
        status: AuditStatus::Success,
    }
}

/// The fence admits exactly the entitled scope: rows written through the
/// module's own verb under unit A carry org_unit_id = A (the decorator's fill
/// trigger stamps it), a unit-A role sees them and never unit B's, and the
/// entitlement union spans every listed unit. Rows are committed (a
/// cross-connection visibility proof needs commits) and tagged with a
/// per-run prefix so accumulated probe rows never collide.
#[tokio::test]
async fn the_org_fence_admits_exactly_the_entitled_scope() {
    let Some(admin) = admin().await else { return };
    let _ddl = ROLE_DDL_LOCK.lock().await;
    let app = bootstrap_role(&admin).await;
    let run = uuid::Uuid::new_v4().simple().to_string();
    let (row_a, row_b) = (format!("{run}-a"), format!("{run}-b"));

    for (unit, subject) in [(UNIT_A, &row_a), (UNIT_B, &row_b)] {
        let mut tx = app.begin().await.unwrap();
        bind_scope(&mut *tx, unit, &[unit]).await;
        verb(&app)
            .log_event(&mut *tx, event(subject.clone()))
            .await
            .unwrap_or_else(|e| panic!("verb write under unit {unit} must be admitted: {e}"));
        tx.commit().await.unwrap();
    }

    // Unit-A scope: sees its own row, not B's.
    let mut tx = app.begin().await.unwrap();
    bind_scope(&mut *tx, UNIT_A, &[UNIT_A]).await;
    let mine: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auditlog.audit_trails WHERE subject_id = $1")
        .bind(&row_a)
        .fetch_one(&mut *tx).await.unwrap();
    let theirs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auditlog.audit_trails WHERE subject_id = $1")
        .bind(&row_b)
        .fetch_one(&mut *tx).await.unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(mine, 1, "an in-scope row must be visible to its unit");
    assert_eq!(theirs, 0, "another unit's row must be invisible");

    // Entitlement union: a scope listing BOTH units sees both of this run's rows.
    let mut tx = app.begin().await.unwrap();
    bind_scope(&mut *tx, UNIT_A, &[UNIT_A, UNIT_B]).await;
    let both: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auditlog.audit_trails WHERE subject_id LIKE $1 || '%'",
    )
    .bind(&run)
    .fetch_one(&mut *tx)
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(both, 2, "the entitlement union spans every listed unit");

    // No scope at all: fail-closed — this run's rows invisible, nothing writable.
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM auditlog.audit_trails WHERE subject_id LIKE $1 || '%'",
    )
    .bind(&run)
    .fetch_one(&app)
    .await
    .unwrap();
    assert_eq!(n, 0, "an unscoped role sees nothing, not even this run's rows");

    let unscoped = verb(&app).log_event(&app, event(format!("{run}-unscoped"))).await;
    assert!(
        unscoped.is_err(),
        "a request with no bound scope must not be able to write an audit row"
    );
}

/// The kind guard: the acting unit must be an organization node of an allowed
/// kind — an unknown id is refused, a branch node is accepted (audit rows may
/// anchor below the company). Both attempted through the verb's own INSERT.
#[tokio::test]
async fn the_kind_guard_rejects_unknown_units_and_accepts_branches() {
    let Some(admin) = admin().await else { return };
    let _ddl = ROLE_DDL_LOCK.lock().await;
    let app = bootstrap_role(&admin).await;

    // Unknown unit: no org node answers — refused at write time.
    let mut tx = app.begin().await.unwrap();
    bind_scope(
        &mut *tx,
        "ffffffff-ffff-ffff-ffff-ffffffffffff",
        &["ffffffff-ffff-ffff-ffff-ffffffffffff"],
    )
    .await;
    let refused = verb(&app)
        .log_event(&mut *tx, event("unknown-unit".into()))
        .await;
    assert!(
        refused.is_err(),
        "an acting unit that is not an org node must be refused"
    );
    tx.rollback().await.unwrap();

    // Branch node: allowed kind — the row lands with the branch stamp.
    let mut tx = app.begin().await.unwrap();
    bind_scope(&mut *tx, UNIT_BRANCH, &[UNIT_BRANCH]).await;
    let id = verb(&app)
        .log_event(&mut *tx, event("branch-anchored".into()))
        .await
        .expect("a branch node is an allowed anchor for an audit row");
    let stamped: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT org_unit_id FROM auditlog.audit_trails WHERE id = $1")
            .bind(id)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
    tx.rollback().await.unwrap();
    assert_eq!(
        stamped.map(|u| u.to_string()),
        Some(UNIT_BRANCH.to_string()),
        "the fill trigger must stamp the acting branch on the row"
    );
}

/// The decorator and the module's append-only trigger coexist: an in-scope
/// UPDATE passes the fence (the row and its new form are both inside the
/// entitled scope) and is then refused by the immutability trigger — the
/// module's own contract outranks whatever the composed surface would allow.
#[tokio::test]
async fn append_only_still_rejects_an_in_scope_update() {
    let Some(admin) = admin().await else { return };
    let _ddl = ROLE_DDL_LOCK.lock().await;
    let app = bootstrap_role(&admin).await;

    let mut tx = app.begin().await.unwrap();
    bind_scope(&mut *tx, UNIT_A, &[UNIT_A]).await;
    let id = verb(&app)
        .log_event(&mut *tx, event("tamper-target".into()))
        .await
        .unwrap();

    let refused = sqlx::query("UPDATE auditlog.audit_trails SET action = 'tampered' WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await;
    assert!(
        refused.is_err(),
        "an in-scope UPDATE must still be refused — append-only outranks the fence"
    );
    assert!(
        refused.unwrap_err().to_string().contains("append-only"),
        "the refusal must name the append-only contract, not the fence"
    );
    tx.rollback().await.unwrap();
}

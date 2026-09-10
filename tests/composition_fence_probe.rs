//! Tenancy posture probe (ADR-0029).
//!
//! The module ships NO tenancy: no tenant column, no tenant predicate in any
//! statement, and no RLS policy of its own. What it ships is the half-fence
//! the composing service's tenancy decorator completes: `audit_trails` carries
//! ENABLE + FORCE ROW LEVEL SECURITY with zero policies. This probe pins that
//! posture from below (the accounting rls_probe family pattern):
//!
//! - the flags are armed and the policy set is empty (schema pin);
//! - a plain non-superuser, NOBYPASSRLS role — granted SELECT and INSERT, so
//!   the refusals are RLS, not missing grants — is default-DENIED: zero rows,
//!   writes refused, no matter which session variable is set (no policy reads
//!   anything yet; the decorator's org-scoped policies will, once composed);
//! - the owner/superuser pool still writes and reads through the audit verbs,
//!   proving the denial is the missing policy and not a broken module.
//!
//! Requires DATABASE_URL (defaults to the module dev database on :5433)
//! backed by a superuser-capable role so it can mint/teardown the probe role.
//! The one row this probe commits cannot be deleted (append-only) and is left
//! behind — a row per run in a scratch database is the accepted cost of
//! proving a cross-connection fence.

use sqlx::PgPool;

use backbone_auditlog::application::service::{
    AuditEvent, AuditTrailService, AuditTrailWriter,
};
use backbone_auditlog::domain::entity::{AuditEventType, AuditStatus};

const ROLE: &str = "bbaud_fence_probe";
const PWD: &str = "probe";

async fn admin() -> Option<PgPool> {
    let url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        "postgresql://postgres:postgres@localhost:5433/backbone_auditlog".to_string()
    });
    match PgPool::connect(&url).await {
        Ok(pool) => Some(pool),
        Err(e) => {
            eprintln!("SKIP: auditlog dev database unreachable ({e}); set DATABASE_URL");
            None
        }
    }
}

/// Shed the role's grants, then drop it. Leftover grants (from a run whose
/// teardown never reached the drop) make plain DROP ROLE fail with 2BP01 —
/// DROP OWNED BY first keeps both bootstrap and teardown idempotent.
async fn drop_role(admin: &PgPool) {
    let _ = sqlx::query(&format!("DROP OWNED BY {ROLE}"))
        .execute(admin)
        .await;
    let _ = sqlx::query(&format!("DROP ROLE IF EXISTS {ROLE}"))
        .execute(admin)
        .await;
}

async fn bootstrap_role(admin: &PgPool) {
    drop_role(admin).await;
    for stmt in [
        format!("CREATE ROLE {ROLE} LOGIN PASSWORD '{PWD}' NOSUPERUSER NOBYPASSRLS"),
        format!("GRANT USAGE ON SCHEMA auditlog TO {ROLE}"),
        format!("GRANT SELECT, INSERT ON auditlog.audit_trails TO {ROLE}"),
    ] {
        sqlx::query(&stmt).execute(admin).await.unwrap();
    }
}

/// The schema pin: armed flags, empty policy set. If a strip or regen ever
/// drops the flags, an undecorated deployment would silently become readable
/// by any role the host grants; if a policy ever appears module-side, the
/// decorator's org-scoped policies would fight it.
#[tokio::test]
async fn audit_trails_carries_the_rls_half_fence_and_the_module_ships_no_policy() {
    let Some(admin) = admin().await else { return };
    let armed: bool = sqlx::query_scalar(
        "SELECT c.relrowsecurity AND c.relforcerowsecurity \
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'auditlog' AND c.relkind = 'r' AND c.relname = 'audit_trails'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert!(
        armed,
        "audit_trails must carry ENABLE + FORCE ROW LEVEL SECURITY — the half-fence the decorator completes"
    );

    let policies: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pg_policy WHERE polrelid::regnamespace::text = 'auditlog'",
    )
    .fetch_one(&admin)
    .await
    .unwrap();
    assert_eq!(
        policies, 0,
        "the module ships no RLS policy — isolation belongs to the composing service's decorator"
    );
}

/// Default-deny until composed: the plain probe role. The owner writes one
/// audit row through the verb (the module's own write path, as superuser —
/// superusers bypass RLS even under FORCE), then the probe role sees nothing,
/// cannot append even with its INSERT grant (no WITH CHECK policy admits the
/// row), and no session variable resurrects visibility — the decorator, and
/// only the decorator, opens this table.
#[tokio::test]
async fn plain_role_is_default_denied_until_the_decorator_composes() {
    let Some(admin) = admin().await else { return };
    bootstrap_role(&admin).await;

    // The module's own write path, as the owner: the verb must be unaffected
    // by the armed flags (superuser bypasses RLS even under FORCE).
    let service = AuditTrailService::with_repository(std::sync::Arc::new(
        backbone_auditlog::infrastructure::persistence::AuditTrailRepository::new(admin.clone()),
    ));
    let seeded = service
        .log_event(
            &admin,
            AuditEvent {
                event_type: AuditEventType::DataChange,
                action: "insert".into(),
                subject_type: Some("probes.fence".into()),
                subject_id: Some("fence-probe-row".into()),
                changed: None,
                reason: Some("tenancy posture probe seed".into()),
                status: AuditStatus::Success,
            },
        )
        .await
        .expect("the owner's verb write must succeed under the armed half-fence");

    let restricted = PgPool::connect(&format!(
        "postgresql://{ROLE}:{PWD}@localhost:5433/backbone_auditlog"
    ))
    .await
    .expect("connect probe role");

    // Bare read: zero rows — default-deny with no policy admitting the role.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auditlog.audit_trails WHERE id=$1")
        .bind(seeded)
        .fetch_one(&restricted)
        .await
        .unwrap();
    assert_eq!(n, 0, "a role no policy admits sees zero rows");

    // Session variables resurrect nothing: no policy reads them yet. The
    // decorator's org-scoped policies (app.acting_unit_id / app.scope_unit_ids)
    // are the only lane that will ever admit this role.
    let mut tx = restricted.begin().await.unwrap();
    for (name, value) in [
        ("app.actor", "11111111-2222-3333-4444-555555555555"),
        ("app.acting_unit_id", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        ("app.company_id", "77777777-7777-7777-7777-777777777777"),
    ] {
        sqlx::query("SELECT set_config($1, $2, true)")
            .bind(name)
            .bind(value)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auditlog.audit_trails WHERE id=$1")
        .bind(seeded)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
    assert_eq!(
        n, 0,
        "no session variable may bypass the absent policy set — only the decorator admits"
    );
    tx.rollback().await.unwrap();

    // The granted INSERT is refused by RLS itself (no WITH CHECK policy
    // admits the new row) — the refusal is not a missing grant.
    let err = sqlx::query(
        r#"INSERT INTO auditlog.audit_trails
             (event_type, action, actor, status, txid)
           VALUES ('data_change'::audit_event_type, 'probe_write', 'probe',
                   'success'::audit_status, txid_current()::text)"#,
    )
    .execute(&restricted)
    .await;
    assert!(
        err.is_err(),
        "an INSERT no WITH CHECK policy admits must be refused despite the grant"
    );

    // The owner pool still sees the row it wrote: the denial is the missing
    // policy, not an empty database or a broken verb.
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM auditlog.audit_trails WHERE id=$1")
        .bind(seeded)
        .fetch_one(&admin)
        .await
        .unwrap();
    assert_eq!(n, 1, "the owner pool must still see the row the verb wrote");

    drop_role(&admin).await;
}

-- Arm the tenancy half-fence on auditlog.audit_trails (ADR-0029).
--
-- The module ships NO tenancy: no tenant column, no tenant predicate, no RLS
-- policy of its own. What it ships is the half the composing service's tenancy
-- decorator completes: ENABLE + FORCE ROW LEVEL SECURITY with zero policies —
-- a plain non-superuser role is default-denied (zero rows, writes refused)
-- until the decorator installs the org-scoped policies that admit it.
--
-- The flags must be armed module-side: if a strip or regen ever drops them, an
-- undecorated deployment would silently become readable by any role the host
-- grants. The owner/superuser pool (migrations, seeders, the verbs' own tests)
-- is unaffected — superusers bypass RLS even under FORCE.

ALTER TABLE auditlog.audit_trails ENABLE ROW LEVEL SECURITY;
ALTER TABLE auditlog.audit_trails FORCE  ROW LEVEL SECURITY;

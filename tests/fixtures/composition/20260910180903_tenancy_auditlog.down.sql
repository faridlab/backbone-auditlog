-- Tenancy decorator reversal — emitted by `metaphor schema tenancy`.
-- Drops the decorator's artifacts. Destructive: org_unit_id and its data are
-- removed (a dev-stage posture; the up chain can re-backfill from company_id
-- only while that column still exists).

DROP TRIGGER IF EXISTS audit_trails_org_unit_kind_guard ON auditlog.audit_trails;
DROP FUNCTION IF EXISTS auditlog.audit_trails_org_unit_kind_guard();

DROP TRIGGER IF EXISTS audit_trails_org_unit_fill ON auditlog.audit_trails;
DROP FUNCTION IF EXISTS auditlog.audit_trails_org_unit_fill();

DROP POLICY IF EXISTS audit_trails_org_unit_isolation ON auditlog.audit_trails;
ALTER TABLE auditlog.audit_trails NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auditlog.audit_trails DISABLE ROW LEVEL SECURITY;
ALTER TABLE auditlog.audit_trails ALTER COLUMN org_unit_id DROP DEFAULT;
ALTER TABLE auditlog.audit_trails DROP COLUMN IF EXISTS org_unit_id;

DROP EVENT TRIGGER IF EXISTS tenancy_deny_undecorated_table;
DROP FUNCTION IF EXISTS tenancy.deny_undecorated_table();
DROP SCHEMA IF EXISTS tenancy;

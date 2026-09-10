-- Disarm the tenancy half-fence on auditlog.audit_trails.
-- Exists for migration symmetry only: in a real deployment the flags stay
-- armed (dropping them reopens the table to any role the host grants before
-- the decorator composes).

ALTER TABLE auditlog.audit_trails NO FORCE ROW LEVEL SECURITY;
ALTER TABLE auditlog.audit_trails DISABLE ROW LEVEL SECURITY;

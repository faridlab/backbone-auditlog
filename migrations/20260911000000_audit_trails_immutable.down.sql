-- Remove the append-only enforcement from auditlog.audit_trails.
-- Exists for migration symmetry only: in any real deployment the trigger
-- stays armed (dropping it reopens the trail to silent edits).

DROP TRIGGER IF EXISTS audit_trails_immutable ON auditlog.audit_trails;
DROP FUNCTION IF EXISTS auditlog.forbid_audit_trail_mutation();

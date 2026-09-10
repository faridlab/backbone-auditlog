-- Enforce append-only on auditlog.audit_trails (ADR-0025): an audit row is
-- never updated and never deleted, by anything. The trail must stay the truth
-- of what happened — including rows a bug wrote; the correction is always a
-- new row, never an edit.
--
-- Enforcement lives in the database, not convention: a BEFORE trigger fires
-- for every role, owner included (the attendance-clocks immutable precedent).
-- A REVOKE-only design would still leave the owner able to mutate, and RLS
-- never fires for the table owner at all.

CREATE OR REPLACE FUNCTION auditlog.forbid_audit_trail_mutation() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION 'audit_trails rows are append-only (id %)', OLD.id
        USING ERRCODE = 'P0001',
              HINT = 'the audit trail is never edited or deleted; correct the record by appending';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_trails_immutable ON auditlog.audit_trails;

CREATE TRIGGER audit_trails_immutable
    BEFORE UPDATE OR DELETE ON auditlog.audit_trails
    FOR EACH ROW EXECUTE FUNCTION auditlog.forbid_audit_trail_mutation();

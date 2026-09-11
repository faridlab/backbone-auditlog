-- Fixture: a toy audited table for the capture-trigger probe.
--
-- Stands in for any `@audited` model: a plain table with a text name, an
-- int quantity, a nullable note (so full-image diffs have a NULL to skip)
-- and a nullable org_unit_id — present on every decorator-scoped table,
-- absent on unscoped ones; the capture function must inherit it when it
-- exists and pass NULL when it does not.
-- The trigger attach lives in data_change_audit_trigger.sql.
CREATE SCHEMA IF NOT EXISTS probes;

CREATE TABLE IF NOT EXISTS probes.gadgets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    qty int NOT NULL DEFAULT 0,
    note text,
    org_unit_id uuid
);
-- The table may predate the org-unit column; bring old probe databases along.
ALTER TABLE probes.gadgets ADD COLUMN IF NOT EXISTS org_unit_id uuid;


-- Fixture: a toy audited table for the capture-trigger probe.
--
-- Stands in for any `@audited` model: a plain table with a text name, an
-- int quantity and a nullable note (so full-image diffs have a NULL to skip).
-- The trigger attach lives in data_change_audit_trigger.sql.
CREATE SCHEMA IF NOT EXISTS probes;

CREATE TABLE IF NOT EXISTS probes.gadgets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text NOT NULL,
    qty int NOT NULL DEFAULT 0,
    note text
);

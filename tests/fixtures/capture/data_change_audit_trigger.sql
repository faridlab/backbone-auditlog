-- Fixture: the trigger attach for probes.gadgets.
--
-- This is the exact shape the schema generator's `@audited` attribute emits
-- (metaphor-plugin-schema, one migration per audited table): a row-level
-- AFTER trigger calling the module's capture function with the primary-key
-- column name as the single trigger argument. When the generator emission
-- changes, this fixture follows it byte-for-byte.
DROP TRIGGER IF EXISTS gadgets_data_change_audit ON probes.gadgets;

CREATE TRIGGER gadgets_data_change_audit
    AFTER INSERT OR UPDATE OR DELETE ON probes.gadgets
    FOR EACH ROW EXECUTE FUNCTION auditlog.capture_data_change('id');

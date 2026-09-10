-- Down: drop the data-change capture function. Audit rows already written
-- stay (append-only law); tables whose triggers call this function must have
-- their triggers dropped first or their writes will fail loudly.
DROP FUNCTION IF EXISTS auditlog.capture_data_change();

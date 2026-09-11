-- The audit row inherits the SUBJECT row's org unit (ADR-0029 composition).
--
-- A composer that scopes auditlog.audit_trails with the tenancy decorator
-- puts a kind guard on the trail table: the capture INSERT must resolve a
-- real org unit or the guard rejects it — and takes the BUSINESS write down
-- with it. The session GUC alone is not enough there: migrations, seeders
-- and psql repairs are the deliberately GUC-less system path, and on those
-- connections app.acting_unit_id is unset.
--
-- The subject row always knows its unit. The capture function has the row
-- images in hand, so the trail INSERT now passes the subject's
-- org_unit_id explicitly:
--   * INSERT/UPDATE → NEW.org_unit_id
--   * DELETE        → OLD.org_unit_id
--   * subject table without the column → NULL, and the decorator's fill
--     trigger falls back to app.acting_unit_id as before.
-- In request lanes the two sources agree — writes are fenced to the acting
-- unit — so behavior there is unchanged; only the attribution becomes
-- strictly truthful: the trail row labels WHERE the audited row lives,
-- app.actor keeps saying WHO wrote it.
--
-- The column itself moves into the module's base table (nullable, no
-- fence): undecorated deployments keep a single table shape, and a
-- decorator that later scopes the table finds the column already there —
-- its ADD COLUMN is guarded, and the fence/fill/guard stay the composer's.

ALTER TABLE auditlog.audit_trails ADD COLUMN IF NOT EXISTS org_unit_id uuid;

CREATE OR REPLACE FUNCTION auditlog.capture_data_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    new_image jsonb;
    old_image jsonb;
    subject_key text;
    subject_unit uuid;
    diff jsonb;
BEGIN
    -- Never audit the audit store itself (infinite-recursion guard).
    IF TG_TABLE_SCHEMA = 'auditlog' AND TG_TABLE_NAME = 'audit_trails' THEN
        RETURN NULL;
    END IF;

    new_image := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END;
    old_image := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END;
    subject_key := coalesce(new_image, old_image) ->> TG_ARGV[0];
    subject_unit := NULLIF(coalesce(new_image, old_image) ->> 'org_unit_id', '')::uuid;

    IF TG_OP = 'INSERT' THEN
        diff := (SELECT jsonb_object_agg(key, jsonb_build_object('to', value))
                 FROM jsonb_each(new_image) WHERE value <> 'null'::jsonb);
    ELSIF TG_OP = 'DELETE' THEN
        diff := (SELECT jsonb_object_agg(key, jsonb_build_object('from', value))
                 FROM jsonb_each(old_image) WHERE value <> 'null'::jsonb);
    ELSE
        diff := (SELECT jsonb_object_agg(o.key, jsonb_build_object('from', o.value, 'to', n.value))
                 FROM jsonb_each(old_image) o
                 JOIN jsonb_each(new_image) n ON n.key = o.key
                 WHERE o.value IS DISTINCT FROM n.value);
    END IF;

    INSERT INTO auditlog.audit_trails
        (occurred_at, event_type, action, actor, subject_type, subject_id,
         changed, reason, status,
         correlation_id, client_ip, user_agent, http_method, resource_path,
         txid, org_unit_id)
    VALUES
        (NOW(), 'data_change', lower(TG_OP),
         COALESCE(NULLIF(current_setting('app.actor', true), ''), 'system'),
         TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME, subject_key,
         COALESCE(diff, '{}'::jsonb),
         NULLIF(current_setting('app.audit_reason', true), ''),
         'success',
         NULLIF(current_setting('app.correlation_id', true), ''),
         NULLIF(current_setting('app.client_ip', true), ''),
         NULLIF(current_setting('app.user_agent', true), ''),
         NULLIF(current_setting('app.http_method', true), ''),
         NULLIF(current_setting('app.resource_path', true), ''),
         txid_current()::text,
         subject_unit);
    RETURN NULL;
END;
$$;

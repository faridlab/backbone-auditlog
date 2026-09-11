-- Restore the capture function without the subject-org-unit channel
-- (the 20260911000200 shape: the trail INSERT resolves org_unit_id only
-- through the decorator's fill trigger / the acting-unit GUC).
--
-- The org_unit_id column on audit_trails STAYS: a decorator may already
-- have fenced the table on top of it, and dropping a column the composer
-- decorates would destroy scoping. Down here only undoes the function.

CREATE OR REPLACE FUNCTION auditlog.capture_data_change()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    new_image jsonb;
    old_image jsonb;
    subject_key text;
    diff jsonb;
BEGIN
    -- Never audit the audit store itself (infinite-recursion guard).
    IF TG_TABLE_SCHEMA = 'auditlog' AND TG_TABLE_NAME = 'audit_trails' THEN
        RETURN NULL;
    END IF;

    new_image := CASE WHEN TG_OP = 'DELETE' THEN NULL ELSE to_jsonb(NEW) END;
    old_image := CASE WHEN TG_OP = 'INSERT' THEN NULL ELSE to_jsonb(OLD) END;
    subject_key := coalesce(new_image, old_image) ->> TG_ARGV[0];

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
         txid)
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
         txid_current()::text);
    RETURN NULL;
END;
$$;

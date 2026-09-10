-- The data-change capture function (ADR-0025 trigger lane).
--
-- One shared implementation owned by this module: the schema generator's
-- `@audited` attribute emits row-level AFTER INSERT/UPDATE/DELETE triggers
-- that call this function with the table's primary-key column name as the
-- single trigger argument. Everything else is read here — the row images
-- from NEW/OLD, the actor and request context from the session GUCs the
-- host middleware sets — so trigger rows and this module's service-emitted
-- verbs attribute identically (the INSERT below mirrors the verb SQL).
--
-- Diff semantics (the trail is diff-only, and the history read re-anchors
-- on full images):
--   INSERT → {field: {"to": value}} for every non-null field (full image)
--   DELETE → {field: {"from": value}} for every non-null field (full image)
--   UPDATE → {field: {"from": old, "to": new}} for fields that actually
--            changed; an UPDATE that changes nothing records `{}` — the
--            write happened, nothing differed.
--
-- Outside request scope (cron, migrations, psql) nothing is set and rows
-- record actor 'system' with NULL request context — the same honest
-- attribution as the verbs. `app.audit_reason` is this lane's cascade
-- channel: a service that sets it around a cascade gets the reason on every
-- cascade-written row.

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

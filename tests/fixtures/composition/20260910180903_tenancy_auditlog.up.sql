-- Tenancy decorator chain — emitted by `metaphor schema tenancy` from tenancy.yaml.
-- Composition-installed tenancy (ADR-0029): modules ship no scoping columns; the
-- composing service installs org-unit fencing on the tables its descriptor lists.
-- Additive-only (nothing is removed — the module's own strip migration drops the
-- legacy company artifacts once org_unit_id is populated) and re-runnable (every
-- statement is guarded; a partially-applied file converges on re-run).

-- ══ auditlog.audit_trails: install the org-unit scoping column (ADR-0029) ══
ALTER TABLE auditlog.audit_trails ADD COLUMN IF NOT EXISTS org_unit_id uuid;

-- Backfill only while the module still carries company_id (the org spine
-- copied company ids verbatim, so values are identity-stable); then seal.
-- Stripped and fresh-empty tables have no source column and nothing to move.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_schema = 'auditlog' AND table_name = 'audit_trails'
                 AND column_name = 'company_id') THEN
        UPDATE auditlog.audit_trails SET org_unit_id = company_id WHERE org_unit_id IS NULL;
    END IF;
    IF EXISTS (SELECT 1 FROM auditlog.audit_trails WHERE org_unit_id IS NULL) THEN
        RAISE EXCEPTION 'auditlog.audit_trails: rows with NULL org_unit_id and no company_id to backfill from — the org spine must cover every company before this table can be sealed';
    END IF;
    ALTER TABLE auditlog.audit_trails ALTER COLUMN org_unit_id SET NOT NULL;
END $$;

ALTER TABLE auditlog.audit_trails ALTER COLUMN org_unit_id SET DEFAULT nullif(current_setting('app.acting_unit_id', true), '')::uuid;

-- Fence + write-path kind guard + per-unit uniques: the ADR-0028 runtime
-- shape, installed by the composer.
ALTER TABLE auditlog.audit_trails ENABLE ROW LEVEL SECURITY;
ALTER TABLE auditlog.audit_trails FORCE  ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_trails_org_unit_isolation ON auditlog.audit_trails;
CREATE POLICY audit_trails_org_unit_isolation ON auditlog.audit_trails
    FOR ALL
    USING      (org_unit_id = ANY(string_to_array(current_setting('app.scope_unit_ids', true), ',')::uuid[]))
    WITH CHECK (org_unit_id = ANY(string_to_array(current_setting('app.scope_unit_ids', true), ',')::uuid[]));

-- Write-path kind guard (ADR-0028): org_unit_id must name an
-- organization.org_units node of an allowed kind; unknown ids and
-- wrong-kind nodes are rejected at write time.
CREATE OR REPLACE FUNCTION auditlog.audit_trails_org_unit_kind_guard() RETURNS trigger AS $$
DECLARE
    v_kind text;
BEGIN
    SELECT kind::text INTO v_kind FROM organization.org_units WHERE id = NEW.org_unit_id;
    IF v_kind IS NULL THEN
        RAISE EXCEPTION 'audit_trails.org_unit_id % does not reference an organization.org_units node', NEW.org_unit_id;
    END IF;
    IF v_kind NOT IN ('company', 'branch') THEN
        RAISE EXCEPTION 'audit_trails.org_unit_id must reference a company or branch node, got a % node', v_kind;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_trails_org_unit_kind_guard ON auditlog.audit_trails;
CREATE TRIGGER audit_trails_org_unit_kind_guard
    BEFORE INSERT OR UPDATE OF org_unit_id ON auditlog.audit_trails
    FOR EACH ROW EXECUTE FUNCTION auditlog.audit_trails_org_unit_kind_guard();
-- Insert-path unit stamp (ADR-0029): fill a NULL org_unit_id from the
-- acting-unit session variable before the kind guard runs (trigger
-- names sort first). Writers that name every column — an ORM mapping
-- the whole row type — insert an explicit NULL that bypasses the
-- column DEFAULT; an unbound scope stays NULL and is refused loudly.
CREATE OR REPLACE FUNCTION auditlog.audit_trails_org_unit_fill() RETURNS trigger AS $$
BEGIN
    IF NEW.org_unit_id IS NULL THEN
        NEW.org_unit_id := nullif(current_setting('app.acting_unit_id', true), '')::uuid;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_trails_org_unit_fill ON auditlog.audit_trails;
CREATE TRIGGER audit_trails_org_unit_fill
    BEFORE INSERT ON auditlog.audit_trails
    FOR EACH ROW EXECUTE FUNCTION auditlog.audit_trails_org_unit_fill();

-- ══ Deny-by-default coverage over the scoped schemas (ADR-0029) ══
CREATE SCHEMA IF NOT EXISTS tenancy;
CREATE OR REPLACE FUNCTION tenancy.deny_undecorated_table() RETURNS event_trigger
LANGUAGE plpgsql AS $$
DECLARE
    cmd record;
    t text;
BEGIN
    FOR cmd IN SELECT * FROM pg_event_trigger_ddl_commands()
             WHERE command_tag IN ('CREATE TABLE', 'CREATE TABLE AS', 'SELECT INTO')
               AND schema_name IN ('auditlog')
    LOOP
        SELECT c.relname INTO t FROM pg_class c WHERE c.oid = cmd.objid;
        EXECUTE format('ALTER TABLE %s ENABLE ROW LEVEL SECURITY', cmd.object_identity);
        EXECUTE format('ALTER TABLE %s FORCE ROW LEVEL SECURITY', cmd.object_identity);
        EXECUTE format('CREATE POLICY %I ON %s FOR ALL USING (false) WITH CHECK (false)', t || '_deny', cmd.object_identity);
        EXECUTE format('COMMENT ON POLICY %I ON %s IS ''tenancy: table created in a scoped schema without a tenancy descriptor entry — locked until the descriptor covers it (ADR-0029)''', t || '_deny', cmd.object_identity);
    END LOOP;
END $$;

DROP EVENT TRIGGER IF EXISTS tenancy_deny_undecorated_table;
CREATE EVENT TRIGGER tenancy_deny_undecorated_table ON ddl_command_end
    EXECUTE FUNCTION tenancy.deny_undecorated_table();

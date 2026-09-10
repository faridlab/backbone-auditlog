-- Org-spine fixture for the decorated composition probe.
--
-- The decorator's kind guard validates org_unit_id against
-- organization.org_units (the org spine the composing deployment carries).
-- The module's dev database has no such schema, so the probe's scratch
-- deployment creates this minimal stand-in: two company nodes and one branch
-- node, all as a bootstrap role (superuser) so RLS cannot bind them.
--
-- Idempotent: safe to re-run (ON CONFLICT DO NOTHING, guarded DDL).

CREATE SCHEMA IF NOT EXISTS organization;

CREATE TABLE IF NOT EXISTS organization.org_units (
    id   uuid PRIMARY KEY,
    kind text NOT NULL
);

-- Fixed ids so the probe (and re-runs) reference stable nodes.
INSERT INTO organization.org_units (id, kind) VALUES
    ('00000000-0000-0000-0001-00000000000a', 'company'),
    ('00000000-0000-0000-0001-00000000000b', 'company'),
    ('00000000-0000-0000-0001-00000000000c', 'branch')
ON CONFLICT (id) DO NOTHING;

# backbone-auditlog

The central append-only audit store (ADR-0025). One `audit_trails` row per
audited change or refusal, written **in the same transaction** that mutated
the subject, carrying the actor from the request context, a diff-only
`changed` payload, and request correlation.

## Why a central trail

The alternative — per-module audit tables — was surveyed and rejected: six
legacy `<module>_audit_log` tables already exist in the tree, each
service-emitted only, with a plain UUID actor, no request context, no
database enforcement, and no rollback coupling. A query like "everything
that touched this quote" cannot cross them. This module is the single
store every composed service writes to, so the trail is queryable in one
place and the invariants are enforced once, in the database.

## The hybrid capture design

Two lanes feed the same table (ADR-0025):

| Lane | Who writes | What it captures |
|---|---|---|
| **Data-change** | row-level triggers (`@audited` on a model, emitted by the schema plugin, calling this module's `auditlog.capture_data_change()`) | every insert/update/delete on an audited table, with the row diff |
| **Service-emitted** | this module's write verbs, called by a composing service | what has no row to diff — refused writes, security edges, and any service that wants an explicit row |

Both lanes attribute identically: actor and request context are read from
the session GUCs inside the INSERT, so a trigger row and a verb row from
the same request carry the same actor, correlation id, and client facts.

The trigger lane's one shared implementation lives here:
`auditlog.capture_data_change()` (migration `20260911000200`). The
generator's `@audited` attribute emits one migration per audited table —
nothing but a row-level `AFTER INSERT OR UPDATE OR DELETE` trigger calling
the capture function with the table's primary-key column name as the single
trigger argument — so the diff semantics and GUC reads are defined once, in
this module, and every audited table in every composing service attributes
identically. The INSERT inside the function mirrors the verbs' SQL
byte-for-byte. Diff shapes: INSERT records the full non-null new image as
`{field: {"to": v}}`, DELETE the full prior image as `{field: {"from": v}}`
(the anchors the history read re-anchors on), and UPDATE only the fields
that changed as `{field: {"from": old, "to": new}}` (`{}` when nothing
differed). `app.audit_reason` is this lane's cascade channel: set it around
a cascade and every cascade-written row carries the reason.

## The write verbs

`AuditTrailWriter` (in `src/application/service/audit_trail_service_custom.rs`)
extends the generated `AuditTrailService`:

- `log_event(exec, event)` — the general verb: one explicit audit row.
- `log_refusal(exec, action, subject_type, subject_id, reason)` — a refused
  write; `event_type = refusal`, `status = failure` by definition.
- `log_security_edge(exec, action, reason)` — a security-relevant boundary
  event; `event_type = security_edge`, `status = failure`.

Every verb takes the **caller's executor** — the same transaction running
the business mutation. The audit row commits with the write and dies with
it on rollback: an audit row that survives a rolled-back write is lying.
Calling a verb with a pool instead of the mutation's transaction throws
that property away and is a caller bug.

## Session GUC contract

The composing service's request middleware sets these per request (fallback
in the INSERT when unset):

| GUC | Meaning | Fallback |
|---|---|---|
| `app.actor` | acting user id | `'system'` |
| `app.correlation_id` | request correlation | NULL |
| `app.client_ip` | client address | NULL |
| `app.user_agent` | client user agent | NULL |
| `app.http_method` | request method | NULL |
| `app.resource_path` | request path | NULL |

Outside request scope (cron, migrations, psql) nothing is set and the row
records `system` with NULL request context — the honest attribution for a
non-request write. `reason` is an explicit parameter on the verbs (the
caller knows why it is logging); the `app.audit_reason` GUC belongs to the
trigger lane's cascade attribution and is deliberately not read here.

## Append-only enforcement

`migrations/20260911000000_audit_trails_immutable.up.sql` installs a
`BEFORE UPDATE OR DELETE` trigger that raises for every mutation of an
audit row. Enforcement lives in the database, not convention: the trigger
fires for every role, owner included. The trail stays the truth of what
happened — including rows a bug wrote; the correction is always a new row,
never an edit.

## Promotion contract (no FKs)

`subject_type` / `subject_id` are loose text join keys — never foreign
keys into business tables — and `correlation_id` is likewise unconstrained.
The store must stay liftable to an independent service without rewriting
its consumers.

## Tenancy-free by composition

Per the composition-installed tenancy ruling (ADR-0029), this module ships
**no** tenancy. The composing service owns `tenancy.yaml` and installs the
org-unit fence via the decorator chain (`metaphor schema tenancy`), exactly
as it does for every other module.

## Reads

The model is `read_only`: the generator emits GET routes only
(`readonly_routes()`), and writes to those routes return 405. Audit rows
are appended through the verbs or the trigger lane — never through the
HTTP surface.

## Testing

```bash
# module dev database (convention: the scratch postgres on 5433)
createdb -h 127.0.0.1 -p 5433 -U postgres backbone_auditlog

# apply migrations out-of-band, in order
for f in migrations/*.up.sql; do
  psql -h 127.0.0.1 -p 5433 -U postgres -d backbone_auditlog -f "$f"
done

cargo test --test audit_trail_semantics
```

`tests/audit_trail_semantics.rs` is the behavior oracle: the refusal-row
contract, append-only rejection (attempted, not assumed — UPDATE and DELETE
each exercised directly and refused), rollback truth, the no-FK promotion
contract, and GUC attribution. `tests/capture_trigger_probe.rs` proves the
trigger lane end to end on the same database: a bare psql write with no
service involved still lands (actor `system`), a batch statement audits one
row per affected row, DELETE records the full prior image, the GUC context
(actor, correlation, cascade reason) lands, and a no-op UPDATE records the
honest empty diff. When the database is unreachable the tests
SKIP (env), they do not fail.

`tests/composition_fence_probe.rs` pins the tenancy half-fence module-side:
armed RLS flags, zero policies, and a minted non-superuser app role
default-denied until the decorator composes. `tests/decorated_composition_probe.rs`
proves the composed shape on a second scratch database
(`backbone_auditlog_decorated`): the module's migrations plus the decorator
chain emitted from `tests/fixtures/composition/tenancy.yaml` (the stand-in for
the composing service's descriptor) over an org-spine fixture — as the app
role, the fence admits exactly the entitled scope through the module's own
verbs, the kind guard rejects unknown acting units, and append-only still
outranks the fence. Prepare that database per the doc comment at the top of
the probe.

## Schema

`schema/models/audit_trail.model.yaml` is the single source of truth;
regenerate with `metaphor schema schema generate --force`. Hand-written
files (`audit_trail_service_custom.rs`, the immutability migration, the
test suites, `docs/`) are declared in `metaphor.codegen.yaml` and survive
regeneration.

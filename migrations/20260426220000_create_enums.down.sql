-- Down: drop enum types for auditlog module
DROP TYPE IF EXISTS audit_status CASCADE;
DROP TYPE IF EXISTS audit_event_type CASCADE;

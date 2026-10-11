// This directory's extension (hand-written; ADR-0031). The generated mod.rs (lib.rs for
// src/) pulls it in with include!, so its lines resolve against this directory.

// The same-transaction audit verbs (ADR-0025 service-emitted lane).
pub mod audit_trail_service_custom;
pub use audit_trail_service_custom::{append, AuditEvent, AuditHistoryProvider, AuditTrailWriter};

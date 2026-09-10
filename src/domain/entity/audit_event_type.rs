use serde::{Deserialize, Serialize};
use sqlx::Type;
use std::str::FromStr;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Type)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "snake_case")]
#[sqlx(type_name = "audit_event_type", rename_all = "snake_case")]
pub enum AuditEventType {
    DataChange,
    Refusal,
    SecurityEdge,
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::DataChange => write!(f, "data_change"),
            Self::Refusal => write!(f, "refusal"),
            Self::SecurityEdge => write!(f, "security_edge"),
        }
    }
}

impl FromStr for AuditEventType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "data_change" => Ok(Self::DataChange),
            "refusal" => Ok(Self::Refusal),
            "security_edge" => Ok(Self::SecurityEdge),
            _ => Err(format!("Unknown AuditEventType variant: {}", s)),
        }
    }
}

impl Default for AuditEventType {
    fn default() -> Self {
        Self::DataChange
    }
}

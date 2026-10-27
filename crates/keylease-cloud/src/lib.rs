//! KeyLease Cloud modular control plane.

mod api;
mod enterprise;
mod enterprise_api;
mod oidc;
mod relay;
mod siem;
mod store;

pub use api::{CloudApiConfig, CloudApiState, router};
pub use enterprise::{AuditExportBatch, ScimTokenSecret};
pub use siem::SiemExporter;
pub use store::{
    ApprovalDecisionBinding, AuditIntegrityReport, AuditQueryFilter, AuditQueryPage,
    CloudRepository, CredentialLeaseFilter, EdgeEnrollmentSecret,
};

pub const SERVICE_NAME: &str = "keylease-cloud";

//! KeyLease Cloud modular control plane.

mod api;
mod store;

pub use api::{CloudApiConfig, CloudApiState, router};
pub use store::{ApprovalDecisionBinding, CloudRepository, EdgeEnrollmentSecret};

pub const SERVICE_NAME: &str = "keylease-cloud";

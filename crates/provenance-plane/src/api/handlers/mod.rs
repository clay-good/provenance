//! API request handlers

pub mod federation;
pub mod issue;
pub mod keys;
pub mod process;

pub use issue::{issue_pca, AppState, TrustPlaneConfig, IssuePcaRequest, IssuePcaResponse};
pub use keys::{list_executors, register_executor, ListExecutorsResponse, RegisterExecutorRequest, RegisterExecutorResponse};
pub use process::{process_poc, ProcessPocRequest, ProcessPocResponse};
pub use federation::{
    get_info, register_cat, list_cats, unregister_cat, verify_federated_pca, discover_cat,
    TrustPlaneInfo, RegisterCatRequest, RegisterCatResponse, ListCatsResponse, CatEntry,
    VerifyFederatedPcaRequest, VerifyFederatedPcaResponse, DiscoverCatRequest,
};

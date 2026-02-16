use pbts_core::contract::ContractManager;
use pbts_core::types::{TrackerConfig, TrackerState};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state accessible from all route handlers.
pub struct AppState {
    pub tracker: Arc<RwLock<TrackerState>>,
    pub contract: Arc<RwLock<Option<ContractManager>>>,
}

impl AppState {
    pub fn new(config: TrackerConfig) -> Self {
        Self {
            tracker: Arc::new(RwLock::new(TrackerState::new(config))),
            contract: Arc::new(RwLock::new(None)),
        }
    }
}

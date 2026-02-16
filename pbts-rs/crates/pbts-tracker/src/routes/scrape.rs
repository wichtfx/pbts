use axum::extract::{Query, State};
use axum::response::IntoResponse;
use serde::Deserialize;
use std::sync::Arc;

use crate::state::AppState;

#[derive(Deserialize)]
pub struct ScrapeParams {
    pub info_hash: Option<String>,
}

pub async fn handle_scrape(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ScrapeParams>,
) -> impl IntoResponse {
    let tracker = state.tracker.read().await;

    let mut files = String::from("d5:filesd");

    if let Some(ih) = &params.info_hash {
        let infohash_bytes = super::announce::url_decode_binary(ih);
        if infohash_bytes.len() == 20 {
            let mut infohash = [0u8; 20];
            infohash.copy_from_slice(&infohash_bytes);
            if let Some(swarm) = tracker.swarms.get(&infohash) {
                let complete = swarm.values().filter(|p| p.left == 0).count();
                let incomplete = swarm.len() - complete;
                files.push_str(&format!(
                    "20:{}d8:completei{complete}e10:incompletei{incomplete}e10:downloadedi0ee",
                    String::from_utf8_lossy(&infohash)
                ));
            }
        }
    } else {
        for (infohash, swarm) in &tracker.swarms {
            let complete = swarm.values().filter(|p| p.left == 0).count();
            let incomplete = swarm.len() - complete;
            files.push_str(&format!(
                "20:{}d8:completei{complete}e10:incompletei{incomplete}e10:downloadedi0ee",
                String::from_utf8_lossy(infohash)
            ));
        }
    }

    files.push_str("ee");
    files
}

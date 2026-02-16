mod routes;
mod state;

use axum::routing::{get, post};
use axum::Router;
use pbts_core::types::TrackerConfig;
use state::AppState;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8000".to_string())
        .parse()
        .unwrap_or(8000);

    let min_ratio: f64 = std::env::var("MIN_RATIO")
        .unwrap_or_else(|_| "0.5".to_string())
        .parse()
        .unwrap_or(0.5);

    let config = TrackerConfig {
        min_ratio,
        ..TrackerConfig::default()
    };

    let shared_state = Arc::new(AppState::new(config));

    let app = Router::new()
        // Standard BitTorrent
        .route("/announce", get(routes::announce::handle_announce))
        .route("/scrape", get(routes::scrape::handle_scrape))
        // PBTS extensions
        .route("/register", post(routes::register::handle_register))
        .route("/report", post(routes::report::handle_report))
        // Crypto operations
        .route("/keygen", post(routes::crypto::handle_keygen))
        .route("/attest", post(routes::crypto::handle_attest))
        .route(
            "/verify-receipt",
            post(routes::crypto::handle_verify_receipt),
        )
        // Contract operations
        .route("/contract/init", post(routes::contract::handle_contract_init))
        .route(
            "/contract/user/{username}",
            get(routes::contract::handle_contract_get_user),
        )
        .route(
            "/contract/status",
            get(routes::contract::handle_contract_status),
        )
        // TEE operations
        .route(
            "/generate-attestation",
            post(routes::tee::handle_generate_attestation),
        )
        .route(
            "/verify-attestation",
            post(routes::tee::handle_verify_attestation),
        )
        // Info
        .route("/health", get(handle_health))
        .route("/stats", get(handle_stats))
        .with_state(shared_state.clone());

    tracing::info!("PBTS Tracker (Rust) listening on 0.0.0.0:{port}");
    tracing::info!("  min_ratio: {min_ratio}");

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_health(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    let tracker = state.tracker.read().await;
    axum::Json(serde_json::json!({
        "status": "ok",
        "instance_id": tracker.config.instance_id,
        "implementation": "rust",
    }))
}

async fn handle_stats(
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> axum::Json<serde_json::Value> {
    let tracker = state.tracker.read().await;
    let total_peers: usize = tracker.swarms.values().map(|s| s.len()).sum();
    axum::Json(serde_json::json!({
        "instance_id": tracker.config.instance_id,
        "total_torrents": tracker.swarms.len(),
        "total_peers": total_peers,
        "total_users": tracker.users.len(),
        "min_ratio": tracker.config.min_ratio,
        "implementation": "rust",
    }))
}

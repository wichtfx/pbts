use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use pbts_core::crypto;
use pbts_core::types::User;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub user_id: String,
    pub public_key: String, // base64
    pub signature: Option<String>, // base64, optional
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub success: bool,
    pub instance_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_register(
    State(state): State<Arc<AppState>>,
    Json(req): Json<RegisterRequest>,
) -> (StatusCode, Json<RegisterResponse>) {
    let mut tracker = state.tracker.write().await;
    let b64 = base64::engine::general_purpose::STANDARD;

    // Check if user already exists
    if tracker.users.contains_key(&req.user_id) {
        return (
            StatusCode::CONFLICT,
            Json(RegisterResponse {
                success: false,
                instance_id: tracker.config.instance_id.clone(),
                error: Some("User already registered".to_string()),
            }),
        );
    }

    // Decode public key
    let pk_bytes = match b64.decode(&req.public_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(RegisterResponse {
                    success: false,
                    instance_id: tracker.config.instance_id.clone(),
                    error: Some("Invalid public key encoding".to_string()),
                }),
            );
        }
    };

    // Verify signature if provided and verification enabled
    if tracker.config.verify_signatures {
        if let Some(sig_b64) = &req.signature {
            if let Ok(sig_bytes) = b64.decode(sig_b64) {
                let msg = format!(
                    "register{}{}",
                    tracker.config.instance_id, req.user_id
                );
                match crypto::verify_signature(&pk_bytes, msg.as_bytes(), &sig_bytes) {
                    Ok(true) => {}
                    _ => {
                        return (
                            StatusCode::UNAUTHORIZED,
                            Json(RegisterResponse {
                                success: false,
                                instance_id: tracker.config.instance_id.clone(),
                                error: Some("Invalid signature".to_string()),
                            }),
                        );
                    }
                }
            }
        }
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    tracker.users.insert(
        req.user_id.clone(),
        User {
            user_id: req.user_id,
            public_key: pk_bytes,
            total_uploaded: 1024, // InitCredit
            total_downloaded: 0,
            registered_at: now,
        },
    );

    (
        StatusCode::OK,
        Json(RegisterResponse {
            success: true,
            instance_id: tracker.config.instance_id.clone(),
            error: None,
        }),
    )
}

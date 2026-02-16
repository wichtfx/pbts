use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

// POST /generate-attestation
#[derive(Deserialize)]
pub struct AttestationRequest {
    pub payload: String,
}

#[derive(Serialize)]
pub struct AttestationResponse {
    pub success: bool,
    pub quote: Option<String>,
    pub generation_time_ms: Option<f64>,
    pub quote_size_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_generate_attestation(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<AttestationRequest>,
) -> (StatusCode, Json<AttestationResponse>) {
    match pbts_tee::manager::TEEManager::new_enabled().await {
        Ok(manager) => {
            let start = std::time::Instant::now();
            match manager.generate_attestation(&req.payload).await {
                Ok(report) => {
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    (
                        StatusCode::OK,
                        Json(AttestationResponse {
                            success: true,
                            quote: Some(report.quote),
                            generation_time_ms: Some(elapsed),
                            quote_size_bytes: Some(report.quote_size_bytes),
                            error: None,
                        }),
                    )
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(AttestationResponse {
                        success: false,
                        quote: None,
                        generation_time_ms: None,
                        quote_size_bytes: None,
                        error: Some(format!("Attestation generation failed: {e}")),
                    }),
                ),
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(AttestationResponse {
                success: false,
                quote: None,
                generation_time_ms: None,
                quote_size_bytes: None,
                error: Some(format!("TEE not available: {e}")),
            }),
        ),
    }
}

// POST /verify-attestation
#[derive(Deserialize)]
pub struct VerifyAttestationRequest {
    pub quote: String,
    pub expected_payload: String,
}

#[derive(Serialize)]
pub struct VerifyAttestationResponse {
    pub success: bool,
    pub is_valid: bool,
    pub verification_time_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_verify_attestation(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<VerifyAttestationRequest>,
) -> (StatusCode, Json<VerifyAttestationResponse>) {
    match pbts_tee::manager::TEEManager::new_enabled().await {
        Ok(manager) => {
            let start = std::time::Instant::now();
            match manager
                .verify_attestation(&req.quote, &req.expected_payload)
                .await
            {
                Ok(valid) => {
                    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
                    (
                        StatusCode::OK,
                        Json(VerifyAttestationResponse {
                            success: true,
                            is_valid: valid,
                            verification_time_ms: Some(elapsed),
                            error: None,
                        }),
                    )
                }
                Err(e) => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(VerifyAttestationResponse {
                        success: false,
                        is_valid: false,
                        verification_time_ms: None,
                        error: Some(format!("{e}")),
                    }),
                ),
            }
        }
        Err(e) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(VerifyAttestationResponse {
                success: false,
                is_valid: false,
                verification_time_ms: None,
                error: Some(format!("TEE not available: {e}")),
            }),
        ),
    }
}

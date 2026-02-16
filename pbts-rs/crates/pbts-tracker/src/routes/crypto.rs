use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use pbts_core::crypto;
use pbts_core::receipt;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

// POST /keygen
#[derive(Serialize)]
pub struct KeygenResponse {
    pub success: bool,
    pub private_key: String, // base64
    pub public_key: String,  // base64
    pub key_type: String,
    pub private_key_size: usize,
    pub public_key_size: usize,
}

pub async fn handle_keygen(State(_state): State<Arc<AppState>>) -> Json<KeygenResponse> {
    let (sk, pk) = crypto::generate_keypair();
    Json(KeygenResponse {
        success: true,
        private_key: base64::encode(&sk),
        public_key: base64::encode(&pk),
        key_type: "BLS12-381".to_string(),
        private_key_size: sk.len(),
        public_key_size: pk.len(),
    })
}

// POST /attest
#[derive(Deserialize)]
pub struct AttestRequest {
    pub receiver_private_key: String, // base64
    pub sender_public_key: String,    // base64
    pub piece_hash: String,           // hex
    pub piece_index: u32,
    pub infohash: String, // hex
    pub timestamp: u64,
}

#[derive(Serialize)]
pub struct AttestResponse {
    pub success: bool,
    pub receipt: Option<String>, // base64
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_attest(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<AttestRequest>,
) -> (StatusCode, Json<AttestResponse>) {
    let rx_sk = match base64::decode(&req.receiver_private_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AttestResponse {
                    success: false,
                    receipt: None,
                    timestamp: req.timestamp,
                    error: Some("Invalid receiver key".to_string()),
                }),
            )
        }
    };
    let sender_pk = match base64::decode(&req.sender_public_key) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AttestResponse {
                    success: false,
                    receipt: None,
                    timestamp: req.timestamp,
                    error: Some("Invalid sender key".to_string()),
                }),
            )
        }
    };
    let piece_hash = match hex::decode(&req.piece_hash) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AttestResponse {
                    success: false,
                    receipt: None,
                    timestamp: req.timestamp,
                    error: Some("Invalid piece hash".to_string()),
                }),
            )
        }
    };
    let infohash = match hex::decode(&req.infohash) {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(AttestResponse {
                    success: false,
                    receipt: None,
                    timestamp: req.timestamp,
                    error: Some("Invalid infohash".to_string()),
                }),
            )
        }
    };

    match receipt::attest_piece_transfer(
        &rx_sk,
        &sender_pk,
        &piece_hash,
        req.piece_index,
        &infohash,
        req.timestamp,
    ) {
        Ok(sig) => (
            StatusCode::OK,
            Json(AttestResponse {
                success: true,
                receipt: Some(base64::encode(&sig)),
                timestamp: req.timestamp,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AttestResponse {
                success: false,
                receipt: None,
                timestamp: req.timestamp,
                error: Some(format!("Signing failed: {e}")),
            }),
        ),
    }
}

// POST /verify-receipt
#[derive(Deserialize)]
pub struct VerifyReceiptRequest {
    pub receiver_public_key: String, // base64
    pub sender_public_key: String,   // base64
    pub piece_hash: String,          // hex
    pub piece_index: u32,
    pub infohash: String, // hex
    pub timestamp: u64,
    pub receipt: String, // base64
}

#[derive(Serialize)]
pub struct VerifyReceiptResponse {
    pub success: bool,
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_verify_receipt(
    State(_state): State<Arc<AppState>>,
    Json(req): Json<VerifyReceiptRequest>,
) -> (StatusCode, Json<VerifyReceiptResponse>) {
    let rx_pk = base64::decode(&req.receiver_public_key).unwrap_or_default();
    let sender_pk = base64::decode(&req.sender_public_key).unwrap_or_default();
    let piece_hash = hex::decode(&req.piece_hash).unwrap_or_default();
    let infohash = hex::decode(&req.infohash).unwrap_or_default();
    let sig = base64::decode(&req.receipt).unwrap_or_default();

    match receipt::verify_receipt(
        &rx_pk,
        &sender_pk,
        &piece_hash,
        req.piece_index,
        &infohash,
        req.timestamp,
        &sig,
    ) {
        Ok(valid) => (
            StatusCode::OK,
            Json(VerifyReceiptResponse {
                success: true,
                valid,
                error: None,
            }),
        ),
        Err(e) => (
            StatusCode::OK,
            Json(VerifyReceiptResponse {
                success: true,
                valid: false,
                error: Some(format!("{e}")),
            }),
        ),
    }
}

// Base64 encode/decode helpers using the base64 crate
mod base64 {
    use ::base64::{engine::general_purpose::STANDARD, Engine};

    pub fn encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ::base64::DecodeError> {
        STANDARD.decode(s)
    }
}

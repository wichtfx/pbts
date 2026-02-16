use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::state::AppState;

// POST /contract/init
#[derive(Deserialize)]
pub struct ContractInitRequest {
    pub rpc_url: String,
    pub private_key: String,
    pub factory_address: String,
    pub referrer_address: Option<String>,
}

#[derive(Serialize)]
pub struct ContractInitResponse {
    pub success: bool,
    pub reputation_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_contract_init(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ContractInitRequest>,
) -> (StatusCode, Json<ContractInitResponse>) {
    let mut manager = match pbts_core::contract::ContractManager::new(
        &req.rpc_url,
        &req.private_key,
        &req.factory_address,
    ) {
        Ok(m) => m,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ContractInitResponse {
                    success: false,
                    reputation_address: None,
                    error: Some(format!("Failed to create contract manager: {e}")),
                }),
            )
        }
    };

    let referrer = req
        .referrer_address
        .and_then(|a| a.parse().ok());

    match manager.create_reputation_contract(referrer).await {
        Ok(addr) => {
            let addr_str = format!("{:?}", addr);
            *state.contract.write().await = Some(manager);
            (
                StatusCode::OK,
                Json(ContractInitResponse {
                    success: true,
                    reputation_address: Some(addr_str),
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ContractInitResponse {
                success: false,
                reputation_address: None,
                error: Some(format!("Contract deployment failed: {e}")),
            }),
        ),
    }
}

// GET /contract/user/:username
#[derive(Serialize)]
pub struct ContractUserResponse {
    pub success: bool,
    pub username: String,
    pub download_size: String,
    pub upload_size: String,
    pub ratio: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_contract_get_user(
    State(state): State<Arc<AppState>>,
    Path(username): Path<String>,
) -> (StatusCode, Json<ContractUserResponse>) {
    let contract = state.contract.read().await;
    let manager = match contract.as_ref() {
        Some(m) => m,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ContractUserResponse {
                    success: false,
                    username,
                    download_size: "0".to_string(),
                    upload_size: "0".to_string(),
                    ratio: 0.0,
                    error: Some("Contract not initialized".to_string()),
                }),
            )
        }
    };

    match manager.get_user(&username).await {
        Ok(data) => {
            let dl: u64 = data.downloadSize.try_into().unwrap_or(0);
            let ul: u64 = data.uploadSize.try_into().unwrap_or(0);
            let ratio = if dl == 0 {
                f64::INFINITY
            } else {
                ul as f64 / dl as f64
            };
            (
                StatusCode::OK,
                Json(ContractUserResponse {
                    success: true,
                    username,
                    download_size: data.downloadSize.to_string(),
                    upload_size: data.uploadSize.to_string(),
                    ratio,
                    error: None,
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ContractUserResponse {
                success: false,
                username,
                download_size: "0".to_string(),
                upload_size: "0".to_string(),
                ratio: 0.0,
                error: Some(format!("Query failed: {e}")),
            }),
        ),
    }
}

// GET /contract/status
#[derive(Serialize)]
pub struct ContractStatusResponse {
    pub configured: bool,
    pub reputation_address: Option<String>,
}

pub async fn handle_contract_status(
    State(state): State<Arc<AppState>>,
) -> Json<ContractStatusResponse> {
    let contract = state.contract.read().await;
    Json(ContractStatusResponse {
        configured: contract.is_some(),
        reputation_address: contract
            .as_ref()
            .and_then(|m| m.reputation_address.map(|a| format!("{:?}", a))),
    })
}

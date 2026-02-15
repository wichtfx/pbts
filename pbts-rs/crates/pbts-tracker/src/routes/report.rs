use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use base64::Engine;
use pbts_core::receipt;
use pbts_core::types::{PBTSReceipt, ReportRequest};
use serde::Serialize;
use std::sync::Arc;

use crate::state::AppState;

#[derive(Serialize)]
pub struct ReportResponse {
    pub success: bool,
    pub verified_receipts: usize,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub ratio: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub async fn handle_report(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ReportRequest>,
) -> (StatusCode, Json<ReportResponse>) {
    let mut tracker = state.tracker.write().await;
    let b64 = base64::engine::general_purpose::STANDARD;

    // GC old receipts periodically
    tracker.gc_receipts();

    // Check user exists
    if !tracker.users.contains_key(&req.user_id) {
        return (
            StatusCode::NOT_FOUND,
            Json(ReportResponse {
                success: false,
                verified_receipts: 0,
                total_uploaded: 0,
                total_downloaded: 0,
                ratio: 0.0,
                error: Some("User not found".to_string()),
            }),
        );
    }

    // Convert receipt entries to PBTSReceipt
    let receipts: Vec<PBTSReceipt> = req
        .receipts
        .iter()
        .filter_map(|entry| {
            let receiver_pk = b64.decode(&entry.receiver_public_key).ok()?;
            let sender_pk = b64.decode(&entry.sender_pk).ok()?;
            let piece_hash = hex::decode(&entry.piece_hash).ok()?;
            let infohash = hex::decode(&entry.infohash).ok()?;
            let sig = b64.decode(&entry.signature).ok()?;
            Some(PBTSReceipt {
                infohash,
                sender_pk,
                receiver_pk,
                piece_hash,
                piece_index: entry.piece_index,
                timestamp: entry.timestamp,
                t_epoch: entry.timestamp,
                signature: sig,
                piece_size: entry.piece_size,
            })
        })
        .collect();

    if receipts.len() != req.receipts.len() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ReportResponse {
                success: false,
                verified_receipts: 0,
                total_uploaded: 0,
                total_downloaded: 0,
                ratio: 0.0,
                error: Some("Invalid receipt encoding".to_string()),
            }),
        );
    }

    // Process report with aggregate verification
    let window = tracker.config.receipt_window;
    let verify = tracker.config.verify_signatures;

    if verify && !receipts.is_empty() {
        match receipt::process_report(&receipts, &mut tracker.used_receipts, window) {
            Ok(result) => {
                if let Some(user) = tracker.users.get_mut(&req.user_id) {
                    user.total_uploaded += req.uploaded_delta;
                    user.total_downloaded += req.downloaded_delta;
                    let ratio = user.ratio();
                    return (
                        StatusCode::OK,
                        Json(ReportResponse {
                            success: true,
                            verified_receipts: result.verified_count,
                            total_uploaded: user.total_uploaded,
                            total_downloaded: user.total_downloaded,
                            ratio,
                            error: None,
                        }),
                    );
                }
            }
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ReportResponse {
                        success: false,
                        verified_receipts: 0,
                        total_uploaded: 0,
                        total_downloaded: 0,
                        ratio: 0.0,
                        error: Some(format!("Report verification failed: {e}")),
                    }),
                );
            }
        }
    }

    // No verification or no receipts: just update stats
    if let Some(user) = tracker.users.get_mut(&req.user_id) {
        user.total_uploaded += req.uploaded_delta;
        user.total_downloaded += req.downloaded_delta;
        let ratio = user.ratio();
        return (
            StatusCode::OK,
            Json(ReportResponse {
                success: true,
                verified_receipts: receipts.len(),
                total_uploaded: user.total_uploaded,
                total_downloaded: user.total_downloaded,
                ratio,
                error: None,
            }),
        );
    }

    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ReportResponse {
            success: false,
            verified_receipts: 0,
            total_uploaded: 0,
            total_downloaded: 0,
            ratio: 0.0,
            error: Some("Internal error".to_string()),
        }),
    )
}

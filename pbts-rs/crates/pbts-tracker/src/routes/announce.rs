use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use base64::Engine;
use pbts_core::types::Peer;
use rand::seq::SliceRandom;
use serde::Deserialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::state::AppState;

#[derive(Deserialize)]
pub struct AnnounceParams {
    pub info_hash: String,
    pub peer_id: String,
    pub port: u16,
    #[serde(default)]
    pub uploaded: u64,
    #[serde(default)]
    pub downloaded: u64,
    #[serde(default)]
    pub left: u64,
    #[serde(default)]
    pub event: Option<String>,
    #[serde(default)]
    pub compact: Option<u8>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
}

pub async fn handle_announce(
    State(state): State<Arc<AppState>>,
    Query(params): Query<AnnounceParams>,
) -> impl IntoResponse {
    let mut tracker = state.tracker.write().await;

    // Decode info_hash (URL-encoded binary)
    let infohash_bytes = url_decode_binary(&params.info_hash);
    if infohash_bytes.len() != 20 {
        return (
            StatusCode::BAD_REQUEST,
            bencode_error("Invalid info_hash"),
        );
    }
    let mut infohash = [0u8; 20];
    infohash.copy_from_slice(&infohash_bytes);

    let event = params.event.as_deref().unwrap_or("none");
    let peer_key = format!("{}:{}", params.ip.as_deref().unwrap_or("0.0.0.0"), params.port);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    // Handle stop event
    if event == "stopped" {
        if let Some(swarm) = tracker.swarms.get_mut(&infohash) {
            swarm.remove(&peer_key);
        }
        return (StatusCode::OK, bencode_response(&[], 0, 0));
    }

    // Check reputation if configured
    if event == "started" && tracker.config.min_ratio > 0.0 {
        if let Some(uid) = &params.user_id {
            if let Some(user) = tracker.users.get(uid.as_str()) {
                if user.ratio() < tracker.config.min_ratio && user.total_downloaded > 0 {
                    return (
                        StatusCode::FORBIDDEN,
                        bencode_error("Insufficient reputation"),
                    );
                }
            }
        }
    }

    // Read config before mutable borrow on swarms
    let max_peers = tracker.config.max_peers;

    // Add/update peer in swarm
    let swarm = tracker.swarms.entry(infohash).or_default();
    let b64 = base64::engine::general_purpose::STANDARD;
    let peer = Peer {
        peer_id: url_decode_binary(&params.peer_id),
        ip: params.ip.unwrap_or_else(|| "0.0.0.0".to_string()),
        port: params.port,
        user_id: params.user_id,
        public_key: params.public_key.and_then(|pk| b64.decode(&pk).ok()),
        uploaded: params.uploaded,
        downloaded: params.downloaded,
        left: params.left,
        last_seen: now,
    };
    swarm.insert(peer_key.clone(), peer);

    // Select random peers (excluding the requester)
    let mut candidates: Vec<&Peer> = swarm
        .iter()
        .filter(|(k, _)| *k != &peer_key)
        .map(|(_, p)| p)
        .collect();
    candidates.shuffle(&mut rand::thread_rng());
    candidates.truncate(max_peers);

    let complete = swarm.values().filter(|p| p.left == 0).count();
    let incomplete = swarm.len() - complete;

    let compact = params.compact.unwrap_or(1) == 1;
    if compact {
        // BEP 23 compact format: 6 bytes per peer (4 IP + 2 port)
        let mut peers_bytes = Vec::with_capacity(candidates.len() * 6);
        for p in &candidates {
            if let Ok(ip) = p.ip.parse::<std::net::Ipv4Addr>() {
                peers_bytes.extend_from_slice(&ip.octets());
                peers_bytes.extend_from_slice(&p.port.to_be_bytes());
            }
        }
        let response = format!(
            "d8:completei{complete}e10:incompletei{incomplete}e8:intervali1800e12:min intervali900e5:peers{}:{}e",
            peers_bytes.len(),
            String::from_utf8_lossy(&peers_bytes)
        );
        (StatusCode::OK, response)
    } else {
        (
            StatusCode::OK,
            bencode_response(&candidates, complete, incomplete),
        )
    }
}

fn bencode_error(msg: &str) -> String {
    format!("d14:failure reason{}:{}e", msg.len(), msg)
}

fn bencode_response(peers: &[&Peer], complete: usize, incomplete: usize) -> String {
    let mut peer_list = String::from("l");
    for p in peers {
        peer_list.push_str(&format!(
            "d2:ip{}:{}4:porti{}e7:peer id{}:{}e",
            p.ip.len(),
            p.ip,
            p.port,
            p.peer_id.len(),
            String::from_utf8_lossy(&p.peer_id)
        ));
    }
    peer_list.push('e');

    format!(
        "d8:completei{complete}e10:incompletei{incomplete}e8:intervali1800e12:min intervali900e5:peers{peer_list}e"
    )
}

pub fn url_decode_binary(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                &String::from_utf8_lossy(&bytes[i + 1..i + 3]),
                16,
            ) {
                result.push(byte);
                i += 3;
                continue;
            }
        }
        result.push(bytes[i]);
        i += 1;
    }
    result
}

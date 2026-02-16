use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::SystemTime;

/// 20-byte BitTorrent info hash
pub type InfoHash = [u8; 20];

/// BLS12-381 public key (48 bytes compressed)
pub type BlsPublicKey = [u8; 48];

/// BLS12-381 signature (96 bytes compressed)
pub type BlsSignature = [u8; 96];

/// SHA-256 piece hash (32 bytes)
pub type PieceHash = [u8; 32];

/// A peer in a BitTorrent swarm.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub peer_id: Vec<u8>,
    pub ip: String,
    pub port: u16,
    pub user_id: Option<String>,
    pub public_key: Option<Vec<u8>>,
    pub uploaded: u64,
    pub downloaded: u64,
    pub left: u64,
    pub last_seen: f64,
}

/// A registered user with reputation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub user_id: String,
    pub public_key: Vec<u8>,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
    pub registered_at: f64,
}

impl User {
    pub fn ratio(&self) -> f64 {
        if self.total_downloaded == 0 {
            f64::INFINITY
        } else {
            self.total_uploaded as f64 / self.total_downloaded as f64
        }
    }
}

/// A cryptographic receipt for a piece transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PBTSReceipt {
    pub infohash: Vec<u8>,
    pub sender_pk: Vec<u8>,
    pub receiver_pk: Vec<u8>,
    pub piece_hash: Vec<u8>,
    pub piece_index: u32,
    pub timestamp: u64,
    pub t_epoch: u64,
    pub signature: Vec<u8>,
    #[serde(default)]
    pub piece_size: u64,
}

impl PBTSReceipt {
    /// Build the signed message from receipt fields.
    /// Format: infohash(20B) || sender_pk(48B) || piece_hash(32B) || piece_index(4B) || timestamp(8B)
    pub fn message(&self) -> Vec<u8> {
        let mut msg = Vec::with_capacity(112);
        msg.extend_from_slice(&self.infohash);
        msg.extend_from_slice(&self.sender_pk);
        msg.extend_from_slice(&self.piece_hash);
        msg.extend_from_slice(&self.piece_index.to_be_bytes());
        msg.extend_from_slice(&self.timestamp.to_be_bytes());
        msg
    }

    /// Unique receipt ID for double-spend prevention.
    pub fn receipt_id(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&self.infohash);
        hasher.update(&self.sender_pk);
        hasher.update(&self.receiver_pk);
        hasher.update(&self.piece_hash);
        hasher.update(self.piece_index.to_be_bytes());
        hasher.update(self.t_epoch.to_be_bytes());
        hex::encode(hasher.finalize())
    }
}

/// Tracker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerConfig {
    pub min_ratio: f64,
    pub max_peers: usize,
    pub verify_signatures: bool,
    pub receipt_window: u64,
    pub instance_id: String,
}

impl Default for TrackerConfig {
    fn default() -> Self {
        Self {
            min_ratio: 0.5,
            max_peers: 50,
            verify_signatures: true,
            receipt_window: 3600,
            instance_id: hex::encode(rand::random::<[u8; 16]>()),
        }
    }
}

/// Full tracker state.
#[derive(Debug)]
pub struct TrackerState {
    /// infohash -> (peer_key -> Peer)
    pub swarms: HashMap<InfoHash, HashMap<String, Peer>>,
    /// user_id -> User
    pub users: HashMap<String, User>,
    /// receipt_id -> timestamp (for double-spend prevention)
    pub used_receipts: HashMap<String, f64>,
    pub config: TrackerConfig,
}

impl TrackerState {
    pub fn new(config: TrackerConfig) -> Self {
        Self {
            swarms: HashMap::new(),
            users: HashMap::new(),
            used_receipts: HashMap::new(),
            config,
        }
    }

    /// Garbage collect expired receipts.
    pub fn gc_receipts(&mut self) {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();
        let window = self.config.receipt_window as f64;
        self.used_receipts.retain(|_, ts| now - *ts < window * 2.0);
    }
}

/// Report request from a peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportRequest {
    pub user_id: String,
    pub public_key: String,
    pub uploaded_delta: u64,
    pub downloaded_delta: u64,
    pub receipts: Vec<ReceiptEntry>,
}

/// A single receipt entry in a report request (JSON format).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptEntry {
    pub receiver_public_key: String,
    pub sender_pk: String,
    pub piece_hash: String,
    pub piece_index: u32,
    pub infohash: String,
    pub timestamp: u64,
    pub signature: String,
    #[serde(default = "default_piece_size")]
    pub piece_size: u64,
}

fn default_piece_size() -> u64 {
    262144 // 256 KB
}

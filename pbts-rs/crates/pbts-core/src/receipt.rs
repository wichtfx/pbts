use crate::crypto;
use crate::types::PBTSReceipt;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("crypto error: {0}")]
    Crypto(#[from] crypto::CryptoError),
    #[error("receipt expired (epoch {epoch}, window [{window_start}, {window_end}])")]
    Expired {
        epoch: u64,
        window_start: u64,
        window_end: u64,
    },
    #[error("duplicate receipt: {0}")]
    Duplicate(String),
    #[error("signature verification failed for receipt index {0}")]
    InvalidSignature(usize),
    #[error("aggregate verification failed")]
    AggregateVerificationFailed,
}

/// Build the message bytes for a receipt.
/// Format: infohash || sender_pk || piece_hash || piece_index(4B BE) || timestamp(8B BE)
pub fn build_receipt_message(
    infohash: &[u8],
    sender_pk: &[u8],
    piece_hash: &[u8],
    piece_index: u32,
    timestamp: u64,
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(112);
    msg.extend_from_slice(infohash);
    msg.extend_from_slice(sender_pk);
    msg.extend_from_slice(piece_hash);
    msg.extend_from_slice(&piece_index.to_be_bytes());
    msg.extend_from_slice(&timestamp.to_be_bytes());
    msg
}

/// Generate a cryptographic receipt (Attest algorithm).
/// The *receiver* signs acknowledgment that the *sender* uploaded a piece.
pub fn attest_piece_transfer(
    receiver_sk: &[u8],
    sender_pk: &[u8],
    piece_hash: &[u8],
    piece_index: u32,
    infohash: &[u8],
    timestamp: u64,
) -> Result<Vec<u8>, crypto::CryptoError> {
    let msg = build_receipt_message(infohash, sender_pk, piece_hash, piece_index, timestamp);
    crypto::sign_message(receiver_sk, &msg)
}

/// Verify a single receipt (Verify algorithm).
pub fn verify_receipt(
    receiver_pk: &[u8],
    sender_pk: &[u8],
    piece_hash: &[u8],
    piece_index: u32,
    infohash: &[u8],
    timestamp: u64,
    signature: &[u8],
) -> Result<bool, crypto::CryptoError> {
    let msg = build_receipt_message(infohash, sender_pk, piece_hash, piece_index, timestamp);
    crypto::verify_signature(receiver_pk, &msg, signature)
}

/// Result of processing a report.
#[derive(Debug)]
pub struct ReportResult {
    pub verified_count: usize,
    pub total_uploaded: u64,
    pub total_downloaded: u64,
}

/// Process a batch of receipts with aggregate verification and double-spend checking.
/// This implements the tracker's Report algorithm.
pub fn process_report(
    receipts: &[PBTSReceipt],
    used_receipts: &mut HashMap<String, f64>,
    receipt_window: u64,
) -> Result<ReportResult, ReceiptError> {
    if receipts.is_empty() {
        return Ok(ReportResult {
            verified_count: 0,
            total_uploaded: 0,
            total_downloaded: 0,
        });
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut pk_bytes_list = Vec::with_capacity(receipts.len());
    let mut messages = Vec::with_capacity(receipts.len());
    let mut sig_bytes_list = Vec::with_capacity(receipts.len());
    let mut total_upload_credit: u64 = 0;
    let mut total_download_debit: u64 = 0;

    for (_i, receipt) in receipts.iter().enumerate() {
        // Check epoch window
        let epoch = receipt.t_epoch;
        if epoch > now || now - epoch > receipt_window {
            return Err(ReceiptError::Expired {
                epoch,
                window_start: now.saturating_sub(receipt_window),
                window_end: now,
            });
        }

        // Check double-spend
        let rid = receipt.receipt_id();
        if used_receipts.contains_key(&rid) {
            return Err(ReceiptError::Duplicate(rid));
        }

        // Build message and collect for aggregate verification
        let msg = receipt.message();
        messages.push(msg);
        pk_bytes_list.push(receipt.receiver_pk.clone());
        sig_bytes_list.push(receipt.signature.clone());

        total_upload_credit += receipt.piece_size;
        total_download_debit += receipt.piece_size;
    }

    // Aggregate verify all receipts at once
    let sig_refs: Vec<&[u8]> = sig_bytes_list.iter().map(|s| s.as_slice()).collect();
    let agg_sig = crypto::aggregate_signatures(&sig_refs)?;

    let pk_refs: Vec<&[u8]> = pk_bytes_list.iter().map(|p| p.as_slice()).collect();
    let msg_refs: Vec<&[u8]> = messages.iter().map(|m| m.as_slice()).collect();

    let valid = crypto::aggregate_verify(&pk_refs, &msg_refs, &agg_sig)?;
    if !valid {
        return Err(ReceiptError::AggregateVerificationFailed);
    }

    // Mark all receipts as used
    let now_f64 = now as f64;
    for receipt in receipts {
        used_receipts.insert(receipt.receipt_id(), now_f64);
    }

    Ok(ReportResult {
        verified_count: receipts.len(),
        total_uploaded: total_upload_credit,
        total_downloaded: total_download_debit,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_keypair;
    use sha2::{Digest, Sha256};

    fn make_test_receipt(
        receiver_sk: &[u8],
        receiver_pk: &[u8],
        sender_pk: &[u8],
        piece_index: u32,
    ) -> PBTSReceipt {
        let infohash = [0xABu8; 20];
        let piece_data = format!("piece data {piece_index}");
        let piece_hash: Vec<u8> = Sha256::digest(piece_data.as_bytes()).to_vec();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let sig = attest_piece_transfer(
            receiver_sk,
            sender_pk,
            &piece_hash,
            piece_index,
            &infohash,
            timestamp,
        )
        .unwrap();

        PBTSReceipt {
            infohash: infohash.to_vec(),
            sender_pk: sender_pk.to_vec(),
            receiver_pk: receiver_pk.to_vec(),
            piece_hash,
            piece_index,
            timestamp,
            t_epoch: timestamp,
            signature: sig,
            piece_size: 262144,
        }
    }

    #[test]
    fn test_attest_and_verify() {
        let (sender_sk, sender_pk) = generate_keypair();
        let (receiver_sk, receiver_pk) = generate_keypair();
        let infohash = [0xABu8; 20];
        let piece_hash = Sha256::digest(b"piece data").to_vec();
        let timestamp = 1700000000u64;

        let sig = attest_piece_transfer(
            &receiver_sk,
            &sender_pk,
            &piece_hash,
            0,
            &infohash,
            timestamp,
        )
        .unwrap();

        assert!(
            verify_receipt(&receiver_pk, &sender_pk, &piece_hash, 0, &infohash, timestamp, &sig)
                .unwrap()
        );

        // Wrong sender should fail
        let (_, wrong_pk) = generate_keypair();
        assert!(
            !verify_receipt(&receiver_pk, &wrong_pk, &piece_hash, 0, &infohash, timestamp, &sig)
                .unwrap()
        );
    }

    #[test]
    fn test_process_report() {
        let (sender_sk, sender_pk) = generate_keypair();
        let (receiver_sk, receiver_pk) = generate_keypair();

        let receipts: Vec<PBTSReceipt> = (0..5)
            .map(|i| make_test_receipt(&receiver_sk, &receiver_pk, &sender_pk, i))
            .collect();

        let mut used = HashMap::new();
        let result = process_report(&receipts, &mut used, 3600).unwrap();
        assert_eq!(result.verified_count, 5);
        assert_eq!(used.len(), 5);

        // Double submit should fail
        let err = process_report(&receipts, &mut used, 3600);
        assert!(err.is_err());
    }
}

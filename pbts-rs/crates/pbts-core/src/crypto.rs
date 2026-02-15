use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::RngCore;
use thiserror::Error;

/// Domain Separation Tag for BLS signatures in PBTS.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid secret key bytes")]
    InvalidSecretKey,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("invalid signature bytes")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("aggregate verification failed")]
    AggregateVerificationFailed,
    #[error("blst error: {0:?}")]
    BlstError(BLST_ERROR),
}

/// Generate a BLS12-381 keypair.
/// Returns (secret_key_bytes[32], public_key_bytes[48]).
pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ikm);
    let sk = SecretKey::key_gen(&ikm, &[]).expect("key_gen with 32 bytes should never fail");
    let pk = sk.sk_to_pk();
    (sk.to_bytes().to_vec(), pk.compress().to_vec())
}

/// Sign a message with a BLS secret key.
/// Returns signature bytes (96 bytes compressed).
pub fn sign_message(sk_bytes: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let sk = SecretKey::from_bytes(sk_bytes).map_err(|_| CryptoError::InvalidSecretKey)?;
    let sig = sk.sign(message, DST, &[]);
    Ok(sig.compress().to_vec())
}

/// Verify a BLS signature.
pub fn verify_signature(pk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<bool, CryptoError> {
    let pk = PublicKey::from_bytes(pk_bytes).map_err(|_| CryptoError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(sig_bytes).map_err(|_| CryptoError::InvalidSignature)?;
    let result = sig.verify(true, message, DST, &[], &pk, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

/// Aggregate multiple BLS signatures into one.
/// Returns aggregated signature bytes (96 bytes).
pub fn aggregate_signatures(sig_bytes_list: &[&[u8]]) -> Result<Vec<u8>, CryptoError> {
    if sig_bytes_list.is_empty() {
        return Err(CryptoError::InvalidSignature);
    }

    let sigs: Vec<Signature> = sig_bytes_list
        .iter()
        .map(|b| Signature::from_bytes(b).map_err(|_| CryptoError::InvalidSignature))
        .collect::<Result<Vec<_>, _>>()?;

    let sig_refs: Vec<&Signature> = sigs.iter().collect();
    let agg = AggregateSignature::aggregate(&sig_refs, true)
        .map_err(CryptoError::BlstError)?;
    Ok(agg.to_signature().compress().to_vec())
}

/// Verify an aggregate BLS signature against multiple (pk, msg) pairs.
pub fn aggregate_verify(
    pk_bytes_list: &[&[u8]],
    messages: &[&[u8]],
    agg_sig_bytes: &[u8],
) -> Result<bool, CryptoError> {
    if pk_bytes_list.len() != messages.len() || pk_bytes_list.is_empty() {
        return Err(CryptoError::AggregateVerificationFailed);
    }

    let agg_sig =
        Signature::from_bytes(agg_sig_bytes).map_err(|_| CryptoError::InvalidSignature)?;

    let pks: Vec<PublicKey> = pk_bytes_list
        .iter()
        .map(|b| PublicKey::from_bytes(b).map_err(|_| CryptoError::InvalidPublicKey))
        .collect::<Result<Vec<_>, _>>()?;

    let pk_refs: Vec<&PublicKey> = pks.iter().collect();
    let msgs: Vec<&[u8]> = messages.to_vec();

    let result = agg_sig.aggregate_verify(true, &msgs, DST, &pk_refs, true);
    Ok(result == BLST_ERROR::BLST_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keygen_sign_verify() {
        let (sk, pk) = generate_keypair();
        assert_eq!(sk.len(), 32);
        assert_eq!(pk.len(), 48);

        let msg = b"test message";
        let sig = sign_message(&sk, msg).unwrap();
        assert_eq!(sig.len(), 96);

        assert!(verify_signature(&pk, msg, &sig).unwrap());
        assert!(!verify_signature(&pk, b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_aggregate_sign_verify() {
        let n = 10;
        let mut sks = Vec::new();
        let mut pks = Vec::new();
        let mut msgs: Vec<Vec<u8>> = Vec::new();
        let mut sigs = Vec::new();

        for i in 0..n {
            let (sk, pk) = generate_keypair();
            let msg = format!("message {i}").into_bytes();
            let sig = sign_message(&sk, &msg).unwrap();
            sks.push(sk);
            pks.push(pk);
            msgs.push(msg);
            sigs.push(sig);
        }

        let sig_refs: Vec<&[u8]> = sigs.iter().map(|s| s.as_slice()).collect();
        let agg_sig = aggregate_signatures(&sig_refs).unwrap();
        assert_eq!(agg_sig.len(), 96);

        let pk_refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
        let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        assert!(aggregate_verify(&pk_refs, &msg_refs, &agg_sig).unwrap());
    }
}

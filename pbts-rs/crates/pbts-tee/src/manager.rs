use anyhow::Result;
use blst::min_pk::SecretKey;
use dstack_sdk::dstack_client::DstackClient;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TEEKeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
    pub tee_derived: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AttestationReport {
    pub quote: String,
    pub quote_size_bytes: usize,
    pub payload: String,
}

pub struct TEEManager {
    client: DstackClient,
}

impl TEEManager {
    /// Create a TEE manager connected to the dstack daemon.
    pub async fn new_enabled() -> Result<Self> {
        let client = DstackClient::new(None);
        // Test connectivity by requesting info
        let _info = client.info().await?;
        Ok(Self { client })
    }

    /// Derive a BLS keypair from TEE (deterministic from measurement + path).
    pub async fn generate_keypair_tee(&self) -> Result<TEEKeyPair> {
        let path = format!("pbts/bls/{}", hex::encode(rand::random::<[u8; 16]>()));
        let response = self
            .client
            .get_key(Some(path), Some("signature".to_string()))
            .await?;

        // Decode the key material
        let key_bytes = hex::decode(&response.key)?;
        anyhow::ensure!(
            key_bytes.len() >= 32,
            "dstack key material too short ({} bytes)",
            key_bytes.len()
        );

        // Use blst's key_gen which derives a valid BLS secret key via HKDF
        let sk = SecretKey::key_gen(&key_bytes, &[])
            .map_err(|e| anyhow::anyhow!("BLS key generation failed: {:?}", e))?;
        let pk = sk.sk_to_pk();

        Ok(TEEKeyPair {
            private_key: sk.to_bytes().to_vec(),
            public_key: pk.compress().to_vec(),
            tee_derived: true,
        })
    }

    /// Generate a TEE attestation quote.
    pub async fn generate_attestation(&self, payload: &str) -> Result<AttestationReport> {
        let mut report_data = payload.as_bytes().to_vec();
        if report_data.len() > 64 {
            use sha2::{Digest, Sha256};
            report_data = Sha256::digest(&report_data).to_vec();
        }

        let response = self.client.get_quote(report_data).await?;
        let quote_bytes = hex::decode(&response.quote).unwrap_or_default();

        Ok(AttestationReport {
            quote: response.quote,
            quote_size_bytes: quote_bytes.len(),
            payload: payload.to_string(),
        })
    }

    /// Verify a TEE attestation quote.
    pub async fn verify_attestation(&self, quote: &str, _expected_payload: &str) -> Result<bool> {
        let quote_bytes = hex::decode(quote)?;
        let resp = self.client.verify(
            "tdx_quote",
            quote_bytes,
            vec![],
            vec![],
        ).await?;
        Ok(resp.valid)
    }
}

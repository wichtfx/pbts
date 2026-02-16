use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::Result;
use std::str::FromStr;

// Generate Rust bindings from Solidity ABI using alloy's sol! macro.
sol! {
    #[sol(rpc)]
    contract ReputationFactory {
        event ReputationCreated(address newReputationAddress, address owner, address referrer, bytes attestation);
        function createReputation(address _referrerReputation, bytes calldata _attestation) public returns (address);
    }

    #[sol(rpc)]
    contract Reputation {
        struct UserData {
            string username;
            string salt;
            bytes32 passwordHash;
            uint256 downloadSize;
            uint256 uploadSize;
        }

        function owner() public view returns (address);
        function referrerReputation() public view returns (address);
        function getUserData(string memory _username) public view returns (UserData memory);
        function migrateUserData(string memory _username) public;
        function addUser(string memory _username, string memory _salt, bytes32 _passwordHash, uint256 _downloadSize, uint256 _uploadSize) public;
        function updateUser(string memory _username, uint256 _downloadSize, uint256 _uploadSize) public;
        function setOffchainDataUrl(string memory _offchainDataUrl) public;
        function getOffchainDataUrl() public view returns (string memory);
    }
}

/// Manages interactions with the on-chain reputation smart contracts.
pub struct ContractManager {
    pub rpc_url: String,
    pub factory_address: Address,
    pub reputation_address: Option<Address>,
    pub signer: PrivateKeySigner,
}

/// Gas cost measurement result for a single operation.
#[derive(Debug, Clone, serde::Serialize)]
pub struct GasMeasurement {
    pub operation: String,
    pub gas_used: u64,
    pub tx_hash: String,
}

impl ContractManager {
    pub fn new(rpc_url: &str, private_key: &str, factory_address: &str) -> Result<Self> {
        let signer = PrivateKeySigner::from_str(private_key)?;
        let factory_addr = Address::from_str(factory_address)?;
        Ok(Self {
            rpc_url: rpc_url.to_string(),
            factory_address: factory_addr,
            reputation_address: None,
            signer,
        })
    }

    fn provider(&self) -> impl std::future::Future<Output = Result<impl alloy::providers::Provider>> + '_ {
        async move {
            let provider = ProviderBuilder::new()
                .wallet(alloy::network::EthereumWallet::from(self.signer.clone()))
                .connect_http(self.rpc_url.parse()?);
            Ok(provider)
        }
    }

    /// Deploy a new Reputation contract via the factory.
    pub async fn create_reputation_contract(
        &mut self,
        referrer: Option<Address>,
    ) -> Result<Address> {
        let provider = self.provider().await?;
        let factory = ReputationFactory::new(self.factory_address, &provider);
        let referrer_addr = referrer.unwrap_or(Address::ZERO);
        let call = factory.createReputation(referrer_addr, vec![].into());
        let receipt = call.send().await?.get_receipt().await?;

        // Extract new contract address from event logs
        let log = receipt
            .inner
            .logs()
            .iter()
            .find_map(|log| {
                log.log_decode::<ReputationFactory::ReputationCreated>()
                    .ok()
            })
            .ok_or_else(|| anyhow::anyhow!("ReputationCreated event not found"))?;

        let new_addr = log.inner.data.newReputationAddress;
        self.reputation_address = Some(new_addr);
        Ok(new_addr)
    }

    /// Add a user to the reputation contract.
    pub async fn add_user(
        &self,
        username: &str,
        salt: &str,
        password_hash: FixedBytes<32>,
        download_size: u64,
        upload_size: u64,
    ) -> Result<GasMeasurement> {
        let addr = self
            .reputation_address
            .ok_or_else(|| anyhow::anyhow!("no reputation contract"))?;
        let provider = self.provider().await?;
        let contract = Reputation::new(addr, &provider);
        let call = contract.addUser(
            username.to_string(),
            salt.to_string(),
            password_hash,
            U256::from(download_size),
            U256::from(upload_size),
        );
        let receipt = call.send().await?.get_receipt().await?;
        Ok(GasMeasurement {
            operation: "addUser".to_string(),
            gas_used: receipt.gas_used,
            tx_hash: format!("{:?}", receipt.transaction_hash),
        })
    }

    /// Read user data from the reputation contract.
    pub async fn get_user(&self, username: &str) -> Result<Reputation::UserData> {
        let addr = self
            .reputation_address
            .ok_or_else(|| anyhow::anyhow!("no reputation contract"))?;
        let provider = self.provider().await?;
        let contract = Reputation::new(addr, &provider);
        let data = contract.getUserData(username.to_string()).call().await?;
        Ok(data)
    }

    /// Update user reputation on-chain.
    pub async fn update_user(
        &self,
        username: &str,
        download_size: u64,
        upload_size: u64,
    ) -> Result<GasMeasurement> {
        let addr = self
            .reputation_address
            .ok_or_else(|| anyhow::anyhow!("no reputation contract"))?;
        let provider = self.provider().await?;
        let contract = Reputation::new(addr, &provider);
        let call = contract.updateUser(
            username.to_string(),
            U256::from(download_size),
            U256::from(upload_size),
        );
        let receipt = call.send().await?.get_receipt().await?;
        Ok(GasMeasurement {
            operation: "updateUser".to_string(),
            gas_used: receipt.gas_used,
            tx_hash: format!("{:?}", receipt.transaction_hash),
        })
    }

    /// Migrate user data from referrer contract.
    pub async fn migrate_user_data(&self, username: &str) -> Result<GasMeasurement> {
        let addr = self
            .reputation_address
            .ok_or_else(|| anyhow::anyhow!("no reputation contract"))?;
        let provider = self.provider().await?;
        let contract = Reputation::new(addr, &provider);
        let call = contract.migrateUserData(username.to_string());
        let receipt = call.send().await?.get_receipt().await?;
        Ok(GasMeasurement {
            operation: "migrateUserData".to_string(),
            gas_used: receipt.gas_used,
            tx_hash: format!("{:?}", receipt.transaction_hash),
        })
    }
}

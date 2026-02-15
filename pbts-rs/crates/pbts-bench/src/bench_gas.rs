use alloy::node_bindings::Anvil;
use alloy::primitives::{Address, FixedBytes, U256};
use alloy::providers::ProviderBuilder;
use alloy::signers::local::PrivateKeySigner;
use anyhow::{Context, Result};
use pbts_core::contract::{Reputation, ReputationFactory};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::process::Command;
use std::str::FromStr;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct GasResult {
    pub operation: String,
    pub gas_used: u64,
    pub latency_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct GasBenchmarkResults {
    pub create_reputation: GasResult,
    pub add_user: GasResult,
    pub update_user: GasResult,
    pub migrate_user: GasResult,
    pub batch_add_users: Vec<GasResult>,
    pub batch_update_users: Vec<GasResult>,
    pub annual_cost_projections: Vec<AnnualCostProjection>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnnualCostProjection {
    pub frequency: String,
    pub users: u64,
    pub updates_per_year: u64,
    pub total_gas: u64,
    pub estimated_eth: f64,
    pub estimated_usd: f64,
}

/// Deploy a contract using `forge create` and return its address.
fn forge_deploy(
    rpc_url: &str,
    private_key: &str,
    contract_path: &str,
    constructor_args: &[&str],
    project_root: &str,
) -> Result<Address> {
    let mut cmd = Command::new("forge");
    cmd.arg("create")
        .arg(contract_path)
        .arg("--rpc-url")
        .arg(rpc_url)
        .arg("--private-key")
        .arg(private_key)
        .arg("--root")
        .arg(project_root);

    if !constructor_args.is_empty() {
        cmd.arg("--constructor-args");
        for arg in constructor_args {
            cmd.arg(arg);
        }
    }

    let output = cmd.output().context("Failed to run forge. Is Foundry installed?")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !output.status.success() {
        anyhow::bail!("forge create failed:\n{stderr}\n{stdout}");
    }

    // Parse "Deployed to: 0x..." from output
    for line in stdout.lines().chain(stderr.lines()) {
        if let Some(addr_str) = line.strip_prefix("Deployed to: ") {
            let addr = Address::from_str(addr_str.trim())
                .context("Failed to parse deployed address")?;
            return Ok(addr);
        }
    }

    anyhow::bail!("Could not find deployed address in forge output:\n{stdout}\n{stderr}")
}

pub async fn run_gas_benchmarks(num_users: usize, contract_project: &str) -> Result<GasBenchmarkResults> {
    println!("\n=== Smart Contract Gas Cost Benchmarks ===\n");

    // Check forge availability
    let forge_check = Command::new("forge").arg("--version").output();
    if forge_check.is_err() || !forge_check.unwrap().status.success() {
        anyhow::bail!(
            "Foundry (forge) is required for gas benchmarks.\n\
             Install: curl -L https://foundry.paradigm.xyz | bash && foundryup"
        );
    }

    // Start local Anvil instance
    println!("Starting Anvil...");
    let anvil = Anvil::new().try_spawn()?;
    let rpc_url = anvil.endpoint();
    let signer: PrivateKeySigner = anvil.keys()[0].clone().into();
    let private_key = hex::encode(signer.to_bytes());

    let provider = ProviderBuilder::new()
        .wallet(alloy::network::EthereumWallet::from(signer))
        .connect_http(rpc_url.parse()?);

    // Deploy ReputationFactory via forge
    println!("Deploying ReputationFactory via forge...");
    let factory_addr = forge_deploy(
        &rpc_url,
        &private_key,
        "src/factory.sol:ReputationFactory",
        &[],
        contract_project,
    )?;
    println!("  Factory deployed at: {factory_addr}");
    let factory = ReputationFactory::new(factory_addr, &provider);

    // Create Reputation contract
    println!("Creating Reputation contract...");
    let start = Instant::now();
    let create_call = factory.createReputation(Address::ZERO, vec![].into());
    let receipt = create_call.send().await?.get_receipt().await?;
    let create_time = start.elapsed().as_secs_f64() * 1000.0;
    let create_gas = receipt.gas_used;

    let log = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| {
            log.log_decode::<ReputationFactory::ReputationCreated>()
                .ok()
        })
        .expect("ReputationCreated event");
    let rep_addr = log.inner.data.newReputationAddress;
    let rep_contract = Reputation::new(rep_addr, &provider);
    println!("  Reputation at: {rep_addr}, gas: {create_gas}");

    let create_reputation = GasResult {
        operation: "createReputation".to_string(),
        gas_used: create_gas,
        latency_ms: create_time,
    };

    // Add user
    println!("Adding user...");
    let pw_hash = FixedBytes::<32>::from(Sha256::digest(b"password").as_ref());
    let start = Instant::now();
    let add_receipt = rep_contract
        .addUser(
            "user0".to_string(),
            "salt0".to_string(),
            pw_hash,
            U256::from(0),
            U256::from(1024),
        )
        .send()
        .await?
        .get_receipt()
        .await?;
    let add_time = start.elapsed().as_secs_f64() * 1000.0;
    let add_gas = add_receipt.gas_used;
    println!("  addUser gas: {add_gas}");

    let add_user = GasResult {
        operation: "addUser".to_string(),
        gas_used: add_gas,
        latency_ms: add_time,
    };

    // Update user
    println!("Updating user...");
    let start = Instant::now();
    let update_receipt = rep_contract
        .updateUser("user0".to_string(), U256::from(1024), U256::from(2048))
        .send()
        .await?
        .get_receipt()
        .await?;
    let update_time = start.elapsed().as_secs_f64() * 1000.0;
    let update_gas = update_receipt.gas_used;
    println!("  updateUser gas: {update_gas}");

    let update_user = GasResult {
        operation: "updateUser".to_string(),
        gas_used: update_gas,
        latency_ms: update_time,
    };

    // Migrate user (create second contract with referrer)
    println!("Testing migration...");
    let create2_receipt = factory
        .createReputation(rep_addr, vec![].into())
        .send()
        .await?
        .get_receipt()
        .await?;
    let log2 = create2_receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| {
            log.log_decode::<ReputationFactory::ReputationCreated>()
                .ok()
        })
        .expect("ReputationCreated event");
    let rep2_addr = log2.inner.data.newReputationAddress;
    let rep2 = Reputation::new(rep2_addr, &provider);

    let start = Instant::now();
    let migrate_receipt = rep2
        .migrateUserData("user0".to_string())
        .send()
        .await?
        .get_receipt()
        .await?;
    let migrate_time = start.elapsed().as_secs_f64() * 1000.0;
    let migrate_gas = migrate_receipt.gas_used;
    println!("  migrateUserData gas: {migrate_gas}");

    let migrate_user = GasResult {
        operation: "migrateUserData".to_string(),
        gas_used: migrate_gas,
        latency_ms: migrate_time,
    };

    // Batch add users
    println!("\nBatch operations ({num_users} users)...");
    let mut batch_add = Vec::new();
    let mut batch_update = Vec::new();

    for i in 1..=num_users {
        let username = format!("batchuser{i}");
        let ph = FixedBytes::<32>::from(Sha256::digest(username.as_bytes()).as_ref());

        let start = Instant::now();
        let r = rep_contract
            .addUser(
                username.clone(),
                format!("salt{i}"),
                ph,
                U256::from(0),
                U256::from(1024 * i as u64),
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        let t = start.elapsed().as_secs_f64() * 1000.0;
        batch_add.push(GasResult {
            operation: format!("addUser[{i}]"),
            gas_used: r.gas_used,
            latency_ms: t,
        });

        let start = Instant::now();
        let r = rep_contract
            .updateUser(
                username,
                U256::from(512 * i as u64),
                U256::from(2048 * i as u64),
            )
            .send()
            .await?
            .get_receipt()
            .await?;
        let t = start.elapsed().as_secs_f64() * 1000.0;
        batch_update.push(GasResult {
            operation: format!("updateUser[{i}]"),
            gas_used: r.gas_used,
            latency_ms: t,
        });

        if i % 20 == 0 {
            println!("  Processed {i}/{num_users} users...");
        }
    }

    let avg_add_gas = batch_add.iter().map(|g| g.gas_used).sum::<u64>() / batch_add.len() as u64;
    let avg_update_gas =
        batch_update.iter().map(|g| g.gas_used).sum::<u64>() / batch_update.len() as u64;
    let avg_add_ms =
        batch_add.iter().map(|g| g.latency_ms).sum::<f64>() / batch_add.len() as f64;
    let avg_update_ms =
        batch_update.iter().map(|g| g.latency_ms).sum::<f64>() / batch_update.len() as f64;

    println!("\n  Avg addUser:    gas={avg_add_gas}, latency={avg_add_ms:.2} ms");
    println!("  Avg updateUser: gas={avg_update_gas}, latency={avg_update_ms:.2} ms");

    // Annual cost projections (30 gwei gas price, $3000/ETH reference)
    let gas_price_gwei = 30.0;
    let eth_price_usd = 3000.0;
    let gas_to_eth = |gas: u64| -> f64 { gas as f64 * gas_price_gwei * 1e-9 };
    let gas_to_usd = |gas: u64| -> f64 { gas_to_eth(gas) * eth_price_usd };

    let mut projections = Vec::new();
    for (freq_name, updates_per_year_per_user) in [
        ("per-transfer (10/day)", 3650u64),
        ("hourly", 8760),
        ("daily", 365),
        ("weekly", 52),
    ] {
        for user_count in [100u64, 1000, 10000] {
            let total_updates = updates_per_year_per_user * user_count;
            let total_gas = total_updates * avg_update_gas;
            projections.push(AnnualCostProjection {
                frequency: freq_name.to_string(),
                users: user_count,
                updates_per_year: total_updates,
                total_gas,
                estimated_eth: gas_to_eth(total_gas),
                estimated_usd: gas_to_usd(total_gas),
            });
        }
    }

    println!("\n  Annual Cost Projections (30 gwei, $3000/ETH):");
    println!(
        "  {:>25} {:>8} {:>14} {:>12} {:>12}",
        "Frequency", "Users", "Updates/yr", "ETH", "USD"
    );
    for p in &projections {
        println!(
            "  {:>25} {:>8} {:>14} {:>12.4} ${:>10.2}",
            p.frequency, p.users, p.updates_per_year, p.estimated_eth, p.estimated_usd
        );
    }

    Ok(GasBenchmarkResults {
        create_reputation,
        add_user,
        update_user,
        migrate_user,
        batch_add_users: batch_add,
        batch_update_users: batch_update,
        annual_cost_projections: projections,
    })
}

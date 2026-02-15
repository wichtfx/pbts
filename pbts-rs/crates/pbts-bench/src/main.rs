use clap::{Parser, Subcommand};
use std::path::PathBuf;

mod bench_receipts;
mod bench_download;
mod bench_gas;
mod bench_tee;
mod bench_scale;

#[derive(Parser)]
#[command(name = "pbts-bench", about = "PBTS Benchmark Suite")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run BLS receipt operation benchmarks
    Receipts {
        #[arg(long, default_value_t = 1000)]
        iterations: usize,
        #[arg(long, value_delimiter = ',', default_values_t = vec![10, 25, 50, 100, 500])]
        batch_sizes: Vec<usize>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run client download simulation
    Download {
        #[arg(long, value_delimiter = ',', default_values_t = vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0])]
        speeds: Vec<f64>,
        #[arg(long, value_delimiter = ',', default_values_t = vec![256, 512, 1024, 2048])]
        pieces: Vec<u32>,
        #[arg(long, default_value_t = 100.0)]
        file_size_mb: f64,
        #[arg(long, default_value_t = 10)]
        warmup: usize,
        #[arg(long, default_value_t = 100)]
        iterations: usize,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run TEE overhead benchmarks
    Tee {
        #[arg(long, default_value_t = 100)]
        iterations: usize,
        #[arg(long, default_value_t = 5)]
        verify_iterations: usize,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run smart contract gas cost benchmarks
    Gas {
        #[arg(long, default_value_t = 100)]
        users: usize,
        /// Path to the Foundry smartcontract project directory
        #[arg(long, default_value = "../smartcontract")]
        contract_project: String,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run scalability benchmarks (concurrent peers + swarm scale)
    Scalability {
        #[arg(long, value_delimiter = ',', default_values_t = vec![10, 50, 100, 200, 500])]
        peers: Vec<usize>,
        #[arg(long, value_delimiter = ',', default_values_t = vec![100, 1000, 5000, 10000])]
        swarm_sizes: Vec<usize>,
        #[arg(long, default_value_t = 10)]
        receipts_per_report: usize,
        #[arg(long, default_value_t = 100)]
        announce_iterations: usize,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Run all benchmarks
    All {
        #[arg(long)]
        output: Option<PathBuf>,
        #[arg(long)]
        skip_tee: bool,
        #[arg(long)]
        skip_gas: bool,
    },
}

fn save_json(path: &PathBuf, value: &impl serde::Serialize) {
    let json = serde_json::to_string_pretty(value).unwrap();
    std::fs::create_dir_all(path.parent().unwrap_or(&PathBuf::from("."))).ok();
    std::fs::write(path, json).unwrap();
    println!("\nResults saved to {}", path.display());
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Receipts {
            iterations,
            batch_sizes,
            output,
        } => {
            let results = bench_receipts::run_receipt_benchmarks(iterations, &batch_sizes);
            bench_receipts::print_results(&results);
            if let Some(path) = output {
                save_json(&path, &results);
            }
        }
        Commands::Download {
            speeds,
            pieces,
            file_size_mb,
            warmup,
            iterations,
            output,
        } => {
            let results = bench_download::run_download_benchmarks(
                &speeds,
                &pieces,
                file_size_mb,
                warmup,
                iterations,
            );
            if let Some(path) = output {
                save_json(&path, &results);
            }
        }
        Commands::Tee {
            iterations,
            verify_iterations,
            output,
        } => {
            // Try to detect TEE availability
            let tee_available = check_tee_available().await;
            let results =
                bench_tee::run_tee_benchmarks(iterations, verify_iterations, tee_available).await;
            if let Some(path) = output {
                save_json(&path, &results);
            }
        }
        Commands::Gas { users, contract_project, output } => {
            let results = bench_gas::run_gas_benchmarks(users, &contract_project).await?;
            if let Some(path) = output {
                save_json(&path, &results);
            }
        }
        Commands::Scalability {
            peers,
            swarm_sizes,
            receipts_per_report,
            announce_iterations,
            output,
        } => {
            let results = bench_scale::run_scalability_benchmarks(
                &peers,
                &swarm_sizes,
                receipts_per_report,
                announce_iterations,
            )
            .await;
            if let Some(path) = output {
                save_json(&path, &results);
            }
        }
        Commands::All {
            output,
            skip_tee,
            skip_gas,
        } => {
            let out_dir = output.unwrap_or_else(|| PathBuf::from("/tmp/pbts_results"));
            std::fs::create_dir_all(&out_dir)?;

            println!("=== PBTS Complete Benchmark Suite ===");
            println!("Output: {}\n", out_dir.display());

            // 1. Receipts
            let receipts =
                bench_receipts::run_receipt_benchmarks(1000, &[10, 25, 50, 100, 500]);
            bench_receipts::print_results(&receipts);
            save_json(&out_dir.join("receipts.json"), &receipts);

            // 2. Download simulation
            let download = bench_download::run_download_benchmarks(
                &[1.0, 5.0, 10.0, 25.0, 50.0, 100.0],
                &[256, 512, 1024, 2048],
                100.0,
                10,
                100,
            );
            save_json(&out_dir.join("client_download.json"), &download);

            // 3. TEE (optional)
            if !skip_tee {
                let tee_available = check_tee_available().await;
                let tee = bench_tee::run_tee_benchmarks(100, 5, tee_available).await;
                save_json(&out_dir.join("tee.json"), &tee);
            }

            // 4. Gas (optional)
            if !skip_gas {
                match bench_gas::run_gas_benchmarks(100, "../smartcontract").await {
                    Ok(gas) => save_json(&out_dir.join("gas.json"), &gas),
                    Err(e) => println!("Gas benchmark failed (Anvil not available?): {e}"),
                }
            }

            // 5. Scalability
            let scale = bench_scale::run_scalability_benchmarks(
                &[10, 50, 100, 200, 500],
                &[100, 1000, 5000, 10000],
                10,
                100,
            )
            .await;
            save_json(&out_dir.join("scalability.json"), &scale);

            // Save combined results
            let combined = serde_json::json!({
                "receipts": receipts,
                "client_download": download,
                "scalability": scale,
            });
            save_json(&out_dir.join("all_results.json"), &combined);

            println!("\n=== ALL BENCHMARKS COMPLETE ===");
            println!("Results in: {}", out_dir.display());
        }
    }

    Ok(())
}

async fn check_tee_available() -> bool {
    match pbts_tee::manager::TEEManager::new_enabled().await {
        Ok(_) => {
            println!("TEE: available (dstack-sdk connected)");
            true
        }
        Err(_) => {
            println!("TEE: not available (running without TEE)");
            false
        }
    }
}

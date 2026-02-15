use pbts_core::crypto;
use serde::Serialize;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct TimingStats {
    pub mean_ms: f64,
    pub median_ms: f64,
    pub stdev_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
}

fn compute_stats(timings: &[f64]) -> TimingStats {
    let n = timings.len() as f64;
    let mean = timings.iter().sum::<f64>() / n;
    let mut sorted = timings.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = sorted[sorted.len() / 2];
    let variance: f64 = timings.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / n;
    TimingStats {
        mean_ms: mean,
        median_ms: median,
        stdev_ms: variance.sqrt(),
        min_ms: sorted[0],
        max_ms: *sorted.last().unwrap(),
    }
}

#[derive(Debug, Serialize)]
pub struct TEEBenchmarkResults {
    pub key_generation: KeyGenResults,
    pub attestation_generation: Option<AttestationGenResults>,
    pub attestation_verification: Option<AttestationVerifyResults>,
}

#[derive(Debug, Serialize)]
pub struct KeyGenResults {
    pub regular: TimingStats,
    pub tee: Option<TimingStats>,
    pub overhead_ms: Option<f64>,
    pub overhead_percent: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct AttestationGenResults {
    pub stats: TimingStats,
    pub quote_size_bytes: usize,
}

#[derive(Debug, Serialize)]
pub struct AttestationVerifyResults {
    pub stats: TimingStats,
    pub success_rate: f64,
}

/// Run TEE benchmarks.
/// `tee_available`: if true, attempt dstack-sdk operations.
pub async fn run_tee_benchmarks(
    iterations: usize,
    verify_iterations: usize,
    tee_available: bool,
) -> TEEBenchmarkResults {
    println!("\n=== TEE Benchmarks ===\n");

    // 1. Regular key generation (always available)
    println!("1. Regular BLS key generation ({iterations} iterations)...");
    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = crypto::generate_keypair();
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let regular_stats = compute_stats(&timings);
    println!("   Mean: {:.4} ms", regular_stats.mean_ms);

    // 2. TEE key generation (if available)
    let mut tee_stats = None;
    let mut overhead_ms = None;
    let mut overhead_percent = None;

    if tee_available {
        println!("2. TEE key generation ({iterations} iterations)...");
        match run_tee_keygen(iterations).await {
            Ok(stats) => {
                let oh = stats.mean_ms - regular_stats.mean_ms;
                let pct = (oh / regular_stats.mean_ms) * 100.0;
                println!("   Mean: {:.4} ms (overhead: +{:.4} ms, {:.1}%)", stats.mean_ms, oh, pct);
                overhead_ms = Some(oh);
                overhead_percent = Some(pct);
                tee_stats = Some(stats);
            }
            Err(e) => {
                println!("   TEE key generation failed: {e}");
            }
        }
    } else {
        println!("2. TEE key generation: SKIPPED (dstack-sdk not available)");
    }

    // 3. Attestation generation
    let mut attestation_gen = None;
    if tee_available {
        println!("3. Attestation generation ({iterations} iterations)...");
        match run_attestation_gen(iterations).await {
            Ok(results) => {
                println!(
                    "   Mean: {:.2} ms, quote size: {} bytes",
                    results.stats.mean_ms, results.quote_size_bytes
                );
                attestation_gen = Some(results);
            }
            Err(e) => {
                println!("   Attestation generation failed: {e}");
            }
        }
    } else {
        println!("3. Attestation generation: SKIPPED");
    }

    // 4. Attestation verification
    let mut attestation_verify = None;
    if tee_available && verify_iterations > 0 {
        println!("4. Attestation verification ({verify_iterations} iterations, SLOW)...");
        match run_attestation_verify(verify_iterations).await {
            Ok(results) => {
                println!(
                    "   Mean: {:.2} ms, success rate: {:.1}%",
                    results.stats.mean_ms,
                    results.success_rate * 100.0
                );
                attestation_verify = Some(results);
            }
            Err(e) => {
                println!("   Attestation verification failed: {e}");
            }
        }
    } else {
        println!("4. Attestation verification: SKIPPED");
    }

    TEEBenchmarkResults {
        key_generation: KeyGenResults {
            regular: regular_stats,
            tee: tee_stats,
            overhead_ms,
            overhead_percent,
        },
        attestation_generation: attestation_gen,
        attestation_verification: attestation_verify,
    }
}

async fn run_tee_keygen(iterations: usize) -> anyhow::Result<TimingStats> {
    use pbts_tee::manager::TEEManager;
    let manager = TEEManager::new_enabled().await?;

    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = manager.generate_keypair_tee().await?;
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    Ok(compute_stats(&timings))
}

async fn run_attestation_gen(iterations: usize) -> anyhow::Result<AttestationGenResults> {
    use pbts_tee::manager::TEEManager;
    let manager = TEEManager::new_enabled().await?;

    let mut timings = Vec::with_capacity(iterations);
    let mut quote_size = 0usize;
    for i in 0..iterations {
        let payload = format!("bench-attestation-{i}");
        let start = Instant::now();
        let report = manager.generate_attestation(&payload).await?;
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
        quote_size = report.quote_size_bytes;
    }
    Ok(AttestationGenResults {
        stats: compute_stats(&timings),
        quote_size_bytes: quote_size,
    })
}

async fn run_attestation_verify(iterations: usize) -> anyhow::Result<AttestationVerifyResults> {
    use pbts_tee::manager::TEEManager;
    let manager = TEEManager::new_enabled().await?;

    // Generate one attestation to verify repeatedly
    let report = manager.generate_attestation("verify-bench").await?;

    let mut timings = Vec::with_capacity(iterations);
    let mut successes = 0u32;
    for _ in 0..iterations {
        let start = Instant::now();
        let valid = manager
            .verify_attestation(&report.quote, "verify-bench")
            .await
            .unwrap_or(false);
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
        if valid {
            successes += 1;
        }
    }
    Ok(AttestationVerifyResults {
        stats: compute_stats(&timings),
        success_rate: successes as f64 / iterations as f64,
    })
}

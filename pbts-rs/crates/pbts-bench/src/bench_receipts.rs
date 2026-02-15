use pbts_core::crypto;
use pbts_core::receipt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct TimingStats {
    pub mean_ms: f64,
    pub median_ms: f64,
    pub stdev_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub total_ms: f64,
    pub iterations: usize,
}

fn compute_stats(timings: &[f64]) -> TimingStats {
    let n = timings.len() as f64;
    let total: f64 = timings.iter().sum();
    let mean = total / n;
    let mut sorted = timings.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let median = if sorted.len() % 2 == 0 {
        (sorted[sorted.len() / 2 - 1] + sorted[sorted.len() / 2]) / 2.0
    } else {
        sorted[sorted.len() / 2]
    };
    let variance: f64 = timings.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / n;
    let stdev = variance.sqrt();
    TimingStats {
        mean_ms: mean,
        median_ms: median,
        stdev_ms: stdev,
        min_ms: sorted[0],
        max_ms: *sorted.last().unwrap(),
        total_ms: total,
        iterations: timings.len(),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AggregateVerifyStats {
    pub aggregate_mean_ms: f64,
    pub aggregate_median_ms: f64,
    pub aggregate_stdev_ms: f64,
    pub individual_mean_ms: f64,
    pub speedup: f64,
    pub num_runs: usize,
}

#[derive(Debug, Serialize)]
pub struct ReceiptBenchmarkResults {
    pub keypair_generation: TimingStats,
    pub receipt_creation: TimingStats,
    pub receipt_verification: TimingStats,
    pub aggregate_verification: HashMap<String, AggregateVerifyStats>,
}

pub fn run_receipt_benchmarks(
    iterations: usize,
    batch_sizes: &[usize],
) -> ReceiptBenchmarkResults {
    println!("\n=== Receipt Benchmarks (blst BLS12-381) ===\n");

    // 1. Keypair generation
    println!("1. Benchmarking keypair generation ({iterations} iterations)...");
    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let _ = crypto::generate_keypair();
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let keypair_stats = compute_stats(&timings);
    println!("   Mean: {:.4} ms, Median: {:.4} ms", keypair_stats.mean_ms, keypair_stats.median_ms);

    // 2. Receipt creation (signing)
    println!("2. Benchmarking receipt creation ({iterations} iterations)...");
    let (_sender_sk, sender_pk) = crypto::generate_keypair();
    let (receiver_sk, receiver_pk) = crypto::generate_keypair();
    let infohash = [0xABu8; 20];
    let piece_hash: Vec<u8> = Sha256::digest(b"benchmark piece data").to_vec();

    let mut timings = Vec::with_capacity(iterations);
    for i in 0..iterations {
        let start = Instant::now();
        let _ = receipt::attest_piece_transfer(
            &receiver_sk,
            &sender_pk,
            &piece_hash,
            i as u32,
            &infohash,
            1700000000 + i as u64,
        )
        .unwrap();
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
    }
    let creation_stats = compute_stats(&timings);
    println!("   Mean: {:.4} ms, Median: {:.4} ms", creation_stats.mean_ms, creation_stats.median_ms);

    // 3. Receipt verification
    println!("3. Benchmarking receipt verification ({iterations} iterations)...");
    let sig = receipt::attest_piece_transfer(
        &receiver_sk,
        &sender_pk,
        &piece_hash,
        0,
        &infohash,
        1700000000,
    )
    .unwrap();

    let mut timings = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let start = Instant::now();
        let valid = receipt::verify_receipt(
            &receiver_pk,
            &sender_pk,
            &piece_hash,
            0,
            &infohash,
            1700000000,
            &sig,
        )
        .unwrap();
        timings.push(start.elapsed().as_secs_f64() * 1000.0);
        assert!(valid);
    }
    let verify_stats = compute_stats(&timings);
    println!("   Mean: {:.4} ms, Median: {:.4} ms", verify_stats.mean_ms, verify_stats.median_ms);

    // 4. Aggregate verification
    println!("4. Benchmarking aggregate verification...");
    let mut agg_results = HashMap::new();

    for &batch_size in batch_sizes {
        println!("   Batch size = {batch_size}...");

        // Create receipts from different receivers (realistic scenario)
        let mut pks = Vec::with_capacity(batch_size);
        let mut msgs = Vec::with_capacity(batch_size);
        let mut sigs = Vec::with_capacity(batch_size);

        for i in 0..batch_size {
            let (rx_sk, rx_pk) = crypto::generate_keypair();
            let ph: Vec<u8> = Sha256::digest(format!("piece {i}").as_bytes()).to_vec();
            let ts = 1700000000u64 + i as u64;
            let msg = receipt::build_receipt_message(&infohash, &sender_pk, &ph, i as u32, ts);
            let sig = crypto::sign_message(&rx_sk, &msg).unwrap();
            pks.push(rx_pk);
            msgs.push(msg);
            sigs.push(sig);
        }

        // Aggregate
        let sig_refs: Vec<&[u8]> = sigs.iter().map(|s| s.as_slice()).collect();
        let agg_sig = crypto::aggregate_signatures(&sig_refs).unwrap();

        // Benchmark aggregate verify
        let num_runs = (100usize).max(1000 / batch_size).min(500);
        let mut agg_timings = Vec::with_capacity(num_runs);
        for _ in 0..num_runs {
            let pk_refs: Vec<&[u8]> = pks.iter().map(|p| p.as_slice()).collect();
            let msg_refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
            let start = Instant::now();
            let valid = crypto::aggregate_verify(&pk_refs, &msg_refs, &agg_sig).unwrap();
            agg_timings.push(start.elapsed().as_secs_f64() * 1000.0);
            assert!(valid);
        }
        let agg_stats = compute_stats(&agg_timings);

        // Benchmark individual verify for comparison
        let ind_runs = num_runs.min(50);
        let mut ind_timings = Vec::with_capacity(ind_runs);
        for _ in 0..ind_runs {
            let start = Instant::now();
            for j in 0..batch_size {
                let valid =
                    crypto::verify_signature(&pks[j], &msgs[j], &sigs[j]).unwrap();
                assert!(valid);
            }
            ind_timings.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        let ind_stats = compute_stats(&ind_timings);

        let speedup = ind_stats.mean_ms / agg_stats.mean_ms;
        println!(
            "   Aggregate: {:.2} ms, Individual: {:.2} ms, Speedup: {:.2}x",
            agg_stats.mean_ms, ind_stats.mean_ms, speedup
        );

        agg_results.insert(
            batch_size.to_string(),
            AggregateVerifyStats {
                aggregate_mean_ms: agg_stats.mean_ms,
                aggregate_median_ms: agg_stats.median_ms,
                aggregate_stdev_ms: agg_stats.stdev_ms,
                individual_mean_ms: ind_stats.mean_ms,
                speedup,
                num_runs,
            },
        );
    }

    ReceiptBenchmarkResults {
        keypair_generation: keypair_stats,
        receipt_creation: creation_stats,
        receipt_verification: verify_stats,
        aggregate_verification: agg_results,
    }
}

pub fn print_results(results: &ReceiptBenchmarkResults) {
    println!("\n=== RECEIPT BENCHMARK RESULTS ===");
    println!("\nKeypair Generation:  {:.4} ms (mean)", results.keypair_generation.mean_ms);
    println!("Receipt Creation:    {:.4} ms (mean)", results.receipt_creation.mean_ms);
    println!("Receipt Verification:{:.4} ms (mean)", results.receipt_verification.mean_ms);
    println!("\nAggregate Verification:");
    let mut batch_sizes: Vec<&String> = results.aggregate_verification.keys().collect();
    batch_sizes.sort_by_key(|k| k.parse::<usize>().unwrap_or(0));
    for bs in batch_sizes {
        let s = &results.aggregate_verification[bs];
        println!(
            "  {bs:>5} receipts: agg={:.2}ms, ind={:.2}ms, speedup={:.2}x",
            s.aggregate_mean_ms, s.individual_mean_ms, s.speedup
        );
    }
}

use pbts_core::crypto;
use pbts_core::receipt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::time::Instant;

#[derive(Debug, Clone, Serialize)]
pub struct DownloadScenario {
    pub download_speed_mbps: f64,
    pub piece_size_kb: u32,
    pub num_pieces: u32,
    pub batch_size: u32,
}

impl DownloadScenario {
    pub fn total_size_mb(&self) -> f64 {
        (self.piece_size_kb as f64 * self.num_pieces as f64) / 1024.0
    }

    pub fn download_time_per_piece_ms(&self) -> f64 {
        (self.piece_size_kb as f64 / 1024.0) / self.download_speed_mbps * 1000.0
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DownloadBenchmarkResult {
    pub scenario: DownloadScenario,
    pub mean_receipt_time_ms: f64,
    pub median_receipt_time_ms: f64,
    pub stdev_receipt_time_ms: f64,
    pub total_download_time_sec: f64,
    pub total_receipt_gen_time_sec: f64,
    pub total_overhead_percent: f64,
    pub baseline_throughput_mbps: f64,
    pub actual_throughput_mbps: f64,
    pub throughput_reduction_percent: f64,
    pub baseline_total_time_sec: f64,
    pub actual_total_time_sec: f64,
    pub total_overhead_sec: f64,
}

#[derive(Debug, Serialize)]
pub struct ClientDownloadResults {
    pub scenarios: Vec<DownloadBenchmarkResult>,
}

pub fn run_download_benchmarks(
    speeds: &[f64],
    piece_sizes_kb: &[u32],
    file_size_mb: f64,
    warmup_iterations: usize,
    measure_iterations: usize,
) -> ClientDownloadResults {
    println!("\n=== Client Download Simulation ===\n");

    // First, measure receipt generation time
    let (_sender_sk, sender_pk) = crypto::generate_keypair();
    let (receiver_sk, _receiver_pk) = crypto::generate_keypair();
    let infohash = [0xABu8; 20];
    let piece_hash: Vec<u8> = Sha256::digest(b"benchmark piece").to_vec();

    // Warmup
    println!("Warming up ({warmup_iterations} iterations)...");
    for i in 0..warmup_iterations {
        let _ = receipt::attest_piece_transfer(
            &receiver_sk,
            &sender_pk,
            &piece_hash,
            i as u32,
            &infohash,
            1700000000 + i as u64,
        );
    }

    // Measure receipt generation time
    println!("Measuring receipt generation ({measure_iterations} iterations)...");
    let mut timings = Vec::with_capacity(measure_iterations);
    for i in 0..measure_iterations {
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

    timings.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mean = timings.iter().sum::<f64>() / timings.len() as f64;
    let median = timings[timings.len() / 2];
    let variance: f64 = timings.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / timings.len() as f64;
    let stdev = variance.sqrt();

    println!("Receipt generation: mean={mean:.4} ms, median={median:.4} ms, stdev={stdev:.4} ms\n");

    // Simulate scenarios
    let mut results = Vec::new();
    println!(
        "{:>8} {:>10} {:>12} {:>12} {:>12}",
        "Speed", "Piece Size", "Receipt (ms)", "Overhead %", "Throughput -%"
    );
    println!("{}", "-".repeat(60));

    for &speed in speeds {
        for &piece_size_kb in piece_sizes_kb {
            let num_pieces = ((file_size_mb * 1024.0) / piece_size_kb as f64).ceil() as u32;
            let scenario = DownloadScenario {
                download_speed_mbps: speed,
                piece_size_kb,
                num_pieces,
                batch_size: 1,
            };

            let total_size_mb = scenario.total_size_mb();
            let total_download_time_sec = total_size_mb / speed;
            let num_receipts = num_pieces; // batch_size = 1
            let total_receipt_gen_time_sec = (mean / 1000.0) * num_receipts as f64;
            let total_overhead_percent =
                (total_receipt_gen_time_sec / total_download_time_sec) * 100.0;

            let baseline_throughput = speed;
            let actual_total = total_download_time_sec + total_receipt_gen_time_sec;
            let actual_throughput = total_size_mb / actual_total;
            let throughput_reduction =
                ((baseline_throughput - actual_throughput) / baseline_throughput) * 100.0;

            println!(
                "{speed:>7.0} {:>9} KB {:>11.4} {:>11.2}% {:>11.2}%",
                piece_size_kb, mean, total_overhead_percent, throughput_reduction
            );

            results.push(DownloadBenchmarkResult {
                scenario,
                mean_receipt_time_ms: mean,
                median_receipt_time_ms: median,
                stdev_receipt_time_ms: stdev,
                total_download_time_sec,
                total_receipt_gen_time_sec,
                total_overhead_percent,
                baseline_throughput_mbps: baseline_throughput,
                actual_throughput_mbps: actual_throughput,
                throughput_reduction_percent: throughput_reduction,
                baseline_total_time_sec: total_download_time_sec,
                actual_total_time_sec: actual_total,
                total_overhead_sec: total_receipt_gen_time_sec,
            });
        }
    }

    // Print key insights
    if let Some(best) = results.iter().min_by(|a, b| {
        a.total_overhead_percent
            .partial_cmp(&b.total_overhead_percent)
            .unwrap()
    }) {
        println!("\nBest case: {:.0} MB/s, {} KB pieces → {:.2}% overhead, {:.2}% throughput reduction",
            best.scenario.download_speed_mbps, best.scenario.piece_size_kb,
            best.total_overhead_percent, best.throughput_reduction_percent);
    }
    if let Some(worst) = results.iter().max_by(|a, b| {
        a.total_overhead_percent
            .partial_cmp(&b.total_overhead_percent)
            .unwrap()
    }) {
        println!("Worst case: {:.0} MB/s, {} KB pieces → {:.2}% overhead, {:.2}% throughput reduction",
            worst.scenario.download_speed_mbps, worst.scenario.piece_size_kb,
            worst.total_overhead_percent, worst.throughput_reduction_percent);
    }

    ClientDownloadResults { scenarios: results }
}

use pbts_core::crypto;
use pbts_core::receipt;
use pbts_core::types::{PBTSReceipt, TrackerConfig, TrackerState};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize)]
pub struct ConcurrencyResult {
    pub num_peers: usize,
    pub receipts_per_report: usize,
    pub total_reports: usize,
    pub total_time_sec: f64,
    pub throughput_reports_per_sec: f64,
    pub mean_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub min_latency_ms: f64,
    pub max_latency_ms: f64,
    pub success_rate: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SwarmScaleResult {
    pub swarm_size: usize,
    pub announce_mean_ms: f64,
    pub announce_p95_ms: f64,
    pub report_mean_ms: f64,
    pub report_p95_ms: f64,
}

#[derive(Debug, Serialize)]
pub struct ScalabilityResults {
    pub concurrency: Vec<ConcurrencyResult>,
    pub swarm_scale: Vec<SwarmScaleResult>,
}

fn percentile(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((p / 100.0) * (sorted.len() - 1) as f64).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Generate pre-built receipts for a peer reporting to the tracker.
fn generate_test_receipts(
    sender_pk: &[u8],
    count: usize,
    base_timestamp: u64,
) -> Vec<(PBTSReceipt, Vec<u8>, Vec<u8>)> {
    let infohash = [0xABu8; 20];
    let mut results = Vec::with_capacity(count);
    for i in 0..count {
        let (rx_sk, rx_pk) = crypto::generate_keypair();
        let piece_hash: Vec<u8> = Sha256::digest(format!("piece-{i}").as_bytes()).to_vec();
        let ts = base_timestamp + i as u64;
        let sig = receipt::attest_piece_transfer(
            &rx_sk,
            sender_pk,
            &piece_hash,
            i as u32,
            &infohash,
            ts,
        )
        .unwrap();

        let r = PBTSReceipt {
            infohash: infohash.to_vec(),
            sender_pk: sender_pk.to_vec(),
            receiver_pk: rx_pk.clone(),
            piece_hash,
            piece_index: i as u32,
            timestamp: ts,
            t_epoch: ts,
            signature: sig,
            piece_size: 262144,
        };
        results.push((r, rx_pk, rx_sk));
    }
    results
}

/// Concurrent report processing benchmark.
/// Simulates N peers each submitting reports with M receipts in parallel.
pub async fn run_concurrency_benchmark(
    peer_counts: &[usize],
    receipts_per_report: usize,
) -> Vec<ConcurrencyResult> {
    println!("\n=== Scalability: Concurrent Report Processing ===\n");
    println!(
        "{:>8} {:>10} {:>12} {:>12} {:>10} {:>10} {:>10}",
        "Peers", "Reports", "Throughput", "Mean (ms)", "P50", "P95", "P99"
    );
    println!("{}", "-".repeat(75));

    let mut results = Vec::new();

    for &num_peers in peer_counts {
        let state = Arc::new(RwLock::new(TrackerState::new(TrackerConfig {
            verify_signatures: true,
            receipt_window: 7200,
            ..TrackerConfig::default()
        })));

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Pre-generate all receipts for each peer
        let mut peer_data = Vec::with_capacity(num_peers);
        for p in 0..num_peers {
            let (_sk, pk) = crypto::generate_keypair();
            let base_ts = now - 100 + p as u64 * 1000;
            let test_receipts = generate_test_receipts(&pk, receipts_per_report, base_ts);
            let receipts: Vec<PBTSReceipt> = test_receipts.into_iter().map(|(r, _, _)| r).collect();
            peer_data.push(receipts);
        }

        // Launch all peers concurrently
        let total_start = Instant::now();
        let mut handles = Vec::with_capacity(num_peers);

        for receipts in peer_data {
            let state_clone = state.clone();
            handles.push(tokio::spawn(async move {
                let start = Instant::now();
                let mut s = state_clone.write().await;
                let window = s.config.receipt_window;
                let result = receipt::process_report(
                    &receipts,
                    &mut s.used_receipts,
                    window,
                );
                let latency = start.elapsed().as_secs_f64() * 1000.0;
                (result.is_ok(), latency)
            }));
        }

        let mut latencies = Vec::with_capacity(num_peers);
        let mut successes = 0usize;
        for h in handles {
            let (ok, lat) = h.await.unwrap();
            if ok {
                successes += 1;
            }
            latencies.push(lat);
        }
        let total_time = total_start.elapsed().as_secs_f64();

        latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mean = latencies.iter().sum::<f64>() / latencies.len() as f64;

        let result = ConcurrencyResult {
            num_peers,
            receipts_per_report,
            total_reports: num_peers,
            total_time_sec: total_time,
            throughput_reports_per_sec: num_peers as f64 / total_time,
            mean_latency_ms: mean,
            p50_latency_ms: percentile(&latencies, 50.0),
            p95_latency_ms: percentile(&latencies, 95.0),
            p99_latency_ms: percentile(&latencies, 99.0),
            min_latency_ms: latencies[0],
            max_latency_ms: *latencies.last().unwrap(),
            success_rate: successes as f64 / num_peers as f64,
        };

        println!(
            "{:>8} {:>10} {:>10.1}/s {:>10.2} {:>10.2} {:>10.2} {:>10.2}",
            result.num_peers,
            result.total_reports,
            result.throughput_reports_per_sec,
            result.mean_latency_ms,
            result.p50_latency_ms,
            result.p95_latency_ms,
            result.p99_latency_ms,
        );

        results.push(result);
    }

    results
}

/// Swarm scale benchmark.
/// Tests how announce and report performance changes with swarm size.
pub async fn run_swarm_scale_benchmark(
    swarm_sizes: &[usize],
    announce_iterations: usize,
) -> Vec<SwarmScaleResult> {
    println!("\n=== Scalability: Swarm Size Impact ===\n");
    println!(
        "{:>10} {:>14} {:>14} {:>14} {:>14}",
        "Swarm", "Ann mean(ms)", "Ann p95(ms)", "Rep mean(ms)", "Rep p95(ms)"
    );
    println!("{}", "-".repeat(70));

    let mut results = Vec::new();
    let infohash = [0xBBu8; 20];

    for &size in swarm_sizes {
        let mut state = TrackerState::new(TrackerConfig {
            verify_signatures: true,
            receipt_window: 7200,
            ..TrackerConfig::default()
        });

        // Populate swarm with `size` peers
        let swarm = state.swarms.entry(infohash).or_default();
        for i in 0..size {
            let (_sk, pk) = crypto::generate_keypair();
            let peer = pbts_core::types::Peer {
                peer_id: format!("peer-{i}").into_bytes(),
                ip: format!("10.0.{}.{}", i / 256, i % 256),
                port: 6881 + (i % 1000) as u16,
                user_id: Some(format!("user-{i}")),
                public_key: Some(pk),
                uploaded: 0,
                downloaded: 0,
                left: 1024,
                last_seen: 0.0,
            };
            swarm.insert(format!("peer-{i}"), peer);
        }

        // Benchmark announce (lookup + random sample)
        let mut announce_timings = Vec::with_capacity(announce_iterations);
        for _ in 0..announce_iterations {
            let start = Instant::now();
            // Simulate announce: get swarm, sample peers
            if let Some(swarm) = state.swarms.get(&infohash) {
                let peers: Vec<_> = swarm.values().take(50).collect();
                std::hint::black_box(&peers);
            }
            announce_timings.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        announce_timings.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let ann_mean = announce_timings.iter().sum::<f64>() / announce_timings.len() as f64;
        let ann_p95 = percentile(&announce_timings, 95.0);

        // Benchmark report processing (with receipts)
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let (_sk, pk) = crypto::generate_keypair();

        let report_iters = announce_iterations.min(100);
        let mut report_timings = Vec::with_capacity(report_iters);
        for _ in 0..report_iters {
            // Each iteration needs fresh receipt IDs to avoid double-spend
            let fresh_data = generate_test_receipts(&pk, 10, now + rand::random::<u64>() % 100000);
            let fresh_receipts: Vec<PBTSReceipt> = fresh_data.into_iter().map(|(r, _, _)| r).collect();

            let start = Instant::now();
            let _ = receipt::process_report(
                &fresh_receipts,
                &mut state.used_receipts,
                state.config.receipt_window,
            );
            report_timings.push(start.elapsed().as_secs_f64() * 1000.0);
        }
        report_timings.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let rep_mean = report_timings.iter().sum::<f64>() / report_timings.len() as f64;
        let rep_p95 = percentile(&report_timings, 95.0);

        println!(
            "{:>10} {:>14.4} {:>14.4} {:>14.4} {:>14.4}",
            size, ann_mean, ann_p95, rep_mean, rep_p95
        );

        results.push(SwarmScaleResult {
            swarm_size: size,
            announce_mean_ms: ann_mean,
            announce_p95_ms: ann_p95,
            report_mean_ms: rep_mean,
            report_p95_ms: rep_p95,
        });
    }

    results
}

pub async fn run_scalability_benchmarks(
    peer_counts: &[usize],
    swarm_sizes: &[usize],
    receipts_per_report: usize,
    announce_iterations: usize,
) -> ScalabilityResults {
    let concurrency = run_concurrency_benchmark(peer_counts, receipts_per_report).await;
    let swarm_scale = run_swarm_scale_benchmark(swarm_sizes, announce_iterations).await;
    ScalabilityResults {
        concurrency,
        swarm_scale,
    }
}

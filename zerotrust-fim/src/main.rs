//! AegisX ZeroTrust FIM Guard - daemon entry point.
//!
//! Watches configured roots, maintains a trusted BLAKE3 baseline in SQLite
//! (hashed in parallel via rayon), streams normalized events over a Unix
//! socket, periodically scans /proc for process anomalies, optionally streams
//! exec telemetry (eBPF tracepoint with a /proc fallback), and — with the
//! `yara` feature — scans flagged process memory with compiled YARA rules.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aegis_core::anomaly;
use aegis_core::{AegisFim, ipc};

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "aegisx-fim", version, about = "AegisX ZeroTrust FIM Guard")]
struct Args {
    /// Baseline database path.
    #[arg(long, default_value = "/var/lib/aegisx/fim-baseline.db")]
    baseline: PathBuf,

    /// Directories to watch recursively (repeatable).
    #[arg(long = "watch", required = true)]
    watch: Vec<PathBuf>,

    /// Unix socket path for JSON-lines IPC telemetry.
    #[arg(long, default_value = "/var/run/aegisx-fim.sock")]
    socket: String,

    /// Seconds between process-anomaly polls.
    #[arg(long, default_value = "5")]
    anomaly_interval: u64,

    /// Skip the process anomaly scanner.
    #[arg(long)]
    no_anomaly: bool,

    /// Rayon worker threads for parallel baseline hashing (0 = auto).
    #[arg(long, default_value = "0")]
    threads: usize,

    /// Stream process exec telemetry (eBPF hook when available, else /proc).
    #[arg(long)]
    trace_exec: bool,

    /// Path to a prebuilt eBPF object file (empty = embedded locator paths).
    #[arg(long, default_value = "")]
    ebpf_elf: String,

    /// Restrict exec telemetry to these usernames (repeatable, empty = all).
    #[arg(long = "exec-user")]
    exec_user: Vec<String>,

    /// Restrict exec telemetry to these comm names (repeatable, empty = all).
    #[arg(long = "exec-comm")]
    exec_comm: Vec<String>,

    /// YARA rules files to compile for process-memory scanning (repeatable).
    #[cfg(feature = "yara")]
    #[arg(long = "yara-rules")]
    yara_rules: Vec<PathBuf>,

    /// Seconds between YARA memscan passes over flagged processes.
    #[cfg(feature = "yara")]
    #[arg(long, default_value = "60")]
    memscan_interval: u64,
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let args = Args::parse();

    let fim = match AegisFim::new_with_threads(&args.baseline, args.watch.clone(), args.threads) {
        Ok(f) => f,
        Err(e) => {
            log::error!("failed to initialize FIM core: {e}");
            std::process::exit(1);
        }
    };

    // Shared telemetry snapshot refreshed every second by the pump loop.
    let stats = Arc::new(Mutex::new(fim.stats()));
    let shutdown = Arc::new(AtomicU64::new(0));

    // Start the fs watcher; the returned channel is consumed by the IPC server.
    let events = match fim.watch(&args.watch) {
        Ok(rx) => rx,
        Err(e) => {
            log::error!("failed to start watcher: {e}");
            std::process::exit(1);
        }
    };

    // Auxiliary JSON-lines channel (exec / memscan telemetry) merged into the
    // IPC socket alongside FIM events.
    let (aux_tx, aux_rx) = std::sync::mpsc::channel::<serde_json::Value>();

    // IPC server thread (JSON-lines over Unix socket). Owns the event channel.
    let ipc_socket = args.socket.clone();
    let ipc_stats = stats.clone();
    let ipc_shutdown = shutdown.clone();
    let _ipc_thread = std::thread::Builder::new()
        .name("ipc-server".into())
        .spawn(move || {
            if let Err(e) = ipc::serve(&ipc_socket, events, aux_rx, ipc_stats, ipc_shutdown) {
                log::error!("IPC server failed: {e}");
            }
        })
        .expect("spawn ipc thread");

    // Pids flagged as anomalous by the exec streamer; the YARA memscan thread
    // (feature `yara`) periodically re-scans them.
    let mem_flagged: Arc<Mutex<HashSet<i32>>> = Arc::new(Mutex::new(HashSet::new()));

    // Process exec telemetry streamer (eBPF hook, transparent /proc fallback).
    if args.trace_exec {
        let (exec_ctl, exec_rx) = aegis_core::ebpf::spawn_exec_streamer_with_elf(
            "aegisx-fim",
            &args.exec_user,
            &args.exec_comm,
            true,
            Some(args.ebpf_elf.clone()),
        );
        let _exec_ctl = exec_ctl; // keep the control sender alive for future IPC
        let aux_tx = aux_tx.clone();
        let flagged = mem_flagged.clone();
        let _ = std::thread::Builder::new()
            .name("exec-forward".into())
            .spawn(move || {
                for ev in exec_rx {
                    if ev.anomaly {
                        if let Ok(mut set) = flagged.lock() {
                            set.insert(ev.pid);
                        }
                        log::warn!(
                            "process exec anomaly: pid={} comm={} exe={} type={} detail={}",
                            ev.pid,
                            ev.comm,
                            ev.exe,
                            ev.anomaly_type,
                            ev.detail
                        );
                    }
                    if let Ok(v) = serde_json::to_value(&ev) {
                        let _ = aux_tx.send(serde_json::json!({ "exec": v }));
                    }
                }
            });
    }

    // YARA process-memory scanner over exec-flagged pids.
    #[cfg(feature = "yara")]
    {
        use aegis_core::memscan::MemScanner;

        if !args.yara_rules.is_empty() {
            let mut scanners = Vec::new();
            for rf in &args.yara_rules {
                match MemScanner::compile(rf) {
                    Ok(s) => {
                        log::info!("loaded YARA rules from {}", rf.display());
                        scanners.push(s);
                    }
                    Err(e) => {
                        log::error!("failed to compile YARA rules {}: {e}", rf.display());
                    }
                }
            }
            if !scanners.is_empty() {
                let aux_tx = aux_tx.clone();
                let flagged = mem_flagged.clone();
                let interval = Duration::from_secs(args.memscan_interval.max(1));
                let _ = std::thread::Builder::new()
                    .name("yara-memscan".into())
                    .spawn(move || loop {
                        std::thread::sleep(interval);
                        let pids: Vec<i32> = flagged
                            .lock()
                            .map(|s| s.iter().copied().collect())
                            .unwrap_or_default();
                        for pid in pids {
                            for scanner in &scanners {
                                for m in scanner.scan_process(pid) {
                                    log::warn!(
                                        "yara memscan match pid={} rule={} strings={:?}",
                                        m.pid,
                                        m.rule_name,
                                        m.strings
                                    );
                                    let v = serde_json::json!({
                                        "memscan_match": {
                                            "pid": m.pid,
                                            "rule": m.rule_name,
                                            "strings": m.strings,
                                            "meta": m.meta,
                                        }
                                    });
                                    let _ = aux_tx.send(v);
                                }
                            }
                        }
                    });
            }
        }
    }

    // Process anomaly scanner thread.
    if !args.no_anomaly {
        let mut prior: std::collections::HashMap<i32, (u64, u64)> =
            std::collections::HashMap::new();
        let interval = Duration::from_secs(args.anomaly_interval);
        let _ = std::thread::Builder::new()
            .name("anomaly-scanner".into())
            .spawn(move || loop {
                std::thread::sleep(interval);
                for anom in anomaly::poll(&mut prior) {
                    match serde_json::to_string(&anom) {
                        Ok(line) => log::warn!("process anomaly: {line}"),
                        Err(_) => {}
                    }
                }
            });
    }

    log::info!(
        "AegisX FIM guard online: baseline={} socket={} roots=[{}]",
        args.baseline.display(),
        args.socket,
        args.watch
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Main pump: refresh telemetry counters and surface periodic summaries.
    // Runs until the process is signalled by the container runtime / systemd.
    let mut ticks: u64 = 0;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        ticks += 1;
        {
            if let Ok(mut s) = stats.lock() {
                *s = fim.stats();
            }
        }
        if ticks % 30 == 0 {
            log::info!("fim counters: {}", fim.stats());
        }
    }
}

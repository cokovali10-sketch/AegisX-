//! AegisX ZeroTrust FIM Guard core library.
//!
//! Design goals:
//!   * Memory safety + zero-cost abstractions (Rust ownership, no GC).
//!   * Zero lock contention: the live in-memory baseline is a sharded
//!     [`dashmap::DashMap`]; disk (SQLite) is written on a single background
//!     thread so readers never block on the database.
//!   * Constant-time BLAKE3 comparison for `FILE_CREATE/MODIFY/DELETE`.
//!   * A lightweight IPC surface (Unix domain socket, JSON-lines) plus a C
//!     ABI under the `ffi` feature for cross-language callers.

pub mod anomaly;
pub mod baseline;
pub mod ebpf;
pub mod ffi;
pub mod hasher;
pub mod ipc;
pub mod watch;
#[cfg(feature = "yara")]
pub mod memscan;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use baseline::BaselineStore;
use watch::{FimEvent, FimEventHandler};

/// Top-level runtime wiring for the FIM guard. Owns the baseline store, the
/// event pump, counters surfaced through IPC telemetry, and the shared rayon
/// pool used for parallel baseline (re)scans.
pub struct AegisFim {
    store: Arc<BaselineStore>,
    handler: Arc<FimEventHandler>,
    scanned: Arc<AtomicU64>,
    alerts: Arc<AtomicU64>,
    pool: rayon::ThreadPool,
}

impl AegisFim {
    /// Open (or create) a baseline database at `db_path` and seed it with the
    /// current hash state of every file under `watch_paths`, hashed in
    /// parallel on a pool sized to the number of available CPUs.
    pub fn new(db_path: &Path, watch_paths: Vec<PathBuf>) -> anyhow::Result<Self> {
        let threads = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        Self::new_with_threads(db_path, watch_paths, threads)
    }

    /// Like [`AegisFim::new`] but with an explicit rayon worker count
    /// (`0` = auto / available parallelism).
    pub fn new_with_threads(
        db_path: &Path,
        watch_paths: Vec<PathBuf>,
        threads: usize,
    ) -> anyhow::Result<Self> {
        let store = Arc::new(BaselineStore::open(db_path)?);
        let scanned = Arc::new(AtomicU64::new(0));
        let alerts = Arc::new(AtomicU64::new(0));

        let handler = Arc::new(FimEventHandler::new(
            store.clone(),
            scanned.clone(),
            alerts.clone(),
        ));

        let pool = hasher::parallel_hasher_pool(threads);

        // Initial baseline pass - establish a trusted snapshot.
        for root in &watch_paths {
            store.scan_root_parallel(root, &pool)?;
        }

        Ok(Self {
            store,
            handler,
            scanned,
            alerts,
            pool,
        })
    }

    /// Begin watching all configured roots and return the event receiver.
    /// The caller is responsible for pumping the channel.
    pub fn watch(&self, watch_paths: &[PathBuf]) -> anyhow::Result<std::sync::mpsc::Receiver<FimEvent>> {
        self.handler.spawn(watch_paths)
    }

    /// Force a full rescan (used after manual baseline re-seed / CommandFrame).
    pub fn rescan(&self, roots: &[PathBuf]) -> anyhow::Result<u64> {
        let mut total = 0u64;
        for root in roots {
            total += self.store.scan_root(root)?;
        }
        self.scanned.fetch_add(total, Ordering::Relaxed);
        Ok(total)
    }

    /// Force a full parallel rescan using the shared rayon pool.
    pub fn rescan_parallel(&self, roots: &[PathBuf]) -> anyhow::Result<u64> {
        let mut total = 0u64;
        for root in roots {
            total += self.store.scan_root_parallel(root, &self.pool)?;
        }
        self.scanned.fetch_add(total, Ordering::Relaxed);
        Ok(total)
    }

    /// Live snapshot of counters for IPC/telemetry frames.
    pub fn stats(&self) -> serde_json::Value {
        serde_json::json!({
            "files_scanned": self.scanned.load(Ordering::Relaxed),
            "alerts_emitted": self.alerts.load(Ordering::Relaxed),
            "baseline_entries": self.store.len(),
        })
    }

    pub fn store(&self) -> &BaselineStore {
        &self.store
    }

    pub fn alerts(&self) -> Arc<AtomicU64> {
        self.alerts.clone()
    }
}

/// Error convenience alias so callers do not need to reach into anyhow.
pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

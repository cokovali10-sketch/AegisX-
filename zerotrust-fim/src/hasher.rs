//! BLAKE3 streaming hashing with a large buffered reader.
//!
//! BLAKE3 is selected over SHA-256 for its multi-threaded hashing on large
//! files, single pass over the data, and native extensibility (keyed hashing,
//! subtree hashing) that a FIM can use later for Merkle proofs.

use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// A finalized digest rendered as lowercase hex.
pub type Digest = String;

/// File metadata captured alongside the hash for change triage.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileSnapshot {
    pub path: String,
    pub digest: Digest,
    pub size: u64,
    pub modified: i64,
    pub mode: u32,
}

/// Default read buffer: 1 MiB, tuned for NVMe sequential throughput while
/// staying well within L2/L3 cache for hash state.
const IO_BUF_SIZE: usize = 1 << 20;

/// Compute a streaming BLAKE3 digest for the file at `path`.
pub fn hash_file(path: &Path) -> io::Result<Digest> {
    let mut file = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; IO_BUF_SIZE];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

/// Hash + metadata snapshot. `Err` is returned for unreadable files so the
/// caller can decide whether the unreadability is itself an alert.
pub fn snapshot(path: &Path) -> io::Result<FileSnapshot> {
    let meta = std::fs::symlink_metadata(path)?;
    let digest = hash_file(path)?;
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    #[cfg(unix)]
    let mode = meta.permissions().mode();
    #[cfg(not(unix))]
    let mode = 0u32;

    Ok(FileSnapshot {
        path: path.to_string_lossy().into_owned(),
        digest,
        size: meta.len(),
        modified: mtime,
        mode,
    })
}

/// Hash a byte slice (used by the FFI surface and unit tests).
pub fn hash_bytes(data: &[u8]) -> Digest {
    blake3::hash(data).to_hex().to_string()
}

// ---------------------------------------------------------------------------
// Parallel multi-threaded tree scanning (Rayon)
// ---------------------------------------------------------------------------

/// Directory names skipped during a recursive scan. /proc, /sys, /dev are
/// kernel pseudo-filesystems with unbounded/no stable content; .git and target
/// are churn-heavy and not monitored integrity surface.
pub(crate) const IGNORE_DIRS: [&str; 5] = ["proc", "sys", "dev", ".git", "target"];

/// Default stack size (8 MiB) for rayon workers so deep recursion / large
/// stack frames in `snapshot` never trip the default 2 MiB worker stack.
const PARALLEL_WORKER_STACK: usize = 8 << 20;

/// Build a Rayon thread pool sized for parallel BLAKE3 hashing.
///
/// `threads == 0` means "auto" (use the number of available CPUs).
pub fn parallel_hasher_pool(threads: usize) -> rayon::ThreadPool {
    let num_threads = if threads == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        threads.max(1)
    };
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .stack_size(PARALLEL_WORKER_STACK)
        .thread_name(|i| format!("fim-hash-{i}"))
        .build()
        .unwrap_or_else(|err| {
            // Fall back to a minimal single-threaded pool rather than aborting.
            log::warn!("rayon pool build failed ({err}); using single worker");
            rayon::ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .expect("single-threaded rayon pool")
        })
}

/// Recursively collect every regular file path under `root`, skipping ignored
/// directories and symlinks (via `symlink_metadata`, which does not follow the
/// final symlink; any non-regular entry is dropped).
pub(crate) fn collect_files(root: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut walk = vec![root.to_path_buf()];
    while let Some(dir) = walk.pop() {
        let read = match std::fs::read_dir(&dir) {
            Ok(r) => r,
            Err(_) => continue, // unreadable dir: skip (matches baseline::scan_root)
        };
        for entry in read.flatten() {
            let path = entry.path();
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(_) => continue,
            };
            if meta.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if IGNORE_DIRS.iter().any(|d| *d == name) {
                        continue;
                    }
                }
                walk.push(path);
            } else if meta.is_file() {
                out.push(path);
            }
            // symlinks, sockets, fifos, devices: skipped.
        }
    }
    Ok(out)
}

/// Recursively hash every file under `root` in parallel, calling `emit` for
/// each successful snapshot. Returns the number of files successfully hashed.
///
/// `emit` runs on rayon worker threads so it must be `Send + Sync`. This is
/// independent of the single-threaded [`snapshot`]/per-file path.
pub fn scan_tree_parallel<F>(
    root: &Path,
    pool: &rayon::ThreadPool,
    emit: F,
) -> std::io::Result<u64>
where
    F: Fn(FileSnapshot) + Send + Sync,
{
    if !root.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("watch root does not exist: {}", root.display()),
        ));
    }
    let paths = collect_files(root)?;
    let seen = Arc::new(AtomicU64::new(0));
    let counter = seen.clone();
    pool.install(move || {
        paths
            .par_iter()
            .filter_map(|p| snapshot(p).ok())
            .for_each(|snap| {
                counter.fetch_add(1, Ordering::Relaxed);
                emit(snap);
            });
    });
    Ok(seen.load(Ordering::Relaxed))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_known_vector() {
        // blake3("abc") well-known vector.
        assert_eq!(
            hash_bytes(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
        );
    }
}

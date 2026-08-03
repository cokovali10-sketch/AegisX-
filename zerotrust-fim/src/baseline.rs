//! Baseline persistence + comparison.
//!
//! The "trusted baseline" lives in two places:
//!   1. A sharded in-memory map ([`dashmap::DashMap`]) for contention-free
//!      single-fingerprint lookups performed on every fs event.
//!   2. A SQLite WAL database for durable persistence and fast rescan of
//!      sub-second-cadence churn.
//!
//! All database writes funnel through a single-owner [`BaselineStore`] worker
//! so that filesystem webs can never deadlock on the DB lock.

use std::path::Path;
use std::sync::Arc;

use dashmap::DashMap;
use rusqlite::{Connection, params};

use crate::hasher::{self, FileSnapshot};

/// One trusted record for a watched file.
#[derive(Debug, Clone)]
pub struct BaselineEntry {
    pub digest: String,
    pub size: u64,
    pub modified: i64,
    pub mode: u32,
    pub seen_at: i64,
}

pub struct BaselineStore {
    conn: Connection,
    mem: DashMap<String, BaselineEntry>,
}

impl BaselineStore {
    /// Open (or create) the baseline database and hydrate the in-memory map.
    pub fn open(db_path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(db_path)?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS baseline (
                path      TEXT PRIMARY KEY NOT NULL,
                digest    TEXT NOT NULL,
                size      INTEGER NOT NULL,
                modified  INTEGER NOT NULL,
                mode      INTEGER NOT NULL,
                seen_at   INTEGER NOT NULL
            );",
        )?;

        let mem = DashMap::new();
        {
            let mut stmt = conn.prepare(
                "SELECT path, digest, size, modified, mode, seen_at FROM baseline",
            )?;
            let rows = stmt.query_map([], |r| {
                Ok(FileEntry {
                    path: r.get(0)?,
                    digest: r.get(1)?,
                    size: r.get(2)?,
                    modified: r.get(3)?,
                    mode: r.get(4)?,
                    seen_at: r.get(5)?,
                })
            })?;
            for row in rows.flatten() {
                mem.insert(
                    row.path.clone(),
                    BaselineEntry {
                        digest: row.digest,
                        size: row.size,
                        modified: row.modified,
                        mode: row.mode,
                        seen_at: row.seen_at,
                    },
                );
            }
        }
        Ok(Self { conn, mem })
    }

    /// Recursively scan `root`, hashing every regular file and upserting it to
    /// the baseline. Returns the number of files hashed.
    pub fn scan_root(&self, root: &Path) -> anyhow::Result<u64> {
        if !root.exists() {
            anyhow::bail!("watch root does not exist: {}", root.display());
        }
        let mut count = 0u64;
        let mut walk = vec![root.to_path_buf()];
        let ignore_dirs = vec!["proc", "sys", "dev", ".git", "target"];

        while let Some(dir) = walk.pop() {
            let read = match std::fs::read_dir(&dir) {
                Ok(r) => r,
                Err(_) => continue,
            };
            for entry in read.flatten() {
                let path = entry.path();
                let ft = match entry.file_type() {
                    Ok(t) => t,
                    Err(_) => continue,
                };
                if ft.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if ignore_dirs.iter().any(|d| *d == name) {
                            continue;
                        }
                    }
                    walk.push(path);
                } else if ft.is_file() {
                    if let Ok(snap) = hasher::snapshot(&path) {
                        self.upsert(&snap);
                        count += 1;
                    }
                }
            }
        }
        Ok(count)
    }

    /// Recursively scan `root` using the caller-provided rayon pool, hashing
    /// every regular file in parallel and upserting each snapshot. Returns the
    /// number of files hashed.
    ///
    /// `scan_tree_parallel`'s emit closure runs on rayon worker threads; the
    /// SQLite handle is not `Sync`, so snapshots are collected concurrently
    /// and the (single-owner) persist pass runs here on the caller thread.
    /// The DashMap in-memory index still benefits from the parallel hashing.
    pub fn scan_root_parallel(
        &self,
        root: &Path,
        pool: &rayon::ThreadPool,
    ) -> anyhow::Result<u64> {
        if !root.exists() {
            anyhow::bail!("watch root does not exist: {}", root.display());
        }
        let collected: Arc<std::sync::Mutex<Vec<FileSnapshot>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = collected.clone();
        let count = hasher::scan_tree_parallel(root, pool, move |snap| {
            if let Ok(mut v) = sink.lock() {
                v.push(snap);
            }
        })?;
        let snaps = collected
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for snap in snaps.iter() {
            self.upsert(snap);
        }
        Ok(count)
    }

    /// Insert or refresh an entry in both memory and the WAL database.
    pub fn upsert(&self, snap: &FileSnapshot) {
        let entry = BaselineEntry {
            digest: snap.digest.clone(),
            size: snap.size,
            modified: snap.modified,
            mode: snap.mode,
            seen_at: now_epoch_secs(),
        };
        self.upsert_from(snap.path.clone(), entry);
    }

    fn upsert_from(&self, path: String, entry: BaselineEntry) {
        self.mem.insert(path.clone(), entry.clone());
        self.persist(&path, &entry);
    }

    fn persist(&self, path: &str, e: &BaselineEntry) {
        let res = self.conn.execute(
            "INSERT INTO baseline(path, digest, size, modified, mode, seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(path) DO UPDATE SET
               digest=excluded.digest, size=excluded.size,
               modified=excluded.modified, mode=excluded.mode,
               seen_at=excluded.seen_at",
            params![path, e.digest, e.size, e.modified, e.mode, e.seen_at],
        );
        if let Err(err) = res {
            log::warn!("baseline persist failed for {}: {}", path, err);
        }
    }

    /// Look up the trusted baseline entry for a path.
    pub fn lookup(&self, path: &str) -> Option<BaselineEntry> {
        self.mem.get(path).map(|e| (*e).clone())
    }

    /// Compare a freshly-hashed snapshot against the baseline.
    /// Returns `true` when the file is intact, `false` when it changed.
    pub fn verify(&self, path: &str, snap: &FileSnapshot) -> bool {
        match self.lookup(path) {
            Some(entry) => entry.digest == snap.digest,
            None => {
                // Not in baseline yet -> treat as newly trusted (or new) entry.
                self.upsert(snap);
                true
            }
        }
    }

    /// Remove all entries under `path` and their DB rows (used on DELETE).
    pub fn remove(&self, path: &str) {
        self.mem.remove(path);
        let _ = self
            .conn
            .execute("DELETE FROM baseline WHERE path = ?1", params![path]);
    }

    pub fn len(&self) -> usize {
        self.mem.len()
    }
}

#[derive(Debug, Clone)]
struct FileEntry {
    path: String,
    digest: String,
    size: u64,
    modified: i64,
    mode: u32,
    seen_at: i64,
}

fn now_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
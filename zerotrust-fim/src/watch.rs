//! Cross-platform file system watcher using `notify`.
//!
//! Maps the OS kernel notification layer (inotify on Linux, ReadDirectoryChangesW
//! on Windows, FSEvents/kqueue on macOS) onto a normalized [`FimEvent`] stream,
//! then runs the hashing-compare cycle on a dedicated worker.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::baseline::BaselineStore;
use crate::hasher;

/// Normalized integrity event emitted to upstream consumers.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FimEvent {
    pub path: String,
    pub kind: FimKind,
    /// The new BLAKE3 digest when the file was hashed (MODIFY/CREATE).
    pub digest: Option<String>,
    pub timestamp: i64,
    pub alert: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, serde::Serialize, PartialEq)]
#[serde(rename_all = "UPPERCASE")]
pub enum FimKind {
    Created,
    Modified,
    Deleted,
}

/// Bridges `notify` events into our integrity pipeline.
pub struct FimEventHandler {
    store: Arc<BaselineStore>,
    scanned: Arc<AtomicU64>,
    alerts: Arc<AtomicU64>,
}

impl FimEventHandler {
    pub fn new(store: Arc<BaselineStore>, scanned: Arc<AtomicU64>, alerts: Arc<AtomicU64>) -> Self {
        Self {
            store,
            scanned,
            alerts,
        }
    }

    /// Start a watcher over `paths`; returns the channel carrying [`FimEvent`]s.
    pub fn spawn(&self, watch_paths: &[PathBuf]) -> anyhow::Result<std::sync::mpsc::Receiver<FimEvent>> {
        let (tx, rx) = std::sync::mpsc::channel::<FimEvent>();
        let (raw_tx, raw_rx) = std::sync::mpsc::channel::<notify::Result<Event>>();

        let mut watcher: RecommendedWatcher =
            notify::recommended_watcher(move |res: notify::Result<Event>| {
                // drain-compatible send; dropping on failure is acceptable.
                let _ = raw_tx.send(res);
            })?;
        watcher.configure(Config::default())?;
        for root in watch_paths {
            watcher.watch(root, RecursiveMode::Recursive)?;
        }

        // Keep the watcher alive: the spawned thread owns it; dropping the
        // JoinHandle detaches (the daemon keeps running for the process life).
        let store = self.store.clone();
        let scanned = self.scanned.clone();
        let alerts = self.alerts.clone();
        let _ = std::thread::Builder::new()
            .name("fim-worker".into())
            .spawn(move || {
                let mut watcher = watcher;
                while let Ok(res) = raw_rx.recv() {
                    if let Ok(event) = res {
                        if let Some(fim) = translate(event, &store, &scanned, &alerts) {
                            let _ = tx.send(fim);
                        }
                    }
                }
                drop(watcher);
            })?;

        Ok(rx)
    }
}

/// Translate a raw notify event into zero-or-one FIM event.
fn translate(
    ev: Event,
    store: &BaselineStore,
    scanned: &AtomicU64,
    alerts: &AtomicU64,
) -> Option<FimEvent> {
    let path = ev.paths.first()?.to_string_lossy().into_owned();

    let fim = match ev.kind {
        EventKind::Create(_) => {
            // New file: hash it, register in baseline, alert on unexpected.
            let snap = hasher::snapshot(&Path::new(&path)).ok()?;
            let trusted = store.lookup(&path);
            let changed = trusted
                .map(|t| t.digest != snap.digest)
                .unwrap_or(true);
            store.upsert(&snap);
            scanned.fetch_add(1, Ordering::Relaxed);
            if changed {
                alerts.fetch_add(1, Ordering::Relaxed);
            }
            FimEvent {
                path,
                kind: FimKind::Created,
                digest: Some(snap.digest),
                timestamp: now_ms(),
                alert: changed,
                detail: "new file observed on watched root".into(),
            }
        }
        EventKind::Modify(_) => {
            let snap = match hasher::snapshot(&Path::new(&path)) {
                Ok(s) => s,
                Err(_) => return None, // transient (still being written)
            };
            // Baseline is authoritative until the operator confirms via rescan,
            // so repeated eviction attempts keep alerting (Zero-Trust posture).
            let changed = match store.lookup(&path) {
                Some(baseline) => baseline.digest != snap.digest,
                None => true,
            };
            if changed {
                alerts.fetch_add(1, Ordering::Relaxed);
            }
            scanned.fetch_add(1, Ordering::Relaxed);
            FimEvent {
                path,
                kind: FimKind::Modified,
                digest: Some(snap.digest),
                timestamp: now_ms(),
                alert: changed,
                detail: if changed {
                    "content hash changed from baseline".into()
                } else {
                    "file re-written identically".into()
                },
            }
        }
        EventKind::Remove(_) => {
            let had = store.lookup(&path).is_some();
            store.remove(&path);
            if had {
                alerts.fetch_add(1, Ordering::Relaxed);
            }
            FimEvent {
                path,
                kind: FimKind::Deleted,
                digest: None,
                timestamp: now_ms(),
                alert: had,
                detail: "file removed from watched root".into(),
            }
        }
        _ => {
            return match ev.kind {
                EventKind::Any => Some(FimEvent {
                    path,
                    kind: FimKind::Modified,
                    digest: None,
                    timestamp: now_ms(),
                    alert: false,
                    detail: "unspecified filesystem activity".into(),
                }),
                _ => None,
            };
        }
    };

    // For Modify(Created) we already handled; return translated.
    Some(fim)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}
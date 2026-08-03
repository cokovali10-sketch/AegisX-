//! CAP_BPF-free execve detection via `/proc` polling (Linux only).
//!
//! Snapshots `/proc/<pid>` identity (pid, ppid, comm, exe, uid, starttime,
//! argv) between polls and synthesizes [`ExecEvent`]s for pids that were not
//! seen before — including pid-reuse, which is detected via a starttime
//! change. The first poll pass only establishes the baseline set so the daemon
//! does not report every pre-existing process as a fresh exec.

use std::collections::HashMap;
use std::path::Path;

use super::{ExecEvent, classify, passes_filters, uid_to_user};

pub struct ProcExecScanner {
    node: String,
    watch_users: Vec<String>,
    watch_comm: Vec<String>,
    /// pid -> starttime (ns); used for new-exec + pid-reuse detection.
    seen: HashMap<i32, u64>,
    /// Whether the initial baseline pass has completed.
    warmed: bool,
}

impl ProcExecScanner {
    pub fn new(node: &str, watch_users: Vec<String>, watch_comm: Vec<String>) -> Self {
        Self {
            node: node.to_string(),
            watch_users,
            watch_comm,
            seen: HashMap::new(),
            warmed: false,
        }
    }

    /// One poll pass over `/proc`, returning synthetic exec events for newly
    /// observed pids.
    pub fn poll(&mut self) -> Vec<ExecEvent> {
        let mut out = Vec::new();
        let entries = match std::fs::read_dir("/proc") {
            Ok(e) => e.flatten(),
            Err(_) => return out,
        };
        for entry in entries {
            let name = match entry.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue,
            };
            let pid = match name.parse::<i32>() {
                Ok(p) => p,
                Err(_) => continue, // non-numeric entries (cpuinfo, ...)
            };
            let dir = entry.path();

            let ppid = read_ppid(&dir);
            let comm = read_comm(&dir);
            let exe = resolve_exe(&dir);
            let uid = read_uid(&dir);
            let start_ns = read_starttime_ns(&dir);
            let argv = read_argv(&dir);

            // A pid we have seen with a different starttime means the kernel
            // recycled the pid for a brand-new process.
            let is_new = match self.seen.get(&pid) {
                Some(prev) => start_ns != 0 && *prev != start_ns,
                None => true,
            };
            if !is_new {
                continue;
            }
            self.seen.insert(pid, start_ns);
            if !self.warmed {
                continue; // baseline pass: no synthetic events
            }

            let (anomaly, anomaly_type, detail) = classify(&exe, &argv);
            let ev = ExecEvent {
                pid,
                ppid,
                comm,
                exe,
                argv,
                user: uid_to_user(uid),
                uid,
                start_ns,
                anomaly,
                anomaly_type,
                detail,
                node: self.node.clone(),
            };
            if passes_filters(&ev, &self.watch_users, &self.watch_comm) {
                out.push(ev);
            }
        }
        self.warmed = true;
        self.prune();
        out
    }

    /// Drop pids that are no longer alive so the seen-map stays bounded.
    fn prune(&mut self) {
        let alive: std::collections::HashSet<i32> = std::fs::read_dir("/proc")
            .map(|rd| {
                rd.flatten()
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter_map(|n| n.parse::<i32>().ok())
                    .collect()
            })
            .unwrap_or_default();
        self.seen.retain(|pid, _| alive.contains(pid));
    }
}

/// Parse the fields of `/proc/<pid>/stat` after the parenthesized comm.
/// Returns the fields starting at `state` (index 0 = state, 1 = ppid,
/// 19 = starttime).
fn stat_fields(proc: &Path) -> Option<Vec<String>> {
    let stat = std::fs::read_to_string(proc.join("stat")).ok()?;
    let rparen = stat.rfind(')')?;
    Some(
        stat[rparen + 1..]
            .split_whitespace()
            .map(|s| s.to_string())
            .collect(),
    )
}

fn read_ppid(proc: &Path) -> i32 {
    stat_fields(proc)
        .and_then(|f| f.get(1).and_then(|s| s.parse().ok()))
        .unwrap_or(0)
}

/// `/proc/<pid>/stat` field 22 (`starttime`) in clock ticks, converted to
/// nanoseconds via `sysconf(_SC_CLK_TCK)`. `0` if unreadable.
fn read_starttime_ns(proc: &Path) -> u64 {
    let ticks = stat_fields(proc)
        .and_then(|f| f.get(19).and_then(|s| s.parse::<u64>().ok()))
        .unwrap_or(0);
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks == 0 || clk_tck <= 0 {
        return 0;
    }
    (ticks as u128 * 1_000_000_000u128 / clk_tck as u128) as u64
}

fn read_comm(proc: &Path) -> String {
    std::fs::read_to_string(proc.join("comm"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn resolve_exe(proc: &Path) -> String {
    std::fs::read_link(proc.join("exe"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn read_uid(proc: &Path) -> u32 {
    let status = std::fs::read_to_string(proc.join("status")).unwrap_or_default();
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            if let Some(ru) = rest.trim().split_whitespace().next() {
                if let Ok(v) = ru.parse() {
                    return v;
                }
            }
            break;
        }
    }
    0
}

fn read_argv(proc: &Path) -> Vec<String> {
    std::fs::read(proc.join("cmdline"))
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect()
        })
        .unwrap_or_default()
}

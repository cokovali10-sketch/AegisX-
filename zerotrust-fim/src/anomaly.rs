//! Linux process-anomaly detection.
//!
//! Scans the `/proc` pseudo-filesystem for two high-signal anomalies without
//! any instrumentation of the kernel:
//!   1. **Unlinked execution** — a running binary whose backing file was
//!      deleted (`/proc/<pid>/exe` resolves to `foo (deleted)`).
//!   2. **Privilege escalation** — a process whose *effective* uid/gid differ
//!      from its *real* uid/gid, or that changed identity between polls.
//!
//! This module is Linux-only by design (the host telemetry of the container
//! runtime); a no-op shim is provided for other targets so the crate still
//! compiles cross-platform.

use std::collections::HashMap;
use std::path::PathBuf;

/// A process that failed the anomaly predicate.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Anomaly {
    pub pid: i32,
    pub exe: String,
    pub cmdline: String,
    pub real_uid: u64,
    pub effective_uid: u64,
    pub real_gid: u64,
    pub effective_gid: u64,
    pub anomaly_type: String, // "unlinked_binary" | "privilege_escalation"
    pub detail: String,
    pub timestamp: i64,
}

/// State seen on the previous poll pass, keyed by pid.
type PriorState = HashMap<i32, (u64, u64)>; // (effective_uid, effective_gid)

/// Poll `/proc` once and return any anomalies discovered. `prior` is the
/// caller-owned map of last-seen effective identity; it is updated in place so
/// repeated calls can detect *transitions*.
pub fn poll(prior: &mut PriorState) -> Vec<Anomaly> {
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
            Err(_) => continue, // non-numeric entries: names like "cpuinfo"
        };
        let dir = entry.path();

        let exe = resolve_exe(&dir);
        let (real_uid, effective_uid, real_gid, effective_gid) = read_uids(&dir);
        let cmdline = read_cmdline(&dir);

        // Anomaly 1: unlinked (deleted) executable.
        if let Some(exe) = &exe {
            if exe.ends_with(" (deleted)") {
                out.push(Anomaly {
                    pid,
                    exe: exe.clone(),
                    cmdline,
                    real_uid: real_uid.unwrap_or(0),
                    effective_uid: effective_uid.unwrap_or(0),
                    real_gid: real_gid.unwrap_or(0),
                    effective_gid: effective_gid.unwrap_or(0),
                    anomaly_type: "unlinked_binary".into(),
                    detail: "executable file was deleted while process was running".into(),
                    timestamp: now_ms(),
                });
                continue;
            }
        }

        // Anomaly 2: privilege escalation (transient setuid activity).
        if let (Some(eu), Some(ru), Some(eg), Some(rg)) =
            (effective_uid, real_uid, effective_gid, real_gid)
        {
            if eu != ru || eg != rg {
                out.push(Anomaly {
                    pid,
                    exe: exe.clone().unwrap_or_else(|| "unknown".into()),
                    cmdline,
                    real_uid: ru,
                    effective_uid: eu,
                    real_gid: rg,
                    effective_gid: eg,
                    anomaly_type: "privilege_escalation".into(),
                    detail: format!(
                        "effective uid/gid ({eu}:{eg}) differ from real ({ru}:{rg})"
                    ),
                    timestamp: now_ms(),
                });
            }
            // Transition detection: identity changed since last poll.
            let sig = (eu, eg);
            match prior.get(&pid) {
                Some(prev) if *prev != sig => {
                    out.push(Anomaly {
                        pid,
                        exe: exe.clone().unwrap_or_else(|| "?".into()),
                        cmdline,
                        real_uid: ru,
                        effective_uid: eu,
                        real_gid: rg,
                        effective_gid: eg,
                        anomaly_type: "privilege_escalation".into(),
                        detail: "process identity transitioned between poll passes".into(),
                        timestamp: now_ms(),
                    });
                }
                _ => {}
            }
            prior.insert(pid, sig);
        } else {
            prior.remove(&pid);
        }
    }
    out
}

fn resolve_exe(proc: &PathBuf) -> Option<String> {
    std::fs::read_link(proc.join("exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn read_uids(proc: &PathBuf) -> (Option<u64>, Option<u64>, Option<u64>, Option<u64>) {
    let status = std::fs::read_to_string(proc.join("status")).ok()?;
    let mut uid = None;
    let mut gid = None;
    for line in status.lines() {
        if uid.is_none() {
            if let Some(v) = parse_tab_line(line, "Uid") {
                uid = Some(v);
            }
        }
        if gid.is_none() {
            if let Some(v) = parse_tab_line(line, "Gid") {
                gid = Some(v);
            }
        }
    }
    let (ru, eu) = uid.map(|(a, b)| (Some(a), Some(b))).unwrap_or((None, None));
    let (rg, eg) = gid.map(|(a, b)| (Some(a), Some(b))).unwrap_or((None, None));
    (ru, eu, rg, eg)
}

/// `/proc/<pid>/status` lines look like: `Uid:\t1000\t1000\t1000\t1000`
/// (real, effective, saved, fs). We only need real and effective.
fn parse_tab_line(line: &str, key: &str) -> Option<(u64, u64)> {
    let rest = line.strip_prefix(key)?;
    let rest = rest.strip_prefix(":")?.trim();
    let mut it = rest.split_whitespace();
    let real = it.next()?.parse().ok()?;
    let eff = it.next()?.parse().ok()?;
    Some((real, eff))
}

fn read_cmdline(proc: &PathBuf) -> String {
    std::fs::read(proc.join("cmdline"))
        .ok()
        .map(|b| {
            b.split(|c| *c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default()
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::parse_tab_line;

    #[test]
    fn parses_uid_gid_columns() {
        assert_eq!(parse_tab_line("Uid:\t1000\t1000\t1000\t1000", "Uid"),
                   Some((1000, 1000)));
        assert_eq!(parse_tab_line("Gid:\t0\t0\t0\t0", "Gid"),
                   Some((0, 0)));
        // real != effective is captured correctly.
        assert_eq!(parse_tab_line("Uid:\t0\t1000\t1000\t1000", "Uid"),
                   Some((0, 1000)));
    }

    #[test]
    fn rejects_wrong_key_and_malformed_lines() {
        assert_eq!(parse_tab_line("Name:\tbash", "Uid"), None);
        assert_eq!(parse_tab_line("Uid:", "Uid"), None);
        assert_eq!(parse_tab_line("Uid:", "Gid"), None);
        assert_eq!(parse_tab_line("", "Uid"), None);
    }
}
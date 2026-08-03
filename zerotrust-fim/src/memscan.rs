//! YARA-based in-memory process scanning (feature `yara`).
//!
//! Compiles user-supplied YARA rules and scans the readable regions of each
//! process's address space via `/proc/<pid>/mem` (requires root, or the same
//! uid as the target with ptrace access). Region bounds come from
//! `/proc/<pid>/maps`; each region is read in bounded chunks with `pread` and
//! handed to [`yara::Rules::scan_mem`].
//!
//! Verified against yara 0.13.0 (bindings by Hugal31):
//!   * `Compiler::new() -> Result<Compiler, YaraError>`
//!   * `Compiler::add_rules_file<P: AsRef<Path>>(self, path) -> Result<Compiler, Error>`
//!   * `Compiler::compile_rules(self) -> Result<Rules, YaraError>`
//!   * `Rules::scan_mem(&self, mem: &[u8], timeout: i32) -> Result<Vec<Rule>, YaraError>`
//!   * `Rule { identifier, metadatas, strings, .. }`, `MetadataValue::{Integer,String,Boolean}`

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Context as _;
use yara::{Compiler, MetadataValue, Rule};

/// Total bytes read per process before giving up (1 GiB).
const MAX_TOTAL_BYTES: u64 = 1 << 30;
/// Per-region scan cap (4 MiB).
const MAX_REGION_BYTES: u64 = 4 << 20;
/// Single `pread` chunk (1 MiB).
const CHUNK_BYTES: usize = 1 << 20;
/// YARA scan timeout in seconds.
const SCAN_TIMEOUT_SECS: i32 = 5;

/// One YARA rule match against a process's memory.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MemMatch {
    pub pid: i32,
    pub rule_name: String,
    /// Identifiers of the matched strings (e.g. `$s1`).
    pub strings: Vec<String>,
    /// Rule metadata flattened to strings.
    pub meta: HashMap<String, String>,
}

/// A compiled set of YARA rules, ready to scan processes.
pub struct MemScanner {
    rules: yara::Rules,
}

impl MemScanner {
    /// Compile a YARA rules file into a scanner. The resulting `Rules` is
    /// `Send + Sync` and safe to share across scanner threads.
    pub fn compile(rules_file: &Path) -> anyhow::Result<MemScanner> {
        let mut compiler = Compiler::new()?;
        compiler = compiler
            .add_rules_file(rules_file)
            .with_context(|| format!("loading YARA rules {}", rules_file.display()))?;
        let rules = compiler.compile_rules()?;
        Ok(MemScanner { rules })
    }

    /// Scan a process's readable memory regions, returning every rule match.
    /// Unreadable or already-exited processes yield an empty result rather
    /// than an error.
    #[cfg(target_os = "linux")]
    pub fn scan_process(&self, pid: i32) -> Vec<MemMatch> {
        let regions = match read_regions(pid) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };
        // Opening /proc/<pid>/mem requires the caller to be root or the same
        // uid; EACCES/ESRCH just mean "nothing to scan".
        let mem = match std::fs::File::open(format!("/proc/{pid}/mem")) {
            Ok(f) => f,
            Err(_) => return Vec::new(),
        };

        let mut out = Vec::new();
        let mut budget = MAX_TOTAL_BYTES;
        for (start, len) in regions {
            if budget == 0 {
                break;
            }
            let scan_len = len.min(MAX_REGION_BYTES).min(budget);
            budget -= scan_len;

            let mut offset = start;
            let mut done = 0u64;
            while done < scan_len {
                let want = ((scan_len - done) as usize).min(CHUNK_BYTES);
                let mut buf = vec![0u8; want];
                match std::os::unix::fs::FileExt::read_at(&mem, &mut buf, offset) {
                    Ok(0) | Err(_) => break, // EOF or region shrank / died
                    Ok(n) => {
                        if let Ok(results) = self.rules.scan_mem(&buf[..n], SCAN_TIMEOUT_SECS) {
                            out.extend(results.into_iter().map(|r| mem_match(pid, r)));
                        }
                        done += n as u64;
                        offset += n as u64;
                    }
                }
            }
        }
        dedupe(out)
    }

    /// Non-Linux fallback: rules compile, but there is no `/proc` memory
    /// interface to scan.
    #[cfg(not(target_os = "linux"))]
    pub fn scan_process(&self, _pid: i32) -> Vec<MemMatch> {
        Vec::new()
    }
}

/// Parse `/proc/<pid>/maps` into `(start, length)` pairs for readable regions.
#[cfg(target_os = "linux")]
fn read_regions(pid: i32) -> std::io::Result<Vec<(u64, u64)>> {
    let data = std::fs::read(format!("/proc/{pid}/maps"))?;
    let maps = String::from_utf8_lossy(&data);
    let mut regions = Vec::new();
    for line in maps.lines() {
        let mut it = line.split_whitespace();
        let range = match it.next() {
            Some(r) => r,
            None => continue,
        };
        let perms = match it.next() {
            Some(p) => p,
            None => continue,
        };
        if !perms.contains('r') {
            continue; // write-only / execute-only regions are not readable
        }
        let (start, end) = match range.split_once('-') {
            Some((s, e)) => (
                u64::from_str_radix(s, 16).unwrap_or(0),
                u64::from_str_radix(e, 16).unwrap_or(0),
            ),
            None => continue,
        };
        if end > start {
            regions.push((start, end - start));
        }
    }
    Ok(regions)
}

/// Convert a scanned [`Rule`] (which borrows from the scan context) into an
/// owned [`MemMatch`].
fn mem_match(pid: i32, rule: Rule) -> MemMatch {
    let strings = rule
        .strings
        .iter()
        .map(|s| s.identifier.to_string())
        .collect();
    let mut meta = HashMap::new();
    for m in &rule.metadatas {
        let value = match &m.value {
            MetadataValue::Integer(i) => i.to_string(),
            MetadataValue::String(s) => s.to_string(),
            MetadataValue::Boolean(b) => b.to_string(),
        };
        meta.insert(m.identifier.to_string(), value);
    }
    MemMatch {
        pid,
        rule_name: rule.identifier.to_string(),
        strings,
        meta,
    }
}

/// Collapse identical matches reported from multiple regions of one process.
fn dedupe(out: Vec<MemMatch>) -> Vec<MemMatch> {
    let mut seen = HashSet::new();
    let mut res = Vec::new();
    for m in out {
        let key = serde_json::to_string(&m).unwrap_or_default();
        if seen.insert(key) {
            res.push(m);
        }
    }
    res
}

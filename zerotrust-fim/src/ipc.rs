//! Lightweight JSON-lines IPC over a Unix domain socket.
//!
//! Gives host orchestrators (systemd, the Control Center bridge, or a sidecar
//! in the FIM container) a zero-dependency way to pull live FIM events and
//! process anomalies. Each line is a self-describing JSON object:
//!
//!   {"path":"/etc/passwd","kind":"MODIFIED",...}
//!   {"files_scanned":4096,"alerts_emitted":3}

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::watch::FimEvent;

/// Serve the socket until the `shutdown` flag flips. `events` is the stream of
/// normalized FIM events; `aux` carries pre-serialized JSON values (exec
/// telemetry, memscan matches) that are broadcast verbatim alongside FIM
/// events; `stats` is the shared live-counter snapshot map.
#[cfg(unix)]
pub fn serve(
    socket_path: &str,
    events: std::sync::mpsc::Receiver<FimEvent>,
    aux: std::sync::mpsc::Receiver<serde_json::Value>,
    stats: Arc<std::sync::Mutex<serde_json::Value>>,
    shutdown: Arc<AtomicU64>,
) -> std::io::Result<()> {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::io::Write;

    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    log::info!("IPC socket listening at {socket_path}");

    listener.set_nonblocking(true)?;
    let mut clients: Vec<UnixStream> = Vec::new();

    loop {
        if shutdown.load(Ordering::Relaxed) != 0 {
            break;
        }

        // Accept any newly connecting client (non-blocking).
        loop {
            match listener.accept() {
                Ok((stream, _addr)) => {
                    let _ = stream.set_nonblocking(true);
                    let _ = stream
                        .set_write_timeout(Some(std::time::Duration::from_millis(200)));
                    clients.push(stream);
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }

        // Drain one pending FIM event (non-blocking) and broadcast it.
        if let Ok(fim) = events.try_recv() {
            if let Ok(line) = serde_json::to_string(&fim) {
                broadcast(&mut clients, &format!("{}\n", line));
            }
        }
        // Drain any pending auxiliary JSON lines (exec / memscan telemetry).
        while let Ok(value) = aux.try_recv() {
            if let Ok(line) = serde_json::to_string(&value) {
                broadcast(&mut clients, &format!("{}\n", line));
            }
        }
        // Periodic stats heartbeat so clients always have fresh data.
        if let Ok(s) = stats.try_lock() {
            broadcast(&mut clients, &format!("{}\n", *s));
        }

        std::thread::sleep(std::time::Duration::from_millis(25));
    }

    let _ = std::fs::remove_file(socket_path);
    Ok(())
}

#[cfg(not(unix))]
pub fn serve(
    _socket_path: &str,
    _events: std::sync::mpsc::Receiver<FimEvent>,
    _aux: std::sync::mpsc::Receiver<serde_json::Value>,
    _stats: Arc<std::sync::Mutex<serde_json::Value>>,
    _shutdown: Arc<AtomicU64>,
) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn broadcast(clients: &mut Vec<std::os::unix::net::UnixStream>, payload: &str) {
    use std::io::Write;
    clients.retain_mut(|c| match c.write_all(payload.as_bytes()) {
        Ok(_) => {
            let _ = c.flush();
            true
        }
        Err(_) => false, // dead client: drop it
    });
}
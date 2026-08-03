//! C ABI bindings for `aegis_core` (feature `ffi`).
//!
//! Purpose-built for embedding the FIM core into C/C++, and by extension into
//! other runtimes (Python via ctypes, Kotlin/JVM via JNA). The ABI is kept
//! trivial and allocation-free on the caller side: buffers are caller-owned.
//!
//! `aegis_core.h` mirrors these declarations 1:1.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::path::Path;

/// Compute a BLAKE3 digest for a file into a caller-owned buffer.
/// Returns 0 on success, nonzero on failure. `out_len` must be >= 64 bytes.
///
/// # Safety
/// `path` must be a valid NUL-terminated C string; `out` must point to at
/// least `out_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aegis_hash_file(
    path: *const c_char,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    if path.is_null() || out.is_null() || out_len < 65 {
        return 1;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(p) => p,
        Err(_) => return 2,
    };
    let digest = match crate::hasher::hash_file(Path::new(path)) {
        Ok(d) => d,
        Err(_) => return 3,
    };
    write_str(out, out_len, &digest)
}

/// Verify a file against a baseline digest string (hex).
/// Returns 0 = intact, 1 = modified, 2 = error.
///
/// # Safety
/// Both arguments must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn aegis_verify_file(
    path: *const c_char,
    baseline_hex: *const c_char,
) -> c_int {
    if path.is_null() || baseline_hex.is_null() {
        return 2;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(p) => p,
        Err(_) => return 2,
    };
    let baseline = match CStr::from_ptr(baseline_hex).to_str() {
        Ok(b) => b,
        Err(_) => return 2,
    };
    match crate::hasher::hash_file(Path::new(path)) {
        Ok(current) if current == baseline => 0,
        Ok(_) => 1,
        Err(_) => 2,
    }
}

/// Snapshot the current hash of a file as JSON into a caller buffer.
/// Returns 0 on success. `out_len` must be >= 512 bytes.
///
/// # Safety
/// Same buffer contract as `aegis_hash_file`.
#[no_mangle]
pub unsafe extern "C" fn aegis_snapshot_json(
    path: *const c_char,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    if path.is_null() || out.is_null() || out_len < 512 {
        return 1;
    }
    let path = match CStr::from_ptr(path).to_str() {
        Ok(p) => p,
        Err(_) => return 2,
    };
    let snap = match crate::hasher::snapshot(Path::new(path)) {
        Ok(s) => s,
        Err(_) => return 3,
    };
    let json = match serde_json::to_string(&snap) {
        Ok(j) => j,
        Err(_) => return 4,
    };
    write_str(out, out_len, &json)
}

fn write_str(out: *mut c_char, cap: usize, value: &str) -> c_int {
    if value.len() + 1 > cap {
        return 1;
    }
    let bytes = value.as_bytes();
    let ptr = out as *mut u8;
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        std::ptr::write(ptr.add(bytes.len()), 0);
    }
    0
}

/// Convenience: hash a byte slice (e.g., memory-mapped file) to hex.
/// Returns 0 on success.
///
/// # Safety
/// `data` must point to `len` readable bytes; `out` buffer must be >= 66 bytes.
#[no_mangle]
pub unsafe extern "C" fn aegis_hash_bytes(
    data: *const u8,
    len: usize,
    out: *mut c_char,
    out_len: usize,
) -> c_int {
    if data.is_null() || out.is_null() || out_len < 66 {
        return 1;
    }
    let slice = std::slice::from_raw_parts(data, len);
    let hex = crate::hasher::hash_bytes(slice);
    write_str(out, out_len, &hex)
}

/// Fetch the AegisX FIM library version string.
///
/// # Safety
/// `out` must point to at least 16 writable bytes.
#[no_mangle]
pub unsafe extern "C" fn aegis_version(out: *mut c_char, out_len: usize) -> c_int {
    if out.is_null() || out_len < 16 {
        return 1;
    }
    write_str(out, out_len, "aegis_core-0.1.0")
}

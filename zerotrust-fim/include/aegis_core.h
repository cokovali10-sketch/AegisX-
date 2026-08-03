/*!
 * AegisX ZeroTrust FIM Guard - C header.
 * Mirrors the `#[no_mangle]` exports in src/ffi.rs.
 * Compile with: rustup target add x86_64-unknown-linux-gnu
 *               cargo build --release --features ffi
 * Link:        cc app.c -laegis_core -L target/release
 */
#ifndef AEGIS_CORE_H
#define AEGIS_CORE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AEGIS_HASH_HEX_LEN    64
#define AEGIS_SNAPSHOT_BUF_LEN 512

/* Compute a BLAKE3 digest for a file. Returns 0 on success. */
int aegis_hash_file(const char *path, char *out, size_t out_len);

/* Verify a file against a baseline hex digest. 0=ok, 1=modified, 2=error. */
int aegis_verify_file(const char *path, const char *baseline_hex);

/* Snapshot path/hash/size/mtime/mode as JSON. Returns 0 on success. */
int aegis_snapshot_json(const char *path, char *out, size_t out_len);

/* Hash an in-memory byte buffer to hex. Returns 0 on success. */
int aegis_hash_bytes(const unsigned char *data, size_t len,
                     char *out, size_t out_len);

/* Fetch the library version string. Returns 0 on success. */
int aegis_version(char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* AEGIS_CORE_H */

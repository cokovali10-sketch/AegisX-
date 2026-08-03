// bpf_prog.c - AegisX ZeroTrust FIM execve interceptor (eBPF)
//
// The crate does NOT compile eBPF at build time. This source is embedded in
// the binary (see src/ebpf/mod.rs, BPF_PROG_SRC) for reference and is compiled
// out-of-band with clang into an object file that the daemon loads via aya:
//
//   clang -O2 -g -target bpf -Wall -c bpf_prog.c -o execve.bpf.o
//
// Build-time packages required (see Dockerfile notes):
//   - linux-libc-dev           (for <linux/bpf.h>)
//   - libbpf-dev or bpftool    (for <bpf/bpf_helpers.h>, the SEC() macro)
//   - clang >= 12 with BPF target support
//
// Runtime requirements:
//   - Linux kernel >= 5.8 (BPF ring buffer), BPF enabled, and either
//     CAP_BPF/CAP_SYS_ADMIN or an unprivileged BPF kernel setting that
//     permits tracepoint attachment.
//
// The program is attached by the daemon to the syscalls:sys_enter_execve
// tracepoint. Events are pushed into the `exec_events` ring buffer map with
// the layout below (decoded by parse_raw_event in src/ebpf/aya_impl.rs):
//
//   u32 pid; u32 ppid; u32 tgid; u32 uid;
//   u8  comm[16]; u8 filename[256]; u8 argv[512];

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define TASK_COMM_LEN 16
#define FILENAME_LEN 256
#define ARGV_LEN 512
#define MAX_ARGS 16

struct exec_event {
    __u32 pid;
    __u32 ppid;
    __u32 tgid;
    __u32 uid;
    __u8 comm[TASK_COMM_LEN];
    __u8 filename[FILENAME_LEN];
    __u8 argv[ARGV_LEN];
};

// Classic (non-BTF) map definition; aya parses this from the "maps" section
// without requiring BTF. 1 << 18 = 256 KiB ring buffer.
struct bpf_map_def SEC("maps") exec_events = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .key_size = 0,
    .value_size = 0,
    .max_entries = 1 << 18,
};

// Layout of the sys_enter_execve tracepoint context. See
// /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format. On all
// 64-bit targets trace_entry is 8 bytes, so filename/argv/envp sit at the
// offsets below. Adjust for 32-bit kernels if this is ever built for one.
struct sys_enter_execve_ctx {
    __u16 common_type;
    __u8 common_flags;
    __u8 common_preempt_count;
    __s32 common_pid;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

static __always_inline void read_user_str(__u8 *dst, const char *src, int cap) {
    long n = bpf_probe_read_user_str(dst, cap, src);
    if (n < 0)
        dst[0] = '\0';
}

SEC("tracepoint/syscalls/sys_enter_execve")
int execve_enter(struct sys_enter_execve_ctx *ctx) {
    struct exec_event *ev;
    long ret;
    int i, off = 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid = bpf_get_current_uid_gid();

    ev = bpf_ringbuf_reserve(&exec_events, sizeof(struct exec_event), 0);
    if (!ev)
        return 0;

    ev->pid = (__u32)pid_tgid;
    ev->tgid = (__u32)(pid_tgid >> 32);
    // ppid requires walking task_struct; it is filled in by the /proc
    // fallback path instead.
    ev->ppid = 0;
    ev->uid = (__u32)uid_gid;

    ret = bpf_get_current_comm(ev->comm, TASK_COMM_LEN);
    if (ret < 0)
        ev->comm[0] = '\0';

    read_user_str(ev->filename, ctx->filename, FILENAME_LEN);

    // Copy the argv vector (truncated at ARGV_LEN). Each probe read is
    // NUL-terminated by the helper, so the buffer is always well-formed.
    for (i = 0; i < MAX_ARGS && off < ARGV_LEN; i++) {
        const char *arg = NULL;
        long n;
        if (bpf_probe_read_user(&arg, sizeof(arg), &ctx->argv[i]) < 0)
            break;
        if (!arg)
            break;
        n = bpf_probe_read_user_str(ev->argv + off, ARGV_LEN - off, arg);
        if (n <= 0)
            break;
        off += (int)n;
    }
    if (off < ARGV_LEN)
        ev->argv[off] = '\0';

    bpf_ringbuf_submit(ev, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";

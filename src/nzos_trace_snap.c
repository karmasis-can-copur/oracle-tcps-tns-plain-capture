#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct bp {
    const char *name;
    unsigned long addr;
    unsigned long orig_word;
    int enabled;
};

static pid_t g_pid;
static const char *g_outdir = "/tmp/oracle_nzos_snapshots";
static FILE *g_log;

static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
    if (g_log) {
        va_start(ap, fmt);
        vfprintf(g_log, fmt, ap);
        va_end(ap);
        fputc('\n', g_log);
        fflush(g_log);
    }
}

static int is_user_ptr(unsigned long x)
{
    return x >= 0x10000UL && x < 0x0000800000000000UL;
}

static ssize_t read_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static int read_u64(pid_t pid, unsigned long addr, unsigned long *out)
{
    unsigned long v = 0;
    ssize_t n = read_mem(pid, addr, &v, sizeof(v));
    if (n != (ssize_t)sizeof(v))
        return -1;
    *out = v;
    return 0;
}

static unsigned long ptrace_peek(pid_t pid, unsigned long addr)
{
    errno = 0;
    unsigned long v = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
    if (errno)
        die("PTRACE_PEEKTEXT 0x%lx failed: %s", addr, strerror(errno));
    return v;
}

static void ptrace_poke(pid_t pid, unsigned long addr, unsigned long word)
{
    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)word) != 0)
        die("PTRACE_POKETEXT 0x%lx failed: %s", addr, strerror(errno));
}

static void bp_enable(pid_t pid, struct bp *bp)
{
    if (bp->enabled)
        return;
    bp->orig_word = ptrace_peek(pid, bp->addr);
    unsigned long trap_word = (bp->orig_word & ~0xffUL) | 0xcc;
    ptrace_poke(pid, bp->addr, trap_word);
    bp->enabled = 1;
}

static void bp_disable(pid_t pid, struct bp *bp)
{
    if (!bp->enabled)
        return;
    ptrace_poke(pid, bp->addr, bp->orig_word);
    bp->enabled = 0;
}

static unsigned long find_lib_base(pid_t pid, const char *needle)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        die("open %s failed: %s", path, strerror(errno));

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0, off = 0;
        char perms[8] = {0};
        char map_path[PATH_MAX] = {0};
        int got = sscanf(line, "%lx-%lx %7s %lx %*s %*s %4095s", &start, &end, perms, &off, map_path);
        if (got >= 4 && strstr(line, needle) && off == 0) {
            fclose(f);
            return start;
        }
    }
    fclose(f);
    return 0;
}

static void hex_preview(const unsigned char *buf, ssize_t n, char *out, size_t outsz)
{
    size_t pos = 0;
    ssize_t limit = n < 32 ? n : 32;
    for (ssize_t i = 0; i < limit && pos + 4 < outsz; i++)
        pos += snprintf(out + pos, outsz - pos, "%02x ", buf[i]);
    if (pos > 0 && pos < outsz)
        out[pos - 1] = '\0';
}

static long find_bytes(const unsigned char *buf, ssize_t n, const unsigned char *pat, size_t patlen)
{
    if (n < 0 || (size_t)n < patlen)
        return -1;
    for (ssize_t i = 0; i <= n - (ssize_t)patlen; i++) {
        if (memcmp(buf + i, pat, patlen) == 0)
            return i;
    }
    return -1;
}

static long find_be_len(const unsigned char *buf, ssize_t n, unsigned long len)
{
    unsigned char pat[2];
    pat[0] = (unsigned char)((len >> 8) & 0xff);
    pat[1] = (unsigned char)(len & 0xff);
    return find_bytes(buf, n, pat, 2);
}

static void dump_region(int ev, const char *func, unsigned long len, const char *label,
                        unsigned long addr, size_t want)
{
    if (!is_user_ptr(addr) || want == 0)
        return;
    if (want > 65536)
        want = 65536;

    unsigned char *buf = calloc(1, want);
    if (!buf)
        return;

    ssize_t n = read_mem(g_pid, addr, buf, want);
    if (n <= 0) {
        free(buf);
        return;
    }

    char fname[PATH_MAX];
    snprintf(fname, sizeof(fname), "%s/event_%04d_%s_len%lu_%s_0x%lx.bin",
             g_outdir, ev, func, len, label, addr);
    int fd = open(fname, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) {
        (void)write(fd, buf, (size_t)n);
        close(fd);
    }

    char prev[128] = {0};
    hex_preview(buf, n, prev, sizeof(prev));
    long marker = find_bytes(buf, n, (const unsigned char *)"KARMASIS_TCPS_LOOP", 18);
    long belen = find_be_len(buf, n, len);
    logmsg("  dump %-18s addr=0x%lx want=%zu got=%zd be_len_at=%ld marker_at=%ld first=[%s] file=%s",
           label, addr, want, n, belen, marker, prev, fname);

    free(buf);
}

static void dump_event(int ev, const char *func, struct user_regs_struct *regs)
{
    unsigned long len = regs->rcx;
    unsigned long desc = regs->rdx;
    unsigned long q[16] = {0};
    for (int i = 0; i < 16; i++)
        (void)read_u64(g_pid, desc + (unsigned long)i * 8, &q[i]);

    unsigned long d_q32 = 0, d_q40 = 0, d_q48 = 0;
    if (is_user_ptr(q[4]))
        (void)read_u64(g_pid, q[4], &d_q32);
    if (is_user_ptr(q[5]))
        (void)read_u64(g_pid, q[5], &d_q40);
    if (is_user_ptr(q[6]))
        (void)read_u64(g_pid, q[6], &d_q48);

    char meta[PATH_MAX];
    snprintf(meta, sizeof(meta), "%s/event_%04d_%s_len%lu_meta.txt", g_outdir, ev, func, len);
    FILE *mf = fopen(meta, "w");
    if (mf) {
        fprintf(mf, "event=%d pid=%d func=%s len=%lu desc=0x%lx\n", ev, g_pid, func, len, desc);
        fprintf(mf, "regs rdi=0x%llx rsi=0x%llx rdx=0x%llx rcx=0x%llx r8=0x%llx r9=0x%llx rip=0x%llx rsp=0x%llx\n",
                regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8, regs->r9, regs->rip, regs->rsp);
        for (int i = 0; i < 16; i++)
            fprintf(mf, "q%-2d +%-3d = 0x%016lx (%lu)\n", i, i * 8, q[i], q[i]);
        fprintf(mf, "deref q32=0x%lx q40=0x%lx q48=0x%lx\n", d_q32, d_q40, d_q48);
        fclose(mf);
    }

    logmsg("event=%04d func=%s len=%lu desc=0x%lx q0=%lu q16=%lu q32=0x%lx q40=0x%lx q48=0x%lx deref_q48=0x%lx",
           ev, func, len, desc, q[0], q[2], q[4], q[5], q[6], d_q48);

    size_t small = (len > 0 && len < 32768) ? (size_t)len + 1024 : 12288;
    if (small < 4096)
        small = 4096;

    dump_region(ev, func, len, "desc", desc, 512);
    dump_region(ev, func, len, "desc_minus256", desc > 256 ? desc - 256 : desc, 1024);
    dump_region(ev, func, len, "q32_minus512", is_user_ptr(q[4]) && q[4] > 512 ? q[4] - 512 : q[4], small);
    dump_region(ev, func, len, "q40_minus512", is_user_ptr(q[5]) && q[5] > 512 ? q[5] - 512 : q[5], small);
    dump_region(ev, func, len, "q48_minus512", is_user_ptr(q[6]) && q[6] > 512 ? q[6] - 512 : q[6], small);
    dump_region(ev, func, len, "deref_q32_minus512", is_user_ptr(d_q32) && d_q32 > 512 ? d_q32 - 512 : d_q32, small);
    dump_region(ev, func, len, "deref_q40_minus512", is_user_ptr(d_q40) && d_q40 > 512 ? d_q40 - 512 : d_q40, small);
    dump_region(ev, func, len, "deref_q48_minus512", is_user_ptr(d_q48) && d_q48 > 512 ? d_q48 - 512 : d_q48, small);
    dump_region(ev, func, len, "deref_q48", d_q48, 8192);
}

static void usage(const char *argv0)
{
    fprintf(stderr, "usage: %s <pid> <write_off_hex> [read_off_hex] [max_events] [outdir]\n", argv0);
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        usage(argv[0]);
        return 2;
    }
    g_pid = (pid_t)strtol(argv[1], NULL, 10);
    unsigned long write_off = strtoul(argv[2], NULL, 16);
    unsigned long read_off = argc >= 4 ? strtoul(argv[3], NULL, 16) : 0;
    int max_events = argc >= 5 ? atoi(argv[4]) : 20;
    if (argc >= 6)
        g_outdir = argv[5];

    if (mkdir(g_outdir, 0755) != 0 && errno != EEXIST)
        die("mkdir %s failed: %s", g_outdir, strerror(errno));

    char logpath[PATH_MAX];
    snprintf(logpath, sizeof(logpath), "%s/trace.log", g_outdir);
    g_log = fopen(logpath, "a");

    unsigned long base = find_lib_base(g_pid, "libnnzsrv.so");
    if (!base)
        die("libnnzsrv.so not mapped in pid %d", g_pid);

    struct bp bps[2];
    int nbp = 0;
    bps[nbp++] = (struct bp){ .name = "nzos_Write", .addr = base + write_off };
    if (read_off)
        bps[nbp++] = (struct bp){ .name = "nzos_Read", .addr = base + read_off };

    logmsg("pid=%d libnnzsrv_base=0x%lx write_addr=0x%lx read_addr=0x%lx max_events=%d outdir=%s",
           g_pid, base, bps[0].addr, nbp > 1 ? bps[1].addr : 0, max_events, g_outdir);

    if (ptrace(PTRACE_ATTACH, g_pid, NULL, NULL) != 0)
        die("PTRACE_ATTACH %d failed: %s", g_pid, strerror(errno));
    int status = 0;
    waitpid(g_pid, &status, 0);

    for (int i = 0; i < nbp; i++)
        bp_enable(g_pid, &bps[i]);

    if (ptrace(PTRACE_CONT, g_pid, NULL, NULL) != 0)
        die("PTRACE_CONT failed: %s", strerror(errno));

    int events = 0;
    while (events < max_events) {
        if (waitpid(g_pid, &status, 0) < 0)
            die("waitpid failed: %s", strerror(errno));
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            logmsg("tracee exited");
            break;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        int sig = WSTOPSIG(status);
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, g_pid, NULL, &regs) != 0)
            die("PTRACE_GETREGS failed: %s", strerror(errno));

        struct bp *hit = NULL;
        unsigned long trap_addr = regs.rip - 1;
        if (sig == SIGTRAP) {
            for (int i = 0; i < nbp; i++) {
                if (trap_addr == bps[i].addr) {
                    hit = &bps[i];
                    break;
                }
            }
        }

        if (!hit) {
            if (ptrace(PTRACE_CONT, g_pid, NULL, (void *)(long)sig) != 0)
                die("PTRACE_CONT signal failed: %s", strerror(errno));
            continue;
        }

        bp_disable(g_pid, hit);
        regs.rip = hit->addr;
        if (ptrace(PTRACE_SETREGS, g_pid, NULL, &regs) != 0)
            die("PTRACE_SETREGS failed: %s", strerror(errno));

        events++;
        dump_event(events, hit->name, &regs);

        if (ptrace(PTRACE_SINGLESTEP, g_pid, NULL, NULL) != 0)
            die("PTRACE_SINGLESTEP failed: %s", strerror(errno));
        waitpid(g_pid, &status, 0);
        bp_enable(g_pid, hit);

        if (ptrace(PTRACE_CONT, g_pid, NULL, NULL) != 0)
            die("PTRACE_CONT loop failed: %s", strerror(errno));
    }

    for (int i = 0; i < nbp; i++)
        bp_disable(g_pid, &bps[i]);
    ptrace(PTRACE_DETACH, g_pid, NULL, NULL);
    logmsg("done events=%d", events);
    if (g_log)
        fclose(g_log);
    return 0;
}

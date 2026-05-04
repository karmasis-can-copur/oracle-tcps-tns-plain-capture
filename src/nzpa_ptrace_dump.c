#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static ssize_t read_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t fnv1a64(const unsigned char *p, size_t n)
{
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static int read_u32(pid_t pid, unsigned long addr, uint32_t *out)
{
    uint32_t v = 0;
    ssize_t n = read_mem(pid, addr, &v, sizeof(v));
    if (n != (ssize_t)sizeof(v))
        return -1;
    *out = v;
    return 0;
}

static unsigned long find_lib_base(pid_t pid, const char *needle)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;

    char line[4096];
    while (fgets(line, sizeof(line), f)) {
        unsigned long start = 0, end = 0, off = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &off) == 4 &&
            off == 0 && strstr(line, needle)) {
            fclose(f);
            return start;
        }
    }
    fclose(f);
    return 0;
}

static unsigned long peek_text(pid_t pid, unsigned long addr)
{
    errno = 0;
    unsigned long v = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
    if (errno) {
        fprintf(stderr, "PTRACE_PEEKTEXT 0x%lx: %s\n", addr, strerror(errno));
        exit(1);
    }
    return v;
}

static void poke_text(pid_t pid, unsigned long addr, unsigned long word)
{
    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)word) != 0) {
        fprintf(stderr, "PTRACE_POKETEXT 0x%lx: %s\n", addr, strerror(errno));
        exit(1);
    }
}

static int write_all(int fd, const void *buf, size_t n)
{
    const unsigned char *p = buf;
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static int dump_packet(pid_t pid, int event_no, unsigned long buf_addr, uint32_t len,
                       const char *outdir, FILE *index, int aggregate_fd)
{
    if (len < 8 || len > 65535)
        return 0;
    unsigned char *buf = malloc(len);
    if (!buf)
        return 0;
    ssize_t n = read_mem(pid, buf_addr, buf, len);
    if (n != (ssize_t)len) {
        free(buf);
        return 0;
    }

    unsigned be32 = ((unsigned)buf[0] << 24) | ((unsigned)buf[1] << 16) |
                    ((unsigned)buf[2] << 8) | buf[3];
    if (be32 != len) {
        free(buf);
        return 0;
    }

    uint64_t ts = now_ns();
    uint64_t h = fnv1a64(buf, len);
    char pkt_path[PATH_MAX];
    snprintf(pkt_path, sizeof(pkt_path), "%s/%" PRIu64 "_%d_server_to_client_%u.bin",
             outdir, ts, pid, len);
    int fd = open(pkt_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd >= 0) {
        (void)write_all(fd, buf, len);
        close(fd);
    }

    uint32_t magic = 0x4f50544eU;
    uint32_t pid32 = (uint32_t)pid;
    uint32_t len32 = len;
    (void)write_all(aggregate_fd, &magic, sizeof(magic));
    (void)write_all(aggregate_fd, &ts, sizeof(ts));
    (void)write_all(aggregate_fd, &pid32, sizeof(pid32));
    (void)write_all(aggregate_fd, &len32, sizeof(len32));
    (void)write_all(aggregate_fd, buf, len);

    fprintf(index, "%" PRIu64 "\t%d\tnzpa_ssl_Write\tserver_to_client\t%u\t0x%lx\t0x%016" PRIx64 "\t%s\n",
            ts, pid, len, buf_addr, h, pkt_path);
    fflush(index);
    printf("event=%d captured len=%u buf=0x%lx hash=0x%016" PRIx64 " file=%s\n",
           event_no, len, buf_addr, h, pkt_path);
    fflush(stdout);
    free(buf);
    return 1;
}

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pid> <nzpa_ssl_Write_offset_hex> <max_events> [outdir]\n", argv[0]);
        return 2;
    }

    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    unsigned long off = strtoul(argv[2], NULL, 16);
    int max_events = atoi(argv[3]);
    const char *outdir = argc >= 5 ? argv[4] : "/tmp/oracle_plain_packets_hook";

    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir outdir");
        return 1;
    }
    char index_path[PATH_MAX];
    snprintf(index_path, sizeof(index_path), "%s/index.tsv", outdir);
    FILE *index = fopen(index_path, "w");
    if (!index) {
        perror("index");
        return 1;
    }
    fprintf(index, "timestamp_ns\tpid\tfunction\tdirection\tlength\tbuf_addr\thash\tfile\n");

    char agg_path[PATH_MAX];
    snprintf(agg_path, sizeof(agg_path), "%s/oracle_plain_packets_hook.bin", outdir);
    int aggregate_fd = open(agg_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (aggregate_fd < 0) {
        perror("aggregate");
        return 1;
    }

    unsigned long base = find_lib_base(pid, "libnnzsrv.so");
    if (!base) {
        fprintf(stderr, "libnnzsrv.so not found in pid %d\n", pid);
        return 1;
    }
    unsigned long addr = base + off;
    fprintf(stderr, "pid=%d base=0x%lx nzpa_ssl_Write=0x%lx max_events=%d\n", pid, base, addr, max_events);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        perror("PTRACE_ATTACH");
        return 1;
    }
    int status = 0;
    waitpid(pid, &status, 0);

    unsigned long orig = peek_text(pid, addr);
    poke_text(pid, addr, (orig & ~0xffUL) | 0xcc);

    int captured = 0;
    int seen = 0;
    bool bp_enabled = true;
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
        perror("PTRACE_CONT");
        return 1;
    }

    while (seen < max_events) {
        if (waitpid(pid, &status, 0) < 0) {
            perror("waitpid");
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            fprintf(stderr, "tracee exited while tracing\n");
            bp_enabled = false;
            break;
        }
        if (!WIFSTOPPED(status)) {
            continue;
        }

        int sig = WSTOPSIG(status);
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0) {
            perror("PTRACE_GETREGS");
            break;
        }

        if (sig == SIGTRAP && regs.rip - 1 == addr) {
            seen++;
            poke_text(pid, addr, orig);
            bp_enabled = false;
            regs.rip = addr;
            if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) != 0) {
                perror("PTRACE_SETREGS");
                break;
            }

            uint32_t len = 0;
            if (read_u32(pid, regs.rdx, &len) == 0)
                captured += dump_packet(pid, seen, regs.rsi, len, outdir, index, aggregate_fd);

            if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) != 0) {
                perror("PTRACE_SINGLESTEP");
                break;
            }
            if (waitpid(pid, &status, 0) < 0) {
                perror("waitpid singlestep");
                break;
            }
            if (WIFEXITED(status) || WIFSIGNALED(status)) {
                fprintf(stderr, "tracee exited after singlestep\n");
                break;
            }
            if (seen >= max_events)
                break;

            poke_text(pid, addr, (orig & ~0xffUL) | 0xcc);
            bp_enabled = true;
            if (ptrace(PTRACE_CONT, pid, NULL, NULL) != 0) {
                perror("PTRACE_CONT hit");
                break;
            }
        } else {
            if (ptrace(PTRACE_CONT, pid, NULL, (void *)(long)sig) != 0) {
                perror("PTRACE_CONT signal");
                break;
            }
        }
    }

    if (bp_enabled)
        poke_text(pid, addr, orig);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    close(aggregate_fd);
    fclose(index);
    fprintf(stderr, "done seen=%d captured=%d outdir=%s aggregate=%s\n", seen, captured, outdir, agg_path);
    return captured > 0 ? 0 : 1;
}

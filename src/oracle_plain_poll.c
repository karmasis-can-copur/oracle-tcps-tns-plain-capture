#define _GNU_SOURCE
#include <sys/uio.h>
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

static volatile sig_atomic_t stop_now;

static void on_signal(int sig)
{
    (void)sig;
    stop_now = 1;
}

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

static int plausible_tns_type(unsigned type)
{
    switch (type) {
    case 1: case 2: case 3: case 4: case 5: case 6: case 7:
    case 9: case 11: case 12: case 14:
        return 1;
    default:
        return 0;
    }
}

static int detect_packet(const unsigned char *buf, size_t n, size_t *start, size_t *plen)
{
    if (n >= 10) {
        unsigned len4 = ((unsigned)buf[0] << 24) | ((unsigned)buf[1] << 16) |
                        ((unsigned)buf[2] << 8) | buf[3];
        if (len4 >= 8 && len4 <= 32767 && len4 <= n && plausible_tns_type(buf[4])) {
            *start = 0;
            *plen = len4;
            return 1;
        }
        unsigned len0 = ((unsigned)buf[0] << 8) | buf[1];
        if (len0 >= 8 && len0 <= 32767 && len0 <= n && plausible_tns_type(buf[4])) {
            *start = 0;
            *plen = len0;
            return 1;
        }
        unsigned len2 = ((unsigned)buf[2] << 8) | buf[3];
        if (buf[0] == 0 && buf[1] == 0 && len2 >= 8 && len2 <= 32767 &&
            len2 + 2 <= n && plausible_tns_type(buf[4])) {
            *start = 2;
            *plen = len2;
            return 1;
        }
    }
    return 0;
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

int main(int argc, char **argv)
{
    if (argc < 4) {
        fprintf(stderr, "usage: %s <pid> <buf_addr> <seconds> [outdir] [poll_us] [function] [direction] [aggregate_path]\n", argv[0]);
        return 2;
    }

    pid_t pid = (pid_t)strtol(argv[1], NULL, 10);
    unsigned long addr = strtoul(argv[2], NULL, 0);
    int seconds = atoi(argv[3]);
    const char *outdir = argc >= 5 ? argv[4] : "/tmp/oracle_plain_packets";
    useconds_t poll_us = argc >= 6 ? (useconds_t)strtoul(argv[5], NULL, 0) : 10000;
    const char *function = argc >= 7 ? argv[6] : "nzpa_ssl_Write";
    const char *direction = argc >= 8 ? argv[7] : "server_to_client";

    if (mkdir(outdir, 0755) != 0 && errno != EEXIST) {
        perror("mkdir outdir");
        return 1;
    }

    char index_path[PATH_MAX];
    snprintf(index_path, sizeof(index_path), "%s/index.tsv", outdir);
    FILE *index = fopen(index_path, "a");
    if (!index) {
        perror("open index");
        return 1;
    }
    fprintf(index, "timestamp_ns\tpid\tfunction\tdirection\tlength\tbuf_addr\tpacket_offset\thash\tfile\n");
    fflush(index);

    char aggregate_path[PATH_MAX];
    snprintf(aggregate_path, sizeof(aggregate_path), "%s",
             argc >= 9 ? argv[8] : "/tmp/oracle_plain_packets.bin");
    int aggregate_fd = open(aggregate_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (aggregate_fd < 0) {
        perror("open aggregate");
        return 1;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    const size_t cap = 65536;
    unsigned char *buf = malloc(cap);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    uint64_t end = now_ns() + (uint64_t)seconds * 1000000000ULL;
    uint64_t last_hash = 0;
    size_t last_len = 0;
    int count = 0;

    while (!stop_now && now_ns() < end) {
        ssize_t n = read_mem(pid, addr, buf, cap);
        if (n <= 0) {
            fprintf(stderr, "read_mem failed: %s\n", strerror(errno));
            usleep(poll_us);
            continue;
        }
        size_t start = 0, plen = 0;
        if (!detect_packet(buf, (size_t)n, &start, &plen)) {
            usleep(poll_us);
            continue;
        }

        const unsigned char *packet = buf + start;
        uint64_t h = fnv1a64(packet, plen);
        if (h == last_hash && plen == last_len) {
            usleep(poll_us);
            continue;
        }
        last_hash = h;
        last_len = plen;

        uint64_t ts = now_ns();
        char pkt_path[PATH_MAX];
        snprintf(pkt_path, sizeof(pkt_path), "%s/%" PRIu64 "_%d_%s_%zu.bin",
                 outdir, ts, pid, direction, plen);
        int fd = open(pkt_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (fd >= 0) {
            (void)write_all(fd, packet, plen);
            close(fd);
        }

        uint32_t magic = 0x4f50544eU; /* NTPO, little endian marker for this PoC container */
        uint64_t ts_le = ts;
        uint32_t pid_le = (uint32_t)pid;
        uint32_t len_le = (uint32_t)plen;
        (void)write_all(aggregate_fd, &magic, sizeof(magic));
        (void)write_all(aggregate_fd, &ts_le, sizeof(ts_le));
        (void)write_all(aggregate_fd, &pid_le, sizeof(pid_le));
        (void)write_all(aggregate_fd, &len_le, sizeof(len_le));
        (void)write_all(aggregate_fd, packet, plen);

        fprintf(index, "%" PRIu64 "\t%d\t%s\t%s\t%zu\t0x%lx\t%zu\t0x%016" PRIx64 "\t%s\n",
                ts, pid, function, direction, plen, addr, start, h, pkt_path);
        fflush(index);
        printf("captured count=%d ts=%" PRIu64 " len=%zu start=%zu hash=0x%016" PRIx64 " file=%s\n",
               ++count, ts, plen, start, h, pkt_path);
        fflush(stdout);

        usleep(poll_us);
    }

    close(aggregate_fd);
    fclose(index);
    free(buf);
    fprintf(stderr, "done captured=%d outdir=%s aggregate=%s\n", count, outdir, aggregate_path);
    return count > 0 ? 0 : 1;
}

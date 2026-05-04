#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <limits.h>
#include <inttypes.h>
#include <stddef.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ORACLE_HOME "/opt/oracle/product/26ai/dbhomeFree"
#define DEFAULT_PORT 2484
#define DEFAULT_OUT "/tmp/oracle_plain_tcps.pcap"
#define MAX_SESSIONS 4096
#define MAX_PACKET_LEN 262144U
#define TCP_ESTABLISHED 1

#define LIBNNZSRV "libnnzsrv.so"
#define LIBNNZ "libnnz.so"
#define LIBNNZSRV_NZPA_SSL_WRITE 0x11c570UL
#define LIBNNZSRV_NZOS_READ 0x137a70UL
#define LIBNNZ_NZPA_SSL_WRITE 0x11b250UL
#define LIBNNZ_NZOS_READ 0x136750UL
#define NZOS_READ_SUCCESS_DELTA 0xfcUL

#ifndef BPF_F_CURRENT_CPU
#define BPF_F_CURRENT_CPU 0xffffffffULL
#endif

static volatile sig_atomic_t g_stop;
static int g_ack_data_frames;
static uint64_t g_bpf_events;
static uint64_t g_bad_bpf_events;
static uint64_t g_listener_filtered;
static uint64_t g_capture_dropped;
static uint64_t g_lost_records;

enum capture_source {
    SRC_DEDICATED,
    SRC_LISTENER
};

enum packet_format {
    PKT_UNKNOWN,
    PKT_TNS16,
    PKT_NS32
};

struct endpoint {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
};

struct session {
    pid_t first_pid;
    pid_t last_pid;
    int active;
    int handshake_written;
    int fin_written;
    uint32_t seq_cli;
    uint32_t seq_srv;
    uint16_t ip_id;
    uint64_t packets;
    uint64_t bytes;
    time_t last_seen;
    unsigned long dedicated_ctx;
    unsigned long listener_ctx;
    struct endpoint ep;
};

struct pcap_hdr {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

struct pcaprec_hdr {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

static uint16_t csum16(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += ((uint16_t)p[0] << 8) | p[1];
        p += 2;
        len -= 2;
    }
    if (len)
        sum += (uint16_t)p[0] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static ssize_t read_mem(pid_t pid, unsigned long addr, void *buf, size_t len)
{
    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void *)addr, .iov_len = len };
    return process_vm_readv(pid, &local, 1, &remote, 1, 0);
}

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int is_numeric(const char *s)
{
    if (!*s)
        return 0;
    for (; *s; s++) {
        if (!isdigit((unsigned char)*s))
            return 0;
    }
    return 1;
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t be16(const uint8_t *p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

static uint32_t be32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static int valid_tns_type(uint8_t type)
{
    switch (type) {
    case 1:  /* CONNECT */
    case 2:  /* ACCEPT */
    case 3:  /* ACK */
    case 4:  /* REFUSE */
    case 5:  /* REDIRECT */
    case 6:  /* DATA */
    case 7:  /* NULL */
    case 9:  /* ABORT */
    case 11: /* RESEND */
    case 12: /* MARKER */
    case 13: /* ATTENTION */
    case 14: /* CONTROL */
    case 15:
    case 16:
        return 1;
    default:
        return 0;
    }
}

static enum packet_format packet_format(const uint8_t *buf, uint32_t len)
{
    if (len >= 8 && be16(buf) == len && valid_tns_type(buf[4]))
        return PKT_TNS16;
    if (len >= 5 && be32(buf) == len && valid_tns_type(buf[4]))
        return PKT_NS32;
    return PKT_UNKNOWN;
}

static const char *packet_format_name(enum packet_format fmt)
{
    switch (fmt) {
    case PKT_TNS16:
        return "tns16";
    case PKT_NS32:
        return "ns32";
    default:
        return "unknown";
    }
}

static int write_pcap_header(const char *path)
{
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0)
        return -1;
    struct pcap_hdr hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = MAX_PACKET_LEN,
        .network = 1
    };
    int rc = write_all(fd, &hdr, sizeof(hdr));
    close(fd);
    return rc;
}

static int append_tcp_frame(int fd, struct session *s, int server_to_client,
                            uint8_t flags, const uint8_t *payload, uint32_t payload_len)
{
    uint32_t src_ip = server_to_client ? s->ep.server_ip : s->ep.client_ip;
    uint32_t dst_ip = server_to_client ? s->ep.client_ip : s->ep.server_ip;
    uint16_t src_port = server_to_client ? s->ep.server_port : s->ep.client_port;
    uint16_t dst_port = server_to_client ? s->ep.client_port : s->ep.server_port;
    uint32_t seq = server_to_client ? s->seq_srv : s->seq_cli;
    uint32_t ack = server_to_client ? s->seq_cli : s->seq_srv;

    size_t frame_len = 14 + 20 + 20 + payload_len;
    uint8_t *frame = calloc(1, frame_len);
    if (!frame)
        return -1;

    uint8_t *eth = frame;
    uint8_t *ip = frame + 14;
    uint8_t *tcp = ip + 20;
    uint8_t *data = tcp + 20;

    const uint8_t mac_cli[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
    const uint8_t mac_srv[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    memcpy(eth, server_to_client ? mac_cli : mac_srv, 6);
    memcpy(eth + 6, server_to_client ? mac_srv : mac_cli, 6);
    eth[12] = 0x08;
    eth[13] = 0x00;

    ip[0] = 0x45;
    put16(ip + 2, (uint16_t)(20 + 20 + payload_len));
    put16(ip + 4, s->ip_id++);
    put16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = 6;
    memcpy(ip + 12, &src_ip, 4);
    memcpy(ip + 16, &dst_ip, 4);
    put16(ip + 10, csum16(ip, 20));

    put16(tcp, src_port);
    put16(tcp + 2, dst_port);
    put32(tcp + 4, seq);
    put32(tcp + 8, ack);
    tcp[12] = 0x50;
    tcp[13] = flags;
    put16(tcp + 14, 65535);
    if (payload_len)
        memcpy(data, payload, payload_len);

    size_t pseudo_len = 12 + 20 + payload_len;
    uint8_t *pseudo = calloc(1, pseudo_len);
    if (pseudo) {
        memcpy(pseudo, &src_ip, 4);
        memcpy(pseudo + 4, &dst_ip, 4);
        pseudo[9] = 6;
        put16(pseudo + 10, (uint16_t)(20 + payload_len));
        memcpy(pseudo + 12, tcp, 20 + payload_len);
        put16(tcp + 16, csum16(pseudo, pseudo_len));
        free(pseudo);
    }

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct pcaprec_hdr rh = {
        .ts_sec = (uint32_t)ts.tv_sec,
        .ts_usec = (uint32_t)(ts.tv_nsec / 1000),
        .incl_len = (uint32_t)frame_len,
        .orig_len = (uint32_t)frame_len
    };

    flock(fd, LOCK_EX);
    int rc = write_all(fd, &rh, sizeof(rh));
    if (rc == 0)
        rc = write_all(fd, frame, frame_len);
    flock(fd, LOCK_UN);
    free(frame);
    if (rc != 0)
        return rc;

    uint32_t advance = payload_len;
    if (flags & 0x02)
        advance++;
    if (flags & 0x01)
        advance++;
    if (server_to_client)
        s->seq_srv += advance;
    else
        s->seq_cli += advance;
    return 0;
}

static void write_handshake(int fd, struct session *s)
{
    if (s->handshake_written)
        return;
    append_tcp_frame(fd, s, 0, 0x02, NULL, 0);
    append_tcp_frame(fd, s, 1, 0x12, NULL, 0);
    append_tcp_frame(fd, s, 0, 0x10, NULL, 0);
    s->handshake_written = 1;
}

static void write_fin(int fd, struct session *s)
{
    if (!s->active || s->fin_written || !s->handshake_written)
        return;
    append_tcp_frame(fd, s, 0, 0x11, NULL, 0);
    append_tcp_frame(fd, s, 1, 0x11, NULL, 0);
    append_tcp_frame(fd, s, 0, 0x10, NULL, 0);
    s->fin_written = 1;
    s->active = 0;
}

struct tcp_entry {
    unsigned long inode;
    uint32_t lip;
    uint32_t rip;
    uint16_t lport;
    uint16_t rport;
    uint8_t state;
};

static int parse_tcp4(struct tcp_entry *entries, int max_entries)
{
    FILE *fp = fopen("/proc/net/tcp", "r");
    if (!fp)
        return 0;
    char line[1024];
    int count = 0;
    (void)fgets(line, sizeof(line), fp);
    while (fgets(line, sizeof(line), fp) && count < max_entries) {
        char *tok[16] = {0};
        int ntok = 0;
        char *save = NULL;
        for (char *p = strtok_r(line, " \t\n", &save); p && ntok < 16; p = strtok_r(NULL, " \t\n", &save))
            tok[ntok++] = p;
        if (ntok < 10)
            continue;
        char *colon = strchr(tok[1], ':');
        char *rcolon = strchr(tok[2], ':');
        if (!colon || !rcolon)
            continue;
        *colon = 0;
        *rcolon = 0;
        entries[count].lip = (uint32_t)strtoul(tok[1], NULL, 16);
        entries[count].lport = (uint16_t)strtoul(colon + 1, NULL, 16);
        entries[count].rip = (uint32_t)strtoul(tok[2], NULL, 16);
        entries[count].rport = (uint16_t)strtoul(rcolon + 1, NULL, 16);
        entries[count].state = (uint8_t)strtoul(tok[3], NULL, 16);
        entries[count].inode = strtoul(tok[9], NULL, 10);
        count++;
    }
    fclose(fp);
    return count;
}

static int tcp_entry_to_endpoint(const struct tcp_entry *e, int tcps_port, struct endpoint *ep)
{
    if (e->state != TCP_ESTABLISHED || e->rip == 0 || e->rport == 0)
        return -1;
    if (e->lport == (uint16_t)tcps_port) {
        ep->server_ip = e->lip;
        ep->server_port = e->lport;
        ep->client_ip = e->rip;
        ep->client_port = e->rport;
        return 0;
    }
    if (e->rport == (uint16_t)tcps_port) {
        ep->server_ip = e->rip;
        ep->server_port = e->rport;
        ep->client_ip = e->lip;
        ep->client_port = e->lport;
        return 0;
    }
    return -1;
}

static int endpoint_for_pid(pid_t pid, int tcps_port, struct endpoint *ep)
{
    struct tcp_entry entries[8192];
    int nentries = parse_tcp4(entries, 8192);
    if (nentries <= 0)
        return -1;

    char fd_dir[PATH_MAX];
    snprintf(fd_dir, sizeof(fd_dir), "/proc/%d/fd", pid);
    DIR *dir = opendir(fd_dir);
    if (!dir)
        return -1;

    struct dirent *de;
    int found = -1;
    while ((de = readdir(dir)) && found != 0) {
        if (!is_numeric(de->d_name))
            continue;
        char link_buf[256];
        ssize_t len = readlinkat(dirfd(dir), de->d_name, link_buf, sizeof(link_buf) - 1);
        if (len <= 0)
            continue;
        link_buf[len] = 0;
        unsigned long inode = 0;
        if (sscanf(link_buf, "socket:[%lu]", &inode) != 1)
            continue;
        for (int i = 0; i < nentries; i++) {
            if (entries[i].inode != inode)
                continue;
            if (tcp_entry_to_endpoint(&entries[i], tcps_port, ep) == 0) {
                found = 0;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

static int same_endpoint(const struct endpoint *a, const struct endpoint *b)
{
    return a->client_ip == b->client_ip &&
           a->server_ip == b->server_ip &&
           a->client_port == b->client_port &&
           a->server_port == b->server_port;
}

static int endpoint_established(const struct endpoint *ep)
{
    struct tcp_entry entries[8192];
    int nentries = parse_tcp4(entries, 8192);
    for (int i = 0; i < nentries; i++) {
        struct endpoint cur;
        if (tcp_entry_to_endpoint(&entries[i], ep->server_port, &cur) == 0 &&
            same_endpoint(ep, &cur))
            return 1;
    }
    return 0;
}

static void update_session_ctx(struct session *s, enum capture_source source,
                               unsigned long ctx)
{
    if (!ctx)
        return;
    if (source == SRC_LISTENER)
        s->listener_ctx = ctx;
    else
        s->dedicated_ctx = ctx;
}

static struct session *session_by_ctx(struct session *sessions,
                                      enum capture_source source,
                                      unsigned long ctx)
{
    if (!ctx)
        return NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active)
            continue;
        if (source == SRC_LISTENER && sessions[i].listener_ctx == ctx)
            return &sessions[i];
        if (source == SRC_DEDICATED && sessions[i].dedicated_ctx == ctx)
            return &sessions[i];
    }
    return NULL;
}

static struct session *single_active_session_for_pid(struct session *sessions, pid_t pid)
{
    struct session *found = NULL;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active || sessions[i].last_pid != pid)
            continue;
        if (found)
            return NULL;
        found = &sessions[i];
    }
    return found;
}

static struct session *get_session(struct session *sessions, pid_t pid,
                                   enum capture_source source,
                                   unsigned long ctx, int tcps_port)
{
    struct session *ctx_session = session_by_ctx(sessions, source, ctx);
    if (ctx_session) {
        ctx_session->last_pid = pid;
        ctx_session->last_seen = time(NULL);
        return ctx_session;
    }

    struct endpoint ep;
    if (endpoint_for_pid(pid, tcps_port, &ep) != 0) {
        struct session *s = single_active_session_for_pid(sessions, pid);
        if (s) {
            update_session_ctx(s, source, ctx);
            s->last_seen = time(NULL);
        }
        return s;
    }

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && same_endpoint(&sessions[i].ep, &ep)) {
            sessions[i].last_pid = pid;
            sessions[i].last_seen = time(NULL);
            update_session_ctx(&sessions[i], source, ctx);
            return &sessions[i];
        }
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) {
            memset(&sessions[i], 0, sizeof(sessions[i]));
            sessions[i].first_pid = pid;
            sessions[i].last_pid = pid;
            sessions[i].active = 1;
            sessions[i].seq_cli = 1000 + (uint32_t)pid;
            sessions[i].seq_srv = 500000 + (uint32_t)pid;
            sessions[i].ip_id = (uint16_t)pid;
            sessions[i].last_seen = time(NULL);
            sessions[i].ep = ep;
            update_session_ctx(&sessions[i], source, ctx);
            return &sessions[i];
        }
    }
    return NULL;
}

static void close_inactive_sessions(int pcap_fd, struct session *sessions)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && !endpoint_established(&sessions[i].ep))
            write_fin(pcap_fd, &sessions[i]);
    }
}

static int symbol_offset(const char *oracle_home, const char *libname,
                         const char *symbol, unsigned long fallback,
                         unsigned long *off)
{
    char cmd[PATH_MAX + 128];
    const char *modes[] = {
        "nm -D --defined-only '%s/lib/%s' 2>/dev/null",
        "nm '%s/lib/%s' 2>/dev/null"
    };
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
        snprintf(cmd, sizeof(cmd), modes[m], oracle_home, libname);
        FILE *fp = popen(cmd, "r");
        if (!fp)
            continue;
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            unsigned long addr = 0;
            char type = 0;
            char name[256] = {0};
            if (sscanf(line, "%lx %c %255s", &addr, &type, name) == 3 && strcmp(name, symbol) == 0) {
                *off = addr;
                pclose(fp);
                return 0;
            }
        }
        pclose(fp);
    }
    if (fallback) {
        *off = fallback;
        return 0;
    }
    return -1;
}

enum bpf_event_mode {
    BPF_EVT_WRITE,
    BPF_EVT_READ_SUCCESS
};

struct bpf_capture_event {
    uint64_t ts_ns;
    uint64_t ctx;
    uint64_t buf;
    uint64_t b0;
    uint32_t pid;
    uint32_t source;
    uint32_t direction;
    uint32_t len;
    char comm[16];
};

struct perf_reader {
    int cpu;
    int fd;
    void *base;
    size_t mmap_len;
    size_t data_size;
};

struct uprobe_link {
    int fd;
};

struct ebpf_state {
    int events_map_fd;
    int prog_fd[4];
    struct perf_reader *readers;
    int reader_count;
    struct uprobe_link *links;
    int link_count;
};

static int bpf_sys(enum bpf_cmd cmd, union bpf_attr *attr)
{
    return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int bpf_create_map(enum bpf_map_type type, uint32_t key_size,
                          uint32_t value_size, uint32_t max_entries)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_type = type;
    attr.key_size = key_size;
    attr.value_size = value_size;
    attr.max_entries = max_entries;
    return bpf_sys(BPF_MAP_CREATE, &attr);
}

static int bpf_update_map(int map_fd, const void *key, const void *value)
{
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.map_fd = (uint32_t)map_fd;
    attr.key = (uint64_t)(uintptr_t)key;
    attr.value = (uint64_t)(uintptr_t)value;
    attr.flags = BPF_ANY;
    return bpf_sys(BPF_MAP_UPDATE_ELEM, &attr);
}

static int bpf_load_prog(const struct bpf_insn *insns, size_t insn_cnt,
                         const char *name)
{
    char log_buf[65536];
    const char license[] = "GPL";
    union bpf_attr attr;

    memset(log_buf, 0, sizeof(log_buf));
    memset(&attr, 0, sizeof(attr));
    attr.prog_type = BPF_PROG_TYPE_KPROBE;
    attr.insn_cnt = (uint32_t)insn_cnt;
    attr.insns = (uint64_t)(uintptr_t)insns;
    attr.license = (uint64_t)(uintptr_t)license;
    attr.log_buf = (uint64_t)(uintptr_t)log_buf;
    attr.log_size = sizeof(log_buf);
    attr.log_level = 1;
    snprintf(attr.prog_name, sizeof(attr.prog_name), "%s", name);

    int fd = bpf_sys(BPF_PROG_LOAD, &attr);
    if (fd < 0)
        fprintf(stderr, "BPF_PROG_LOAD %s failed: %s\n%s\n", name, strerror(errno), log_buf);
    return fd;
}

static int perf_event_open_wrap(struct perf_event_attr *attr, pid_t pid,
                                int cpu, int group_fd, unsigned long flags)
{
    return (int)syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM) \
    ((struct bpf_insn){ .code = (CODE), .dst_reg = (DST), .src_reg = (SRC), .off = (OFF), .imm = (IMM) })
#define BPF_ALU32_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU | BPF_K | (OP), DST, 0, 0, IMM)
#define BPF_ALU64_IMM(OP, DST, IMM) BPF_RAW_INSN(BPF_ALU64 | BPF_K | (OP), DST, 0, 0, IMM)
#define BPF_ALU64_REG(OP, DST, SRC) BPF_RAW_INSN(BPF_ALU64 | BPF_X | (OP), DST, SRC, 0, 0)
#define BPF_MOV32_IMM(DST, IMM) BPF_ALU32_IMM(BPF_MOV, DST, IMM)
#define BPF_MOV64_IMM(DST, IMM) BPF_ALU64_IMM(BPF_MOV, DST, IMM)
#define BPF_MOV64_REG(DST, SRC) BPF_ALU64_REG(BPF_MOV, DST, SRC)
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_LDX | BPF_MEM | (SIZE), DST, SRC, OFF, 0)
#define BPF_STX_MEM(SIZE, DST, SRC, OFF) BPF_RAW_INSN(BPF_STX | BPF_MEM | (SIZE), DST, SRC, OFF, 0)
#define BPF_ST_MEM(SIZE, DST, OFF, IMM) BPF_RAW_INSN(BPF_ST | BPF_MEM | (SIZE), DST, 0, OFF, IMM)
#define BPF_EMIT_CALL(FUNC) BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, FUNC)
#define BPF_EXIT_INSN() BPF_RAW_INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0)

#define BPF_HELPER_KTIME_GET_NS 5
#define BPF_HELPER_GET_CURRENT_PID_TGID 14
#define BPF_HELPER_GET_CURRENT_COMM 16
#define BPF_HELPER_PERF_EVENT_OUTPUT 25
#define BPF_HELPER_PROBE_READ_USER 112

#define X86_REG_R14 8
#define X86_REG_R12 24
#define X86_REG_RBP 32
#define X86_REG_RDX 96
#define X86_REG_RSI 104
#define X86_REG_RDI 112

#define EVENT_SIZE ((int)sizeof(struct bpf_capture_event))
#define EVENT_TS_OFF (-64)
#define EVENT_CTX_OFF (-56)
#define EVENT_BUF_OFF (-48)
#define EVENT_B0_OFF (-40)
#define EVENT_PID_OFF (-32)
#define EVENT_SOURCE_OFF (-28)
#define EVENT_DIRECTION_OFF (-24)
#define EVENT_LEN_OFF (-20)
#define EVENT_COMM_OFF (-16)

static void emit_ld_map_fd(struct bpf_insn *insns, int *i, int dst_reg, int map_fd)
{
    insns[(*i)++] = BPF_RAW_INSN(BPF_LD | BPF_DW | BPF_IMM, dst_reg,
                                 BPF_PSEUDO_MAP_FD, 0, map_fd);
    insns[(*i)++] = BPF_RAW_INSN(0, 0, 0, 0, 0);
}

static int load_capture_prog(int events_map_fd, enum capture_source source,
                             int direction, enum bpf_event_mode mode,
                             const char *name)
{
    struct bpf_insn insns[160];
    int i = 0;

#define EMIT(X) do { insns[i++] = (X); } while (0)
    EMIT(BPF_MOV64_REG(BPF_REG_6, BPF_REG_1));
    for (int off = -EVENT_SIZE; off < 0; off += 8)
        EMIT(BPF_ST_MEM(BPF_DW, BPF_REG_10, off, 0));

    EMIT(BPF_EMIT_CALL(BPF_HELPER_KTIME_GET_NS));
    EMIT(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_0, EVENT_TS_OFF));

    EMIT(BPF_EMIT_CALL(BPF_HELPER_GET_CURRENT_PID_TGID));
    EMIT(BPF_ALU64_IMM(BPF_RSH, BPF_REG_0, 32));
    EMIT(BPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_0, EVENT_PID_OFF));

    EMIT(BPF_ST_MEM(BPF_W, BPF_REG_10, EVENT_SOURCE_OFF, source));
    EMIT(BPF_ST_MEM(BPF_W, BPF_REG_10, EVENT_DIRECTION_OFF, direction));

    EMIT(BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, EVENT_COMM_OFF));
    EMIT(BPF_MOV64_IMM(BPF_REG_2, 16));
    EMIT(BPF_EMIT_CALL(BPF_HELPER_GET_CURRENT_COMM));

    if (mode == BPF_EVT_WRITE) {
        EMIT(BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, X86_REG_RDI));
        EMIT(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_7, EVENT_CTX_OFF));
        EMIT(BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, X86_REG_RSI));
        EMIT(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_8, EVENT_BUF_OFF));
        EMIT(BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_6, X86_REG_RDX));
    } else {
        EMIT(BPF_LDX_MEM(BPF_DW, BPF_REG_7, BPF_REG_6, X86_REG_RBP));
        EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_7, -64));
        EMIT(BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
        EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, EVENT_CTX_OFF));
        EMIT(BPF_MOV64_IMM(BPF_REG_2, 8));
        EMIT(BPF_MOV64_REG(BPF_REG_3, BPF_REG_7));
        EMIT(BPF_EMIT_CALL(BPF_HELPER_PROBE_READ_USER));
        EMIT(BPF_LDX_MEM(BPF_DW, BPF_REG_8, BPF_REG_6, X86_REG_R14));
        EMIT(BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_8, EVENT_BUF_OFF));
        EMIT(BPF_LDX_MEM(BPF_DW, BPF_REG_9, BPF_REG_6, X86_REG_R12));
    }

    EMIT(BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, EVENT_LEN_OFF));
    EMIT(BPF_MOV64_IMM(BPF_REG_2, 4));
    EMIT(BPF_MOV64_REG(BPF_REG_3, BPF_REG_9));
    EMIT(BPF_EMIT_CALL(BPF_HELPER_PROBE_READ_USER));

    EMIT(BPF_MOV64_REG(BPF_REG_1, BPF_REG_10));
    EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_1, EVENT_B0_OFF));
    EMIT(BPF_MOV64_IMM(BPF_REG_2, 8));
    EMIT(BPF_MOV64_REG(BPF_REG_3, BPF_REG_8));
    EMIT(BPF_EMIT_CALL(BPF_HELPER_PROBE_READ_USER));

    EMIT(BPF_MOV64_REG(BPF_REG_1, BPF_REG_6));
    emit_ld_map_fd(insns, &i, BPF_REG_2, events_map_fd);
    EMIT(BPF_MOV32_IMM(BPF_REG_3, -1));
    EMIT(BPF_MOV64_REG(BPF_REG_4, BPF_REG_10));
    EMIT(BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, -EVENT_SIZE));
    EMIT(BPF_MOV64_IMM(BPF_REG_5, EVENT_SIZE));
    EMIT(BPF_EMIT_CALL(BPF_HELPER_PERF_EVENT_OUTPUT));
    EMIT(BPF_MOV64_IMM(BPF_REG_0, 0));
    EMIT(BPF_EXIT_INSN());
#undef EMIT

    return bpf_load_prog(insns, (size_t)i, name);
}

static int read_int_file(const char *path)
{
    char buf[64];
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    buf[n] = 0;
    return atoi(buf);
}

static int setup_perf_readers(struct ebpf_state *st)
{
    int ncpu = (int)sysconf(_SC_NPROCESSORS_ONLN);
    if (ncpu <= 0)
        ncpu = 1;

    st->events_map_fd = bpf_create_map(BPF_MAP_TYPE_PERF_EVENT_ARRAY,
                                       sizeof(uint32_t), sizeof(int), (uint32_t)ncpu);
    if (st->events_map_fd < 0) {
        perror("BPF_MAP_CREATE perf_event_array");
        return -1;
    }

    st->readers = calloc((size_t)ncpu, sizeof(*st->readers));
    if (!st->readers)
        return -1;

    long page_size = sysconf(_SC_PAGESIZE);
    size_t data_pages = 8;
    size_t mmap_len = (size_t)page_size * (1 + data_pages);
    for (int cpu = 0; cpu < ncpu; cpu++) {
        struct perf_event_attr attr;
        memset(&attr, 0, sizeof(attr));
        attr.type = PERF_TYPE_SOFTWARE;
        attr.size = sizeof(attr);
        attr.config = PERF_COUNT_SW_BPF_OUTPUT;
        attr.sample_type = PERF_SAMPLE_RAW;
        attr.wakeup_events = 1;
        attr.disabled = 1;

        int fd = perf_event_open_wrap(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd < 0)
            continue;
        void *base = mmap(NULL, mmap_len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (base == MAP_FAILED) {
            close(fd);
            continue;
        }
        if (bpf_update_map(st->events_map_fd, &cpu, &fd) != 0) {
            munmap(base, mmap_len);
            close(fd);
            continue;
        }
        st->readers[st->reader_count].cpu = cpu;
        st->readers[st->reader_count].fd = fd;
        st->readers[st->reader_count].base = base;
        st->readers[st->reader_count].mmap_len = mmap_len;
        st->readers[st->reader_count].data_size = (size_t)page_size * data_pages;
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
        st->reader_count++;
    }
    return st->reader_count > 0 ? 0 : -1;
}

static int attach_one_uprobe(int uprobe_type, const char *lib_path,
                             unsigned long offset, int prog_fd, int cpu)
{
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = (uint32_t)uprobe_type;
    attr.size = sizeof(attr);
    attr.sample_period = 1;
    attr.wakeup_events = 1;
    attr.disabled = 1;
    attr.config1 = (uint64_t)(uintptr_t)lib_path;
    attr.config2 = offset;

    int fd = perf_event_open_wrap(&attr, -1, cpu, -1, PERF_FLAG_FD_CLOEXEC);
    if (fd < 0)
        return -1;
    if (ioctl(fd, PERF_EVENT_IOC_SET_BPF, prog_fd) != 0 ||
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int attach_uprobe_once(struct ebpf_state *st, const char *lib_path,
                              unsigned long offset, int prog_fd)
{
    int uprobe_type = read_int_file("/sys/bus/event_source/devices/uprobe/type");
    if (uprobe_type < 0)
        return -1;
    if (st->reader_count <= 0)
        return -1;

    int fd = attach_one_uprobe(uprobe_type, lib_path, offset, prog_fd, -1);
    if (fd < 0)
        fd = attach_one_uprobe(uprobe_type, lib_path, offset, prog_fd, st->readers[0].cpu);
    if (fd < 0)
        return -1;
    st->links[st->link_count++].fd = fd;
    return 0;
}

static int setup_ebpf(struct ebpf_state *st, const char *oracle_home,
                      unsigned long srv_write_off,
                      unsigned long srv_read_success_off,
                      unsigned long lsnr_write_off,
                      unsigned long lsnr_read_success_off)
{
    char srv_lib[PATH_MAX];
    char lsnr_lib[PATH_MAX];
    snprintf(srv_lib, sizeof(srv_lib), "%s/lib/%s", oracle_home, LIBNNZSRV);
    snprintf(lsnr_lib, sizeof(lsnr_lib), "%s/lib/%s", oracle_home, LIBNNZ);

    memset(st, 0, sizeof(*st));
    if (setup_perf_readers(st) != 0)
        return -1;

    st->links = calloc(4, sizeof(*st->links));
    if (!st->links)
        return -1;

    st->prog_fd[0] = load_capture_prog(st->events_map_fd, SRC_DEDICATED, 1,
                                       BPF_EVT_WRITE, "ora_srv_wr");
    st->prog_fd[1] = load_capture_prog(st->events_map_fd, SRC_DEDICATED, 0,
                                       BPF_EVT_READ_SUCCESS, "ora_srv_rd");
    st->prog_fd[2] = load_capture_prog(st->events_map_fd, SRC_LISTENER, 1,
                                       BPF_EVT_WRITE, "ora_lsn_wr");
    st->prog_fd[3] = load_capture_prog(st->events_map_fd, SRC_LISTENER, 0,
                                       BPF_EVT_READ_SUCCESS, "ora_lsn_rd");
    for (int i = 0; i < 4; i++) {
        if (st->prog_fd[i] < 0)
            return -1;
    }

    if (attach_uprobe_once(st, srv_lib, srv_write_off, st->prog_fd[0]) != 0 ||
        attach_uprobe_once(st, srv_lib, srv_read_success_off, st->prog_fd[1]) != 0 ||
        attach_uprobe_once(st, lsnr_lib, lsnr_write_off, st->prog_fd[2]) != 0 ||
        attach_uprobe_once(st, lsnr_lib, lsnr_read_success_off, st->prog_fd[3]) != 0)
        return -1;

    return 0;
}

static void cleanup_ebpf(struct ebpf_state *st)
{
    if (!st)
        return;
    for (int i = 0; i < st->link_count; i++) {
        if (st->links[i].fd >= 0)
            close(st->links[i].fd);
    }
    for (int i = 0; i < 4; i++) {
        if (st->prog_fd[i] > 0)
            close(st->prog_fd[i]);
    }
    for (int i = 0; i < st->reader_count; i++) {
        if (st->readers[i].base && st->readers[i].base != MAP_FAILED)
            munmap(st->readers[i].base, st->readers[i].mmap_len);
        if (st->readers[i].fd >= 0)
            close(st->readers[i].fd);
    }
    if (st->events_map_fd > 0)
        close(st->events_map_fd);
    free(st->links);
    free(st->readers);
    memset(st, 0, sizeof(*st));
}

static enum packet_format plausible_packet(const uint8_t *buf, uint32_t len)
{
    return packet_format(buf, len);
}

static void u64_to_le_bytes(uint64_t v, uint8_t *out)
{
    for (int i = 0; i < 8; i++)
        out[i] = (uint8_t)(v >> (8 * i));
}

static int capture_event(int pcap_fd, struct session *sessions, int tcps_port,
                         pid_t pid, enum capture_source source, int server_to_client,
                         unsigned long ctx, unsigned long buf_addr, uint64_t inline_b0,
                         uint32_t len)
{
    uint8_t *buf = malloc(len);
    if (!buf)
        return 0;

    ssize_t n = -1;
    if (len <= 8) {
        uint8_t tmp[8];
        u64_to_le_bytes(inline_b0, tmp);
        memcpy(buf, tmp, len);
        n = (ssize_t)len;
    } else {
        n = read_mem(pid, buf_addr, buf, len);
    }

    enum packet_format fmt = n == (ssize_t)len ? plausible_packet(buf, len) : PKT_UNKNOWN;
    if (fmt == PKT_UNKNOWN) {
        free(buf);
        return 0;
    }

    struct session *s = get_session(sessions, pid, source, ctx, tcps_port);
    if (!s) {
        free(buf);
        return 0;
    }

    write_handshake(pcap_fd, s);
    if (append_tcp_frame(pcap_fd, s, server_to_client, 0x18, buf, len) == 0) {
        if (g_ack_data_frames)
            append_tcp_frame(pcap_fd, s, !server_to_client, 0x10, NULL, 0);
        s->packets++;
        s->bytes += len;
        s->last_seen = time(NULL);
        fprintf(stderr, "pid=%d source=%s %s len=%u format=%s ctx=0x%lx packets=%" PRIu64 "\n",
                pid, source == SRC_LISTENER ? "listener" : "dedicated",
                server_to_client ? "server_to_client" : "client_to_server",
                len, packet_format_name(fmt), ctx, s->packets);
        free(buf);
        return 1;
    }
    free(buf);
    return 0;
}

static int copy_perf_ring(const struct perf_reader *r, uint64_t off, void *dst, size_t len)
{
    if (!r->base || r->data_size == 0)
        return -1;

    const uint8_t *data = (const uint8_t *)r->base + (r->mmap_len - r->data_size);
    uint8_t *out = dst;
    off %= r->data_size;
    while (len) {
        size_t chunk = r->data_size - (size_t)off;
        if (chunk > len)
            chunk = len;
        memcpy(out, data + off, chunk);
        out += chunk;
        len -= chunk;
        off = 0;
    }
    return 0;
}

static int consume_one_bpf_event(const struct bpf_capture_event *ev, int pcap_fd,
                                 struct session *sessions, int tcps_port)
{
    g_bpf_events++;
    if (ev->source > SRC_LISTENER || ev->direction > 1) {
        g_bad_bpf_events++;
        return 0;
    }
    if (!ev->buf || ev->len < 5 || ev->len > MAX_PACKET_LEN) {
        g_bad_bpf_events++;
        return 0;
    }

    char comm[sizeof(ev->comm) + 1];
    memcpy(comm, ev->comm, sizeof(ev->comm));
    comm[sizeof(ev->comm)] = 0;
    if (ev->source == SRC_LISTENER && strcmp(comm, "tnslsnr") != 0) {
        g_listener_filtered++;
        return 0;
    }

    int ok = capture_event(pcap_fd, sessions, tcps_port, (pid_t)ev->pid,
                           (enum capture_source)ev->source, (int)ev->direction,
                           (unsigned long)ev->ctx, (unsigned long)ev->buf,
                           ev->b0, ev->len);
    if (!ok)
        g_capture_dropped++;
    return ok;
}

static uint64_t consume_perf_reader(struct perf_reader *r, int pcap_fd,
                                    struct session *sessions, int tcps_port,
                                    uint64_t max_packets, uint64_t *captured)
{
    struct perf_event_mmap_page *meta = r->base;
    uint64_t local = 0;

    if (!meta)
        return 0;

    uint64_t head = meta->data_head;
    __sync_synchronize();
    uint64_t tail = meta->data_tail;

    while (tail < head && (max_packets == 0 || *captured < max_packets)) {
        struct perf_event_header hdr;
        if (copy_perf_ring(r, tail, &hdr, sizeof(hdr)) != 0)
            break;
        if (hdr.size < sizeof(hdr) || hdr.size > r->data_size) {
            fprintf(stderr, "perf ring cpu=%d has invalid record size=%u; resyncing\n",
                    r->cpu, hdr.size);
            tail = head;
            break;
        }

        if (hdr.type == PERF_RECORD_SAMPLE) {
            uint32_t raw_size = 0;
            if (hdr.size >= sizeof(hdr) + sizeof(raw_size) &&
                copy_perf_ring(r, tail + sizeof(hdr), &raw_size, sizeof(raw_size)) == 0 &&
                raw_size >= sizeof(struct bpf_capture_event) &&
                sizeof(hdr) + sizeof(raw_size) + raw_size <= hdr.size) {
                struct bpf_capture_event ev;
                if (copy_perf_ring(r, tail + sizeof(hdr) + sizeof(raw_size),
                                   &ev, sizeof(ev)) == 0 &&
                    consume_one_bpf_event(&ev, pcap_fd, sessions, tcps_port)) {
                    (*captured)++;
                    local++;
                }
            }
        } else if (hdr.type == PERF_RECORD_LOST) {
            g_lost_records++;
        }

        tail += hdr.size;
    }

    meta->data_tail = tail;
    return local;
}

static void bump_memlock_rlimit(void)
{
    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0)
        fprintf(stderr, "warning: could not raise RLIMIT_MEMLOCK: %s\n", strerror(errno));
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [-H ORACLE_HOME] [-p TCPS_PORT] [-o OUT_PCAP] [-n MAX_PACKETS] [-A]\n"
            "Defaults: ORACLE_HOME=%s, TCPS_PORT=%d, OUT_PCAP=%s, MAX_PACKETS=0 unlimited\n"
            "  -A  emit synthetic ACK-only frames after each data frame\n"
            "\n"
            "This variant uses eBPF uprobes only; payload capture and pcap/session logic run in user space.\n",
            argv0, DEFAULT_ORACLE_HOME, DEFAULT_PORT, DEFAULT_OUT);
}

int main(int argc, char **argv)
{
    const char *oracle_home = getenv("ORACLE_HOME");
    if (!oracle_home || !*oracle_home)
        oracle_home = DEFAULT_ORACLE_HOME;
    int tcps_port = DEFAULT_PORT;
    const char *out_pcap = DEFAULT_OUT;
    uint64_t max_packets = 0;

    int opt;
    while ((opt = getopt(argc, argv, "H:p:o:n:Ah")) != -1) {
        switch (opt) {
        case 'H':
            oracle_home = optarg;
            break;
        case 'p':
            tcps_port = atoi(optarg);
            break;
        case 'o':
            out_pcap = optarg;
            break;
        case 'n':
            max_packets = strtoull(optarg, NULL, 10);
            break;
        case 'A':
            g_ack_data_frames = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 2;
        }
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    unsigned long srv_write_off = 0, srv_nzos_read_off = 0;
    unsigned long lsnr_write_off = 0, lsnr_nzos_read_off = 0;
    if (symbol_offset(oracle_home, LIBNNZSRV, "nzpa_ssl_Write",
                      LIBNNZSRV_NZPA_SSL_WRITE, &srv_write_off) != 0 ||
        symbol_offset(oracle_home, LIBNNZSRV, "nzos_Read",
                      LIBNNZSRV_NZOS_READ, &srv_nzos_read_off) != 0 ||
        symbol_offset(oracle_home, LIBNNZ, "nzpa_ssl_Write",
                      LIBNNZ_NZPA_SSL_WRITE, &lsnr_write_off) != 0 ||
        symbol_offset(oracle_home, LIBNNZ, "nzos_Read",
                      LIBNNZ_NZOS_READ, &lsnr_nzos_read_off) != 0) {
        fprintf(stderr, "Could not resolve required symbols from %s/lib\n", oracle_home);
        return 1;
    }
    unsigned long srv_read_success_off = srv_nzos_read_off + NZOS_READ_SUCCESS_DELTA;
    unsigned long lsnr_read_success_off = lsnr_nzos_read_off + NZOS_READ_SUCCESS_DELTA;

    bump_memlock_rlimit();

    if (write_pcap_header(out_pcap) != 0) {
        fprintf(stderr, "Could not create %s: %s\n", out_pcap, strerror(errno));
        return 1;
    }

    int pcap_fd = open(out_pcap, O_WRONLY | O_APPEND);
    if (pcap_fd < 0) {
        perror("open pcap append");
        return 1;
    }

    struct ebpf_state bpf;
    if (setup_ebpf(&bpf, oracle_home, srv_write_off, srv_read_success_off,
                   lsnr_write_off, lsnr_read_success_off) != 0) {
        fprintf(stderr, "Could not set up eBPF uprobes. Are you root, and is BPF/perf_event enabled?\n");
        cleanup_ebpf(&bpf);
        close(pcap_fd);
        return 1;
    }

    fprintf(stderr,
            "oracle_home=%s tcps_port=%d out=%s srv_write=0x%lx srv_read_success=0x%lx lsnr_write=0x%lx lsnr_read_success=0x%lx\n",
            oracle_home, tcps_port, out_pcap, srv_write_off, srv_read_success_off,
            lsnr_write_off, lsnr_read_success_off);
    fprintf(stderr, "capturing globally with eBPF uprobes; perf_readers=%d data_ack_frames=%s. Ctrl+C to stop.\n",
            bpf.reader_count, g_ack_data_frames ? "on" : "off");

    struct session *sessions = calloc(MAX_SESSIONS, sizeof(*sessions));
    if (!sessions) {
        perror("calloc sessions");
        cleanup_ebpf(&bpf);
        close(pcap_fd);
        return 1;
    }
    struct pollfd *pfds = calloc((size_t)bpf.reader_count, sizeof(*pfds));
    if (!pfds) {
        perror("calloc pollfds");
        free(sessions);
        cleanup_ebpf(&bpf);
        close(pcap_fd);
        return 1;
    }

    uint64_t captured = 0;
    while (!g_stop && (max_packets == 0 || captured < max_packets)) {
        for (int i = 0; i < bpf.reader_count; i++) {
            pfds[i].fd = bpf.readers[i].fd;
            pfds[i].events = POLLIN;
            pfds[i].revents = 0;
        }

        int prc = poll(pfds, (nfds_t)bpf.reader_count, 250);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (prc == 0) {
            for (int i = 0; i < bpf.reader_count; i++)
                consume_perf_reader(&bpf.readers[i], pcap_fd, sessions,
                                    tcps_port, max_packets, &captured);
            close_inactive_sessions(pcap_fd, sessions);
            continue;
        }

        for (int i = 0; i < bpf.reader_count; i++)
            consume_perf_reader(&bpf.readers[i], pcap_fd, sessions,
                                tcps_port, max_packets, &captured);
        close_inactive_sessions(pcap_fd, sessions);
    }

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active)
            write_fin(pcap_fd, &sessions[i]);
    }
    free(pfds);
    free(sessions);
    cleanup_ebpf(&bpf);
    close(pcap_fd);
    fprintf(stderr,
            "stats bpf_events=%" PRIu64 " bad=%" PRIu64 " listener_filtered=%" PRIu64
            " capture_dropped=%" PRIu64 " lost_records=%" PRIu64 "\n",
            g_bpf_events, g_bad_bpf_events, g_listener_filtered,
            g_capture_dropped, g_lost_records);
    fprintf(stderr, "done captured=%" PRIu64 " out=%s\n", captured, out_pcap);
    return captured > 0 ? 0 : 1;
}

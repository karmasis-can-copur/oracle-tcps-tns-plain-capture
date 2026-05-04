#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ORACLE_HOME "/opt/oracle/product/26ai/dbhomeFree"
#define DEFAULT_PORT 2484
#define DEFAULT_OUT "/tmp/oracle_plain_tcps.pcap"
#define TRACEFS "/sys/kernel/tracing"
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

static volatile sig_atomic_t g_stop;

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

static int append_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY | O_APPEND);
    if (fd < 0)
        return -1;
    int rc = write_all(fd, s, strlen(s));
    close(fd);
    return rc;
}

static int write_file(const char *path, const char *s)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;
    int rc = write_all(fd, s, strlen(s));
    close(fd);
    return rc;
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
        char link_path[PATH_MAX];
        char link_buf[256];
        snprintf(link_path, sizeof(link_path), "%s/%s", fd_dir, de->d_name);
        ssize_t len = readlink(link_path, link_buf, sizeof(link_buf) - 1);
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

static void remove_probe(const char *event)
{
    char path[PATH_MAX];
    char line[128];

    snprintf(path, sizeof(path), TRACEFS "/events/ora_plain/%s/enable", event);
    if (access(path, F_OK) == 0)
        write_file(path, "0");

    snprintf(line, sizeof(line), "-:ora_plain/%s\n", event);
    append_file(TRACEFS "/uprobe_events", line);
}

static int add_probe(const char *event, const char *lib, unsigned long off,
                     const char *args)
{
    char line[PATH_MAX + 256];
    snprintf(line, sizeof(line), "p:ora_plain/%s %s:0x%lx %s\n",
             event, lib, off, args);
    return append_file(TRACEFS "/uprobe_events", line);
}

static int enable_probe(const char *event)
{
    char path[PATH_MAX];
    snprintf(path, sizeof(path), TRACEFS "/events/ora_plain/%s/enable", event);
    return write_file(path, "1");
}

static int setup_tracefs(const char *oracle_home,
                         unsigned long srv_write_off,
                         unsigned long srv_read_success_off,
                         unsigned long lsnr_write_off,
                         unsigned long lsnr_read_success_off)
{
    char srv_lib[PATH_MAX];
    char lsnr_lib[PATH_MAX];
    snprintf(srv_lib, sizeof(srv_lib), "%s/lib/%s", oracle_home, LIBNNZSRV);
    snprintf(lsnr_lib, sizeof(lsnr_lib), "%s/lib/%s", oracle_home, LIBNNZ);

    remove_probe("srv_write");
    remove_probe("srv_read_success");
    remove_probe("lsnr_write");
    remove_probe("lsnr_read_success");
    remove_probe("write");
    remove_probe("read_success");

    if (add_probe("srv_write", srv_lib, srv_write_off,
                  "ctx=%di:u64 buf=%si:u64 len=+0(%dx):u32 b0=+0(%si):u64") != 0)
        return -1;
    if (add_probe("srv_read_success", srv_lib, srv_read_success_off,
                  "ctx=-64(%bp):u64 buf=%r14:u64 len=+0(%r12):u32 b0=+0(%r14):u64") != 0)
        return -1;
    if (add_probe("lsnr_write", lsnr_lib, lsnr_write_off,
                  "ctx=%di:u64 buf=%si:u64 len=+0(%dx):u32 b0=+0(%si):u64") != 0)
        return -1;
    if (add_probe("lsnr_read_success", lsnr_lib, lsnr_read_success_off,
                  "ctx=-64(%bp):u64 buf=%r14:u64 len=+0(%r12):u32 b0=+0(%r14):u64") != 0)
        return -1;

    write_file(TRACEFS "/trace", "");
    if (enable_probe("srv_write") != 0)
        return -1;
    if (enable_probe("srv_read_success") != 0)
        return -1;
    if (enable_probe("lsnr_write") != 0)
        return -1;
    if (enable_probe("lsnr_read_success") != 0)
        return -1;
    return 0;
}

static void cleanup_tracefs(void)
{
    remove_probe("srv_write");
    remove_probe("srv_read_success");
    remove_probe("lsnr_write");
    remove_probe("lsnr_read_success");
    remove_probe("write");
    remove_probe("read_success");
}

static pid_t parse_comm_pid_from_trace_line(const char *line, char *comm, size_t comm_len)
{
    const char *br = strchr(line, '[');
    if (!br)
        return -1;
    const char *p = br;
    while (p > line && isspace((unsigned char)p[-1]))
        p--;
    const char *end = p;
    while (p > line && isdigit((unsigned char)p[-1]))
        p--;
    if (p == end || p == line || p[-1] != '-')
        return -1;
    char tmp[32];
    size_t n = (size_t)(end - p);
    if (n >= sizeof(tmp))
        return -1;
    memcpy(tmp, p, n);
    tmp[n] = 0;
    if (comm && comm_len) {
        const char *cs = line;
        while (cs < p - 1 && isspace((unsigned char)*cs))
            cs++;
        const char *ce = p - 1;
        while (ce > cs && isspace((unsigned char)ce[-1]))
            ce--;
        size_t cn = (size_t)(ce - cs);
        if (cn >= comm_len)
            cn = comm_len - 1;
        memcpy(comm, cs, cn);
        comm[cn] = 0;
    }
    return (pid_t)strtol(tmp, NULL, 10);
}

static int parse_trace_line(const char *line, pid_t *pid, enum capture_source *source,
                            int *server_to_client, unsigned long *ctx,
                            unsigned long *buf, uint64_t *inline_b0,
                            uint32_t *len)
{
    char comm[64] = {0};
    if (strstr(line, ": srv_write:")) {
        *source = SRC_DEDICATED;
        *server_to_client = 1;
    } else if (strstr(line, ": srv_read_success:")) {
        *source = SRC_DEDICATED;
        *server_to_client = 0;
    } else if (strstr(line, ": lsnr_write:")) {
        *source = SRC_LISTENER;
        *server_to_client = 1;
    } else if (strstr(line, ": lsnr_read_success:")) {
        *source = SRC_LISTENER;
        *server_to_client = 0;
    } else {
        return 0;
    }

    *pid = parse_comm_pid_from_trace_line(line, comm, sizeof(comm));
    if (*pid <= 0)
        return 0;
    if (*source == SRC_LISTENER && strcmp(comm, "tnslsnr") != 0)
        return 0;

    const char *cp = strstr(line, "ctx=");
    const char *bp = strstr(line, "buf=");
    const char *lp = strstr(line, "len=");
    const char *b0p = strstr(line, "b0=");
    if (!cp || !bp || !lp || !b0p)
        return 0;
    *ctx = strtoul(cp + 4, NULL, 0);
    *buf = strtoul(bp + 4, NULL, 0);
    *inline_b0 = strtoull(b0p + 3, NULL, 0);
    *len = (uint32_t)strtoul(lp + 4, NULL, 0);
    return *buf != 0 && *len >= 5 && *len <= MAX_PACKET_LEN;
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

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s [-H ORACLE_HOME] [-p TCPS_PORT] [-o OUT_PCAP] [-n MAX_PACKETS]\n"
            "Defaults: ORACLE_HOME=%s, TCPS_PORT=%d, OUT_PCAP=%s, MAX_PACKETS=0 unlimited\n",
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
    while ((opt = getopt(argc, argv, "H:p:o:n:h")) != -1) {
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

    if (write_pcap_header(out_pcap) != 0) {
        fprintf(stderr, "Could not create %s: %s\n", out_pcap, strerror(errno));
        return 1;
    }

    if (setup_tracefs(oracle_home, srv_write_off, srv_read_success_off,
                      lsnr_write_off, lsnr_read_success_off) != 0) {
        fprintf(stderr, "Could not set up tracefs uprobes. Are you root, and is tracefs writable?\n");
        cleanup_tracefs();
        return 1;
    }

    int pcap_fd = open(out_pcap, O_WRONLY | O_APPEND);
    if (pcap_fd < 0) {
        perror("open pcap append");
        cleanup_tracefs();
        return 1;
    }
    int trace_fd = open(TRACEFS "/trace_pipe", O_RDONLY);
    if (trace_fd < 0) {
        perror("open trace_pipe");
        close(pcap_fd);
        cleanup_tracefs();
        return 1;
    }

    fprintf(stderr,
            "oracle_home=%s tcps_port=%d out=%s srv_write=0x%lx srv_read_success=0x%lx lsnr_write=0x%lx lsnr_read_success=0x%lx\n",
            oracle_home, tcps_port, out_pcap, srv_write_off, srv_read_success_off,
            lsnr_write_off, lsnr_read_success_off);
    fprintf(stderr, "capturing globally; start fast TCPS sessions now. Ctrl+C to stop.\n");

    struct session *sessions = calloc(MAX_SESSIONS, sizeof(*sessions));
    if (!sessions) {
        perror("calloc sessions");
        close(trace_fd);
        close(pcap_fd);
        cleanup_tracefs();
        return 1;
    }

    uint64_t captured = 0;
    char readbuf[32768];
    char linebuf[65536];
    size_t line_len = 0;
    while (!g_stop && (max_packets == 0 || captured < max_packets)) {
        struct pollfd pfd = { .fd = trace_fd, .events = POLLIN };
        int prc = poll(&pfd, 1, 250);
        if (prc < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (prc == 0) {
            close_inactive_sessions(pcap_fd, sessions);
            continue;
        }
        ssize_t n = read(trace_fd, readbuf, sizeof(readbuf));
        if (n <= 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            break;
        }
        for (ssize_t i = 0; i < n; i++) {
            if (readbuf[i] == '\n') {
                linebuf[line_len] = 0;
                pid_t pid = 0;
                enum capture_source source = SRC_DEDICATED;
                int server_to_client = 0;
                unsigned long ctx = 0;
                unsigned long buf_addr = 0;
                uint64_t inline_b0 = 0;
                uint32_t len = 0;
                if (parse_trace_line(linebuf, &pid, &source, &server_to_client,
                                     &ctx, &buf_addr, &inline_b0, &len)) {
                    if (capture_event(pcap_fd, sessions, tcps_port, pid, source,
                                      server_to_client, ctx, buf_addr, inline_b0, len))
                        captured++;
                }
                line_len = 0;
            } else if (line_len + 1 < sizeof(linebuf)) {
                linebuf[line_len++] = readbuf[i];
            } else {
                line_len = 0;
            }
        }
    }

    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active)
            write_fin(pcap_fd, &sessions[i]);
    }
    free(sessions);
    close(trace_fd);
    close(pcap_fd);
    cleanup_tracefs();
    fprintf(stderr, "done captured=%" PRIu64 " out=%s\n", captured, out_pcap);
    return captured > 0 ? 0 : 1;
}

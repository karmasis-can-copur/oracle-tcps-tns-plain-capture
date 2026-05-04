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

static volatile sig_atomic_t g_stop;

struct endpoint {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
};

struct session {
    pid_t pid;
    int active;
    int handshake_written;
    int fin_written;
    uint32_t seq_cli;
    uint32_t seq_srv;
    uint16_t ip_id;
    uint64_t packets;
    uint64_t bytes;
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
        entries[count].inode = strtoul(tok[9], NULL, 10);
        count++;
    }
    fclose(fp);
    return count;
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
            if (entries[i].lport == (uint16_t)tcps_port) {
                ep->server_ip = entries[i].lip;
                ep->server_port = entries[i].lport;
                ep->client_ip = entries[i].rip;
                ep->client_port = entries[i].rport;
                found = 0;
                break;
            }
            if (entries[i].rport == (uint16_t)tcps_port) {
                ep->server_ip = entries[i].rip;
                ep->server_port = entries[i].rport;
                ep->client_ip = entries[i].lip;
                ep->client_port = entries[i].lport;
                found = 0;
                break;
            }
        }
    }
    closedir(dir);
    return found;
}

static struct session *get_session(struct session *sessions, pid_t pid, int tcps_port)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && sessions[i].pid == pid)
            return &sessions[i];
    }
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) {
            memset(&sessions[i], 0, sizeof(sessions[i]));
            sessions[i].pid = pid;
            sessions[i].active = 1;
            sessions[i].seq_cli = 1000 + (uint32_t)pid;
            sessions[i].seq_srv = 500000 + (uint32_t)pid;
            sessions[i].ip_id = (uint16_t)pid;
            if (endpoint_for_pid(pid, tcps_port, &sessions[i].ep) != 0) {
                sessions[i].active = 0;
                return NULL;
            }
            return &sessions[i];
        }
    }
    return NULL;
}

static int pid_exists(pid_t pid)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d", pid);
    return access(path, F_OK) == 0;
}

static void close_dead_sessions(int pcap_fd, struct session *sessions)
{
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].active && !pid_exists(sessions[i].pid))
            write_fin(pcap_fd, &sessions[i]);
    }
}

static int symbol_offset(const char *oracle_home, const char *symbol, unsigned long *off)
{
    char cmd[PATH_MAX + 128];
    const char *modes[] = {
        "nm -D --defined-only '%s/lib/libnnzsrv.so' 2>/dev/null",
        "nm '%s/lib/libnnzsrv.so' 2>/dev/null"
    };
    for (size_t m = 0; m < sizeof(modes) / sizeof(modes[0]); m++) {
        snprintf(cmd, sizeof(cmd), modes[m], oracle_home);
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
    if (strcmp(symbol, "nzpa_ssl_Write") == 0) {
        *off = 0x11c570;
        return 0;
    }
    if (strcmp(symbol, "nzos_Read") == 0) {
        *off = 0x137a70;
        return 0;
    }
    return -1;
}

static int setup_tracefs(const char *oracle_home, unsigned long write_off, unsigned long read_success_off)
{
    char lib[PATH_MAX];
    char line[PATH_MAX + 256];
    snprintf(lib, sizeof(lib), "%s/lib/libnnzsrv.so", oracle_home);

    write_file(TRACEFS "/events/ora_plain/write/enable", "0");
    write_file(TRACEFS "/events/ora_plain/read_success/enable", "0");
    append_file(TRACEFS "/uprobe_events", "-:ora_plain/write\n");
    append_file(TRACEFS "/uprobe_events", "-:ora_plain/read_success\n");

    snprintf(line, sizeof(line),
             "p:ora_plain/write %s:0x%lx buf=%%si:u64 len=+0(%%dx):u32\n",
             lib, write_off);
    if (append_file(TRACEFS "/uprobe_events", line) != 0)
        return -1;

    snprintf(line, sizeof(line),
             "p:ora_plain/read_success %s:0x%lx buf=%%r14:u64 len=+0(%%r12):u32\n",
             lib, read_success_off);
    if (append_file(TRACEFS "/uprobe_events", line) != 0)
        return -1;

    write_file(TRACEFS "/trace", "");
    if (write_file(TRACEFS "/events/ora_plain/write/enable", "1") != 0)
        return -1;
    if (write_file(TRACEFS "/events/ora_plain/read_success/enable", "1") != 0)
        return -1;
    return 0;
}

static void cleanup_tracefs(void)
{
    write_file(TRACEFS "/events/ora_plain/write/enable", "0");
    write_file(TRACEFS "/events/ora_plain/read_success/enable", "0");
    append_file(TRACEFS "/uprobe_events", "-:ora_plain/write\n");
    append_file(TRACEFS "/uprobe_events", "-:ora_plain/read_success\n");
}

static pid_t parse_pid_from_trace_line(const char *line)
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
    return (pid_t)strtol(tmp, NULL, 10);
}

static int parse_trace_line(const char *line, pid_t *pid, int *server_to_client,
                            unsigned long *buf, uint32_t *len)
{
    if (strstr(line, ": write:"))
        *server_to_client = 1;
    else if (strstr(line, ": read_success:"))
        *server_to_client = 0;
    else
        return 0;

    *pid = parse_pid_from_trace_line(line);
    if (*pid <= 0)
        return 0;

    const char *bp = strstr(line, "buf=");
    const char *lp = strstr(line, "len=");
    if (!bp || !lp)
        return 0;
    *buf = strtoul(bp + 4, NULL, 0);
    *len = (uint32_t)strtoul(lp + 4, NULL, 0);
    return *buf != 0 && *len >= 8 && *len <= MAX_PACKET_LEN;
}

static int plausible_packet(const uint8_t *buf, uint32_t len)
{
    if (len < 8)
        return 0;
    uint32_t be_len = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                      ((uint32_t)buf[2] << 8) | buf[3];
    return be_len == len;
}

static int capture_event(int pcap_fd, struct session *sessions, int tcps_port,
                         pid_t pid, int server_to_client, unsigned long buf_addr, uint32_t len)
{
    uint8_t *buf = malloc(len);
    if (!buf)
        return 0;
    ssize_t n = read_mem(pid, buf_addr, buf, len);
    if (n != (ssize_t)len || !plausible_packet(buf, len)) {
        free(buf);
        return 0;
    }

    struct session *s = get_session(sessions, pid, tcps_port);
    if (!s) {
        free(buf);
        return 0;
    }
    write_handshake(pcap_fd, s);
    if (append_tcp_frame(pcap_fd, s, server_to_client, 0x18, buf, len) == 0) {
        s->packets++;
        s->bytes += len;
        fprintf(stderr, "pid=%d %s len=%u packets=%" PRIu64 "\n",
                pid, server_to_client ? "server_to_client" : "client_to_server",
                len, s->packets);
    }
    free(buf);
    return 1;
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

    unsigned long write_off = 0, nzos_read_off = 0;
    if (symbol_offset(oracle_home, "nzpa_ssl_Write", &write_off) != 0 ||
        symbol_offset(oracle_home, "nzos_Read", &nzos_read_off) != 0) {
        fprintf(stderr, "Could not resolve required symbols from %s/lib/libnnzsrv.so\n", oracle_home);
        return 1;
    }
    unsigned long read_success_off = nzos_read_off + 0xfc;

    if (write_pcap_header(out_pcap) != 0) {
        fprintf(stderr, "Could not create %s: %s\n", out_pcap, strerror(errno));
        return 1;
    }

    if (setup_tracefs(oracle_home, write_off, read_success_off) != 0) {
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

    fprintf(stderr, "oracle_home=%s tcps_port=%d out=%s write_off=0x%lx read_success_off=0x%lx\n",
            oracle_home, tcps_port, out_pcap, write_off, read_success_off);
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
            close_dead_sessions(pcap_fd, sessions);
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
                int server_to_client = 0;
                unsigned long buf_addr = 0;
                uint32_t len = 0;
                if (parse_trace_line(linebuf, &pid, &server_to_client, &buf_addr, &len)) {
                    if (capture_event(pcap_fd, sessions, tcps_port, pid, server_to_client, buf_addr, len))
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

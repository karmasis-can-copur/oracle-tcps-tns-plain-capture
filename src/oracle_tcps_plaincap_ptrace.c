#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ptrace.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_ORACLE_HOME "/opt/oracle/product/26ai/dbhomeFree"
#define DEFAULT_PORT 2484
#define DEFAULT_OUT "/tmp/oracle_plain_tcps.pcap"
#define MAX_TARGETS 64

static volatile sig_atomic_t g_stop;

struct endpoint {
    uint32_t client_ip;
    uint32_t server_ip;
    uint16_t client_port;
    uint16_t server_port;
};

struct target {
    pid_t pid;
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

static int read_u32(pid_t pid, unsigned long addr, uint32_t *out)
{
    uint32_t v = 0;
    ssize_t n = read_mem(pid, addr, &v, sizeof(v));
    if (n != (ssize_t)sizeof(v))
        return -1;
    *out = v;
    return 0;
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

static unsigned long lib_base(pid_t pid, const char *oracle_home)
{
    char maps_path[PATH_MAX];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *fp = fopen(maps_path, "r");
    if (!fp)
        return 0;

    char needle[PATH_MAX];
    snprintf(needle, sizeof(needle), "%s/lib/libnnzsrv.so", oracle_home);
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        unsigned long start = 0, end = 0, off = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %7s %lx", &start, &end, perms, &off) == 4 &&
            off == 0 && strstr(line, needle)) {
            fclose(fp);
            return start;
        }
    }
    fclose(fp);
    return 0;
}

static int pid_has_lib(pid_t pid, const char *oracle_home)
{
    return lib_base(pid, oracle_home) != 0;
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
    struct tcp_entry entries[4096];
    int nentries = parse_tcp4(entries, 4096);
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

static int discover_targets(const char *oracle_home, int tcps_port, struct target *targets, int max_targets)
{
    DIR *proc = opendir("/proc");
    if (!proc)
        return 0;
    int count = 0;
    struct dirent *de;
    while ((de = readdir(proc)) && count < max_targets) {
        if (!is_numeric(de->d_name))
            continue;
        pid_t pid = (pid_t)strtol(de->d_name, NULL, 10);
        if (pid <= 1 || pid == getpid())
            continue;
        if (!pid_has_lib(pid, oracle_home))
            continue;
        struct endpoint ep;
        memset(&ep, 0, sizeof(ep));
        if (endpoint_for_pid(pid, tcps_port, &ep) != 0)
            continue;
        targets[count].pid = pid;
        targets[count].ep = ep;
        count++;
    }
    closedir(proc);
    return count;
}

static void ip_to_str(uint32_t ip, char *out, size_t out_len)
{
    struct in_addr a;
    a.s_addr = ip;
    const char *s = inet_ntop(AF_INET, &a, out, out_len);
    if (!s)
        snprintf(out, out_len, "0.0.0.0");
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
        .snaplen = 262144,
        .network = 1
    };
    int rc = write_all(fd, &hdr, sizeof(hdr));
    close(fd);
    return rc;
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

static int append_plain_packet(int fd, const struct endpoint *ep, int server_to_client,
                               const uint8_t *payload, uint32_t payload_len,
                               uint32_t *seq_cli, uint32_t *seq_srv, uint16_t *ip_id)
{
    uint32_t src_ip = server_to_client ? ep->server_ip : ep->client_ip;
    uint32_t dst_ip = server_to_client ? ep->client_ip : ep->server_ip;
    uint16_t src_port = server_to_client ? ep->server_port : ep->client_port;
    uint16_t dst_port = server_to_client ? ep->client_port : ep->server_port;
    uint32_t seq = server_to_client ? *seq_srv : *seq_cli;
    uint32_t ack = server_to_client ? *seq_cli : *seq_srv;

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
    put16(ip + 4, (*ip_id)++);
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
    tcp[13] = 0x18;
    put16(tcp + 14, 65535);
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
    if (rc == 0) {
        if (server_to_client)
            *seq_srv += payload_len;
        else
            *seq_cli += payload_len;
    }
    return rc;
}

static unsigned long peek_text(pid_t pid, unsigned long addr)
{
    errno = 0;
    unsigned long v = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL);
    if (errno) {
        fprintf(stderr, "pid %d PEEKTEXT 0x%lx failed: %s\n", pid, addr, strerror(errno));
        exit(1);
    }
    return v;
}

static void poke_text(pid_t pid, unsigned long addr, unsigned long word)
{
    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)word) != 0) {
        fprintf(stderr, "pid %d POKETEXT 0x%lx failed: %s\n", pid, addr, strerror(errno));
        exit(1);
    }
}

static int try_poke_text(pid_t pid, unsigned long addr, unsigned long word)
{
    if (ptrace(PTRACE_POKETEXT, pid, (void *)addr, (void *)word) != 0) {
        fprintf(stderr, "pid %d cleanup POKETEXT 0x%lx failed: %s\n", pid, addr, strerror(errno));
        return -1;
    }
    return 0;
}

static int plausible_plain_packet(const uint8_t *buf, uint32_t len)
{
    if (len < 8 || len > 65535)
        return 0;
    uint32_t be_len = ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16) |
                      ((uint32_t)buf[2] << 8) | buf[3];
    return be_len == len;
}

static int dump_from_tracee(pid_t pid, int fd, const struct endpoint *ep, int server_to_client,
                            unsigned long buf_addr, uint32_t len,
                            uint32_t *seq_cli, uint32_t *seq_srv, uint16_t *ip_id)
{
    if (len < 8 || len > 65535)
        return 0;
    uint8_t *buf = malloc(len);
    if (!buf)
        return 0;
    ssize_t n = read_mem(pid, buf_addr, buf, len);
    if (n != (ssize_t)len || !plausible_plain_packet(buf, len)) {
        free(buf);
        return 0;
    }
    int rc = append_plain_packet(fd, ep, server_to_client, buf, len, seq_cli, seq_srv, ip_id);
    free(buf);
    return rc == 0;
}

static int trace_target(const struct target *target, const char *oracle_home, const char *pcap_path,
                        unsigned long write_off, unsigned long read_success_off, int max_packets)
{
    pid_t pid = target->pid;
    unsigned long base = lib_base(pid, oracle_home);
    if (!base)
        return 1;
    unsigned long write_addr = base + write_off;
    unsigned long read_addr = base + read_success_off;

    int fd = open(pcap_path, O_WRONLY | O_APPEND);
    if (fd < 0) {
        perror("open pcap");
        return 1;
    }

    char cip[64], sip[64];
    ip_to_str(target->ep.client_ip, cip, sizeof(cip));
    ip_to_str(target->ep.server_ip, sip, sizeof(sip));
    fprintf(stderr, "capturing pid=%d %s:%u <-> %s:%u write=0x%lx read_success=0x%lx\n",
            pid, cip, target->ep.client_port, sip, target->ep.server_port, write_addr, read_addr);

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) != 0) {
        fprintf(stderr, "attach pid %d failed: %s\n", pid, strerror(errno));
        close(fd);
        return 1;
    }
    int status = 0;
    waitpid(pid, &status, 0);

    unsigned long write_orig = peek_text(pid, write_addr);
    unsigned long read_orig = peek_text(pid, read_addr);
    poke_text(pid, write_addr, (write_orig & ~0xffUL) | 0xcc);
    poke_text(pid, read_addr, (read_orig & ~0xffUL) | 0xcc);
    int write_enabled = 1, read_enabled = 1;

    uint32_t seq_cli = 1000 + (uint32_t)pid;
    uint32_t seq_srv = 500000 + (uint32_t)pid;
    uint16_t ip_id = (uint16_t)pid;
    int captured = 0;

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    while (!g_stop && (max_packets <= 0 || captured < max_packets)) {
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            write_enabled = read_enabled = 0;
            break;
        }
        if (!WIFSTOPPED(status))
            continue;

        int sig = WSTOPSIG(status);
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) != 0)
            break;

        unsigned long trap = regs.rip - 1;
        int hit = 0;
        if (sig == SIGTRAP && trap == write_addr) {
            hit = 1;
            poke_text(pid, write_addr, write_orig);
            write_enabled = 0;
            regs.rip = write_addr;
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            uint32_t len = 0;
            if (read_u32(pid, regs.rdx, &len) == 0 &&
                dump_from_tracee(pid, fd, &target->ep, 1, regs.rsi, len, &seq_cli, &seq_srv, &ip_id)) {
                captured++;
                fprintf(stderr, "pid=%d server_to_client len=%u total=%d\n", pid, len, captured);
            }
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) || WIFSIGNALED(status))
                break;
            if (max_packets <= 0 || captured < max_packets) {
                poke_text(pid, write_addr, (write_orig & ~0xffUL) | 0xcc);
                write_enabled = 1;
            }
        } else if (sig == SIGTRAP && trap == read_addr) {
            hit = 1;
            poke_text(pid, read_addr, read_orig);
            read_enabled = 0;
            regs.rip = read_addr;
            ptrace(PTRACE_SETREGS, pid, NULL, &regs);
            uint32_t len = 0;
            if (read_u32(pid, regs.r12, &len) == 0 &&
                dump_from_tracee(pid, fd, &target->ep, 0, regs.r14, len, &seq_cli, &seq_srv, &ip_id)) {
                captured++;
                fprintf(stderr, "pid=%d client_to_server len=%u total=%d\n", pid, len, captured);
            }
            ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);
            waitpid(pid, &status, 0);
            if (WIFEXITED(status) || WIFSIGNALED(status))
                break;
            if (max_packets <= 0 || captured < max_packets) {
                poke_text(pid, read_addr, (read_orig & ~0xffUL) | 0xcc);
                read_enabled = 1;
            }
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            write_enabled = read_enabled = 0;
            break;
        }
        if (max_packets > 0 && captured >= max_packets)
            break;
        ptrace(PTRACE_CONT, pid, NULL, hit ? NULL : (void *)(long)sig);
    }

    if (write_enabled)
        (void)try_poke_text(pid, write_addr, write_orig);
    if (read_enabled)
        (void)try_poke_text(pid, read_addr, read_orig);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    close(fd);
    fprintf(stderr, "pid=%d done captured=%d\n", pid, captured);
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
    int max_packets = 0;

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
            max_packets = atoi(optarg);
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
        fprintf(stderr, "Could not create pcap %s: %s\n", out_pcap, strerror(errno));
        return 1;
    }

    fprintf(stderr, "oracle_home=%s tcps_port=%d out=%s nzpa_ssl_Write=0x%lx nzos_Read_success=0x%lx\n",
            oracle_home, tcps_port, out_pcap, write_off, read_success_off);
    fprintf(stderr, "waiting for active Oracle dedicated TCPS process on port %d...\n", tcps_port);

    struct target targets[MAX_TARGETS];
    int ntargets = 0;
    while (!g_stop) {
        ntargets = discover_targets(oracle_home, tcps_port, targets, MAX_TARGETS);
        if (ntargets > 0)
            break;
        sleep(1);
    }
    if (ntargets <= 0)
        return 1;

    pid_t children[MAX_TARGETS];
    int nchildren = 0;
    for (int i = 0; i < ntargets; i++) {
        pid_t child = fork();
        if (child == 0)
            _exit(trace_target(&targets[i], oracle_home, out_pcap, write_off, read_success_off, max_packets));
        if (child > 0)
            children[nchildren++] = child;
    }

    int rc = 0;
    for (int i = 0; i < nchildren; i++) {
        int st = 0;
        waitpid(children[i], &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0)
            rc = 1;
    }
    return rc;
}

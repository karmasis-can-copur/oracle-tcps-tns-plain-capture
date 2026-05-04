# Oracle TCPS Plaincap Lab

Authorized endpoint-side instrumentation proof of concept for capturing plaintext Oracle Net/TNS packet buffers after Oracle TCPS/TLS decryption, while traffic on the network remains encrypted.

This is a lab snapshot. It is not an Oracle auditing, SQL polling, proxy, TLS termination, or TLS weakening approach. The capture point is inside the authorized database server process after decrypt.

## Current Working Path

The main PoC is:

```text
src/oracle_tcps_plaincap_tracefs.c
```

It uses tracefs uprobes against Oracle `libnnzsrv.so` and writes a synthetic plaintext pcap containing the post-decrypt Oracle Net/TNS buffers.

Validated on the lab Oracle 26ai Free-style home:

```text
ORACLE_HOME=/opt/oracle/product/26ai/dbhomeFree
TCPS port=2484
library=/opt/oracle/product/26ai/dbhomeFree/lib/libnnzsrv.so
```

Observed hook points for this build:

```text
nzpa_ssl_Write offset:   0x11c570
nzos_Read success path:  nzos_Read + 0xfc
effective read offset:   0x137b6c
```

The program resolves `nzpa_ssl_Write` and `nzos_Read` from `nm` where possible, then applies the known `nzos_Read + 0xfc` success-path offset.

## Build

On the Oracle Linux server:

```bash
./scripts/build.sh
```

This produces:

```text
build/oracle_tcps_plaincap_tracefs
```

## Run

Run as root on the DB server:

```bash
sudo ./build/oracle_tcps_plaincap_tracefs \
  -H /opt/oracle/product/26ai/dbhomeFree \
  -p 2484 \
  -o /tmp/oracle_plain_tcps.pcap
```

or:

```bash
sudo ./scripts/run_tracefs_capture.sh \
  -H /opt/oracle/product/26ai/dbhomeFree \
  -p 2484 \
  -o /tmp/oracle_plain_tcps.pcap
```

Use `Ctrl+C` to stop. On graceful exit, the tool disables and removes its tracefs uprobes.

## Output

The pcap is synthetic plaintext traffic built from post-decrypt TNS buffers:

```text
/tmp/oracle_plain_tcps.pcap
```

Each payload preserves the packet-like Oracle Net/TNS bytes captured from the process, including the 4-byte big-endian length prefix observed in the plaintext buffers.

The pcap uses the real local TCP 4-tuple discovered from the Oracle dedicated server process where possible, but it is not a copy of the original encrypted TLS packets. It is intended for downstream parsing as a plaintext TNS stream.

## Validation

Network capture on port 2484 should still show encrypted TLS application data:

```bash
tcpdump -i any -s 0 -w /tmp/tcps_2484_encrypted.pcap port 2484
```

The plaintext capture should contain packet-like TNS data:

```bash
tcpdump -nn -r /tmp/oracle_plain_tcps.pcap | head
grep -a KARMASIS /tmp/oracle_plain_tcps.pcap
```

The marker grep is only a validation convenience. The goal is preserving plaintext packet buffers for the downstream parser.

## Cleanup

If the process is killed before graceful cleanup, remove the tracefs probes manually:

```bash
echo 0 > /sys/kernel/tracing/events/ora_plain/write/enable 2>/dev/null || true
echo 0 > /sys/kernel/tracing/events/ora_plain/read_success/enable 2>/dev/null || true
echo '-:ora_plain/write' >> /sys/kernel/tracing/uprobe_events 2>/dev/null || true
echo '-:ora_plain/read_success' >> /sys/kernel/tracing/uprobe_events 2>/dev/null || true
```

## Included Sources

```text
src/oracle_tcps_plaincap_tracefs.c  Main tracefs global uprobe capturer.
src/oracle_tcps_plaincap_ptrace.c   Older ptrace capturer, useful for persistent sessions.
src/nzpa_ptrace_dump.c              Discovery helper for buffer inspection.
src/oracle_plain_poll.c             Early polling helper.
src/nzos_trace_snap.c               Discovery helper for tracing candidate buffers.
```

The `remote_*.sh` lab scripts, portable SSH/Git tools, pcap files, and credential-bearing test material are intentionally excluded from this snapshot.

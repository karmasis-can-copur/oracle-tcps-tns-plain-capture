# Agent Compatibility Notes

The first plaintext pcap version exposed SQL/TTC data but was not a complete replayable Oracle Net session for parsers that expect the full Oracle Net startup exchange.

## Finding

A baseline plaintext TCP capture on port 1521 showed the session starts with classic Oracle Net/TNS packets:

```text
00 4a 00 00 01 ...                      CONNECT fragment
00 fa 00 00 06 ... DESCRIPTION=(...)    CONNECT data fragment
```

The earlier TCPS plaincap output started later:

```text
00 00 00 0a 0c ...
00 00 00 a3 06 ...
```

The missing `DESCRIPTION=(...)` was not primarily a replay concept problem. The hook saw these early buffers, but the filter only accepted 4-byte length frames, so classic 2-byte length TNS packets were discarded.

The next replay failure stopped at `processed=334`, which matched:

```text
74-byte CONNECT prefix
250-byte DESCRIPTION fragment
10-byte NS32 marker/control packet
```

That showed another missing piece: the 8-byte TNS `RESEND` response from `tnslsnr` and the subsequent repeated connect material from the dedicated process. The repeated `CONNECT/DESCRIPTION` packets are not duplicate capture noise; they are part of the real Oracle Net startup after `RESEND`.

## Fix

The tracefs capturer now accepts both observed plaintext packet families:

```text
TNS16: 2-byte big-endian length, packet type at byte 4.
NS32:  4-byte big-endian length, packet type at byte 4.
```

The synthetic session is keyed by TCP 4-tuple instead of PID. This matters because the same network session can surface in `tnslsnr` and later in a dedicated Oracle server process.

The tool also emits ACK-only frames after each synthetic data frame to make the pcap friendlier to TCP-stream reassemblers used by downstream agents.

Short listener responses can disappear before a later `process_vm_readv()` call. The uprobe event therefore includes the first 8 payload bytes inline, which preserves the observed TNS `RESEND` packet:

```text
00 08 00 00 0b 08 00 00
```

## Current Validation

The updated pcap begins with the `TNS16` connect material and contains the connection description:

```text
DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=freepdb1)...
```

Later packets continue as `NS32` data frames containing authentication, TTC, SQL text, and result data.

The corrected startup sequence now looks like:

```text
C->S TNS16 CONNECT prefix
C->S TNS16 DESCRIPTION fragment
S->C TNS16 RESEND
C->S TNS16 CONNECT prefix
C->S TNS16 DESCRIPTION fragment
S->C TNS16 ACCEPT
C->S NS32/TTC...
```

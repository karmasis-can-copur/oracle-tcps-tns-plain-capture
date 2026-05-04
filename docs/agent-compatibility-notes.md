# Agent Compatibility Notes

The first plaintext pcap version exposed SQL/TTC data but was not a complete replayable Oracle Net session for parsers that expect the session to begin with Oracle Net `CONNECT` material.

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

## Fix

The tracefs capturer now accepts both observed plaintext packet families:

```text
TNS16: 2-byte big-endian length, packet type at byte 4.
NS32:  4-byte big-endian length, packet type at byte 4.
```

The synthetic session is keyed by TCP 4-tuple instead of PID. This matters because the same network session can surface in `tnslsnr` and later in a dedicated Oracle server process.

The tool also emits ACK-only frames after each synthetic data frame to make the pcap friendlier to TCP-stream reassemblers used by downstream agents.

## Current Validation

The updated pcap begins with the `TNS16` connect material and contains the connection description:

```text
DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=freepdb1)...
```

Later packets continue as `NS32` data frames containing authentication, TTC, SQL text, and result data.

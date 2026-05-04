# Discovery Notes

The useful Oracle TCPS path in the lab dedicated server process is `libnnzsrv.so`, not the normal system OpenSSL `libssl` path.

Initial candidates in `libclntshcore.so` did not produce useful hits for the active server-side TCPS path.

Useful symbols discovered in `libnnzsrv.so`:

```text
nnz_SSL_read
nnz_SSL_write
nnz_SSL_read_ex
nnz_SSL_write_ex
nzos_Read
nzos_Write
nzpa_ssl_Write
```

`nzos_Write` is a wrapper. On the tested 26ai Free-style build it passes a plaintext packet buffer to `nzpa_ssl_Write`.

Observed argument mapping:

```text
nzpa_ssl_Write entry:
  %rsi        plaintext packet buffer
  *(u32 *)rdx plaintext packet length

nzos_Read success path at nzos_Read + 0xfc:
  %r14        plaintext packet buffer
  *(u32 *)r12 plaintext packet length
```

Plaintext packet buffers begin with a 4-byte big-endian packet length, followed by Oracle Net/TNS packet bytes.

That is true for post-connect `NS32` data frames. Early Oracle Net connect material uses a classic 2-byte TNS length field and packet type at byte 4. The first version rejected these early `TNS16` packets, which caused the output pcap to miss the `DESCRIPTION=(...)` connect data.

The tracefs PoC registers global uprobes so very fast session open/close traffic can be captured without first attaching to a specific PID. It keys synthetic sessions by TCP 4-tuple because early connection material can be observed in `tnslsnr`, while later buffers are observed in the dedicated server process.

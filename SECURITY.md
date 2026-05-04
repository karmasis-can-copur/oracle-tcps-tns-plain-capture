# Security Scope

This repository is for authorized database-server-side lab instrumentation.

The intended model is:

```text
customer-approved agent
runs on the Oracle DB server
captures buffers after local TCPS decrypt
network traffic remains encrypted
plaintext buffers are forwarded to an approved parsing pipeline
```

Do not use this code to intercept traffic on systems where you do not have explicit permission.

This project does not provide a TLS bypass, proxy, credential harvester, wire decryption method, or recommendation to weaken Oracle TCPS.

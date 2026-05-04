#!/usr/bin/env bash
set -euo pipefail

cc=${CC:-gcc}
mkdir -p build

"$cc" -O2 -Wall -Wextra -o build/oracle_tcps_plaincap_tracefs src/oracle_tcps_plaincap_tracefs.c
"$cc" -O2 -Wall -Wextra -o build/oracle_tcps_plaincap_ptrace src/oracle_tcps_plaincap_ptrace.c

echo "built:"
echo "  build/oracle_tcps_plaincap_tracefs"
echo "  build/oracle_tcps_plaincap_ptrace"

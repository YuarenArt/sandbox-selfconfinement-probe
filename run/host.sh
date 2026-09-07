#!/usr/bin/env bash
# Host baseline: the probe with no container around it at all.
#
# Run it as the unprivileged user you normally are. Several rows differ from the
# pod columns purely because of that — chroot, OPEN_TREE_CLONE and fanotify want
# capabilities a normal user does not have — and the point of keeping this
# column is exactly to show which rows are about privilege rather than about the
# runtime.
set -euo pipefail

HERE=$(cd "$(dirname "$0")/.." && pwd)
OUT=${OUT:-$HERE/results}

cd "$HERE"
make probe
mkdir -p "$OUT"
date=$(date +%F)
{
	echo "# host, no container"
	echo "# run as the invoking user, not root: rows needing capabilities fail here by design"
	echo "# date: $date"
	echo "# host kernel $(uname -r)"
	echo "# $(. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME")"
	echo "# gcc $(gcc -dumpversion)"
	echo
	./probe
} > "$OUT/$date-host-baseline.txt"
cat "$OUT/$date-host-baseline.txt"
echo
echo "wrote $OUT/$date-host-baseline.txt"

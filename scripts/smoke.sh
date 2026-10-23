#!/bin/sh
# Smoke-test one published release binary on a real OS with a real PHP.
# Usage: scripts/smoke.sh <binary> <tag> <php-binary>
# Passes when the binary reports the tag's version, scans without a scan
# error, and reports the same version that PHP itself reports.
set -eu
bin=$1 tag=$2 php=$3
chmod +x "$bin"

out=$("$bin" version)
echo "$out"
case "$out" in
*"php2shell-check ${tag#v} "*) ;;
*) echo "FAIL: expected version ${tag#v}" >&2; exit 1 ;;
esac

want=$("$php" -n -r 'echo PHP_VERSION;')
echo "PHP reports $want ($php)"

"$bin" --no-color --verbose || true # human output for the log
set +e
"$bin" --json >scan.json
code=$?
set -e
echo "exit code $code"
if [ "$code" -gt 2 ]; then
	echo "FAIL: scan error" >&2
	exit 1
fi
if ! jq -e --arg v "$want" '[.targets[0].installations[] | select(.version == $v)] | length >= 1' scan.json >/dev/null; then
	echo "FAIL: no installation reported version $want" >&2
	jq '.targets[0].installations[] | {real_path, sapi, version}' scan.json >&2
	exit 1
fi
echo "PASS: found PHP $want"

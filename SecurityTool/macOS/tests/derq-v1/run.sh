#!/bin/bash
# Source-owned behavioral regressions for the supported derq XML -> V1 DER path.
# Run INSIDE Darling with the deployed /usr/bin/derq:
#   DERQ=/usr/bin/derq bash /Volumes/SystemRoot/.../tests/derq-v1/run.sh
# Expected DER files are the native macOS 26.6.2 known answers recorded in
# darling-workspace/evidence/derq-native-contract-20261024b.tar.zst.

set -u
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DERQ=${DERQ:-/usr/bin/derq}
tmp=${TMPDIR:-/private/var/tmp}/derq-v1-test.$$
failures=0
cases=0

cleanup() {
    rm -f "$tmp" "$tmp.err"
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    failures=$((failures + 1))
}

pass() {
    echo "PASS: $*"
    cases=$((cases + 1))
}

run_case() {
    name=$1
    input=$2
    expected=$3
    shift 3
    "$DERQ" query -f xml -i "$here/$input" -o "$tmp" "$@" 2>"$tmp.err"
    rc=$?
    if [ "$rc" -ne 0 ]; then
        fail "$name (exit $rc): $(tr '\n' ' ' < "$tmp.err")"
    elif ! cmp -s "$tmp" "$here/$expected"; then
        fail "$name (DER mismatch)"
        echo "  first differing bytes (position, expected-octal, actual-octal):" >&2
        cmp -l "$here/$expected" "$tmp" 2>/dev/null | head -20 >&2 || true
    else
        pass "$name"
    fi
}

run_reject() {
    name=$1
    input=$2
    "$DERQ" query -f xml -i "$here/$input" -o "$tmp" 2>"$tmp.err"
    rc=$?
    if [ "$rc" -eq 0 ]; then
        fail "$name (accepted invalid input)"
    elif [ "$rc" -ge 128 ]; then
        fail "$name (died by signal, exit $rc)"
    else
        pass "$name"
    fi
}

run_case empty-value empty-value.plist empty-value.raw.der --raw
run_case empty-value-inner empty-value.plist empty-value.inner.der
run_case ordering ordering.plist ordering.raw.der --raw
run_case nested-and-number-edges nested-mixed.plist nested-mixed.raw.der --raw
run_case unsigned-2pow63 u63.plist u63.raw.der --raw
run_case unsigned-2pow64-minus1 u64max.plist u64max.raw.der --raw
run_case real-1.5 real-1.5.plist real-1.5.raw.der --raw
run_case real-1.0 real-1.0.plist real-1.0.raw.der --raw
run_reject empty-key empty-key.plist

# fd1 is a dup of the read-only /dev/null stdin, so the only available stdout
# is unwritable.  The DER is small enough to sit in stdio's buffer; the checked
# fflush must turn the eventual write failure into a nonzero exit.
"$DERQ" query -f xml -i "$here/empty-value.plist" -o - --raw </dev/null 1<&0 2>"$tmp.err"
rc=$?
if [ "$rc" -eq 0 ]; then
    fail "stdout-failure (reported success after short write)"
elif [ "$rc" -ge 128 ]; then
    fail "stdout-failure (died by signal, exit $rc)"
else
    pass "stdout-failure"
fi

echo "derq-v1 cases=$((cases + failures)) failures=$failures"
[ "$failures" -eq 0 ]

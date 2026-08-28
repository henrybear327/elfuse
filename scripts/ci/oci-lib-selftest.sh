#!/usr/bin/env bash
# Self-test for scripts/ci/oci-lib.sh: a diagnostic a wait_for predicate writes
# to fd 3 must survive the predicate's >/dev/null 2>&1. Needs no binary, store,
# or HVF.
# shellcheck source=scripts/ci/oci-lib.sh
. "$(dirname "$0")/oci-lib.sh"

# The subject runs as a child so its exit does not end this script; its stderr
# is captured to be measured rather than merely displayed.
tmpd="$(mktemp -d)"
trap 'rm -rf "$tmpd"' EXIT
errfile="$tmpd/err"

cat > "$tmpd/subject.sh" << 'SUB'
#!/usr/bin/env bash
. "$1"
evidence="$2"
doomed() {
    cat "$evidence" >&3
    fail "subject died before becoming ready"
}
wait_for 1 "readiness that never comes" doomed
SUB

evidence="$tmpd/evidence"
printf 'subject-crash-evidence\n' > "$evidence"
status=0
bash "$tmpd/subject.sh" "$OCI_CI_DIR/oci-lib.sh" "$evidence" 2> "$errfile" || status=$?

[ "$status" -ne 0 ] || fail "a predicate that called fail did not fail the script"
grep -F 'subject died before becoming ready' "$errfile" > /dev/null \
    || fail "wait_for discarded the predicate's fail message"
grep -F 'subject-crash-evidence' "$errfile" > /dev/null \
    || fail "wait_for discarded the evidence the predicate dumped"

echo "oci-lib selftest OK"

# The workload key list and the CI matrix must agree, or a case arm with no
# matrix entry silently never runs (the shape .ci/check-matrix-lists.sh guards
# for the test matrix).
script_keys="$(sed -n "s/^KEYS='\(.*\)'$/\1/p" "$ROOT/scripts/ci/oci-workload.sh" | tr '|' '\n' | sort)"
matrix_keys="$(sed -n '/^  workload:$/,/^  [a-z]/{ s/^ *- { key: \([a-z]*\),.*/\1/p; }' "$ROOT/.github/workflows/build.yml" | sort)"
[ -n "$script_keys" ] || fail "workload KEYS not found in oci-workload.sh"
[ -n "$matrix_keys" ] || fail "workload matrix keys not found in build.yml"
[ "$script_keys" = "$matrix_keys" ] || {
    echo "script keys: $script_keys" >&2
    echo "matrix keys: $matrix_keys" >&2
    fail "oci-workload.sh KEYS and build.yml workload matrix disagree"
}

# The case arms are the third list: an arm with no KEYS entry (and so no matrix
# entry) would pass the comparison above and never run.
case_keys="$(sed -n 's/^    \([a-z]*\)) .*/\1/p; s/^    \([a-z]*\))$/\1/p' "$ROOT/scripts/ci/oci-workload.sh" | sort)"
[ -n "$case_keys" ] || fail "workload case arms not found in oci-workload.sh"
[ "$script_keys" = "$case_keys" ] || {
    echo "script keys: $script_keys" >&2
    echo "case arms:   $case_keys" >&2
    fail "oci-workload.sh KEYS and its case arms disagree"
}

echo "workload key lists agree"

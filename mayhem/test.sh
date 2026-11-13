#!/usr/bin/env bash
#
# mayhem/test.sh — run the OpenOffice known-answer selftest that mayhem/build.sh built with normal
# flags (no sanitizers). It parses PDFs with sdext's pdfparse (object/stream counts, inflated stream
# hashes, re-emitted size) and reads/subsets a TrueType font with vcl's sft (family, metrics, cmap,
# Type 42 output) and asserts the exact values.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

BIN="$SRC/openoffice_selftest"
EXPECTED_CASES=27
if [ ! -x "$BIN" ]; then
  echo "missing $BIN — mayhem/build.sh did not build the selftest" >&2
  emit_ctrf "openoffice-selftest" 0 1
  exit 1
fi

out="$("$BIN" 2>&1)"
rc=$?
printf '%s\n' "$out"

passed=$(printf '%s\n' "$out" | grep -c '^PASS ')
failed=$(printf '%s\n' "$out" | grep -c '^FAIL ')
if ! printf '%s\n' "$out" | grep -qx "TOTAL passed=$EXPECTED_CASES failed=0"; then
  echo "selftest did not report TOTAL passed=$EXPECTED_CASES failed=0 (rc=$rc)" >&2
  failed=$(( failed + 1 ))
fi
if [ "$rc" -ne 0 ]; then
  failed=$(( failed + 1 ))
fi
emit_ctrf "openoffice-selftest" "$passed" "$failed"

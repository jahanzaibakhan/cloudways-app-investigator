#!/usr/bin/env bash
# Offline regression tests: parsers/bots, root-cause logic, end-to-end report, exact-count validation, scenario matrix.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL $1"; exit 1; }
python3 "$here/test_parsers_and_bots.py" >/dev/null || fail "parsers/bots"
echo "PASS parsers/bots"
python3 "$here/test_root_cause.py" > "$tmp/rca.txt" || fail "root-cause (crashed)"
grep -q "^a {'primary': 'traffic'" "$tmp/rca.txt" && grep -q "^b {'primary': 'database'" "$tmp/rca.txt" \
  && grep -q "^c {'primary': None" "$tmp/rca.txt" || fail "root-cause scenarios"
echo "PASS root-cause scenarios"
python3 "$here/make_fixtures.py" "$tmp" >/dev/null
python3 "$here/../analyze_cloudways_applications.py" --applications-root "$tmp/applications" --strict-root \
  --sample-seconds 4 --skip-mysql --skip-history --top 3 --no-color > "$tmp/report.txt" 2>"$tmp/err.txt" || { cat "$tmp/err.txt"; fail "end-to-end (crashed)"; }
awk '/9. ROOT CAUSE/,/10. INTERNAL/' "$tmp/report.txt" > "$tmp/rc.txt"
grep -q "Inefficient application (PHP) execution" "$tmp/rc.txt" && grep -q "Suspicious / bot traffic" "$tmp/rc.txt" \
  || fail "end-to-end report (root causes not found in section 9)"
echo "PASS end-to-end report"
python3 "$here/test_exact_counts.py" > "$tmp/exact.txt" || { grep -v "^PASS" "$tmp/exact.txt"; fail "exact counts"; }
tail -1 "$tmp/exact.txt"
python3 "$here/test_scenarios.py" > "$tmp/matrix.txt" || { grep -v "^PASS" "$tmp/matrix.txt"; exit 1; }
tail -1 "$tmp/matrix.txt"

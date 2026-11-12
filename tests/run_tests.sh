#!/usr/bin/env bash
# Offline regression tests: parsers, RCA scenarios, and an end-to-end run on synthetic app logs.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
python3 "$here/test_parsers_and_bots.py" >/dev/null && echo "PASS parsers"
python3 "$here/test_root_cause.py" > "$tmp/rca.txt"
grep -q "^a {'primary': 'traffic'" "$tmp/rca.txt" && grep -q "^b {'primary': 'database'" "$tmp/rca.txt" \
  && grep -q "^c {'primary': None" "$tmp/rca.txt" && echo "PASS root-cause scenarios"
python3 "$here/make_fixtures.py" "$tmp" >/dev/null
python3 "$here/../analyze_cloudways_applications.py" --applications-root "$tmp/applications" --strict-root \
  --sample-seconds 4 --skip-mysql --skip-history --top 3 --no-color > "$tmp/report.txt" 2>/dev/null
grep -A1 "▸ slowblog" "$tmp/report.txt" | grep -q . 
awk '/8. ROOT CAUSE/,/9. INTERNAL/' "$tmp/report.txt" > "$tmp/rc.txt"
grep -q "Inefficient application (PHP) execution" "$tmp/rc.txt" && grep -q "Suspicious / bot traffic" "$tmp/rc.txt" \
  && echo "PASS end-to-end report"
python3 "$here/test_scenarios.py" > "$tmp/matrix.txt" || { grep -v "^PASS" "$tmp/matrix.txt"; exit 1; }; tail -1 "$tmp/matrix.txt"

# Cloudways App Investigator

A read-only investigation tool for Cloudways servers. It finds the applications using the most CPU and memory and **explains why**, by correlating per-app resource use with traffic, PHP-FPM behaviour and MySQL/MariaDB activity. It ends with an evidence-backed root cause, internal PlatformOps recommendations, and a separate customer-ready response.

It replaces most of a manual "why is this server slow / which app is eating it" investigation with one command.

## Quick start

Run as root on the Cloudways server:

```bash
sudo -i
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/main/analyze_cloudways_applications.py | python3 - --top 5 --hour 1 --progress
```

Common variants:

```bash
U=https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/main/analyze_cloudways_applications.py

# investigate one application over the last 3 hours, sample live usage for 2 minutes
curl -sS "$U" | python3 - --only-app abcdefghij --hour 3 --minutes 2

# save a Markdown report for Jira/GitHub (ANSI-free, /tmp, mode 600) plus JSON
curl -sS "$U" | python3 - --top 5 --hour 1 --report --format markdown --json

# explicit window (UTC)
curl -sS "$U" | python3 - --from-time 12-11-2026:08 --to-time 12-11-2026:10
```

It needs Python ≥ 3.7 and only the standard library. Nothing is installed.

## What the report contains

1. Investigation Overview
2. Overall Server Health: CPU, load, memory, swap, iowait, steal, OOM, disks, PSI, and the CPU/RAM split between apps and shared services
3. Top N resource-consuming applications, with profile tags: High CPU, High Memory, Many FPM workers, Low traffic / high cost
4. Application Traffic Analysis: requests, req/min and req/s, unique IPs, top IPs/URLs/User-Agents, status codes, static vs dynamic, WordPress REST/admin-ajax/wp-login/xmlrpc/wp-cron, WooCommerce, bots, attack indicators
5. PHP-FPM Investigation: pool config, live and peak workers, listen queue, max_children hits, timeouts, duration percentiles, CPU ms/request, memory per request, slowest paths and slow-log functions
6. MySQL / MariaDB Investigation: connections, query rates, lock waits, deadlocks, slow-query fingerprints per database/app, running queries per database
7. Application-Level Bottlenecks: findings, each with numeric evidence and a confidence level
8. Root Cause Analysis: root cause, confidence (Confirmed / Likely / Suspected / Inconclusive) and a two-line summary
9. Internal PlatformOps Recommendations, each with the evidence that triggered it
10. Customer-Shareable Recommendations, in a copy-paste block
11. Evidence and Supporting Logs
12. Final Investigation Summary

## Options

| Option | Meaning |
|---|---|
| `--top N` | applications to investigate (default 5) |
| `--hour H` / `--from-time` `--to-time` | log/traffic window (default last 1h, UTC) |
| `--minutes M` / `--sample-seconds S` | live /proc sampling duration (default 30s) |
| `--only-app ID` | single application |
| `--report --format txt\|markdown` | save ANSI-free report to `--output-dir` (default /tmp, mode 600) |
| `--json` | machine-readable results |
| `--no-color`, `--progress`, `--verbose` | output control |
| `--skip-health`, `--skip-mysql`, `--skip-history` | skip optional collectors |
| `--explain` | opt-in read-only `EXPLAIN` for suspected full-scan SELECTs |

`--skip-health` is kept from the traffic analyzer for compatibility. Here it skips Redis/Varnish/OOM/filesystem checks; the WP health manager is never run. `--no-ip-lookup` is accepted and ignored, because this tool never sends visitor IPs to a third party.

## Data sources (in order of trust)

| Source | Gives | Measured / estimated |
|---|---|---|
| `php-app.access.log` (Cloudways FPM `access.format`) | per-request duration, peak memory, user+sys CPU % | **measured**. CPU-seconds = duration × CPU% (capped at 100% per request) |
| atop raw logs `/var/log/atop/atop_YYYYMMDD` (5-min intervals) | historical per-process CPU ticks and RSS, plus server CPU/MEM/SWP | **measured** (includes processes that exited during an interval) |
| `/proc` sampling (`--sample-seconds`) | live CPU per process, RSS, **PSS** (root), process state | measured. "Busy worker" = state R/D or CPU advanced (**estimated**) |
| `ss -xlnH` on pool sockets | FPM listen queue (Recv-Q of the LISTEN socket) | measured (live only) |
| `/var/log/php*-fpm.log` | `max_children` reached, "seems busy", `request_terminate_timeout` kills | measured |
| `php-app.slow.log` | stack traces, attributed to plugin/theme/vendor | measured |
| `backend_*.access.log` (post-Varnish) + `nginx-app.status.log` | traffic, bots, attack indicators | measured |
| MariaDB: GLOBAL STATUS deltas, PROCESSLIST samples, INNODB_TRX, INNODB STATUS, slow log | DB load, per-database running queries, slow fingerprints | measured. SQL literals are always masked |

## Accuracy review

1. **PHP-FPM process → application mapping.** The worker title `php-fpm: pool <name>` is resolved through the parsed pool config: the `-NN` PHP-version suffix is stripped (multi-PHP servers use `<app>-83`), then the `prefix`/`access.log`/`slowlog` path and the pool `user` are checked. Pool `user` equals the app's system user, so non-FPM processes such as WP-CLI, cron and workers are attributed by UID. That separation is exact: each Cloudways app has its own pool and user. Masters are reported as the shared `php-fpm-master` service.
2. **CPU attribution.** "Sustained CPU" uses the best source available for the window: atop history, then FPM access-log CPU-seconds, then live sampling. The report names the source per app. CPU is shown as % of one vCPU core and as % of server capacity. Live sampling misses CPU from workers that start and exit between samples (Cloudways uses `pm.process_idle_timeout=1s`), which is why the FPM log and atop are preferred.
   **Memory attribution:** PSS when running as root, which divides shared pages between workers so nothing is counted twice; otherwise RSS, which over-counts and is flagged as such. Shared services (MySQL, Redis, Varnish, Elasticsearch, Imunify…) are listed separately and never added to an app.
3. **Multiple pools.** Every `/etc/php/*/fpm/pool.d/*.conf` file is parsed. `include` is processed in place, so the global `cw_customization.conf` defaults come first and the app's `conf/fpm-pool.conf` overrides win, matching FPM's own precedence. When an app has pools in several PHP versions, the pool whose workers are running is chosen.
4. **Traffic → application.** Each app's own `logs/` directory is used, so no domain matching is needed. Backend requests are those that reached Apache/PHP after Varnish; the nginx total is shown alongside. PHP request counts come from the FPM log, which is the actual PHP execution count. Each log line is counted once, filtered by its own timestamp. Rotated `.gz` logs are read only if their mtime overlaps the window, and large plain logs are binary-searched to the window start.
5. **MySQL slow query → application.** The schema comes from the slow-log `Schema:`/`use` lines, or from the user, since the Cloudways DB user equals the DB name. It is mapped to the app via `DB_NAME` in wp-config.php, Magento env.php or Laravel `.env`, then the Cloudways convention db = app ID. `mysqldump` reads (`/*!40001 SQL_NO_CACHE */`) are classified as backups, not app load. Missing-index claims are **Suspected** (rows examined ≫ rows sent) unless `--explain` shows `type=ALL` with no key (**Confirmed**).

## Root-cause rules (summary)

- **Suspicious traffic** needs 3 or more independent indicators, or 2 when one of them is concentration or abuse (a dominant IP or /24, wp-login/xmlrpc POST floods). High volume alone is never an attack. The verdict is at most "Likely", never "Confirmed".
- **Traffic-driven**: high CPU, the app's share of server PHP CPU close to its share of PHP requests (≤1.6x), and CPU per request below 400 ms.
- **Optimization**: CPU share ≥3x request share, or ≥400 ms CPU/request, or a measured slow p95, slow-log traces or terminate-timeouts.
- **FPM saturation**: `max_children` reached or listen queue > 0 (Confirmed); all workers busy (Likely); estimated concurrency ≥ limit (Suspected). When it co-occurs with slow DB or slow PHP, the slowness is named as the cause and saturation as the symptom.
- **Upscaling** is recommended only when the load is traffic-driven **and** server pressure is sustained (atop average ≥75% busy or ≥50% of intervals ≥85%, memory ≥90%, heavy swap, or OOM kills). A momentary spike never triggers it.
- No evidence leads to "No sustained bottleneck" (when nothing is elevated) or **Inconclusive**.

## Safety

No package installs. No writes, except the optional report/JSON files. No restarts, kills or configuration changes. Every subprocess runs without a shell and with a timeout. SQL literals are masked, credentials are never read into output, and command lines shown for CLI processes have password arguments masked. Visitor IPs are not sent to external services.

## Validation status

- Parsers were tested against real log lines from a Debian 12 / MariaDB 11.4 / multi-PHP Cloudways server: FPM access format, backend access, atop `-P` output, FPM pool includes, MariaDB slow log and PHP slow log.
- An end-to-end run against synthetic app fixtures covered the slow-plugin, normal-traffic and wp-login brute-force cases. Unit tests covered the traffic-driven + upscale case and the DB-slow-causing-FPM-saturation case.
- **Live run** as root on a 1-vCPU Debian 12 Cloudways server with 10 apps and multi-PHP: about 28 s in total, with atop history (31 intervals), PSS, pool configs, listen queues, the MariaDB processlist and STATUS deltas all working. The first run's false positives were fixed: hidden directories counted as apps, the platform FPM pool counted as an app, lifetime CPU of PM2/node daemons flagged as current load, and a subnet signal that double-counted a single IP. The second run correctly reports "No sustained bottleneck" for every idle app.
- **Not yet seen live:** a server under real CPU/memory pressure, max_children breaches, or a busy MySQL slow log. Validate on a loaded server before relying on it fully.

## Development

```bash
tests/run_tests.sh      # offline: parsers, RCA scenarios, end-to-end report on synthetic app logs
```

`tests/mkfix.py` generates a synthetic Cloudways applications root with three cases: a slow-plugin app, a normal busy shop, and a wp-login brute-force target. To test changes on a real server without copying files, push a branch and run:

```bash
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/<branch-or-sha>/analyze_cloudways_applications.py | sudo python3 - --top 5 --hour 1
```

### Code layout (single file, by section)

| Section | Responsibility |
|---|---|
| Discovery | apps, FPM pools (includes and overrides), pool → app and user → app maps |
| Live sampling | `/proc` CPU/RSS/PSS, worker states, listen queues, disk/net, MySQL processlist hook |
| atop history | per-app and server CPU/memory over the window |
| FPM access / master / slow logs | per-request CPU-seconds, saturation, traces |
| Traffic | access-log analysis plus `traffic_signals()` attack indicators |
| MySQL | STATUS deltas, processlist, InnoDB, slow-log fingerprints, optional EXPLAIN |
| Profiles & ranking | `build_profiles()`, `resource_tags()` |
| Correlation engine | `investigate_app()`, `decide_root_cause()`, `server_findings()`, `recommendations()` |
| Rendering | `Doc` model, then txt/ANSI or Markdown |

All thresholds are CLI flags (`--cpu-threshold`, `--mem-threshold`, `--cpu-ms-per-req-threshold`, `--slow-p95-seconds`, `--slow-query-min`, `--long-query-seconds`, `--steal-threshold`, `--bg-cpu-threshold`).

## Origin

This tool merges and extends two earlier scripts: the backend traffic/DDoS analyzer (`jahanzaibakhan/opsgenie/analyze_cloudways_backend_traffic.py`) and the PHP-FPM performance analyzer by Osama Hilal (`OsamaHilal-CWDO/HealthChecks`).

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
2. Overall Server Health: CPU, load, memory, swap, iowait, steal, OOM, disks, PSI, the CPU/RAM split between apps and shared services, and the **issue origin** (applications / shared services / other processes / infrastructure)
3. Top N resource-consuming applications, with profile tags: High CPU, High Memory, Many FPM workers, Low traffic / high cost
4. Application Traffic Analysis: requests, req/min and req/s, unique IPs, top IPs/URLs/User-Agents, status codes, static vs dynamic, WordPress REST/admin-ajax/wp-login/xmlrpc/wp-cron, WooCommerce, bots, attack indicators
5. PHP-FPM Investigation: pool config, live and peak workers, listen queue, max_children hits, timeouts, duration percentiles, CPU ms/request, memory per request, slowest paths and slow-log functions
6. MySQL / MariaDB Investigation: connections, query rates, lock waits, deadlocks, slow-query fingerprints per database/app, running queries per database
7. Application-Level Bottlenecks: findings, each with numeric evidence, severity, a confidence level and a recommended next action
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
| `--long-request-seconds N` | live: an FPM worker busy continuously this long counts as a long-running request (default 10) |
| `--pool-conf-glob G` | comma-separated globs for PHP-FPM pool configs (default `/etc/php/*/fpm/pool.d/*.conf,/etc/php-fpm.d/*.conf`) |
| `--help`, `--version` | usage and version |

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

## Safety (read-only by design)

The script only reads. It never:

- installs anything (no pip/apt/yum, and no auto-install of optional libraries)
- changes PHP-FPM, MySQL, web server or system configuration
- restarts, reloads, enables or disables services
- kills processes
- changes files, permissions, logs, cron jobs, firewall rules or databases

MySQL is queried only with `SHOW` / `SELECT` against `information_schema`, plus `EXPLAIN` if you pass `--explain`. Every subprocess runs without a shell and with a timeout. Large logs are streamed (and binary-searched to the window start), never loaded into memory.

SQL literals are masked, credentials are never printed, and password-like arguments in process command lines are masked. Visitor IPs are never sent to an external service. The only files it writes are the optional `--report`/`--json` outputs, to `--output-dir` (default `/tmp`, mode 600), and their paths are printed at the end.

## Architecture

```
discover apps + PHP-FPM pools ──► per-app CPU-seconds from php-app.access.log (all apps, window)
        │                                    │
        ▼                                    ▼
live /proc sampling (N samples) ──► atop history (window) ──► rank apps (CPU share + memory share)
  + MySQL processlist each sample                                  │ top N
        │                                                          ▼
        └──────────► deep per-app analysis: traffic, FPM access/slow/master logs,
                     pool limits, listen queue, MySQL slow-log + live per-DB
                                          │
                                          ▼
         correlation engine: findings (evidence, severity, confidence, next action)
            → root cause per app → issue origin (apps / services / other / infra)
            → internal + customer recommendations → txt / ANSI / Markdown / JSON
```

**Mapping app → processes:** PHP-FPM workers are matched by `php-fpm: pool <name>` and the parsed pool config. Everything else (WP-CLI, cron, node/PM2) is matched by the app's system user, which equals the pool `user`. Unresolvable pools (platform pools) are reported as shared services.

**Mapping database → app:** `DB_NAME` from wp-config.php, Magento env.php or Laravel `.env` (labelled *config*). Failing that, the Cloudways convention that the database name equals the app ID (labelled *naming*). Anything else is shown as *unmapped*.

## Example output

This excerpt is from the synthetic test fixture (`tests/mkfix.py`), run on macOS, so the live `/proc` columns show `n/a`. On a Linux server they are filled in.

```
3. TOP 3 RESOURCE-CONSUMING APPLICATIONS
  | # | Application | CPU live | CPU live pk | CPU window | CPU win pk | Srv% | Mem live | Mem window |
  | 1 | slowblog    |      n/a |         n/a |        50% |        n/a |   5% |      n/a |        n/a |
  ...
7. APPLICATION-LEVEL BOTTLENECKS (KEY FINDINGS)
▸ slowblog
  - [WARNING] Slow PHP execution (measured in PHP-FPM access log) [Confirmed]
      - p95 11.53s, p99 11.89s, max 12.0s over 328 requests
      - Top CPU path: / - 132 hits, 716.5s CPU, avg 7.038s
      - Next action: Profile the slowest paths listed; check slow-log traces
          and slow queries for the same window.
  - [WARNING] 1 slow-log traces (> request_slowlog_timeout ?) [Confirmed]
      - Components: plugin:heavy-sync (1)
      - curl_exec() at wp-content/plugins/heavy-sync/api.php:88 - 1 traces
8. ROOT CAUSE ANALYSIS
▸ slowblog
  Root cause   : Inefficient application (PHP) execution
  Confidence   : Likely
  slowblog (wordpress) used ~50% of one CPU core (5% of server capacity) ...
  Most likely reason [Likely]: inefficient application (PHP) execution.
10. CUSTOMER-SHAREABLE RECOMMENDATIONS
  >>> BEGIN CUSTOMER RESPONSE >>>
  Application Optimization Required (slowblog)
  The investigation identified resource-intensive PHP execution associated
    with the application. We recommend reviewing the application code,
    plugins, themes and scheduled tasks to improve execution efficiency.
  Unwanted / Bot Traffic Mitigation (botsite)
  ...
  <<< END CUSTOMER RESPONSE <<<
```

## Known limitations

- **No PHP-FPM status page on Cloudways.** "Busy" and "idle" workers are estimated from process state and CPU activity. Live long-running requests are inferred from a worker staying busy continuously; the script path comes from the slow log, not from the worker.
- **Live sampling misses very short-lived workers** (`pm.process_idle_timeout=1s`). Window CPU therefore prefers atop history and FPM access-log CPU-seconds.
- **FPM access-log CPU% covers PHP-FPM requests only.** CLI and cron CPU comes from atop and live sampling.
- **Per-database query counts aren't available** while `performance_schema` is OFF, which is the Cloudways default. Database activity per app is limited to processlist samples (connections and running queries) and the slow log.
- **The slow log only contains queries over `long_query_time`** (5 s on Cloudways), so moderately slow, high-frequency queries are not visible.
- **Missing-index claims stay *Suspected*** unless `--explain` is used.
- **The listen queue is only measured live,** through `ss`. Historical saturation comes from the "max_children reached" warnings in the FPM master log.
- **Peak concurrency in the window is an estimate,** derived from busy worker-seconds per second.
- **As non-root,** MySQL, atop, PSS, pool overrides and some logs are unavailable. The report lists each one.
- **Traffic analysis needs the Cloudways log layout** (`<app>/logs/backend_*.access.log` or the nginx access/status logs).

## Testing results

What was actually run (2026-11-12):

| Test | Environment | Result |
|---|---|---|
| Parser tests: FPM access, backend access, atop `-P`, pool includes, MariaDB and PHP slow logs | real log lines from a Debian 12 / MariaDB 11.4 Cloudways server | pass |
| RCA scenarios: traffic-driven + upscale, DB slowness causing FPM saturation, idle app | unit test | pass |
| `tests/test_matrix.py` (17 checks) | macOS, synthetic | **17/17 pass** |
| ↳ 121 apps, run time | | 4.6 s |
| ↳ multi-PHP pools (7.4/8.1/8.2/8.3), app `fpm-pool.conf` override beats the global default | | pass |
| ↳ low-traffic / high-CPU app ranked #1, root cause = optimization | | pass |
| ↳ xmlrpc flood → suspicious; busy legitimate app → not suspicious | | pass |
| ↳ nginx-only app (no backend log), app with no logs, unreadable log, hidden dir | | pass, no crash |
| ↳ credentials never printed; Markdown file has no ANSI codes; every finding has a next action | | pass |
| Live, root | 1-vCPU Debian 12 Cloudways server, 10 apps, PHP 8.3/8.4, MariaDB 11.4, atop | pass, 26–28 s; all collectors working |
| Live, non-root | same server, unprivileged user | pass; MySQL/atop/PSS/FPM logs reported as unavailable, no crash |

**Not yet tested on a real server:** sustained high CPU or memory pressure, real max_children breaches, OOM kills, a busy MySQL slow log, a Lightning (nginx-only) stack, or a server with 50–100+ real apps. The logic for these was tested only with synthetic data. Run it on such a server and compare its conclusions with a manual investigation before relying on it fully.

## Development

```bash
tests/run_tests.sh      # offline: parsers, RCA scenarios, end-to-end report, 17-check scenario matrix
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

All thresholds are CLI flags (`--cpu-threshold`, `--mem-threshold`, `--cpu-ms-per-req-threshold`, `--slow-p95-seconds`, `--slow-query-min`, `--long-query-seconds`, `--steal-threshold`, `--bg-cpu-threshold`, `--long-request-seconds`).

## Origin

This tool merges and extends two earlier scripts: the backend traffic/DDoS analyzer (`jahanzaibakhan/opsgenie/analyze_cloudways_backend_traffic.py`) and the PHP-FPM performance analyzer by Osama Hilal (`OsamaHilal-CWDO/HealthChecks`).

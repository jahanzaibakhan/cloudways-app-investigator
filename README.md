# Cloudways App Investigator

A read-only investigation tool for Cloudways servers. It finds the applications using the most CPU and memory and **explains why**, by correlating per-app resource use with traffic, PHP-FPM behaviour and MySQL/MariaDB activity. It ends with an evidence-backed root cause, internal PlatformOps recommendations, and a separate customer-ready response.

It replaces most of a manual "why is this server slow / which app is eating it" investigation with one command.

See [CHANGELOG.md](CHANGELOG.md) for version history.

## Quick start

Run as root on the Cloudways server:

```bash
sudo -i
curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/main/analyze_cloudways_applications.py | python3 - --top 5 --hour 1 --progress
```

Common variants:

```bash
U=https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/main/analyze_cloudways_applications.py

# only the shareable reports for CRITICAL/HIGH apps, each also saved as its own file
curl -sS "$U" | python3 - --top 5 --hour 1 --app-reports-only --report

# investigate one application over the last 3 hours, sample live usage for 2 minutes
curl -sS "$U" | python3 - --only-app abcdefghij --hour 3 --minutes 2

# save a Markdown report for Jira/GitHub (ANSI-free, /tmp, mode 600) plus JSON
curl -sS "$U" | python3 - --top 5 --hour 1 --report --format markdown --json

# explicit window (UTC)
curl -sS "$U" | python3 - --from-time 12-11-2026:08 --to-time 12-11-2026:10
```

It needs Python ≥ 3.7 and only the standard library. Nothing is installed.

## What the report contains

After the **Investigation Overview** (server, window, privileges, data sources):

> In the terminal, apps with CRITICAL findings are shown **red and underlined** and HIGH apps **orange and underlined** everywhere they appear, so you can follow one app through the whole report.

1. **Critical Findings**
2. **High-Priority Findings** (HIGH, plus the top WARNINGs). Each shows the application, key metrics, evidence, confidence and next action.
   - **Shareable application report** for every CRITICAL/HIGH app: one self-contained block (and, with `--report`, one file per app) with that app's summary, findings, resources, traffic, bots, slow PHP requests, server errors, MySQL slow queries and the matching customer recommendations. It holds only that app's data and no internal notes, so it is ready to paste into the customer's ticket.
3. **Top Resource-Consuming Applications**: CPU and memory live vs window average/peak, PHP and backend requests, busy/idle workers, profile tags
4. **Top Bots Across the Server**: one ranking over all applications
5. **Overall Server Health**: CPU, load, memory, swap, iowait, steal, disks, an **OOM kill table** (each kill attributed to its application or service, with memory at kill, trigger and scope), PSI, CPU/RAM split between apps and shared services, and the **issue origin** (applications / shared services / other processes / infrastructure)
6. **Application Traffic & Bot Analysis**: requests, req/min and req/s, unique IPs, top IPs/URLs/User-Agents, status codes, static vs dynamic, WordPress REST/admin-ajax/wp-login/xmlrpc/wp-cron, WooCommerce, attack indicators, and a per-app top-10 bot table with estimated PHP cost
7. **PHP-FPM Investigation & Slow Requests**: pool config, workers, listen queue, max_children hits, timeouts, duration percentiles, per-app processes. Also the 10 slowest / highest-CPU / highest-memory requests (wall time vs CPU time vs wait), repeated slow URLs, 5xx responses, and plugin/theme involvement from slow logs.
8. **MySQL / MariaDB Investigation**: connections, query rates, lock waits, deadlocks, running queries per database, and slow queries as top-10 slowest, top-10 by total time and most frequent, with database → app mapping
9. **Root Cause Analysis & Key Findings**: per-app root cause, confidence, two-line summary, then every finding with evidence and next action
10. **Internal PlatformOps Recommendations**, each with the evidence that triggered it
11. **Customer-Shareable Recommendations**, in a copy-paste block
12. **Supporting Evidence**: slow-log traces, logs read, data availability notes

The report ends with the **Final Findings Summary**: Finding / Application / Severity / Recommended action, most severe first.

## Options

| Option | Meaning |
|---|---|
| `--top N` | applications to investigate (default 5) |
| `--hour H` / `--from-time` `--to-time` | log/traffic window (default last 1h, UTC) |
| `--minutes M` / `--sample-seconds S` | live /proc sampling duration (default 30s) |
| `--only-app ID` | single application |
| `--report --format txt\|markdown` | save ANSI-free report to `--output-dir` (default /tmp, mode 600) |
| `--json` | machine-readable results |
| `--app-reports-only` | print only the shareable per-application reports (CRITICAL/HIGH apps) |
| `--no-app-reports` | leave the per-application reports out of the output and saved files |
| `--no-color`, `--progress`, `--verbose` | output control |
| `--skip-health`, `--skip-mysql`, `--skip-history` | skip optional collectors |
| `--explain` | opt-in read-only `EXPLAIN` for suspected full-scan SELECTs |
| `--long-request-seconds N` | live: an FPM worker busy continuously this long counts as a long-running request (default 10) |
| `--pool-conf-glob G` | comma-separated globs for PHP-FPM pool configs (default `/etc/php/*/fpm/pool.d/*.conf,/etc/php-fpm.d/*.conf`) |
| `--no-dns-verify` | skip reverse/forward DNS verification of claimed search-engine bots |
| `--dns-verify-max N` | max IPs DNS-verified per run (default 60) |
| `--bot-share-high` / `--bot-share-warn` | bot share of backend requests rated HIGH / WARNING (default 25% / 10%) |
| `--bot-high-cpu` / `--bot-min-cpu` | bot PHP CPU (% of one core, window avg) needed for HIGH / below which a bot under 60 req/min is never flagged (default 5 / 2) |
| `--cpu-high` / `--cpu-critical` / `--mem-high` | app severity thresholds as % of server capacity / RAM (default 40 / 70 / 30) |
| `--attack-min-rpm` | below this backend req/min on an app without resource pressure, attack patterns are downgraded to INFO (Suspected) / WARNING (Likely) (default 60) |
| `--php-rpm-per-core-warn` | PHP requests/min per vCPU considered high volume (default 120) |
| `--server-bots-top N` / `--skip-bot-census` | size of the server-wide bot ranking (default 10) / skip that pass |
| `--bot-requests-high` / `--bot-rpm-high` / `--bot-php-requests-high` | bot volume thresholds: requests per hour (5000), req/min (60), estimated PHP requests per hour (2000). Volume alone gives at most WARNING |
| `--slow-request-seconds` / `--very-slow-request-seconds` / `--request-mem-high` | request flags SLOW (5s), HIGH (2x), VERY SLOW (30s), HIGH-MEM (256 MB) |
| `--db-conn-high` | per-database connection peak flagged (default 40) |
| `--kernel-log-glob G` | kernel logs searched for OOM kills, in order (default `/var/log/kern.log*,/var/log/syslog*,/var/log/messages*`; falls back to `journalctl -k`) |
| `--help`, `--version` | usage and version |

`--skip-health` is kept from the traffic analyzer for compatibility. Here it skips Redis/Varnish/OOM/filesystem checks; the WP health manager is never run. `--no-ip-lookup` is accepted and ignored, because this tool never sends visitor IPs to a third party.

## Output options compared

These options control different things and can be combined. The investigation itself (sampling, logs, MySQL, analysis) is identical with all of them; they only change what is shown and saved.

| Option | What it changes | Where it goes | Report content |
|---|---|---|---|
| *(none)* | nothing; the default | stdout | full report (all sections + shareable app reports) |
| `--progress` | adds timestamped **status messages while the script runs** (`[ 12.3s] Live resource sampling…`) | **stderr** | unchanged; never in saved files |
| `--verbose` | everything `--progress` shows, plus debug lines (failed queries, timeouts, data notes as they happen) | stderr | unchanged |
| `--app-reports-only` | prints **only the shareable reports** for CRITICAL/HIGH apps, or one line saying there are none | stdout | the other sections are not printed (they are still computed, and still saved with `--report`) |
| `--no-app-reports` | leaves the shareable app reports out | stdout and saved files | full report without the app blocks |
| `--report` | saves to `--output-dir` (default `/tmp`, mode 600) | files | the full report **plus** one `cloudways_app_<app>_<ts>` file per CRITICAL/HIGH app, even with `--app-reports-only` |
| `--json` | also saves machine-readable results | file | all collected data |
| `--format markdown` | Markdown instead of plain text, for Jira/GitHub | stdout and saved files | same content |
| `--no-color` | no ANSI colours, and no red/orange app-name highlighting | stdout | same content |

**`--progress` vs `--app-reports-only` in one line:** `--progress` tells you what the script is *doing* while it runs; `--app-reports-only` decides *which report* you see at the end.

Typical combinations:

```bash
U=https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/main/analyze_cloudways_applications.py

# watch progress, read the full report on screen
curl -sS "$U" | python3 - --top 5 --hour 1 --progress

# only what you will paste to the customer, plus all files saved for the internal ticket
curl -sS "$U" | python3 - --top 5 --hour 1 --progress --app-reports-only --report

# progress on screen, clean report into a file (progress goes to stderr, so it doesn't end up in the file)
curl -sS "$U" | python3 - --top 5 --hour 1 --progress --no-color > /tmp/investigation.txt
```

## Bot & crawler analysis

Each top application gets a bot table (Bot, Category, Requests, Share, /min, IPs, Dynamic %, est. PHP CPU, Status). HIGH and WARNING bots also get their top IPs, URLs, status codes and DNS verification result.

- **Identification:** about 50 signatures plus a generic `*bot|crawler|spider` fallback, in five categories:
  1. verified search engines
  2. commercial SEO crawlers (AhrefsBot, SemrushBot, MJ12bot, DotBot…)
  3. AI crawlers (GPTBot, ClaudeBot, Bytespider, CCBot, PerplexityBot…)
  4. other automated bots (monitors, social previews, scripts, scanners)
  5. unknown or suspicious (empty User-Agent, outdated/spoofed browser User-Agents, impersonators)
- **Verification:** claimed Googlebot/Bingbot/Applebot/Yandex/Baidu/Petal/Seznam (and Ahrefs/Semrush) IPs are checked with reverse DNS, then forward DNS. This uses the server's own resolver, never a third-party API, and is bounded by `--dns-verify-max` and 4 s timeouts. A wrong domain, a forward mismatch or no PTR record means **impersonation**. A timeout or resolver error is *inconclusive*; it is never taken as impersonation.
- **Cost attribution:** each bot's PHP requests and CPU are **estimated** by joining its client IPs with `php-app.access.log`. That log records the client IP and per-request CPU, but not the User-Agent.
- **Rating:** shares alone never flag a bot; HIGH also needs real PHP cost (≥ `--bot-high-cpu`, 5% of a core), and WARNING needs ≥2% of a core or ≥60 req/min. A bot that mostly fetches static or cached files is never rated HIGH, and its finding is INFO. Verified search engines are only HIGH if they drive ≥40% of the app's PHP CPU, and the advice is to tune their crawl rate, never to block them. Named crawlers are kept out of the attack heuristics, so a busy AhrefsBot is "bot traffic", not "DDoS".
- **Suspicious patterns:**
  - dominant IP or /24, or high per-IP rate
  - wp-login and xmlrpc POST floods
  - wp-admin hammering from one IP
  - 403/404 scanning
  - heavy REST or WooCommerce Store API use
  - spoofed or headless User-Agents
  - search-engine impersonation
- **No per-bot MySQL attribution:** this would need per-request database data, so the report says so explicitly.

## Severity model

| Level | Colour | Meaning |
|---|---|---|
| CRITICAL | red | confirmed service-impacting bottleneck or serious abnormal activity (OOM kills, queued FPM requests, ≥10 max_children hits, ≥30 min of slow queries/hour, app ≥70% of a saturated server) |
| HIGH | orange | significant consumption or strong bottleneck evidence |
| WARNING | yellow | elevated usage or a developing issue |
| INFO | blue | observation without an identified problem |
| HEALTHY | green | nothing significant |

Severity is set in one calibration pass that takes into account server size (shares of total capacity and requests per vCPU), sample length (live-only findings are capped at WARNING when `--sample-seconds` < 60) and whether the pressure is sustained (atop history versus a single sample). All thresholds are flags.

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

This excerpt is from the synthetic test fixture (`tests/make_fixtures.py`), run on macOS, so the live `/proc` columns show `n/a`. On a Linux server they are filled in.

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
- **Bot PHP cost is estimated by client IP.** Humans and bots sharing an IP (NAT, proxies) blur it. Cloudflare-proxied sites need the real client IP in the logs, which Cloudways normally provides.
- **DNS verification covers engines with published reverse-DNS domains.** DuckDuckBot, MJ12bot and most AI crawlers can't be verified this way and are labelled by User-Agent only.
- **OOM attribution needs a kernel that logs the victim's UID or cgroup** (Linux 4.19+/5.x, Debian 10+). On older kernels the killed process name is still shown, but the owner falls back to the process name. Kills of PHP-FPM workers are attributed to the app through the pool user; if two apps shared a system user they couldn't be told apart, but Cloudways uses one user per app.
- **Traffic analysis needs the Cloudways log layout** (`<app>/logs/backend_*.access.log` or the nginx access/status logs).

## Testing results

What was actually run (2026-11-12):

| Test | Environment | Result |
|---|---|---|
| Parser tests: FPM access, backend access, atop `-P`, pool includes, MariaDB and PHP slow logs | real log lines from a Debian 12 / MariaDB 11.4 Cloudways server | pass |
| RCA scenarios: traffic-driven + upscale, DB slowness causing FPM saturation, idle app | unit test | pass |
| `tests/test_exact_counts.py` (38 checks, incl. OOM kill parsing and attribution by UID/cgroup, memory at kill, trigger, dedupe, window, and the end-to-end CRITICAL block / OOM table / app report): hand-built logs with known answers (request counting incl. out-of-window, bot classification and %, server census, CPU-seconds, wall vs CPU vs wait, 5xx, repeated slow URLs, bot CPU by IP, MySQL count/total/avg/max, dump detection, literal masking, Markdown table shape, no ANSI, no password leak) | macOS | **38/38 pass** |
| `tests/test_scenarios.py` (27 checks, incl. per-app reports: one per CRITICAL/HIGH app, no other apps' data, no internal notes, one file each) | macOS, synthetic | **27/27 pass** |
| ↳ 124 apps, run time | | 4.8 s |
| ↳ multi-PHP pools (7.4/8.1/8.2/8.3), app `fpm-pool.conf` override beats the global default | | pass |
| ↳ low-traffic / high-CPU app ranked #1, root cause = optimization | | pass |
| ↳ xmlrpc flood → suspicious; busy legitimate app → not suspicious | | pass |
| ↳ nginx-only app (no backend log), app with no logs, unreadable log, hidden dir | | pass, no crash |
| ↳ AhrefsBot on dynamic pages → SEO crawler, HIGH, ~94% of app PHP CPU by IP, root cause "bot traffic driving PHP" | | pass |
| ↳ Googlebot fetching only static files → not HIGH, <5% PHP CPU, INFO finding | | pass |
| ↳ alert block and final findings table rendered | | pass |
| DNS verification with a stubbed resolver: genuine, wrong domain, suffix trick, forward mismatch, no PTR, timeout (must not count as impersonation) | unit test | pass |
| ↳ credentials never printed; Markdown file has no ANSI codes; every finding has a next action | | pass |
| Live, root | 1-vCPU Debian 12 Cloudways server, 10 apps, PHP 8.3/8.4, MariaDB 11.4, atop | pass, 26–28 s; all collectors working |
| Live, non-root | same server, unprivileged user | pass; MySQL/atop/PSS/FPM logs reported as unavailable, no crash |

**Not yet tested on a real server:** sustained high CPU or memory pressure, real max_children breaches, OOM kills, a busy MySQL slow log, a Lightning (nginx-only) stack, or a server with 50–100+ real apps. The logic for these was tested only with synthetic data. Run it on such a server and compare its conclusions with a manual investigation before relying on it fully.

## Development

```bash
tests/run_tests.sh      # runs everything offline; exits non-zero on any failure - run before every push
```

The `tests/` folder is for development only. Servers fetch just `analyze_cloudways_applications.py` with `curl`, so this folder never reaches them.

| File | What it checks |
|---|---|
| `tests/run_tests.sh` | runs all of the below |
| `tests/test_parsers_and_bots.py` | log parsers (real Cloudways line formats), SQL masking, pool includes, bot verification with a stubbed DNS resolver, bot rating |
| `tests/test_root_cause.py` | root-cause and recommendation logic (traffic-driven + upscale, DB slowness causing FPM saturation, idle app) |
| `tests/test_exact_counts.py` | 38 deterministic checks with exact expected numbers (counting, percentages, PHP-FPM metrics, MySQL aggregation, masking, formatting) |
| `tests/test_scenarios.py` | 27-check end-to-end matrix on 124 synthetic apps (multi-PHP pools, missing/unreadable logs, nginx-only app, xmlrpc flood, crawlers, impersonation) |
| `tests/make_fixtures.py` | builds a small synthetic Cloudways applications root (slow plugin, busy shop, wp-login brute force) |

To test changes on a real server without copying files there, push a branch and run:

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

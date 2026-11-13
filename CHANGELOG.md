# Changelog

All notable changes to `analyze_cloudways_applications.py`. The execution command and every existing flag stay compatible across versions.

## 1.7.0 - 2026-11-13

### Changed
- **Application reports present findings as paragraphs**, not bullet lists:
  - an "Overall" line with the counts per severity
  - **"What is happening"**: impact, i.e. server errors, OOM kills, PHP worker limit and queue, timeouts, slow pages, CPU/memory use
  - **"Why"**: causes, i.e. the heaviest URL, CPU per request, plugins/themes in slow-log traces, slow database queries, DB connections, bots, abusive traffic, long-running requests, background processes

  Each sentence is built from the measured values and only appears when the matching finding exists, so the text is ready to paste into a ticket.

### Added
- **Alarming values in red** (terminal) and **bold** (Markdown); plain in saved `.txt` files. In the app report this covers:
  - the #1 most requested URL and the #1 visitor IP, always
  - any URL above 20% of traffic, any IP above 10% or belonging to a flagged bot
  - 5xx status codes above 5%, HIGH bots and the top IP of each, impersonators
  - request durations at/above the slow threshold, HIGH-MEM requests, 5xx responses
  - the top repeated slow URL and the top slow-query pattern, queries averaging ≥10 s or peaking ≥30 s, more than 300 s of slow queries in total
  - every key number in the paragraphs

  Table alignment is unchanged.

## 1.6.0 - 2026-11-13

### Changed
- **The default screen output is now a compact summary** (about 60 lines for 2 apps, instead of several hundred). It contains:
  - one server-status line, each metric coloured on its own
  - the issue origin
  - one line per CRITICAL/HIGH finding with its key metrics, and WARNINGs collapsed into one line
  - a top-apps table (CPU, memory, PHP/min, p95, bot %, workers, short root cause)
  - the top 5 bots with their top IP
  - a short digest per app: traffic, PHP, slow URLs, slow-log plugins, MySQL, OOM, next action
  - the customer-shareable recommendations

  **`--full`** prints the complete 12-section report as before. `--report` saves the full report, the summary (`cloudways_summary_<ts>`) and the per-app reports. `--app-reports-only` is unchanged.
- **Width follows the terminal** (up to 160 columns; 120 when piped or saved) instead of a fixed 78, so lines no longer wrap early. `--width N` overrides.

### Fixed
- **Double-counted applications:** an app directory reached through a symlink (e.g. `magento2_prd -> weryrreupf`) was analysed as a second application with the same logs, so traffic and CPU appeared twice. Apps are now de-duplicated by real path: they are counted once under the real app ID, and the alias is shown next to it.
- **Misleading CPU finding title:** "CPU consumption is disproportionate to traffic" was also shown when the real trigger was high CPU per request, even with a 0.3x CPU/traffic ratio in its own evidence. That case is now titled "High CPU cost per PHP request" and leads with the per-request evidence.

## 1.5.0 - 2026-11-12

### Added
- **OOM kill attribution.** The kernel's OOM lines (`… invoked oom-killer`, `oom-kill:… task_memcg=…,pid=…,uid=…`, `Out of memory: Killed process … anon-rss:… UID:…`) are joined per kill. Each kill now records:
  - **owner:** the application, via the process UID = the app's system user; otherwise the **service**, via its systemd cgroup (e.g. `mariadb.service` → mysql) or process name
  - **memory at kill** (anon+shmem RSS) and total VM
  - the **trigger** process
  - whether it hit a **cgroup memory limit** rather than total server RAM
- **Server Health** shows an OOM table (time, process, PID, owner, memory at kill, trigger, scope). The server-wide CRITICAL finding now lists kills per owner ("app shop 3x up to 512 MB, service mysql 1x up to 1 GB") and the trigger.
- **The affected app gets its own CRITICAL finding** ("OOM killer killed this application's processes"). It is therefore highlighted red throughout the report and gets a shareable app report with an "Out-of-memory kills" line and a "Memory Exhaustion" customer recommendation. It also has a new root-cause class: memory exhaustion.
- `--kernel-log-glob` (default `kern.log*`, then `syslog*`, then `messages*`; `journalctl -k` as fallback).
- 9 new exact checks: UID/cgroup/name attribution, memory and trigger parsing, duplicate syslog copies, window filtering, cgroup-limit kills, and the end-to-end CRITICAL block, OOM table and app report.

## 1.4.1 - 2026-11-12

### Fixed
- **False "Outdated/spoofed browser" traffic:** the newest real Chrome was estimated with a 40.5-day release cadence, inherited from the original traffic analyzer, giving v147 for Nov 2026. Chrome actually ships about every 4 weeks (about v154), so visitors on current Chrome 148+ were counted as spoofed; one report showed 95% of an app's traffic that way. The estimate now uses 30.5 days, and versions are only "future/non-existent" more than 3 majors ahead of stable (Beta/Dev/Canary). `--chrome-latest-major` still overrides.
- The single "Outdated/spoofed browser UA" bucket is split into **"Outdated Chrome UA (<= vN)"** and **"Future Chrome UA (> vN)"**, with the cutoff version in the name so the classification can be sanity-checked.

### Added
- **Bot IPs everywhere:**
  - app reports: an IPs column, plus the top IPs (with request counts) of each bot, and an example User-Agent for suspicious buckets
  - section 6: top IPs for every listed bot, not only flagged ones
  - server-wide ranking: top IPs for the top 5 bots

## 1.4.0 - 2026-11-12

### Added
- **Priority app highlighting:** in the terminal, every mention of an app with CRITICAL findings is red and underlined, and HIGH apps are orange and underlined, in every section and table, so one app can be followed through the whole report. Table alignment is unchanged. Saved files and Markdown stay plain.
- **Shareable application reports:** right after the alert sections, each CRITICAL/HIGH application gets one self-contained block:
  - summary, root cause and findings with evidence
  - resource usage
  - traffic, with top URLs and IPs
  - bots
  - slow PHP requests (wall vs CPU vs wait), repeatedly slow URLs, plugins/themes from slow logs, server errors
  - MySQL slow queries (values masked) and connections
  - the customer recommendations that apply to that app

  Each block holds only that app's data, with no other applications and no internal PlatformOps notes or thresholds. It is wrapped in `>>> BEGIN/END SHAREABLE APPLICATION REPORT` markers.
- `--report` also saves each application report as its own file: `cloudways_app_<app>_<timestamp>.txt|md`.
- `--app-reports-only` prints just the application reports; `--no-app-reports` turns them off.

## 1.3.0 - 2026-11-12

### Added
- **Server-wide top bots** (new section 4): one lightweight pass over every application's access log ranks the top bots across the server (requests, % of all backend traffic, req/min, unique IPs, backend/dynamic requests, number of apps, top app, top URLs, status codes). `--server-bots-top`, `--skip-bot-census`.
- **Bot volume thresholds**, normalised per hour of the window so `--hour 1` and `--hour 24` judge the same rate the same way: `--bot-requests-high` (requests/hour), `--bot-rpm-high`, `--bot-php-requests-high` (PHP requests/hour). Volume alone gives at most WARNING; HIGH still needs real PHP cost (`--bot-high-cpu`). Each flagged bot lists the thresholds it crossed.
- **Bot ↔ PHP-FPM/MySQL time correlation**: bot share of backend requests during the busiest PHP minute, during "max_children reached" minutes and during minutes with slow queries, compared with the overall share. This is reported as co-occurrence, not attribution.
- **Slow request analysis** (section 7): 10 slowest, 10 highest-CPU and 10 highest-memory PHP requests with **wall time, CPU time and wait %** in separate columns, flags (SLOW / HIGH / VERY SLOW / HIGH-MEM / 5xx), repeated slow URLs, HTTP 500/502/503/504 by URL (PHP-FPM log and access log), and a plugin/theme/component table from slow-log traces. `--slow-request-seconds`, `--very-slow-request-seconds`, `--request-mem-high`.
- **MySQL slow-query views**: top 10 slowest (by max), top 10 by total time, and most frequently repeated patterns, each with count, total, average and max time, rows examined, and database → application mapping with its evidence.
- **High database connections** finding per application (`--db-conn-high`).
- `tests/test_exact_counts.py`: 29 deterministic checks against hand-built logs with known answers.
- `CHANGELOG.md`.

### Changed
- **Report layout:** 1 Critical findings, 2 High-priority findings, 3 Top resource-consuming applications, 4 Top bots across the server, 5 Server health, 6 Application traffic & bot analysis, 7 PHP-FPM & slow requests, 8 MySQL, 9 Root cause analysis & key findings, 10 Internal recommendations, 11 Customer-shareable recommendations, 12 Supporting evidence, then the Final Findings Summary table. Investigation Overview stays at the top.
- **Missing-index wording:** it is never claimed without `EXPLAIN` evidence. A high rows-examined ratio is reported as "index usage not verified".
- Search engines that can't be DNS-verified are labelled "Search engine (unverified)". This now also applies to engines without a published reverse-DNS domain (e.g. DuckDuckBot).
- `tests/run_tests.sh` fails loudly on any check. Before, a broken `grep` chain could skip a check silently.

## 1.2.0 - 2026-11-12

### Added
- Bot & crawler analysis per application: about 50 signatures in 7 classes (verified/unverified search engine, SEO, AI, monitoring, other automated, suspicious), reverse+forward DNS verification through the server's own resolver (timeouts are inconclusive, never impersonation), and bot PHP CPU estimated by joining client IPs with `php-app.access.log`.
- Unified severity: CRITICAL / HIGH (orange) / WARNING / INFO / HEALTHY, calibrated to server capacity, sample length and how long the load lasted.
- HIGH PRIORITY FINDINGS block, Final Findings Summary table, and new detectors (hot PHP process, PHP worker memory, PHP requests per vCPU, 403/404 scanning, wp-admin hammering, REST/Store API floods, impersonation).

### Fixed (live-run false positives)
- Bots are rated on absolute load (% of a core, req/min), not share. Attack patterns on idle, low-rate apps become observations; security abuse (brute force, impersonation) keeps its severity.

## 1.1.0 - 2026-11-12

### Added
- Recommended next action on every finding, live vs window CPU/memory columns, per-app process table, live long-running request detection, issue-origin verdict, DB-mapping evidence, `--pool-conf-glob`, the scenario test matrix and README test results.

## 1.0.0 - 2026-11-12

- First release: per-app CPU/memory (FPM access-log CPU-seconds, atop history, PSS sampling), traffic, PHP-FPM, MySQL, root cause analysis, and internal plus customer recommendations. Read-only; txt/markdown/json output.

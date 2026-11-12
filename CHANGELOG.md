# Changelog

All notable changes to `analyze_cloudways_applications.py`. The execution command and every existing flag stay compatible across versions.

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

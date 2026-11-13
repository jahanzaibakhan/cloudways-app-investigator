#!/usr/bin/env python3
"""Deterministic validation: hand-built logs with known answers.

Checks exact request counting (incl. out-of-window exclusion), bot classification and
traffic percentages, server-wide bot census, PHP-FPM metrics (CPU-seconds, wait share,
thresholds, 5xx, repeated slow URLs), MySQL slow-log aggregation (count/total/avg/max,
dump detection, literal masking) and report formatting (no ANSI, Markdown table shape).
"""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "analyze_cloudways_applications.py"
spec = importlib.util.spec_from_file_location("cw", SCRIPT)
cw = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cw)

NOW = datetime.now(timezone.utc).replace(tzinfo=None).replace(microsecond=0)
T0 = NOW - timedelta(minutes=30)                     # inside a 1h window
OLD = NOW - timedelta(hours=3)                       # outside the window
UA = {
    "ahrefs": "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
    "google": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "uptime": "Mozilla/5.0+(compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
    "gpt": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)",
    "human": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36",
}
results = []


def check(name, cond, detail=""):
    results.append(bool(cond))
    print(f"{'PASS' if cond else 'FAIL'} {name}" + (f"  ({detail})" if detail else ""))


def ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


def acc(t, ip, uri, ua, st=200, m="GET"):
    return f'{ip} - - [{ts(t)}] "{m} {uri} HTTP/1.1" {st} 100 "-" "{ua}"'


def fpm(t, ip, uri, dur, mem_mb, cpu_pct, st=200):
    return f'{ip} - [{ts(t)}] "GET /index.php" {st} 0 - 1 2 {dur:.3f} {mem_mb * 1048576} {cpu_pct * 0.75:.2f}% {cpu_pct * 0.25:.2f}% "{uri}"'


def build(root: Path):
    apps = root / "applications"
    for app in ("shop", "blog"):
        (apps / app / "logs").mkdir(parents=True)
        (apps / app / "public_html").mkdir()
        (apps / app / "public_html" / "wp-config.php").write_text(f"<?php define('DB_NAME','{app}_db'); define('DB_PASSWORD','hunter2');")
    # shop backend: 100 in-window lines + 5 out-of-window lines
    b, f = [], []
    k = 0
    def add(n, ip_fmt, uri, ua, st=200, php=None):
        nonlocal k
        for i in range(n):
            t = T0 + timedelta(seconds=k)
            k += 1
            b.append(acc(t, ip_fmt.format(i % 4), uri, ua, st))
            if php:
                f.append(fpm(t, ip_fmt.format(i % 4), uri, *php))
    add(30, "54.36.148.{}", "/shop/?filter=red", UA["ahrefs"], php=(2.0, 40, 50))     # 30 dynamic, 30 CPU-s
    add(10, "54.36.148.{}", "/wp-content/a.jpg", UA["ahrefs"])                       # 10 static
    add(20, "66.249.66.{}", "/product/x/", UA["google"], php=(0.1, 20, 50))           # 20 dynamic, 1.0 CPU-s
    add(10, "1.2.3.{}", "/", UA["uptime"], php=(0.05, 10, 40))                         # 0.2 CPU-s
    add(25, "81.2.3.{}", "/", UA["human"], php=(0.2, 30, 50))                          # 2.5 CPU-s
    add(3, "81.2.3.{}", "/checkout/", UA["human"], st=500, php=(6.0, 300, 10, 500))     # slow, high-mem, 500, mostly waiting
    add(2, "81.2.3.{}", "/checkout/", UA["human"], st=502)                             # proxy 502, no PHP line
    for i in range(5):
        b.append(acc(OLD + timedelta(seconds=i), "9.9.9.9", "/old", UA["gpt"]))
        f.append(fpm(OLD + timedelta(seconds=i), "9.9.9.9", "/old", 50, 999, 100))
    (apps / "shop" / "logs" / "backend_shop.access.log").write_text("\n".join(b[-5:] + b[:-5]) + "\n")   # old lines first
    (apps / "shop" / "logs" / "php-app.access.log").write_text("\n".join(f[-5:] + f[:-5]) + "\n")
    # blog: 10 GPTBot + 10 humans
    bb = [acc(T0 + timedelta(seconds=i), "20.15.240.1", "/post/", UA["gpt"]) for i in range(10)]
    bb += [acc(T0 + timedelta(seconds=20 + i), "81.9.9.9", "/post/", UA["human"]) for i in range(10)]
    (apps / "blog" / "logs" / "backend_blog.access.log").write_text("\n".join(bb) + "\n")
    # MySQL slow log
    ep = int(T0.replace(tzinfo=timezone.utc).timestamp())
    sl = []

    def q(db, qt, rs, rx, sql, off):
        sl.extend([f"# User@Host: {db}[{db}] @ localhost []", f"# Thread_id: 1  Schema: {db}  QC_hit: No",
                   f"# Query_time: {qt}  Lock_time: 0.0  Rows_sent: {rs}  Rows_examined: {rx}",
                   f"SET timestamp={ep + off};", sql])
    q("shop_db", 6.0, 1, 500000, "SELECT * FROM wp_options WHERE option_name = 'secret_token_123';", 1)
    q("shop_db", 8.0, 1, 500000, "SELECT * FROM wp_options WHERE option_name = 'another_secret';", 2)
    q("shop_db", 10.0, 1, 500000, "SELECT * FROM wp_options WHERE option_name = 'x';", 3)
    q("blog_db", 30.0, 5, 10, "UPDATE wp_posts SET post_title = 'Private Title' WHERE ID = 42;", 4)
    q("shop_db", 7.0, 9000, 9000, "SELECT /*!40001 SQL_NO_CACHE */ * FROM `wp_users`;", 5)
    (root / "slow.log").write_text("\n".join(sl) + "\n")
    return apps


def main() -> int:
    root = Path(tempfile.mkdtemp())
    try:
        apps_root = build(root)
        args = cw.build_parser().parse_args(["--no-dns-verify"])
        args.window_s = 3600
        ctx = cw.Ctx(args)
        apps = cw.collect_apps([apps_root])
        start, end = NOW - timedelta(hours=1), NOW + timedelta(seconds=5)
        ctx.pools, ctx.user_to_app = {}, {}

        # --- traffic counting & bots
        t = cw.analyze_traffic(ctx, apps["shop"], start, end)
        check("backend requests counted exactly (out-of-window excluded)", t["total"] == 100, t["total"])
        bots = {b["name"]: b for b in t["bots"]}
        ah = bots.get("AhrefsBot", {})
        check("AhrefsBot: 40 requests, 40.0%", ah.get("requests") == 40 and abs(ah.get("pct", 0) - 40.0) < 1e-9, (ah.get("requests"), ah.get("pct")))
        check("AhrefsBot: 30 dynamic / 10 static", (ah.get("dynamic"), ah.get("static")) == (30, 10), (ah.get("dynamic"), ah.get("static")))
        check("AhrefsBot: 4 unique IPs, category seo", ah.get("unique_ips") == 4 and ah.get("category") == "seo")
        check("Googlebot claimed (search), 20 req", bots.get("Googlebot", {}).get("requests") == 20 and bots["Googlebot"]["category"] == "search")
        check("UptimeRobot = monitor, 10 req", bots.get("UptimeRobot", {}).get("category") == "monitor" and bots["UptimeRobot"]["requests"] == 10)
        check("browser traffic not counted as bots (bot total 70)", t["bot_requests"] == 70, t["bot_requests"])
        check("5xx: 500 x3 and 502 x2 by URL", {(x["status"], x["path"], x["count"]) for x in t["http_5xx"]} ==
              {("500", "/checkout/", 3), ("502", "/checkout/", 2)}, t["http_5xx"])

        # --- PHP-FPM metrics
        fa = cw.analyze_fpm_access(ctx, apps["shop"], start, end, deep=True)
        check("PHP requests counted exactly (88, old excluded)", fa["requests"] == 88, fa["requests"])
        exp_cpu = 30 * 2.0 * .5 + 20 * .1 * .5 + 10 * .05 * .4 + 25 * .2 * .5 + 3 * 6.0 * .1
        check("CPU-seconds = sum(duration x CPU%)", abs(fa["cpu_s"] - exp_cpu) < 0.05, f"{fa['cpu_s']:.2f} vs {exp_cpu:.2f}")
        sr = fa["slowest_requests"][0]
        check("slowest request: 6s wall, 0.6s CPU, 90% wait, 500, high-mem flag",
              sr["dur"] == 6.0 and abs(sr["cpu_s"] - 0.6) < 0.01 and sr["status"] == "500" and
              cw.req_flag(sr, args) == "SLOW,HIGH-MEM,500", (sr, cw.req_flag(sr, args)))
        check("top CPU request is an AhrefsBot filter page (1.0 CPU-s)", fa["top_cpu_requests"][0]["uri"].startswith("/shop/?filter")
              and abs(fa["top_cpu_requests"][0]["cpu_s"] - 1.0) < 0.01)
        check("repeated slow URL /checkout/ x3", fa["repeated_slow_paths"] and fa["repeated_slow_paths"][0]["path"] == "/checkout/"
              and fa["repeated_slow_paths"][0]["slow_hits"] == 3, fa.get("repeated_slow_paths"))
        check(">=5s count = 3", fa["over"].get(5) == 3, fa["over"])

        # --- bot -> PHP CPU correlation by IP
        p = {"traffic": t, "fpm": fa}
        cw.correlate_bots(ctx, cw.BotVerifier(ctx), p)
        ah = next(b for b in t["bots"] if b["name"] == "AhrefsBot")
        check("AhrefsBot est. PHP CPU share = 30/37.1 (by IP)", abs(ah["php_cpu_share"] - 100 * 30 / exp_cpu) < 0.5,
              f"{ah['php_cpu_share']:.1f}% vs {100 * 30 / exp_cpu:.1f}%")
        check("AhrefsBot est. PHP requests = 30", ah["php_requests_est"] == 30, ah["php_requests_est"])
        check("Googlebot without DNS verification = unverified", next(b for b in t["bots"] if b["name"] == "Googlebot")["category_label"]
              == "Search engine (unverified)")

        # --- server-wide census across both apps
        c = cw.bot_census(ctx, apps, start, end, cw.BotVerifier(ctx))
        cb = {b["name"]: b for b in c["bots"]}
        check("census total = 120 backend requests across 2 apps", c["total"] == 120 and c["apps_scanned"] == 2, (c["total"], c["apps_scanned"]))
        check("census GPTBot = 10 (old lines excluded), AI crawler, 8.33%", cb.get("GPTBot (OpenAI)", {}).get("requests") == 10
              and abs(cb["GPTBot (OpenAI)"]["pct"] - 100 * 10 / 120) < 1e-9 and cb["GPTBot (OpenAI)"]["category"] == "ai")
        check("census ranks AhrefsBot first (40)", c["bots"][0]["name"] == "AhrefsBot" and c["bots"][0]["requests"] == 40)

        # --- MySQL slow log aggregation
        mres = {"vars": {"slow_query_log_file": str(root / "slow.log"), "slow_query_log": "ON", "long_query_time": "5"}, "available": True}
        ms = cw.analyze_mysql_slowlog(ctx, None, mres, {"shop_db": "shop", "blog_db": "blog"}, start, end)
        check("slow queries counted = 5 (1 dump)", ms["total"] == 5 and ms["dump_queries"] == 1, (ms["total"], ms["dump_queries"]))
        opt = next(x for x in ms["fingerprints"] if "wp_options" in x["fingerprint"])
        check("3 option lookups grouped: count 3, total 24s, avg 8s, max 10s",
              (opt["count"], opt["time"], opt["avg"], opt["max"]) == (3, 24.0, 8.0, 10.0), (opt["count"], opt["time"], opt["avg"], opt["max"]))
        check("fingerprint mapped to app 'shop'", opt["app"] == "shop")
        check("literals masked (no secrets/titles/ids)", not any(re.search(r"secret|Private Title|\b42\b", x["fingerprint"])
                                                                 for x in ms["fingerprints"]), [x["fingerprint"] for x in ms["fingerprints"]])
        check("slowest single query is the 30s blog UPDATE", max(ms["fingerprints"], key=lambda x: x["max"])["db"] == "blog_db")

        # --- OOM: join kernel lines, attribute by UID / cgroup / name, memory at kill, trigger, dedupe, window
        def kl(tm, msg):
            return f"{tm.strftime('%Y-%m-%dT%H:%M:%S')}.123456+00:00 web1 kernel: [12345.678] {msg}"
        k1, k2, k3, k4 = T0 + timedelta(minutes=1), T0 + timedelta(minutes=2), T0 + timedelta(minutes=3), T0 + timedelta(minutes=4)
        klines = [
            kl(k1, "php-fpm8.3 invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0, oom_score_adj=0"),
            kl(k1, "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,"
                   "task_memcg=/system.slice/php8.3-fpm.service,task=php-fpm8.3,pid=4242,uid=1017"),
            kl(k1, "Out of memory: Killed process 4242 (php-fpm8.3) total-vm:812000kB, anon-rss:524288kB, file-rss:0kB, "
                   "shmem-rss:0kB, UID:1017 pgtables:1200kB oom_score_adj:0"),
            kl(k1, "Out of memory: Killed process 4242 (php-fpm8.3) total-vm:812000kB, anon-rss:524288kB, file-rss:0kB, "
                   "shmem-rss:0kB, UID:1017 pgtables:1200kB oom_score_adj:0"),                       # duplicate copy
            kl(k2, "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,"
                   "task_memcg=/system.slice/mariadb.service,task=mariadbd,pid=777,uid=106"),
            kl(k2, "Out of memory: Killed process 777 (mariadbd) total-vm:2400000kB, anon-rss:1048576kB, file-rss:0kB, "
                   "shmem-rss:0kB, UID:106 pgtables:3000kB oom_score_adj:0"),
            kl(k3, "Memory cgroup out of memory: Killed process 888 (redis-server) total-vm:300000kB, anon-rss:204800kB, "
                   "file-rss:0kB, shmem-rss:0kB, UID:107 pgtables:500kB oom_score_adj:0"),
            kl(OLD, "Out of memory: Killed process 999 (php-fpm8.3) total-vm:1kB, anon-rss:1kB, file-rss:0kB, shmem-rss:0kB, UID:1017"),
            kl(k4, "systemd[1]: some unrelated line"),
        ]
        saved_uid_name = cw.uid_name
        cw.uid_name = lambda uid, _m={1017: "shopuser", 106: "mysql", 107: "redis"}: _m.get(uid, str(uid))
        ctx.user_to_app = {"shopuser": "shop"}
        ev = cw.parse_oom_lines(ctx, apps, klines, start, end)
        cw.uid_name = saved_uid_name
        check("OOM: 3 kills (duplicate and out-of-window excluded)", len(ev) == 3, [(e["pid"], e["process"]) for e in ev])
        e1, e2, e3 = ev
        check("OOM: php-fpm kill attributed to app 'shop' via UID", (e1["owner_kind"], e1["owner"]) == ("app", "shop"), e1)
        check("OOM: memory at kill 512 MB, trigger php-fpm8.3", e1["rss_mb"] == 512.0 and e1["trigger"] == "php-fpm8.3", e1)
        check("OOM: mariadbd -> service mysql (cgroup), 1024 MB", (e2["owner_kind"], e2["owner"], e2["rss_mb"]) == ("service", "mysql", 1024.0), e2)
        check("OOM: redis cgroup-limit kill flagged as memcg", e3["owner"] == "redis" and e3["memcg"], e3)

        # --- report formatting (full CLI run)
        import os as _os
        import pwd as _pwd
        me = _pwd.getpwuid(_os.getuid()).pw_name
        (apps_root / me / "logs").mkdir(parents=True)
        (apps_root / me / "public_html").mkdir()
        (apps_root / me / "logs" / f"backend_{me}.access.log").write_text(acc(T0, "81.2.3.4", "/", UA["human"]) + "\n")
        klog = root / "kern.log"
        klog.write_text("\n".join([
            kl(k1, "php-fpm8.3 invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0, oom_score_adj=0"),
            kl(k1, f"Out of memory: Killed process 4242 (php-fpm8.3) total-vm:812000kB, anon-rss:524288kB, file-rss:0kB, "
                   f"shmem-rss:0kB, UID:{_os.getuid()} pgtables:1200kB oom_score_adj:0"),
            kl(k2, "oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=/,mems_allowed=0,global_oom,"
                   "task_memcg=/system.slice/mariadb.service,task=mariadbd,pid=777,uid=106"),
            kl(k2, "Out of memory: Killed process 777 (mariadbd) total-vm:2400000kB, anon-rss:1048576kB, file-rss:0kB, "
                   "shmem-rss:0kB, UID:106 pgtables:3000kB oom_score_adj:0")]) + "\n")
        out = root / "out"
        out.mkdir()
        base = [sys.executable, str(SCRIPT), "--applications-root", str(apps_root), "--strict-root", "--sample-seconds", "4",
                "--skip-mysql", "--skip-history", "--no-dns-verify", "--top", "2", "--output-dir", str(out), "--full"]
        r1 = subprocess.run(base + ["--no-color"], capture_output=True, text=True, timeout=120)
        check("plain text run ok and ANSI-free", r1.returncode == 0 and "\x1b[" not in r1.stdout, r1.stderr[-200:])
        check("password never printed", "hunter2" not in r1.stdout)
        r2 = subprocess.run(base + ["--format", "markdown", "--report", "--json"], capture_output=True, text=True, timeout=120)
        md = next(out.glob("*.md")).read_text()
        bad = []
        lines = md.splitlines()
        for i, ln in enumerate(lines):          # every table row has the same column count as its header
            if ln.startswith("| ") and i + 1 < len(lines) and re.match(r"^\|(-+:?\|)+$", lines[i + 1].replace("---:", "---")):
                ncol = ln.count(" | ") + 1
                j = i + 2
                while j < len(lines) and lines[j].startswith("| "):
                    if lines[j].replace("\\|", "").count(" | ") + 1 != ncol:
                        bad.append(lines[j][:60])
                    j += 1
        check("markdown export: tables well-formed, no ANSI", r2.returncode == 0 and not bad and "\x1b[" not in md, bad[:3])
        js = json.loads(next(out.glob("*.json")).read_text())
        check("json export parses and has census", js.get("census", {}).get("total") == 121)
        r3 = subprocess.run(base + ["--top", "3", "--no-color", "--kernel-log-glob", str(klog)], capture_output=True, text=True, timeout=120)
        o3 = r3.stdout
        crit = o3[o3.find("1. CRITICAL FINDINGS"):o3.find("2. HIGH-PRIORITY FINDINGS")]
        check("OOM table in server health with owners", "OOM killer events" in o3 and f"app: {me}" in o3 and "service: mysql" in o3,
              r3.stderr[-200:])
        check("OOM-killed app listed under CRITICAL with its name", "OOM KILLER KILLED THIS APPLICATION" in crit and me in crit)
        check("OOM-killed app gets a shareable app report with OOM line",
              f"APPLICATION REPORT: {me}" in o3 and "Out-of-memory kills" in o3 and "Memory Exhaustion" in o3)
        check("server OOM finding names owners and trigger", "Killed by owner:" in o3 and "Triggered by: php-fpm8.3" in o3)
        check("app report findings written as paragraphs from measured values",
              "What is happening: The server ran out of memory and the operating system stopped 1 of this application's PHP processes "
              "(the largest was using 512 MB)." in " ".join(o3.split()))
        print(f"\n{sum(results)}/{len(results)} exact checks passed")
        return 0 if all(results) else 1
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

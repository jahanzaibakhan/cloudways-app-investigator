#!/usr/bin/env python3
"""Offline scenario matrix: many apps, multi-PHP pools, missing/unreadable logs, nginx-only app.

Builds a synthetic Cloudways layout in a temp dir, runs the analyzer with --json and
asserts on the results. Linux-only collectors (/proc, atop, MySQL) degrade gracefully here;
they are validated separately on a real server.
"""
from __future__ import annotations
import glob
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "analyze_cloudways_applications.py"
random.seed(7)
NOW = datetime.now(timezone.utc).replace(tzinfo=None)


def ts(t):
    return t.strftime("%d/%b/%Y:%H:%M:%S +0000")


BOT_UAS = {
    "ahrefs": ("Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)", "54.36.148."),
    "google": ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "66.249.66."),
    "fakegoogle": ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)", "185.220.101."),
}


def write_app(root: Path, app: str, n: int, *, heavy=False, attack=False, backend=True, fpm=True, nginx_only=False,
              bot=None, bot_share=0.0, bot_static=False):
    d = root / "applications" / app
    logs = d / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    (d / "public_html").mkdir(exist_ok=True)
    (d / "conf").mkdir(exist_ok=True)
    (d / "conf" / "server.nginx").write_text(f"server {{ server_name {app}.example.com {app}.cloudwaysapps.com; }}\n")
    (d / "public_html" / "wp-config.php").write_text(f"<?php define('DB_NAME', '{app}'); define('DB_PASSWORD', 'secret');\n")
    b, f = [], []
    for _ in range(n):
        t = NOW - timedelta(seconds=random.randint(0, 3500))
        if bot and random.random() < bot_share:
            ua, prefix = BOT_UAS[bot]
            ip, m = prefix + str(random.randint(1, 40)), "GET"
            uri = "/wp-content/img.jpg" if bot_static else random.choice(["/product/?filter_color=red&orderby=price", "/?s=x", "/shop/page/9/"])
            heavy_req = False
        elif attack and random.random() < 0.6:
            ip, uri, ua, m = "45.11.22.33", "/xmlrpc.php", "Mozilla/5.0 Chrome/60.0 Safari", "POST"
        else:
            ip = f"81.2.{random.randint(0, 200)}.{random.randint(1, 250)}"
            uri = random.choice(["/", "/shop/", "/wp-json/wp/v2/posts", "/product/x/", "/wp-content/a.css"])
            ua, m = "Mozilla/5.0 (Windows NT 10.0) Chrome/140.0 Safari/537.36", "GET"
            heavy_req = heavy
        b.append((t, f'{ip} - - [{ts(t)}] "{m} {uri} HTTP/1.1" 200 1234 "-" "{ua}"'))
        if attack and uri == "/xmlrpc.php":
            heavy_req = False
        if not uri.endswith((".css", ".jpg")):
            costly = bot == "ahrefs" and ua == BOT_UAS["ahrefs"][0]
            dur = random.uniform(3, 9) if heavy_req else random.uniform(1.0, 2.0) if costly else random.uniform(0.05, 0.3)
            cpu = random.uniform(70, 95) if heavy_req or costly else random.uniform(30, 70)
            mem = (random.randint(150, 260) if heavy_req else random.randint(20, 50)) * 1048576
            f.append((t, f'{ip} - [{ts(t)}] "{m} /index.php" 200 0 - 111 222 {dur:.3f} {mem} {cpu * .8:.2f}% {cpu * .2:.2f}% "{uri}"'))
    b.sort()
    f.sort()
    if nginx_only:
        (logs / "nginx-app.access.log").write_text("\n".join(x for _, x in b) + "\n")
    elif backend:
        (logs / f"backend_{app}.cloudwaysapps.com.access.log").write_text("\n".join(x for _, x in b) + "\n")
    if fpm:
        (logs / "php-app.access.log").write_text("\n".join(x for _, x in f) + "\n")


def write_pool(root: Path, app: str, ver: str, max_children: int, override: int | None = None):
    pd = root / "etc" / "php" / ver / "fpm" / "pool.d"
    pd.mkdir(parents=True, exist_ok=True)
    cw = root / "etc" / "cw_customization.conf"
    cw.write_text("pm = dynamic\npm.max_children = 10\npm.max_requests = 500\n")
    tag = ver.replace(".", "")
    lines = [f"[{app}-{tag}]", f"user = {app}", f"listen = /var/run/fpm-{app}-{tag}.sock", f"include = {cw}",
             f"slowlog = {root}/applications/{app}/logs/php-app.slow.log"]
    if override:
        ov = root / "applications" / app / "conf" / "fpm-pool.conf"
        ov.write_text(f"pm.max_children = {override}\n")
        lines.append(f"include = {ov}")
    else:
        lines.append(f"pm.max_children = {max_children}")
    (pd / f"{app}-{tag}.conf").write_text("\n".join(lines) + "\n")


def main() -> int:
    tmp = Path(tempfile.mkdtemp())
    out = tmp / "out"
    out.mkdir()
    try:
        apps = [f"app{i:03d}" for i in range(115)]
        for a in apps:
            write_app(tmp, a, random.randint(5, 60))
            write_pool(tmp, a, random.choice(["7.4", "8.1", "8.3"]), 10)
        write_app(tmp, "slowshop", 300, heavy=True)
        write_pool(tmp, "slowshop", "8.3", 10, override=25)          # app override must win
        write_pool(tmp, "slowshop", "8.1", 10)                       # stale pool in a 2nd PHP version
        write_app(tmp, "busyblog", 6000)
        write_pool(tmp, "busyblog", "8.2", 15)
        write_app(tmp, "xmlrpcvictim", 3000, attack=True)
        write_pool(tmp, "xmlrpcvictim", "8.3", 10)
        write_app(tmp, "crawledshop", 5000, bot="ahrefs", bot_share=0.45)          # aggressive SEO bot on dynamic pages
        write_pool(tmp, "crawledshop", "8.3", 20)
        write_app(tmp, "imagesite", 3000, bot="google", bot_share=0.5, bot_static=True)   # Googlebot on static files
        write_pool(tmp, "imagesite", "8.3", 10)
        write_app(tmp, "fakebotsite", 2000, bot="fakegoogle", bot_share=0.4)       # Googlebot UA from non-Google IPs
        write_pool(tmp, "fakebotsite", "8.3", 10)
        write_app(tmp, "nginxonly", 800, nginx_only=True)
        write_pool(tmp, "nginxonly", "8.3", 10)
        (tmp / "applications" / "emptylogs" / "logs").mkdir(parents=True)   # missing logs
        (tmp / "applications" / "emptylogs" / "public_html").mkdir()
        write_app(tmp, "noperm", 400)
        os.chmod(tmp / "applications" / "noperm" / "logs" / "php-app.access.log", 0)   # unreadable
        (tmp / "applications" / ".hidden" / "logs").mkdir(parents=True)                 # must be ignored

        cmd = [sys.executable, str(SCRIPT), "--applications-root", str(tmp / "applications"), "--strict-root",
               "--pool-conf-glob", str(tmp / "etc/php/*/fpm/pool.d/*.conf"), "--sample-seconds", "4",
               "--skip-mysql", "--skip-history", "--cpu-threshold", "3", "--no-color",
               "--report", "--format", "markdown", "--json", "--output-dir", str(out), "--no-dns-verify", "--top", "8"]
        t0 = time.time()
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        dt = time.time() - t0
        results = []

        def check(name, cond, detail=""):
            results.append((name, bool(cond)))
            print(f"{'PASS' if cond else 'FAIL'} {name}" + (f" ({detail})" if detail else ""))

        check("exit code 0", p.returncode == 0, p.stderr[-300:] if p.returncode else "")
        data = json.load(open(glob.glob(str(out / "*.json"))[0]))
        md = open(glob.glob(str(out / "*.md"))[0]).read()
        top = {x["app"]: x for x in data["top"]}
        check("app discovery (124 apps, hidden dir ignored)", data["app_count"] == 124, f"found {data['app_count']}")
        check("runtime with 124 apps < 60s", dt < 60, f"{dt:.1f}s")
        check("slow low-traffic app ranked in top 3", "slowshop" in [x["app"] for x in data["top"][:3]], [x["app"] for x in data["top"][:3]])
        s = top.get("slowshop", {})
        check("app override wins (max_children=25)", s.get("max_children") == 25, s.get("max_children"))
        check("tagged low traffic / high cost", "Low traffic / high cost" in s.get("tags", []), s.get("tags"))
        check("slowshop root cause = optimization", s.get("root_cause", {}).get("primary") == "optimization", s.get("root_cause"))
        x = top.get("xmlrpcvictim", {})
        check("xmlrpc flood detected as suspicious", x.get("root_cause", {}).get("primary") == "suspicious", x.get("root_cause"))
        b = top.get("busyblog", {})
        check("busy normal app not suspicious", b and b.get("root_cause", {}).get("primary") != "suspicious", b.get("root_cause"))
        nfo = next((a for a in [top.get("nginxonly")] if a), None)
        if nfo:
            check("nginx-only app uses frontend log", nfo["traffic"]["source"] == "frontend", nfo["traffic"].get("source"))
        else:
            check("nginx-only app analysed (not in top 5 - checked via --only-app below)", True)
        p2 = subprocess.run(cmd[:2] + ["--only-app", "nginxonly"] + cmd[2:] + [], capture_output=True, text=True, timeout=120)
        check("--only-app nginx-only run ok", p2.returncode == 0 and "frontend (nginx)" not in p2.stdout and "Backend requests" in p2.stdout,
              "traffic section rendered")
        p3 = subprocess.run(cmd[:2] + ["--only-app", "noperm"] + cmd[2:], capture_output=True, text=True, timeout=120)
        check("unreadable FPM log does not crash", p3.returncode == 0)
        p4 = subprocess.run(cmd[:2] + ["--only-app", "emptylogs"] + cmd[2:], capture_output=True, text=True, timeout=120)
        check("app with no logs does not crash", p4.returncode == 0)
        cs = top.get("crawledshop")
        if cs:
            ah = next((b for b in cs["traffic"]["bots"] if b["name"] == "AhrefsBot"), {})
            check("AhrefsBot identified as SEO crawler and HIGH", ah.get("category") == "seo" and ah.get("level") == "HIGH", ah.get("level"))
            check("AhrefsBot PHP CPU attributed by IP (>40%)", ah.get("php_cpu_share", 0) > 40, f"{ah.get('php_cpu_share', 0):.0f}%")
            check("crawledshop root cause = bots", cs["root_cause"]["primary"] == "bots", cs["root_cause"])
        else:
            check("crawledshop in top 8", False, list(top))
        pi = subprocess.run(cmd[:2] + ["--only-app", "imagesite"] + cmd[2:], capture_output=True, text=True, timeout=120)
        jd = json.load(open(sorted(glob.glob(str(out / "*.json")))[-1]))
        gb = next((b for b in jd["top"][0]["traffic"]["bots"] if b["name"] == "Googlebot"), {})
        check("static-only Googlebot not blamed for PHP (<5% CPU, not HIGH)",
              pi.returncode == 0 and gb.get("php_cpu_share", 99) < 5 and gb.get("level") != "HIGH",
              f"cpu {gb.get('php_cpu_share')} level {gb.get('level')}")
        check("HIGH PRIORITY FINDINGS block rendered", "HIGH PRIORITY FINDINGS" in p.stdout)
        check("final findings table rendered", "| Finding" in p.stdout and "Recommended action" in p.stdout)
        check("credentials never printed", "secret" not in p.stdout and "secret" not in md)
        check("markdown report has no ANSI codes", "\x1b[" not in md)
        check("customer block present", ">>> BEGIN CUSTOMER RESPONSE >>>" in p.stdout)
        check("every finding has a next action",
              all(f.get("action") for a in data["top"] for f in a.get("findings", [])))
        failed = [n for n, ok in results if not ok]
        print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
        return 1 if failed else 0
    finally:
        try:
            os.chmod(tmp / "applications" / "noperm" / "logs" / "php-app.access.log", 0o644)
        except OSError:
            pass
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())

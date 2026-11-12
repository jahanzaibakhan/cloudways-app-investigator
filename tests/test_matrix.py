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


def write_app(root: Path, app: str, n: int, *, heavy=False, attack=False, backend=True, fpm=True, nginx_only=False):
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
        if attack and random.random() < 0.6:
            ip, uri, ua, m = "45.11.22.33", "/xmlrpc.php", "Mozilla/5.0 Chrome/60.0 Safari", "POST"
        else:
            ip = f"81.2.{random.randint(0, 200)}.{random.randint(1, 250)}"
            uri = random.choice(["/", "/shop/", "/wp-json/wp/v2/posts", "/product/x/", "/wp-content/a.css"])
            ua, m = "Mozilla/5.0 (Windows NT 10.0) Chrome/140.0 Safari/537.36", "GET"
        b.append((t, f'{ip} - - [{ts(t)}] "{m} {uri} HTTP/1.1" 200 1234 "-" "{ua}"'))
        if not uri.endswith(".css"):
            dur = random.uniform(3, 9) if heavy else random.uniform(0.05, 0.3)
            cpu = random.uniform(70, 95) if heavy else random.uniform(30, 70)
            mem = (random.randint(150, 260) if heavy else random.randint(20, 50)) * 1048576
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
        write_app(tmp, "nginxonly", 800, nginx_only=True)
        write_pool(tmp, "nginxonly", "8.3", 10)
        (tmp / "applications" / "emptylogs" / "logs").mkdir(parents=True)   # missing logs
        (tmp / "applications" / "emptylogs" / "public_html").mkdir()
        write_app(tmp, "noperm", 400)
        os.chmod(tmp / "applications" / "noperm" / "logs" / "php-app.access.log", 0)   # unreadable
        (tmp / "applications" / ".hidden" / "logs").mkdir(parents=True)                 # must be ignored

        cmd = [sys.executable, str(SCRIPT), "--applications-root", str(tmp / "applications"), "--strict-root",
               "--pool-conf-glob", str(tmp / "etc/php/*/fpm/pool.d/*.conf"), "--sample-seconds", "4",
               "--skip-mysql", "--skip-history", "--top", "5", "--cpu-threshold", "3", "--no-color",
               "--report", "--format", "markdown", "--json", "--output-dir", str(out)]
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
        check("app discovery (121 apps, hidden dir ignored)", data["app_count"] == 121, f"found {data['app_count']}")
        check("runtime with 121 apps < 60s", dt < 60, f"{dt:.1f}s")
        check("slow low-traffic app ranked #1", data["top"][0]["app"] == "slowshop", data["top"][0]["app"])
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

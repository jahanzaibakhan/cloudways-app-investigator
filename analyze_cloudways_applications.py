#!/usr/bin/env python3
"""
Cloudways Application Resource & Traffic Investigation Tool
===========================================================

Identifies the applications consuming the most CPU/memory on a Cloudways
server, correlates that consumption with traffic, PHP-FPM behaviour and
MySQL/MariaDB activity, and produces an evidence-backed report with separate
internal (PlatformOps) and customer-shareable recommendations.

Usage:
  curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/main/analyze_cloudways_applications.py \
    | python3 - --top 5 --hour 1 --progress

Data sources (all read-only):
  * /proc sampling over --sample-seconds  -> live per-app CPU%, PSS/RSS, worker states
  * php-app.access.log (FPM access log)   -> per-request duration, peak memory, CPU%
                                             (=> measured CPU-seconds per app for the window)
  * atop raw logs (/var/log/atop)         -> historical per-app CPU/RSS and server CPU/MEM
  * backend_*.access.log / nginx-app.status.log -> traffic analysis
  * php-app.slow.log, /var/log/php*-fpm.log    -> slow traces, max_children, timeouts
  * MariaDB/MySQL (SHOW STATUS/PROCESSLIST, slow log) via /root/.my.cnf
  * kern.log/syslog/journal, /proc/{stat,meminfo,diskstats,pressure}, redis-cli INFO

Safety: never writes outside the optional report file, never restarts or kills
anything, never changes configuration, runs every subprocess with a timeout,
masks SQL literals and never prints credentials.
"""
from __future__ import annotations

import argparse
import glob
import gzip
import ipaddress
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from heapq import heappush, heapreplace
from pathlib import Path

VERSION = "1.7.0"

# ----------------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------------
MONTH_NUM = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
CLK_TCK = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
PAGE_KB = (os.sysconf("SC_PAGE_SIZE") // 1024) if hasattr(os, "sysconf") else 4
NCPU = os.cpu_count() or 1

# Combined access-log line (nginx/apache): ip - - [ts] "METHOD uri HTTP/x" status bytes "ref" "ua"
ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<d>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):'
    r'(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})\s*(?P<tz>[+-]\d{4})?\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<uri>[^\s"]*)(?:\s+HTTP/[0-9.]+)?"\s+(?P<status>\d{3})\s+\S+'
    r'(?:\s+"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)")?')
TS_RE = re.compile(r"\[(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?\]")
# Cloudways FPM access.format:
# %{HTTP_X_FORWARDED_FOR}e - [%t] "%m %r%Q%q" %s %l - %P %p %{seconds}d %{bytes}M %{user}C%% %{system}C%% "%{REQUEST_URI}e"
FPM_ACCESS_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\[(?P<d>\d{1,2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2})'
    r'\s*(?P<tz>[+-]\d{4})?\]\s+"(?P<method>[A-Z]+)\s+(?P<script>[^"]*)"\s+(?P<status>\d{3})\s+\S+\s+\S+\s+'
    r'(?:(?P<mpid>\d+)\s+(?P<pid>\d+)\s+)?(?P<dur>\d+(?:\.\d+)?)\s+(?P<mem>\d+)\s+'
    r'(?P<cu>[\d.]+)%\s+(?P<cs>[\d.]+)%\s*(?:"(?P<uri>[^"]*)")?')
FPM_LOG_TS_RE = re.compile(r"^\[(\d{1,2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})")
FPM_POOL_RE = re.compile(r"\[pool ([^\]]+)\]")
FPM_MAXCHILD_RE = re.compile(r"server reached (?:pm\.)?max_children setting \((\d+)\)")
FPM_BUSY_RE = re.compile(r"seems busy \(you may need to increase pm\.start_servers")
FPM_TIMEOUT_RE = re.compile(r"child (\d+), script '([^']*)' .*?execution timed out \(([\d.]+) sec")
SLOW_HEADER_RE = re.compile(
    r"^\[(\d{2})-([A-Za-z]{3})-(\d{4})\s+(\d{2}):(\d{2}):(\d{2})\]\s+\[pool ([^\]]+)\]\s+pid\s+(\d+)")
SLOW_SCRIPT_RE = re.compile(r"^script_filename\s*=\s*(.+)$")
SLOW_FRAME_RE = re.compile(r"^\[0x[0-9a-fA-F]+\]\s+(.+?)\(\)\s+(.+?):(\d+)\s*$")
POOL_SUFFIX_RE = re.compile(r"-\d{2}$")
OOM_KILLED_RE = re.compile(r"(?:Out of memory|Memory cgroup out of memory): Killed process (\d+) \(([^)]+)\)(.*)", re.I)
OOM_INVOKED_RE = re.compile(r"(?:\]\s+|kernel:\s+)?(\S+) invoked oom-killer", re.I)
OOM_KILLINFO_RE = re.compile(r"oom-kill:constraint=([A-Z_]+).*?(?:task_memcg=([^,]*),)?task=([^,]+),pid=(\d+),uid=(\d+)")
OOM_FIELD_RE = re.compile(r"(total-vm|anon-rss|file-rss|shmem-rss):(\d+)kB|UID:(\d+)")
SYSLOG_ISO_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?([+-]\d{2}:?\d{2}|Z)?")
SYSLOG_CLASSIC_RE = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
CHROME_RE = re.compile(r"(?:chrome|crios|chromium)/(\d+)", re.I)
SQL_STRING_RE = re.compile(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"")
SQL_NUMBER_RE = re.compile(r"\b\d+(?:\.\d+)?\b")
SQL_INLIST_RE = re.compile(r"\(\s*\?(?:\s*,\s*\?)+\s*\)")

STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico",
              ".woff", ".woff2", ".ttf", ".eot", ".otf", ".map", ".mp4", ".webm", ".mp3", ".pdf",
              ".zip", ".gz", ".txt")
BOT_UA_MARKERS = ("bot", "crawler", "spider", "slurp", "crawl", "fetch", "scrapy", "python-requests",
                  "curl/", "wget/", "go-http-client", "httpclient", "java/", "okhttp", "libwww",
                  "headless", "phantomjs", "puppeteer", "playwright", "semrush", "ahrefs", "mj12",
                  "dotbot", "petalbot", "bytespider", "gptbot", "claudebot", "ccbot", "amazonbot",
                  "facebookexternalhit", "dataforseo", "barkrowler", "serpstat", "zoominfo")
GOOD_BOT_MARKERS = ("googlebot", "bingbot", "applebot", "duckduckbot", "yandexbot", "baiduspider")
UPTIME_MARKERS = ("uptimerobot", "pingdom", "statuscake", "site24x7", "jetpack", "newrelic",
                  "better uptime", "betteruptime", "hetrixtools", "freshping")

SERVICE_PATTERNS = [
    ("mysql", re.compile(r"^(mysqld|mariadbd|mariadb)$")),
    ("redis", re.compile(r"^redis-server")),
    ("memcached", re.compile(r"^memcached$")),
    ("varnish", re.compile(r"^(varnishd|cache-main|cache-worker)")),
    ("nginx", re.compile(r"^nginx")),
    ("apache", re.compile(r"^(apache2|httpd)$")),
    ("elasticsearch", re.compile(r"^(java|elasticsearch|opensearch)$")),
    ("php-fpm-master", re.compile(r"^php-fpm")),
    ("imunify", re.compile(r"^(imunify|i360|aibolit|php-imunify|clamd|ossec|wazuh)")),
    ("monitoring", re.compile(r"^(atop|newrelic|nrsysmond|node_exporter|telegraf|monit|netdata|cwmon)")),
    ("backup/duplicity", re.compile(r"^(duplicity|rsync|tar|gzip|pigz|mysqldump|mariadb-dump|xtrabackup|mariabackup)$")),
    ("cron", re.compile(r"^(cron|crond)$")),
]

# ----------------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------------
class Ctx:
    """Run-wide context: options, notes about unavailable data, verbose log."""

    def __init__(self, args):
        self.args = args
        self.is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
        self.notes: list[str] = []        # data-availability notes shown in the report
        self.t0 = time.time()

    def progress(self, msg: str):
        if self.args.progress or self.args.verbose:
            el = time.time() - self.t0
            print(f"[{el:6.1f}s] {msg}", file=sys.stderr, flush=True)

    def debug(self, msg: str):
        if self.args.verbose:
            print(f"[debug] {msg}", file=sys.stderr, flush=True)

    def note(self, msg: str):
        if msg not in self.notes:
            self.notes.append(msg)
            self.debug("NOTE: " + msg)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def run_cmd(cmd: list[str], timeout: float = 15, ctx: Ctx | None = None, env: dict | None = None) -> tuple[int, str, str]:
    """Run a read-only command safely (no shell, timeout, bounded output)."""
    if not shutil.which(cmd[0]) and not os.path.isabs(cmd[0]):
        return 127, "", f"{cmd[0]} not found"
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False,
                           stdin=subprocess.DEVNULL, env=env, errors="replace")
        return p.returncode, p.stdout[:20_000_000], p.stderr[:20000]
    except subprocess.TimeoutExpired:
        if ctx:
            ctx.debug(f"timeout after {timeout}s: {' '.join(cmd[:3])}")
        return 124, "", "timeout"
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def read_text(path, limit: int = 2_000_000) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read(limit)
    except (OSError, ValueError):
        return None


def make_ts(y, mon, d, h, mi, s, tz=None) -> datetime | None:
    month = MONTH_NUM.get(mon[:1].upper() + mon[1:3].lower()) if isinstance(mon, str) else mon
    if not month:
        return None
    try:
        ts = datetime(int(y), month, int(d), int(h), int(mi), int(s))
    except ValueError:
        return None
    if tz and tz not in ("+0000", "-0000"):
        sign = 1 if tz[0] == "+" else -1
        ts -= timedelta(minutes=sign * (int(tz[1:3]) * 60 + int(tz[3:5])))
    return ts


def access_line_ts(line: str) -> datetime | None:
    m = TS_RE.search(line, 0, 160)
    return make_ts(m.group(3), m.group(2), m.group(1), m.group(4), m.group(5), m.group(6), m.group(7)) if m else None


def fpm_line_ts(line: str) -> datetime | None:
    m = FPM_LOG_TS_RE.match(line)
    return make_ts(m.group(3), m.group(2), m.group(1), m.group(4), m.group(5), m.group(6)) if m else None


def rotated_index(path: Path) -> int:
    m = re.search(r"\.log(?:\.(\d+))?(?:\.gz)?$", path.name)
    if not m:
        return 9999
    return 0 if m.group(1) is None else int(m.group(1))


def files_for_window(pattern_or_files, start: datetime | None) -> list[Path]:
    """Rotated log files that may contain lines newer than `start` (by mtime), oldest first."""
    files = pattern_or_files if isinstance(pattern_or_files, list) else [Path(p) for p in glob.glob(pattern_or_files)]
    keep = []
    cutoff = start.replace(tzinfo=timezone.utc).timestamp() if start else None
    for f in files:
        try:
            if not f.is_file():
                continue
            if cutoff and f.stat().st_mtime < cutoff:
                continue
        except OSError:
            continue
        keep.append(f)
    keep.sort(key=rotated_index, reverse=True)
    return keep


def _seek_to_time(fh, start: datetime, ts_func) -> None:
    """Binary-search an uncompressed, time-ordered log for the first line >= start."""
    try:
        size = os.fstat(fh.fileno()).st_size
    except OSError:
        return
    if size < 4_000_000:          # small file: just read it
        return
    lo, hi = 0, size
    for _ in range(40):
        if hi - lo < 65536:
            break
        mid = (lo + hi) // 2
        fh.seek(mid)
        fh.readline()
        ts = None
        for _ in range(50):       # skip lines without a timestamp
            line = fh.readline()
            if not line:
                break
            ts = ts_func(line.decode("utf-8", "replace"))
            if ts:
                break
        if ts is None or ts >= start:
            hi = mid
        else:
            lo = mid
    fh.seek(lo)
    if lo:
        fh.readline()


def iter_lines(path: Path, start: datetime | None = None, ts_func=None, max_bytes: int | None = None):
    """Stream lines (gzip aware). For plain files, seek near `start` using ts_func."""
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rt", encoding="utf-8", errors="replace") as f:
                for line in f:
                    yield line.rstrip("\n")
            return
        with open(path, "rb") as fb:
            if start is not None and ts_func is not None:
                _seek_to_time(fb, start, ts_func)
            read = 0
            for raw in fb:
                read += len(raw)
                if max_bytes and read > max_bytes:
                    break
                yield raw.decode("utf-8", "replace").rstrip("\n")
    except (OSError, EOFError):
        return


def in_window(ts, start, end) -> bool:
    if ts is None:
        return False
    return (start is None or ts >= start) and (end is None or ts <= end)


def pct(part, whole) -> float:
    return (part * 100.0 / whole) if whole else 0.0


def fmt_mb(mb: float | None) -> str:
    if mb is None:
        return "n/a"
    if mb >= 1024:
        return f"{mb / 1024:.2f} GB"
    return f"{mb:.1f} MB" if mb < 10 else f"{mb:.0f} MB"


def fmt_num(n) -> str:
    if n is None:
        return "n/a"
    if isinstance(n, float):
        return f"{n:,.1f}"
    return f"{n:,}"


def trunc(s, n: int) -> str:
    s = str(s)
    return s if len(s) <= n else s[: max(n - 1, 0)] + "…"


def percentile(sorted_vals, q: float):
    if not sorted_vals:
        return None
    k = min(len(sorted_vals) - 1, max(0, int(round(q * (len(sorted_vals) - 1)))))
    return sorted_vals[k]


def sql_fingerprint(q: str, max_len: int = 160) -> str:
    """Mask all literals so no customer data leaks into the report."""
    q = " ".join(q.split())
    q = SQL_STRING_RE.sub("?", q)
    q = SQL_NUMBER_RE.sub("?", q)
    q = SQL_INLIST_RE.sub("(?+)", q)
    return trunc(q, max_len)


def component_of(path: str) -> str:
    m = re.search(r"wp-content/plugins/([^/]+)/", path)
    if m:
        return f"plugin:{m.group(1)}"
    m = re.search(r"wp-content/themes/([^/]+)/", path)
    if m:
        return f"theme:{m.group(1)}"
    m = re.search(r"wp-content/mu-plugins/([^/]+)", path)
    if m:
        return f"mu-plugin:{m.group(1)}"
    m = re.search(r"/vendor/([^/]+/[^/]+)/", path)
    if m:
        return f"vendor:{m.group(1)}"
    if "/wp-includes/" in path or "/wp-admin/" in path:
        return "wordpress-core"
    m = re.search(r"/app/code/([^/]+/[^/]+)/", path)
    if m:
        return f"magento-module:{m.group(1)}"
    return "app"


def short_path(path: str) -> str:
    i = path.find("public_html/")
    return path[i + 12:] if i >= 0 else path


# ----------------------------------------------------------------------------
# Discovery: applications, PHP-FPM pools, users
# ----------------------------------------------------------------------------
def safe_is_dir(p: Path) -> bool:
    try:
        return p.is_dir()
    except OSError:
        return False


def detect_roots(requested: Path, strict: bool) -> list[Path]:
    def has_apps(root: Path) -> bool:
        if not safe_is_dir(root):
            return False
        try:
            return any(safe_is_dir(c / "logs") for c in root.iterdir())
        except OSError:
            return False

    roots = [requested] if has_apps(requested) else []
    if not strict and safe_is_dir(Path("/home")):
        try:
            for item in Path("/home").iterdir():
                for cand in (item, item / "applications"):
                    if has_apps(cand):
                        roots.append(cand)
        except OSError:
            pass
    seen, uniq = set(), []
    for r in roots:
        try:
            rp = str(r.resolve())
        except OSError:
            rp = str(r)
        if rp not in seen:
            seen.add(rp)
            uniq.append(r)
    return uniq


def parse_server_name(conf: Path) -> str:
    txt = read_text(conf, 200_000) or ""
    pref, fall = [], []
    for raw in txt.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line.startswith("server_name"):
            continue
        for host in line.rstrip(";").split()[1:]:
            host = host.strip().lower().lstrip("*.")
            if not host or host == "_":
                continue
            fall.append(host)
            if "cloudwaysapps.com" not in host:
                pref.append(host)
    return (pref or fall or [""])[0]


def detect_app_meta(app_dir: Path) -> dict:
    """Application type and DB name, read from config files (values only, never credentials)."""
    ph = app_dir / "public_html"
    meta = {"type": "php", "db_name": "", "db_source": ""}
    wp = read_text(ph / "wp-config.php", 300_000)
    if wp is not None:
        meta["type"] = "wordpress"
        m = re.search(r"""define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]""", wp)
        if m:
            meta["db_name"], meta["db_source"] = m.group(1), "wp-config.php"
        if "woocommerce" in " ".join(os.listdir(ph / "wp-content" / "plugins")) if safe_is_dir(ph / "wp-content" / "plugins") else False:
            meta["type"] = "wordpress+woocommerce"
        return meta
    env = read_text(ph / "app" / "etc" / "env.php", 300_000)
    if env is not None:
        meta["type"] = "magento"
        m = re.search(r"""['"]dbname['"]\s*=>\s*['"]([^'"]+)['"]""", env)
        if m:
            meta["db_name"], meta["db_source"] = m.group(1), "app/etc/env.php"
        return meta
    dotenv = read_text(ph / ".env", 100_000)
    if dotenv is not None and "DB_DATABASE" in dotenv:
        meta["type"] = "laravel"
        m = re.search(r"^DB_DATABASE\s*=\s*\"?([^\"\s]+)", dotenv, re.M)
        if m:
            meta["db_name"], meta["db_source"] = m.group(1), ".env"
    return meta


def collect_apps(roots: list[Path]) -> dict[str, dict]:
    apps: dict[str, dict] = {}
    by_real: dict[str, str] = {}          # real path of app dir -> app name (dedupe symlinked aliases)
    for root in roots:
        try:
            children = sorted(root.iterdir())
        except OSError:
            continue
        for d in children:
            logs = d / "logs"
            if d.name.startswith(".") or not safe_is_dir(logs) or d.name in apps:
                continue
            if not (safe_is_dir(d / "public_html") or safe_is_dir(d / "conf")):
                continue
            real = os.path.realpath(d)
            if real in by_real:
                # Same directory reached through a symlink: count it once, under the real (non-symlink) name.
                first = by_real[real]
                if os.path.islink(apps[first]["app_dir"]) and not os.path.islink(d):
                    entry = apps.pop(first)
                    entry["aliases"] = entry.get("aliases", []) + [first]
                    entry.update({"app": d.name, "app_dir": d})
                    apps[d.name] = entry
                    by_real[real] = d.name
                else:
                    apps[first].setdefault("aliases", []).append(d.name)
                continue
            by_real[real] = d.name
            try:
                names = os.listdir(logs)
            except OSError:
                names = []
            backend = sorted((logs / n for n in names if n.startswith("backend") and ".access.log" in n), key=rotated_index)
            frontend = sorted((logs / n for n in names if n.startswith("nginx-app.status.log") or
                               (n.startswith("nginx") and ".access.log" in n)), key=rotated_index)
            meta = detect_app_meta(d)
            apps[d.name] = {
                "app": d.name, "app_dir": d, "logs_dir": logs,
                "domain": parse_server_name(d / "conf" / "server.nginx"),
                "backend_logs": backend, "frontend_logs": frontend,
                "fpm_access_logs": sorted((logs / n for n in names if n.startswith("php-app.access.log")), key=rotated_index),
                "fpm_slow_logs": sorted((logs / n for n in names if n.startswith("php-app.slow.log")), key=rotated_index),
                "cron_logs": sorted((logs / n for n in names if n.startswith("wp-cron.log")), key=rotated_index),
                **meta,
            }
    return apps


POOL_KEYS = ("user", "listen", "pm", "pm.max_children", "pm.start_servers", "pm.min_spare_servers",
             "pm.max_spare_servers", "pm.max_requests", "pm.process_idle_timeout",
             "request_terminate_timeout", "request_slowlog_timeout", "pm.status_path", "slowlog",
             "access.log", "prefix", "php_admin_value[memory_limit]", "php_value[memory_limit]",
             "php_admin_value[max_execution_time]", "php_value[max_execution_time]")


def _parse_fpm_conf(path: Path, current: dict | None, pools: dict, depth: int = 0, defaults: dict | None = None):
    """Parse an FPM ini file honouring `include` in place (later values override)."""
    if depth > 5:
        return current
    txt = read_text(path, 500_000)
    if txt is None:
        if current is not None:
            current.setdefault("_unreadable", []).append(str(path))
        return current
    for raw in txt.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            name = m.group(1).strip()
            if name.lower() in ("global", "www") and name.lower() == "global":
                current = None
                continue
            current = pools.setdefault(name, {"pool": name, "conf_files": []})
            if defaults:
                for k, v in defaults.items():
                    current.setdefault(k, v)
            current["conf_files"].append(str(path))
            continue
        if "=" not in line:
            continue
        key, val = (x.strip() for x in line.split("=", 1))
        val = val.split(";", 1)[0].strip().strip('"').strip("'")
        if key == "include":
            for inc in sorted(glob.glob(val)) or [val]:
                current = _parse_fpm_conf(Path(inc), current, pools, depth + 1)
                if current is not None and str(inc) not in current["conf_files"]:
                    current["conf_files"].append(str(inc))
            continue
        if current is not None and (key in POOL_KEYS or key.startswith("pm")):
            current[key] = val
    return current


def collect_pools(ctx: Ctx, apps: dict) -> dict[str, dict]:
    """Return pool_name -> config, with `app` and `php_version` resolved."""
    pools: dict[str, dict] = {}
    for conf in [c for g in ctx.args.pool_conf_glob.split(",") for c in sorted(glob.glob(g.strip()))]:
        if conf.endswith("placeholder.conf"):
            continue
        before = set(pools)
        _parse_fpm_conf(Path(conf), None, pools)
        m = re.search(r"/php/([\d.]+)/", conf)
        for name in set(pools) - before:
            pools[name]["php_version"] = m.group(1) if m else ""
    user_to_app, unreadable = {}, []
    for name, p in pools.items():
        app = resolve_pool_app(name, p, apps)
        p["app"] = app
        if p.get("user") and app in apps:
            user_to_app[p["user"]] = app
        if p.get("_unreadable"):
            unreadable.append(p["_unreadable"][0])
    if unreadable:
        ctx.note(f"{len(unreadable)} pool include file(s) unreadable, e.g. {unreadable[0]} - app-level PHP-FPM "
                 "overrides (max_children etc.) may be missing; run as root.")
    ctx.user_to_app = user_to_app
    return pools


def resolve_pool_app(pool: str, conf: dict, apps: dict) -> str:
    base = POOL_SUFFIX_RE.sub("", pool)
    if base in apps:
        return base
    if pool in apps:
        return pool
    for key in ("prefix", "access.log", "slowlog"):
        v = conf.get(key, "")
        for app in apps:
            if f"/{app}/" in v:
                return app
    if conf.get("user") in apps:
        return conf["user"]
    return base


def pool_to_app(pool: str, ctx: Ctx, apps: dict) -> str:
    p = ctx.pools.get(pool)
    if p:
        return p["app"]
    base = POOL_SUFFIX_RE.sub("", pool.strip())
    return base


def uid_name(uid: int, cache: dict = {}) -> str:  # noqa: B006 - intentional cache
    if uid not in cache:
        try:
            cache[uid] = pwd.getpwuid(uid).pw_name
        except KeyError:
            cache[uid] = str(uid)
    return cache[uid]


# ----------------------------------------------------------------------------
# Live sampling (/proc)
# ----------------------------------------------------------------------------
def read_proc_stat_cpu() -> list[int] | None:
    txt = read_text("/proc/stat", 100_000)
    if not txt:
        return None
    for line in txt.splitlines():
        if line.startswith("cpu "):
            return [int(x) for x in line.split()[1:]]
    return None


def read_meminfo() -> dict:
    out = {}
    for line in (read_text("/proc/meminfo") or "").splitlines():
        k, _, v = line.partition(":")
        try:
            out[k.strip()] = int(v.split()[0])  # kB
        except (ValueError, IndexError):
            pass
    return out


def read_diskstats() -> dict:
    out = {}
    for line in (read_text("/proc/diskstats") or "").splitlines():
        p = line.split()
        if len(p) < 14:
            continue
        name = p[2]
        if re.match(r"^(loop|ram|sr|fd|dm-)", name) or re.match(r"^(sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+p)\d+$", name):
            continue
        # reads, read_ms, writes, write_ms, io_ms (busy), sectors r/w
        out[name] = (int(p[3]), int(p[6]), int(p[7]), int(p[10]), int(p[12]), int(p[5]), int(p[9]))
    return out


def read_netdev() -> dict:
    out = {}
    for line in (read_text("/proc/net/dev") or "").splitlines()[2:]:
        if ":" not in line:
            continue
        name, data = line.split(":", 1)
        name = name.strip()
        if name == "lo":
            continue
        f = data.split()
        if len(f) >= 9:
            out[name] = (int(f[0]), int(f[8]))
    return out


def read_pressure(kind: str) -> dict:
    txt = read_text(f"/proc/pressure/{kind}")
    res = {}
    for line in (txt or "").splitlines():
        p = line.split()
        if p and p[0] in ("some", "full"):
            for kv in p[1:]:
                k, _, v = kv.partition("=")
                if k == "avg60":
                    res[p[0]] = float(v)
    return res


def read_listen_queues() -> dict[str, tuple[int, int]]:
    """unix-socket path -> (current accept queue, backlog). Recv-Q of a LISTEN socket is the queue."""
    rc, out, _ = run_cmd(["ss", "-xlnH"], timeout=5)
    res = {}
    if rc != 0:
        return res
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 5 and p[1] == "LISTEN":
            try:
                res[p[4]] = (int(p[2]), int(p[3]))
            except ValueError:
                pass
    return res


def read_pid(pid: str):
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read().decode("utf-8", "replace")
        r = raw.rfind(")")
        comm = raw[raw.find("(") + 1:r]
        f2 = raw[r + 2:].split()
        state, ppid = f2[0], int(f2[1])
        utime, stime = int(f2[11]), int(f2[12])
        start = int(f2[19])
        rss_kb = int(f2[21]) * PAGE_KB
        uid = os.stat(f"/proc/{pid}").st_uid
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            cmd = f.read(400).replace(b"\0", b" ").decode("utf-8", "replace").strip()
        return comm, state, ppid, utime + stime, start, rss_kb, uid, cmd
    except (OSError, ValueError, IndexError):
        return None


def read_pss_kb(pid: int) -> int | None:
    txt = read_text(f"/proc/{pid}/smaps_rollup", 10_000)
    if not txt:
        return None
    m = re.search(r"^Pss:\s+(\d+)", txt, re.M)
    return int(m.group(1)) if m else None


def classify_process(comm: str, cmd: str, uid: int, ctx: Ctx, apps: dict) -> tuple[str, str, str]:
    """Return (owner_kind, owner, detail). owner_kind in app|service|other."""
    if cmd.startswith("php-fpm: pool "):
        pool = cmd[len("php-fpm: pool "):].strip()
        app = pool_to_app(pool, ctx, apps)
        if app not in apps:
            return "service", f"fpm-pool:{pool}", "fpm:" + pool
        return "app", app, "fpm:" + pool
    if cmd.startswith("php-fpm: master"):
        return "service", "php-fpm-master", "master"
    user = uid_name(uid)
    app = ctx.user_to_app.get(user) or (user if user in apps else None)
    if app:
        kind = f"cli:{comm}"
        if "wp-cron" in cmd or " cron " in cmd:
            kind = "wp-cron"
        elif "wp " in cmd or "wp-cli" in cmd:
            kind = "wp-cli"
        return "app", app, kind
    for name, rx in SERVICE_PATTERNS:
        if rx.match(comm):
            if name == "elasticsearch" and comm == "java" and not re.search(r"elasticsearch|opensearch", cmd):
                break
            return "service", name, comm
    return "other", comm, comm


def sample_resources(ctx: Ctx, apps: dict, seconds: float, interval: float, hooks=()) -> dict:
    """Take repeated /proc snapshots and attribute CPU/memory to apps and services."""
    nsamples = max(2, int(seconds / interval) + 1)
    proc_prev: dict[str, tuple] = {}
    per_owner = defaultdict(lambda: {"cpu_ticks": 0, "cpu_series": [], "rss_series": [], "procs_series": [],
                                    "busy_series": [], "kinds": Counter(), "long_cli": []})
    server = {"cpu": [], "load": [], "mem": [], "disk": [], "net": [], "listen": defaultdict(list)}
    pool_socks = {p.get("listen", ""): p["app"] for p in ctx.pools.values() if p.get("listen")}
    btime = 0
    for line in (read_text("/proc/stat") or "").splitlines():
        if line.startswith("btime"):
            btime = int(line.split()[1])
    last_snapshot = {}
    prev_cpu = read_proc_stat_cpu()
    prev_disk, prev_net, prev_t = read_diskstats(), read_netdev(), time.time()
    first_t = prev_t
    first_ticks: dict[str, tuple[int, int]] = {}
    busy_streak: dict[str, int] = {}
    busy_best: dict[str, tuple[int, tuple]] = {}      # pid -> (max consecutive busy samples, owner key)
    for i in range(nsamples):
        t = time.time()
        snap = {}
        try:
            pids = [p for p in os.listdir("/proc") if p.isdigit()]
        except OSError:
            pids = []
        for pid in pids:
            info = read_pid(pid)
            if info:
                snap[pid] = info
        # Per-owner aggregation for this sample
        owners_cpu = Counter()
        owners_rss = Counter()
        owners_procs = Counter()
        owners_busy = Counter()
        dt = max(t - prev_t, 0.001) if i else None
        for pid, (comm, state, ppid, ticks, start, rss, uid, cmd) in snap.items():
            if ppid == 2 or pid == "2":   # kernel threads
                continue
            kind, owner, detail = classify_process(comm, cmd, uid, ctx, apps)
            key = (kind, owner)
            owners_rss[key] += rss
            owners_procs[key] += 1
            prev = proc_prev.get(pid)
            delta = 0
            if i:
                if prev and prev[4] == start:
                    delta = max(0, ticks - prev[3])
                elif start / CLK_TCK + btime >= first_t - 1:
                    delta = ticks          # process born during sampling
                owners_cpu[key] += delta
            if detail.startswith("fpm:"):
                if state in ("R", "D") or delta > 0:
                    owners_busy[key] += 1
                    busy_streak[pid] = busy_streak.get(pid, 0) + 1
                    if busy_streak[pid] > busy_best.get(pid, (0,))[0]:
                        busy_best[pid] = (busy_streak[pid], key)
                elif i:
                    busy_streak[pid] = 0
            if i == 0:
                per_owner[key]["kinds"][detail] += 1
            if i == 0:
                first_ticks[pid] = (ticks, start)
            if i == nsamples - 1 and kind == "app" and not detail.startswith("fpm:"):
                age = time.time() - (start / CLK_TCK + btime) if btime else 0
                ft = first_ticks.get(pid)
                span = max(t - first_t, 0.001)
                live_cpu = ((ticks - ft[0]) / CLK_TCK / span * 100.0) if ft and ft[1] == start else (ticks / CLK_TCK / max(age, span) * 100.0)
                if age >= 60 and comm not in ("bash", "sh", "sleep", "sshd", "systemd", "(sd-pam)"):
                    per_owner[key]["long_cli"].append({"pid": int(pid), "age_s": int(age), "comm": comm,
                                                       "live_cpu": round(live_cpu, 1),
                                                       "life_cpu": round(ticks / CLK_TCK / max(age, 1) * 100.0, 1),
                                                       "cpu_s": round(ticks / CLK_TCK, 1),
                                                       "cmd": trunc(re.sub(r"(--?(?:pass(?:word)?|pwd|p)[= ])\S+", r"\1***", cmd), 120)})
        if i:
            for key in set(owners_cpu) | set(per_owner):
                per_owner[key]["cpu_ticks"] += owners_cpu.get(key, 0)
                per_owner[key]["cpu_series"].append(owners_cpu.get(key, 0) / CLK_TCK / dt * 100.0)
        for key in set(owners_rss) | set(per_owner):
            per_owner[key]["rss_series"].append(owners_rss.get(key, 0) / 1024.0)
            per_owner[key]["procs_series"].append(owners_procs.get(key, 0))
            per_owner[key]["busy_series"].append(owners_busy.get(key, 0))
        # Server-level
        cpu = read_proc_stat_cpu()
        if cpu and prev_cpu and i:
            d = [a - b for a, b in zip(cpu, prev_cpu)]
            tot = sum(d[:8]) or 1
            server["cpu"].append({"user": pct(d[0] + d[1], tot), "system": pct(d[2] + d[5] + d[6], tot),
                                  "iowait": pct(d[4], tot), "steal": pct(d[7], tot) if len(d) > 7 else 0.0,
                                  "idle": pct(d[3], tot)})
        prev_cpu = cpu
        la = (read_text("/proc/loadavg") or "0 0 0").split()
        server["load"].append(tuple(float(x) for x in la[:3]))
        server["mem"].append(read_meminfo())
        disk, net = read_diskstats(), read_netdev()
        if i:
            for dev, cur in disk.items():
                pv = prev_disk.get(dev)
                if not pv:
                    continue
                ios = (cur[0] - pv[0]) + (cur[2] - pv[2])
                ms = (cur[1] - pv[1]) + (cur[3] - pv[3])
                server["disk"].append({"dev": dev, "util": min(100.0, (cur[4] - pv[4]) / (dt * 1000) * 100),
                                       "iops": ios / dt, "await_ms": (ms / ios) if ios else 0.0,
                                       "mbps": ((cur[5] - pv[5]) + (cur[6] - pv[6])) * 512 / dt / 1048576})
            for dev, cur in net.items():
                pv = prev_net.get(dev)
                if pv:
                    server["net"].append({"dev": dev, "rx_mbps": (cur[0] - pv[0]) * 8 / dt / 1e6,
                                          "tx_mbps": (cur[1] - pv[1]) * 8 / dt / 1e6})
        prev_disk, prev_net = disk, net
        lq = read_listen_queues()
        for sock, (q, backlog) in lq.items():
            if sock in pool_socks:
                server["listen"][pool_socks[sock]].append((q, backlog))
        for hook in hooks:
            try:
                hook(i)
            except Exception as exc:  # noqa: BLE001
                ctx.debug(f"sample hook failed: {exc}")
        proc_prev = snap
        last_snapshot = snap
        prev_t = t
        if i < nsamples - 1:
            ctx.progress(f"Resource sample {i + 1}/{nsamples} collected")
            time.sleep(interval)
    elapsed = prev_t - first_t

    # PSS (proportional set size) avoids double counting shared pages between FPM workers.
    pss = Counter()
    pss_ok = False
    top_procs = defaultdict(list)
    for pid, (comm, state, ppid, ticks, start, rss, uid, cmd) in last_snapshot.items():
        if ppid == 2:
            continue
        v = read_pss_kb(int(pid))
        kind, owner, detail = classify_process(comm, cmd, uid, ctx, apps)
        if v is not None:
            pss_ok = True
            pss[(kind, owner)] += v
        if kind == "app":
            ft = first_ticks.get(pid)
            span = max(elapsed, 0.001)
            age = (time.time() - (start / CLK_TCK + btime)) if btime else 0
            cpu_now = ((ticks - ft[0]) / CLK_TCK / span * 100.0) if ft and ft[1] == start else \
                (ticks / CLK_TCK / max(age, span) * 100.0)
            top_procs[(kind, owner)].append({"pid": int(pid), "what": detail, "state": state, "cpu": round(cpu_now, 1),
                                             "mem_mb": round((v if v is not None else rss) / 1024.0, 1),
                                             "mem_kind": "PSS" if v is not None else "RSS", "age_s": int(age)})
    long_busy = defaultdict(list)
    min_streak = max(3, int(ctx.args.long_request_seconds / max(interval, 0.5)))
    for pid, (n, key) in busy_best.items():
        if n >= min_streak:
            long_busy[key].append({"pid": int(pid), "busy_s": round(n * interval)})
    if not pss_ok:
        ctx.note("PSS (smaps_rollup) not readable - memory per app uses RSS, which over-counts memory shared between PHP-FPM workers. Run as root for PSS.")

    owners = {}
    for key, o in per_owner.items():
        cs, rs = o["cpu_series"], o["rss_series"]
        owners[key] = {
            "kind": key[0], "owner": key[1],
            "cpu_avg": (o["cpu_ticks"] / CLK_TCK / elapsed * 100.0) if elapsed else 0.0,   # % of one core
            "cpu_peak": max(cs) if cs else 0.0,
            "rss_avg_mb": sum(rs) / len(rs) if rs else 0.0,
            "rss_peak_mb": max(rs) if rs else 0.0,
            "pss_mb": (pss[key] / 1024.0) if pss_ok and key in pss else None,
            "procs_avg": sum(o["procs_series"]) / len(o["procs_series"]) if o["procs_series"] else 0,
            "procs_peak": max(o["procs_series"]) if o["procs_series"] else 0,
            "busy_avg": sum(o["busy_series"]) / len(o["busy_series"]) if o["busy_series"] else 0,
            "busy_peak": max(o["busy_series"]) if o["busy_series"] else 0,
            "kinds": dict(o["kinds"]), "long_cli": sorted(o["long_cli"], key=lambda x: -x["live_cpu"])[:5],
            "procs_last": o["procs_series"][-1] if o["procs_series"] else 0,
            "busy_last": o["busy_series"][-1] if o["busy_series"] else 0,
            "top_procs": sorted(top_procs.get(key, []), key=lambda x: (-x["cpu"], -x["mem_mb"]))[:8],
            "long_busy": sorted(long_busy.get(key, []), key=lambda x: -x["busy_s"])[:5],
        }
    return {"elapsed": elapsed, "samples": nsamples, "owners": owners, "server": server, "pss_ok": pss_ok}


# ----------------------------------------------------------------------------
# Historical resources from atop raw logs
# ----------------------------------------------------------------------------
ATOP_PROC_RE = re.compile(r"^(PRC|PRM|PRG) (\S+) (\d+) (\S+) (\S+) (\d+) (\d+) \((.*?)\) (\S) (.*)$")


def atop_history(ctx: Ctx, apps: dict, start: datetime, end: datetime) -> dict | None:
    if not shutil.which("atop"):
        ctx.note("atop is not installed - no historical per-application CPU/memory; only live sampling and PHP-FPM logs were used.")
        return None
    days, d = [], start.date()
    while d <= end.date():
        days.append(d)
        d += timedelta(days=1)
    lines: list[str] = []
    used_files = []
    for day in days:
        f = Path(f"/var/log/atop/atop_{day:%Y%m%d}")
        if not f.exists():
            continue
        b = start.strftime("%H:%M") if day == start.date() else "00:00"
        e = end.strftime("%H:%M") if day == end.date() else "23:59"
        rc, out, err = run_cmd(["atop", "-r", str(f), "-b", b, "-e", e, "-P", "CPU,MEM,SWP,PRC,PRM,PRG"],
                               timeout=ctx.args.atop_timeout, ctx=ctx)
        if rc != 0 and not out:
            ctx.note(f"atop history unreadable ({trunc(err.strip() or 'exit ' + str(rc), 80)}) - run as root.")
            continue
        used_files.append(str(f))
        lines.extend(out.splitlines())
    if not lines:
        if not used_files:
            ctx.note("No atop raw log covers the investigation window - historical averages unavailable.")
        return None

    intervals: dict[int, dict] = {}
    cmdmap: dict[tuple[int, int], tuple[str, int]] = {}
    prc_rows, prm_rows = [], []
    for line in lines:
        if line.startswith(("CPU ", "MEM ", "SWP ")):
            p = line.split()
            ep, iv = int(p[2]), int(p[5])
            slot = intervals.setdefault(ep, {"interval": iv, "time": f"{p[3]} {p[4]}"})
            r = [int(x) for x in p[6:] if re.fullmatch(r"-?\d+", x)]
            if p[0] == "CPU" and len(r) >= 10:
                ticks, ncpu, sys_, usr, nice, idle, wait, irq, sirq, steal = r[:10]
                tot = sys_ + usr + nice + idle + wait + irq + sirq + steal or 1
                slot["cpu_busy"] = pct(tot - idle - wait, tot)
                slot["iowait"] = pct(wait, tot)
                slot["steal"] = pct(steal, tot)
                slot["ncpu"] = ncpu
                slot["ticks"] = ticks
            elif p[0] == "MEM" and len(r) >= 8:
                pg, phys, free, cache, buf, slab, dirty, slabrec = r[:8]
                shmem = r[9] if len(r) > 9 else 0
                avail = free + cache + buf + slabrec - shmem
                slot["mem_used_pct"] = pct(phys - avail, phys)
                slot["mem_total_mb"] = phys * pg / 1048576
            elif p[0] == "SWP" and len(r) >= 3:
                pg, tot, free = r[:3]
                slot["swap_used_mb"] = (tot - free) * pg / 1048576
            continue
        m = ATOP_PROC_RE.match(line)
        if not m:
            continue
        label, ep, iv, pid, name, state, rest = m.group(1), int(m.group(3)), int(m.group(6)), int(m.group(7)), m.group(8), m.group(9), m.group(10)
        if label == "PRG":
            cm = re.search(r"\((.*?)\s*\)", rest)
            ruid = int(rest.split()[0]) if rest.split()[0].lstrip("-").isdigit() else -1
            cmdmap[(ep, pid)] = ((cm.group(1).strip() if cm else ""), ruid)
            continue
        f = rest.split()
        if label == "PRC" and len(f) > 10 and f[10] == "y":
            prc_rows.append((ep, iv, pid, name, state, int(f[0]), int(f[1]) + int(f[2])))
        elif label == "PRM" and len(f) > 13 and f[13] == "y" and state != "E":
            prm_rows.append((ep, pid, name, int(f[2])))

    owner_cpu = defaultdict(lambda: defaultdict(float))     # owner -> epoch -> % of one core
    owner_rss = defaultdict(lambda: defaultdict(float))     # owner -> epoch -> MB
    for ep, iv, pid, name, state, ticks, used in prc_rows:
        cmd, ruid = cmdmap.get((ep, pid), ("", -1))
        kind, owner, _ = classify_process(name, cmd, ruid if ruid >= 0 else 0, ctx, apps) if ruid >= 0 else ("other", name, name)
        owner_cpu[(kind, owner)][ep] += used / max(ticks * iv, 1) * 100.0
    for ep, pid, name, rss in prm_rows:
        cmd, ruid = cmdmap.get((ep, pid), ("", -1))
        kind, owner, _ = classify_process(name, cmd, ruid if ruid >= 0 else 0, ctx, apps) if ruid >= 0 else ("other", name, name)
        owner_rss[(kind, owner)][ep] += rss / 1024.0
    epochs = sorted(intervals)
    owners = {}
    for key in set(owner_cpu) | set(owner_rss):
        cs = [owner_cpu[key].get(ep, 0.0) for ep in epochs]
        rs = [owner_rss[key].get(ep, 0.0) for ep in epochs]
        peak_i = max(range(len(cs)), key=lambda i: cs[i]) if cs else 0
        owners[key] = {"cpu_avg": sum(cs) / len(cs) if cs else 0.0, "cpu_peak": max(cs) if cs else 0.0,
                       "cpu_peak_at": intervals[epochs[peak_i]]["time"] if epochs else "",
                       "rss_avg_mb": sum(rs) / len(rs) if rs else 0.0, "rss_peak_mb": max(rs) if rs else 0.0,
                       "intervals_high": sum(1 for c in cs if c >= 50.0)}
    srv = [intervals[ep] for ep in epochs]

    def agg(key):
        vals = [s[key] for s in srv if key in s]
        return (sum(vals) / len(vals), max(vals)) if vals else (None, None)
    return {"files": used_files, "intervals": len(epochs),
            "interval_s": srv[0]["interval"] if srv else 0, "owners": owners,
            "cpu_busy": agg("cpu_busy"), "iowait": agg("iowait"), "steal": agg("steal"),
            "mem_used_pct": agg("mem_used_pct"), "swap_used_mb": agg("swap_used_mb"),
            "high_cpu_intervals": sum(1 for s in srv if s.get("cpu_busy", 0) >= 85),
            "high_mem_intervals": sum(1 for s in srv if s.get("mem_used_pct", 0) >= 90)}


# ----------------------------------------------------------------------------
# PHP-FPM access log (per-request duration, memory and CPU)
# ----------------------------------------------------------------------------
def classify_uri(uri: str) -> str:
    u = uri.lower()
    path = u.split("?", 1)[0]
    if "wp-cron.php" in path:
        return "wp-cron"
    if "xmlrpc.php" in path:
        return "xmlrpc"
    if "wp-login.php" in path:
        return "wp-login"
    if "admin-ajax.php" in path:
        return "admin-ajax"
    if "/wp-json/" in path or "rest_route=" in u:
        return "wc-rest" if "/wc/" in path or "/wc-" in path else "rest-api"
    if "wc-ajax=" in u or "/cart" in path or "/checkout" in path or "add-to-cart=" in u or "/my-account" in path:
        return "woocommerce"
    if "/wp-admin/" in path:
        return "wp-admin"
    if path.endswith(STATIC_EXT):
        return "static"
    if "/feed" in path:
        return "feed"
    if "s=" in u.split("?", 1)[-1] and "?" in u:
        return "search"
    return "page"


def analyze_fpm_access(ctx: Ctx, app: dict, start, end, deep: bool) -> dict:
    files = files_for_window(app["fpm_access_logs"], start)
    res = {"files": [f.name for f in files], "requests": 0, "cpu_s": 0.0, "dur_s": 0.0, "mem_sum": 0.0,
           "mem_max": 0.0, "unparsed": 0, "available": bool(app["fpm_access_logs"])}
    if not files:
        return res
    durations = []
    per_min = Counter()
    conc = Counter()
    paths = {}
    types = Counter()
    status = Counter()
    over = Counter()
    heap_cpu, heap_dur, heap_mem = [], [], []
    ip_stats: dict[str, list] = {}
    slow_paths: dict[str, list] = {}
    err5 = Counter()
    seq = 0
    for f in files:
        for line in iter_lines(f, start, access_line_ts):
            m = FPM_ACCESS_RE.match(line)
            if not m:
                if line.strip():
                    res["unparsed"] += 1
                continue
            ts = make_ts(m["y"], m["mon"], m["d"], m["h"], m["mi"], m["s"], m["tz"])
            if not in_window(ts, start, end):
                continue
            dur = float(m["dur"])
            mem_mb = int(m["mem"]) / 1048576.0
            cpu_pct = min(100.0, float(m["cu"]) + float(m["cs"]))
            cpu_s = dur * cpu_pct / 100.0
            res["requests"] += 1
            res["cpu_s"] += cpu_s
            res["dur_s"] += dur
            res["mem_sum"] += mem_mb
            res["mem_max"] = max(res["mem_max"], mem_mb)
            status[m["status"]] += 1
            for thr in (1, 5, 10, 30):
                if dur >= thr:
                    over[thr] += 1
            if not deep:
                continue
            durations.append(dur)
            ipst = ip_stats.get(m["ip"])
            if ipst is None:
                if len(ip_stats) < 300000:
                    ip_stats[m["ip"]] = [1, cpu_s, dur]
            else:
                ipst[0] += 1
                ipst[1] += cpu_s
                ipst[2] += dur
            minute = ts.replace(second=0)
            per_min[minute] += 1
            s0 = int(ts.replace(tzinfo=timezone.utc).timestamp())
            rem = dur
            for sec in range(s0, s0 + min(3600, int(dur) + 1)):
                conc[sec] += min(1.0, rem)
                rem -= 1.0
                if rem <= 0:
                    break
            uri = m["uri"] or m["script"]
            rtype = classify_uri(uri)
            types[rtype] += 1
            p = uri.split("?", 1)[0]
            if len(paths) < 50000 or p in paths:
                a = paths.setdefault(p, [0, 0.0, 0.0, 0.0, 0.0])
                a[0] += 1
                a[1] += cpu_s
                a[2] += dur
                a[3] = max(a[3], dur)
                a[4] = max(a[4], mem_mb)
            seq += 1
            rec = {"time": ts.strftime("%H:%M:%S"), "method": m["method"], "status": m["status"], "dur": round(dur, 3),
                   "cpu_s": round(cpu_s, 3), "cpu_pct": round(cpu_pct, 1), "mem": round(mem_mb, 1), "uri": trunc(uri, 90)}
            if dur >= ctx.args.slow_request_seconds:
                sp = slow_paths.setdefault(p, [0, 0.0, 0.0])
                sp[0] += 1
                sp[1] += dur
                sp[2] = max(sp[2], dur)
            if m["status"][0] == "5":
                err5[(m["status"], trunc(p, 80))] += 1
            for heap, k in ((heap_cpu, cpu_s), (heap_dur, dur), (heap_mem, mem_mb)):
                if len(heap) < 10:
                    heappush(heap, (k, seq, rec))
                elif k > heap[0][0]:
                    heapreplace(heap, (k, seq, rec))
    n = res["requests"]
    res["avg_dur"] = res["dur_s"] / n if n else None
    res["avg_mem"] = res["mem_sum"] / n if n else None
    res["cpu_ms_per_req"] = res["cpu_s"] * 1000 / n if n else None
    res["over"] = dict(over)
    res["status"] = dict(status)
    if deep and n:
        durations.sort()
        res["p50"] = percentile(durations, 0.5)
        res["p95"] = percentile(durations, 0.95)
        res["p99"] = percentile(durations, 0.99)
        res["max_dur"] = durations[-1]
        res["peak_rpm"] = max(per_min.values())
        res["peak_rpm_at"] = max(per_min, key=per_min.get).strftime("%H:%M")
        res["_per_min"] = dict(per_min)
        res["_peak_min"] = max(per_min, key=per_min.get)
        peak_at = max(conc, key=conc.get) if conc else None
        peak = conc[peak_at] if peak_at is not None else 0
        res["peak_concurrency"] = round(peak, 1)
        res["peak_concurrency_at"] = datetime.fromtimestamp(peak_at, timezone.utc).strftime("%H:%M:%S") if peak_at else ""
        res["types"] = types.most_common()
        res["_ip_stats"] = ip_stats
        top = sorted(paths.items(), key=lambda kv: -kv[1][1])[:10]
        res["top_paths_cpu"] = [{"path": trunc(k, 70), "hits": v[0], "cpu_s": round(v[1], 1),
                                 "avg_s": round(v[2] / v[0], 3), "max_s": round(v[3], 2), "max_mb": round(v[4], 1)}
                                for k, v in top]
        res["top_cpu_requests"] = [r for _, _, r in sorted(heap_cpu, reverse=True)]
        res["slowest_requests"] = [r for _, _, r in sorted(heap_dur, reverse=True)]
        res["top_mem_requests"] = [r for _, _, r in sorted(heap_mem, reverse=True)]
        res["repeated_slow_paths"] = [
            {"path": trunc(k, 70), "slow_hits": v[0], "hits": paths.get(k, [v[0]])[0], "avg_slow_s": round(v[1] / v[0], 2),
             "max_s": round(v[2], 2)}
            for k, v in sorted(slow_paths.items(), key=lambda kv: -kv[1][0]) if v[0] >= 2][:10]
        res["fpm_5xx"] = [{"status": st, "path": pth, "count": c} for (st, pth), c in err5.most_common(10)]
    return res


# ----------------------------------------------------------------------------
# PHP-FPM master logs, slow logs, cron logs, OOM events
# ----------------------------------------------------------------------------
def scan_fpm_master_logs(ctx: Ctx, apps: dict, start, end) -> dict:
    """max_children breaches, 'seems busy' warnings, request_terminate_timeout kills per app."""
    out = defaultdict(lambda: {"max_children_hits": 0, "limit": None, "busy_warnings": 0,
                               "timeouts": 0, "timeout_scripts": Counter(), "first": None, "last": None})
    files = files_for_window(ctx.args.fpm_log_glob, start)
    readable = 0
    for f in files:
        if not os.access(f, os.R_OK):
            continue
        readable += 1
        for line in iter_lines(f, start, fpm_line_ts):
            if "WARNING" not in line and "NOTICE" not in line:
                continue
            if not ("max_children" in line or "seems busy" in line or "timed out" in line):
                continue
            ts = fpm_line_ts(line)
            if not in_window(ts, start, end):
                continue
            pm = FPM_POOL_RE.search(line)
            if not pm:
                continue
            app = pool_to_app(pm.group(1), ctx, apps)
            o = out[app]
            mc = FPM_MAXCHILD_RE.search(line)
            if mc:
                o["max_children_hits"] += 1
                o["limit"] = int(mc.group(1))
                o.setdefault("minutes", Counter())[ts.replace(second=0)] += 1
            elif FPM_BUSY_RE.search(line):
                o["busy_warnings"] += 1
            else:
                mt = FPM_TIMEOUT_RE.search(line)
                if mt:
                    o["timeouts"] += 1
                    o["timeout_scripts"][short_path(mt.group(2))] += 1
                else:
                    continue
            o["first"] = o["first"] or ts
            o["last"] = ts
    if files and not readable:
        ctx.note("PHP-FPM master logs (/var/log/php*-fpm.log) are not readable - max_children/timeout events unavailable (run as root).")
    elif not files:
        ctx.note("No PHP-FPM master log found for the window (pattern " + ctx.args.fpm_log_glob + ").")
    return dict(out)


def analyze_slowlog(ctx: Ctx, app: dict, start, end) -> dict:
    files = files_for_window(app["fpm_slow_logs"], start)
    res = {"available": bool(app["fpm_slow_logs"]), "entries": 0, "scripts": Counter(),
           "functions": Counter(), "components": Counter(), "samples": []}
    if app["fpm_slow_logs"] and not any(os.access(f, os.R_OK) for f in app["fpm_slow_logs"]):
        res["unreadable"] = True
        return res
    for f in files:
        cur = None

        def flush(c):
            if not c:
                return
            res["entries"] += 1
            if c["script"]:
                res["scripts"][short_path(c["script"])] += 1
            frame = c["app_frame"] or c["top_frame"]
            if frame:
                res["functions"][(frame[0], short_path(frame[1]) + ":" + frame[2])] += 1
            comps = {component_of(fr[1]) for fr in c["frames"]}
            for comp in comps - {"wordpress-core", "app"} or comps:
                res["components"][comp] += 1
            if len(res["samples"]) < 3 and c["frames"]:
                res["samples"].append({"time": c["ts"].strftime("%Y-%m-%d %H:%M:%S"), "script": short_path(c["script"]),
                                       "frames": [f"{fr[0]}() {short_path(fr[1])}:{fr[2]}" for fr in c["frames"][:6]]})

        for line in iter_lines(f):
            h = SLOW_HEADER_RE.match(line)
            if h:
                if cur and in_window(cur["ts"], start, end):
                    flush(cur)
                ts = make_ts(h.group(3), h.group(2), h.group(1), h.group(4), h.group(5), h.group(6))
                cur = {"ts": ts, "script": "", "frames": [], "top_frame": None, "app_frame": None}
                continue
            if cur is None:
                continue
            m = SLOW_SCRIPT_RE.match(line)
            if m:
                cur["script"] = m.group(1).strip()
                continue
            m = SLOW_FRAME_RE.match(line)
            if m and len(cur["frames"]) < 40:
                fr = (m.group(1), m.group(2), m.group(3))
                cur["frames"].append(fr)
                cur["top_frame"] = cur["top_frame"] or fr
                if cur["app_frame"] is None and ("/wp-content/" in fr[1] or "/app/code/" in fr[1]):
                    cur["app_frame"] = fr
        if cur and in_window(cur["ts"], start, end):
            flush(cur)
    return res


CRON_EVENT_RE = re.compile(r"Executed the cron event '([^']+)' in ([0-9.]+)s")


def analyze_cron_log(app: dict, start) -> dict | None:
    files = files_for_window(app["cron_logs"], start)
    if not files:
        return None
    hooks = Counter()
    total, slow, n = 0.0, [], 0
    for f in files[-2:]:
        for line in iter_lines(f, max_bytes=50_000_000):
            m = CRON_EVENT_RE.search(line)
            if m:
                d = float(m.group(2))
                n += 1
                total += d
                hooks[m.group(1)] += 1
                if d >= 10:
                    slow.append((d, m.group(1)))
    slow.sort(reverse=True)
    return {"events": n, "event_time_s": round(total, 1), "slow": slow[:5], "top_hooks": hooks.most_common(5),
            "approximate_window": True}


def parse_syslog_ts(line: str, now: datetime) -> datetime | None:
    m = SYSLOG_ISO_RE.match(line)
    if m:
        ts = make_ts(m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5), m.group(6))
        tz = m.group(7)
        if ts and tz and tz != "Z":
            tz = tz.replace(":", "")
            ts = make_ts(m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5), m.group(6), tz)
        return ts
    m = SYSLOG_CLASSIC_RE.match(line)
    if m:
        ts = make_ts(now.year, m.group(1), m.group(2), m.group(3), m.group(4), m.group(5))
        if ts and ts > now + timedelta(days=1):
            ts = ts.replace(year=now.year - 1)
        return ts
    return None


def oom_owner(ctx: Ctx, apps: dict, comm: str, uid: int | None, cgroup: str) -> tuple[str, str]:
    """Who owned the OOM victim: ('app', app) via the process UID, else ('service', name) via cgroup/name."""
    if uid is not None:
        user = uid_name(uid)
        app = getattr(ctx, "user_to_app", {}).get(user) or (user if user in apps else None)
        if app:
            return "app", app
    unit = cgroup.rstrip("/").split("/")[-1] if cgroup else ""
    if unit.endswith(".service"):
        base = unit[:-8]
        for name, rx in SERVICE_PATTERNS:
            if rx.match(base) or rx.match(comm):
                return "service", name
        if not re.match(r"^(user@|session-)", base):
            return "service", base
    for name, rx in SERVICE_PATTERNS:
        if rx.match(comm):
            return "service", name
    return "other", comm + (f" (uid {uid_name(uid)})" if uid is not None else "")


def parse_oom_lines(ctx: Ctx, apps: dict, lines, start, end) -> list[dict]:
    """Join the kernel's 3 OOM lines (invoked / oom-kill / Killed process) into one event per kill."""
    now = utcnow()
    events, seen = [], set()
    trigger, info = None, {}
    for line in lines:
        if "oom" not in line and "Out of memory" not in line and "out of memory" not in line:
            continue
        mi = OOM_INVOKED_RE.search(line)
        if mi and "invoked oom-killer" in line:
            trigger = mi.group(1)
            continue
        mk = OOM_KILLINFO_RE.search(line)
        if mk:
            info[mk.group(4)] = {"constraint": mk.group(1), "cgroup": mk.group(2) or "", "uid": int(mk.group(5))}
            continue
        m = OOM_KILLED_RE.search(line)
        if not m:
            continue
        ts = parse_syslog_ts(line, now)
        if ts is not None and not in_window(ts, start, end):
            continue
        pid, comm, rest = m.group(1), m.group(2), m.group(3)
        key = (pid, ts.strftime("%Y%m%d%H%M") if ts else "?")
        if key in seen:
            continue
        seen.add(key)
        fields, uid = {}, None
        for f in OOM_FIELD_RE.finditer(rest):
            if f.group(3):
                uid = int(f.group(3))
            else:
                fields[f.group(1)] = int(f.group(2))
        ki = info.pop(pid, {})
        uid = uid if uid is not None else ki.get("uid")
        kind, owner = oom_owner(ctx, apps, comm, uid, ki.get("cgroup", ""))
        events.append({"time": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "?", "pid": pid, "process": comm,
                       "uid": uid, "user": uid_name(uid) if uid is not None else "", "owner_kind": kind, "owner": owner,
                       "rss_mb": round((fields.get("anon-rss", 0) + fields.get("shmem-rss", 0)) / 1024, 1) if fields else None,
                       "vm_mb": round(fields["total-vm"] / 1024, 1) if "total-vm" in fields else None,
                       "cgroup": ki.get("cgroup", ""), "constraint": ki.get("constraint", ""),
                       "memcg": "cgroup" in m.group(0).lower() or ki.get("constraint") == "CONSTRAINT_MEMCG",
                       "trigger": trigger or ""})
        trigger = None
    return events


def scan_oom(ctx: Ctx, start, end, apps: dict | None = None) -> dict:
    apps = apps or {}
    events, sources = [], []
    for pattern in ctx.args.kernel_log_glob.split(","):
        files = [f for f in files_for_window(pattern.strip(), start) if os.access(f, os.R_OK)]
        if not files:
            continue
        sources.extend(str(f) for f in files)
        for f in files:
            events.extend(parse_oom_lines(ctx, apps, iter_lines(f), start, end))
        break       # kern.log and syslog duplicate each other; use the first readable source
    if not sources:
        rc, out, _ = run_cmd(["journalctl", "-k", "--no-pager", "-o", "short-iso",
                              "--since", start.strftime("%Y-%m-%d %H:%M:%S") + " UTC"], timeout=20, ctx=ctx)
        if rc == 0:
            sources.append("journalctl -k")
            events = parse_oom_lines(ctx, apps, out.splitlines(), start, end)
        else:
            ctx.note("Kernel logs (kern.log/syslog/journal) not readable - OOM events could not be checked (run as root).")
    by_owner = {}
    for e in events:
        o = by_owner.setdefault((e["owner_kind"], e["owner"]), {"kind": e["owner_kind"], "owner": e["owner"], "kills": 0,
                                                                "max_rss_mb": 0.0, "processes": Counter(), "last": ""})
        o["kills"] += 1
        o["max_rss_mb"] = max(o["max_rss_mb"], e["rss_mb"] or 0)
        o["processes"][e["process"]] += 1
        o["last"] = max(o["last"], e["time"])
    owners = sorted(by_owner.values(), key=lambda x: (-x["kills"], -x["max_rss_mb"]))
    triggers = Counter(e["trigger"] for e in events if e["trigger"])
    return {"events": events, "sources": sources, "by_process": Counter(e["process"] for e in events).most_common(),
            "by_owner": owners, "triggers": triggers.most_common(5),
            "memcg_kills": sum(1 for e in events if e["memcg"])}


# ----------------------------------------------------------------------------
# Bot identification & verification
# ----------------------------------------------------------------------------
# (regex on User-Agent, display name, category, DNS suffixes for verification or None)
# Categories: search | seo | ai | monitor | social | automation | other-bot
BOT_SIGNATURES = [
    (r"googlebot|google-inspectiontool|googleother|adsbot-google|mediapartners-google|storebot-google", "Googlebot", "search",
     (".googlebot.com", ".google.com", ".googleusercontent.com")),
    (r"bingbot|msnbot|bingpreview|adidxbot", "Bingbot", "search", (".search.msn.com",)),
    (r"applebot(?!-extended)", "Applebot", "search", (".applebot.apple.com",)),
    (r"yandex(?:bot|images|mobilebot|metrika|accessibilitybot|renderresourcesbot)", "YandexBot", "search",
     (".yandex.ru", ".yandex.net", ".yandex.com")),
    (r"baiduspider", "Baiduspider", "search", (".baidu.com", ".baidu.jp")),
    (r"petalbot", "PetalBot", "search", (".petalsearch.com", ".aspiegel.com")),
    (r"duckduckbot|duckassistbot", "DuckDuckBot", "search", None),
    (r"seznambot", "SeznamBot", "search", (".seznam.cz",)),
    (r"ahrefs(?:bot|siteaudit)", "AhrefsBot", "seo", (".ahrefs.com", ".ahrefs.net")),
    (r"semrushbot|siteauditbot|splitsignalbot", "SemrushBot", "seo", (".semrush.com",)),
    (r"mj12bot", "MJ12bot", "seo", None),
    (r"dotbot", "DotBot", "seo", None),
    (r"blexbot", "BLEXBot", "seo", None),
    (r"dataforseobot", "DataForSeoBot", "seo", None),
    (r"barkrowler", "Barkrowler", "seo", None),
    (r"serpstatbot", "SerpstatBot", "seo", None),
    (r"screaming frog", "Screaming Frog", "seo", None),
    (r"rogerbot|moz\.com", "Moz rogerbot", "seo", None),
    (r"megaindex|seokicks|linkdexbot|seekport|sistrix|oncrawl|lumar|deepcrawl|ryte", "SEO crawler (other)", "seo", None),
    (r"gptbot", "GPTBot (OpenAI)", "ai", None),
    (r"chatgpt-user|oai-searchbot", "ChatGPT-User/OAI-SearchBot", "ai", None),
    (r"claudebot|claude-web|claude-user|claude-searchbot|anthropic-ai", "ClaudeBot (Anthropic)", "ai", None),
    (r"perplexitybot|perplexity-user", "PerplexityBot", "ai", None),
    (r"bytespider", "Bytespider (ByteDance)", "ai", None),
    (r"ccbot", "CCBot (Common Crawl)", "ai", None),
    (r"amazonbot", "Amazonbot", "ai", None),
    (r"meta-externalagent|meta-externalfetcher|facebookbot", "Meta AI crawler", "ai", None),
    (r"cohere-ai|cohere-training", "Cohere", "ai", None),
    (r"diffbot", "Diffbot", "ai", None),
    (r"youbot|imagesiftbot|timpibot|pangubot|kangaroo bot|omgili|ai2bot|duckassist|mistralai-user", "AI crawler (other)", "ai", None),
    (r"facebookexternalhit|facebookcatalog", "Facebook preview", "social", None),
    (r"twitterbot|linkedinbot|slackbot|whatsapp|telegrambot|discordbot|pinterestbot|skypeuripreview|redditbot", "Social preview bot", "social", None),
    (r"uptimerobot", "UptimeRobot", "monitor", None),
    (r"pingdom", "Pingdom", "monitor", None),
    (r"statuscake|site24x7|betteruptime|better uptime|hetrixtools|freshping|uptime-kuma|nodeping|updown\.io|datadog|newrelicpinger|monitis", "Uptime monitor", "monitor", None),
    (r"jetpack", "Jetpack", "monitor", None),
    (r"gtmetrix|chrome-lighthouse|pagespeed|webpagetest", "Performance tester", "monitor", None),
    (r"wordpress/\d", "WordPress loopback/cron", "automation", None),
    (r"woocommerce", "WooCommerce webhook/API client", "automation", None),
    (r"headlesschrome|phantomjs|puppeteer|playwright|selenium|chromedriver", "Headless browser", "automation", None),
    (r"python-requests|python-urllib|aiohttp|httpx|scrapy", "Python script/scraper", "automation", None),
    (r"curl/", "curl", "automation", None),
    (r"wget/", "wget", "automation", None),
    (r"go-http-client", "Go HTTP client", "automation", None),
    (r"okhttp|java/|apache-httpclient|jakarta", "Java/Android HTTP client", "automation", None),
    (r"node-fetch|axios|undici|got \(|\bnode/\d", "Node.js HTTP client", "automation", None),
    (r"guzzlehttp|php/\d", "PHP HTTP client", "automation", None),
    (r"libwww-perl|lwp::", "Perl script", "automation", None),
    (r"masscan|zgrab|nmap|nikto|sqlmap|wpscan|nuclei|censysinspect|expanse|internet-measurement|paloalto", "Vulnerability scanner", "automation", None),
]
BOT_RES = [(re.compile(rx, re.I), name, cat, dns) for rx, name, cat, dns in BOT_SIGNATURES]
GENERIC_BOT_RE = re.compile(r"([A-Za-z][A-Za-z0-9_.-]*(?:bot|crawler|spider|scraper)[A-Za-z0-9_.-]*)", re.I)
BOT_CATEGORY_LABEL = {
    "search": "Search engine", "seo": "Commercial SEO crawler", "ai": "AI crawler", "monitor": "Monitoring",
    "social": "Social preview", "automation": "Automated client", "other-bot": "Other bot",
    "suspicious": "Unknown / suspicious",
}
_bot_cache: dict = {}


def identify_bot(ua: str):
    """Return (name, category, dns_suffixes) or None for browser-like traffic."""
    hit = _bot_cache.get(ua)
    if hit is not None or ua in _bot_cache:
        return hit
    res = None
    if not ua or ua == "-":
        res = ("(empty User-Agent)", "suspicious", None)
    else:
        for rx, name, cat, dns in BOT_RES:
            if rx.search(ua):
                res = (name, cat, dns)
                break
        if res is None:
            m = GENERIC_BOT_RE.search(ua)
            if m and "cubot" not in ua.lower():           # Cubot is a phone brand
                res = (trunc(m.group(1), 30), "other-bot", None)
    if len(_bot_cache) < 50000:
        _bot_cache[ua] = res
    return res


class BotVerifier:
    """Reverse+forward DNS verification of claimed search-engine bots (bounded, with timeouts)."""

    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.enabled = not ctx.args.no_dns_verify
        self.budget = ctx.args.dns_verify_max
        self.cache: dict[str, tuple[str, str]] = {}

    @staticmethod
    def _lookup(ip: str):
        host = socket.gethostbyaddr(ip)[0].lower().rstrip(".")
        fwd = socket.gethostbyname_ex(host)[2] if ":" not in ip else \
            [ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET6)]
        return host, fwd

    def verify(self, bot: str, suffixes, ips: list[str]) -> dict:
        res = {"verified": 0, "failed": 0, "unknown": 0, "checked": [], "status": "unverifiable"}
        if not suffixes:
            return res
        if not self.enabled:
            res["status"] = "not checked (--no-dns-verify)"
            return res
        todo = [ip for ip in ips if ip not in self.cache][: max(0, self.budget)]
        if todo:
            from concurrent.futures import ThreadPoolExecutor
            ex = ThreadPoolExecutor(max_workers=8)
            futs = {ip: ex.submit(self._lookup, ip) for ip in todo}
            self.budget -= len(todo)
            for ip, fu in futs.items():
                try:
                    host, fwd = fu.result(timeout=4)
                    ok = host.endswith(tuple(suffixes)) and ip in fwd
                    self.cache[ip] = ("verified" if ok else "failed", host)
                except socket.herror:                       # no PTR record: definitive
                    self.cache[ip] = ("failed-no-ptr", "")
                except socket.gaierror as exc:              # forward lookup: only NONAME is definitive
                    definitive = getattr(exc, "errno", None) in (socket.EAI_NONAME, getattr(socket, "EAI_NODATA", -999))
                    self.cache[ip] = ("failed-no-forward" if definitive else "unknown-dns-error", "")
                except Exception:   # noqa: BLE001 - timeout / resolver unavailable: NOT evidence of impersonation
                    self.cache[ip] = ("unknown-timeout", "")
            ex.shutdown(wait=False)
        for ip in ips:
            st, host = self.cache.get(ip, ("unknown", ""))
            if st == "verified":
                res["verified"] += 1
            elif st.startswith("failed"):
                res["failed"] += 1
            else:
                res["unknown"] += 1
            res["checked"].append({"ip": ip, "result": st, "host": host or "-"})
        if res["verified"] and not res["failed"]:
            res["status"] = "verified"
        elif res["failed"] and not res["verified"]:
            res["status"] = "IMPERSONATION (DNS verification failed)"
        elif res["failed"]:
            res["status"] = "partially verified - some IPs impersonate"
        elif res["unknown"] and self.budget > 0:
            res["status"] = "inconclusive (DNS lookups timed out/failed)"
        else:
            res["status"] = "unchecked (DNS budget exhausted)"
        return res


# ----------------------------------------------------------------------------
# Traffic analysis (backend = requests that passed Varnish to Apache/PHP)
# ----------------------------------------------------------------------------
CHROME_DAYS_PER_MAJOR = 30.5     # Chrome stable ships a new major roughly every 4 weeks (126 = 2024-06-11, 142 = 2025-10-28)
CHROME_CHANNEL_LEAD = 3          # Beta/Dev/Canary run up to 3 majors ahead of stable - not "non-existent"


def estimate_latest_chrome(now: datetime) -> int:
    return 126 + max(0, int((now - datetime(2024, 6, 11)).days / CHROME_DAYS_PER_MAJOR))


def ua_class(ua: str) -> str:
    u = ua.lower()
    if not ua or ua == "-":
        return "empty"
    if any(m in u for m in UPTIME_MARKERS):
        return "monitor"
    if any(m in u for m in GOOD_BOT_MARKERS):
        return "search-bot"
    if any(m in u for m in BOT_UA_MARKERS):
        return "bot/tool"
    if "mozilla" in u or "opera" in u:
        return "browser"
    return "other"


def subnet_of(ip: str) -> str | None:
    try:
        a = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))
    except ValueError:
        return None


def analyze_traffic(ctx: Ctx, app: dict, start, end) -> dict:
    src = "backend"
    files = files_for_window(app["backend_logs"], start)
    if not app["backend_logs"]:
        src = "frontend"
        files = files_for_window(app["frontend_logs"], start)
    res = {"source": src, "files": [f.name for f in files], "total": 0}
    if not files:
        return res
    latest_chrome = ctx.args.chrome_latest_major or estimate_latest_chrome(utcnow())
    ips, uas, urls, status, cats, ua_cls = Counter(), Counter(), Counter(), Counter(), Counter(), Counter()
    per_min, per_sec = Counter(), Counter()
    subnets = Counter()
    ip_cats = defaultdict(Counter)
    chrome_bad = headless = query = login_post = xmlrpc_post = 0
    ua_ips = defaultdict(set)
    unparsed = 0
    bots: dict[str, dict] = {}
    ip_err = Counter()
    err5_urls = Counter()
    store_api = 0
    for f in files:
        for line in iter_lines(f, start, access_line_ts):
            m = ACCESS_RE.match(line)
            if not m:
                if line.strip():
                    unparsed += 1
                continue
            ts = make_ts(m["y"], m["mon"], m["d"], m["h"], m["mi"], m["s"], m["tz"])
            if not in_window(ts, start, end):
                continue
            res["total"] += 1
            ip, uri, ua, method = m["ip"], m["uri"], (m["ua"] or "-"), m["method"]
            ips[ip] += 1
            status[m["status"]] += 1
            path = uri.split("?", 1)[0]
            urls[trunc(path, 100)] += 1
            if "?" in uri:
                query += 1
            c = classify_uri(uri)
            cats[c] += 1
            ip_cats[ip][c] += 1 if len(ip_cats) < 200000 else 0
            if c == "wp-login" and method == "POST":
                login_post += 1
            if c == "xmlrpc" and method == "POST":
                xmlrpc_post += 1
            uc = ua_class(ua)
            ua_cls[uc] += 1
            uas[trunc(ua, 110)] += 1
            if len(ua_ips) < 20000 or ua in ua_ips:
                if len(ua_ips[ua]) < 5000:
                    ua_ips[ua].add(ip)
            spoofed = False
            cm = CHROME_RE.search(ua)
            if cm:
                v = int(cm.group(1))
                if v > latest_chrome + CHROME_CHANNEL_LEAD:
                    chrome_bad += 1
                    spoofed = "future"
                elif v <= latest_chrome - ctx.args.chrome_obsolete_margin:
                    chrome_bad += 1
                    spoofed = "outdated"
                if "headless" in ua.lower():
                    headless += 1
            minute = ts.replace(second=0)
            st = m["status"]
            if st in ("403", "404"):
                ip_err[ip] += 1
            elif st[0] == "5":
                err5_urls[(st, trunc(path, 80))] += 1
            if "/wp-json/wc/store" in path or "rest_route=/wc/store" in uri:
                store_api += 1
            bot = identify_bot(ua)
            if bot is None and spoofed and uc == "browser":
                bot = ((f"Future Chrome UA (> v{latest_chrome + CHROME_CHANNEL_LEAD})", "suspicious", None) if spoofed == "future"
                       else (f"Outdated Chrome UA (<= v{latest_chrome - ctx.args.chrome_obsolete_margin})", "suspicious", None))
            if bot:
                b = bots.get(bot[0])
                if b is None:
                    b = bots[bot[0]] = {"name": bot[0], "category": bot[1], "dns": bot[2], "requests": 0, "dynamic": 0,
                                        "ips": Counter(), "urls": Counter(), "status": Counter(), "per_min": Counter(),
                                        "cats": Counter(), "ua_sample": trunc(ua, 120)}
                b["requests"] += 1
                if c != "static":
                    b["dynamic"] += 1
                if len(b["ips"]) < 20000 or ip in b["ips"]:
                    b["ips"][ip] += 1
                if len(b["urls"]) < 5000 or path in b["urls"]:
                    b["urls"][trunc(path, 90)] += 1
                b["status"][st] += 1
                b["per_min"][minute] += 1
                b["cats"][c] += 1
            per_min[minute] += 1
            per_sec[ts] += 1 if len(per_sec) < 400000 else 0
    total = res["total"]
    res["unparsed"] = unparsed
    if not total:
        return res
    win_min = max((end - start).total_seconds() / 60, 1) if (end and start) else max(1, len(per_min))
    bot_rows = []
    for b in sorted(bots.values(), key=lambda x: -x["requests"]):
        n = b["requests"]
        bot_rows.append({
            "name": b["name"], "category": b["category"], "dns": list(b["dns"]) if b["dns"] else None,
            "requests": n, "pct": pct(n, total), "rpm": n / win_min,
            "peak_rpm": max(b["per_min"].values()) if b["per_min"] else 0,
            "unique_ips": len(b["ips"]), "top_ips": b["ips"].most_common(5),
            "top_urls": b["urls"].most_common(5), "status": b["status"].most_common(6),
            "dynamic": b["dynamic"], "static": n - b["dynamic"], "cats": dict(b["cats"]),
            "err_4xx": sum(v for k, v in b["status"].items() if k.startswith("4")),
            "ua_sample": b["ua_sample"], "all_ips": dict(b["ips"].most_common(2000)), "_per_min": dict(b["per_min"]),
        })
    res["bots"] = bot_rows
    res["_ip_totals"] = {ip: ips[ip] for b in bot_rows for ip in b["all_ips"]}
    res["bot_requests"] = sum(b["requests"] for b in bot_rows)
    res["bot_dynamic"] = sum(b["dynamic"] for b in bot_rows)
    res["bot_by_category"] = Counter()
    for b in bot_rows:
        res["bot_by_category"][b["category"]] += b["requests"]
    res["bot_by_category"] = res["bot_by_category"].most_common()
    res["store_api"] = store_api
    res["_per_min"] = dict(per_min)
    res["err_403"] = status.get("403", 0)
    res["err_404"] = status.get("404", 0)
    res["top_err_ips"] = ip_err.most_common(3)
    res["http_5xx"] = [{"status": st, "path": pth, "count": c} for (st, pth), c in err5_urls.most_common(10)]
    adm = Counter({ip: c["wp-admin"] + c["admin-ajax"] for ip, c in ip_cats.items() if c.get("wp-admin") or c.get("admin-ajax")})
    res["top_admin_ip"] = adm.most_common(1)[0] if adm else None
    for ip, n in ips.items():
        sn = subnet_of(ip)
        if sn:
            subnets[sn] += n
    minutes = (end - start).total_seconds() / 60 if (end and start) else max(1, len(per_min))
    active = len(per_min)
    avg_rpm = total / max(minutes, 1)
    peak_min, peak_rpm = max(per_min.items(), key=lambda kv: kv[1])
    dynamic = total - cats.get("static", 0)
    res.update({
        "unique_ips": len(ips), "avg_rpm": avg_rpm, "avg_rps": avg_rpm / 60,
        "peak_rpm": peak_rpm, "peak_rpm_at": peak_min.strftime("%H:%M"),
        "peak_rps": max(per_sec.values()) if per_sec else 0,
        "active_minutes": active, "spike_ratio": (peak_rpm / avg_rpm) if avg_rpm else 0,
        "static": cats.get("static", 0), "dynamic": dynamic, "categories": cats.most_common(),
        "status": sorted(status.items()), "ua_classes": ua_cls.most_common(),
        "errors_4xx": sum(v for k, v in status.items() if k.startswith("4")),
        "errors_5xx": sum(v for k, v in status.items() if k.startswith("5")),
        "query_pct": pct(query, total), "login_post": login_post, "xmlrpc_post": xmlrpc_post,
        "chrome_suspicious": chrome_bad, "headless": headless,
        "top_ips": [{"ip": ip, "requests": n, "pct": pct(n, total),
                     "top_target": (ip_cats[ip].most_common(1)[0][0] if ip_cats[ip] else "-")}
                    for ip, n in ips.most_common(10)],
        "top_subnets": [{"subnet": s, "requests": n, "pct": pct(n, total)} for s, n in subnets.most_common(5)],
        "top_uas": [{"ua": u, "requests": n, "pct": pct(n, total), "class": ua_class(u),
                     "ips": len(ua_ips.get(u, ()))} for u, n in uas.most_common(8)],
        "top_urls": [{"url": u, "requests": n, "pct": pct(n, total)} for u, n in urls.most_common(10)],
    })
    # Frontend (nginx) totals give the full picture incl. Varnish/static hits.
    if src == "backend" and app["frontend_logs"]:
        ftotal, fbots = 0, Counter()
        for f in files_for_window(app["frontend_logs"], start):
            for line in iter_lines(f, start, access_line_ts):
                if not in_window(access_line_ts(line), start, end):
                    continue
                ftotal += 1
                q = line.rfind('"', 0, len(line) - 1)
                fua = line[q + 1:-1] if q > 0 and line.endswith('"') else "-"
                fb = identify_bot(fua)
                if fb:
                    fbots[fb[0]] += 1
        res["frontend_total"] = ftotal
        for b in res["bots"]:
            b["frontend"] = fbots.get(b["name"], 0)
    return res


def traffic_signals(t: dict) -> list[dict]:
    """Suspicious-traffic indicators. Each is evidence only; verdicts need several."""
    sig = []
    total = t.get("total", 0)
    if total < 200:
        return sig
    # Traffic from identified, non-impersonated crawlers is judged by the bot analysis, not the attack heuristics.
    named_ips, named_subnets = set(), Counter()
    for b in t.get("bots", []):
        if b["category"] in ("search", "seo", "ai", "monitor", "social") and not b.get("impersonation"):
            for ip, n in b["top_ips"]:
                named_ips.add(ip)
            named_subnets.update({subnet_of(ip): n for ip, n in b["top_ips"]})
    top_is_named = bool(t["top_ips"]) and t["top_ips"][0]["ip"] in named_ips
    if t["top_ips"] and t["top_ips"][0]["pct"] >= 25 and t["top_ips"][0]["requests"] >= 300 and not top_is_named:
        ip = t["top_ips"][0]
        sig.append({"key": "dominant_ip", "text": f"Single IP {ip['ip']} sent {ip['requests']:,} requests "
                    f"({ip['pct']:.1f}% of backend traffic), mostly '{ip['top_target']}'"})
    top_ip_n = t["top_ips"][0]["requests"] if t["top_ips"] else 0
    sn_named = t["top_subnets"] and named_subnets.get(t["top_subnets"][0]["subnet"], 0) > 0
    if t["top_subnets"] and t["top_subnets"][0]["pct"] >= 40 and t["top_subnets"][0]["requests"] >= 500 and \
            t["top_subnets"][0]["requests"] - top_ip_n >= 0.2 * total and not sn_named:
        s = t["top_subnets"][0]
        sig.append({"key": "dominant_subnet", "text": f"Subnet {s['subnet']} sent {s['requests']:,} requests ({s['pct']:.1f}%)"})
    if t["spike_ratio"] >= 6 and t["peak_rpm"] >= 120:
        sig.append({"key": "burst", "text": f"Burst: {t['peak_rpm']:,} req/min at {t['peak_rpm_at']} UTC vs "
                    f"{t['avg_rpm']:.0f} req/min average ({t['spike_ratio']:.1f}x)"})
    if t["login_post"] >= 100:
        sig.append({"key": "login_bruteforce", "text": f"{t['login_post']:,} POST requests to wp-login.php"})
    if t["xmlrpc_post"] >= 100:
        sig.append({"key": "xmlrpc_abuse", "text": f"{t['xmlrpc_post']:,} POST requests to xmlrpc.php"})
    bc = dict(t.get("bot_by_category", []))
    unnamed = bc.get("automation", 0) + bc.get("other-bot", 0) + bc.get("suspicious", 0)
    if pct(unnamed, total) >= 40:
        sig.append({"key": "bot_share", "text": f"{pct(unnamed, total):.0f}% of requests come from unidentified bots, scripts or "
                    "empty/spoofed User-Agents"})
    if pct(t["chrome_suspicious"] + t["headless"], total) >= 20:
        sig.append({"key": "spoofed_ua", "text": f"{t['chrome_suspicious'] + t['headless']:,} requests use obsolete/non-existent "
                    "Chrome versions or HeadlessChrome (spoofed UA indicator)"})
    for u in t["top_uas"][:3]:
        cm = CHROME_RE.search(u["ua"])
        odd_browser = u["class"] == "browser" and cm and int(cm.group(1)) < 100
        if u["pct"] >= 30 and u["ips"] >= 50 and (u["class"] in ("other", "empty") or odd_browser):
            sig.append({"key": "distributed_same_ua", "text": f"{u['pct']:.0f}% of requests share one User-Agent across "
                        f"{u['ips']:,} IPs (distributed client indicator): {trunc(u['ua'], 60)}"})
            break
    errs = t.get("err_403", 0) + t.get("err_404", 0)
    if errs >= 300 and pct(errs, total) >= 20:
        ip_e = t.get("top_err_ips") or []
        sig.append({"key": "error_scan", "text": f"{errs:,} 403/404 responses ({pct(errs, total):.0f}%)"
                    + (f"; top source {ip_e[0][0]} ({ip_e[0][1]:,})" if ip_e else "") + " - scanning/probing indicator"})
    adm = t.get("top_admin_ip")
    if adm and adm[1] >= 300:
        sig.append({"key": "admin_hammer", "text": f"{adm[0]} made {adm[1]:,} wp-admin/admin-ajax requests"})
    cats = dict(t["categories"])
    rest = cats.get("rest-api", 0) + cats.get("wc-rest", 0)
    if rest >= 2000 and pct(rest, total) >= 40:
        sig.append({"key": "rest_heavy", "text": f"{rest:,} WordPress REST API requests ({pct(rest, total):.0f}% of backend traffic)"})
    if t.get("store_api", 0) >= 1000:
        sig.append({"key": "store_api", "text": f"{t['store_api']:,} WooCommerce Store API requests (/wp-json/wc/store)"})
    for b in t.get("bots", []):
        if b.get("impersonation") and b["requests"] >= 50:
            bad = [c for c in b["verification"]["checked"] if c["result"].startswith("failed")]
            sig.append({"key": "impersonation", "text": f"{b['requests']:,} requests claim to be {b['name']} but "
                        f"{len(bad)} of {len(b['verification']['checked'])} checked IPs fail reverse/forward DNS "
                        f"(e.g. {bad[0]['ip']} -> {bad[0]['host'] or 'no PTR'})"})
            break
    win_min = max(t.get("active_minutes") or 1, 1)
    if t["top_ips"] and t["top_ips"][0]["requests"] / win_min >= 60 and not top_is_named and \
            not any(x["key"] == "dominant_ip" for x in sig):
        ip = t["top_ips"][0]
        sig.append({"key": "ip_rate", "text": f"{ip['ip']} averaged {ip['requests'] / win_min:.0f} req/min over active minutes"})
    if t["query_pct"] >= 60 and t["dynamic"] >= 1000:
        sig.append({"key": "cache_bypass", "text": f"{t['query_pct']:.0f}% of requests carry query strings (possible cache-bypass)"})
    return sig


# ----------------------------------------------------------------------------
# MySQL / MariaDB
# ----------------------------------------------------------------------------
class MySQL:
    STATUS_KEYS = ("Threads_connected", "Threads_running", "Max_used_connections", "Questions", "Slow_queries",
                   "Created_tmp_tables", "Created_tmp_disk_tables", "Select_full_join", "Select_scan",
                   "Sort_merge_passes", "Innodb_row_lock_waits", "Innodb_row_lock_time", "Innodb_deadlocks",
                   "Aborted_connects", "Uptime", "Innodb_buffer_pool_reads", "Innodb_buffer_pool_read_requests",
                   "Table_locks_waited", "Connection_errors_max_connections")
    VAR_KEYS = ("max_connections", "slow_query_log", "slow_query_log_file", "long_query_time", "datadir",
                "innodb_buffer_pool_size", "tmp_table_size", "max_heap_table_size", "log_output", "version")

    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.bin = shutil.which("mariadb") or shutil.which("mysql")
        self.base = None
        self.error = ""
        if not self.bin:
            self.error = "mysql/mariadb client not found"
            return
        base = [self.bin, "-N", "-B", "--connect-timeout=5"]
        cnf = "/root/.my.cnf"
        if os.access(cnf, os.R_OK):
            base.insert(1, f"--defaults-extra-file={cnf}")
        rc, out, err = run_cmd(base + ["-e", "SELECT VERSION()"], timeout=10)
        if rc == 0:
            self.base = base
            self.version = out.strip()
        else:
            self.error = "cannot connect (" + trunc(re.sub(r"'[^']*'@", "'***'@", err.strip().splitlines()[-1] if err.strip() else "unknown"), 90) + ")"

    @property
    def ok(self):
        return self.base is not None

    def q(self, sql: str, db: str | None = None, timeout: float = 15) -> list[list[str]] | None:
        if not self.ok:
            return None
        cmd = self.base + ([db] if db else []) + ["-e", sql]
        rc, out, err = run_cmd(cmd, timeout=timeout, ctx=self.ctx)
        if rc != 0:
            self.ctx.debug(f"mysql query failed: {trunc(err.strip(), 160)}")
            return None
        return [line.split("\t") for line in out.splitlines()]

    def kv(self, sql: str, keys) -> dict:
        rows = self.q(sql) or []
        return {r[0]: r[1] for r in rows if len(r) >= 2 and r[0] in keys}


def mysql_collect(ctx: Ctx, my: MySQL) -> dict:
    res = {"available": my.ok, "error": my.error}
    if not my.ok:
        ctx.note(f"MySQL/MariaDB data unavailable: {my.error}. Run as root (uses /root/.my.cnf).")
        return res
    res["version"] = my.version
    res["vars"] = my.kv("SHOW GLOBAL VARIABLES", MySQL.VAR_KEYS)
    res["status_start"] = my.kv("SHOW GLOBAL STATUS", MySQL.STATUS_KEYS)
    res["t_start"] = time.time()
    res["proc_samples"] = []
    return res


def mysql_sample(my: MySQL, res: dict):
    rows = my.q("SELECT ID,USER,IFNULL(DB,''),COMMAND,TIME,IFNULL(STATE,''),LEFT(IFNULL(INFO,''),2000) "
                "FROM information_schema.PROCESSLIST WHERE ID<>CONNECTION_ID()", timeout=8)
    if rows is None:
        return
    res["proc_samples"].append(rows)


def mysql_finish(ctx: Ctx, my: MySQL, res: dict, db_to_app: dict):
    if not my.ok:
        return
    end = my.kv("SHOW GLOBAL STATUS", MySQL.STATUS_KEYS)
    dt = max(time.time() - res["t_start"], 1)
    s0 = res["status_start"]

    def rate(k):
        try:
            return (int(end.get(k, 0)) - int(s0.get(k, 0))) / dt
        except ValueError:
            return 0.0
    res["status_end"] = end
    res["rates"] = {k: rate(k) for k in ("Questions", "Slow_queries", "Created_tmp_disk_tables", "Select_full_join",
                                         "Innodb_row_lock_waits", "Select_scan")}
    # Process list aggregation across samples
    per_db_conn = defaultdict(list)
    per_db_running = defaultdict(list)
    long_running = {}
    for rows in res["proc_samples"]:
        conn, running = Counter(), Counter()
        for r in rows:
            if len(r) < 7:
                continue
            _id, user, db, cmd, tsec, state, info = r[:7]
            db = db or "(none)"
            conn[db] += 1
            if cmd not in ("Sleep", "Daemon", "Binlog Dump") and info and info != "NULL":
                running[db] += 1
                try:
                    secs = int(tsec)
                except ValueError:
                    secs = 0
                if secs >= ctx.args.long_query_seconds:
                    q = info.replace("\\n", " ").replace("\\t", " ")
                    long_running[_id] = {"db": db, "app": db_to_app.get(db, ""), "time_s": secs, "state": state,
                                         "user": user, "query": sql_fingerprint(q, 140),
                                         "dump": "SQL_NO_CACHE" in q and "40001" in q}
        for db in set(conn) | set(per_db_conn):
            per_db_conn[db].append(conn.get(db, 0))
            per_db_running[db].append(running.get(db, 0))
    res["per_db"] = {db: {"conn_avg": sum(v) / len(v), "conn_peak": max(v),
                          "running_avg": sum(per_db_running[db]) / len(per_db_running[db]),
                          "running_peak": max(per_db_running[db]), "app": db_to_app.get(db, "")}
                     for db, v in per_db_conn.items() if v}
    res["long_running"] = sorted(long_running.values(), key=lambda x: -x["time_s"])[:15]
    trx = my.q("SELECT COUNT(*), IFNULL(MAX(TIMESTAMPDIFF(SECOND,trx_wait_started,NOW())),0) FROM "
               "information_schema.INNODB_TRX WHERE trx_state='LOCK WAIT'")
    if trx and trx[0]:
        res["lock_waits_now"] = int(trx[0][0])
        res["lock_wait_max_s"] = int(trx[0][1] or 0)
    st = my.q("SHOW ENGINE INNODB STATUS", timeout=15)
    if st:
        txt = "\t".join("\t".join(r) for r in st).replace("\\n", "\n")
        m = re.search(r"LATEST DETECTED DEADLOCK\n-+\n(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", txt)
        if m:
            res["last_deadlock"] = m.group(1)
            tables = sorted(set(re.findall(r"table `([^`]+)`\.`([^`]+)`", txt[m.start(): m.start() + 20000])))
            res["deadlock_tables"] = [f"{a}.{b}" for a, b in tables][:6]


SLOW_TS_RE = re.compile(r"^SET timestamp=(\d+)")
SLOW_TIME_ISO_RE = re.compile(r"^# Time:\s+(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
SLOW_TIME_OLD_RE = re.compile(r"^# Time:\s+(\d{2})(\d{2})(\d{2})\s+(\d{1,2}):(\d{2}):(\d{2})")
SLOW_USER_RE = re.compile(r"^# User@Host:\s*([^\[\s]+)")
SLOW_SCHEMA_RE = re.compile(r"Schema:\s*(\S+)")
SLOW_QT_RE = re.compile(r"^# Query_time:\s*([\d.]+)\s+Lock_time:\s*([\d.]+)\s+Rows_sent:\s*(\d+)\s+Rows_examined:\s*(\d+)")
SLOW_USE_RE = re.compile(r"^use\s+`?([^`;\s]+)`?;", re.I)


def slow_ts(line: str) -> datetime | None:
    m = SLOW_TS_RE.match(line)
    if m:
        return datetime.fromtimestamp(int(m.group(1)), timezone.utc).replace(tzinfo=None)
    m = SLOW_TIME_ISO_RE.match(line)
    if m:
        return make_ts(m.group(1), int(m.group(2)), m.group(3), m.group(4), m.group(5), m.group(6))
    return None


def analyze_mysql_slowlog(ctx: Ctx, my: MySQL, mres: dict, db_to_app: dict, start, end) -> dict:
    v = mres.get("vars", {})
    path = v.get("slow_query_log_file") or ""
    if path and not path.startswith("/"):
        path = os.path.join(v.get("datadir", "/var/lib/mysql"), path)
    candidates = [path] if path else []
    candidates += [p for p in ("/var/log/mysql/slow-query.log", "/var/log/mysql/mysql-slow.log") if p not in candidates]
    files, exists = [], False
    for c in candidates:
        if glob.glob(c + "*"):
            exists = True
            path = c
            files = files_for_window(c + "*", start)
            break
    res = {"file": path, "enabled": v.get("slow_query_log", "?"), "long_query_time": v.get("long_query_time", "?"),
           "total": 0, "by_db": {}, "fingerprints": [], "dump_queries": 0}
    if not files:
        if mres.get("available") and not exists:
            ctx.note(f"MySQL slow query log not found (slow_query_log={v.get('slow_query_log', '?')}).")
        return res
    if not any(os.access(f, os.R_OK) for f in files):
        ctx.note("MySQL slow query log is not readable (run as root).")
        return res
    fps = {}
    by_db = defaultdict(lambda: {"count": 0, "time": 0.0, "max": 0.0, "app": ""})
    samples_for_explain = {}
    for f in files:
        cur, sql, user, schema, ts = None, [], "", "", None

        def flush():
            nonlocal cur, sql
            if cur is None:
                return
            q = " ".join(sql).strip()
            cur_ts = cur.get("ts") or ts
            if q and in_window(cur_ts, start, end):
                db = cur["db"] or "(unknown)"
                dump = "SQL_NO_CACHE" in q and "/*!40001" in q
                if dump:
                    res["dump_queries"] += 1
                fp = sql_fingerprint(q)
                a = fps.setdefault((db, fp), {"db": db, "app": db_to_app.get(db, ""), "fingerprint": fp, "count": 0,
                                              "time": 0.0, "max": 0.0, "lock": 0.0, "rows_ex": 0, "rows_sent": 0,
                                              "dump": dump, "last": ""})
                a["count"] += 1
                a["time"] += cur["qt"]
                a["max"] = max(a["max"], cur["qt"])
                a["lock"] += cur["lt"]
                a["rows_ex"] += cur["re"]
                a["rows_sent"] += cur["rs"]
                a["last"] = cur_ts.strftime("%H:%M:%S") if cur_ts else ""
                if q.lstrip().upper().startswith("SELECT") and (db, fp) not in samples_for_explain:
                    samples_for_explain[(db, fp)] = q[:20000]      # kept in memory only, never printed
                d = by_db[db]
                if cur_ts:
                    d.setdefault("minutes", Counter())[cur_ts.replace(second=0)] += 1
                d["count"] += 1
                d["time"] += cur["qt"]
                d["max"] = max(d["max"], cur["qt"])
                d["app"] = db_to_app.get(db, "")
                res["total"] += 1
            cur, sql = None, []

        for line in iter_lines(f, start, slow_ts):
            if line.startswith("# Time:"):
                flush()
                ts = slow_ts(line)
                if ts is None:
                    m = SLOW_TIME_OLD_RE.match(line)
                    if m:
                        ts = make_ts(2000 + int(m.group(1)), int(m.group(2)), m.group(3), m.group(4), m.group(5), m.group(6))
                continue
            if line.startswith("# User@Host:"):
                flush()
                m = SLOW_USER_RE.match(line)
                user = m.group(1) if m else ""
                schema = ""
                continue
            if line.startswith("# Thread_id:") or line.startswith("# Schema:"):
                m = SLOW_SCHEMA_RE.search(line)
                schema = m.group(1) if m else schema
                continue
            m = SLOW_QT_RE.match(line)
            if m:
                flush()
                cur = {"qt": float(m.group(1)), "lt": float(m.group(2)), "rs": int(m.group(3)),
                       "re": int(m.group(4)), "db": schema or (user if user in db_to_app else ""), "ts": None}
                continue
            if line.startswith("#"):
                continue
            if cur is not None:
                mt = SLOW_TS_RE.match(line)
                if mt:
                    cur["ts"] = slow_ts(line)
                    continue
                mu = SLOW_USE_RE.match(line)
                if mu:
                    cur["db"] = mu.group(1)
                    continue
                if line.startswith(("/usr/sbin/", "Tcp port:", "Time ")) and not sql:
                    continue
                if len(sql) < 200:
                    sql.append(line.strip())
        flush()
    for a in fps.values():
        a["avg_rows_ex"] = a["rows_ex"] / a["count"]
        a["avg_rows_sent"] = a["rows_sent"] / a["count"]
        a["scan_ratio"] = a["rows_ex"] / max(a["rows_sent"], 1)
        a["scan_suspect"] = (not a["dump"]) and a["avg_rows_ex"] >= 50_000 and a["scan_ratio"] >= 100
    for a_ in fps.values():
        a_["avg"] = a_["time"] / a_["count"]
    allfp = sorted(fps.values(), key=lambda x: -x["time"])
    top = allfp[:15]
    res["fingerprints"] = allfp[:200]
    res["distinct_fingerprints"] = len(fps)
    res["by_db"] = dict(sorted(by_db.items(), key=lambda kv: -kv[1]["time"]))
    if ctx.args.explain and my.ok:
        for a in [x for x in top if x["scan_suspect"]][:3]:
            q = samples_for_explain.get((a["db"], a["fingerprint"]))
            if not q or a["db"] == "(unknown)":
                continue
            rows = my.q("EXPLAIN " + q, db=a["db"], timeout=10)
            if rows:
                plan = []
                for r in rows:
                    # id select_type table [partitions] type possible_keys key key_len ref rows ...
                    if len(r) >= 9:
                        off = 1 if len(r) >= 11 else 0
                        plan.append({"table": r[2], "type": r[3 + off], "key": r[5 + off], "rows": r[8 + off]})
                a["explain"] = plan
                a["explain_full_scan"] = any(p["type"] == "ALL" and p["key"] in ("NULL", "") for p in plan)
    return res


# ----------------------------------------------------------------------------
# Server health & shared services
# ----------------------------------------------------------------------------
def server_health(ctx: Ctx, sample: dict, history: dict | None, start, end) -> dict:
    s = sample["server"]
    h: dict = {"ncpu": NCPU}
    if s["cpu"]:
        def avg(k):
            return sum(c[k] for c in s["cpu"]) / len(s["cpu"])
        h["cpu_busy"] = 100 - avg("idle") - avg("iowait")
        h["cpu_busy_peak"] = max(100 - c["idle"] - c["iowait"] for c in s["cpu"])
        h["iowait"] = avg("iowait")
        h["steal"] = avg("steal")
        h["steal_peak"] = max(c["steal"] for c in s["cpu"])
    if s["load"]:
        h["load"] = s["load"][-1]
    mem = s["mem"][-1] if s["mem"] else {}
    if mem:
        tot = mem.get("MemTotal", 0)
        avail = mem.get("MemAvailable", mem.get("MemFree", 0) + mem.get("Cached", 0))
        h["mem_total_mb"] = tot / 1024
        h["mem_used_mb"] = (tot - avail) / 1024
        h["mem_used_pct"] = pct(tot - avail, tot)
        h["swap_total_mb"] = mem.get("SwapTotal", 0) / 1024
        h["swap_used_mb"] = (mem.get("SwapTotal", 0) - mem.get("SwapFree", 0)) / 1024
    h["psi"] = {k: read_pressure(k) for k in ("cpu", "memory", "io")}
    disks = defaultdict(list)
    for d in s["disk"]:
        disks[d["dev"]].append(d)
    h["disks"] = [{"dev": dev, "util": sum(x["util"] for x in v) / len(v), "util_peak": max(x["util"] for x in v),
                   "await_ms": sum(x["await_ms"] for x in v) / len(v), "iops": sum(x["iops"] for x in v) / len(v),
                   "mbps": sum(x["mbps"] for x in v) / len(v)} for dev, v in disks.items()]
    nets = defaultdict(list)
    for n in s["net"]:
        nets[n["dev"]].append(n)
    h["net"] = [{"dev": dev, "rx_mbps": sum(x["rx_mbps"] for x in v) / len(v), "tx_mbps": sum(x["tx_mbps"] for x in v) / len(v)}
                for dev, v in nets.items()]
    fs = []
    for mnt in ("/", "/home", "/var", "/var/lib/mysql", "/mnt", "/tmp"):
        try:
            st = os.statvfs(mnt)
        except OSError:
            continue
        total = st.f_blocks * st.f_frsize
        if not total:
            continue
        free = st.f_bavail * st.f_frsize
        key = (st.f_blocks, st.f_files)
        if any(f["_key"] == key for f in fs):
            continue
        fs.append({"_key": key, "mount": mnt, "size_gb": total / 1e9, "used_pct": pct(total - free, total),
                   "inode_pct": pct(st.f_files - st.f_favail, st.f_files) if st.f_files else 0.0})
    h["filesystems"] = [{k: v for k, v in f.items() if k != "_key"} for f in fs]
    h["history"] = history
    return h


def redis_info(ctx: Ctx) -> dict | None:
    if not shutil.which("redis-cli"):
        return None
    rc, out, err = run_cmd(["redis-cli", "-h", "127.0.0.1", "INFO", "memory"], timeout=5, ctx=ctx)
    if rc != 0 or "used_memory:" not in out:
        return {"error": "INFO not permitted (AUTH required or redis down)" if "NOAUTH" in out + err else trunc((out + err).strip(), 60)}
    kv = dict(line.split(":", 1) for line in out.splitlines() if ":" in line)
    res = {"used_mb": int(kv.get("used_memory", 0)) / 1048576, "rss_mb": int(kv.get("used_memory_rss", 0)) / 1048576,
           "maxmemory_mb": int(kv.get("maxmemory", 0)) / 1048576, "policy": kv.get("maxmemory_policy", "").strip(),
           "frag": float(kv.get("mem_fragmentation_ratio", 0) or 0)}
    rc, out, _ = run_cmd(["redis-cli", "-h", "127.0.0.1", "INFO", "stats"], timeout=5, ctx=ctx)
    kv = dict(line.split(":", 1) for line in out.splitlines() if ":" in line)
    res["evicted"] = int(kv.get("evicted_keys", 0) or 0)
    return res


def varnish_info(ctx: Ctx) -> dict | None:
    if not shutil.which("varnishstat"):
        return None
    rc, out, _ = run_cmd(["varnishstat", "-1", "-f", "MAIN.cache_hit", "-f", "MAIN.cache_miss", "-f", "MAIN.client_req",
                          "-f", "MAIN.n_lru_nuked"], timeout=8, ctx=ctx)
    if rc != 0:
        return None
    vals = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) >= 2 and p[1].isdigit():
            vals[p[0].split(".")[-1]] = int(p[1])
    hit, miss = vals.get("cache_hit", 0), vals.get("cache_miss", 0)
    return {"hit_ratio": pct(hit, hit + miss) if hit + miss else None, "lru_nuked": vals.get("n_lru_nuked", 0),
            "since": "service start"}


def label_bot(b: dict, verifier) -> None:
    """Set category_label; search engines are only 'verified' after reverse+forward DNS succeeds."""
    if b["category"] == "search":
        if b.get("dns"):
            b["verification"] = verifier.verify(b["name"], b["dns"], [ip for ip, _ in b["top_ips"]])
            st = b["verification"]["status"]
        else:
            st = "unverifiable"
        if st == "verified":
            b["category_label"] = "Search engine (verified)"
        elif st.startswith("IMPERSONATION"):
            b["category_label"] = "IMPERSONATION of " + b["name"]
            b["impersonation"] = True
        elif st.startswith("partially"):
            b["category_label"] = "Search engine (partly impersonated)"
            b["impersonation"] = True
        else:
            b["category_label"] = "Search engine (unverified)"
    else:
        b["category_label"] = BOT_CATEGORY_LABEL.get(b["category"], b["category"])


def bot_census(ctx: Ctx, apps: dict, start, end, verifier) -> dict:
    """Server-wide bot ranking across ALL applications (lightweight single pass per app)."""
    total, apps_scanned = 0, 0
    agg: dict[str, dict] = {}
    win_min = max((end - start).total_seconds() / 60, 1)
    for name, app in apps.items():
        files = files_for_window(app["backend_logs"] or app["frontend_logs"], start)
        if not files:
            continue
        apps_scanned += 1
        for f in files:
            for line in iter_lines(f, start, access_line_ts):
                m = ACCESS_RE.match(line)
                if not m:
                    continue
                ts = make_ts(m["y"], m["mon"], m["d"], m["h"], m["mi"], m["s"], m["tz"])
                if not in_window(ts, start, end):
                    continue
                total += 1
                bot = identify_bot(m["ua"] or "-")
                if not bot:
                    continue
                b = agg.get(bot[0])
                if b is None:
                    b = agg[bot[0]] = {"name": bot[0], "category": bot[1], "dns": bot[2], "requests": 0, "dynamic": 0,
                                       "apps": Counter(), "ips": Counter(), "urls": Counter(), "status": Counter(),
                                       "per_min": Counter()}
                b["requests"] += 1
                path = m["uri"].split("?", 1)[0]
                if classify_uri(m["uri"]) != "static":
                    b["dynamic"] += 1
                b["apps"][name] += 1
                if len(b["ips"]) < 20000 or m["ip"] in b["ips"]:
                    b["ips"][m["ip"]] += 1
                if len(b["urls"]) < 5000 or path in b["urls"]:
                    b["urls"][trunc(path, 80)] += 1
                b["status"][m["status"]] += 1
                b["per_min"][ts.replace(second=0)] += 1
    rows = []
    for b in sorted(agg.values(), key=lambda x: -x["requests"])[: ctx.args.server_bots_top]:
        row = {"name": b["name"], "category": b["category"], "dns": list(b["dns"]) if b["dns"] else None,
               "requests": b["requests"], "pct": pct(b["requests"], total), "rpm": b["requests"] / win_min,
               "peak_rpm": max(b["per_min"].values()) if b["per_min"] else 0, "unique_ips": len(b["ips"]),
               "top_ips": b["ips"].most_common(5), "top_urls": b["urls"].most_common(3),
               "status": b["status"].most_common(4), "dynamic": b["dynamic"], "static": b["requests"] - b["dynamic"],
               "apps": b["apps"].most_common(3), "app_count": len(b["apps"])}
        label_bot(row, verifier)
        rows.append(row)
    return {"total": total, "apps_scanned": apps_scanned, "bots": rows,
            "bot_requests": sum(b["requests"] for b in agg.values()), "distinct_bots": len(agg)}


def correlate_bots(ctx: Ctx, verifier, p: dict):
    """Verify claimed search bots and estimate each bot's PHP requests / CPU via client IP."""
    t, fa = p.get("traffic") or {}, p.get("fpm") or {}
    bots = t.get("bots") or []
    ip_stats, ip_tot = fa.get("_ip_stats") or {}, t.get("_ip_totals") or {}
    total_cpu = fa.get("cpu_s") or 0.0
    total_php = fa.get("requests") or 0
    for b in bots:
        label_bot(b, verifier)
        php_n = cpu = 0.0
        if ip_stats:
            for ip, n in b["all_ips"].items():
                st = ip_stats.get(ip)
                if not st:
                    continue
                share = n / max(ip_tot.get(ip, n), n)
                php_n += st[0] * share
                cpu += st[1] * share
        b["php_requests_est"] = round(php_n)
        b["php_cpu_s_est"] = round(cpu, 1)
        b["php_cpu_share"] = pct(cpu, total_cpu)
        b["php_req_share"] = pct(php_n, total_php)
        b.pop("all_ips", None)
    t.pop("_ip_totals", None)
    fa.pop("_ip_stats", None)
    t["bot_php_cpu_share"] = sum(b["php_cpu_share"] for b in bots)
    # Time correlation (co-occurrence, not attribution): bot share of backend traffic in stress minutes vs overall.
    app_min = t.get("_per_min") or {}
    bot_min = Counter()
    for b in bots:
        bot_min.update(b.get("_per_min") or {})
    overall = pct(sum(bot_min.values()), sum(app_min.values()))

    def share_in(minutes) -> tuple[float, int] | None:
        mins = [m for m in minutes if m in app_min]
        if not mins:
            return None
        return pct(sum(bot_min.get(m, 0) for m in mins), sum(app_min[m] for m in mins)), len(mins)
    corr = {"overall_bot_share": overall}
    if fa.get("_peak_min") is not None:
        pm = fa["_peak_min"]
        corr["php_peak"] = {"minute": pm.strftime("%H:%M"), "php_requests": (fa.get("_per_min") or {}).get(pm, 0),
                            "bot_share": pct(bot_min.get(pm, 0), app_min.get(pm, 0)) if app_min.get(pm) else None}
    if p.get("fpm_minutes"):
        corr["max_children"] = share_in(p["fpm_minutes"])
    if p.get("slow_minutes"):
        corr["slow_queries"] = share_in(p["slow_minutes"])
    t["bot_correlation"] = corr
    for b in bots:
        b.pop("_per_min", None)
    t.pop("_per_min", None)
    fa.pop("_per_min", None)
    fa.pop("_peak_min", None)


# ----------------------------------------------------------------------------
# Profiles & ranking
# ----------------------------------------------------------------------------
def build_profiles(ctx: Ctx, apps: dict, sample: dict, history: dict | None, fpm_quick: dict, window_s: float,
                   mem_total_mb: float) -> list[dict]:
    live = {o["owner"]: o for k, o in sample["owners"].items() if k[0] == "app"}
    hist = {k[1]: o for k, o in (history or {}).get("owners", {}).items() if k[0] == "app"} if history else {}
    total_php = sum(v["requests"] for v in fpm_quick.values()) or 0
    total_php_cpu = sum(v["cpu_s"] for v in fpm_quick.values()) or 0
    profiles = []
    for name, app in apps.items():
        lv, hv, fq = live.get(name, {}), hist.get(name), fpm_quick.get(name, {})
        fpm_cpu_pct = (fq.get("cpu_s", 0) / window_s * 100.0) if window_s else 0.0     # % of one core
        if hv:
            sustained, src = hv["cpu_avg"], "atop history"
        elif fq.get("requests"):
            sustained, src = fpm_cpu_pct, "PHP-FPM access log"
        else:
            sustained, src = lv.get("cpu_avg", 0.0), "live sampling"
        mem_now = lv.get("pss_mb") if lv.get("pss_mb") is not None else lv.get("rss_avg_mb", 0.0)
        mem_hist = hv["rss_avg_mb"] if hv else None
        mem_basis = mem_now or 0.0
        p = {
            "app": name, "domain": app.get("domain", ""), "type": app.get("type", ""), "app_dir": str(app["app_dir"]),
            "db": app.get("db_name") or name, "db_source": app.get("db_source") or "Cloudways convention (db = app id)",
            "aliases": app.get("aliases", []),
            "cpu_sustained": sustained, "cpu_source": src,
            "cpu_live_avg": lv.get("cpu_avg"), "cpu_live_peak": lv.get("cpu_peak"),
            "cpu_hist_avg": hv["cpu_avg"] if hv else None, "cpu_hist_peak": hv["cpu_peak"] if hv else None,
            "cpu_hist_peak_at": hv["cpu_peak_at"] if hv else "",
            "cpu_fpm_pct": fpm_cpu_pct if fq.get("requests") else None,
            "cpu_server_share": sustained / NCPU,
            "mem_mb": mem_now if lv else None, "mem_kind": "PSS" if lv.get("pss_mb") is not None else "RSS",
            "mem_peak_mb": lv.get("rss_peak_mb"), "mem_hist_avg": mem_hist, "mem_hist_peak": hv["rss_peak_mb"] if hv else None,
            "mem_pct": pct(mem_basis, mem_total_mb),
            "procs_peak": lv.get("procs_peak", 0), "busy_peak": lv.get("busy_peak", 0), "busy_avg": lv.get("busy_avg", 0),
            "proc_kinds": lv.get("kinds", {}), "long_cli": lv.get("long_cli", []),
            "top_procs": lv.get("top_procs", []), "long_busy": lv.get("long_busy", []), "busy_last": lv.get("busy_last", 0),
            "fpm_procs_last": sum(v for k, v in lv.get("kinds", {}).items() if k.startswith("fpm:")),
            "fpm_pss_mb": sum(x["mem_mb"] for x in lv.get("top_procs", []) if x["what"].startswith("fpm:")),
            "php_requests": fq.get("requests", 0), "php_cpu_s": fq.get("cpu_s", 0.0),
            "php_req_share": pct(fq.get("requests", 0), total_php), "php_cpu_share": pct(fq.get("cpu_s", 0), total_php_cpu),
            "cpu_ms_per_req": fq.get("cpu_ms_per_req"),
            "fpm_log_available": fq.get("available", False),
        }
        p["score"] = p["cpu_server_share"] + p["mem_pct"] * 0.6 + (lv.get("cpu_avg", 0) / NCPU) * 0.25
        profiles.append(p)
    profiles.sort(key=lambda x: -x["score"])
    return profiles


def resource_tags(p: dict, ctx: Ctx) -> list[str]:
    tags = []
    hi_cpu = p["cpu_server_share"] >= ctx.args.cpu_threshold
    hi_mem = p["mem_pct"] >= ctx.args.mem_threshold
    if hi_cpu and hi_mem:
        tags.append("High CPU + Memory")
    elif hi_cpu:
        tags.append("High CPU")
    elif hi_mem:
        tags.append("High Memory")
    mc = p.get("max_children")
    if mc and (p["busy_peak"] >= 0.8 * mc or p.get("fpm_hits", 0)):
        tags.append("Many FPM workers")
    if (p["php_cpu_share"] >= 25 and p["php_req_share"] and p["php_cpu_share"] / p["php_req_share"] >= 3) or \
            (p.get("cpu_ms_per_req") or 0) >= 500 and p["php_requests"] >= 20:
        tags.append("Low traffic / high cost")
    return tags or ["Normal"]


# ----------------------------------------------------------------------------
# Correlation & root-cause engine
# ----------------------------------------------------------------------------
CONF_ORDER = {"Confirmed": 0, "Likely": 1, "Suspected": 2, "Inconclusive": 3}


# (substring of finding text, recommended next action). First match wins.
NEXT_ACTIONS = [
    ("HIGH BOT TRAFFIC", "Review the flagged crawlers: rate-limit or block aggressive SEO/AI bots (Cloudflare bot rules, robots.txt); never block verified search engines - tune their crawl rate instead."),
    ("Elevated bot traffic", "Monitor the flagged crawlers; consider crawl-delay/rate limits for SEO/AI bots if PHP load grows."),
    ("static/cached content", "No PHP impact; only act if bandwidth or CDN cost is a concern."),
    ("Bot impersonation", "Treat as unverified automated traffic: rate-limit or block the listed IPs at Cloudflare/WAF; real search engines are unaffected."),
    ("High backend/PHP request volume", "Check cache hit ratio (Varnish/page cache) and whether the dynamic requests are bots or real users."),
    ("Application is a top consumer", "Confirm with the per-app process list and the CPU source shown; compare against the window average before acting."),
    ("proportional to legitimate PHP traffic", "Check whether resource pressure is sustained (atop history); if so evaluate upscaling, otherwise monitor peak hours."),
    ("High CPU cost per PHP request", "Profile the top CPU paths (New Relic/Xdebug/Query Monitor); review plugins, theme and custom code on those URLs."),
    ("disproportionate to traffic", "Profile the top CPU paths (New Relic/Xdebug/Query Monitor); review plugins, theme and custom code on those URLs."),
    ("non-web processes", "Identify the job from the command line; review its schedule and runtime with the application owner."),
    ("Background processes owned", "Identify the process from its command line and confirm with the customer whether it is expected."),
    ("high lifetime CPU", "Re-check during the customer's busy period; no action if it stays idle."),
    ("Slow WP-Cron", "Review the listed hooks (WP Crontrol) and their schedule; move heavy hooks to off-peak."),
    ("bot / application-layer attack", "Review the listed IPs/UAs/URLs manually; if abusive, apply Cloudflare/WAF rate limits or targeted blocks."),
    ("Isolated traffic anomaly", "No action on its own; re-check if it recurs alongside resource pressure."),
    ("worker exhaustion", "Find what keeps workers busy (slow paths, slow queries, external calls) before raising pm.max_children; check RAM headroom."),
    ("queued waiting for a free PHP-FPM worker", "Treat as worker saturation: reduce PHP execution time first; raise max_children only if RAM allows."),
    ("All PHP-FPM workers were busy", "Re-sample for longer (--minutes) and check max_children warnings in the FPM log."),
    ("concurrency reached pm.max_children", "Verify with a longer live sample; check for max_children warnings."),
    ("Long-running PHP requests", "Match the busy workers with slow-log traces and slow paths; check external API calls and DB waits."),
    ("terminated by request_terminate_timeout", "Review the listed scripts; they exceed the execution limit and fail for visitors."),
    ("Slow PHP execution", "Profile the slowest paths listed; check slow-log traces and slow queries for the same window."),
    ("slow-log traces", "Review the plugin/function in the trace (often external HTTP calls or heavy loops) with the developer."),
    ("High memory per PHP request", "Find the memory-heavy URLs listed; check memory_limit and per-worker RAM x max_children."),
    ("Recurring slow database queries", "Review the query fingerprints with the developer: indexes, autoload options, object cache (Redis)."),
    ("mysqldump/backup", "No app action; consider moving backup windows away from peak traffic."),
    ("full table scan", "Add an appropriate index or rewrite the query (developer)."),
    ("examines far more rows", "Re-run with --explain (read-only) to check the query plan before suggesting any index change."),
    ("database connections", "Check for connection leaks/persistent connections and slow queries holding connections; compare with PHP-FPM busy workers."),
    ("concurrently running queries", "Inspect SHOW FULL PROCESSLIST during the peak; look for lock waits and slow fingerprints."),
    ("Long-running query", "Check whether it is expected (report/backup) or blocking others; do not kill without customer approval."),
    ("Elevated 5xx", "Check the app error log and PHP-FPM log for the 5xx timestamps."),
    ("OOM killer killed this application", "Compare per-request memory x pm.max_children with free RAM; reduce memory_limit/heavy plugins or add RAM. Check the trigger process in the evidence."),
    ("OOM-killer", "Review memory sizing: max_children x per-request memory, MySQL buffer pool, Redis maxmemory; consider more RAM."),
    ("Sustained high server CPU", "Identify the top consumer above; if it is traffic-driven and legitimate, evaluate upscaling."),
    ("High CPU during live sampling", "Re-run with --minutes 10+ or review atop to confirm whether it is sustained."),
    ("Memory pressure", "Reduce memory footprint (FPM max_children, MySQL buffers, Redis) or upscale RAM."),
    ("Heavy swap", "Find the processes in swap; swap activity slows PHP and MySQL - reduce memory pressure."),
    ("CPU steal", "Check hypervisor/provider health; consider migrating the server if steal persists."),
    ("High I/O wait", "Use atop -d / iostat to find the I/O source (MySQL tmp tables, backups, logs)."),
    ("nearly full", "Free space (logs, backups, local backups) or expand the disk."),
    ("Shared service", "Review that service's configuration and usage; it affects every application on the server."),
    ("Redis has evicted", "Raise maxmemory or reduce cached data; evictions lower cache hit ratio."),
    ("near max_connections", "Find the databases holding connections; check for connection leaks or slow queries."),
    ("waiting on row locks", "Inspect INNODB_TRX for the blocking transaction."),
    ("InnoDB deadlock", "Review the listed tables' write patterns with the developer if deadlocks recur."),
    ("on-disk temporary tables", "Review queries with GROUP BY/ORDER BY on large sets; consider tmp_table_size if justified."),
    ("High CPU but no PHP-FPM access log", "Enable/check php-app.access.log, or rely on atop history for attribution."),
]


def next_action_for(text: str) -> str:
    for key, act in NEXT_ACTIONS:
        if key.lower() in text.lower():
            return act
    return ""


def F(area, severity, confidence, text, evidence=None, scenario=None, action=None, metrics=None):
    return {"area": area, "severity": severity, "confidence": confidence, "text": text,
            "evidence": evidence or [], "scenario": scenario, "action": action or next_action_for(text),
            "metrics": metrics or []}


SEV_ORDER = {"critical": 0, "high": 1, "warning": 2, "info": 3, "ok": 4}


def bot_level(ctx: Ctx, b: dict, t: dict) -> str:
    """HIGH / WARNING / NORMAL for one bot, using traffic share AND PHP cost, not request count alone."""
    a = ctx.args
    if b["requests"] < 200:
        return "NORMAL"
    share, cpu = b["pct"], b.get("php_cpu_share", 0.0)
    # Absolute load: a large *share* of a nearly idle app is irrelevant. HIGH needs real PHP cost.
    core_pct = b.get("php_cpu_s_est", 0.0) / max(getattr(a, "window_s", 3600), 1) * 100.0
    b["php_core_pct"] = round(core_pct, 1)
    heavy, notable = core_pct >= a.bot_high_cpu, core_pct >= a.bot_min_cpu or b["rpm"] >= a.bot_rpm_high
    reasons = []
    hours = max(getattr(a, "window_s", 3600) / 3600, 1 / 60)
    per_h = b["requests"] / hours
    if per_h >= a.bot_requests_high:
        reasons.append(f"{per_h:,.0f} requests/hour >= {a.bot_requests_high:,}")
    if b["rpm"] >= a.bot_rpm_high:
        reasons.append(f"{b['rpm']:.0f} req/min >= {a.bot_rpm_high:g}")
    if b.get("php_requests_est", 0) / hours >= a.bot_php_requests_high:
        reasons.append(f"~{b['php_requests_est'] / hours:,.0f} PHP requests/hour >= {a.bot_php_requests_high:,}")
    if share >= a.bot_share_high:
        reasons.append(f"{share:.0f}% of backend traffic >= {a.bot_share_high:g}%")
    if heavy:
        reasons.append(f"~{core_pct:.0f}% of a core PHP CPU >= {a.bot_high_cpu:g}%")
    b["reasons"] = reasons
    volume = any(r for r in reasons if "requests" in r or "req/min" in r)
    if b["category"] == "monitor" or b["name"].startswith("WordPress loopback"):
        return "WARNING" if heavy or b["rpm"] >= a.bot_rpm_high else "NORMAL"
    if b.get("category_label") == "Search engine (verified)":
        return "HIGH" if cpu >= 40 and heavy else "WARNING" if (share >= 40 or cpu >= 20) and notable else "NORMAL"
    mostly_static = pct(b["dynamic"], b["requests"]) < 20 and cpu < 10
    if (share >= a.bot_share_high or cpu >= 25) and heavy:
        return "WARNING" if mostly_static and not b.get("impersonation") else "HIGH"
    if (share >= a.bot_share_warn or cpu >= 10) and notable or (b.get("impersonation") and notable) or volume:
        return "WARNING"
    return "NORMAL"


def investigate_app(ctx: Ctx, p: dict, server: dict, window_h: float) -> dict:
    a = ctx.args
    fnd: list[dict] = []
    fa, t, sl, pool = p.get("fpm") or {}, p.get("traffic") or {}, p.get("slow") or {}, p.get("pool") or {}
    db = p.get("mysql") or {}
    mc = p.get("max_children")
    sig = traffic_signals(t) if t.get("total") else []
    p["traffic_signals"] = sig
    hi_cpu = p["cpu_server_share"] >= a.cpu_threshold
    hi_mem = p["mem_pct"] >= a.mem_threshold
    per_req = p.get("cpu_ms_per_req") or 0
    ratio = (p["php_cpu_share"] / p["php_req_share"]) if p["php_req_share"] else None

    # --- Resource consumption summary finding
    ev = [f"Sustained CPU {p['cpu_sustained']:.0f}% of one core ({p['cpu_server_share']:.0f}% of {NCPU}-vCPU capacity) "
          f"[source: {p['cpu_source']}]"]
    if p.get("cpu_live_avg") is not None:
        ev.append(f"Live sampling: avg {p['cpu_live_avg']:.0f}% / peak {p['cpu_live_peak']:.0f}% of one core over {a.sample_seconds:.0f}s")
    if p.get("cpu_hist_peak") is not None:
        ev.append(f"atop history: peak {p['cpu_hist_peak']:.0f}% of one core at {p['cpu_hist_peak_at']}")
    if p["mem_mb"] is not None:
        ev.append(f"Memory {fmt_mb(p['mem_mb'])} {p['mem_kind']} ({p['mem_pct']:.1f}% of RAM)")
    if hi_cpu or hi_mem:
        fnd.append(F("resources", "warning", "Confirmed",
                     f"Application is a top consumer: {', '.join(x for x in p['tags'] if x != 'Normal')}", ev))

    # --- Traffic correlation
    php_rpm = p["php_requests"] / (window_h * 60) if window_h else 0
    suspicious = None
    strong = ("dominant_ip", "dominant_subnet", "login_bruteforce", "xmlrpc_abuse", "impersonation", "admin_hammer", "error_scan")
    weak_only = all(x["key"] in ("rest_heavy", "store_api", "cache_bypass") for x in sig)
    if not weak_only and (len(sig) >= 3 or (len(sig) >= 2 and any(x["key"] in strong for x in sig))):
        conf = "Likely" if len(sig) >= 3 else "Suspected"
        suspicious = conf
        fnd.append(F("traffic", "critical" if conf == "Likely" else "warning", conf,
                     "Traffic pattern indicates possible bot / application-layer attack activity",
                     [s["text"] for s in sig], scenario="suspicious"))
    elif sig:
        fnd.append(F("traffic", "info", "Suspected", "Isolated traffic anomaly (single indicator - not sufficient to call an attack)",
                     [s["text"] for s in sig]))
    if hi_cpu and p["php_requests"]:
        if ratio is not None and ratio <= 1.6 and per_req < a.cpu_ms_per_req_threshold and not suspicious:
            fnd.append(F("correlation", "info", "Likely",
                         "CPU consumption is proportional to legitimate PHP traffic (traffic-driven)",
                         [f"{p['php_requests']:,} PHP requests ({php_rpm:.0f}/min) = {p['php_req_share']:.0f}% of server PHP requests "
                          f"and {p['php_cpu_share']:.0f}% of PHP CPU time",
                          f"Average CPU per request {per_req:.0f} ms (below {a.cpu_ms_per_req_threshold} ms threshold)"],
                         scenario="traffic"))
        elif (ratio is not None and ratio >= 3 and p["php_cpu_share"] >= 25) or per_req >= a.cpu_ms_per_req_threshold:
            disprop = ratio is not None and ratio >= 3 and p["php_cpu_share"] >= 25
            title = ("CPU consumption is disproportionate to traffic - inefficient PHP execution per request" if disprop
                     else "High CPU cost per PHP request - inefficient PHP execution")
            fnd.append(F("correlation", "warning", "Likely", title,
                         [f"Average CPU per request {per_req:,.0f} ms (threshold {a.cpu_ms_per_req_threshold:,.0f} ms); "
                          f"p95 duration {fmt_s(fa.get('p95'))}",
                          f"{p['php_cpu_share']:.0f}% of server PHP CPU time from {p['php_req_share']:.0f}% of PHP requests"
                          + (f" ({ratio:.1f}x)" if ratio else "")] if not disprop else
                         [f"{p['php_cpu_share']:.0f}% of server PHP CPU time from {p['php_req_share']:.0f}% of PHP requests"
                          + (f" ({ratio:.1f}x)" if ratio else ""),
                          f"Average CPU per request {per_req:,.0f} ms; p95 duration {fmt_s(fa.get('p95'))}"],
                         scenario="optimization"))
    elif hi_cpu and not p["php_requests"]:
        non_fpm = {k: v for k, v in p["proc_kinds"].items() if not k.startswith("fpm:")}
        if non_fpm or p["long_cli"]:
            fnd.append(F("cron", "warning", "Likely", "CPU is consumed by non-web processes (cron, WP-CLI, workers, daemons)",
                         [fmt_proc(c) for c in p["long_cli"][:3]] or
                         [f"Process kinds: {non_fpm}"], scenario="cron"))
        elif not p["fpm_log_available"]:
            fnd.append(F("correlation", "info", "Inconclusive", "High CPU but no PHP-FPM access log available to correlate with traffic"))

    # --- Long running CLI / cron
    if p["long_cli"] and not any(f["area"] == "cron" for f in fnd):
        heavy = [c for c in p["long_cli"] if c["live_cpu"] >= a.bg_cpu_threshold]
        if heavy:
            fnd.append(F("cron", "warning", "Confirmed", "Background processes owned by this application are using significant CPU now",
                         [fmt_proc(c) for c in heavy[:3]], scenario="cron"))
        elif any(c["life_cpu"] >= a.bg_cpu_threshold for c in p["long_cli"]):
            fnd.append(F("cron", "info", "Suspected", "Long-running background process with high lifetime CPU average (idle during sampling)",
                         [fmt_proc(c) for c in p["long_cli"][:2]]))
    cron = p.get("cron")
    if cron and cron["slow"]:
        fnd.append(F("cron", "info", "Suspected", "Slow WP-Cron events recorded by the Cloudways Cron Optimizer (window approximated by log rotation)",
                     [f"{h} took {d:.1f}s" for d, h in cron["slow"][:3]]))

    # --- PHP-FPM
    hits, lq = p.get("fpm_hits", 0), p.get("listen_queue_peak", 0)
    if hits:
        fnd.append(F("php-fpm", "critical", "Confirmed", "PHP-FPM worker exhaustion: pm.max_children limit was reached",
                     [f"{hits} 'max_children' warnings in the window (limit {p.get('fpm_limit') or mc})",
                      f"Estimated peak concurrent PHP requests: {fa.get('peak_concurrency', 'n/a')} at {fa.get('peak_concurrency_at', '')} UTC"],
                     scenario="fpm"))
    if lq:
        fnd.append(F("php-fpm", "critical", "Confirmed", "Requests were queued waiting for a free PHP-FPM worker (listen queue > 0)",
                     [f"Peak listen queue {lq} on {pool.get('listen', 'pool socket')} during live sampling"], scenario="fpm"))
    if mc and p["busy_peak"] >= mc and not hits:
        fnd.append(F("php-fpm", "warning", "Likely", "All PHP-FPM workers were busy during sampling",
                     [f"{p['busy_peak']} busy workers observed vs pm.max_children={mc}"], scenario="fpm"))
    elif mc and fa.get("peak_concurrency", 0) >= mc and not hits:
        fnd.append(F("php-fpm", "warning", "Suspected", "Estimated PHP concurrency reached pm.max_children",
                     [f"Estimated peak concurrency {fa['peak_concurrency']} (from request start+duration, 1s resolution) vs limit {mc}"]))
    if p.get("long_busy"):
        lb = p["long_busy"]
        fnd.append(F("php-fpm", "warning", "Likely", "Long-running PHP requests observed live (worker busy continuously)",
                     [f"PID {x['pid']} busy for ~{x['busy_s']}s of the {a.sample_seconds:.0f}s sample" for x in lb[:3]]
                     + (["Slowest logged paths: " + ", ".join(f"{r['uri']} ({r['dur']}s)" for r in fa.get("slowest_requests", [])[:2])]
                        if fa.get("slowest_requests") else []), scenario="optimization"))
    if p.get("fpm_timeouts"):
        fnd.append(F("php-fpm", "critical", "Confirmed", "PHP requests were terminated by request_terminate_timeout",
                     [f"{p['fpm_timeouts']} timeouts; scripts: " + ", ".join(f"{s} ({c})" for s, c in p["fpm_timeout_scripts"][:3])],
                     scenario="optimization"))
    n = fa.get("requests", 0)
    if n >= 20 and fa.get("p95") and fa["p95"] >= a.slow_p95_seconds:
        fnd.append(F("php-fpm", "warning", "Confirmed", "Slow PHP execution (measured in PHP-FPM access log)",
                     [f"p95 {fa['p95']:.2f}s, p99 {fa.get('p99', 0):.2f}s, max {fa.get('max_dur', 0):.1f}s over {n:,} requests",
                      f"{fa['over'].get(5, 0):,} requests >= 5s, {fa['over'].get(30, 0):,} >= 30s"]
                     + [f"Top CPU path: {x['path']} - {x['hits']} hits, {x['cpu_s']}s CPU, avg {x['avg_s']}s" for x in fa.get("top_paths_cpu", [])[:2]],
                     scenario="optimization"))
    if sl.get("entries"):
        comps = ", ".join(f"{c} ({k})" for c, k in sl["components"].most_common(3))
        funcs = [f"{fn}() at {loc} - {k} traces" for (fn, loc), k in sl["functions"].most_common(3)]
        fnd.append(F("php-fpm", "warning", "Confirmed",
                     f"{sl['entries']} slow-log traces (> request_slowlog_timeout {pool.get('request_slowlog_timeout', '?')})",
                     ([f"Components: {comps}"] if comps else []) + funcs, scenario="optimization"))
    if n >= 20 and fa.get("avg_mem") is not None and (fa["avg_mem"] >= 128 or fa["mem_max"] >= 512):
        fnd.append(F("php-fpm", "warning", "Confirmed", "High memory per PHP request",
                     [f"Average peak memory {fa['avg_mem']:.0f} MB, max {fa['mem_max']:.0f} MB per request"]
                     + [f"{r['uri']} - {r['mem']} MB" for r in fa.get("top_mem_requests", [])[:2]]))

    # --- MySQL
    sdb = db.get("slow") or {}
    if sdb.get("count", 0) >= a.slow_query_min or sdb.get("time", 0) >= 60:
        fps = [x for x in db.get("fingerprints", []) if not x["dump"]]
        sev = "critical" if sdb["time"] >= 300 else "warning"
        fnd.append(F("mysql", sev, "Confirmed" if fps else "Likely",
                     f"Recurring slow database queries on '{p['db']}'",
                     [f"{sdb['count']} slow queries, {sdb['time']:.0f}s total, max {sdb['max']:.1f}s"]
                     + [f"{x['count']}x avg {x['time'] / x['count']:.1f}s rows_examined~{x['avg_rows_ex']:,.0f}: {trunc(x['fingerprint'], 110)}" for x in fps[:3]],
                     scenario="database"))
    dumps = [x for x in db.get("fingerprints", []) if x["dump"]]
    if dumps:
        fnd.append(F("mysql", "info", "Confirmed", "Some slow queries are mysqldump/backup reads, not application traffic",
                     [f"{sum(x['count'] for x in dumps)} dump queries, {sum(x['time'] for x in dumps):.0f}s"]))
    for x in db.get("fingerprints", []):
        if x.get("explain_full_scan"):
            fnd.append(F("mysql", "warning", "Confirmed", "Query plan shows a full table scan with no usable index",
                         [f"{trunc(x['fingerprint'], 110)}", "EXPLAIN: " + ", ".join(f"{e['table']} type={e['type']} key={e['key']} rows={e['rows']}" for e in x["explain"][:3])],
                         scenario="database"))
        elif x.get("scan_suspect"):
            fnd.append(F("mysql", "info", "Suspected",
                         "Query examines far more rows than it returns (index usage not verified - no EXPLAIN evidence)",
                         [f"avg rows examined {x['avg_rows_ex']:,.0f} vs returned {x['avg_rows_sent']:,.0f}: {trunc(x['fingerprint'], 100)}"]))
    live = db.get("live") or {}
    if live.get("conn_peak", 0) >= a.db_conn_high:
        fnd.append(F("mysql", "high" if live["conn_peak"] >= a.db_conn_high * 2 else "warning", "Confirmed",
                     f"High number of database connections for '{p['db']}'",
                     [f"Peak {live['conn_peak']} connections (avg {live['conn_avg']:.1f}), {live['running_peak']} running at peak, "
                      f"during {a.sample_seconds:.0f}s of processlist sampling"],
                     metrics=[("Database", p["db"]), ("Connections peak", live["conn_peak"]), ("Running peak", live["running_peak"])]))
    if live.get("running_peak", 0) >= max(4, NCPU * 2):
        fnd.append(F("mysql", "warning", "Confirmed", "High number of concurrently running queries for this database",
                     [f"Peak {live['running_peak']} running / {live['conn_peak']} connections during sampling"], scenario="database"))
    for q in db.get("long_running", [])[:2]:
        fnd.append(F("mysql", "info" if q["dump"] else "warning", "Confirmed",
                     "Long-running query" + (" (backup dump)" if q["dump"] else ""),
                     [f"{q['time_s']}s, state '{q['state']}': {trunc(q['query'], 110)}"]))

    # --- Bots
    bot_rows = t.get("bots") or []
    flagged = []
    for b in bot_rows:
        level = bot_level(ctx, b, t)
        b["level"] = level
        if level in ("HIGH", "WARNING"):
            flagged.append(b)
    if flagged:
        worst = "high" if any(b["level"] == "HIGH" for b in flagged) else "warning"
        cpu_bots = sum(b["php_cpu_share"] for b in flagged)
        ev = []
        for b in flagged[:4]:
            dyn = pct(b["dynamic"], b["requests"])
            ev.append(f"{b['name']} [{b.get('category_label', b['category'])}]: {b['requests']:,} req ({b['pct']:.0f}% of backend), "
                      f"{b['rpm']:.0f}/min, {b['unique_ips']} IPs, {dyn:.0f}% dynamic, est. {b['php_cpu_share']:.0f}% of app PHP CPU "
                      f"(~{b.get('php_core_pct', 0):.0f}% of a core)"
                      + (" - mostly static/cached, not driving PHP" if dyn < 20 else ""))
        drives = hi_cpu and cpu_bots >= 30
        static_only = cpu_bots < 10 and all(pct(b["dynamic"], b["requests"]) < 20 for b in flagged)
        if static_only:
            worst = "info"
        bc = t.get("bot_correlation") or {}
        for b in flagged[:2]:
            if b.get("reasons"):
                ev.append(f"{b['name']} thresholds: " + "; ".join(b["reasons"]))
        if (bc.get("php_peak") or {}).get("bot_share") is not None:
            ev.append(f"Busiest PHP minute {bc['php_peak']['minute']} UTC ({bc['php_peak']['php_requests']} PHP req): bots "
                      f"{bc['php_peak']['bot_share']:.0f}% of backend requests vs {bc['overall_bot_share']:.0f}% overall")
        for key, label in (("max_children", "max_children-reached minutes"), ("slow_queries", "minutes with slow queries")):
            if bc.get(key):
                ev.append(f"During {bc[key][1]} {label}: bots {bc[key][0]:.0f}% of backend requests vs "
                          f"{bc['overall_bot_share']:.0f}% overall (co-occurrence, not proof)")
        fnd.append(F("bots", worst, "Likely" if drives else "Confirmed",
                     "HIGH BOT TRAFFIC DETECTED" if worst == "high" else
                     "High bot request volume on static/cached content (not driving PHP)" if static_only else "Elevated bot traffic",
                     ev + [f"Flagged bots account for an estimated {cpu_bots:.0f}% of this app's PHP CPU (attributed by client IP)"],
                     scenario="bots" if drives else None,
                     metrics=[("Bots", ", ".join(b["name"] for b in flagged[:3])),
                              ("Requests", f"{sum(b['requests'] for b in flagged):,} ({sum(b['pct'] for b in flagged):.0f}% of backend)"),
                              ("Est. PHP CPU", f"{cpu_bots:.0f}% of app")]))
    for b in bot_rows:
        if b.get("impersonation") and b["requests"] >= 20:
            bad = [c for c in b["verification"]["checked"] if c["result"].startswith("failed")]
            fnd.append(F("bots", "high", "Confirmed", f"Bot impersonation: traffic claiming to be {b['name']} fails DNS verification",
                         [f"{b['requests']:,} requests; {len(bad)}/{len(b['verification']['checked'])} checked IPs failed"]
                         + [f"{c['ip']} -> {c['host'] or 'no PTR record'}" for c in bad[:3]], scenario="suspicious"))

    # --- OOM kills of this application's processes
    if p.get("oom"):
        ks = p["oom"]
        mx = max((e["rss_mb"] or 0) for e in ks)
        fnd.append(F("memory", "critical", "Confirmed", "OOM killer killed this application's processes",
                     [f"{len(ks)} kill(s); processes: " + ", ".join(f"{n} ({c})" for n, c in Counter(e["process"] for e in ks).most_common(3))
                      + (f"; largest {fmt_mb(mx)} RSS at kill" if mx else "")]
                     + [f"{e['time']} pid {e['pid']} {e['process']}" + (f" ({fmt_mb(e['rss_mb'])})" if e["rss_mb"] else "")
                        + (f", triggered by {e['trigger']}" if e["trigger"] else "") + (" [cgroup limit]" if e["memcg"] else "")
                        for e in ks[:3]],
                     scenario="memory",
                     metrics=[("OOM kills", len(ks)), ("Largest at kill", fmt_mb(mx) if mx else "n/a")]
                     + ([("Memory per request", f"avg {fmt_mb(fa.get('avg_mem'))}, max {fmt_mb(fa.get('mem_max'))}")]
                        if fa.get("requests") else [])))

    # --- Errors
    if t.get("total", 0) >= 200 and pct(t.get("errors_5xx", 0), t["total"]) >= 5:
        fnd.append(F("traffic", "warning", "Confirmed", "Elevated 5xx error rate",
                     [f"{t['errors_5xx']:,} 5xx responses ({pct(t['errors_5xx'], t['total']):.1f}% of backend requests)"]))

    calibrate_app_severity(ctx, p, fnd, server)
    fnd.sort(key=lambda f: (SEV_ORDER[f["severity"]], CONF_ORDER[f["confidence"]]))
    p["findings"] = fnd
    p["root_cause"] = decide_root_cause(p, fnd, server, suspicious)
    return p


def fmt_age(sec: int) -> str:
    if sec >= 86400:
        return f"{sec / 86400:.1f}d"
    if sec >= 3600:
        return f"{sec / 3600:.1f}h"
    return f"{sec // 60}m"


def _has(f, *keys):
    t = f["text"].lower()
    return any(k.lower() in t for k in keys)


def calibrate_app_severity(ctx: Ctx, p: dict, fnd: list, h: dict):
    """Unified severity (critical/high/warning/info) using server capacity, sample length and evidence strength."""
    a = ctx.args
    fa, t = p.get("fpm") or {}, p.get("traffic") or {}
    hist = (h or {}).get("history") or {}
    srv_busy = (hist.get("cpu_busy") or (None,))[0]
    srv_busy = srv_busy if srv_busy is not None else (h or {}).get("cpu_busy", 0)
    short = a.sample_seconds < 60
    saturated = any(_has(f, "worker exhaustion", "queued waiting") for f in fnd)

    # Extra detectors that need the whole profile
    fpm_procs = [x for x in p.get("top_procs", []) if x["what"].startswith("fpm:")]
    hot = [x for x in fpm_procs if x["cpu"] >= 80]
    if hot:
        fnd.append(F("php-fpm", "high", "Confirmed", "High CPU from individual PHP-FPM processes",
                     [f"PID {x['pid']} averaged {x['cpu']:.0f}% of a core over the {a.sample_seconds:.0f}s sample" for x in hot[:3]],
                     action="Match the PID's busy period with the slowest requests/slow-log traces; check for loops or heavy imports."))
    if fpm_procs and fpm_procs[0]["mem_kind"] == "PSS":
        avg = sum(x["mem_mb"] for x in fpm_procs) / len(fpm_procs)
        if avg >= 128:
            fnd.append(F("php-fpm", "high" if avg >= 256 else "warning", "Confirmed", "Excessive PHP-FPM worker memory",
                         [f"Average {avg:.0f} MB PSS per worker across {len(fpm_procs)} sampled worker(s)",
                          f"pm.max_children={p.get('max_children') or '?'} -> worst case ~{fmt_mb(avg * (p.get('max_children') or 0))}"],
                         action="Find memory-heavy requests (top memory URLs); size max_children to RAM / per-worker memory."))
    win_min = max(getattr(a, "window_s", 3600) / 60, 1)
    php_rpm_core = p["php_requests"] / win_min / NCPU
    if php_rpm_core >= a.php_rpm_per_core_warn:
        loaded = p["cpu_server_share"] >= a.cpu_threshold
        fnd.append(F("traffic", ("high" if php_rpm_core >= a.php_rpm_per_core_warn * 2.5 else "warning") if loaded else "info",
                     "Confirmed", "High backend/PHP request volume" + ("" if loaded else " (handled without resource pressure)"),
                     [f"{p['php_requests']:,} PHP requests = {p['php_requests'] / win_min:.0f}/min ({php_rpm_core:.0f}/min per vCPU)",
                      f"Backend requests: {t.get('total', 0):,}; bots {pct(t.get('bot_requests', 0), t.get('total') or 1):.0f}% of them"],
                     metrics=[("PHP req/min", f"{p['php_requests'] / win_min:.0f}"), ("Per vCPU", f"{php_rpm_core:.0f}/min")]))

    for f in fnd:
        sev = f["severity"]
        if _has(f, "top consumer"):
            share, mem = p["cpu_server_share"], p["mem_pct"]
            sev = "critical" if share >= a.cpu_critical and srv_busy >= 85 else \
                "high" if share >= a.cpu_high or mem >= a.mem_high else "warning"
            f["metrics"] = [("CPU", f"{p['cpu_sustained']:.0f}% of a core ({share:.0f}% of server) [{p['cpu_source']}]"),
                            ("Memory", f"{fmt_mb(p['mem_mb'])} ({mem:.0f}% of RAM)" if p["mem_mb"] is not None else "n/a (no live data)")]
        elif _has(f, "disproportionate", "High CPU cost per PHP request"):
            sev = "high" if p["cpu_server_share"] >= a.cpu_threshold * 2 or srv_busy >= 70 else "warning"
        elif _has(f, "proportional to legitimate"):
            sev = "info"
        elif _has(f, "attack activity"):
            sev = ("critical" if saturated or srv_busy >= 85 else "high") if f["confidence"] == "Likely" else "warning"
            abuse = {x["key"] for x in p.get("traffic_signals", [])} & {"login_bruteforce", "xmlrpc_abuse", "impersonation", "admin_hammer"}
            idle = p["tags"] == ["Normal"] and (t.get("avg_rpm") or 0) < a.attack_min_rpm and not saturated and not abuse
            if idle:      # pattern without load: an observation, not an alert
                sev = "warning" if f["confidence"] == "Likely" else "info"
                f["evidence"] = f["evidence"] + [f"Low impact: {t.get('avg_rpm', 0):.0f} req/min and no resource pressure on this app"]
        elif _has(f, "impersonation"):
            sev = "high"
        elif _has(f, "worker exhaustion"):
            sev = "critical" if p.get("fpm_hits", 0) >= 10 or p.get("listen_queue_peak") else "high"
            f["metrics"] = [("max_children", p.get("max_children") or "?"), ("Limit reached", f"{p.get('fpm_hits', 0)}x"),
                            ("Listen queue", p.get("listen_queue_peak", 0)), ("Busy peak", p["busy_peak"])]
        elif _has(f, "queued waiting"):
            sev = "critical"
            f["metrics"] = [("Listen queue", p.get("listen_queue_peak", 0)), ("Busy workers", p["busy_peak"])]
        elif _has(f, "All PHP-FPM workers were busy"):
            sev = "warning" if short else "high"
        elif _has(f, "Long-running PHP requests"):
            sev = "high" if any(x["busy_s"] >= 30 for x in p.get("long_busy", [])) and not short else "warning"
        elif _has(f, "request_terminate_timeout"):
            sev = "critical" if p.get("fpm_timeouts", 0) >= 10 else "high"
        elif _has(f, "Slow PHP execution"):
            n = fa.get("requests") or 1
            sev = "high" if (fa.get("p95") or 0) >= 10 or fa.get("over", {}).get(5, 0) >= 0.25 * n else "warning"
            f["metrics"] = [("p95", fmt_s(fa.get("p95"))), ("Requests >=5s", f"{fa.get('over', {}).get(5, 0):,} of {n:,}")]
        elif _has(f, "slow-log traces"):
            sev = "high" if (p.get("slow") or {}).get("entries", 0) >= 50 else "warning"
        elif _has(f, "High memory per PHP request"):
            sev = "high" if (fa.get("avg_mem") or 0) >= 256 or fa.get("mem_max", 0) >= 1024 else "warning"
        elif _has(f, "Recurring slow database"):
            tm = ((p.get("mysql") or {}).get("slow") or {}).get("time", 0)
            sev = "critical" if tm >= 1800 else "high" if tm >= 300 else "warning"
            sq = (p.get("mysql") or {}).get("slow") or {}
            f["metrics"] = [("Database", p["db"]), ("Slow queries", sq.get("count", 0)), ("Total time", f"{tm:.0f}s")]
        elif _has(f, "concurrently running queries"):
            sev = "high"
        elif _has(f, "Long-running query"):
            m = re.match(r"(\d+)s, state", f["evidence"][0]) if f["evidence"] else None
            sev = "info" if "backup" in f["text"] else "high" if m and int(m.group(1)) >= 60 else "warning"
        elif _has(f, "5xx"):
            sev = "high" if pct(t.get("errors_5xx", 0), t.get("total") or 1) >= 20 else "warning"
        elif _has(f, "significant CPU now"):
            sev = "warning" if short or not any(c["live_cpu"] >= 50 for c in p.get("long_cli", [])) else "high"
        f["severity"] = sev


def calibrate_server_severity(ctx: Ctx, out: list, h: dict):
    hist = h.get("history") or {}
    for f in out:
        sev = f["severity"]
        if _has(f, "OOM-killer"):
            sev = "critical"
        elif _has(f, "Sustained high server CPU"):
            sev = "critical" if (hist.get("cpu_busy") or (0,))[0] >= 90 else "high"
        elif _has(f, "High CPU during live sampling"):
            sev = "warning"
        elif _has(f, "Memory pressure"):
            sev = "critical" if h.get("mem_used_pct", 0) >= 95 and any(_has(x, "swap", "OOM") for x in out) else "high"
        elif _has(f, "Heavy swap"):
            psi = (h.get("psi", {}).get("memory") or {}).get("some", 0) or 0
            sev = "high" if psi >= 1 else "warning"
        elif _has(f, "steal"):
            sev = "high" if h.get("steal", 0) >= 15 else "warning"
        elif _has(f, "I/O wait"):
            sev = "high" if h.get("iowait", 0) >= 25 else "warning"
        elif _has(f, "nearly full"):
            m = re.match(r"([\d.]+)% space", f["evidence"][0])
            sev = "critical" if m and float(m.group(1)) >= 95 else "high"
        elif _has(f, "Shared service"):
            m = re.search(r"\(([\d.]+)% of server\).*\(([\d.]+)% of RAM\)", f["evidence"][0])
            cpu_sh, mem_sh = (float(m.group(1)), float(m.group(2))) if m else (0, 0)
            sev = "high" if cpu_sh >= 50 or mem_sh >= 60 else "warning" if cpu_sh >= 25 or mem_sh >= 40 else "info"
        elif _has(f, "max_connections"):
            sev = "high"
        elif _has(f, "row locks"):
            sev = "warning"
        f["severity"] = sev


def fmt_proc(c: dict) -> str:
    age = fmt_age(c["age_s"])
    return (f"PID {c['pid']} {c.get('comm', '')}: {c['live_cpu']:.0f}% CPU now, {c['life_cpu']:.0f}% lifetime avg, "
            f"running {age}: {trunc(c['cmd'], 70)}")


def fmt_s(v) -> str:
    return f"{v:.2f}s" if isinstance(v, (int, float)) else "n/a"


SCENARIO_SHORT = {"suspicious": "Suspicious traffic", "bots": "Bot/crawler load", "memory": "Memory exhaustion (OOM)",
                  "fpm": "PHP-FPM saturation", "database": "Slow database queries", "optimization": "Inefficient PHP",
                  "cron": "Cron/CLI processes", "traffic": "Traffic-driven"}
SCENARIO_TEXT = {
    "suspicious": "Suspicious / bot traffic is driving backend load",
    "bots": "Crawler / bot traffic is driving PHP load",
    "memory": "Memory exhaustion (processes killed by the OOM killer)",
    "fpm": "PHP-FPM worker saturation is delaying requests",
    "database": "Database query performance is a bottleneck",
    "optimization": "Inefficient application (PHP) execution",
    "cron": "Background cron / CLI PHP processes",
    "traffic": "Legitimate traffic volume (traffic-driven load)",
}


def decide_root_cause(p, fnd, server, suspicious) -> dict:
    by = defaultdict(list)
    for f in fnd:
        if f["scenario"] and f["confidence"] != "Inconclusive":
            by[f["scenario"]].append(f)
    order = ["suspicious", "bots", "memory", "fpm", "database", "optimization", "cron", "traffic"]
    primary = [s for s in order if by.get(s)]
    significant = p["tags"] != ["Normal"] or any(f["severity"] in ("critical", "high") for f in fnd)
    if primary and not significant:
        obs = sum(1 for f in fnd if f["severity"] != "info")
        return {"primary": None, "secondary": [], "confidence": "Confirmed", "observations": obs,
                "text": "No sustained resource bottleneck" + (f" ({obs} observation(s) under Key Findings)" if obs else "")}
    if not primary:
        conf = "Inconclusive" if p["tags"] != ["Normal"] else "Confirmed"
        return {"primary": None, "secondary": [], "confidence": conf,
                "text": "No sustained bottleneck identified" if conf == "Confirmed" else
                        "Resource usage is elevated but the available data does not identify a specific cause"}
    first = primary[0]
    # When FPM saturation co-occurs with slow PHP/DB, the saturation is a symptom - name the cause.
    if first == "fpm" and (by.get("database") or by.get("optimization")):
        cause = "database" if by.get("database") else "optimization"
        primary = [cause, "fpm"] + [s for s in primary if s not in (cause, "fpm")]
        first = cause
    best = min((CONF_ORDER[f["confidence"]] for f in by[first]))
    conf = [k for k, v in CONF_ORDER.items() if v == best][0]
    if conf == "Confirmed" and first in ("optimization", "traffic"):
        conf = "Likely"     # these are interpretations of measurements, not direct proof
    return {"primary": first, "secondary": primary[1:], "confidence": conf, "text": SCENARIO_TEXT[first]}


def two_line_summary(p: dict, window_desc: str) -> list[str]:
    rc = p["root_cause"]
    l1 = (f"{p['app']} ({p['domain'] or p['type']}) used ~{p['cpu_sustained']:.0f}% of one CPU core "
          f"({p['cpu_server_share']:.0f}% of server capacity)" + (f" and {fmt_mb(p['mem_mb'])} RAM" if p["mem_mb"] is not None else "")
          + f" over {window_desc}, "
          f"serving {p['php_requests']:,} PHP requests"
          + (f" ({p['traffic'].get('total', 0):,} backend requests)" if p.get("traffic", {}).get("total") else "") + ".")
    if rc["primary"] is None:
        l2 = rc["text"] + "."
    else:
        extra = f" (also: {'; '.join(SCENARIO_TEXT[s] for s in rc['secondary'][:2])})" if rc["secondary"] else ""
        l2 = f"Most likely reason [{rc['confidence']}]: {rc['text'][0].lower() + rc['text'][1:]}{extra}."
    return [l1, l2]


def server_findings(ctx: Ctx, h: dict, services: dict, oom: dict, mysql: dict, redis, apps_cpu_total: float) -> list[dict]:
    out = []
    hist = h.get("history") or {}
    if oom.get("events"):
        owners = oom.get("by_owner") or []
        ev = ["Killed by owner: " + ", ".join(
            f"{o['kind']} {o['owner']} ({o['kills']}x" + (f", up to {fmt_mb(o['max_rss_mb'])}" if o["max_rss_mb"] else "") + ")"
            for o in owners[:5])]
        if oom.get("triggers"):
            ev.append("Triggered by: " + ", ".join(f"{t} ({c})" for t, c in oom["triggers"][:3]))
        if oom.get("memcg_kills"):
            ev.append(f"{oom['memcg_kills']} kill(s) hit a cgroup memory limit (that service's limit), not total server RAM")
        ev += [f"{e['time']} {e['process']} pid {e['pid']} -> {e['owner_kind']} {e['owner']}"
               + (f", {fmt_mb(e['rss_mb'])} RSS" if e["rss_mb"] else "") for e in oom["events"][:3]]
        out.append(F("server", "critical", "Confirmed", f"{len(oom['events'])} OOM-killer event(s) in the window", ev,
                     metrics=[("OOM kills", len(oom["events"])),
                              ("Most affected", f"{owners[0]['kind']} {owners[0]['owner']} ({owners[0]['kills']}x)" if owners else "-")]))
    cb = hist.get("cpu_busy") or (None, None)
    if cb[0] is not None and hist.get("intervals"):
        share_high = pct(hist["high_cpu_intervals"], hist["intervals"])
        if cb[0] >= 75 or share_high >= 50:
            out.append(F("server", "critical", "Confirmed", "Sustained high server CPU utilisation",
                         [f"atop: avg {cb[0]:.0f}% busy, peak {cb[1]:.0f}%; {hist['high_cpu_intervals']}/{hist['intervals']} "
                          f"intervals >= 85%"]))
    elif h.get("cpu_busy", 0) >= 85:
        out.append(F("server", "warning", "Likely", "High CPU during live sampling (no history to prove it is sustained)",
                     [f"avg {h['cpu_busy']:.0f}% busy over {ctx.args.sample_seconds:.0f}s"]))
    mu = hist.get("mem_used_pct") or (None, None)
    if (mu[0] or 0) >= 90 or h.get("mem_used_pct", 0) >= 90:
        out.append(F("server", "warning", "Confirmed", "Memory pressure",
                     [f"Live used {h.get('mem_used_pct', 0):.0f}% of {fmt_mb(h.get('mem_total_mb'))}"]
                     + ([f"atop avg {mu[0]:.0f}% / peak {mu[1]:.0f}%"] if mu[0] is not None else [])))
    if h.get("swap_total_mb") and pct(h.get("swap_used_mb", 0), h["swap_total_mb"]) >= 50:
        psi = h.get("psi", {}).get("memory", {}).get("some")
        out.append(F("server", "warning", "Confirmed", "Heavy swap usage",
                     [f"{fmt_mb(h['swap_used_mb'])} of {fmt_mb(h['swap_total_mb'])} swap used"]
                     + ([f"memory PSI some avg60={psi:.1f}%"] if psi is not None else [])))
    st = max(h.get("steal", 0), (hist.get("steal") or (0, 0))[0] or 0)
    if st >= ctx.args.steal_threshold:
        out.append(F("server", "warning", "Likely", "Elevated CPU steal - hypervisor contention",
                     [f"steal avg {h.get('steal', 0):.1f}% (live), {((hist.get('steal') or (0, 0))[0] or 0):.1f}% (atop)"]))
    iw = max(h.get("iowait", 0), (hist.get("iowait") or (0, 0))[0] or 0)
    if iw >= 15:
        out.append(F("server", "warning", "Confirmed", "High I/O wait",
                     [f"iowait {iw:.1f}%"] + [f"{d['dev']}: util {d['util']:.0f}%, await {d['await_ms']:.1f} ms" for d in h.get("disks", [])[:2]]))
    for fs in h.get("filesystems", []):
        if fs["used_pct"] >= 90 or fs["inode_pct"] >= 90:
            out.append(F("server", "critical" if fs["used_pct"] >= 95 else "warning", "Confirmed", f"Filesystem {fs['mount']} nearly full",
                         [f"{fs['used_pct']:.0f}% space, {fs['inode_pct']:.0f}% inodes of {fs['size_gb']:.0f} GB"]))
    total_mem = h.get("mem_total_mb") or 1
    for name, s in sorted(services.items(), key=lambda kv: -kv[1]["mem_mb"]):
        if pct(s["mem_mb"], total_mem) >= 25 or s["cpu"] / NCPU >= 25:
            out.append(F("services", "warning" if name != "mysql" or s["cpu"] / NCPU >= 25 else "info", "Confirmed",
                         f"Shared service '{name}' is a major consumer (not attributable to a single app)",
                         [f"CPU {s['cpu']:.0f}% of one core ({s['cpu'] / NCPU:.0f}% of server), memory {fmt_mb(s['mem_mb'])} "
                          f"({pct(s['mem_mb'], total_mem):.0f}% of RAM)"]))
    if redis and redis.get("evicted"):
        out.append(F("services", "info", "Confirmed", "Redis has evicted keys (maxmemory reached at some point)",
                     [f"evicted_keys={redis['evicted']:,}, used {fmt_mb(redis['used_mb'])} / max {fmt_mb(redis['maxmemory_mb']) if redis['maxmemory_mb'] else 'unlimited'}"]))
    if mysql.get("available"):
        v, s = mysql.get("vars", {}), mysql.get("status_end", {})
        try:
            if int(s.get("Max_used_connections", 0)) >= 0.8 * int(v.get("max_connections", 10 ** 9)):
                out.append(F("mysql", "warning", "Confirmed", "MySQL connection count near max_connections",
                             [f"Max_used_connections={s['Max_used_connections']} / max_connections={v['max_connections']}"]))
        except ValueError:
            pass
        if mysql.get("lock_waits_now"):
            out.append(F("mysql", "warning", "Confirmed", "Transactions currently waiting on row locks",
                         [f"{mysql['lock_waits_now']} waiting, longest {mysql.get('lock_wait_max_s', 0)}s"]))
        if mysql.get("last_deadlock"):
            out.append(F("mysql", "info", "Confirmed", "InnoDB deadlock recorded (latest since restart)",
                         [f"at {mysql['last_deadlock']} tables: {', '.join(mysql.get('deadlock_tables', [])) or 'n/a'}"]))
        r = mysql.get("rates", {})
        if r.get("Created_tmp_disk_tables", 0) >= 5:
            out.append(F("mysql", "info", "Confirmed", "Frequent on-disk temporary tables",
                         [f"{r['Created_tmp_disk_tables']:.1f}/s during sampling (tmp_table_size={v.get('tmp_table_size', '?')})"]))
    calibrate_server_severity(ctx, out, h)
    out.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return out


def issue_origin(ctx: Ctx, h: dict, attribution: list, srv_findings: list, top: list) -> dict:
    """Where does pressure come from: applications, shared services, other processes, or the infrastructure?"""
    hist = h.get("history") or {}
    cpu_busy = (hist.get("cpu_busy") or (None,))[0]
    cpu_busy = cpu_busy if cpu_busy is not None else h.get("cpu_busy", 0)
    mem_used = h.get("mem_used_pct", 0)
    oom = any("OOM" in f["text"] for f in srv_findings)
    steal = max(h.get("steal", 0), (hist.get("steal") or (0, 0))[0] or 0)
    iowait = max(h.get("iowait", 0), (hist.get("iowait") or (0, 0))[0] or 0)
    groups = {"applications": [0.0, 0.0], "shared services": [0.0, 0.0], "other processes": [0.0, 0.0]}
    for name, v in attribution:
        g = "applications" if name.startswith(("app:", "other apps")) else \
            "other processes" if name.startswith(("other", "system/other")) else "shared services"
        groups[g][0] += v["cpu"]
        groups[g][1] += v["mem_mb"]
    ev = [f"{g}: CPU {c:.0f}% of one core, memory {fmt_mb(m)}" for g, (c, m) in groups.items()]
    ev.append(f"server CPU busy {cpu_busy:.0f}% ({'atop window avg' if hist else 'live'}), memory {mem_used:.0f}%, "
              f"steal {steal:.1f}%, iowait {iowait:.1f}%")
    infra = []
    if steal >= ctx.args.steal_threshold:
        infra.append(f"CPU steal {steal:.1f}% (hypervisor contention)")
    if iowait >= 15:
        infra.append(f"I/O wait {iowait:.1f}% (disk bottleneck)")
    pressure = cpu_busy >= 70 or mem_used >= 85 or oom
    if infra:
        return {"origin": "infrastructure", "confidence": "Likely", "evidence": infra + ev,
                "text": "Underlying server/infrastructure limitation: " + "; ".join(infra)}
    if not pressure:
        return {"origin": "none", "confidence": "Confirmed", "evidence": ev,
                "text": "No server-level resource pressure during the investigation window"}
    cpu_lead = max(groups.items(), key=lambda kv: kv[1][0])
    mem_lead = max(groups.items(), key=lambda kv: kv[1][1])
    lead = mem_lead if (mem_used >= 85 or oom) and cpu_busy < 70 else cpu_lead
    names = ", ".join(p["app"] for p in top if p["tags"] != ["Normal"]) or "see top applications"
    text = {"applications": f"Application workload (top: {names})",
            "shared services": "Shared services (MySQL/Redis/Varnish/Elasticsearch...) rather than a single application",
            "other processes": "Non-application processes (system, security scanners, backups or other daemons)"}[lead[0]]
    return {"origin": lead[0], "confidence": "Likely", "evidence": ev, "text": text}


def recommendations(ctx: Ctx, profiles: list[dict], srv_findings: list[dict], h: dict) -> tuple[list[dict], list[dict]]:
    internal, customer = [], []
    sustained_cpu = any(f["text"].startswith("Sustained high server CPU") for f in srv_findings)
    sustained_mem = any(f["text"].startswith(("Memory pressure", "Heavy swap")) for f in srv_findings) or \
        any("OOM" in f["text"] for f in srv_findings)
    cust_keys = {}
    current = {"app": None}

    def add_c(key, title, text):
        label = current["app"]
        if key not in cust_keys:
            cust_keys[key] = {"title": title, "text": text, "apps": []}
            customer.append(cust_keys[key])
        if label and label not in cust_keys[key]["apps"]:
            cust_keys[key]["apps"].append(label)

    for p in profiles:
        rc = p["root_cause"]
        current["app"] = p["domain"] or p["app"]
        ev_of = lambda scen: [e for f in p["findings"] if f["scenario"] == scen for e in f["evidence"][:2]]  # noqa: E731
        if rc["primary"] == "suspicious":
            internal.append({"app": p["app"], "text": "Investigate abnormal traffic; consider Cloudflare/WAF rate-limits or IP blocks after manual review",
                             "evidence": ev_of("suspicious")[:4]})
            add_c("bot", "Unwanted / Bot Traffic Mitigation",
                  f"The investigation identified a high volume of automated or suspicious requests reaching {p['domain'] or p['app']}, "
                  "which increases server workload. We recommend enabling a web application firewall / bot protection "
                  "(for example Cloudflare with rate limiting) and restricting abusive sources.")
        if "bots" in [rc["primary"]] + rc["secondary"]:
            bnames = [b["name"] for b in (p.get("traffic") or {}).get("bots", []) if b.get("level") == "HIGH"]
            internal.append({"app": p["app"], "text": "Crawler traffic is driving PHP load: rate-limit/block aggressive SEO/AI bots "
                             f"({', '.join(bnames[:3]) or 'see bot table'}); keep verified search engines, tune their crawl rate",
                             "evidence": ev_of("bots")[:4]})
            add_c("bots", "Bot / Crawler Traffic Management",
                  "A significant share of the application's server workload comes from automated crawlers (for example SEO and "
                  "AI bots) rather than visitors. We recommend limiting non-essential crawlers through bot management or rate-limiting "
                  "rules (for example Cloudflare bot rules) and robots.txt, while keeping legitimate search engines allowed.")
        if "memory" in [rc["primary"]] + rc["secondary"]:
            internal.append({"app": p["app"], "text": "Investigate OOM kills of this app: per-request memory x max_children, "
                             "MySQL/Redis memory, and whether RAM must be increased", "evidence": ev_of("memory")[:3]})
            add_c("oom", "Memory Exhaustion",
                  "The server ran out of available memory and the operating system had to stop processes belonging to the "
                  "application, which can cause errors or downtime for visitors. We recommend reducing the application's memory "
                  "usage (for example heavy plugins, large imports or high PHP memory limits) or upgrading the server memory.")
        if "fpm" in [rc["primary"]] + rc["secondary"]:
            internal.append({"app": p["app"], "text": f"Investigate PHP-FPM worker saturation (pm.max_children={p.get('max_children', '?')}); "
                             "fix slow execution first, raise max_children only if RAM allows "
                             f"(avg {fmt_mb((p.get('fpm') or {}).get('avg_mem'))} per request)", "evidence": ev_of("fpm")[:3]})
        if rc["primary"] == "database" or "database" in rc["secondary"]:
            internal.append({"app": p["app"], "text": f"Review slow queries on database '{p['db']}' (indexes, query patterns, object cache)",
                             "evidence": ev_of("database")[:3]})
            add_c("db", "Database Optimization Required",
                  "The investigation identified recurring slow database queries contributing to increased execution time. "
                  "We recommend having the application developer review and optimize the affected queries and associated "
                  "database operations (for example adding appropriate indexes and enabling object caching).")
        if rc["primary"] == "optimization" or "optimization" in rc["secondary"]:
            internal.append({"app": p["app"], "text": "Application-level optimisation needed before any upscaling (profile slow paths/plugins)",
                             "evidence": ev_of("optimization")[:4]})
            add_c("opt", "Application Optimization Required",
                  "The investigation identified resource-intensive PHP execution associated with the application. We recommend "
                  "reviewing the application code, plugins, themes and scheduled tasks to improve execution efficiency.")
        if rc["primary"] == "cron" or "cron" in rc["secondary"]:
            internal.append({"app": p["app"], "text": "Review application cron jobs / WP-CLI / background workers", "evidence": ev_of("cron")[:3]})
            add_c("cron", "Scheduled Task Review",
                  "Background scheduled tasks of the application are consuming significant server resources. We recommend "
                  "reviewing their frequency and efficiency, and scheduling heavy tasks during off-peak hours.")
        if rc["primary"] == "traffic":
            if sustained_cpu or sustained_mem:
                internal.append({"app": p["app"], "text": "Consider server upscaling: load is traffic-driven and server pressure is sustained",
                                 "evidence": ev_of("traffic")[:2] + [e for f in srv_findings if f["area"] == "server" for e in f["evidence"][:1]][:2]})
                add_c("upscale", "Server Upscaling Recommended",
                      "The application is receiving substantial legitimate traffic, resulting in sustained CPU and memory consumption. "
                      "We recommend upgrading the server resources to accommodate the current workload and maintain optimal performance.")
            else:
                internal.append({"app": p["app"], "text": "Traffic-driven load without proven sustained server pressure - monitor during peak hours before upscaling",
                                 "evidence": ev_of("traffic")[:2]})
        if rc.get("observations"):
            internal.append({"app": p["app"], "text": "Low resource usage - review observations only if the customer reports a problem",
                             "evidence": [f["text"] for f in p["findings"] if f["severity"] != "info"][:3]})
        if rc["confidence"] == "Inconclusive":
            internal.append({"app": p["app"], "text": "Re-run during the reported slow period with a longer --sample-seconds; enable FPM access/slow logs if missing",
                             "evidence": [f"Tags: {', '.join(p['tags'])}"]})
    current["app"] = None
    for f in srv_findings:
        if "steal" in f["text"]:
            internal.append({"app": "server", "text": "Check hypervisor health; consider migration to a healthier host if steal persists", "evidence": f["evidence"]})
        elif "OOM" in f["text"] or f["text"].startswith(("Memory pressure", "Heavy swap")):
            internal.append({"app": "server", "text": "Review memory sizing: PHP-FPM max_children x per-request memory, MySQL buffer pool, Redis maxmemory", "evidence": f["evidence"]})
        elif f["area"] == "services":
            internal.append({"app": "server", "text": f"Review shared service usage: {f['text']}", "evidence": f["evidence"]})
        elif "Filesystem" in f["text"]:
            internal.append({"app": "server", "text": "Free disk space / review log and backup growth", "evidence": f["evidence"]})
            add_c("disk", "Disk Space Attention", "The server disk is nearly full. We recommend removing unneeded files, logs or "
                  "backups, or increasing the disk size to avoid service interruption.")
        elif "I/O wait" in f["text"]:
            internal.append({"app": "server", "text": "Investigate disk I/O contention (atop -d, MySQL temporary tables, backups)", "evidence": f["evidence"]})
    if (sustained_cpu or sustained_mem) and "upscale" not in cust_keys and not any(k in cust_keys for k in ("bot", "opt", "db")):
        add_c("upscale", "Server Upscaling Recommended",
              "The server has shown sustained CPU/memory pressure during the investigation window. We recommend upgrading "
              "the server resources to maintain optimal application performance.")
    if not customer:
        add_c("none", "No Immediate Action Required",
              "The available metrics do not indicate a sustained resource bottleneck or a significant application-level "
              "performance issue during the investigation window.")
    return internal, customer


# ----------------------------------------------------------------------------
# Rendering (plain text / ANSI terminal / Markdown) - no third-party deps
# ----------------------------------------------------------------------------
ANSI = {"red": "\033[1;31m", "orange": "\033[1;38;5;208m", "yellow": "\033[1;33m", "green": "\033[1;32m", "blue": "\033[1;34m",
        "cyan": "\033[1;36m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}
SEV_COLOR = {"critical": "red", "high": "orange", "warning": "yellow", "info": "blue", "ok": "green"}
SEV_TAG = {"critical": "[CRITICAL]", "high": "[HIGH]", "warning": "[WARNING]", "info": "[INFO]", "ok": "[HEALTHY]"}
SEV_NAME = {"critical": "CRITICAL", "high": "HIGH", "warning": "WARNING", "info": "INFO", "ok": "HEALTHY"}
W = 120      # report width; set from the terminal (or --width) in main()


def set_width(args) -> int:
    """Use the real terminal width (capped) instead of a fixed 78 columns, so lines don't wrap early."""
    global W
    if getattr(args, "width", 0):
        W = max(60, args.width)
    elif sys.stdout.isatty():
        W = max(80, min(shutil.get_terminal_size((120, 24)).columns - 2, 160))
    else:
        W = 120
    return W


ANSI_CODE_RE = re.compile(r"\x1b\[[0-9;]*m")
MK_ON, MK_OFF = "\x01", "\x02"          # invisible "alarming value" markers inside report text


def alarm(v) -> str:
    """Mark a value as alarming: red in the terminal, **bold** in Markdown, plain in text files."""
    return f"{MK_ON}{v}{MK_OFF}"


def strip_mk(s: str) -> str:
    return s.replace(MK_ON, "").replace(MK_OFF, "")


def vlen(s: str) -> int:
    return len(strip_mk(s))


def cut_cell(c: str, w: int) -> str:
    """Truncate to w visible characters, keeping an alarm marker intact."""
    if not w or vlen(c) <= w:
        return c
    return alarm(trunc(strip_mk(c), w)) if MK_ON in c else trunc(c, w)


def apply_marks(line: str, color: bool) -> str:
    """Turn markers into red (restoring the surrounding colour afterwards) or drop them."""
    if MK_ON not in line:
        return line
    if not color:
        return strip_mk(line)
    out, active = [], ""
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == MK_ON:
            out.append(ANSI["reset"] + ANSI["red"])
        elif ch == MK_OFF:
            out.append(ANSI["reset"] + active)
        elif ch == "\x1b":
            m = ANSI_CODE_RE.match(line, i)
            if m:
                code = m.group(0)
                active = "" if code == ANSI["reset"] else active + code
                out.append(code)
                i = m.end()
                continue
            out.append(ch)
        else:
            out.append(ch)
        i += 1
    return "".join(out)


class Doc:
    def __init__(self):
        self.blocks = []
        self.highlight: dict[str, str] = {}      # app name/domain -> severity (terminal colouring only)

    def h1(self, t): self.blocks.append(("h1", t))
    def h2(self, t): self.blocks.append(("h2", t))
    def h3(self, t): self.blocks.append(("h3", t))
    def kv(self, rows, status=None): self.blocks.append(("kv", rows))
    def text(self, t, sev=None): self.blocks.append(("text", t, sev))
    def bullet(self, t, sev=None, level=0): self.blocks.append(("bullet", t, sev, level))
    def table(self, headers, rows, align=None, maxw=None): self.blocks.append(("table", headers, rows, align, maxw))
    def blank(self): self.blocks.append(("blank",))
    def banner(self, t, sev=None): self.blocks.append(("banner", t, sev))
    def inline(self, label, parts): self.blocks.append(("inline", label, parts))

    # -- renderers
    def render(self, fmt: str, color: bool) -> str:
        return self._md() if fmt == "markdown" else self._txt(color)

    def _c(self, s, col, on):
        return f"{ANSI[col]}{s}{ANSI['reset']}" if on and col else s

    def _txt(self, color: bool) -> str:
        out = []
        for b in self.blocks:
            k = b[0]
            if k == "h1":
                out += ["", self._c("=" * W, "cyan", color), self._c(b[1].center(W), "bold", color), self._c("=" * W, "cyan", color)]
            elif k == "h2":
                out += ["", self._c("-" * W, "cyan", color), self._c(b[1].upper(), "cyan", color), self._c("-" * W, "cyan", color)]
            elif k == "h3":
                out += ["", self._c(f"▸ {b[1]}", "bold", color)]
            elif k == "kv":
                wk = max((len(r[0]) for r in b[1]), default=0)
                for r in b[1]:
                    val = str(r[1])
                    sev = r[2] if len(r) > 2 else None
                    room = max(30, W - wk - 5)
                    parts = wrap(val, room) if len(val) > room else [val]
                    for i, part in enumerate(parts):
                        lead = f"  {r[0]:<{wk}} : " if i == 0 else " " * (wk + 5)
                        out.append(lead + self._c(part.strip() if i else part, SEV_COLOR.get(sev), color and sev is not None))
            elif k == "text":
                for ln in wrap(b[1], W - 2):
                    out.append("  " + self._c(ln, SEV_COLOR.get(b[2]), color and b[2] is not None))
            elif k == "bullet":
                ind = "  " + "    " * b[3]
                tag = (SEV_TAG[b[2]] + " ") if b[2] else ""
                lines = wrap(tag + b[1], W - len(ind) - 2)
                for i, ln in enumerate(lines):
                    pre = ind + ("- " if i == 0 else "  ")
                    if i == 0 and tag and color:
                        ln = self._c(tag.strip(), SEV_COLOR[b[2]], True) + ln[len(tag.strip()):]
                    out.append(pre + ln)
            elif k == "table":
                out += render_table(b[1], b[2], b[3], b[4], color)
            elif k == "blank":
                out.append("")
            elif k == "inline":
                lead, cur, clen = f"  {b[1]:<7} ", "", 0
                for txt, sev in b[2]:
                    piece = self._c(txt, SEV_COLOR.get(sev), color and sev is not None)
                    if clen and clen + len(txt) + 3 > W - len(lead):
                        out.append(lead + cur)
                        lead, cur, clen = " " * len(lead), "", 0
                    cur, clen = (cur + " | " + piece, clen + len(txt) + 3) if clen else (piece, len(txt))
                out.append(lead + cur)
            elif k == "banner":
                col = SEV_COLOR.get(b[2]) if b[2] else "cyan"
                out.append(self._c("=" * W, col, color))
                if b[1]:
                    out += [self._c(b[1].center(W), col, color), self._c("=" * W, col, color)]
        out = [apply_marks(ln, color) for ln in out]
        if color and self.highlight:
            out = [self._highlight_line(ln) for ln in out]
        return "\n".join(out) + "\n"

    def _highlight_line(self, line: str) -> str:
        """Colour every CRITICAL/HIGH app name (and domain) in its severity colour, restoring the line colour after it."""
        if not hasattr(self, "_hl_re"):
            names = sorted(self.highlight, key=len, reverse=True)
            self._hl_re = re.compile(r"(?<![\w.-])(" + "|".join(re.escape(n) for n in names) + r")(?![\w-])") if names else None
        if self._hl_re is None or not self._hl_re.search(line):
            return line
        res, pos, active = [], 0, ""
        for m in self._hl_re.finditer(line):
            seg = line[pos:m.start()]
            codes = ANSI_CODE_RE.findall(seg)
            for c in codes:
                active = "" if c == ANSI["reset"] else active + c
            col = ANSI[SEV_COLOR[self.highlight[m.group(1)]]]
            res.append(seg + ANSI["reset"] + col + "\033[4m" + m.group(1) + ANSI["reset"] + active)
            pos = m.end()
        res.append(line[pos:])
        return "".join(res)

    def _md(self) -> str:
        out = []
        for b in self.blocks:
            k = b[0]
            if k == "h1":
                out += ["", f"# {b[1]}", ""]
            elif k == "h2":
                out += ["", f"## {b[1]}", ""]
            elif k == "h3":
                out += ["", f"### {b[1]}", ""]
            elif k == "kv":
                out += ["| Metric | Value |", "|---|---|"] + [f"| {r[0]} | {md_esc(r[1])} |" for r in b[1]] + [""]
            elif k == "text":
                out += [md_esc(b[1]), ""]
            elif k == "bullet":
                tag = f"**{SEV_TAG[b[2]]}** " if b[2] else ""
                out.append("  " * b[3] + f"- {tag}{md_esc(b[1])}")
            elif k == "table":
                maxw = b[4] or [0] * len(b[1])
                out.append("| " + " | ".join(b[1]) + " |")
                out.append("|" + "|".join("---:" if (b[3] and b[3][i] == "r") else "---" for i in range(len(b[1]))) + "|")
                for r in b[2]:
                    out.append("| " + " | ".join(md_esc(cut_cell(str(c), maxw[i])) for i, c in enumerate(r)) + " |")
                out.append("")
            elif k == "blank":
                out.append("")
            elif k == "banner" and b[1]:
                out += ["", f"## {b[1]}", ""]
            elif k == "inline":
                out += [f"**{b[1]}** " + " | ".join(f"**{t}**" if sv else t for t, sv in b[2]), ""]
        return "\n".join(out) + "\n"


def md_esc(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ").replace(MK_ON, "**").replace(MK_OFF, "**")


def wrap(text: str, width: int) -> list[str]:
    words, lines, cur = str(text).split(" "), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width and cur:
            lines.append(cur)
            cur = "  " + w if lines else w
        else:
            cur = f"{cur} {w}" if cur else w
    if cur:
        lines.append(cur)
    return lines or [""]


def render_table(headers, rows, align=None, maxw=None, color=False) -> list[str]:
    rows = [[str(c) for c in r] for r in rows]
    n = len(headers)
    align = align or (["l"] + ["r"] * (n - 1))
    if maxw:
        rows = [[cut_cell(c, maxw[i]) for i, c in enumerate(r)] for r in rows]
    widths = [max([len(headers[i])] + [vlen(r[i]) for r in rows]) for i in range(n)]

    def pad(c, i):
        gap = " " * (widths[i] - vlen(c))
        return gap + c if align[i] == "r" else c + gap

    def line(cells):
        return "  | " + " | ".join(pad(c, i) for i, c in enumerate(cells)) + " |"
    sep = "  +" + "+".join("-" * (w + 2) for w in widths) + "+"
    head = line(headers)
    if color:
        head = f"{ANSI['bold']}{head}{ANSI['reset']}"
    return [sep, head, sep] + [line(r) for r in rows] + [sep] if rows else ["  (no data)"]


def collect_alerts(R: dict, min_sev: str = "warning") -> list[dict]:
    """All findings at or above min_sev, de-duplicated, most severe first."""
    limit = SEV_ORDER[min_sev]
    out, seen = [], set()
    for p in R["top"]:
        for f in p["findings"]:
            if SEV_ORDER[f["severity"]] <= limit:
                out.append({**f, "app": p["app"], "domain": p.get("domain", "")})
    for f in R["server_findings"]:
        if SEV_ORDER[f["severity"]] <= limit:
            out.append({**f, "app": "(server)", "domain": ""})
    res = []
    for a in sorted(out, key=lambda x: (SEV_ORDER[x["severity"]], CONF_ORDER.get(x["confidence"], 9))):
        k = (a["app"], a["text"])
        if k not in seen:
            seen.add(k)
            res.append(a)
    return res


def short_action(a: str) -> str:
    a = a.split(";")[0].split(". ")[0].strip().rstrip(".")
    return trunc(a, 64)


def render_alert_section(d: "Doc", R: dict, title: str, levels: tuple, max_warn: int = 6):
    alerts = [a for a in collect_alerts(R) if a["severity"] in levels]
    shown = [a for a in alerts if a["severity"] != "warning"] + [a for a in alerts if a["severity"] == "warning"][:max_warn]
    worst = alerts[0]["severity"] if alerts else "ok"
    d.banner(title, worst)
    if not alerts:
        names = "/".join(SEV_NAME[x] for x in levels)
        d.text(f"[HEALTHY] No {names} findings.", "ok")
    for a in shown:
        d.blank()
        d.text(f"{SEV_TAG[a['severity']]} {a['text'].upper()}", a["severity"])
        rows = [("Application", a["app"] + (f" ({a['domain']})" if a["domain"] else ""))]
        rows += [(k, v) for k, v in a.get("metrics", [])]
        rows.append(("Confidence", a["confidence"]))
        rows.append(("Evidence", "; ".join(a["evidence"][:2]) or "-"))
        if a.get("action"):
            rows.append(("Next action", a["action"]))
        d.kv(rows)
    hidden = len(alerts) - len(shown)
    if hidden > 0:
        d.text(f"(+{hidden} more WARNING findings in section 9 and the Final Findings Summary)")


def render_server_bots(d: "Doc", R: dict):
    c = R.get("census")
    if not c:
        d.text("Skipped (--skip-bot-census)." if c is None else "No data.")
        return
    if not c["total"]:
        d.text("No access-log traffic found in the window.")
        return
    d.kv([("Backend requests (all apps)", f"{c['total']:,} across {c['apps_scanned']} application(s)"),
          ("Identified automated traffic", f"{c['bot_requests']:,} ({pct(c['bot_requests'], c['total']):.0f}%) from {c['distinct_bots']} bot(s)")])
    if not c["bots"]:
        d.text("No identifiable bots.")
        return
    d.table(["Bot", "Category", "Requests", "% all", "/min", "IPs", "Backend (dyn)", "Apps", "Top app"],
            [[b["name"], b["category_label"], f"{b['requests']:,}", f"{b['pct']:.1f}%", f"{b['rpm']:.1f}", b["unique_ips"],
              f"{b['dynamic']:,}", b["app_count"], b["apps"][0][0] if b["apps"] else "-"] for b in c["bots"]],
            align=["l", "l", "r", "r", "r", "r", "r", "r", "l"], maxw=[24, 28, 0, 0, 0, 0, 0, 0, 12])
    for b in c["bots"][:5]:
        d.bullet(f"{b['name']}: top IPs " + ", ".join(f"{ip} ({n:,})" for ip, n in b["top_ips"][:4]), None)
        d.bullet("top URLs " + ", ".join(f"{u} ({n:,})" for u, n in b["top_urls"]) +
                 " | status " + ", ".join(f"{k}:{v:,}" for k, v in b["status"]), None, 1)
    d.text("Category is from the User-Agent; search engines are 'verified' only after reverse+forward DNS succeeds. "
           "Per-app PHP cost of each bot is in section 6.")


LEVEL_SEV = {"HIGH": "high", "WARNING": "warning", "NORMAL": "ok"}


def render_bots(d: "Doc", p: dict):
    t = p.get("traffic") or {}
    bots = t.get("bots") or []
    d.h3(f"{p['app']} - Bot & crawler analysis")
    if not bots:
        d.text("No identifiable bot/crawler/automated traffic in the window.")
        return
    total = t["total"] or 1
    cat = dict(t.get("bot_by_category", []))
    d.kv([("Automated traffic", f"{t['bot_requests']:,} of {t['total']:,} backend requests ({pct(t['bot_requests'], total):.0f}%), "
                                f"{t['bot_dynamic']:,} dynamic"),
          ("By category", ", ".join(f"{BOT_CATEGORY_LABEL.get(k, k)} {v:,}" for k, v in cat.items())),
          ("Est. bot share of PHP CPU", f"{t.get('bot_php_cpu_share', 0):.0f}% (attributed by client IP via php-app.access.log; estimated)")])
    if any(b.get("level") == "HIGH" for b in bots):
        d.text("HIGH BOT TRAFFIC DETECTED", "high")
    d.table(["Bot", "Category", "Requests", "Share", "/min", "IPs", "Dyn%", "PHP CPU", "Status"],
            [[b["name"], b.get("category_label", b["category"]), f"{b['requests']:,}", f"{b['pct']:.0f}%", f"{b['rpm']:.1f}",
              b["unique_ips"], f"{pct(b['dynamic'], b['requests']):.0f}%", f"{b.get('php_cpu_share', 0):.0f}%", b.get("level", "-")]
             for b in bots[:12]],
            align=["l", "l", "r", "r", "r", "r", "r", "r", "l"], maxw=[26, 30, 0, 0, 0, 0, 0, 0, 0])
    for b in bots[:10]:
        if not (b.get("level") in ("HIGH", "WARNING") or b.get("impersonation")):
            d.bullet(f"{b['name']} top IPs: " + ", ".join(f"{ip} ({n:,})" for ip, n in b["top_ips"]), None)
    for b in [b for b in bots if b.get("level") in ("HIGH", "WARNING") or b.get("impersonation")][:4]:
        d.bullet(f"{b['name']} ({b['level']}): {b['requests']:,} requests, peak {b['peak_rpm']}/min, "
                 f"{b['dynamic']:,} dynamic / {b['static']:,} static"
                 + (f", frontend (nginx) {b['frontend']:,}" if b.get("frontend") else "")
                 + f", est. {b.get('php_requests_est', 0):,} PHP requests / {b.get('php_cpu_s_est', 0)}s PHP CPU",
                 LEVEL_SEV.get(b["level"], "warning"))
        d.bullet("Top IPs: " + ", ".join(f"{ip} ({n:,})" for ip, n in b["top_ips"]), None, 1)
        d.bullet("Top URLs: " + ", ".join(f"{u} ({n:,})" for u, n in b["top_urls"][:4]), None, 1)
        d.bullet("Status: " + ", ".join(f"{k}:{v:,}" for k, v in b["status"]), None, 1)
        if b.get("verification"):
            v = b["verification"]
            d.bullet(f"DNS verification: {v['status']} ({v['verified']} verified, {v['failed']} failed of {len(v['checked'])} IPs checked)",
                     "high" if b.get("impersonation") else None, 1)
    d.text("Bots cannot be attributed MySQL activity directly (no per-request DB data); see section 6 for database load.")


def req_flag(r: dict, a) -> str:
    f = []
    if r["dur"] >= a.very_slow_request_seconds:
        f.append("VERY SLOW")
    elif r["dur"] >= a.slow_request_seconds * 2:
        f.append("HIGH")
    elif r["dur"] >= a.slow_request_seconds:
        f.append("SLOW")
    if r["mem"] >= a.request_mem_high:
        f.append("HIGH-MEM")
    if r["status"][0] == "5":
        f.append(r["status"])
    return ",".join(f) or "-"


def render_slow_requests(d: "Doc", p: dict, a):
    fa, sl, t = p.get("fpm") or {}, p.get("slow") or {}, p.get("traffic") or {}
    if not fa.get("requests"):
        return
    d.text(f"Slow request analysis - thresholds: SLOW >= {a.slow_request_seconds:g}s, HIGH >= {a.slow_request_seconds * 2:g}s, "
           f"VERY SLOW >= {a.very_slow_request_seconds:g}s, HIGH-MEM >= {a.request_mem_high:g} MB (all configurable).")
    d.text("Wall = request duration; CPU s = CPU time actually used; Wait = time not on CPU (database, external HTTP, disk).")

    def rows(lst):
        return [[r["time"], r["method"], r["status"], f"{r['dur']:.2f}", f"{r['cpu_s']:.2f}",
                 f"{max(0.0, 100 - r['cpu_pct']):.0f}%", f"{r['mem']:.0f}", req_flag(r, a), r["uri"]] for r in lst[:10]]
    hdr = ["Time", "Mth", "St", "Wall s", "CPU s", "Wait", "MB", "Flag"]
    al = ["l", "l", "l", "r", "r", "r", "r", "l", "l"]
    mw = [0, 0, 0, 0, 0, 0, 0, 14, 40]
    if fa.get("slowest_requests"):
        d.table(hdr + ["URI - 10 slowest (wall time)"], rows(fa["slowest_requests"]), align=al, maxw=mw)
    if fa.get("top_cpu_requests"):
        d.table(hdr + ["URI - 10 highest CPU time"], rows(fa["top_cpu_requests"]), align=al, maxw=mw)
    if fa.get("top_mem_requests"):
        d.table(hdr + ["URI - 10 highest memory"], rows(fa["top_mem_requests"]), align=al, maxw=mw)
    if fa.get("repeated_slow_paths"):
        d.table(["Repeated slow URL", "Slow hits", "All hits", "Avg slow s", "Max s"],
                [[x["path"], x["slow_hits"], x["hits"], x["avg_slow_s"], x["max_s"]] for x in fa["repeated_slow_paths"]],
                maxw=[50, 0, 0, 0, 0])
    errs = [("PHP-FPM", x) for x in fa.get("fpm_5xx", [])] + [("access log", x) for x in t.get("http_5xx", [])]
    if errs:
        d.table(["Source", "Status", "URL", "Count"], [[src, x["status"], x["path"], f"{x['count']:,}"] for src, x in errs[:12]],
                align=["l", "l", "l", "r"], maxw=[0, 0, 56, 0])
        d.text("500 is returned by PHP itself; 502/503/504 come from the proxy/web server (PHP-FPM unavailable, timed out or saturated).")
    else:
        d.text("No HTTP 5xx responses in the window.", "ok")
    if sl.get("components"):
        tot = sum(sl["components"].values()) or 1
        d.table(["Plugin / theme / component (slow-log)", "Traces", "Share"],
                [[c, k, f"{pct(k, tot):.0f}%"] for c, k in sl["components"].most_common(8)], maxw=[44, 0, 0])


def mk(v, cond) -> str:
    """Mark v as alarming (red) when cond is true."""
    return alarm(v) if cond else str(v)


def findings_narrative(p: dict, a) -> tuple[list[str], list[str]]:
    """Turn an app's findings into plain-English sentences (impact, causes). Only measured facts; alarming values marked."""
    fnd = p.get("findings", [])

    def has(*keys):
        return next((f for f in fnd if f["severity"] in ("critical", "high", "warning") and _has(f, *keys)), None)
    t, fa, sl, db = p.get("traffic") or {}, p.get("fpm") or {}, p.get("slow") or {}, p.get("mysql") or {}
    impact, cause = [], []
    # ---- impact on visitors / the server
    if has("5xx") and t.get("total"):
        e5 = t.get("errors_5xx", 0)
        impact.append(f"{alarm(format(e5, ','))} of {t['total']:,} requests ({alarm(format(pct(e5, t['total']), '.1f') + '%')}) "
                      "ended in a server error (HTTP 5xx), so visitors saw failed pages.")
    if p.get("oom"):
        mx = max((e["rss_mb"] or 0) for e in p["oom"])
        impact.append(f"The server ran out of memory and the operating system stopped {alarm(len(p['oom']))} of this application's "
                      "PHP processes" + (f" (the largest was using {alarm(fmt_mb(mx))})" if mx else "") + ".")
    if has("worker exhaustion") or has("queued waiting"):
        txt = (f"PHP reached its limit of {alarm(p.get('max_children') or '?')} simultaneous workers "
               f"{alarm(p.get('fpm_hits', 0))} time(s)" if p.get("fpm_hits") else "All PHP workers were busy")
        if p.get("listen_queue_peak"):
            txt += f", and up to {alarm(format(p['listen_queue_peak'], ','))} requests were waiting in the queue for a free worker"
        impact.append(txt + ", which delays or times out page loads.")
    if has("terminated by request_terminate_timeout"):
        impact.append(f"{alarm(p.get('fpm_timeouts', 0))} PHP requests ran past the execution time limit and were stopped.")
    if has("Slow PHP execution") and fa.get("requests"):
        n, o5, o30 = fa["requests"], fa.get("over", {}).get(5, 0), fa.get("over", {}).get(30, 0)
        impact.append(f"Pages are slow: {alarm(format(o5, ','))} of {n:,} PHP requests took longer than 5 seconds"
                      + (f" ({alarm(format(o30, ','))} longer than 30 seconds)" if o30 else "")
                      + f"; 95% of requests finished within {alarm(fmt_s(fa.get('p95')))} and the slowest took {alarm(fmt_s(fa.get('max_dur')))}.")
    if has("top consumer") or has("High CPU from individual"):
        impact.append(f"Over the window the application used about {alarm(format(p['cpu_sustained'], '.0f') + '%')} of one CPU core "
                      f"({p['cpu_server_share']:.0f}% of the server)"
                      + (f" and {alarm(fmt_mb(p['mem_mb']))} of memory" if p.get("mem_mb") is not None and p.get("mem_pct", 0) >= a.mem_threshold
                         else (f" and {fmt_mb(p['mem_mb'])} of memory" if p.get("mem_mb") is not None else "")) + ".")
    # ---- causes
    if fa.get("top_paths_cpu") and (has("Slow PHP execution") or has("CPU cost") or has("disproportionate")):
        x = fa["top_paths_cpu"][0]
        cause.append(f"Most of the PHP work comes from {alarm(x['path'])} ({x['hits']:,} requests, about {x['avg_s']}s each, "
                     f"{x['cpu_s']:,.0f}s of CPU in total).")
    if has("CPU cost", "disproportionate") and p.get("cpu_ms_per_req"):
        cause.append(f"On average each PHP request needs {alarm(format(p['cpu_ms_per_req'], ',.0f') + ' ms')} of CPU time, "
                     "which points to heavy application code rather than visitor volume.")
    if sl.get("components") and has("slow-log traces"):
        comps = ", ".join(f"{k}" for k, _ in sl["components"].most_common(3))
        cause.append(f"Slow-request traces ({sl['entries']:,}) point mainly to {alarm(comps)}.")
    sdb = db.get("slow")
    if sdb and has("Recurring slow database"):
        fp = next((x for x in db.get("fingerprints", []) if not x["dump"]), None)
        cause.append(f"The database recorded {alarm(sdb['count'])} slow queries ({alarm(format(round(sdb['time']), ','))} seconds in total, "
                     f"slowest {alarm(format(sdb['max'], '.1f') + 's')})"
                     + (f"; the most expensive pattern ran {fp['count']} times, about {alarm(format(fp['avg'], '.1f') + 's')} each: "
                        f"{trunc(fp['fingerprint'], 90)}" if fp else "") + ".")
    live = db.get("live") or {}
    if has("database connections"):
        cause.append(f"It held up to {alarm(live.get('conn_peak', 0))} database connections at the same time.")
    bots = [b for b in t.get("bots", []) if b.get("level") in ("HIGH", "WARNING")]
    if bots and has("BOT TRAFFIC", "Elevated bot traffic"):
        b = bots[0]
        cause.append(f"Automated traffic is significant: {alarm(b['name'])} sent {alarm(format(b['requests'], ','))} requests "
                     f"({b['pct']:.0f}% of the traffic) from {b['unique_ips']:,} IPs, an estimated {b.get('php_cpu_share', 0):.0f}% of the PHP load.")
    if p.get("traffic_signals") and has("attack activity", "impersonation"):
        cause.append("The traffic also shows signs of abusive automation: " + "; ".join(x["text"] for x in p["traffic_signals"][:2]) + ".")
    if has("Long-running PHP requests"):
        cause.append(f"{alarm(len(p.get('long_busy', [])))} PHP workers stayed busy for the whole {a.sample_seconds:.0f}-second "
                     "live sample, i.e. individual requests were running for a long time.")
    if has("Background processes", "non-web processes"):
        cause.append("Background processes of the application (cron, CLI or workers) were also using significant CPU.")
    return impact, cause


def render_app_dossier(d: "Doc", R: dict, p: dict, a) -> None:
    """Everything about one CRITICAL/HIGH application in one customer-shareable block.

    Contains only this application's own data: no other applications, no internal PlatformOps notes.
    """
    sev = R.get("priority_apps", {}).get(p["app"], "warning")
    t, fa, sl = p.get("traffic") or {}, p.get("fpm") or {}, p.get("slow") or {}
    db = p.get("mysql") or {}
    name = p["app"] + (f" ({p['domain']})" if p.get("domain") else "")
    d.banner(f"APPLICATION REPORT: {name} [{SEV_NAME[sev]}]", sev)
    d.text(">>> BEGIN SHAREABLE APPLICATION REPORT >>>")
    d.kv([("Application", name), ("Type", p.get("type") or "-"), ("Window", R["window_desc"]),
          ("Generated", R["generated"] + " UTC")])
    # Summary & root cause
    d.h3("Summary")
    for ln in p.get("summary", []):
        d.text(ln)
    rc = p.get("root_cause") or {}
    d.kv([("Root cause", rc.get("text", "-")), ("Confidence", rc.get("confidence", "-"))])
    # Findings as plain-English paragraphs
    d.h3("Findings")
    counts = Counter(f["severity"] for f in p.get("findings", []))
    d.text("Overall: " + (", ".join(f"{counts[k]} {SEV_NAME[k]}" for k in ("critical", "high", "warning") if counts.get(k)) or "no issues")
           + " finding(s).", sev)
    impact, cause = findings_narrative(p, a)
    if impact:
        d.text("What is happening: " + " ".join(impact))
    if cause:
        d.text("Why: " + " ".join(cause))
    if not impact and not cause:
        shown = [f for f in p.get("findings", []) if f["severity"] in ("critical", "high", "warning")]
        d.text(" ".join(f"{f['text']}." for f in shown) or "No significant findings.")
    # Resource usage
    d.h3("Resource usage")
    d.kv([("CPU (window avg)", f"{p['cpu_sustained']:.0f}% of one CPU core ({p['cpu_server_share']:.0f}% of server capacity)"),
          ("CPU (live sample)", f"avg {p['cpu_live_avg']:.0f}% / peak {p['cpu_live_peak']:.0f}% of one core"
           if p.get("cpu_live_avg") is not None else "n/a"),
          ("Memory", f"{fmt_mb(p['mem_mb'])} {p['mem_kind']}" if p.get("mem_mb") is not None else "n/a"),
          ("PHP workers", f"{p.get('fpm_procs_last', 0)} running, busy peak {p['busy_peak']}, limit {p.get('max_children') or '?'}"
                          + (f", limit reached {p['fpm_hits']}x" if p.get("fpm_hits") else "")),
          ("Out-of-memory kills", (f"{len(p['oom'])} process(es) of this application stopped by the OS, last at {p['oom'][-1]['time']} UTC"
                                   if p.get("oom") else "none in the window"))])
    # Traffic
    d.h3("Traffic")
    if t.get("total"):
        cats = dict(t["categories"])
        d.kv([("Requests reaching the server", f"{t['total']:,} ({t['avg_rpm']:.1f}/min avg, peak {t['peak_rpm']:,}/min at {t['peak_rpm_at']} UTC)"),
              ("Dynamic (PHP) requests", f"{p['php_requests']:,}"),
              ("Unique visitor IPs", f"{t['unique_ips']:,}"),
              ("Status codes", ", ".join((alarm(f"{k}: {v:,}") if k[0] == "5" and pct(v, t["total"]) >= 5 or k in ("429", "403") and pct(v, t["total"]) >= 20
                                          else f"{k}: {v:,}") for k, v in t["status"])),
              ("WordPress", f"REST {cats.get('rest-api', 0) + cats.get('wc-rest', 0):,}, admin-ajax {cats.get('admin-ajax', 0):,}, "
                            f"wp-login {cats.get('wp-login', 0):,}, xmlrpc {cats.get('xmlrpc', 0):,}, wp-cron {cats.get('wp-cron', 0):,}, "
                            f"WooCommerce {cats.get('woocommerce', 0):,}")])
        d.table(["Most requested URL", "Requests", "%"],
                [[mk(x["url"], i == 0 or x["pct"] >= 20), mk(f"{x['requests']:,}", i == 0 or x["pct"] >= 20),
                  mk(f"{x['pct']:.1f}%", x["pct"] >= 20)] for i, x in enumerate(t["top_urls"][:5])], maxw=[56, 0, 0])
        flagged_ips = {ip for b in t.get("bots", []) if b.get("level") in ("HIGH", "WARNING") or b.get("impersonation")
                       for ip, _ in b["top_ips"]}
        d.table(["Top visitor IP", "Requests", "%", "Mostly"],
                [[mk(x["ip"], i == 0 or x["pct"] >= 10 or x["ip"] in flagged_ips), mk(f"{x['requests']:,}", i == 0 or x["pct"] >= 10),
                  mk(f"{x['pct']:.1f}%", x["pct"] >= 10), x["top_target"]] for i, x in enumerate(t["top_ips"][:5])],
                align=["l", "r", "r", "l"])
        for sg in p.get("traffic_signals", []):
            d.bullet(sg["text"], "warning")
    else:
        d.text("No access-log traffic in the window.")
    # Bots
    bots = t.get("bots") or []
    if bots:
        d.h3("Bots and crawlers")
        d.table(["Bot", "Type", "Requests", "Share", "/min", "IPs", "Dynamic %", "Est. PHP CPU"],
                [[mk(b["name"], b.get("level") == "HIGH" or b.get("impersonation")), mk(b.get("category_label", b["category"]), b.get("impersonation")),
                  mk(f"{b['requests']:,}", b.get("level") == "HIGH"), mk(f"{b['pct']:.0f}%", b["pct"] >= a.bot_share_high),
                  f"{b['rpm']:.1f}", f"{b['unique_ips']:,}", f"{pct(b['dynamic'], b['requests']):.0f}%",
                  mk(f"{b.get('php_cpu_share', 0):.0f}%", b.get("php_cpu_share", 0) >= 25)] for b in bots[:6]],
                align=["l", "l", "r", "r", "r", "r", "r", "r"], maxw=[30, 26, 0, 0, 0, 0, 0, 0])
        for b in bots[:6]:
            hot = b.get("level") == "HIGH" or b.get("impersonation")
            d.bullet(f"{b['name']} - top IPs: " + ", ".join(mk(f"{ip} ({n:,})", hot and k == 0) for k, (ip, n) in enumerate(b["top_ips"])), None)
            if b["category"] == "suspicious" and b.get("ua_sample"):
                d.bullet(f"example User-Agent: {b['ua_sample']}", None, 1)
    # Slow PHP
    d.h3("Slow PHP requests")
    if fa.get("requests"):
        d.kv([("PHP requests", f"{fa['requests']:,}"),
              ("Duration", f"avg {fmt_s(fa.get('avg_dur'))}, p95 {fmt_s(fa.get('p95'))}, max {fmt_s(fa.get('max_dur'))}"),
              ("Requests >= 5s / >= 30s", f"{fa.get('over', {}).get(5, 0):,} / {fa.get('over', {}).get(30, 0):,}"),
              ("Memory per request", f"avg {fmt_mb(fa.get('avg_mem'))}, max {fmt_mb(fa.get('mem_max'))}")])
        if fa.get("slowest_requests"):
            d.table(["Time (UTC)", "Status", "Duration s", "CPU s", "Waiting", "MB", "URL (slowest)"],
                    [[r["time"], mk(r["status"], r["status"][0] == "5"), mk(f"{r['dur']:.2f}", r["dur"] >= a.slow_request_seconds),
                      f"{r['cpu_s']:.2f}", f"{max(0.0, 100 - r['cpu_pct']):.0f}%", mk(f"{r['mem']:.0f}", r["mem"] >= a.request_mem_high),
                      mk(r["uri"], r["dur"] >= a.very_slow_request_seconds)] for r in fa["slowest_requests"][:5]],
                    align=["l", "l", "r", "r", "r", "r", "l"], maxw=[0, 0, 0, 0, 0, 0, 44])
        if fa.get("repeated_slow_paths"):
            d.table(["Repeatedly slow URL", "Slow requests", "Avg s", "Max s"],
                    [[mk(x["path"], i == 0), mk(f"{x['slow_hits']:,}", i == 0), x["avg_slow_s"], mk(x["max_s"], x["max_s"] >= a.very_slow_request_seconds)]
                     for i, x in enumerate(fa["repeated_slow_paths"][:5])], maxw=[50, 0, 0, 0])
        if sl.get("components"):
            d.text("Plugins/themes seen in slow-request traces: " +
                   ", ".join(f"{c} ({k})" for c, k in sl["components"].most_common(5)))
        errs = fa.get("fpm_5xx", []) + t.get("http_5xx", [])
        if errs:
            d.text("Server errors: " + ", ".join(alarm(f"{x['status']} {x['path']} ({x['count']:,})") for x in errs[:6]))
    else:
        d.text("No PHP-FPM access-log data in the window.")
    # MySQL
    d.h3("Database (MySQL) slow queries")
    sdb, fps = db.get("slow"), [x for x in db.get("fingerprints", []) if not x["dump"]]
    if sdb:
        d.kv([("Database", p["db"]), ("Slow queries", alarm(f"{sdb['count']:,} (total {sdb['time']:.0f}s, max {sdb['max']:.1f}s)")
                                                       if sdb["time"] >= 300 else f"{sdb['count']:,} (total {sdb['time']:.0f}s, max {sdb['max']:.1f}s)")])
        if fps:
            d.table(["Count", "Total s", "Avg s", "Max s", "Rows examined", "Query pattern (values masked)"],
                    [[mk(x["count"], i == 0), mk(f"{x['time']:.0f}", i == 0), mk(f"{x['avg']:.1f}", x["avg"] >= 10),
                      mk(f"{x['max']:.1f}", x["max"] >= 30), f"{x['avg_rows_ex']:,.0f}", mk(x["fingerprint"], i == 0)]
                     for i, x in enumerate(fps[:5])], maxw=[0, 0, 0, 0, 0, 54])
    else:
        d.text("No slow queries recorded for this application's database in the window."
               if R["mysql"].get("available") else "Database data was not available for this investigation.")
    live = db.get("live")
    if live:
        d.text(f"Database connections during sampling: avg {live['conn_avg']:.1f}, peak {live['conn_peak']}; "
               f"running queries peak {live['running_peak']}.")
    # Recommendations that apply to this app (customer wording only)
    labels = {p["app"], p.get("domain") or ""}
    recs = [c for c in R["customer"] if set(c.get("apps") or []) & labels]
    d.h3("Recommendations")
    if recs:
        for c in recs:
            d.text(c["title"])
            d.text(c["text"])
            d.blank()
    else:
        d.text("See the findings above; no specific customer recommendation was generated for this application.")
    d.text("<<< END SHAREABLE APPLICATION REPORT <<<")


def map_label(app: str, src: str | None) -> str:
    if not app:
        return "unmapped"
    return f"{app} ({'naming' if src and src.startswith('naming') else 'config'})"


def sev_for(v, warn, crit):
    if v is None:
        return None
    return "critical" if v >= crit else "warning" if v >= warn else "ok"


def app_severity_map(R: dict) -> dict[str, str]:
    """Worst severity per app, only for apps with CRITICAL/HIGH findings."""
    worst = {}
    for p in R["top"]:
        sevs = [f["severity"] for f in p.get("findings", []) if f["severity"] in ("critical", "high")]
        if sevs:
            worst[p["app"]] = min(sevs, key=lambda x: SEV_ORDER[x])
    return worst


def _metric(v, warn, crit, text):
    """(text, severity) for one compact server metric."""
    sev = None if v is None else "critical" if v >= crit else "warning" if v >= warn else None
    return text, sev


def build_compact(ctx: Ctx, R: dict) -> "Doc":
    """Compact summary: only what matters, one screen per app. The full report is --full / --report."""
    a = ctx.args
    d = Doc()
    R.setdefault("priority_apps", app_severity_map(R))
    for p in R["top"]:
        sev = R["priority_apps"].get(p["app"])
        if sev:
            d.highlight[p["app"]] = sev
    h, hist = R["health"], R["health"].get("history") or {}
    d.banner("CLOUDWAYS INVESTIGATION SUMMARY", None)
    d.text(f"{R['hostname']} ({R['server_ip']}) | {R['window_desc']} | {NCPU} vCPU, {fmt_mb(h.get('mem_total_mb'))} RAM | "
           f"{'root' if ctx.is_root else 'NON-ROOT: partial data'} | v{VERSION}")
    # --- server line (each metric coloured on its own)
    cb = (hist.get("cpu_busy") or (None, None))
    load = h.get("load", (0, 0, 0))
    swap_pct = pct(h.get("swap_used_mb", 0), h.get("swap_total_mb") or 0)
    parts = [
        _metric(cb[0] if cb[0] is not None else h.get("cpu_busy"), 70, 90,
                f"CPU {h.get('cpu_busy', 0):.0f}% now" + (f", {cb[0]:.0f}% avg / {cb[1]:.0f}% peak in window" if cb[0] is not None else "")),
        _metric(h.get("mem_used_pct"), 85, 95, f"RAM {h.get('mem_used_pct', 0):.0f}% of {fmt_mb(h.get('mem_total_mb'))}"),
        _metric(swap_pct, 30, 60, f"swap {fmt_mb(h.get('swap_used_mb'))}/{fmt_mb(h.get('swap_total_mb'))}"),
        _metric(load[1] / NCPU, 1.0, 2.0, f"load {load[1]:.1f}"),
        _metric(h.get("steal"), a.steal_threshold, 15, f"steal {h.get('steal', 0):.1f}%"),
        _metric(h.get("iowait"), 10, 25, f"iowait {h.get('iowait', 0):.1f}%"),
        _metric(len(R["oom"]["events"]), 1, 1, f"OOM kills {len(R['oom']['events'])}"),
    ]
    for fs in h.get("filesystems", []):
        if fs["used_pct"] >= 85:
            parts.append(_metric(fs["used_pct"], 85, 95, f"disk {fs['mount']} {fs['used_pct']:.0f}%"))
    d.inline("SERVER", parts)
    o = R["origin"]
    d.text(f"ORIGIN  {o['text']} [{o['confidence']}]", "ok" if o["origin"] == "none" else "warning")
    # --- alerts, one line each
    alerts = collect_alerts(R)
    big = [x for x in alerts if x["severity"] in ("critical", "high")]
    d.banner(f"CRITICAL & HIGH FINDINGS ({len(big)})", big[0]["severity"] if big else "ok")
    if not big:
        d.text("[HEALTHY] No CRITICAL or HIGH findings.", "ok")
    for x in big:
        key = "; ".join(f"{k} {v}" for k, v in x.get("metrics", [])[:2]) or (x["evidence"][0] if x["evidence"] else "")
        d.text(f"{SEV_TAG[x['severity']]:<11}{x['app']:<14} {x['text']} - {key}", x["severity"])
    warn = [x for x in alerts if x["severity"] == "warning"]
    if warn:
        d.text(f"+{len(warn)} WARNING: " + "; ".join(f"{x['app']}: {trunc(x['text'], 50)}" for x in warn[:4])
               + (" ..." if len(warn) > 4 else ""), "warning")
    # --- top apps
    d.h3(f"Top {len(R['top'])} applications")
    rows = []
    for i, p in enumerate(R["top"], 1):
        t, fa = p.get("traffic") or {}, p.get("fpm") or {}
        rows.append([i, p["app"], trunc(p.get("domain") or "-", 26), f"{p['cpu_sustained']:.0f}%", f"{p['cpu_server_share']:.0f}%",
                     fmt_mb(p["mem_mb"]) if p.get("mem_mb") is not None else "n/a",
                     f"{p['php_requests'] / max(getattr(a, 'window_s', 3600) / 60, 1):.0f}", fmt_s(fa.get("p95")),
                     f"{pct(t.get('bot_requests', 0), t.get('total') or 1):.0f}%" if t.get("total") else "-",
                     f"{p['busy_peak']}/{p.get('max_children') or '?'}",
                     SCENARIO_SHORT.get(p["root_cause"]["primary"], "no bottleneck")])
    d.table(["#", "App", "Domain", "CPU core", "Srv", "Memory", "PHP/min", "p95", "Bots", "Workers", "Root cause"], rows,
            align=["r", "l", "l", "r", "r", "r", "r", "r", "r", "r", "l"])
    # --- top bots (server)
    c = R.get("census")
    if c and c.get("bots"):
        d.h3(f"Top bots (server: {c['bot_requests']:,} of {c['total']:,} requests = {pct(c['bot_requests'], c['total']):.0f}%)")
        d.table(["Bot", "Type", "Requests", "%", "/min", "IPs", "Top IP", "Top app"],
                [[b["name"], b["category_label"], f"{b['requests']:,}", f"{b['pct']:.1f}%", f"{b['rpm']:.1f}", b["unique_ips"],
                  f"{b['top_ips'][0][0]} ({b['top_ips'][0][1]:,})" if b["top_ips"] else "-",
                  b["apps"][0][0] if b["apps"] else "-"] for b in c["bots"][:5]],
                align=["l", "l", "r", "r", "r", "r", "l", "l"], maxw=[26, 26, 0, 0, 0, 0, 30, 14])
    # --- per-app digest
    d.h3("Application digest")
    for p in R["top"]:
        t, fa, sl = p.get("traffic") or {}, p.get("fpm") or {}, p.get("slow") or {}
        rc = p["root_cause"]
        sev = R["priority_apps"].get(p["app"])
        d.text(f"{p['app']} ({p.get('domain') or p['type']})"
               + (f" [alias: {', '.join(p['aliases'])}]" if p.get("aliases") else "")
               + f" - {rc['text']} [{rc['confidence']}]", sev)
        rows = []
        if t.get("total"):
            bots = [b for b in t.get("bots", []) if b["pct"] >= 1][:2]
            e5 = t.get("errors_5xx", 0)
            rows.append(("Traffic", f"{t['total']:,} req, {t['avg_rpm']:.0f}/min (peak {t['peak_rpm']:,} at {t['peak_rpm_at']}), "
                                    f"{t['unique_ips']:,} IPs" + (f", 5xx {e5:,}" if e5 else "")
                                    + (", bots " + ", ".join(f"{b['name']} {b['pct']:.0f}%" for b in bots) if bots else "")))
        if fa.get("requests"):
            rows.append(("PHP", f"{fa['requests']:,} req, p95 {fmt_s(fa.get('p95'))}, {fa.get('cpu_ms_per_req') or 0:,.0f} ms CPU/req, "
                                f"max {fmt_mb(fa.get('mem_max'))}/req, workers {p['busy_peak']}/{p.get('max_children') or '?'}"
                                + (f", max_children hit {p['fpm_hits']}x" if p.get("fpm_hits") else "")))
            if fa.get("repeated_slow_paths"):
                rows.append(("Slow URLs", ", ".join(f"{x['path']} {x['slow_hits']}x (avg {x['avg_slow_s']}s)"
                                                    for x in fa["repeated_slow_paths"][:3])))
        if sl.get("components"):
            rows.append(("Slow-log", ", ".join(f"{k} ({v})" for k, v in sl["components"].most_common(3))))
        db = p.get("mysql") or {}
        if db.get("slow"):
            fp = next((x for x in db.get("fingerprints", []) if not x["dump"]), None)
            rows.append(("MySQL", f"{db['slow']['count']:,} slow queries ({db['slow']['time']:.0f}s)"
                                  + (f" - top: {trunc(fp['fingerprint'], 70)} ({fp['count']}x, avg {fp['avg']:.1f}s)" if fp else "")))
        if p.get("oom"):
            mx = max((e["rss_mb"] or 0) for e in p["oom"])
            rows.append(("OOM", f"{len(p['oom'])} kill(s)" + (f", largest {fmt_mb(mx)}" if mx else "")))
        worst = next((f for f in p.get("findings", []) if f["severity"] in ("critical", "high", "warning")), None)
        if worst and worst.get("action"):
            rows.append(("Next", short_action(worst["action"])))
        if rows:
            d.kv(rows)
        d.blank()
    # --- customer recommendations
    d.h3("Customer-shareable recommendations")
    for cr in R["customer"]:
        d.text(cr["title"] + (f" ({', '.join(cr['apps'])})" if cr.get("apps") else ""))
        d.text(cr["text"])
        d.blank()
    d.text("More: --full (complete 12-section report) | --app-reports-only (shareable per-app reports) | --report (save all to files)")
    return d


def build_app_reports(ctx: Ctx, R: dict) -> dict[str, "Doc"]:
    """One standalone, shareable Doc per CRITICAL/HIGH application."""
    R.setdefault("priority_apps", app_severity_map(R))
    out = {}
    for p in sorted([p for p in R["top"] if p["app"] in R["priority_apps"]],
                    key=lambda x: SEV_ORDER[R["priority_apps"][x["app"]]]):
        d = Doc()
        d.highlight = {p["app"]: R["priority_apps"][p["app"]]}
        render_app_dossier(d, R, p, ctx.args)
        out[p["app"]] = d
    return out


def build_report(ctx: Ctx, R: dict) -> Doc:
    d = Doc()
    R["priority_apps"] = app_severity_map(R)
    for p in R["top"]:
        sev = R["priority_apps"].get(p["app"])
        if sev:
            d.highlight[p["app"]] = sev
            if p.get("domain") and "cloudwaysapps.com" not in p["domain"]:
                d.highlight[p["domain"]] = sev
    top, h, hist = R["top"], R["health"], R["health"].get("history") or {}
    d.h1("CLOUDWAYS APPLICATION INVESTIGATION REPORT")
    # 1. Overview
    d.h2("Investigation Overview")
    d.kv([("Server", f"{R['hostname']} ({R['server_ip']})"), ("Generated At", R["generated"] + " UTC"),
          ("Traffic/log window", R["window_desc"]), ("Live sampling", f"{R['sample']['elapsed']:.0f}s, {R['sample']['samples']} samples"),
          ("Applications", f"Top {len(top)} of {R['app_count']} investigated"),
          ("Privileges", "root" if ctx.is_root else "NON-ROOT (some data unavailable)"),
          ("History source", f"atop ({hist.get('intervals', 0)} x {hist.get('interval_s', 0)}s intervals)" if hist else "none (live + logs only)"),
          ("Tool version", VERSION)])
    d.text("CPU values are '% of one vCPU core' unless marked 'of server'. 'Estimated' marks derived values; everything else is measured.")
    d.text("Severity: CRITICAL (red) > HIGH (orange) > WARNING (yellow) > INFO (blue) > HEALTHY (green).")
    # 1-2. Alerts first
    render_alert_section(d, R, "1. CRITICAL FINDINGS", ("critical",))
    render_alert_section(d, R, "2. HIGH-PRIORITY FINDINGS", ("high", "warning"))
    prio = [p for p in top if p["app"] in R["priority_apps"]]
    if prio and not ctx.args.no_app_reports:
        d.text(f"Application reports follow for {len(prio)} CRITICAL/HIGH application(s): "
               + ", ".join(p["app"] for p in prio) + ". Each block is self-contained and safe to share with that customer.")
        for p in sorted(prio, key=lambda x: SEV_ORDER[R["priority_apps"][x["app"]]]):
            render_app_dossier(d, R, p, ctx.args)
    # 3. Top apps
    d.h2(f"3. Top {len(top)} Resource-Consuming Applications")
    def pc(v):
        return f"{v:.0f}%" if v is not None else "n/a"
    d.text("CPU and memory - LIVE (instantaneous, during sampling) vs WINDOW (historical average over the log window):")
    d.table(["#", "Application", "CPU live", "CPU live pk", "CPU window", "CPU win pk", "Srv%", "Mem live", "Mem window"],
            [[i, p["app"], pc(p.get("cpu_live_avg")), pc(p.get("cpu_live_peak")),
              pc(p["cpu_hist_avg"] if p.get("cpu_hist_avg") is not None else p.get("cpu_fpm_pct")),
              pc(p.get("cpu_hist_peak")), f"{p['cpu_server_share']:.0f}%",
              (f"{fmt_mb(p['mem_mb'])} {p['mem_kind']}" if p['mem_mb'] is not None else "n/a"), fmt_mb(p.get("mem_hist_avg")) + (" RSS" if p.get("mem_hist_avg") else "")]
             for i, p in enumerate(top, 1)],
            align=["r", "l", "r", "r", "r", "r", "r", "r", "r"], maxw=[0, 12, 0, 0, 0, 0, 0, 0, 0])
    d.text("CPU in % of one vCPU core. Srv% = sustained CPU as share of total server capacity (used for ranking).")
    d.table(["#", "Application", "PHP req", "Backend req", "FPM procs", "Busy pk", "Idle", "max_children", "Profile"],
            [[i, p["app"], fmt_num(p["php_requests"]), fmt_num((p.get("traffic") or {}).get("total")),
              p.get("fpm_procs_last", 0), p["busy_peak"], max(0, p.get("fpm_procs_last", 0) - p.get("busy_last", 0)),
              p.get("max_children") or "?", ", ".join(p["tags"])] for i, p in enumerate(top, 1)],
            align=["r", "l", "r", "r", "r", "r", "r", "r", "l"], maxw=[0, 12, 0, 0, 0, 0, 0, 0, 30])
    for p in top:
        d.bullet(f"{p['app']}: {p['domain'] or 'domain n/a'} [{p['type']}] path {p['app_dir']}"
                 + (f" (alias: {', '.join(p['aliases'])} - counted once)" if p.get("aliases") else "") + f" | DB '{p['db']}' "
                 f"(mapping: {p['db_source']}) | CPU source: {p['cpu_source']}"
                 + (f" | live {p['cpu_live_avg']:.0f}%/peak {p['cpu_live_peak']:.0f}%" if p.get("cpu_live_avg") is not None else "")
                 + (f" | history peak {p['cpu_hist_peak']:.0f}% at {p['cpu_hist_peak_at']}" if p.get("cpu_hist_peak") is not None else "")
                 + f" | memory {p['mem_kind']}" + (f", history avg {fmt_mb(p['mem_hist_avg'])} RSS" if p.get("mem_hist_avg") else ""))
    # 4. Server-wide bots
    d.h2(f"4. Top {ctx.args.server_bots_top} Bots Across the Server")
    render_server_bots(d, R)
    # 2. Server health
    d.h2("5. Overall Server Health")
    load = h.get("load", (0, 0, 0))
    rows = [("vCPUs", NCPU),
            ("CPU busy (live)", f"{h.get('cpu_busy', 0):.0f}% avg / {h.get('cpu_busy_peak', 0):.0f}% peak", sev_for(h.get("cpu_busy"), 70, 90))]
    if hist.get("cpu_busy", (None,))[0] is not None:
        rows.append(("CPU busy (history)", f"{hist['cpu_busy'][0]:.0f}% avg / {hist['cpu_busy'][1]:.0f}% peak", sev_for(hist["cpu_busy"][0], 60, 80)))
    rows += [("Load average", f"{load[0]:.2f} {load[1]:.2f} {load[2]:.2f}", sev_for(load[1] / NCPU, 1.0, 2.0)),
             ("Memory used", f"{fmt_mb(h.get('mem_used_mb'))} / {fmt_mb(h.get('mem_total_mb'))} ({h.get('mem_used_pct', 0):.0f}%)", sev_for(h.get("mem_used_pct"), 80, 92)),
             ("Swap used", f"{fmt_mb(h.get('swap_used_mb'))} / {fmt_mb(h.get('swap_total_mb'))}", sev_for(pct(h.get('swap_used_mb', 0), h.get('swap_total_mb') or 0), 30, 60)),
             ("I/O wait", f"{h.get('iowait', 0):.1f}%", sev_for(h.get("iowait"), 10, 25)),
             ("CPU steal", f"{h.get('steal', 0):.1f}% (peak {h.get('steal_peak', 0):.1f}%)", sev_for(h.get("steal"), 5, 15)),
             ("OOM events", len(R["oom"]["events"]), "critical" if R["oom"]["events"] else "ok")]
    psi = h.get("psi", {})
    if any(psi.values()):
        rows.append(("Pressure (avg60)", ", ".join(f"{k} {v.get('some', 0):.1f}%" for k, v in psi.items() if v)))
    for fs in h.get("filesystems", []):
        rows.append((f"Disk {fs['mount']}", f"{fs['used_pct']:.0f}% of {fs['size_gb']:.0f} GB, inodes {fs['inode_pct']:.0f}%", sev_for(fs["used_pct"], 85, 95)))
    for dk in h.get("disks", [])[:3]:
        rows.append((f"I/O {dk['dev']}", f"util {dk['util']:.0f}% (peak {dk['util_peak']:.0f}%), await {dk['await_ms']:.1f} ms, {dk['iops']:.0f} IOPS"))
    for n in h.get("net", [])[:2]:
        rows.append((f"Network {n['dev']}", f"rx {n['rx_mbps']:.1f} / tx {n['tx_mbps']:.1f} Mbit/s"))
    d.kv(rows)
    if R["oom"]["events"]:
        d.h3("OOM killer events")
        d.table(["Time (UTC)", "Killed process", "PID", "Owner", "Memory at kill", "Triggered by", "Scope"],
                [[e["time"], e["process"], e["pid"], f"{e['owner_kind']}: {e['owner']}",
                  fmt_mb(e["rss_mb"]) if e["rss_mb"] else "n/a", e["trigger"] or "-", "cgroup limit" if e["memcg"] else "server RAM"]
                 for e in R["oom"]["events"][:15]],
                align=["l", "l", "r", "l", "r", "l", "l"], maxw=[0, 16, 0, 26, 0, 16, 0])
        if len(R["oom"]["events"]) > 15:
            d.text(f"(+{len(R['oom']['events']) - 15} more OOM kills)")
        d.text("Owner comes from the killed process's UID (app system user) or its systemd cgroup; memory = anon+shmem RSS at kill time.")
    d.h3("Resource attribution (live sampling)")
    attr = [[name, f"{s['cpu']:.0f}%", f"{s['cpu'] / NCPU:.0f}%", fmt_mb(s["mem_mb"]), f"{pct(s['mem_mb'], h.get('mem_total_mb') or 1):.0f}%"]
            for name, s in R["attribution"]]
    d.table(["Consumer", "CPU core%", "Server%", "Memory", "RAM%"], attr[:12])
    d.text("Shared services (MySQL, Redis, Varnish, ...) are shown separately and are NOT attributed to applications.")
    o = R["origin"]
    d.kv([("Issue origin", o["text"], "ok" if o["origin"] == "none" else "warning"), ("Confidence", o["confidence"])])
    for e in o["evidence"]:
        d.bullet(e, None, 1)
    if R.get("redis") and "used_mb" in R["redis"]:
        r = R["redis"]
        d.bullet(f"Redis: used {fmt_mb(r['used_mb'])} (RSS {fmt_mb(r['rss_mb'])}), maxmemory {fmt_mb(r['maxmemory_mb']) if r['maxmemory_mb'] else 'unlimited'}, "
                 f"policy {r['policy']}, evicted keys {r['evicted']:,}")
    if R.get("varnish") and R["varnish"].get("hit_ratio") is not None:
        d.bullet(f"Varnish: hit ratio {R['varnish']['hit_ratio']:.0f}% since service start, LRU nuked {R['varnish']['lru_nuked']:,}")
    for f in R["server_findings"]:
        d.bullet(f"{f['text']} ({f['confidence']}): " + "; ".join(f["evidence"][:2]), f["severity"])
        if f.get("action"):
            d.bullet("Next action: " + f["action"], None, 1)
    # 4. Traffic
    d.h2("6. Application Traffic & Bot Analysis")
    for p in top:
        t = p.get("traffic") or {}
        d.h3(p["app"] + (f" ({p['domain']})" if p["domain"] else ""))
        if not t.get("total"):
            d.text("No access-log traffic found in the window." if t.get("files") is not None else "No access logs available.")
            continue
        cats = dict(t["categories"])
        d.kv([("Backend requests", f"{t['total']:,} ({t['avg_rpm']:.1f}/min, {t['avg_rps']:.2f}/s avg)" +
               (f"; frontend (nginx) {t['frontend_total']:,}" if t.get("frontend_total") else "")),
              ("Peak", f"{t['peak_rpm']:,} req/min at {t['peak_rpm_at']} UTC, {t['peak_rps']} req/s"),
              ("Unique IPs", f"{t['unique_ips']:,}"),
              ("Dynamic / static", f"{t['dynamic']:,} / {t['static']:,}"),
              ("PHP requests (FPM log)", f"{p['php_requests']:,}"),
              ("WordPress", f"REST {cats.get('rest-api', 0) + cats.get('wc-rest', 0):,} | admin-ajax {cats.get('admin-ajax', 0):,} | "
                            f"wp-admin {cats.get('wp-admin', 0):,} | wp-login {cats.get('wp-login', 0):,} (POST {t['login_post']:,}) | "
                            f"xmlrpc {cats.get('xmlrpc', 0):,} | wp-cron {cats.get('wp-cron', 0):,}"),
              ("WooCommerce", f"{cats.get('woocommerce', 0) + cats.get('wc-rest', 0):,}"),
              ("Status codes", ", ".join(f"{k}:{v:,}" for k, v in t["status"])),
              ("Client types", ", ".join(f"{k} {pct(v, t['total']):.0f}%" for k, v in t["ua_classes"]))])
        d.table(["Top IP", "Requests", "%", "Mostly"], [[x["ip"], f"{x['requests']:,}", f"{x['pct']:.1f}%", x["top_target"]] for x in t["top_ips"][:5]],
                align=["l", "r", "r", "l"])
        d.table(["Top URL", "Requests", "%"], [[x["url"], f"{x['requests']:,}", f"{x['pct']:.1f}%"] for x in t["top_urls"][:6]], maxw=[60, 0, 0])
        d.table(["Top User-Agent", "Class", "Req", "IPs"], [[x["ua"], x["class"], f"{x['requests']:,}", x["ips"]] for x in t["top_uas"][:5]],
                align=["l", "l", "r", "r"], maxw=[52, 0, 0, 0])
        for s in p.get("traffic_signals", []):
            d.bullet(s["text"], "warning")
        if not p.get("traffic_signals"):
            d.bullet("No suspicious-traffic indicators triggered.", "ok")
        render_bots(d, p)
    top = R["top"]
    # 5. PHP-FPM
    d.h2("7. PHP-FPM Investigation & Slow Requests")
    for p in top:
        pool, fa, sl = p.get("pool") or {}, p.get("fpm") or {}, p.get("slow") or {}
        d.h3(f"{p['app']} - pool {pool.get('pool', '?')} (PHP {pool.get('php_version', '?')})")
        mc = p.get("max_children")
        d.kv([("Pool config", f"pm={pool.get('pm', '?')} max_children={mc or '?'} start={pool.get('pm.start_servers', '?')} "
                              f"spare={pool.get('pm.min_spare_servers', '?')}-{pool.get('pm.max_spare_servers', '?')} "
                              f"max_requests={pool.get('pm.max_requests', '?')}"),
              ("Timeouts", f"request_terminate_timeout={pool.get('request_terminate_timeout', 'unset')} "
                           f"slowlog_timeout={pool.get('request_slowlog_timeout', 'unset')}"),
              ("Workers (live)", f"{p.get('fpm_procs_last', 0)} FPM workers now; busy avg {p['busy_avg']:.1f} / peak {p['busy_peak']}; "
                                 f"idle now {max(0, p.get('fpm_procs_last', 0) - p.get('busy_last', 0))} (busy = R/D state or CPU activity, estimated)",
               sev_for(p["busy_peak"] / mc if mc else None, 0.7, 1.0)),
              ("Listen queue (live)", f"peak {p.get('listen_queue_peak', 0)}" if p.get("listen_queue_measured") else "not measured (ss unavailable)",
               "critical" if p.get("listen_queue_peak") else "ok" if p.get("listen_queue_measured") else None),
              ("max_children reached", f"{p.get('fpm_hits', 0)} time(s) in window", "critical" if p.get("fpm_hits") else "ok"),
              ("Terminated (timeout)", f"{p.get('fpm_timeouts', 0)}", "critical" if p.get("fpm_timeouts") else "ok"),
              ("Requests (FPM log)", f"{fa.get('requests', 0):,}" + ("" if fa.get("available") else " (php-app.access.log not found)")),
              ("Duration", f"avg {fmt_s(fa.get('avg_dur'))}, p50 {fmt_s(fa.get('p50'))}, p95 {fmt_s(fa.get('p95'))}, max {fmt_s(fa.get('max_dur'))}",
               sev_for(fa.get("p95"), 2, 8)),
              ("CPU time", f"{fa.get('cpu_s', 0):,.0f}s total, {fa.get('cpu_ms_per_req') or 0:.0f} ms/request"),
              ("Memory / request", f"avg {fmt_mb(fa.get('avg_mem'))}, max {fmt_mb(fa.get('mem_max'))}"),
              ("Peak concurrency", (f"{fa['peak_concurrency']} busy workers at {fa.get('peak_concurrency_at', '-')} UTC "
                                    "(estimated: busy worker-seconds in the busiest second)") if fa.get("peak_concurrency") is not None else "n/a"),
              ("Slow-log traces", f"{sl.get('entries', 0)}" + (" (log unreadable)" if sl.get("unreadable") else ""))])
        if p.get("top_procs"):
            d.table(["PID", "Process", "State", "CPU now", "Memory", "Age"],
                    [[x["pid"], x["what"], x["state"], f"{x['cpu']:.0f}%", f"{fmt_mb(x['mem_mb'])} {x['mem_kind']}",
                      fmt_age(x["age_s"])] for x in p["top_procs"][:6]],
                    align=["r", "l", "l", "r", "r", "r"], maxw=[0, 34, 0, 0, 0, 0])
            if p["fpm_procs_last"]:
                d.text(f"PHP-FPM workers: {p['fpm_procs_last']} now, avg {fmt_mb(p['fpm_pss_mb'] / max(1, min(len(p['top_procs']), p['fpm_procs_last'])))} "
                       f"per listed worker. CPU now = average over the live sample.")
        if fa.get("top_paths_cpu"):
            d.table(["Path (by CPU)", "Hits", "CPU s", "Avg s", "Max s", "Max MB"],
                    [[x["path"], x["hits"], x["cpu_s"], x["avg_s"], x["max_s"], x["max_mb"]] for x in fa["top_paths_cpu"][:6]], maxw=[46, 0, 0, 0, 0, 0])
        render_slow_requests(d, p, ctx.args)
        if sl.get("functions"):
            d.table(["Slow function (slow-log)", "Location", "Traces"],
                    [[fn + "()", loc, k] for (fn, loc), k in sl["functions"].most_common(5)], align=["l", "l", "r"], maxw=[30, 46, 0])
        if p["long_cli"]:
            for c in [c for c in p["long_cli"] if c["live_cpu"] >= 2 or c["life_cpu"] >= 5][:3]:
                d.bullet("Background process " + fmt_proc(c), "info")
    # 6. MySQL
    d.h2("8. MySQL / MariaDB Investigation")
    m = R["mysql"]
    if not m.get("available"):
        d.text(f"Not available: {m.get('error')}", "warning")
    else:
        s, v, r = m.get("status_end", {}), m.get("vars", {}), m.get("rates", {})
        svc = dict(R["attribution"]).get("mysql", {"cpu": 0, "mem_mb": 0})
        d.kv([("Version", m.get("version", "?")), ("CPU / memory", f"{svc['cpu']:.0f}% of one core, {fmt_mb(svc['mem_mb'])}"),
              ("Connections", f"{s.get('Threads_connected', '?')} now, max used {s.get('Max_used_connections', '?')} / {v.get('max_connections', '?')}"),
              ("Threads running", s.get("Threads_running", "?")),
              ("Query rate", f"{r.get('Questions', 0):.0f}/s; slow {r.get('Slow_queries', 0):.2f}/s; full joins {r.get('Select_full_join', 0):.2f}/s; "
                             f"tmp disk tables {r.get('Created_tmp_disk_tables', 0):.2f}/s"),
              ("Row lock waits now", f"{m.get('lock_waits_now', 0)} (longest {m.get('lock_wait_max_s', 0)}s)"),
              ("Last deadlock", m.get("last_deadlock", "none recorded")),
              ("Slow log", f"{R['mysql_slow'].get('file') or 'n/a'} (enabled={R['mysql_slow'].get('enabled')}, long_query_time={R['mysql_slow'].get('long_query_time')}s)"),
              ("Slow queries (window)", f"{R['mysql_slow'].get('total', 0):,} ({R['mysql_slow'].get('dump_queries', 0)} backup/dump)")])
        bydb = R["mysql_slow"].get("by_db", {})
        if bydb:
            d.table(["Database", "Application (mapping)", "Slow q", "Total s", "Max s"],
                    [[db, map_label(x["app"], R["db_map_src"].get(db)), x["count"], f"{x['time']:.0f}", f"{x['max']:.1f}"] for db, x in list(bydb.items())[:8]])
        fps = R["mysql_slow"].get("fingerprints", [])
        if fps:
            d.text(f"{R['mysql_slow'].get('total', 0):,} slow queries in {R['mysql_slow'].get('distinct_fingerprints', len(fps))} distinct "
                   "patterns. Literals are masked (?); [dump] = mysqldump/backup read, not application load.")

            def fp_rows(lst):
                return [[x["db"], map_label(x["app"], R["db_map_src"].get(x["db"])), f"{x['count']:,}", f"{x['time']:.0f}",
                         f"{x['avg']:.1f}", f"{x['max']:.1f}", f"{x['avg_rows_ex']:,.0f}",
                         ("[dump] " if x["dump"] else "") + x["fingerprint"]] for x in lst[:10]]
            hdr = ["DB", "App (mapping)", "Count", "Total s", "Avg s", "Max s", "Rows exam."]
            mw = [12, 18, 0, 0, 0, 0, 0, 46]
            d.table(hdr + ["Top 10 slowest queries (by max time)"], fp_rows(sorted(fps, key=lambda x: -x["max"])), maxw=mw)
            d.table(hdr + ["Top 10 by total execution time"], fp_rows(fps), maxw=mw)
            d.table(hdr + ["Most frequently repeated patterns"], fp_rows(sorted(fps, key=lambda x: -x["count"])), maxw=mw)
            d.text("Missing indexes are only reported with EXPLAIN evidence (--explain); a high rows-examined value alone is not proof.")
        per_db = m.get("per_db", {})
        if per_db:
            d.table(["Database", "Application (mapping)", "Conn avg/peak", "Running avg/peak"],
                    [[db, map_label(x["app"], R["db_map_src"].get(db)), f"{x['conn_avg']:.1f}/{x['conn_peak']}", f"{x['running_avg']:.1f}/{x['running_peak']}"]
                     for db, x in sorted(per_db.items(), key=lambda kv: -kv[1]["running_peak"])[:8]])
        for q in m.get("long_running", [])[:5]:
            d.bullet(f"[{q['db']}] {q['time_s']}s {q['state']}: {q['query']}", "info" if q["dump"] else "warning")
    # 8. RCA
    d.h2("9. Root Cause Analysis & Key Findings")
    for p in top:
        rc = p["root_cause"]
        d.h3(p["app"])
        sev = "ok" if rc["primary"] is None and rc["confidence"] == "Confirmed" else "warning" if rc["primary"] else "info"
        d.kv([("Root cause", rc["text"], sev), ("Confidence", rc["confidence"]),
              ("Contributing", ", ".join(SCENARIO_TEXT[s] for s in rc["secondary"]) or "-")])
        d.text("INVESTIGATION SUMMARY:")
        for ln in p["summary"]:
            d.text(ln)
    # 7. App bottlenecks / findings
    d.h3("Key findings per application (evidence and next action)")
    for p in top:
        d.text(p["app"] + ":")
        if not p["findings"]:
            d.bullet("No bottleneck indicators found.", "ok")
        for f in p["findings"]:
            d.bullet(f"{f['text']} [{f['confidence']}]", f["severity"])
            for e in f["evidence"][:4]:
                d.bullet(e, None, 1)
            if f.get("action"):
                d.bullet("Next action: " + f["action"], None, 1)
    # 9. Internal
    d.h2("10. Internal PlatformOps Recommendations (NOT for customer)")
    if not R["internal"]:
        d.bullet("No action required based on collected evidence.", "ok")
    for rec in R["internal"]:
        d.bullet(f"[{rec['app']}] {rec['text']}", "warning")
        for e in rec["evidence"][:4]:
            d.bullet("Evidence: " + e, None, 1)
    # 10. Customer
    d.h2("11. Customer-Shareable Recommendations")
    d.text(">>> BEGIN CUSTOMER RESPONSE >>>")
    for c in R["customer"]:
        d.text(c["title"] + (f" ({', '.join(c['apps'])})" if c.get("apps") else ""))
        d.text(c["text"])
        d.blank()
    d.text("<<< END CUSTOMER RESPONSE <<<")
    # 11. Evidence
    d.h2("12. Supporting Evidence")
    for p in top:
        fa, sl = p.get("fpm") or {}, p.get("slow") or {}
        d.h3(p["app"])
        for smp in sl.get("samples", [])[:2]:
            d.bullet(f"slow-log {smp['time']} {smp['script']}", "info")
            for fr in smp["frames"]:
                d.bullet(fr, None, 1)
        files = [("access", (p.get("traffic") or {}).get("files")), ("fpm", fa.get("files"))]
        d.text("Logs read: " + "; ".join(f"{k}: {', '.join(v) if v else 'none'}" for k, v in files))
    d.h3("Data availability notes")
    for n in ctx.notes or ["All data sources were available."]:
        d.bullet(n, "info")
    # 12. Final
    d.h2("Final Findings Summary")
    alerts = collect_alerts(R, "info")
    rank = [a for a in alerts if a["severity"] != "info"] or alerts[:5]
    if rank:
        d.table(["Finding", "Application", "Severity", "Recommended action"],
                [[trunc(a["text"], 46), a["app"], SEV_NAME[a["severity"]], short_action(a.get("action") or "-")] for a in rank[:25]],
                align=["l", "l", "l", "l"], maxw=[46, 12, 0, 64])
    else:
        d.text("[HEALTHY] No findings that need action.", "ok")
    for i, p in enumerate(top, 1):
        d.text(f"{i}. {p['app']}: {p['root_cause']['text']} [{p['root_cause']['confidence']}]")
        d.text("   " + p["summary"][0])
    d.bullet(f"Issue origin: {R['origin']['text']} [{R['origin']['confidence']}]",
             "ok" if R["origin"]["origin"] == "none" else "warning")
    crit = [f for f in R["server_findings"] if f["severity"] == "critical"]
    d.bullet("Server: " + ("; ".join(f["text"] for f in crit) if crit else "no critical server-level condition detected"),
             "critical" if crit else "ok")
    d.text("This report is read-only evidence. Do not block IPs, restart services or change configuration based on it without review.")
    d.h1("END OF INVESTIGATION")
    return d


# ----------------------------------------------------------------------------
# Orchestration
# ----------------------------------------------------------------------------
def parse_user_time(v: str):
    for f in ("%d-%m-%Y:%H:%M", "%d-%m-%Y:%H"):
        try:
            return datetime.strptime(v.strip(), f)
        except ValueError:
            pass
    return None


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Cloudways application resource & traffic investigation (read-only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example: curl -sS https://raw.githubusercontent.com/jahanzaibakhan/cloudways-app-investigator/main/analyze_cloudways_applications.py "
               "| python3 - --top 5 --hour 1 --progress")
    ap.add_argument("--top", type=int, default=5, help="Number of applications to investigate (default 5)")
    ap.add_argument("--hour", type=float, default=None, help="Log/traffic investigation window in hours (default 1)")
    ap.add_argument("--from-time", default="", help="Window start UTC, DD-MM-YYYY:HH[:MM]")
    ap.add_argument("--to-time", default="", help="Window end UTC, DD-MM-YYYY:HH[:MM]")
    ap.add_argument("--minutes", type=float, default=None, help="Live resource sampling duration in minutes (overrides --sample-seconds)")
    ap.add_argument("--sample-seconds", type=float, default=30, help="Live resource sampling duration in seconds (default 30)")
    ap.add_argument("--sample-interval", type=float, default=0, help="Seconds between samples (default auto, 1-5s)")
    ap.add_argument("--only-app", default="", help="Investigate a single application (folder name)")
    ap.add_argument("--applications-root", default="/home/master/applications")
    ap.add_argument("--strict-root", action="store_true", help="Do not auto-discover other /home roots")
    ap.add_argument("--progress", action="store_true", help="Show progress on stderr")
    ap.add_argument("--verbose", action="store_true", help="Debug output on stderr")
    ap.add_argument("--no-color", action="store_true", help="Disable terminal colours")
    ap.add_argument("--width", type=int, default=0, help="Report width in columns (default: terminal width, max 160; 120 when piped)")
    ap.add_argument("--report", action="store_true", help="Save the report to a timestamped file")
    ap.add_argument("--format", choices=["txt", "markdown"], default="txt", help="Report/terminal format (default txt)")
    ap.add_argument("--output-dir", default="/tmp", help="Directory for --report / --json files (default /tmp)")
    ap.add_argument("--json", action="store_true", help="Also save machine-readable JSON results")
    ap.add_argument("--full", action="store_true",
                    help="Print the complete 12-section report instead of the compact summary (default: summary)")
    ap.add_argument("--app-reports-only", action="store_true",
                    help="Print only the shareable per-application reports for CRITICAL/HIGH applications")
    ap.add_argument("--no-app-reports", action="store_true",
                    help="Do not include/save the per-application reports")
    ap.add_argument("--skip-health", action="store_true", help="Skip optional server checks (Redis, Varnish, OOM, filesystems)")
    ap.add_argument("--skip-mysql", action="store_true", help="Skip MySQL/MariaDB investigation")
    ap.add_argument("--skip-history", action="store_true", help="Skip atop historical analysis")
    ap.add_argument("--explain", action="store_true", help="Run EXPLAIN (read-only) for top suspected full-scan SELECTs")
    ap.add_argument("--fpm-log-glob", default="/var/log/php*-fpm.log*")
    ap.add_argument("--kernel-log-glob", default="/var/log/kern.log*,/var/log/syslog*,/var/log/messages*",
                    help="Comma-separated kernel log globs searched (in order) for OOM kills; journalctl -k is the fallback")
    ap.add_argument("--pool-conf-glob", default="/etc/php/*/fpm/pool.d/*.conf,/etc/php-fpm.d/*.conf",
                    help="Comma-separated globs of PHP-FPM pool configs")
    ap.add_argument("--atop-timeout", type=float, default=90)
    ap.add_argument("--cpu-threshold", type=float, default=20, help="High CPU = this %% of server capacity (default 20)")
    ap.add_argument("--mem-threshold", type=float, default=15, help="High memory = this %% of RAM (default 15)")
    ap.add_argument("--cpu-high", type=float, default=40, help="App CPU share of server for HIGH (default 40)")
    ap.add_argument("--cpu-critical", type=float, default=70, help="App CPU share for CRITICAL when server is saturated (default 70)")
    ap.add_argument("--mem-high", type=float, default=30, help="App memory %% of RAM for HIGH (default 30)")
    ap.add_argument("--php-rpm-per-core-warn", type=float, default=120,
                    help="PHP requests/min per vCPU considered high volume (default 120)")
    ap.add_argument("--cpu-ms-per-req-threshold", type=float, default=400, help="Inefficient PHP above this CPU ms/request (default 400)")
    ap.add_argument("--slow-request-seconds", type=float, default=5, help="Request flagged SLOW at this duration (default 5s)")
    ap.add_argument("--very-slow-request-seconds", type=float, default=30, help="Request flagged VERY SLOW (default 30s)")
    ap.add_argument("--request-mem-high", type=float, default=256, help="Request peak memory flagged HIGH-MEM, MB (default 256)")
    ap.add_argument("--slow-p95-seconds", type=float, default=3, help="Slow PHP when p95 duration >= this (default 3s)")
    ap.add_argument("--slow-query-min", type=int, default=10, help="Min slow queries per DB to flag (default 10)")
    ap.add_argument("--db-conn-high", type=int, default=40, help="Per-database connection peak flagged (default 40)")
    ap.add_argument("--long-query-seconds", type=int, default=10, help="Running query considered long (default 10s)")
    ap.add_argument("--steal-threshold", type=float, default=8)
    ap.add_argument("--long-request-seconds", type=float, default=10,
                    help="Live: FPM worker busy continuously this long = long-running request (default 10)")
    ap.add_argument("--bg-cpu-threshold", type=float, default=10, help="Background process CPU %% of one core to flag (default 10)")
    ap.add_argument("--skip-bot-census", action="store_true", help="Skip the server-wide top-bots pass over all applications")
    ap.add_argument("--server-bots-top", type=int, default=10, help="Bots listed in the server-wide ranking (default 10)")
    ap.add_argument("--no-dns-verify", action="store_true",
                    help="Do not verify claimed search-engine bots via reverse/forward DNS")
    ap.add_argument("--dns-verify-max", type=int, default=60, help="Max IPs to DNS-verify per run (default 60)")
    ap.add_argument("--bot-share-high", type=float, default=25, help="Bot share of backend requests flagged HIGH (default 25%%)")
    ap.add_argument("--bot-share-warn", type=float, default=10, help="Bot share flagged WARNING (default 10%%)")
    ap.add_argument("--attack-min-rpm", type=float, default=60,
                    help="Below this backend req/min on a non-loaded app, attack patterns are reported as INFO/WARNING only (default 60)")
    ap.add_argument("--bot-requests-high", type=int, default=5000,
                    help="A single bot above this many requests per hour (window average) is at least WARNING (default 5000)")
    ap.add_argument("--bot-rpm-high", type=float, default=60, help="Bot requests/min flagged (default 60)")
    ap.add_argument("--bot-php-requests-high", type=int, default=2000,
                    help="Estimated bot PHP requests per hour flagged (default 2000)")
    ap.add_argument("--bot-high-cpu", type=float, default=5,
                    help="Bot PHP CPU (%% of one core, window average) required for HIGH (default 5)")
    ap.add_argument("--bot-min-cpu", type=float, default=2,
                    help="Bots under this PHP CPU (%% of a core) and under 60 req/min are never flagged (default 2)")
    ap.add_argument("--chrome-latest-major", type=int, default=0)
    ap.add_argument("--chrome-obsolete-margin", type=int, default=40)
    ap.add_argument("--no-ip-lookup", action="store_true", help=argparse.SUPPRESS)   # compat: this tool never sends IPs out
    ap.add_argument("--version", action="version", version=VERSION)
    return ap


def server_identity() -> tuple[str, str]:
    host = socket.gethostname()
    rc, out, _ = run_cmd(["hostname", "-I"], timeout=3)
    ips = [x for x in out.split() if ":" not in x] if rc == 0 else []
    pub = [x for x in ips if not ipaddress.ip_address(x).is_private]
    if pub:
        return host, pub[0]
    return host, (f"{ips[0]} private; public IP not on an interface" if ips else "unknown")


def investigate(args) -> tuple[Ctx, dict]:
    ctx = Ctx(args)
    if not ctx.is_root:
        ctx.note("Not running as root: MySQL, atop history, PSS memory, some logs and pool overrides may be unavailable.")
    now = utcnow()
    if args.from_time or args.to_time:
        start = parse_user_time(args.from_time) if args.from_time else now - timedelta(hours=1)
        end = parse_user_time(args.to_time) if args.to_time else now
        if start is None or end is None or start >= end:
            raise SystemExit("Invalid --from-time/--to-time (format DD-MM-YYYY:HH[:MM], start < end)")
        if args.to_time and len(args.to_time.split(":")) == 2:
            end = end.replace(minute=59, second=59)
        window_desc = f"{start:%Y-%m-%d %H:%M} -> {end:%Y-%m-%d %H:%M} UTC"
    else:
        hours = args.hour or 1
        start, end = now - timedelta(hours=hours), now
        window_desc = f"last {hours:g} hour(s) ({start:%Y-%m-%d %H:%M} -> {end:%H:%M} UTC)"
    window_s = (end - start).total_seconds()
    args.window_s = window_s
    short_window = f"the last {window_s / 3600:g}h" if not (args.from_time or args.to_time) else window_desc
    if args.minutes:
        args.sample_seconds = args.minutes * 60
    args.sample_seconds = max(4, min(args.sample_seconds, 3600))
    interval = args.sample_interval or min(5.0, max(1.0, args.sample_seconds / 30))

    ctx.progress("Discovering applications and PHP-FPM pools")
    roots = detect_roots(Path(args.applications_root), args.strict_root)
    apps = collect_apps(roots)
    if not apps:
        raise SystemExit("No Cloudways applications found (expected /home/master/applications/<app>/logs).")
    ctx.pools = collect_pools(ctx, apps)
    if not ctx.pools:
        ctx.note("No PHP-FPM pool configs readable under /etc/php/*/fpm/pool.d - pool limits unknown.")
    db_to_app, db_map_src = {}, {}
    for name, ap in apps.items():
        if ap.get("db_name"):
            db_to_app[ap["db_name"]] = name
            db_map_src[ap["db_name"]] = ap["db_source"]
    for name in apps:
        if name not in db_to_app:
            db_to_app[name] = name
            db_map_src[name] = "naming convention (db = app id)"
    scope = {args.only_app: apps[args.only_app]} if args.only_app and args.only_app in apps else apps
    if args.only_app and args.only_app not in apps:
        raise SystemExit(f"Application '{args.only_app}' not found. Available: {', '.join(sorted(apps))}")

    my = MySQL(ctx) if not args.skip_mysql else None
    mres = mysql_collect(ctx, my) if my else {"available": False, "error": "skipped (--skip-mysql)"}

    ctx.progress(f"Measuring PHP CPU per application from FPM access logs ({len(scope)} apps, {window_desc})")
    fpm_quick = {name: analyze_fpm_access(ctx, ap, start, end, deep=False) for name, ap in apps.items()}
    if not any(v["available"] for v in fpm_quick.values()):
        ctx.note("No php-app.access.log files found - per-request CPU/memory and traffic correlation are limited.")

    ctx.progress(f"Live resource sampling for {args.sample_seconds:.0f}s (interval {interval:.1f}s)")
    hooks = [lambda i: mysql_sample(my, mres)] if my and my.ok else []
    sample = sample_resources(ctx, apps, args.sample_seconds, interval, hooks)
    if my:
        mysql_finish(ctx, my, mres, db_to_app)

    history = None
    if not args.skip_history:
        ctx.progress("Reading atop history for the window")
        history = atop_history(ctx, apps, start, end)

    health = server_health(ctx, sample, history, start, end)
    profiles = build_profiles(ctx, scope, sample, history, fpm_quick, window_s, health.get("mem_total_mb") or 1)
    top = profiles[: max(1, args.top)]
    ctx.progress("Top applications: " + ", ".join(p["app"] for p in top))

    fpm_events = scan_fpm_master_logs(ctx, apps, start, end)
    mslow = analyze_mysql_slowlog(ctx, my, mres, db_to_app, start, end) if my and my.ok else {"total": 0, "by_db": {}, "fingerprints": []}
    pools_by_app = defaultdict(list)
    for pool in ctx.pools.values():
        pools_by_app[pool["app"]].append(pool)
    listen = sample["server"]["listen"]
    verifier = BotVerifier(ctx)
    census = None
    if not args.skip_bot_census:
        ctx.progress(f"Server-wide bot census across {len(scope)} applications")
        census = bot_census(ctx, scope, start, end, verifier)
    for p in top:
        ap = apps[p["app"]]
        ctx.progress(f"[{p['app']}] deep analysis: FPM access log, traffic, slow log")
        p["fpm"] = analyze_fpm_access(ctx, ap, start, end, deep=True)
        p["traffic"] = analyze_traffic(ctx, ap, start, end)
        p["slow"] = analyze_slowlog(ctx, ap, start, end)
        p["fpm_minutes"] = list((fpm_events.get(p["app"], {}).get("minutes") or {}).keys())
        dbs_ = {db for db, a_ in db_to_app.items() if a_ == p["app"]}
        p["slow_minutes"] = [m for db, x in mslow.get("by_db", {}).items() if db in dbs_ for m in (x.get("minutes") or {})]
        correlate_bots(ctx, verifier, p)
        p["cron"] = analyze_cron_log(ap, start)
        cands = sorted(pools_by_app.get(p["app"], []), key=lambda x: x.get("php_version", ""))
        active = [c for c in cands if ("fpm:" + c["pool"]) in p["proc_kinds"]] or cands[-1:]
        p["pool"] = active[0] if active else {}
        try:
            p["max_children"] = int(p["pool"].get("pm.max_children")) if p["pool"].get("pm.max_children") else None
        except ValueError:
            p["max_children"] = None
        ev = fpm_events.get(p["app"], {})
        p["fpm_hits"], p["fpm_limit"] = ev.get("max_children_hits", 0), ev.get("limit")
        p["max_children"] = p["max_children"] or p["fpm_limit"]
        p["fpm_timeouts"] = ev.get("timeouts", 0)
        p["fpm_timeout_scripts"] = ev.get("timeout_scripts", Counter()).most_common(5)
        q = listen.get(p["app"], [])
        p["listen_queue_measured"] = bool(q) or bool(shutil.which("ss"))
        p["listen_queue_peak"] = max((x[0] for x in q), default=0)
        dbs = {db for db, a in db_to_app.items() if a == p["app"]}
        p["mysql"] = {
            "slow": next((x for db, x in mslow.get("by_db", {}).items() if db in dbs), None),
            "fingerprints": [x for x in mslow.get("fingerprints", []) if x["db"] in dbs],
            "live": next((x for db, x in mres.get("per_db", {}).items() if db in dbs), None),
            "long_running": [x for x in mres.get("long_running", []) if x["db"] in dbs],
        }
        p["tags"] = resource_tags(p, ctx)

    oom = scan_oom(ctx, start, end, apps) if not args.skip_health else \
        {"events": [], "by_process": [], "sources": [], "by_owner": [], "triggers": [], "memcg_kills": 0}
    for p in top:
        p["oom"] = [e for e in oom["events"] if e["owner_kind"] == "app" and e["owner"] == p["app"]]
    redis = redis_info(ctx) if not args.skip_health else None
    varnish = varnish_info(ctx) if not args.skip_health else None
    if args.skip_health:
        health["filesystems"] = []
    services = {}
    attribution = []
    app_owners = sorted(((k, o) for k, o in sample["owners"].items() if k[0] == "app"), key=lambda kv: -kv[1]["cpu_avg"])
    for k, o in app_owners[:6]:
        attribution.append((f"app:{k[1]}", {"cpu": o["cpu_avg"], "mem_mb": o["pss_mb"] if o["pss_mb"] is not None else o["rss_avg_mb"]}))
    rest = app_owners[6:]
    if rest:
        attribution.append((f"other apps ({len(rest)})", {"cpu": sum(o["cpu_avg"] for _, o in rest),
                                                         "mem_mb": sum((o["pss_mb"] if o["pss_mb"] is not None else o["rss_avg_mb"]) for _, o in rest)}))
    other = {"cpu": 0.0, "mem_mb": 0.0}
    for k, o in sample["owners"].items():
        mem = o["pss_mb"] if o["pss_mb"] is not None else o["rss_avg_mb"]
        if k[0] == "service":
            services[k[1]] = {"cpu": o["cpu_avg"], "mem_mb": mem}
        elif k[0] == "other":
            other["cpu"] += o["cpu_avg"]
            other["mem_mb"] += mem
            other.setdefault("_top", []).append((mem, k[1]))
    attribution += sorted(services.items(), key=lambda kv: -(kv[1]["cpu"] + kv[1]["mem_mb"] / 50))
    top_other = ", ".join(n for _, n in sorted(other.pop("_top", []), reverse=True)[:3])
    attribution.append((f"other ({top_other})" if top_other else "system/other processes", other))
    attribution.sort(key=lambda kv: -kv[1]["cpu"])
    srv_find = server_findings(ctx, health, services, oom, mres, redis, sum(o["cpu_avg"] for _, o in app_owners))

    window_h = window_s / 3600
    for p in top:
        investigate_app(ctx, p, health, window_h)
        p["summary"] = two_line_summary(p, short_window)
    internal, customer = recommendations(ctx, top, srv_find, health)
    host, ip = server_identity()
    origin = issue_origin(ctx, health, attribution, srv_find, top)
    R = {"census": census, "origin": origin, "db_map_src": db_map_src, "hostname": host, "server_ip": ip, "generated": now.strftime("%Y-%m-%d %H:%M:%S"), "window_desc": window_desc,
         "sample": sample, "app_count": len(scope), "top": top, "health": health, "attribution": attribution,
         "mysql": mres, "mysql_slow": mslow, "oom": oom, "redis": redis, "varnish": varnish,
         "server_findings": srv_find, "internal": internal, "customer": customer}
    return ctx, R


def json_safe(o):
    if isinstance(o, dict):
        return {(", ".join(map(str, k)) if isinstance(k, tuple) else str(k)): json_safe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple, set)):
        return [json_safe(x) for x in o]
    if isinstance(o, Counter):
        return json_safe(o.most_common())
    if isinstance(o, (datetime, Path)):
        return str(o)
    return o


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        ctx, R = investigate(args)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        return 130
    set_width(args)
    doc = build_report(ctx, R)
    app_docs = build_app_reports(ctx, R)
    color = sys.stdout.isatty() and not args.no_color and args.format == "txt" and not os.environ.get("NO_COLOR")
    compact = build_compact(ctx, R)
    if args.app_reports_only:
        if not app_docs:
            print("No application has CRITICAL or HIGH findings - no application reports to show.")
        for d in app_docs.values():
            sys.stdout.write(d.render(args.format, color))
    elif args.full:
        sys.stdout.write(doc.render(args.format, color))
    else:
        sys.stdout.write(compact.render(args.format, color))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    if args.report:
        ext = "md" if args.format == "markdown" else "txt"
        path = Path(args.output_dir) / f"cloudways_summary_{stamp}.{ext}"
        try:
            path.write_text(compact.render(args.format, False), encoding="utf-8")
            os.chmod(path, 0o600)
            print(f"Summary saved: {path}")
        except OSError as exc:
            print(f"Could not save summary: {exc}", file=sys.stderr)
    if args.report and app_docs and not args.no_app_reports:
        ext = "md" if args.format == "markdown" else "txt"
        for app, d in app_docs.items():
            path = Path(args.output_dir) / f"cloudways_app_{re.sub(r'[^A-Za-z0-9_.-]', '_', app)}_{stamp}.{ext}"
            try:
                path.write_text(d.render(args.format, False), encoding="utf-8")
                os.chmod(path, 0o600)
                print(f"Application report saved: {path}")
            except OSError as exc:
                print(f"Could not save application report for {app}: {exc}", file=sys.stderr)
    if args.report:
        ext = "md" if args.format == "markdown" else "txt"
        path = Path(args.output_dir) / f"cloudways_app_investigation_{stamp}.{ext}"
        try:
            path.write_text(doc.render(args.format, False), encoding="utf-8")
            os.chmod(path, 0o600)
            print(f"\nReport saved: {path}")
        except OSError as exc:
            print(f"Could not save report: {exc}", file=sys.stderr)
    if args.json:
        path = Path(args.output_dir) / f"cloudways_app_investigation_{stamp}.json"
        R2 = dict(R)
        R2["sample"] = {k: v for k, v in R["sample"].items() if k != "server"}
        R2["notes"] = ctx.notes
        try:
            path.write_text(json.dumps(json_safe(R2), indent=1, default=str), encoding="utf-8")
            os.chmod(path, 0o600)
            print(f"JSON saved: {path}")
        except OSError as exc:
            print(f"Could not save JSON: {exc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

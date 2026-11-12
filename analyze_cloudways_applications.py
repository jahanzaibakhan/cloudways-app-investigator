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

VERSION = "1.1.0"

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
OOM_KILLED_RE = re.compile(r"Out of memory: Killed process (\d+) \(([^)]+)\)", re.I)
OOM_INVOKED_RE = re.compile(r"(\S+) invoked oom-killer", re.I)
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
            rec = (ts.strftime("%H:%M:%S"), m["method"], m["status"], round(dur, 3), round(mem_mb, 1),
                   round(cpu_pct, 1), trunc(uri, 90))
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
        peak_at = max(conc, key=conc.get) if conc else None
        peak = conc[peak_at] if peak_at is not None else 0
        res["peak_concurrency"] = round(peak, 1)
        res["peak_concurrency_at"] = datetime.fromtimestamp(peak_at, timezone.utc).strftime("%H:%M:%S") if peak_at else ""
        res["types"] = types.most_common()
        top = sorted(paths.items(), key=lambda kv: -kv[1][1])[:10]
        res["top_paths_cpu"] = [{"path": trunc(k, 70), "hits": v[0], "cpu_s": round(v[1], 1),
                                 "avg_s": round(v[2] / v[0], 3), "max_s": round(v[3], 2), "max_mb": round(v[4], 1)}
                                for k, v in top]
        res["top_cpu_requests"] = [r for _, _, r in sorted(heap_cpu, reverse=True)]
        res["slowest_requests"] = [r for _, _, r in sorted(heap_dur, reverse=True)]
        res["top_mem_requests"] = [r for _, _, r in sorted(heap_mem, reverse=True)]
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


def scan_oom(ctx: Ctx, start, end) -> dict:
    events, seen, sources = [], set(), []
    now = utcnow()
    for pattern in ("/var/log/kern.log*", "/var/log/syslog*", "/var/log/messages*"):
        files = [f for f in files_for_window(pattern, start) if os.access(f, os.R_OK)]
        if not files:
            continue
        sources.extend(str(f) for f in files)
        for f in files:
            for line in iter_lines(f):
                if "Killed process" not in line and "invoked oom-killer" not in line:
                    continue
                ts = parse_syslog_ts(line, now)
                if not in_window(ts, start, end):
                    continue
                m = OOM_KILLED_RE.search(line)
                if m:
                    key = (m.group(1), ts.strftime("%Y%m%d%H%M"))
                    if key not in seen:
                        seen.add(key)
                        events.append({"time": ts.strftime("%Y-%m-%d %H:%M:%S"), "pid": m.group(1), "process": m.group(2)})
        break       # kern.log and syslog duplicate each other; use the first readable source
    if not sources:
        rc, out, _ = run_cmd(["journalctl", "-k", "--no-pager", "-o", "short-iso",
                              "--since", start.strftime("%Y-%m-%d %H:%M:%S") + " UTC"], timeout=20, ctx=ctx)
        if rc == 0:
            sources.append("journalctl -k")
            for line in out.splitlines():
                m = OOM_KILLED_RE.search(line)
                if m:
                    ts = parse_syslog_ts(line, now)
                    events.append({"time": ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "?", "pid": m.group(1),
                                   "process": m.group(2)})
        else:
            ctx.note("Kernel logs (kern.log/syslog/journal) not readable - OOM events could not be checked (run as root).")
    return {"events": events, "sources": sources, "by_process": Counter(e["process"] for e in events).most_common()}


# ----------------------------------------------------------------------------
# Traffic analysis (backend = requests that passed Varnish to Apache/PHP)
# ----------------------------------------------------------------------------
def estimate_latest_chrome(now: datetime) -> int:
    return 126 + max(0, int((now - datetime(2024, 6, 11)).days / 40.5))


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
            cm = CHROME_RE.search(ua)
            if cm:
                v = int(cm.group(1))
                if v > latest_chrome or v <= latest_chrome - ctx.args.chrome_obsolete_margin:
                    chrome_bad += 1
                if "headless" in ua.lower():
                    headless += 1
            minute = ts.replace(second=0)
            per_min[minute] += 1
            per_sec[ts] += 1 if len(per_sec) < 400000 else 0
    total = res["total"]
    res["unparsed"] = unparsed
    if not total:
        return res
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
        ftotal = 0
        for f in files_for_window(app["frontend_logs"], start):
            for line in iter_lines(f, start, access_line_ts):
                if in_window(access_line_ts(line), start, end):
                    ftotal += 1
        res["frontend_total"] = ftotal
    return res


def traffic_signals(t: dict) -> list[dict]:
    """Suspicious-traffic indicators. Each is evidence only; verdicts need several."""
    sig = []
    total = t.get("total", 0)
    if total < 200:
        return sig
    if t["top_ips"] and t["top_ips"][0]["pct"] >= 25 and t["top_ips"][0]["requests"] >= 300:
        ip = t["top_ips"][0]
        sig.append({"key": "dominant_ip", "text": f"Single IP {ip['ip']} sent {ip['requests']:,} requests "
                    f"({ip['pct']:.1f}% of backend traffic), mostly '{ip['top_target']}'"})
    top_ip_n = t["top_ips"][0]["requests"] if t["top_ips"] else 0
    if t["top_subnets"] and t["top_subnets"][0]["pct"] >= 40 and t["top_subnets"][0]["requests"] >= 500 and \
            t["top_subnets"][0]["requests"] - top_ip_n >= 0.2 * total:
        s = t["top_subnets"][0]
        sig.append({"key": "dominant_subnet", "text": f"Subnet {s['subnet']} sent {s['requests']:,} requests ({s['pct']:.1f}%)"})
    if t["spike_ratio"] >= 6 and t["peak_rpm"] >= 120:
        sig.append({"key": "burst", "text": f"Burst: {t['peak_rpm']:,} req/min at {t['peak_rpm_at']} UTC vs "
                    f"{t['avg_rpm']:.0f} req/min average ({t['spike_ratio']:.1f}x)"})
    if t["login_post"] >= 100:
        sig.append({"key": "login_bruteforce", "text": f"{t['login_post']:,} POST requests to wp-login.php"})
    if t["xmlrpc_post"] >= 100:
        sig.append({"key": "xmlrpc_abuse", "text": f"{t['xmlrpc_post']:,} POST requests to xmlrpc.php"})
    bots = dict(t["ua_classes"]).get("bot/tool", 0) + dict(t["ua_classes"]).get("empty", 0)
    if pct(bots, total) >= 40:
        sig.append({"key": "bot_share", "text": f"{pct(bots, total):.0f}% of requests come from non-search bots/tools or empty User-Agents"})
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
    top = sorted(fps.values(), key=lambda x: -x["time"])[:15]
    res["fingerprints"] = top
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
    ("Application is a top consumer", "Confirm with the per-app process list and the CPU source shown; compare against the window average before acting."),
    ("proportional to legitimate PHP traffic", "Check whether resource pressure is sustained (atop history); if so evaluate upscaling, otherwise monitor peak hours."),
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
    ("Possible missing index", "Run EXPLAIN on the query (--explain) to confirm before recommending an index."),
    ("concurrently running queries", "Inspect SHOW FULL PROCESSLIST during the peak; look for lock waits and slow fingerprints."),
    ("Long-running query", "Check whether it is expected (report/backup) or blocking others; do not kill without customer approval."),
    ("Elevated 5xx", "Check the app error log and PHP-FPM log for the 5xx timestamps."),
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


def F(area, severity, confidence, text, evidence=None, scenario=None, action=None):
    return {"area": area, "severity": severity, "confidence": confidence, "text": text,
            "evidence": evidence or [], "scenario": scenario, "action": action or next_action_for(text)}


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
    if len(sig) >= 3 or (len(sig) >= 2 and any(s["key"] in ("dominant_ip", "dominant_subnet", "login_bruteforce", "xmlrpc_abuse") for s in sig)):
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
            fnd.append(F("correlation", "warning", "Likely",
                         "CPU consumption is disproportionate to traffic - inefficient PHP execution per request",
                         [f"{p['php_cpu_share']:.0f}% of server PHP CPU time from {p['php_req_share']:.0f}% of PHP requests"
                          + (f" ({ratio:.1f}x)" if ratio else ""),
                          f"Average CPU per request {per_req:.0f} ms; p95 duration {fmt_s(fa.get('p95'))}"],
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
                     + (["Slowest logged paths: " + ", ".join(f"{r[6]} ({r[3]}s)" for r in fa.get("slowest_requests", [])[:2])]
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
                     + [f"{r[6]} - {r[4]} MB" for r in fa.get("top_mem_requests", [])[:2]]))

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
            fnd.append(F("mysql", "info", "Suspected", "Possible missing index (large rows examined vs rows returned; verify with EXPLAIN)",
                         [f"avg rows examined {x['avg_rows_ex']:,.0f} vs sent {x['avg_rows_sent']:,.0f}: {trunc(x['fingerprint'], 100)}"]))
    live = db.get("live") or {}
    if live.get("running_peak", 0) >= max(4, NCPU * 2):
        fnd.append(F("mysql", "warning", "Confirmed", "High number of concurrently running queries for this database",
                     [f"Peak {live['running_peak']} running / {live['conn_peak']} connections during sampling"], scenario="database"))
    for q in db.get("long_running", [])[:2]:
        fnd.append(F("mysql", "info" if q["dump"] else "warning", "Confirmed",
                     "Long-running query" + (" (backup dump)" if q["dump"] else ""),
                     [f"{q['time_s']}s, state '{q['state']}': {trunc(q['query'], 110)}"]))

    # --- Errors
    if t.get("total", 0) >= 200 and pct(t.get("errors_5xx", 0), t["total"]) >= 5:
        fnd.append(F("traffic", "warning", "Confirmed", "Elevated 5xx error rate",
                     [f"{t['errors_5xx']:,} 5xx responses ({pct(t['errors_5xx'], t['total']):.1f}% of backend requests)"]))

    fnd.sort(key=lambda f: ({"critical": 0, "warning": 1, "info": 2}[f["severity"]], CONF_ORDER[f["confidence"]]))
    p["findings"] = fnd
    p["root_cause"] = decide_root_cause(p, fnd, server, suspicious)
    return p


def fmt_age(sec: int) -> str:
    if sec >= 86400:
        return f"{sec / 86400:.1f}d"
    if sec >= 3600:
        return f"{sec / 3600:.1f}h"
    return f"{sec // 60}m"


def fmt_proc(c: dict) -> str:
    age = fmt_age(c["age_s"])
    return (f"PID {c['pid']} {c.get('comm', '')}: {c['live_cpu']:.0f}% CPU now, {c['life_cpu']:.0f}% lifetime avg, "
            f"running {age}: {trunc(c['cmd'], 70)}")


def fmt_s(v) -> str:
    return f"{v:.2f}s" if isinstance(v, (int, float)) else "n/a"


SCENARIO_TEXT = {
    "suspicious": "Suspicious / bot traffic is driving backend load",
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
    order = ["suspicious", "fpm", "database", "optimization", "cron", "traffic"]
    primary = [s for s in order if by.get(s)]
    significant = p["tags"] != ["Normal"] or any(f["severity"] == "critical" for f in fnd)
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
          f"({p['cpu_server_share']:.0f}% of server capacity) and {fmt_mb(p['mem_mb'])} RAM over {window_desc}, "
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
        out.append(F("server", "critical", "Confirmed", f"{len(oom['events'])} OOM-killer event(s) in the window",
                     ["Killed: " + ", ".join(f"{p} ({c})" for p, c in oom["by_process"][:4])] +
                     [f"{e['time']} {e['process']} (pid {e['pid']})" for e in oom["events"][:3]]))
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
ANSI = {"red": "\033[1;31m", "yellow": "\033[1;33m", "green": "\033[1;32m", "blue": "\033[1;34m",
        "cyan": "\033[1;36m", "bold": "\033[1m", "dim": "\033[2m", "reset": "\033[0m"}
SEV_COLOR = {"critical": "red", "warning": "yellow", "info": "blue", "ok": "green"}
SEV_TAG = {"critical": "[CRITICAL]", "warning": "[WARNING]", "info": "[INFO]", "ok": "[OK]"}
W = 78


class Doc:
    def __init__(self):
        self.blocks = []

    def h1(self, t): self.blocks.append(("h1", t))
    def h2(self, t): self.blocks.append(("h2", t))
    def h3(self, t): self.blocks.append(("h3", t))
    def kv(self, rows, status=None): self.blocks.append(("kv", rows))
    def text(self, t, sev=None): self.blocks.append(("text", t, sev))
    def bullet(self, t, sev=None, level=0): self.blocks.append(("bullet", t, sev, level))
    def table(self, headers, rows, align=None, maxw=None): self.blocks.append(("table", headers, rows, align, maxw))
    def blank(self): self.blocks.append(("blank",))

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
                    out.append(f"  {r[0]:<{wk}} : " + self._c(val, SEV_COLOR.get(sev), color and sev is not None))
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
        return "\n".join(out) + "\n"

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
                    out.append("| " + " | ".join(md_esc(trunc(c, maxw[i]) if maxw[i] else c) for i, c in enumerate(r)) + " |")
                out.append("")
            elif k == "blank":
                out.append("")
        return "\n".join(out) + "\n"


def md_esc(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


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
        rows = [[trunc(c, maxw[i]) if maxw[i] else c for i, c in enumerate(r)] for r in rows]
    widths = [max([len(headers[i])] + [len(r[i]) for r in rows]) for i in range(n)]

    def line(cells):
        return "  | " + " | ".join(c.rjust(widths[i]) if align[i] == "r" else c.ljust(widths[i]) for i, c in enumerate(cells)) + " |"
    sep = "  +" + "+".join("-" * (w + 2) for w in widths) + "+"
    head = line(headers)
    if color:
        head = f"{ANSI['bold']}{head}{ANSI['reset']}"
    return [sep, head, sep] + [line(r) for r in rows] + [sep] if rows else ["  (no data)"]


def map_label(app: str, src: str | None) -> str:
    if not app:
        return "unmapped"
    return f"{app} ({'naming' if src and src.startswith('naming') else 'config'})"


def sev_for(v, warn, crit):
    if v is None:
        return None
    return "critical" if v >= crit else "warning" if v >= warn else "ok"


def build_report(ctx: Ctx, R: dict) -> Doc:
    d = Doc()
    top, h, hist = R["top"], R["health"], R["health"].get("history") or {}
    d.h1("CLOUDWAYS APPLICATION INVESTIGATION REPORT")
    # 1. Overview
    d.h2("1. Investigation Overview")
    d.kv([("Server", f"{R['hostname']} ({R['server_ip']})"), ("Generated At", R["generated"] + " UTC"),
          ("Traffic/log window", R["window_desc"]), ("Live sampling", f"{R['sample']['elapsed']:.0f}s, {R['sample']['samples']} samples"),
          ("Applications", f"Top {len(top)} of {R['app_count']} investigated"),
          ("Privileges", "root" if ctx.is_root else "NON-ROOT (some data unavailable)"),
          ("History source", f"atop ({hist.get('intervals', 0)} x {hist.get('interval_s', 0)}s intervals)" if hist else "none (live + logs only)"),
          ("Tool version", VERSION)])
    d.text("CPU values are '% of one vCPU core' unless marked 'of server'. 'Estimated' marks derived values; everything else is measured.")
    # 2. Server health
    d.h2("2. Overall Server Health")
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
        d.bullet(f"{p['app']}: {p['domain'] or 'domain n/a'} [{p['type']}] path {p['app_dir']} | DB '{p['db']}' "
                 f"(mapping: {p['db_source']}) | CPU source: {p['cpu_source']}"
                 + (f" | live {p['cpu_live_avg']:.0f}%/peak {p['cpu_live_peak']:.0f}%" if p.get("cpu_live_avg") is not None else "")
                 + (f" | history peak {p['cpu_hist_peak']:.0f}% at {p['cpu_hist_peak_at']}" if p.get("cpu_hist_peak") is not None else "")
                 + f" | memory {p['mem_kind']}" + (f", history avg {fmt_mb(p['mem_hist_avg'])} RSS" if p.get("mem_hist_avg") else ""))
    # 4. Traffic
    d.h2("4. Application Traffic Analysis")
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
    return build_report_part2(ctx, R, d)


def build_report_part2(ctx: Ctx, R: dict, d: Doc) -> Doc:
    top = R["top"]
    # 5. PHP-FPM
    d.h2("5. PHP-FPM Investigation")
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
        if sl.get("functions"):
            d.table(["Slow function (slow-log)", "Location", "Traces"],
                    [[fn + "()", loc, k] for (fn, loc), k in sl["functions"].most_common(5)], align=["l", "l", "r"], maxw=[30, 46, 0])
        if p["long_cli"]:
            for c in [c for c in p["long_cli"] if c["live_cpu"] >= 2 or c["life_cpu"] >= 5][:3]:
                d.bullet("Background process " + fmt_proc(c), "info")
    # 6. MySQL
    d.h2("6. MySQL / MariaDB Investigation")
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
            d.table(["DB", "Count", "Total s", "Max s", "Rows exam.", "Query fingerprint (literals masked)"],
                    [[x["db"], x["count"], f"{x['time']:.0f}", f"{x['max']:.1f}", f"{x['avg_rows_ex']:,.0f}",
                      ("[dump] " if x["dump"] else "") + x["fingerprint"]] for x in fps[:8]], maxw=[12, 0, 0, 0, 0, 52])
        per_db = m.get("per_db", {})
        if per_db:
            d.table(["Database", "Application (mapping)", "Conn avg/peak", "Running avg/peak"],
                    [[db, map_label(x["app"], R["db_map_src"].get(db)), f"{x['conn_avg']:.1f}/{x['conn_peak']}", f"{x['running_avg']:.1f}/{x['running_peak']}"]
                     for db, x in sorted(per_db.items(), key=lambda kv: -kv[1]["running_peak"])[:8]])
        for q in m.get("long_running", [])[:5]:
            d.bullet(f"[{q['db']}] {q['time_s']}s {q['state']}: {q['query']}", "info" if q["dump"] else "warning")
    # 7. App bottlenecks / findings
    d.h2("7. Application-Level Bottlenecks (Key Findings)")
    for p in top:
        d.h3(p["app"])
        if not p["findings"]:
            d.bullet("No bottleneck indicators found.", "ok")
        for f in p["findings"]:
            d.bullet(f"{f['text']} [{f['confidence']}]", f["severity"])
            for e in f["evidence"][:4]:
                d.bullet(e, None, 1)
            if f.get("action"):
                d.bullet("Next action: " + f["action"], None, 1)
    # 8. RCA
    d.h2("8. Root Cause Analysis")
    for p in top:
        rc = p["root_cause"]
        d.h3(p["app"])
        sev = "ok" if rc["primary"] is None and rc["confidence"] == "Confirmed" else "warning" if rc["primary"] else "info"
        d.kv([("Root cause", rc["text"], sev), ("Confidence", rc["confidence"]),
              ("Contributing", ", ".join(SCENARIO_TEXT[s] for s in rc["secondary"]) or "-")])
        d.text("INVESTIGATION SUMMARY:")
        for ln in p["summary"]:
            d.text(ln)
    # 9. Internal
    d.h2("9. Internal PlatformOps Recommendations (NOT for customer)")
    if not R["internal"]:
        d.bullet("No action required based on collected evidence.", "ok")
    for rec in R["internal"]:
        d.bullet(f"[{rec['app']}] {rec['text']}", "warning")
        for e in rec["evidence"][:4]:
            d.bullet("Evidence: " + e, None, 1)
    # 10. Customer
    d.h2("10. Customer-Shareable Recommendations")
    d.text(">>> BEGIN CUSTOMER RESPONSE >>>")
    for c in R["customer"]:
        d.text(c["title"] + (f" ({', '.join(c['apps'])})" if c.get("apps") else ""))
        d.text(c["text"])
        d.blank()
    d.text("<<< END CUSTOMER RESPONSE <<<")
    # 11. Evidence
    d.h2("11. Evidence and Supporting Logs")
    for p in top:
        fa, sl = p.get("fpm") or {}, p.get("slow") or {}
        d.h3(p["app"])
        if fa.get("slowest_requests"):
            d.table(["Time", "Mth", "St", "Sec", "MB", "CPU%", "URI (slowest)"], [list(r) for r in fa["slowest_requests"][:5]],
                    align=["l", "l", "l", "r", "r", "r", "l"], maxw=[0, 0, 0, 0, 0, 0, 44])
        if fa.get("top_cpu_requests"):
            d.table(["Time", "Mth", "St", "Sec", "MB", "CPU%", "URI (most CPU)"], [list(r) for r in fa["top_cpu_requests"][:5]],
                    align=["l", "l", "l", "r", "r", "r", "l"], maxw=[0, 0, 0, 0, 0, 0, 44])
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
    d.h2("12. Final Investigation Summary")
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
    ap.add_argument("--report", action="store_true", help="Save the report to a timestamped file")
    ap.add_argument("--format", choices=["txt", "markdown"], default="txt", help="Report/terminal format (default txt)")
    ap.add_argument("--output-dir", default="/tmp", help="Directory for --report / --json files (default /tmp)")
    ap.add_argument("--json", action="store_true", help="Also save machine-readable JSON results")
    ap.add_argument("--skip-health", action="store_true", help="Skip optional server checks (Redis, Varnish, OOM, filesystems)")
    ap.add_argument("--skip-mysql", action="store_true", help="Skip MySQL/MariaDB investigation")
    ap.add_argument("--skip-history", action="store_true", help="Skip atop historical analysis")
    ap.add_argument("--explain", action="store_true", help="Run EXPLAIN (read-only) for top suspected full-scan SELECTs")
    ap.add_argument("--fpm-log-glob", default="/var/log/php*-fpm.log*")
    ap.add_argument("--pool-conf-glob", default="/etc/php/*/fpm/pool.d/*.conf,/etc/php-fpm.d/*.conf",
                    help="Comma-separated globs of PHP-FPM pool configs")
    ap.add_argument("--atop-timeout", type=float, default=90)
    ap.add_argument("--cpu-threshold", type=float, default=20, help="High CPU = this %% of server capacity (default 20)")
    ap.add_argument("--mem-threshold", type=float, default=15, help="High memory = this %% of RAM (default 15)")
    ap.add_argument("--cpu-ms-per-req-threshold", type=float, default=400, help="Inefficient PHP above this CPU ms/request (default 400)")
    ap.add_argument("--slow-p95-seconds", type=float, default=3, help="Slow PHP when p95 duration >= this (default 3s)")
    ap.add_argument("--slow-query-min", type=int, default=10, help="Min slow queries per DB to flag (default 10)")
    ap.add_argument("--long-query-seconds", type=int, default=10, help="Running query considered long (default 10s)")
    ap.add_argument("--steal-threshold", type=float, default=8)
    ap.add_argument("--long-request-seconds", type=float, default=10,
                    help="Live: FPM worker busy continuously this long = long-running request (default 10)")
    ap.add_argument("--bg-cpu-threshold", type=float, default=10, help="Background process CPU %% of one core to flag (default 10)")
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
    for p in top:
        ap = apps[p["app"]]
        ctx.progress(f"[{p['app']}] deep analysis: FPM access log, traffic, slow log")
        p["fpm"] = analyze_fpm_access(ctx, ap, start, end, deep=True)
        p["traffic"] = analyze_traffic(ctx, ap, start, end)
        p["slow"] = analyze_slowlog(ctx, ap, start, end)
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

    oom = scan_oom(ctx, start, end) if not args.skip_health else {"events": [], "by_process": [], "sources": []}
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
    R = {"origin": origin, "db_map_src": db_map_src, "hostname": host, "server_ip": ip, "generated": now.strftime("%Y-%m-%d %H:%M:%S"), "window_desc": window_desc,
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
    doc = build_report(ctx, R)
    color = sys.stdout.isatty() and not args.no_color and args.format == "txt" and not os.environ.get("NO_COLOR")
    sys.stdout.write(doc.render(args.format, color))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
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

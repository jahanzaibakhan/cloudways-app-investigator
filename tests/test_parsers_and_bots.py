import importlib.util, tempfile, os
from pathlib import Path
from datetime import datetime
spec = importlib.util.spec_from_file_location("cw", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analyze_cloudways_applications.py"))
cw = importlib.util.module_from_spec(spec); spec.loader.exec_module(cw)
L = '119.63.128.155 - [26/Oct/2026:06:20:21 +0000] "GET /index.php" 200 0 - 3197700 3952116 0.253 2097152 3.95% 7.90% "/"'
m = cw.FPM_ACCESS_RE.match(L); assert m, "fpm"; print("fpm", m["dur"], m["mem"], m["cu"], m["cs"], m["uri"], m["pid"])
B = '167.99.91.5 - - [23/Oct/2026:10:01:17 +0000] "POST /api/report.php HTTP/1.1" 200 194 "-" "curl/7.88.1"'
m = cw.ACCESS_RE.match(B); assert m; print("acc", m["ip"], m["uri"], m["status"], m["ua"], cw.ua_class(m["ua"]))
print("ts", cw.access_line_ts(B))
print(cw.sql_fingerprint("SELECT * FROM wp_posts WHERE ID IN (1,2,3) AND post_title='secret' LIMIT 10"))
print(cw.classify_uri("/wp-json/wc/v3/orders?x=1"), cw.classify_uri("/?wc-ajax=get_refreshed_fragments"), cw.classify_uri("/xmlrpc.php"))
print(cw.POOL_SUFFIX_RE.sub("", "nmjnhthbxz-84"))
l = 'PRG 1503702 1794470402 2026/11/12 08:00:02 300 3316322 (php-fpm8.3) S 1024 33 3316322 1 0 1794441612 (php-fpm: pool mpwbkwzdmg-83          ) 455947 0 1'
m = cw.ATOP_PROC_RE.match(l); print("atop", m.group(7), m.group(8), m.group(9), m.group(10)[:40])
# fpm config parse with include
d = tempfile.mkdtemp()
Path(d, "cw.conf").write_text("pm = dynamic\npm.max_children = 10\n")
Path(d, "app.conf").write_text("pm.max_children = 25\n")
Path(d, "pool.conf").write_text(f"[abc-83]\nuser = abc\nlisten = /var/run/fpm-abc-83.sock\ninclude = {d}/cw.conf\nslowlog = /home/x/abc/logs/php-app.slow.log\ninclude = {d}/app.conf\n")
pools = {}; cw._parse_fpm_conf(Path(d, "pool.conf"), None, pools); print("pool", pools["abc-83"]["pm.max_children"], pools["abc-83"]["pm"], pools["abc-83"]["user"])
# mysql slow log
sl = Path(d, "slow.log"); sl.write_text("""/usr/sbin/mariadbd, Version: 11.4.12-MariaDB-deb12-log (mariadb.org binary distribution). started with:
Tcp port: 3306  Unix socket: /var/run/mysqld/mysqld.sock
Time\t\t    Id Command\tArgument
# Time: 261112  9:00:01
# User@Host: abc[abc] @ localhost []
# Thread_id: 6290  Schema: abc  QC_hit: No
# Query_time: 7.5  Lock_time: 0.000051  Rows_sent: 10  Rows_examined: 900000
# Rows_affected: 0  Bytes_sent: 91040388
SET timestamp=1794474001;
SELECT * FROM wp_options WHERE autoload = 'yes' AND option_name LIKE '%secret%';
# User@Host: abc[abc] @ localhost []
# Thread_id: 6290  Schema: abc  QC_hit: No
# Query_time: 6.0  Lock_time: 0.0  Rows_sent: 5  Rows_examined: 500
SET timestamp=1794474002;
SELECT /*!40001 SQL_NO_CACHE */ `id` FROM `alerts`;
""")
class A: explain=False; long_query_seconds=10
class C:
    args=A(); notes=[]
    def note(self,m): self.notes.append(m)
    def debug(self,m): pass
mres={"vars":{"slow_query_log_file":str(sl),"slow_query_log":"ON","long_query_time":"5"},"available":True}
r = cw.analyze_mysql_slowlog(C(), None, mres, {"abc":"abc"}, datetime(2026,11,12,8,0), datetime(2026,11,12,10,0))
print("slow", r["total"], r["dump_queries"], [(x["fingerprint"][:60], x["scan_suspect"], x["dump"]) for x in r["fingerprints"]], C.notes)
# FPM slowlog
ss = Path(d,"php-app.slow.log"); ss.write_text("""
[12-Nov-2026 09:10:00]  [pool abc-83] pid 123
script_filename = /home/1/abc/public_html/index.php
[0x00007f] curl_exec() /home/1/abc/public_html/wp-content/plugins/woo-sync/lib/api.php:88
[0x00007e] request() /home/1/abc/public_html/wp-includes/class-wp-hook.php:324
""")
app={"fpm_slow_logs":[ss]}
s = cw.analyze_slowlog(C(), app, datetime(2026,11,12,9,0), datetime(2026,11,12,10,0))
print("phpslow", s["entries"], s["components"], s["functions"])
# --- bot verification with a stubbed resolver (no network)
args = cw.build_parser().parse_args([])
v = cw.BotVerifier(cw.Ctx(args))
fake = {"66.249.66.1": ("crawl-66-249-66-1.googlebot.com", ["66.249.66.1"]),
        "185.220.101.5": ("tor-exit.example.net", ["185.220.101.5"]),
        "1.2.3.4": ("crawl.googlebot.com.evil.net", ["1.2.3.4"]),          # suffix trick
        "5.6.7.8": ("crawl-1.googlebot.com", ["9.9.9.9"])}                   # forward mismatch
def _fake(ip):
    if ip == "7.7.7.7":
        raise TimeoutError("resolver down")
    if ip == "8.8.4.9":
        raise cw.socket.herror(1, "Unknown host")
    return fake[ip]
v._lookup = _fake
r = v.verify("Googlebot", (".googlebot.com", ".google.com"), ["66.249.66.1"])
assert r["status"] == "verified", r
r = v.verify("Googlebot", (".googlebot.com",), ["185.220.101.5", "1.2.3.4", "5.6.7.8"])
assert r["status"].startswith("IMPERSONATION") and r["failed"] == 3, r
r = v.verify("Googlebot", (".googlebot.com",), ["7.7.7.7"])
assert r["failed"] == 0 and r["unknown"] == 1 and not r["status"].startswith("IMPERSONATION"), r   # timeout != impersonation
r = v.verify("Googlebot", (".googlebot.com",), ["8.8.4.9"])
assert r["failed"] == 1, r                                                                        # no PTR = failed
print("dns-verify ok")

# --- bot_level: shares alone must not flag a trivial-volume bot
args.window_s = 86400
c2 = cw.Ctx(args)
low = {"name": "UptimeRobot", "category": "monitor", "requests": 284, "pct": 59, "rpm": 0.2, "dynamic": 284, "php_cpu_share": 80, "php_cpu_s_est": 3.0}
assert cw.bot_level(c2, low, {}) == "NORMAL", cw.bot_level(c2, low, {})
seo = {"name": "AhrefsBot", "category": "seo", "requests": 30000, "pct": 35, "rpm": 21, "dynamic": 29000, "php_cpu_share": 60, "php_cpu_s_est": 20000.0}
assert cw.bot_level(c2, seo, {}) == "HIGH"
agent = {"name": "Node.js HTTP client", "category": "automation", "requests": 37583, "pct": 100, "rpm": 26, "dynamic": 37583,
         "php_cpu_share": 100, "php_cpu_s_est": 900.0}       # ~1% of a core over 24h: not a problem
assert cw.bot_level(c2, agent, {}) == "NORMAL", cw.bot_level(c2, agent, {})
args.window_s = 3600
c3 = cw.Ctx(args)
vol = {"name": "SemrushBot", "category": "seo", "requests": 6000, "pct": 8, "rpm": 100, "dynamic": 100, "php_cpu_share": 1, "php_cpu_s_est": 5.0}
assert cw.bot_level(c3, vol, {}) == "WARNING", cw.bot_level(c3, vol, {})       # volume alone -> WARNING, never HIGH
assert any("requests/hour" in r for r in vol["reasons"]), vol["reasons"]
print("bot-level ok")
# --- CRITICAL/HIGH app-name highlighting: colour only in terminal, alignment preserved, no partial matches
d = cw.Doc(); d.highlight = {"shopapp": "critical", "blogapp": "high"}
d.table(["App", "CPU"], [["shopapp", "90%"], ["blogapp", "50%"], ["shopapp2", "1%"]])
d.text("shopapp is slow", "critical")
txt, plain = d.render("txt", True), d.render("txt", False)
assert cw.ANSI_CODE_RE.sub("", txt) == plain
assert "\x1b[1;31m\x1b[4mshopapp" in txt and "\x1b[1;38;5;208m\x1b[4mblogapp" in txt and "\x1b[4mshopapp2" not in txt
assert "\x1b[" not in plain and "\x1b[" not in d.render("markdown", False)
print("highlight ok")

# --- Chrome version estimate (regression: 40.5-day cadence flagged current Chrome 148+ as "spoofed")
from datetime import datetime as _dt
est = cw.estimate_latest_chrome(_dt(2026, 11, 12))
assert 152 <= est <= 157, est
assert cw.estimate_latest_chrome(_dt(2025, 10, 28)) in range(140, 145)      # Chrome 142 shipped 2025-10-28
print("chrome-estimate ok", est)
# --- real log lines through analyze_traffic: current Chrome is a browser, only outdated/future versions are flagged
import tempfile as _tf
from datetime import timedelta as _td
_root = Path(_tf.mkdtemp()); (_root / "a" / "logs").mkdir(parents=True); (_root / "a" / "public_html").mkdir()
_now = cw.utcnow()
_lines = []
for _i, _v in enumerate([150] * 6 + [60] * 3 + [200] * 2):
    _t = (_now - _td(minutes=5) + _td(seconds=_i)).strftime("%d/%b/%Y:%H:%M:%S +0000")
    _lines.append(f'81.2.3.{_i} - - [{_t}] "GET / HTTP/1.1" 200 1 "-" "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/{_v}.0.0.0 Safari/537.36"')
(_root / "a" / "logs" / "backend_a.access.log").write_text("\n".join(_lines) + "\n")
_args = cw.build_parser().parse_args([]); _ctx = cw.Ctx(_args)
_t = cw.analyze_traffic(_ctx, cw.collect_apps([_root])["a"], _now - _td(hours=1), _now + _td(minutes=1))
_names = {b["name"]: b["requests"] for b in _t["bots"]}
assert _t["total"] == 11 and _t["bot_requests"] == 5, (_t["total"], _names)
assert any(n.startswith("Outdated Chrome") and c == 3 for n, c in _names.items()), _names
assert any(n.startswith("Future Chrome") and c == 2 for n, c in _names.items()), _names
print("chrome-ua-classification ok", _names)

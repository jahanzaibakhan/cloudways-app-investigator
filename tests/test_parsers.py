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

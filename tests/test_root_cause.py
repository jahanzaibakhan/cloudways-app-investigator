import importlib.util, os
spec = importlib.util.spec_from_file_location("cw", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analyze_cloudways_applications.py"))
cw = importlib.util.module_from_spec(spec); spec.loader.exec_module(cw)
args = cw.build_parser().parse_args([]); args.sample_seconds = 30
ctx = cw.Ctx(args)
cw.NCPU = 2
def prof(**kw):
    p = dict(app="a", domain="a.com", type="wordpress", db="a", cpu_sustained=150, cpu_source="atop history", cpu_live_avg=140, cpu_live_peak=190,
             cpu_hist_peak=180, cpu_hist_peak_at="09:10", cpu_server_share=75, mem_mb=900, mem_kind="PSS", mem_pct=20, procs_peak=10, busy_peak=4,
             busy_avg=2, proc_kinds={"fpm": 10}, long_cli=[], php_requests=40000, php_cpu_s=5000, php_req_share=80, php_cpu_share=82,
             cpu_ms_per_req=125, fpm_log_available=True, fpm={"requests": 40000, "p95": 0.6, "over": {}, "avg_mem": 40, "mem_max": 90},
             traffic={}, slow={}, pool={"listen": "/x.sock"}, mysql={}, max_children=10, tags=["High CPU + Memory"])
    p.update(kw); return p
srv = [cw.F("server", "critical", "Confirmed", "Sustained high server CPU utilisation", ["atop: avg 88% busy"])]
p1 = cw.investigate_app(ctx, prof(), {}, 1)
p2 = cw.investigate_app(ctx, prof(app="b", fpm_hits=12, php_cpu_share=60, php_req_share=20, cpu_ms_per_req=300,
        mysql={"slow": {"count": 400, "time": 2500, "max": 30}, "fingerprints": [{"db":"b","dump":False,"count":400,"time":2500,"avg_rows_ex":2e6,"fingerprint":"SELECT ...","scan_suspect":True,"avg_rows_sent":3}], "live": None, "long_running": []}), {}, 1)
p3 = cw.investigate_app(ctx, prof(app="c", cpu_server_share=3, cpu_sustained=6, mem_pct=2, tags=["Normal"], php_requests=50, php_req_share=1, php_cpu_share=1), {}, 1)
for p in (p1, p2, p3):
    print(p["app"], p["root_cause"], [f["text"][:50] for f in p["findings"]][:6])
    p["summary"] = cw.two_line_summary(p, "the last 1h"); print("  ", p["summary"][1])
i, c = cw.recommendations(ctx, [p1, p2, p3], srv, {})
print([x["title"] for x in c]); print([x["text"][:70] for x in i])

import random, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
root = Path(sys.argv[1] if len(sys.argv) > 1 else "fixture") / "applications"; random.seed(1)
now = datetime.now(timezone.utc).replace(tzinfo=None)
def ts(t): return t.strftime("%d/%b/%Y:%H:%M:%S +0000")
for app, n, heavy, attack in (("busyshop", 6000, False, False), ("slowblog", 400, True, False), ("botsite", 3000, False, True), ("quiet", 20, False, False)):
    logs = root/app/"logs"; logs.mkdir(parents=True, exist_ok=True)
    (root/app/"public_html").mkdir(exist_ok=True)
    (root/app/"public_html"/"wp-config.php").write_text(f"<?php define('DB_NAME', '{app}'); define('DB_PASSWORD','x');")
    b, f = [], []
    for i in range(n):
        t = now - timedelta(seconds=random.randint(0, 3500))
        if attack and random.random() < .6:
            ip, uri, ua, meth = "45.11.22.33", "/wp-login.php", "Mozilla/5.0 Chrome/60.0 Safari", "POST"
        else:
            ip = f"81.2.{random.randint(0,200)}.{random.randint(1,250)}"; uri = random.choice(["/", "/shop/", "/?wc-ajax=get_refreshed_fragments", "/wp-json/wc/v3/products", "/product/x/", "/wp-content/a.css"]); ua="Mozilla/5.0 (Windows NT 10.0) Chrome/140.0 Safari/537.36"; meth="GET"
        b.append((t, f'{ip} - - [{ts(t)}] "{meth} {uri} HTTP/1.1" 200 1234 "-" "{ua}"'))
        if not uri.endswith(".css"):
            dur = random.uniform(2, 12) if heavy else random.uniform(.05, .4)
            cpu = random.uniform(60, 95) if heavy else random.uniform(30, 80)
            mem = random.randint(150, 300)*1048576 if heavy else random.randint(20, 60)*1048576
            f.append((t, f'{ip} - [{ts(t)}] "{meth} /index.php" 200 0 - 111 {random.randint(1000,2000)} {dur:.3f} {mem} {cpu*.8:.2f}% {cpu*.2:.2f}% "{uri}"'))
    b.sort(); f.sort()
    (logs/f"backend_{app}.cloudwaysapps.com.access.log").write_text("\n".join(x for _, x in b) + "\n")
    (logs/"php-app.access.log").write_text("\n".join(x for _, x in f) + "\n")
    if heavy:
        st = (now - timedelta(minutes=10)).strftime("%d-%b-%Y %H:%M:%S")
        (logs/"php-app.slow.log").write_text(f"\n[{st}]  [pool {app}-83] pid 99\nscript_filename = /home/1/{app}/public_html/index.php\n[0x1] curl_exec() /home/1/{app}/public_html/wp-content/plugins/heavy-sync/api.php:88\n[0x2] apply_filters() /home/1/{app}/public_html/wp-includes/plugin.php:205\n")
print("ok")

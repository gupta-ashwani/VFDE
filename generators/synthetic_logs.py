"""Synthetic labelled log generator.

Writes realistic nginx-style access logs and sshd auth logs containing:
  * benign traffic, including deliberately tricky benign requests that naive
    pattern rules flag (e.g. a search for "O'Brien"), and
  * simulated suspicious activity patterns from documentation-range IPs.

Every simulated suspicious episode is recorded in ground_truth.csv so false
positives and recall can be measured later (Phase 5). This only writes text
log lines to local files; it sends no traffic anywhere.

Usage:  python generators/synthetic_logs.py --out sample_logs --seed 7
"""
import argparse
import csv
import os
import random
from datetime import datetime, timedelta, timezone

BENIGN_IPS = [f"10.0.{a}.{b}" for a in range(1, 4) for b in range(10, 40)]
ATTACKER_IPS = [f"203.0.113.{n}" for n in range(10, 60)]   # TEST-NET-3 (docs range)
BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]
PAGES = ["/", "/index.php", "/products", "/products?id=12", "/about", "/contact",
         "/login", "/account", "/static/app.js", "/static/site.css", "/faq"]
# Benign requests that look suspicious to naive regexes.
TRICKY_BENIGN = [
    "/search?q=O%27Brien",
    "/search?q=rock+%27n%27+roll",
    "/search?q=select+a+plan",
    "/search?q=union+budget+2025",
    "/search?q=i+%3C3+python",
    "/products?name=D%27Souza+%26+Sons",
    "/blog/how-to-choose-a-union-account",
    "/search?q=2+%3D+2",
    "/feedback?msg=it%27s+great+--+thanks",
    # Benign requests that DO match naive attack regexes (raw-rule false positives):
    "/search?q=union+select+committee+members",
    "/search?q=solve+x+or+2%3D2+proof",
    "/blog/why-we-sleep(8)-hours",
    "/feedback?msg=see+you+tomorrow+--",
    "/search?q=how+to+use+the+%3Cscript%3E+tag",
    "/search?q=what+is+information_schema",
]
SQLI = ["/products?id=1%27+OR+%271%27%3D%271", "/products?id=1+UNION+SELECT+username,password+FROM+users--",
        "/products?id=1;+SELECT+sleep(5)--", "/products?id=1+AND+1%3D1+UNION+SELECT+table_name+FROM+information_schema.tables"]
XSS = ["/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "/search?q=%3Cimg+src%3Dx+onerror%3Dalert(1)%3E"]
TRAVERSAL = ["/download?file=../../../../etc/passwd", "/download?file=..%2f..%2f..%2f..%2fetc%2fpasswd"]
SCANNER_UAS = ["sqlmap/1.8", "Nikto/2.5.0", "gobuster/3.6", "Mozilla/5.00 (Nikto/2.1.6)"]
USERS = ["alice", "bob", "carol", "dave", "deploy"]
GUESSED = ["root", "admin", "test", "oracle", "ubuntu", "postgres"]


def web_line(ts, ip, url, status, size, ua, rt, method="GET"):
    t = ts.strftime("%d/%b/%Y:%H:%M:%S %z")
    return (f'{ip} - - [{t}] "{method} {url} HTTP/1.1" {status} {size} "-" "{ua}" rt={rt:.3f}')


def auth_line(ts, host, proc, pid, msg):
    stamp = ts.strftime("%b %d %H:%M:%S").replace(" 0", "  ", 1) if ts.day < 10 else ts.strftime("%b %d %H:%M:%S")
    return f"{stamp} {host} {proc}[{pid}]: {msg}"


class Gen:
    def __init__(self, seed, start):
        self.r = random.Random(seed)
        self.start = start
        self.web, self.auth, self.truth = [], [], []

    def _t(self, base, offset_s):
        return base + timedelta(seconds=offset_s)

    # ----- benign -----
    def benign(self, hours=24, per_hour=120):
        for h in range(hours):
            for _ in range(per_hour):
                ts = self.start + timedelta(hours=h, seconds=self.r.randint(0, 3599))
                ip = self.r.choice(BENIGN_IPS)
                if self.r.random() < 0.08:
                    url = self.r.choice(TRICKY_BENIGN)
                else:
                    url = self.r.choice(PAGES)
                status = self.r.choices([200, 301, 304, 404, 500], [80, 5, 7, 7, 1])[0]
                size = self.r.randint(300, 9000)
                self.web.append((ts, web_line(ts, ip, url, status, size,
                                              self.r.choice(BROWSER_UAS),
                                              self.r.uniform(0.01, 0.4))))
            # normal ssh: occasional typo then success, daytime only
            for _ in range(self.r.randint(0, 3)):
                ts = self.start + timedelta(hours=h, seconds=self.r.randint(0, 3599))
                if 6 <= ts.hour < 22:
                    ip, user = self.r.choice(BENIGN_IPS), self.r.choice(USERS)
                    if self.r.random() < 0.3:
                        self.auth.append((ts, auth_line(ts, "web01", "sshd", 2000 + h,
                                          f"Failed password for {user} from {ip} port 5{h:04d} ssh2")))
                        ts = ts + timedelta(seconds=8)
                    self.auth.append((ts, auth_line(ts, "web01", "sshd", 2100 + h,
                                      f"Accepted password for {user} from {ip} port 5{h:04d} ssh2")))

    def benign_noise(self, hours=24):
        """Legitimate behaviour that trips naive rules. NOT in ground truth, so any
        alert on these IPs counts as a false positive."""
        ips = self.r.sample(BENIGN_IPS, 6)
        # 1) broken page: browser requests many missing assets in seconds (scan_404 FP)
        for ip in ips[:2]:
            t0 = self.start + timedelta(seconds=self.r.randint(0, hours * 3600 - 60))
            ua = self.r.choice(BROWSER_UAS)
            for i in range(self.r.randint(16, 22)):
                t = t0 + timedelta(seconds=i * 0.8)
                self.web.append((t, web_line(t, ip, f"/static/img/missing{i}.png", 404, 162, ua, 0.003)))
        # 2) user forgot password: many failures then success (brute_force FP)
        for ip in ips[2:4]:
            t0 = self.start + timedelta(hours=self.r.randint(8, 18), seconds=self.r.randint(0, 3000))
            for i in range(self.r.randint(5, 7)):
                t = t0 + timedelta(seconds=i * 6)
                self.auth.append((t, auth_line(t, "web01", "sshd", 5000 + i,
                                  f"Failed password for alice from {ip} port 6{i:04d} ssh2")))
            t = t + timedelta(seconds=9)
            self.auth.append((t, auth_line(t, "web01", "sshd", 5100,
                              f"Accepted password for alice from {ip} port 60099 ssh2")))
        # 3) on-call admin logs in at 02:00 UTC (off_hours_login FP)
        for ip in ips[4:6]:
            t = self.start + timedelta(hours=2, minutes=self.r.randint(0, 50))
            self.auth.append((t, auth_line(t, "web01", "sshd", 5200,
                              f"Accepted publickey for deploy from {ip} port 60123 ssh2")))
        # 4) legit uptime monitor with a tool-like user agent
        ip = "10.0.9.99"
        for i in range(12):
            t = self.start + timedelta(minutes=i * 60)
            self.web.append((t, web_line(t, ip, "/health", 200, 15, "Nmap Scripting Engine (uptime-check)", 0.01)))

    def _truth(self, ip, technique, mitre, t0, t1, rule_ids):
        self.truth.append(dict(src_ip=ip, technique=technique, mitre=mitre,
                               start=t0.isoformat(), end=t1.isoformat(),
                               expected_rules="|".join(rule_ids)))

    # ----- simulated suspicious episodes -----
    def episode_brute_force(self, ip, t0, succeed=False):
        t = t0
        for i in range(self.r.randint(12, 25)):
            t = t0 + timedelta(seconds=i * 2)
            user = self.r.choice(GUESSED)
            self.auth.append((t, auth_line(t, "web01", "sshd", 3000 + i,
                              f"Failed password for invalid user {user} from {ip} port 4{i:04d} ssh2")))
        rules = ["brute_force"]
        if succeed:
            t = t + timedelta(seconds=3)
            self.auth.append((t, auth_line(t, "web01", "sshd", 3999,
                              f"Accepted password for deploy from {ip} port 49999 ssh2")))
            rules.append("success_after_failures")
        self._truth(ip, "ssh_brute_force", "T1110", t0, t, rules)

    def episode_scan(self, ip, t0):
        t = t0
        ua = self.r.choice(SCANNER_UAS)
        for i in range(self.r.randint(40, 80)):
            t = t0 + timedelta(seconds=i * 0.3)
            self.web.append((t, web_line(t, ip, f"/{self.r.choice(['admin','backup','old','test','.git','wp-login','phpmyadmin'])}{i}",
                                         404, 162, ua, 0.004)))
        self._truth(ip, "dir_enumeration", "T1595", t0, t, ["scan_404", "scanner_user_agent"])

    def episode_web(self, ip, t0, kind):
        pool, rule, mitre = {
            "sqli": (SQLI, "sqli_pattern", "T1190"),
            "xss": (XSS, "xss_pattern", "T1190"),
            "traversal": (TRAVERSAL, "path_traversal", "T1083"),
        }[kind]
        ua = self.r.choice(BROWSER_UAS)
        t = t0
        for i in range(self.r.randint(3, 8)):
            t = t0 + timedelta(seconds=i * 4)
            status = self.r.choice([200, 200, 500]) if kind == "sqli" else 200
            size = self.r.randint(6000, 40000) if status == 200 and kind != "xss" else self.r.randint(300, 900)
            rt = self.r.uniform(4.9, 5.4) if "sleep" in pool[i % len(pool)] else self.r.uniform(0.02, 0.5)
            self.web.append((t, web_line(t, ip, pool[i % len(pool)], status, size, ua, rt)))
        self._truth(ip, kind, mitre, t0, t, [rule])

    def attacks(self, hours=24):
        ips = self.r.sample(ATTACKER_IPS, 12)
        plan = [
            ("brute", False), ("brute", True), ("scan", None), ("scan", None),
            ("sqli", None), ("sqli", None), ("xss", None), ("xss", None),
            ("traversal", None), ("brute", False), ("sqli", None), ("scan", None),
        ]
        for ip, (kind, flag) in zip(ips, plan):
            t0 = self.start + timedelta(seconds=self.r.randint(0, hours * 3600 - 600))
            if kind == "brute":
                self.episode_brute_force(ip, t0, succeed=flag)
            elif kind == "scan":
                self.episode_scan(ip, t0)
            else:
                self.episode_web(ip, t0, kind)

        # Multi-stage journeys (recon -> exploitation -> credential guessing/login),
        # so kill-chain correlation has real chains to join. Added after the single
        # episodes so those stay identical for a given seed.
        spare = [ip for ip in ATTACKER_IPS if ip not in ips]
        for ip in self.r.sample(spare, 2):
            t0 = self.start + timedelta(seconds=self.r.randint(0, hours * 3600 - 1800))
            self.episode_scan(ip, t0)
            self.episode_web(ip, t0 + timedelta(seconds=150), "sqli")
            self.episode_brute_force(ip, t0 + timedelta(seconds=420), succeed=True)

    def write(self, out):
        os.makedirs(out, exist_ok=True)
        for name, rows in (("access.log", self.web), ("auth.log", self.auth)):
            with open(os.path.join(out, name), "w", encoding="utf-8") as fh:
                for _, line in sorted(rows, key=lambda x: x[0]):
                    fh.write(line + "\n")
        with open(os.path.join(out, "ground_truth.csv"), "w", newline="", encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=["src_ip", "technique", "mitre", "start", "end", "expected_rules"])
            w.writeheader()
            w.writerows(self.truth)
        return len(self.web), len(self.auth), len(self.truth)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--out", default="sample_logs")
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--hours", type=int, default=24)
    ap.add_argument("--per-hour", type=int, default=120, help="benign web requests per hour")
    ap.add_argument("--year", type=int, default=datetime.now().year)
    args = ap.parse_args()

    start = datetime(args.year, 3, 14, 0, 0, 0, tzinfo=timezone.utc)
    g = Gen(args.seed, start)
    g.benign(args.hours, args.per_hour)
    g.benign_noise(args.hours)
    g.attacks(args.hours)
    web, auth, truth = g.write(args.out)
    print(f"wrote {web} web lines, {auth} auth lines, {truth} labelled episodes to {args.out}/")


if __name__ == "__main__":
    main()

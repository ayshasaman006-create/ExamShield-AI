"""Security-activity (exam log) analysis.

Expected log format, one event per line (CSV):
    timestamp,user,ip,action,status
    2026-10-26T09:14:05,student21,10.0.0.5,login,failed

Actions understood: login, view_question, submit_answer, tab_switch, copy_paste,
fullscreen_exit, access_admin, download_paper.  Status: ok | failed.
"""
from collections import defaultdict
from datetime import datetime

from risk import finding, score_findings


def parse_log(text):
    events, bad = [], 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.lower().startswith("timestamp"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 4:
            bad += 1
            continue
        try:
            ts = datetime.fromisoformat(parts[0])
        except ValueError:
            bad += 1
            continue
        events.append({"ts": ts, "user": parts[1], "ip": parts[2], "action": parts[3].lower(),
                       "status": (parts[4].lower() if len(parts) > 4 else "ok")})
    return events, bad


def analyze_activity(text):
    events, bad = parse_log(text)
    findings = []
    users = defaultdict(lambda: defaultdict(int))
    user_risk = defaultdict(list)

    def flag(user, f):
        findings.append(f)
        user_risk[user].append(f["points"])

    failed_by_user, failed_by_ip = defaultdict(int), defaultdict(set)
    ips_by_user = defaultdict(set)
    submits = defaultdict(list)
    for e in events:
        users[e["user"]][e["action"]] += 1
        if e["action"] == "login" and e["status"] == "failed":
            failed_by_user[e["user"]] += 1
            failed_by_ip[e["ip"]].add(e["user"])
        if e["action"] == "login" and e["status"] == "ok":
            ips_by_user[e["user"]].add(e["ip"])
        if e["action"] == "submit_answer":
            submits[e["user"]].append(e["ts"])

    for u, n in failed_by_user.items():
        if n >= 5:
            flag(u, finding("brute_force", f"Brute-force login on '{u}'",
                            f"{n} failed logins.", 55 if n >= 10 else 38))
    for ip, us in failed_by_ip.items():
        if len(us) >= 3:
            flag("IP " + ip, finding("cred_stuffing", "Credential stuffing from one IP",
                 f"{ip} failed logins across {len(us)} accounts: {', '.join(sorted(us))}.", 45))
    for u, ips in ips_by_user.items():
        if len(ips) >= 3:
            flag(u, finding("multi_ip", f"Account '{u}' used from {len(ips)} IPs",
                            "IPs: " + ", ".join(sorted(ips)) + ". Possible shared credentials or session hijack.", 32))
    for e in events:
        if e["action"] == "login" and e["status"] == "ok" and 0 <= e["ts"].hour < 5:
            flag(e["user"], finding("off_hours", f"Off-hours login by '{e['user']}'",
                                    f"{e['ts']:%H:%M} from {e['ip']}.", 14))
            break
    for u, c in users.items():
        if c["tab_switch"] >= 5:
            flag(u, finding("tab_switching", f"Excessive tab switching by '{u}'", f"{c['tab_switch']} switches.", 24))
        if c["copy_paste"] >= 3:
            flag(u, finding("copy_paste", f"Repeated copy/paste by '{u}'", f"{c['copy_paste']} events.", 26))
        if c["fullscreen_exit"] >= 3:
            flag(u, finding("fullscreen_exit", f"Left fullscreen mode: '{u}'", f"{c['fullscreen_exit']} times.", 20))
        if c["access_admin"] and not u.lower().startswith(("admin", "proctor", "staff")):
            flag(u, finding("priv_access", f"Admin area access by '{u}'",
                            f"{c['access_admin']} attempt(s) by a non-staff account.", 50))
        if c["download_paper"] >= 2:
            flag(u, finding("paper_download", f"Repeated paper downloads by '{u}'", f"{c['download_paper']} downloads.", 30))
    for u, ts in submits.items():
        ts.sort()
        for i in range(len(ts) - 4):
            if (ts[i + 4] - ts[i]).total_seconds() <= 60:
                flag(u, finding("rapid_submit", f"Implausibly fast answers by '{u}'",
                                "5 answers submitted within 60 seconds (bot / pre-known answers).", 22))
                break

    score, level = score_findings(findings)
    ranking = sorted(({"user": u, "points": min(100, sum(p)), "signals": len(p)} for u, p in user_risk.items()),
                     key=lambda x: -x["points"])
    return {"findings": findings, "score": score, "level": level,
            "meta": {"events": len(events), "users": len(users), "unparsed_lines": bad, "top_users": ranking[:5]}}

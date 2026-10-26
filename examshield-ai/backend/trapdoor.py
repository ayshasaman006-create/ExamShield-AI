"""Trapdoor (honeypot) mechanism.

Decoy resources look valuable (answer keys, DB backups, .env files) but no real
user or page ever links to them. Any request to one is, by definition,
suspicious, so it is logged and scored. Each decoy embeds a unique canary ID
so leaked copies can be traced back to the access that took them.
"""
import hashlib
import uuid

import database as db

# path -> (name, description, severity, points, content_type, body_factory)
DECOYS = {
    "/trap/admin/answer-key.pdf": ("Fake answer key", "Decoy 'answer key' download", "critical", 60),
    "/trap/exam/question-bank.zip": ("Fake question bank", "Decoy question-bank archive", "critical", 55),
    "/trap/api/v1/grades/export": ("Fake grade export API", "Decoy grade-export endpoint", "high", 45),
    "/trap/backup/db.sql": ("Fake DB backup", "Decoy database dump", "high", 45),
    "/trap/.env": ("Fake .env file", "Decoy secrets file (scanner bait)", "high", 40),
    "/trap/login": ("Fake admin login", "Decoy admin login form", "high", 40),
}

HONEYPOT_FIELD = "website"  # hidden form field: humans leave it empty, bots fill it


def canary_id(path, ip):
    return "CNRY-" + hashlib.sha1(f"{path}|{ip}|{uuid.uuid4()}".encode()).hexdigest()[:10].upper()


def decoy_body(path, canary):
    if path.endswith("answer-key.pdf"):
        return "application/pdf", f"%PDF-1.4\n% DECOY FILE {canary}\n% Not a real answer key.\n"
    if path.endswith(".zip"):
        return "application/zip", f"PK DECOY {canary}"
    if path.endswith(".sql"):
        return "text/plain", f"-- DECOY BACKUP {canary}\nINSERT INTO students VALUES (0,'honeypot','{canary}');\n"
    if path.endswith(".env"):
        return "text/plain", f"DB_PASSWORD=not-real-{canary}\nSECRET_KEY=decoy-{canary}\n"
    if "grades" in path:
        return "application/json", f'{{"status":"ok","canary":"{canary}","rows":[]}}'
    return "text/plain", f"decoy {canary}"


def record(trap_path, method, ip, ua, detail=""):
    name, desc, severity, points = DECOYS.get(trap_path, ("Unknown trap", "Decoy path", "high", 40))
    db.add_trap_hit(name, method, trap_path, ip, ua, detail or desc, severity, points)
    return name, severity, points


def record_honeypot_field(ip, ua, value):
    db.add_trap_hit("Hidden form field", "POST", "/api/trapdoor/form", ip, ua,
                    f"Bot filled hidden field '{HONEYPOT_FIELD}' ({len(value)} chars).", "medium", 28)


def catalog():
    return [{"path": p, "name": v[0], "description": v[1], "severity": v[2], "points": v[3]}
            for p, v in DECOYS.items()]


def robots_txt():
    dirs = sorted({p.rsplit("/", 1)[0] + "/" for p in DECOYS})
    return "\n".join(["User-agent: *"] + [f"Disallow: {d}" for d in dirs]) + "\n"

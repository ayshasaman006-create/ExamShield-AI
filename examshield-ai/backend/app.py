"""ExamShield AI - Flask backend + static frontend server.

Run:  python backend/app.py      then open http://localhost:5000
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from dotenv import load_dotenv
from flask import Flask, Response, jsonify, request, send_file, send_from_directory

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(ROOT, ".env"))

import ai_analyzer  # noqa: E402
import database as db  # noqa: E402
import report  # noqa: E402
import trapdoor  # noqa: E402
from activity_analyzer import analyze_activity  # noqa: E402
from email_analyzer import analyze_email  # noqa: E402
from risk import finding, level_for, score_findings  # noqa: E402

app = Flask(__name__, static_folder=os.path.join(ROOT, "frontend"), static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
db.init_db()


def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()


# ---------------------------------------------------------------- frontend
@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------- analysis
@app.post("/api/analyze/email")
def api_email():
    d = request.get_json(force=True, silent=True) or {}
    if not (d.get("body") or d.get("subject")):
        return jsonify(error="Enter a subject or message body to analyse."), 400
    res = analyze_email(d.get("sender", ""), d.get("subject", ""), d.get("body", ""),
                        d.get("attachments", ""), d.get("reply_to", ""))
    title = f"Email: {d.get('subject', '(no subject)')[:70]}"
    ai = ai_analyzer.analyze("This email", res["findings"], res["score"], res["level"])
    cid = db.add_case("email", title, res["score"], res["level"], res["findings"], ai, res["meta"])
    return jsonify(case=db.get_case(cid))


@app.post("/api/analyze/activity")
def api_activity():
    d = request.get_json(force=True, silent=True) or {}
    text = d.get("log", "")
    if not text.strip():
        return jsonify(error="Paste or upload an activity log first."), 400
    res = analyze_activity(text)
    if res["meta"]["events"] == 0:
        return jsonify(error="No valid log lines found. Expected: timestamp,user,ip,action,status"), 400
    ai = ai_analyzer.analyze("This activity log", res["findings"], res["score"], res["level"])
    title = f"Activity log: {res['meta']['events']} events, {res['meta']['users']} users"
    cid = db.add_case("activity", title, res["score"], res["level"], res["findings"], ai, res["meta"])
    return jsonify(case=db.get_case(cid))


# ---------------------------------------------------------------- trapdoors
@app.route("/trap/<path:p>", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
def trap(p):
    path = "/trap/" + p
    detail = ""
    if path == "/trap/login" and request.method == "POST":
        user = (request.form.get("username") or (request.get_json(silent=True) or {}).get("username") or "")[:40]
        detail = f"Login attempt with username '{user}' (password not stored)."
    trapdoor.record(path, request.method, client_ip(), request.headers.get("User-Agent", "")[:200], detail)
    canary = trapdoor.canary_id(path, client_ip())
    if path == "/trap/login":
        return Response("<form method=post>Admin login<input name=username><input name=password type=password></form>", mimetype="text/html")
    ctype, body = trapdoor.decoy_body(path, canary)
    return Response(body, mimetype=ctype)


@app.get("/robots.txt")
def robots():
    return Response(trapdoor.robots_txt(), mimetype="text/plain")


@app.post("/api/trapdoor/form")
def trap_form():
    d = request.get_json(force=True, silent=True) or {}
    if d.get(trapdoor.HONEYPOT_FIELD):
        trapdoor.record_honeypot_field(client_ip(), request.headers.get("User-Agent", "")[:200], str(d[trapdoor.HONEYPOT_FIELD]))
        return jsonify(ok=True)  # look successful to the bot
    return jsonify(ok=True, note="Message received.")


@app.get("/api/trapdoor/config")
def trap_config():
    return jsonify(decoys=trapdoor.catalog(), honeypot_field=trapdoor.HONEYPOT_FIELD)


@app.get("/api/trapdoor/hits")
def trap_hits():
    return jsonify(hits=db.list_trap_hits())


# ---------------------------------------------------------------- dashboard
def posture():
    cases, hits = db.list_cases(), db.list_trap_hits()
    pts = [{"points": c["score"] * 0.85} for c in sorted(cases, key=lambda c: -c["score"])[:5]]
    pts += [{"points": min(h["points"], 60) * 0.7} for h in hits[:10]]
    score, _ = score_findings(pts)
    return score, level_for(score), cases, hits


@app.get("/api/dashboard")
def dashboard():
    score, level, cases, hits = posture()
    dist = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for c in cases:
        dist[c["level"]] += 1
    top = sorted((f for c in cases for f in c["findings"]), key=lambda f: -f["points"])[:5]
    return jsonify(posture={"score": score, "level": level}, totals={"cases": len(cases), "trap_hits": len(hits)},
                   distribution=dist, recent_cases=[{k: c[k] for k in ("id", "created_at", "kind", "title", "score", "level")} for c in cases[:6]],
                   recent_hits=hits[:6], top_findings=top, ai_enabled=bool(os.getenv("ANTHROPIC_API_KEY")))


@app.get("/api/cases")
def cases():
    return jsonify(cases=[{k: c[k] for k in ("id", "created_at", "kind", "title", "score", "level")} for c in db.list_cases()])


@app.get("/api/cases/<int:cid>")
def case(cid):
    c = db.get_case(cid)
    return (jsonify(case=c) if c else (jsonify(error="Case not found"), 404))


# ---------------------------------------------------------------- reports
@app.get("/api/report/case/<int:cid>")
def report_case(cid):
    c = db.get_case(cid)
    if not c:
        return jsonify(error="Case not found"), 404
    path = os.path.join(ROOT, "reports", f"examshield_case_{cid}.pdf")
    report.case_report(c, path)
    return send_file(path, mimetype="application/pdf", as_attachment=True, download_name=f"examshield_case_{cid}.pdf")


@app.get("/api/report/overview")
def report_overview():
    score, level, cases_, hits = posture()
    path = os.path.join(ROOT, "reports", "examshield_assessment.pdf")
    report.overview_report(cases_, hits, db.now(), score, level, path)
    return send_file(path, mimetype="application/pdf", as_attachment=True, download_name="examshield_assessment.pdf")


# ---------------------------------------------------------------- samples / demo
@app.get("/api/samples")
def samples():
    sd = os.path.join(ROOT, "sample_data")
    with open(os.path.join(sd, "emails.json"), encoding="utf-8") as f:
        emails = json.load(f)
    with open(os.path.join(sd, "activity_log.csv"), encoding="utf-8") as f:
        log = f.read()
    return jsonify(emails=emails, activity_log=log)


@app.post("/api/demo/reset")
def reset():
    db.clear_all()
    return jsonify(ok=True)


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    print(f"\n  ExamShield AI running at http://localhost:{port}\n")
    app.run(host="127.0.0.1", port=port, debug=True)

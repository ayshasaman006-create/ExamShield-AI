# ExamShield AI

AI-powered examination security and threat detection platform (working prototype).

| Capability | Where it lives |
|---|---|
| AI-powered threat analysis | `backend/ai_analyzer.py` (Claude API, with an offline fallback) |
| Trapdoor-based detection | `backend/trapdoor.py` + `/trap/*` decoy routes |
| Risk scoring | `backend/risk.py` |
| Email and security activity analysis | `backend/email_analyzer.py`, `backend/activity_analyzer.py` |
| Automated PDF report generation | `backend/report.py` (ReportLab) |
| Web interface | `frontend/` (plain HTML, CSS, JS) |

## Run it in VS Code

1. Open this folder in VS Code and open a terminal (Ctrl+`).
2. Create a virtual environment and install dependencies:

   Windows:
   ```
   python -m venv venv
   venv\Scripts\activate
   pip install -r requirements.txt
   ```
   macOS / Linux:
   ```
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
3. (Optional) Enable real AI analysis: copy `.env.example` to `.env` and put your `ANTHROPIC_API_KEY` in it.
   Without a key the built-in offline analyst is used, so everything still works.
4. Start the server:
   ```
   python backend/app.py
   ```
5. Open http://localhost:5000 and click **Load demo data** on the dashboard.

## How it works

- **Email analysis**: checks look-alike sender domains, Reply-To mismatch, urgency wording, credential lures,
  exam-leak keywords, risky links (raw IP, shorteners, punycode) and dangerous attachments.
- **Activity analysis**: reads CSV logs (`timestamp,user,ip,action,status`) and detects brute force, credential
  stuffing, account sharing across IPs, off-hours logins, tab switching, copy/paste, fullscreen exits, admin probing,
  paper downloads and implausibly fast submissions. See `sample_data/activity_log.csv`.
- **Trapdoors**: decoy URLs (fake answer key, DB backup, `.env`, grade export, admin login) plus a hidden form field.
  Nothing legitimate links to them, so any hit is logged (IP, user agent, canary ID) and scored. They are advertised
  in `robots.txt` to attract scanners. Try them from the **Trapdoors** page.
- **Risk scoring**: every finding carries points; they combine as `100 * (1 - prod(1 - p/100))`, giving 0-100 and
  Low / Medium / High / Critical.
- **AI analysis**: findings go to Claude for a summary, likely attack type and recommended actions; offline fallback otherwise.
- **PDF reports**: per-case report and an overall assessment, downloadable from the UI
  (also saved in `reports/`).

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/api/analyze/email` | `{sender, reply_to, subject, body, attachments}` |
| POST | `/api/analyze/activity` | `{log}` |
| GET | `/api/dashboard`, `/api/cases`, `/api/cases/<id>` | results |
| GET | `/api/trapdoor/hits`, `/api/trapdoor/config` | trapdoor data |
| ANY | `/trap/...` | decoy endpoints |
| GET | `/api/report/case/<id>`, `/api/report/overview` | PDF reports |

## Customising

- Edit `TRUSTED_DOMAINS` in `backend/email_analyzer.py` to your institution's real domains.
- Tune thresholds and points in `backend/activity_analyzer.py`.
- Add decoys in `backend/trapdoor.py` (`DECOYS`).

## Prototype limits

SQLite, no user authentication, and Flask's dev server: fine for a demo, not for production. Do not expose it publicly as-is.

"""AI-powered threat analysis.

If ANTHROPIC_API_KEY is set, findings are sent to Claude for an analyst-style
assessment. If not (or if the call fails) a built-in offline analyst produces
a comparable structured result, so the prototype always works.
"""
import json
import os
import urllib.request

PLAYBOOK = {
    "spoofed_sender": ("Email spoofing / impersonation", "Block the look-alike domain and warn staff and students."),
    "reply_mismatch": ("Reply hijack", "Quarantine the message; verify the sender through a second channel."),
    "credential_lure": ("Phishing (credential harvesting)", "Reset exposed passwords and enforce MFA."),
    "exam_leak": ("Exam-integrity abuse", "Escalate to the exam controller and preserve the message as evidence."),
    "ip_link": ("Malicious link", "Block the IP at the proxy and scan clicks in web logs."),
    "short_link": ("Obfuscated link", "Expand the link in a sandbox before anyone clicks it."),
    "punycode": ("Homograph attack", "Block the domain; add punycode detection to the mail gateway."),
    "lookalike_link": ("Phishing link", "Block the domain and notify recipients."),
    "bad_attachment": ("Malware delivery", "Detonate the attachment in a sandbox; do not open it."),
    "double_ext": ("Malware delivery", "Delete the message and scan affected mailboxes."),
    "brute_force": ("Brute-force attack", "Lock the account, require a reset and add rate limiting."),
    "cred_stuffing": ("Credential stuffing", "Block the source IP and force resets on targeted accounts."),
    "multi_ip": ("Account sharing / hijack", "Terminate sessions and re-authenticate the candidate."),
    "off_hours": ("Unusual access time", "Review the session and confirm with the candidate."),
    "tab_switching": ("Possible cheating", "Flag the attempt for manual proctor review."),
    "copy_paste": ("Possible cheating", "Review the answers for copied content."),
    "fullscreen_exit": ("Possible cheating", "Review the session recording, if available."),
    "priv_access": ("Privilege escalation", "Suspend the account and audit admin access logs."),
    "paper_download": ("Exam paper exfiltration", "Revoke the candidate's access and check for leaked copies."),
    "rapid_submit": ("Automation / pre-known answers", "Compare answer timing against the cohort."),
}


def _offline(context, findings, score, level):
    if not findings:
        return {"source": "offline-analyst", "summary": "No suspicious indicators were found in the supplied data.",
                "attack_type": "None detected", "confidence": "high", "recommendations": ["Continue routine monitoring."]}
    top = sorted(findings, key=lambda f: -f["points"])
    kinds, recs = [], []
    for f in top:
        kind, rec = PLAYBOOK.get(f["id"], ("Suspicious activity", "Investigate manually."))
        if kind not in kinds:
            kinds.append(kind)
        if rec not in recs:
            recs.append(rec)
    summary = (f"{context} scored {score}/100 ({level}). {len(findings)} indicator(s) were detected; "
               f"the strongest is '{top[0]['title']}'. Likely threat type: {kinds[0]}."
               + (f" Related patterns: {', '.join(kinds[1:3])}." if len(kinds) > 1 else ""))
    return {"source": "offline-analyst", "summary": summary, "attack_type": kinds[0],
            "confidence": "high" if len(findings) >= 3 else "medium", "recommendations": recs[:5]}


def analyze(context, findings, score, level):
    key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    if not key:
        return _offline(context, findings, score, level)
    prompt = (
        "You are a security analyst for an online examination platform. Review these detections and reply with ONLY "
        'JSON: {"summary": str (2-3 sentences), "attack_type": str, "confidence": "low|medium|high", '
        '"recommendations": [up to 5 short strings]}.\n\n'
        f"Context: {context}\nRisk score: {score}/100 ({level})\nFindings:\n{json.dumps(findings, indent=1)}"
    )
    body = json.dumps({"model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-6"), "max_tokens": 700,
                       "messages": [{"role": "user", "content": prompt}]}).encode()
    req = urllib.request.Request("https://api.anthropic.com/v1/messages", data=body, method="POST", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
        text = "".join(b.get("text", "") for b in data["content"]).replace("```json", "").replace("```", "").strip()
        out = json.loads(text)
        out["source"] = "claude"
        return out
    except Exception as exc:  # network error, bad key, bad JSON...
        fallback = _offline(context, findings, score, level)
        fallback["note"] = f"Claude API unavailable ({type(exc).__name__}); used offline analyst."
        return fallback

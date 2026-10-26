"""Email threat analysis: phishing, spoofing and exam-leak indicators."""
import re
from urllib.parse import urlparse

from risk import finding, score_findings

# Domains the institution really uses. Edit for your own institution.
TRUSTED_DOMAINS = ["university.edu", "examportal.edu", "college.ac.in"]

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "ow.ly"}
DANGEROUS_EXT = (".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1", ".iso", ".lnk", ".docm", ".xlsm", ".zip", ".rar")
URGENCY = ["urgent", "immediately", "within 24 hours", "account suspended", "verify your account",
           "act now", "final warning", "password expires", "locked", "confirm your identity"]
CREDENTIAL = ["password", "login", "log in", "sign in", "credentials", "otp", "one-time", "verify"]
LEAK_TERMS = ["answer key", "question paper", "leaked paper", "paper leak", "exam solution", "solved paper",
              "marks changed", "change my grade", "grade change", "pay and get", "guaranteed pass", "impersonat"]


def _urls(text):
    return re.findall(r"https?://[^\s<>\"')]+", text, flags=re.I)


def _domain(addr_or_url):
    s = addr_or_url.strip().lower()
    if "@" in s and "://" not in s:
        return s.rsplit("@", 1)[-1].strip(">")
    return (urlparse(s).hostname or "").lower()


def _lookalike(domain):
    """Return the trusted domain this one imitates, if any."""
    for t in TRUSTED_DOMAINS:
        if domain == t or domain.endswith("." + t):
            return None
    base = domain.split(".")[0]
    for t in TRUSTED_DOMAINS:
        tb = t.split(".")[0]
        norm = base.replace("0", "o").replace("1", "l").replace("rn", "m").replace("-", "")
        if norm == tb or (tb in base and base != tb) or _edit_distance(norm, tb) == 1:
            return t
    return None


def _edit_distance(a, b):
    if abs(len(a) - len(b)) > 1:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def analyze_email(sender, subject, body, attachments="", reply_to=""):
    text = f"{subject}\n{body}".lower()
    findings = []

    sdom = _domain(sender)
    if sdom:
        imitated = _lookalike(sdom)
        if imitated:
            findings.append(finding("spoofed_sender", "Look-alike sender domain",
                                    f"'{sdom}' imitates trusted domain '{imitated}'.", 40))
        elif sdom not in TRUSTED_DOMAINS and not any(sdom.endswith("." + t) for t in TRUSTED_DOMAINS):
            findings.append(finding("external_sender", "External sender",
                                    f"Sender domain '{sdom}' is not an institutional domain.", 8))
    if reply_to:
        rdom = _domain(reply_to)
        if rdom and sdom and rdom != sdom:
            findings.append(finding("reply_mismatch", "Reply-To differs from sender",
                                    f"Replies go to '{rdom}' instead of '{sdom}'.", 25))

    hits = [w for w in URGENCY if w in text]
    if hits:
        findings.append(finding("urgency", "Pressure / urgency language",
                                "Phrases found: " + ", ".join(hits[:5]), min(10 + 6 * len(hits), 28)))

    cred = [w for w in CREDENTIAL if w in text]
    if cred and _urls(body):
        findings.append(finding("credential_lure", "Credential-harvesting pattern",
                                "Message asks for login/verification and contains a link.", 25))

    leak = [w for w in LEAK_TERMS if w in text]
    if leak:
        findings.append(finding("exam_leak", "Exam-integrity keywords",
                                "Mentions: " + ", ".join(leak[:5]) + ". Possible leak sale, grade tampering or collusion.",
                                min(25 + 10 * len(leak), 55)))

    for u in _urls(body):
        host = _domain(u)
        if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
            findings.append(finding("ip_link", "Link points to a raw IP address", u, 30))
        elif host in URL_SHORTENERS:
            findings.append(finding("short_link", "Shortened link hides destination", u, 18))
        elif host.startswith("xn--") or ".xn--" in host:
            findings.append(finding("punycode", "Punycode (homograph) domain", u, 35))
        elif _lookalike(host):
            findings.append(finding("lookalike_link", "Link to look-alike domain", f"{host} imitates {_lookalike(host)}", 35))
        elif u.lower().startswith("http://"):
            findings.append(finding("insecure_link", "Unencrypted link (http)", u, 8))

    for a in [x.strip().lower() for x in re.split(r"[,\n;]", attachments) if x.strip()]:
        if a.endswith(DANGEROUS_EXT):
            findings.append(finding("bad_attachment", "Risky attachment type", a, 35))
        elif re.search(r"\.(pdf|docx?|xlsx?)\.(exe|scr|js|bat)$", a):
            findings.append(finding("double_ext", "Double file extension", a, 45))

    # de-duplicate by (id, detail)
    seen, unique = set(), []
    for f in findings:
        k = (f["id"], f["detail"])
        if k not in seen:
            seen.add(k)
            unique.append(f)
    score, level = score_findings(unique)
    return {"findings": unique, "score": score, "level": level,
            "meta": {"sender": sender, "subject": subject}}

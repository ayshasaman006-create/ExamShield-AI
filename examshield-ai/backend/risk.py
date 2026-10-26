"""Risk scoring engine.

Each finding carries `points` (0-95). Findings are combined with a
diminishing-returns formula so that many weak signals add up, but the
score never exceeds 100:  score = 100 * (1 - prod(1 - p/100))
"""

LEVELS = [(80, "Critical"), (55, "High"), (30, "Medium"), (0, "Low")]


def level_for(score):
    for threshold, name in LEVELS:
        if score >= threshold:
            return name
    return "Low"


def severity_for(points):
    if points >= 45:
        return "critical"
    if points >= 30:
        return "high"
    if points >= 15:
        return "medium"
    return "low"


def finding(fid, title, detail, points):
    return {
        "id": fid,
        "title": title,
        "detail": detail,
        "points": points,
        "severity": severity_for(points),
    }


def score_findings(findings):
    remaining = 1.0
    for f in findings:
        remaining *= 1 - min(f["points"], 95) / 100.0
    score = round(100 * (1 - remaining))
    return score, level_for(score)

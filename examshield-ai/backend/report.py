"""Automated PDF report generation (ReportLab)."""
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import HRFlowable, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

NAVY, TEAL = colors.HexColor("#12304a"), colors.HexColor("#2a7ca0")
LEVEL_COLORS = {"Low": "#2e7d4f", "Medium": "#b7791f", "High": "#c2410c", "Critical": "#b91c1c"}
styles = getSampleStyleSheet()
H1 = ParagraphStyle("h1", parent=styles["Title"], textColor=NAVY, fontSize=22, spaceAfter=2)
SUB = ParagraphStyle("sub", parent=styles["Normal"], textColor=colors.HexColor("#5b7083"), alignment=1, fontSize=10)
H2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=NAVY, spaceBefore=12, spaceAfter=4)
BODY = ParagraphStyle("body", parent=styles["BodyText"], fontSize=10, leading=14)
CELL = ParagraphStyle("cell", parent=styles["BodyText"], fontSize=8.5, leading=11)


def _p(t, s=BODY):
    return Paragraph(escape(str(t)), s)


def _head(story, title, generated):
    story += [Paragraph("EXAMSHIELD AI", H1), Paragraph(title, SUB), Spacer(1, 4),
              HRFlowable(width="100%", color=TEAL, thickness=1.2), Spacer(1, 6),
              _p(f"Generated: {generated}")]


def _score_block(story, score, level):
    col = LEVEL_COLORS.get(level, "#333333")
    t = Table([[f"{score}/100", level.upper() + " RISK"]], colWidths=[40 * mm, 60 * mm])
    t.setStyle(TableStyle([("TEXTCOLOR", (0, 0), (-1, -1), colors.white), ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(col)),
                           ("FONTSIZE", (0, 0), (-1, -1), 14), ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
                           ("ALIGN", (0, 0), (-1, -1), "CENTER"), ("TOPPADDING", (0, 0), (-1, -1), 8),
                           ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story += [Spacer(1, 6), t]


def _findings_table(story, findings):
    if not findings:
        story.append(_p("No findings."))
        return
    rows = [["Severity", "Finding", "Detail", "Pts"]]
    for f in sorted(findings, key=lambda x: -x["points"]):
        rows.append([f["severity"].upper(), _p(f["title"], CELL), _p(f["detail"], CELL), f["points"]])
    t = Table(rows, colWidths=[20 * mm, 55 * mm, 80 * mm, 12 * mm], repeatRows=1)
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                           ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f8")]),
                           ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8d3dc"))]))
    story.append(t)


def _ai_block(story, ai):
    story.append(Paragraph("AI Threat Analysis", H2))
    story.append(_p(ai.get("summary", "")))
    story.append(_p(f"Likely threat type: {ai.get('attack_type', 'n/a')}   |   Confidence: {ai.get('confidence', 'n/a')}   |   Engine: {ai.get('source', 'n/a')}"))
    story.append(Paragraph("Recommended actions", H2))
    for r in ai.get("recommendations", []):
        story.append(_p("•  " + r))


def case_report(case, path):
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"ExamShield AI - Case {case['id']}")
    story = []
    _head(story, f"Security Investigation Report - Case #{case['id']}", case["created_at"])
    story += [Spacer(1, 4), _p(f"Case: {case['title']}   |   Type: {case['kind']}")]
    _score_block(story, case["score"], case["level"])
    story.append(Paragraph("Detected Indicators", H2))
    _findings_table(story, case["findings"])
    _ai_block(story, case["ai"])
    doc.build(story)


def overview_report(cases, hits, generated, posture, level, path):
    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="ExamShield AI - Security Assessment")
    story = []
    _head(story, "Security Assessment Report", generated)
    _score_block(story, posture, level)
    story.append(Paragraph("Summary", H2))
    story.append(_p(f"{len(cases)} analysed case(s) and {len(hits)} trapdoor hit(s) are included in this assessment."))
    if cases:
        story.append(Paragraph("Cases", H2))
        rows = [["#", "Date", "Type", "Title", "Score", "Level"]]
        for c in cases:
            rows.append([c["id"], c["created_at"], c["kind"], _p(c["title"], CELL), c["score"], c["level"]])
        t = Table(rows, colWidths=[10 * mm, 34 * mm, 20 * mm, 68 * mm, 14 * mm, 20 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8d3dc")),
                               ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
    story.append(Paragraph("Trapdoor Activity", H2))
    if hits:
        rows = [["Time", "Trap", "IP", "Severity"]]
        for h in hits[:40]:
            rows.append([h["created_at"], _p(h["trap"], CELL), h["ip"], h["severity"]])
        t = Table(rows, colWidths=[38 * mm, 70 * mm, 36 * mm, 22 * mm], repeatRows=1)
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                               ("FONTSIZE", (0, 0), (-1, -1), 8.5), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#c8d3dc"))]))
        story.append(t)
    else:
        story.append(_p("No trapdoor hits recorded."))
    doc.build(story)

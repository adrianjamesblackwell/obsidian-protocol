#!/usr/bin/env python3
"""
reporting/generate_pdf_report.py

OBSIDIAN PROTOCOL — PDF Operation Report Generator

Produces a multi-page, professional PDF report using reportlab
Platypus. Uses the same data source as the HTML report
(collect_report_data.py), so there is never a data inconsistency
between the two formats.

This generator covers the full pipeline output: Executive Summary,
Correlation Engine, Purple Team Detection Coverage, Risk Scoring,
Coverage Heatmap, Telemetry Gap Analysis, Rule Quality, Root Cause
Discovery, Emulation Score, IOC Confidence & Decay, Attack Replay
Timeline, and the Blackwell Core reasoning layer (Evidence Graph,
BCA, BRS, Confidence Engine, Temporal Reasoning, Evidence Ranking,
Attack Path Prediction, and the Decision Engine's prioritized
findings).
"""

import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from collect_report_data import collect_report_context

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    HRFlowable, KeepTogether, Image, Flowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle
from reportlab.graphics import renderPDF

# --- Unicode font registration ---
# reportlab's default Helvetica font does not render the full Unicode
# range cleanly for all glyphs this report may need. DejaVu Sans gives
# full Unicode coverage and is used when available.
DEJAVU_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/local/lib/python3.12/dist-packages/matplotlib/mpl-data/fonts/ttf/DejaVuSans.ttf",
]
DEJAVU_BOLD_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    "/usr/local/lib/python3.12/dist-packages/matplotlib/mpl-data/fonts/ttf/DejaVuSans-Bold.ttf",
]
DEJAVU_OBLIQUE_PATHS = [
    "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf",
    "/usr/local/lib/python3.12/dist-packages/matplotlib/mpl-data/fonts/ttf/DejaVuSans-Oblique.ttf",
]


def _register_unicode_fonts():
    regular_path = next((p for p in DEJAVU_PATHS if os.path.exists(p)), None)
    bold_path = next((p for p in DEJAVU_BOLD_PATHS if os.path.exists(p)), None)
    oblique_path = next((p for p in DEJAVU_OBLIQUE_PATHS if os.path.exists(p)), None)

    if regular_path and bold_path:
        pdfmetrics.registerFont(TTFont("DejaVuSans", regular_path))
        pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold_path))
        if oblique_path:
            pdfmetrics.registerFont(TTFont("DejaVuSans-Oblique", oblique_path))
            return "DejaVuSans", "DejaVuSans-Bold", "DejaVuSans-Oblique"
        return "DejaVuSans", "DejaVuSans-Bold", "DejaVuSans"
    # Fall back to Helvetica if the font isn't found (some glyphs may
    # render incorrectly, but PDF generation won't fail)
    return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"


FONT_REGULAR, FONT_BOLD, FONT_ITALIC = _register_unicode_fonts()

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "reports", "obsidian_protocol_report.pdf")

# --- Palette ---
DARK_BG = colors.HexColor("#1a1a2e")
DARK_BG2 = colors.HexColor("#16213e")
ACCENT = colors.HexColor("#e94560")
ACCENT_SOFT = colors.HexColor("#ff6b81")
GREEN = colors.HexColor("#2ecc71")
RED = colors.HexColor("#e74c3c")
ORANGE = colors.HexColor("#e67e22")
YELLOW = colors.HexColor("#f1c40f")
BLUE = colors.HexColor("#3498db")
PURPLE = colors.HexColor("#9b59b6")
GREY = colors.HexColor("#888888")
LIGHT_GREY = colors.HexColor("#f4f4f8")
INK = colors.HexColor("#222233")


def risk_band_color(band: str):
    return {
        "CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN,
    }.get(band, GREY)


def severity_color(sev: str):
    return {
        "CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREY,
    }.get(sev, GREY)


# ============================================================
# Styles
# ============================================================

def build_styles():
    styles = getSampleStyleSheet()
    for style_name in ["Normal", "Title", "Heading1", "Heading2", "BodyText"]:
        styles[style_name].fontName = FONT_REGULAR

    styles.add(ParagraphStyle(
        "ObsidianTitle", parent=styles["Title"],
        fontName=FONT_BOLD, fontSize=30, textColor=colors.white, spaceAfter=6,
        alignment=TA_CENTER, leading=34,
    ))
    styles.add(ParagraphStyle(
        "ObsidianSubtitle", parent=styles["Normal"],
        fontName=FONT_REGULAR, fontSize=12, textColor=colors.HexColor("#c8c8e0"),
        alignment=TA_CENTER, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "ObsidianTag", parent=styles["Normal"],
        fontName=FONT_BOLD, fontSize=9, textColor=ACCENT_SOFT,
        alignment=TA_CENTER, spaceAfter=2, leading=12,
    ))
    styles.add(ParagraphStyle(
        "CoverMeta", parent=styles["Normal"],
        fontName=FONT_REGULAR, fontSize=9.5, textColor=colors.HexColor("#9a9ac0"),
        alignment=TA_CENTER, leading=14,
    ))
    styles.add(ParagraphStyle(
        "SectionHeader", parent=styles["Heading2"],
        fontName=FONT_BOLD, fontSize=15, textColor=DARK_BG, spaceBefore=18, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        "SectionKicker", parent=styles["Normal"],
        fontName=FONT_BOLD, fontSize=8.5, textColor=ACCENT, spaceBefore=0, spaceAfter=2,
        leading=11,
    ))
    styles.add(ParagraphStyle(
        "SubHeader", parent=styles["Heading2"],
        fontName=FONT_BOLD, fontSize=11.5, textColor=DARK_BG2, spaceBefore=12, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "Body", parent=styles["Normal"],
        fontName=FONT_REGULAR, fontSize=9.5, leading=14, textColor=INK,
        alignment=TA_JUSTIFY, spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "BodySmall", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=9, leading=12.5,
        textColor=INK,
    ))
    styles.add(ParagraphStyle(
        "BodyTiny", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=7.6, leading=10.5,
        textColor=colors.HexColor("#444455"),
    ))
    styles.add(ParagraphStyle(
        "Disclaimer", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=8, textColor=colors.grey,
        leading=11, alignment=TA_LEFT,
    ))
    styles.add(ParagraphStyle(
        "TOCEntry", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=11, leading=20,
        textColor=INK,
    ))
    styles.add(ParagraphStyle(
        "TOCNum", parent=styles["Normal"], fontName=FONT_BOLD, fontSize=11, leading=20,
        textColor=ACCENT,
    ))
    styles.add(ParagraphStyle(
        "KeyFindingTitle", parent=styles["Normal"], fontName=FONT_BOLD, fontSize=10.5,
        textColor=colors.white, leading=14,
    ))
    styles.add(ParagraphStyle(
        "KeyFindingBody", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=9,
        textColor=colors.HexColor("#e8e8f5"), leading=13,
    ))
    styles.add(ParagraphStyle(
        "MetricLabel", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=8,
        textColor=colors.HexColor("#666680"), leading=10, alignment=TA_CENTER,
    ))
    styles.add(ParagraphStyle(
        "MetricValue", parent=styles["Normal"], fontName=FONT_BOLD, fontSize=18,
        textColor=DARK_BG, leading=22, alignment=TA_CENTER,
    ))
    return styles


# ============================================================
# Cover page background + header/footer canvas
# ============================================================

class ObsidianCanvas(canvas.Canvas):
    """Custom canvas: dark cover page background on page 1, running
    header/footer with page numbers from page 2 onward."""

    def __init__(self, *args, **kwargs):
        canvas.Canvas.__init__(self, *args, **kwargs)
        self._page_count = 0
        self._saved_states = []

    def showPage(self):
        self._page_count += 1
        self._saved_states.append(dict(page_number=self._page_count))
        canvas.Canvas.showPage(self)

    def save(self):
        total = self._page_count + 1
        canvas.Canvas.save(self)


def _draw_cover_background(c, doc):
    page_w, page_h = letter
    c.saveState()
    # Full-bleed dark background
    c.setFillColor(DARK_BG)
    c.rect(0, 0, page_w, page_h, fill=1, stroke=0)
    # Accent gradient-like bands (simulated with rectangles of decreasing alpha-like color steps)
    band_colors = [DARK_BG2, colors.HexColor("#1f2a4d"), colors.HexColor("#24305a")]
    band_h = 1.0 * inch
    for i, bc in enumerate(band_colors):
        c.setFillColor(bc)
        c.rect(0, page_h - (i + 1) * band_h, page_w, band_h, fill=1, stroke=0)
    # Thin accent rule near the top
    c.setStrokeColor(ACCENT)
    c.setLineWidth(2)
    c.line(0.9 * inch, page_h - 3.15 * inch, page_w - 0.9 * inch, page_h - 3.15 * inch)
    # Footer accent rule
    c.setStrokeColor(colors.HexColor("#33335a"))
    c.setLineWidth(1)
    c.line(0.9 * inch, 0.9 * inch, page_w - 0.9 * inch, 0.9 * inch)
    c.restoreState()


def _draw_inner_header_footer(c, doc, ctx):
    page_w, page_h = letter
    c.saveState()
    # Header bar
    c.setFillColor(DARK_BG)
    c.rect(0, page_h - 0.45 * inch, page_w, 0.45 * inch, fill=1, stroke=0)
    c.setFillColor(colors.white)
    c.setFont(FONT_BOLD, 8.5)
    c.drawString(0.6 * inch, page_h - 0.30 * inch, "OBSIDIAN PROTOCOL")
    c.setFont(FONT_REGULAR, 7.5)
    c.setFillColor(colors.HexColor("#c8c8e0"))
    c.drawRightString(page_w - 0.6 * inch, page_h - 0.30 * inch,
                       "Adversarial Simulation & Detection Engineering")
    c.setStrokeColor(ACCENT)
    c.setLineWidth(1.4)
    c.line(0, page_h - 0.45 * inch, page_w, page_h - 0.45 * inch)

    # Footer
    c.setFillColor(colors.HexColor("#999999"))
    c.setFont(FONT_REGULAR, 7.5)
    c.drawString(0.6 * inch, 0.42 * inch, f"Generated {ctx['generated_at']}")
    c.drawCentredString(page_w / 2, 0.42 * inch, "Educational / Portfolio — Isolated Lab Environment Only")
    c.drawRightString(page_w - 0.6 * inch, 0.42 * inch, f"Page {c.getPageNumber()}")
    c.setStrokeColor(colors.HexColor("#dddde6"))
    c.setLineWidth(0.6)
    c.line(0.6 * inch, 0.58 * inch, page_w - 0.6 * inch, 0.58 * inch)
    c.restoreState()


def make_page_callback(ctx, is_cover_fn):
    def _cb(c, doc):
        if is_cover_fn(doc):
            _draw_cover_background(c, doc)
        else:
            _draw_inner_header_footer(c, doc, ctx)
    return _cb


# ============================================================
# Small drawing helpers (mini risk gauge, bar, etc.)
# ============================================================

def make_score_gauge(score: float, band: str, width=110, height=110):
    """A small circular gauge showing the composite score 0-100."""
    d = Drawing(width, height)
    cx, cy, r = width / 2, height / 2, min(width, height) / 2 - 8
    # Background ring
    d.add(Circle(cx, cy, r, strokeColor=colors.HexColor("#e4e4ee"), strokeWidth=9, fillColor=None))
    # Foreground arc approximated via a thick circle when high, else partial via pie segments is
    # complex in plain shapes; use a simple colored ring sized by score for a clean visual proxy.
    pct = max(0.0, min(1.0, score / 100.0))
    ring_color = risk_band_color(band)
    # Draw a partial ring using short line segments around the circle
    import math
    steps = max(1, int(72 * pct))
    for i in range(steps):
        theta1 = math.pi / 2 - (2 * math.pi) * (i / 72)
        theta2 = math.pi / 2 - (2 * math.pi) * ((i + 1) / 72)
        x1, y1 = cx + r * math.cos(theta1), cy + r * math.sin(theta1)
        x2, y2 = cx + r * math.cos(theta2), cy + r * math.sin(theta2)
        d.add(Line(x1, y1, x2, y2, strokeColor=ring_color, strokeWidth=9))
    d.add(String(cx, cy + 3, f"{score:.0f}", fontName=FONT_BOLD, fontSize=20,
                 fillColor=DARK_BG, textAnchor="middle"))
    d.add(String(cx, cy - 14, "/ 100", fontName=FONT_REGULAR, fontSize=8,
                 fillColor=colors.grey, textAnchor="middle"))
    return d


def make_mini_bar(pct: float, width=90, height=8, color=None):
    """A small horizontal progress bar flowable for inline use in tables."""
    d = Drawing(width, height)
    d.add(Rect(0, 0, width, height, fillColor=colors.HexColor("#e8e8ee"), strokeColor=None))
    fill_w = max(1, width * max(0.0, min(1.0, pct / 100.0)))
    bar_color = color or (GREEN if pct >= 70 else YELLOW if pct >= 40 else RED)
    d.add(Rect(0, 0, fill_w, height, fillColor=bar_color, strokeColor=None))
    return d


# ============================================================
# Table builders
# ============================================================

def styled_table(data, col_widths, header=True, font_size=8.5, band_col=None, band_lookup=None,
                  align_cols=None):
    table = Table(data, colWidths=col_widths)
    cmds = [
        ("FONTSIZE", (0, 0), (-1, -1), font_size),
        ("FONTNAME", (0, 0), (-1, -1), FONT_REGULAR),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dadae4")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [colors.white, LIGHT_GREY]),
    ]
    if header:
        cmds += [
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
            ("FONTSIZE", (0, 0), (-1, 0), font_size + 0.3),
        ]
    if align_cols:
        for col in align_cols:
            cmds.append(("ALIGN", (col, 0), (col, -1), "CENTER"))
    table.setStyle(TableStyle(cmds))
    return table


def section_title(title, kicker, styles):
    return [Paragraph(kicker.upper(), styles["SectionKicker"]),
            Paragraph(title, styles["SectionHeader"]),
            HRFlowable(width="100%", thickness=1.2, color=colors.HexColor("#e0e0ea"), spaceAfter=10)]


def build_summary_metric_row(ctx, styles):
    """A 4-card horizontal metric strip for the executive summary."""
    s = ctx["summary"]
    coverage_display = f"{s['coverage_pct']}%" if s["coverage_pct"] is not None else "N/A"
    cards = [
        ("Detection Coverage", coverage_display),
        ("Total Attack Steps", str(s["total_attack_steps"])),
        ("Telemetry Events", str(ctx["telemetry_event_count"])),
        ("STIX Objects (IOC)", str(ctx["stix_object_count"])),
    ]
    row = []
    for label, value in cards:
        cell = [
            Paragraph(value, styles["MetricValue"]),
            Paragraph(label.upper(), styles["MetricLabel"]),
        ]
        row.append(cell)
    t = Table([row], colWidths=[1.5 * inch] * 4)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GREY),
        ("BOX", (0, 0), (-1, -1), 0.6, colors.HexColor("#d8d8e4")),
        ("INNERGRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#d8d8e4")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return t


def build_summary_table(ctx: dict, styles) -> Table:
    s = ctx["summary"]
    coverage_display = f"{s['coverage_pct']}%" if s["coverage_pct"] is not None else "N/A"

    data = [
        ["Metric", "Value"],
        ["Total Attack Steps", str(s["total_attack_steps"])],
        ["Detection Coverage", coverage_display],
        ["Average Detection Latency", f"{s['avg_detection_latency'] or 'N/A'}s"],
        ["Total Telemetry Events", str(ctx["telemetry_event_count"])],
        ["STIX Objects (IOC)", str(ctx["stix_object_count"])],
        ["Highest Risk", f"{s['highest_risk_cve'] or 'N/A'} ({s['highest_risk_score'] or 'N/A'}/100)"],
    ]
    return styled_table(data, [3 * inch, 3 * inch])


def build_coverage_table(ctx: dict, styles) -> Table:
    header = ["Vector", "CVE", "Attack Step", "MITRE", "Status"]
    data = [header]
    row_colors = [None]

    for r in ctx["coverage_results"]:
        status = f"DETECTED\n(+{r['detection_latency_seconds']}s)" if r["detected"] else "MISSED"
        data.append([
            r["vector"],
            r["cve"] or "-",
            Paragraph(r["attack_step"], styles["BodySmall"]),
            r["mitre_technique"] or "-",
            status,
        ])
        row_colors.append(GREEN if r["detected"] else RED)

    table = styled_table(data, [0.7 * inch, 1.1 * inch, 2.6 * inch, 0.7 * inch, 1.1 * inch])
    extra_cmds = []
    for i, c in enumerate(row_colors):
        if c:
            extra_cmds.append(("TEXTCOLOR", (4, i), (4, i), c))
            extra_cmds.append(("FONTNAME", (4, i), (4, i), FONT_BOLD))
    table.setStyle(TableStyle(extra_cmds))
    return table


def build_risk_table(ctx: dict, styles) -> Table:
    header = ["CVE", "Risk Band", "Score", "Rationale"]
    data = [header]
    band_colors = [None]

    for s in ctx["risk_scores"]:
        data.append([
            s["cve"],
            s["risk_band"],
            f"{s['composite_score']}/100",
            Paragraph(s["rationale"], styles["BodyTiny"]),
        ])
        band_colors.append(risk_band_color(s["risk_band"]))

    table = styled_table(data, [1.2 * inch, 1.0 * inch, 0.8 * inch, 3.2 * inch])
    extra_cmds = []
    for i, c in enumerate(band_colors):
        if c:
            extra_cmds.append(("BACKGROUND", (1, i), (1, i), c))
            extra_cmds.append(("TEXTCOLOR", (1, i), (1, i), colors.white))
            extra_cmds.append(("FONTNAME", (1, i), (1, i), FONT_BOLD))
            extra_cmds.append(("ALIGN", (1, i), (1, i), "CENTER"))
    table.setStyle(TableStyle(extra_cmds))
    return table


def build_correlation_table(ctx: dict, styles) -> Table:
    header = ["Severity", "Actor", "MITRE Chain", "Confidence", "Narrative"]
    data = [header]
    row_colors = [None]

    for inc in sorted(ctx["correlated_incidents"], key=lambda i: -i["confidence"]):
        data.append([
            inc["severity"],
            inc["actor_key"],
            " -> ".join(inc["mitre_chain"]) or "-",
            f"{inc['confidence']:.0f}%",
            Paragraph(inc["narrative"], styles["BodyTiny"]),
        ])
        row_colors.append(severity_color(inc["severity"]))

    table = styled_table(data, [0.75 * inch, 0.95 * inch, 1.15 * inch, 0.75 * inch, 2.65 * inch])
    extra_cmds = []
    for i, c in enumerate(row_colors):
        if c:
            extra_cmds.append(("TEXTCOLOR", (0, i), (0, i), c))
            extra_cmds.append(("FONTNAME", (0, i), (0, i), FONT_BOLD))
    table.setStyle(TableStyle(extra_cmds))
    return table


def build_metric_cards_table(items: list, styles) -> Table:
    """General-purpose 'metric card' table - used for single-line
    summary metrics like Coverage Heatmap, Emulation Score."""
    data = [[label, value] for label, value in items]
    table = Table(data, colWidths=[3.5 * inch, 2.5 * inch])
    table.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, -1), FONT_REGULAR),
        ("FONTNAME", (1, 0), (1, -1), FONT_BOLD),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dadae4")),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, LIGHT_GREY]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


def build_rule_quality_table(ctx: dict, styles) -> Table:
    header = ["Rule", "FP Risk", "Perf. Cost", "Coverage"]
    data = [header]
    for r in ctx["rule_quality"]:
        data.append([
            Paragraph(r["rule_file"], styles["BodySmall"]),
            "\u2605" * r["fp_risk_score"] + "\u2606" * (5 - r["fp_risk_score"]),
            "\u2605" * r["performance_cost_score"] + "\u2606" * (5 - r["performance_cost_score"]),
            "\u2605" * r["coverage_score"] + "\u2606" * (5 - r["coverage_score"]),
        ])
    return styled_table(data, [2.6 * inch, 1.13 * inch, 1.13 * inch, 1.13 * inch], align_cols=[1, 2, 3])


def build_ioc_table(ctx: dict, styles) -> Table:
    header = ["IOC", "Type", "Confidence", "Band", "Age (days)"]
    data = [header]
    band_colors = [None]
    band_color_map = {"ACTIVE": GREEN, "AGING": YELLOW, "STALE": ORANGE, "EXPIRED": RED}
    for i in ctx["ioc_confidence"]:
        data.append([
            Paragraph(i["ioc_value"], styles["BodyTiny"]),
            i["ioc_type"],
            f"{i['decayed_confidence']:.1f}",
            i["confidence_band"],
            f"{i['age_days']:.1f}",
        ])
        band_colors.append(band_color_map.get(i["confidence_band"], GREY))
    table = styled_table(data, [2.6 * inch, 1.1 * inch, 0.9 * inch, 0.9 * inch, 0.9 * inch], align_cols=[2, 3, 4])
    extra = []
    for i, c in enumerate(band_colors):
        if c:
            extra.append(("TEXTCOLOR", (3, i), (3, i), c))
            extra.append(("FONTNAME", (3, i), (3, i), FONT_BOLD))
    table.setStyle(TableStyle(extra))
    return table


def build_replay_table(ctx: dict, styles) -> Table:
    header = ["Timestamp", "Source", "Category", "CVE / Technique", "Signal"]
    data = [header]
    sig_colors = [None]
    for ev in ctx["attack_replay"]:
        ts = ev.get("timestamp", "")[:19].replace("T", " ")
        sig = "DETECTED" if ev.get("detected_by_purple_team") else (
            "OFFENSIVE" if ev.get("is_offensive_action") else "SIGNAL" if ev.get("is_detection_signal") else "INFO"
        )
        data.append([
            ts,
            ev.get("source", "-"),
            ev.get("category", "-"),
            f"{ev.get('cve') or '-'} / {ev.get('mitre_technique') or '-'}",
            sig,
        ])
        sig_colors.append({"DETECTED": GREEN, "OFFENSIVE": RED, "SIGNAL": ORANGE, "INFO": GREY}.get(sig))
    table = styled_table(data, [1.35 * inch, 1.15 * inch, 1.15 * inch, 1.45 * inch, 1.0 * inch], font_size=7.8,
                          align_cols=[4])
    extra = []
    for i, c in enumerate(sig_colors):
        if c:
            extra.append(("TEXTCOLOR", (4, i), (4, i), c))
            extra.append(("FONTNAME", (4, i), (4, i), FONT_BOLD))
    table.setStyle(TableStyle(extra))
    return table


def build_decision_table(ctx: dict, styles) -> Table:
    header = ["Rank", "Finding", "Priority", "Risk", "Confidence", "Root Cause"]
    data = [header]
    band_colors = [None]
    decisions = sorted(ctx["blackwell"]["decisions"], key=lambda d: d.get("rank", 999))
    for d in decisions:
        data.append([
            str(d.get("rank", "-")),
            Paragraph(d.get("label", "-"), styles["BodyTiny"]),
            f"{d.get('priority', 0):.2f}",
            f"{d.get('risk_band','-')} ({d.get('risk_score','-')})",
            f"{d.get('confidence', 0):.0%}",
            Paragraph(d.get("root_cause_primary", "-"), styles["BodyTiny"]),
        ])
        band_colors.append(risk_band_color(d.get("risk_band", "")))
    table = styled_table(
        data, [0.45 * inch, 1.55 * inch, 0.65 * inch, 1.0 * inch, 0.75 * inch, 1.7 * inch],
        font_size=7.8, align_cols=[0, 2, 4],
    )
    extra = []
    for i, c in enumerate(band_colors):
        if c:
            extra.append(("TEXTCOLOR", (3, i), (3, i), c))
            extra.append(("FONTNAME", (3, i), (3, i), FONT_BOLD))
    table.setStyle(TableStyle(extra))
    return table


def build_confidence_table(ctx: dict, styles) -> Table:
    header = ["Finding", "Confidence", "Corrob.", "Src. Diversity", "Pattern"]
    data = [header]
    for c in ctx["blackwell"]["confidence"]:
        comp = c.get("components", {})
        data.append([
            Paragraph(c.get("label", "-"), styles["BodyTiny"]),
            f"{c.get('confidence', 0):.0%}",
            f"{comp.get('corroboration', 0):.2f}",
            f"{comp.get('source_diversity', 0):.2f}",
            f"{comp.get('pattern_strength', 0):.2f}",
        ])
    return styled_table(data, [2.1 * inch, 0.85 * inch, 0.75 * inch, 1.15 * inch, 0.75 * inch], align_cols=[1, 2, 3, 4])


# ============================================================
# Document assembly
# ============================================================

def build_cover_page(ctx, styles, story):
    story.append(Spacer(1, 1.05 * inch))
    story.append(Paragraph("OBSIDIAN PROTOCOL", styles["ObsidianTitle"]))
    story.append(Paragraph("Adversarial Simulation &amp; Detection Engineering", styles["ObsidianSubtitle"]))
    story.append(Paragraph("Full Operation &amp; Reasoning Report", styles["ObsidianSubtitle"]))
    story.append(Spacer(1, 0.35 * inch))

    tags = "VECTOR-I: CVE-2021-41773 / CVE-2021-42013  &nbsp;&bull;&nbsp;  VECTOR-II: CVE-2021-4034 (PwnKit)"
    story.append(Paragraph(tags, styles["ObsidianTag"]))
    story.append(Spacer(1, 1.6 * inch))

    meta = (
        f"Generated: {ctx['generated_at']}<br/>"
        "Classification: Educational / Portfolio — Isolated Lab Environment<br/>"
        "Intelligence Sources: NVD &middot; CISA KEV &middot; CISA/FBI Advisories &middot; "
        "MITRE ATT&amp;CK &middot; OASIS STIX/TAXII"
    )
    story.append(Paragraph(meta, styles["CoverMeta"]))
    story.append(PageBreak())


def build_table_of_contents(ctx, styles, story):
    story += section_title("Table of Contents", "Report Map", styles)
    entries = [
        ("01", "Executive Summary"),
        ("02", "Operation Overview &amp; Attack Chain"),
        ("03", "Correlation Engine — Solving Alert Fatigue"),
        ("04", "Purple Team Detection Coverage"),
        ("05", "Risk Scoring Engine Results"),
        ("06", "Detection Coverage Heatmap (MITRE ATT&amp;CK)"),
        ("07", "Telemetry Gap Analysis"),
        ("08", "Rule Quality Analysis (WARDEN)"),
        ("09", "Root Cause Discovery"),
        ("10", "Adversary Emulation Quality Score"),
        ("11", "IOC Confidence &amp; Decay"),
        ("12", "Attack Replay Timeline"),
        ("13", "Blackwell Core — Evidence-Driven Reasoning Layer"),
        ("14", "Related Output Files &amp; Classification"),
    ]
    rows = []
    for num, label in entries:
        rows.append([Paragraph(num, styles["TOCNum"]), Paragraph(label, styles["TOCEntry"])])
    t = Table(rows, colWidths=[0.55 * inch, 5.45 * inch])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#e4e4ee")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(t)
    story.append(PageBreak())


def build_operation_overview(ctx, styles, story):
    story += section_title("Operation Overview &amp; Attack Chain", "Section 02", styles)
    story.append(Paragraph(
        "A real CVE chain from the CISA Known Exploited Vulnerabilities (KEV) catalog was "
        "reproduced end-to-end in an isolated, internet-disconnected Docker range: an externally "
        "facing Apache RCE (VECTOR-I) used to establish a foothold, followed by a local privilege "
        "escalation via the PwnKit vulnerability (VECTOR-II) to obtain root. The full lifecycle of "
        "this operation &mdash; attack, telemetry capture, correlation, detection validation, risk "
        "scoring, root cause analysis, intelligence export, and reporting &mdash; was automated "
        "across the 17-module pipeline summarized in this report, with the Blackwell Core reasoning "
        "layer synthesizing every module's output into a single auditable evidence structure.",
        styles["Body"],
    ))

    chain_data = [
        ["Stage", "Vector", "CVE", "MITRE", "Outcome"],
        ["Initial Access", "VECTOR-I", "CVE-2021-41773", "T1190", "Path traversal -> file read"],
        ["Execution", "VECTOR-I", "CVE-2021-42013", "T1059", "Command execution via CGI redirection"],
        ["Privilege Escalation", "VECTOR-II", "CVE-2021-4034", "T1548.001 / T1068", "Root shell via PwnKit (pkexec)"],
    ]
    story.append(styled_table(chain_data, [1.55 * inch, 0.95 * inch, 1.3 * inch, 1.1 * inch, 2.1 * inch], font_size=8.3))
    story.append(Spacer(1, 0.18 * inch))
    story.append(Paragraph(
        "<b>Why this chain is realistic:</b> the combination of an internet-facing RCE followed by "
        "local privilege escalation mirrors the standard structure of real-world intrusions, "
        "including the AndroxGh0st botnet campaign documented in the FBI/CISA joint advisory "
        "AA24-016A, which chains CVE-2021-41773 with credential-harvesting follow-on activity "
        "against more than 30,000 sites (see <i>docs/threat-intelligence.md</i>).",
        styles["BodySmall"],
    ))
    story.append(Spacer(1, 0.3 * inch))


def build_pdf(ctx: dict, output_path: str):
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    styles = build_styles()
    story = []

    # --- Cover page ---
    build_cover_page(ctx, styles, story)

    # --- Table of contents ---
    build_table_of_contents(ctx, styles, story)

    if ctx["missing_modules"]:
        warn_text = "\u26a0 Missing Module Data: " + "; ".join(ctx["missing_modules"])
        story.append(Paragraph(warn_text, ParagraphStyle("Warn", parent=styles["BodySmall"], textColor=RED)))
        story.append(Spacer(1, 0.15 * inch))

    # --- Executive Summary ---
    story += section_title("Executive Summary", "Section 01", styles)
    story.append(build_summary_metric_row(ctx, styles))
    story.append(Spacer(1, 0.18 * inch))
    story.append(build_summary_table(ctx, styles))
    story.append(Spacer(1, 0.3 * inch))

    # --- Operation Overview ---
    build_operation_overview(ctx, styles, story)
    story.append(PageBreak())

    # --- Correlation Engine ---
    story += section_title("Correlation Engine \u2014 Solving Alert Fatigue", "Section 03", styles)
    story.append(Paragraph(
        "SOC teams routinely face 20,000-200,000+ alerts per day, the overwhelming majority of "
        "which are not false alarms but fragments of the same operation that were never tied "
        "together. The Correlation Engine groups raw telemetry events by actor identity, time "
        "window, and MITRE technique sequence, matching the result against known kill-chain "
        "patterns to produce a small number of high-confidence incidents.",
        styles["Body"],
    ))
    if ctx["correlation_summary"]:
        cs = ctx["correlation_summary"]
        story.append(build_metric_cards_table([
            ("Raw Event Count", str(cs["raw_event_count"])),
            ("Correlated Incidents", str(cs["incident_count"])),
            ("Alert Reduction Ratio", f"{cs['reduction_pct']}%"),
        ], styles))
        story.append(Spacer(1, 0.15 * inch))
        story.append(build_correlation_table(ctx, styles))
    else:
        story.append(Paragraph("No data - correlation-engine/correlate.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Purple Team Coverage ---
    story += section_title("Purple Team Detection Coverage", "Section 04", styles)
    story.append(Paragraph(
        "Each attack step executed during the operation is checked against the WARDEN module's "
        "detection rules (Sigma/auditd/eBPF) to determine whether the step was actually caught, "
        "and how quickly.",
        styles["Body"],
    ))
    if ctx["coverage_results"]:
        story.append(build_coverage_table(ctx, styles))
    else:
        story.append(Paragraph("No data - purple-team/validate.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Risk Scoring ---
    story += section_title("Risk Scoring Engine Results", "Section 05", styles)
    story.append(Paragraph(
        "Risk is computed as a weighted composite of four signals: normalized CVSS, active "
        "exploitation in the wild (CISA KEV), campaign breadth (botnet/sector intelligence), and "
        "this project's own defense gap (how well WARDEN actually detects each CVE). The same CVSS "
        "score can therefore produce different risk scores depending on real-world exploitation "
        "and this environment's own detection coverage.",
        styles["Body"],
    ))
    if ctx["risk_scores"]:
        story.append(build_risk_table(ctx, styles))
        # Small gauge row for the top risk items
        top_scores = sorted(ctx["risk_scores"], key=lambda s: -s["composite_score"])[:3]
        if top_scores:
            gauge_row = []
            label_row = []
            for s in top_scores:
                gauge_row.append(make_score_gauge(s["composite_score"], s["risk_band"], 95, 95))
                label_row.append(Paragraph(f"<b>{s['cve']}</b><br/>{s['risk_band']}", styles["BodySmall"]))
            gt = Table([gauge_row, label_row], colWidths=[2.0 * inch] * len(top_scores))
            gt.setStyle(TableStyle([("ALIGN", (0, 0), (-1, -1), "CENTER"), ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
            story.append(Spacer(1, 0.12 * inch))
            story.append(gt)
    else:
        story.append(Paragraph("No data - risk-engine/risk_engine.py has not been run.", styles["BodySmall"]))

    story.append(PageBreak())

    # --- Coverage Heatmap (summary) ---
    story += section_title("Detection Coverage Heatmap (MITRE ATT&amp;CK)", "Section 06", styles)
    story.append(Paragraph(
        "Three distinct coverage concepts are tracked separately so that \u201cwe have a rule\u201d "
        "is never conflated with \u201cthe rule works\u201d: Rule Coverage (a Sigma/YARA rule "
        "exists), Validated Coverage (the rule actually caught an attack in this run), and Observed "
        "Coverage (the technique was seen at all during the operation).",
        styles["Body"],
    ))
    if ctx["coverage_heatmap"]:
        hm = ctx["coverage_heatmap"]
        rows = [["Tactic", "Validated Coverage", "Rule Coverage"]]
        for tactic, data in hm.items():
            if data.get("known_techniques_in_scope", 0) > 0:
                rows.append([tactic, "", ""])
        # Build with mini bars
        table_rows = [["Tactic", "Validated Coverage", "", "Rule Coverage", ""]]
        for tactic, data in hm.items():
            if data.get("known_techniques_in_scope", 0) > 0:
                vpct = data.get("validated_coverage_pct", 0)
                rpct = data.get("rule_coverage_pct", 0)
                table_rows.append([
                    tactic,
                    make_mini_bar(vpct, 70, 9),
                    f"{vpct}%",
                    make_mini_bar(rpct, 70, 9, color=BLUE),
                    f"{rpct}%",
                ])
        t = Table(table_rows, colWidths=[1.7 * inch, 1.0 * inch, 0.5 * inch, 1.0 * inch, 0.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
            ("FONTNAME", (0, 1), (0, -1), FONT_BOLD),
            ("FONTSIZE", (0, 0), (-1, -1), 8.3),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dadae4")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("ALIGN", (2, 0), (2, -1), "CENTER"),
            ("ALIGN", (4, 0), (4, -1), "CENTER"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT_GREY]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]))
        story.append(t)
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(
            "Note: percentages are computed over the set of techniques this project "
            "knows about/has labeled, not over all 216 MITRE techniques.",
            styles["Disclaimer"],
        ))
    else:
        story.append(Paragraph("No data - coverage-heatmap/heatmap.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Telemetry Gap ---
    story += section_title("Telemetry Gap Analysis", "Section 07", styles)
    story.append(Paragraph(
        "Identifies which MITRE tactics this environment cannot observe at all, by checking "
        "which of eight common telemetry sources are actually being collected.",
        styles["Body"],
    ))
    if ctx["telemetry_gap"]:
        tg = ctx["telemetry_gap"]
        data_rows = [
            ["Fully Visible", ", ".join(tg.get("visible_tactics", [])) or "-"],
            ["Partially Visible", ", ".join(tg.get("partial_tactics", [])) or "-"],
            ["Blind", ", ".join(tg.get("blind_tactics", [])) or "-"],
        ]
        table_data = [["Visibility", "Tactics"]] + [
            [r[0], Paragraph(r[1], styles["BodySmall"])] for r in data_rows
        ]
        t = styled_table(table_data, [1.3 * inch, 4.7 * inch], font_size=8.6)
        story.append(t)
        story.append(Spacer(1, 0.12 * inch))
        story.append(Paragraph("<b>Recommended Collection Priorities:</b>", styles["SubHeader"]))
        for i, rec in enumerate(tg.get("recommendations", []), 1):
            story.append(Paragraph(f"{i}. {rec}", styles["BodySmall"]))
    else:
        story.append(Paragraph("No data - telemetry-gap/gap_analysis.py has not been run.", styles["BodySmall"]))

    story.append(PageBreak())

    # --- Rule Quality ---
    story += section_title("Rule Quality Analysis (WARDEN)", "Section 08", styles)
    story.append(Paragraph(
        "Writing a Sigma rule is easy; writing a good one is hard. Each detection rule is "
        "statically scored across false-positive risk, performance cost, and MITRE/CVE coverage "
        "density, rather than just counted.",
        styles["Body"],
    ))
    if ctx["rule_quality"]:
        story.append(build_rule_quality_table(ctx, styles))
    else:
        story.append(Paragraph("No data - rule-quality/analyze_rules.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Root Cause ---
    story += section_title("Root Cause Discovery", "Section 09", styles)
    story.append(Paragraph(
        "Traces each CVE backward through its causal chain &mdash; from the immediate technical "
        "flaw to the organizational/process failure that allowed it &mdash; and pairs each finding "
        "with concrete preventive actions.",
        styles["Body"],
    ))
    if ctx["root_cause"]:
        for rc in ctx["root_cause"]:
            block = [
                Paragraph(f"<b>{rc['cve']}</b> &mdash; {rc['primary_cause']}", styles["BodySmall"]),
                Paragraph(" &rarr; ".join(rc.get("causal_chain", [])), styles["BodyTiny"]),
            ]
            if rc.get("preventive_actions"):
                actions = "<br/>".join(f"&bull; {a}" for a in rc["preventive_actions"])
                block.append(Paragraph(f"<b>Preventive actions:</b><br/>{actions}", styles["BodyTiny"]))
            story.append(KeepTogether(block))
            story.append(Spacer(1, 0.14 * inch))
    else:
        story.append(Paragraph("No data - root-cause/root_cause.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.2 * inch))

    # --- Emulation Score ---
    story += section_title("Adversary Emulation Quality Score", "Section 10", styles)
    story.append(Paragraph(
        "Measures the quality of the red-team operation itself, across attack diversity, MITRE "
        "matrix coverage, noise level, and detection success &mdash; rather than just whether an "
        "operation happened at all.",
        styles["Body"],
    ))
    if ctx["emulation_score"]:
        es = ctx["emulation_score"]
        story.append(build_metric_cards_table([
            ("Attack Diversity", f"{es.get('attack_diversity_pct', 'N/A')}%"),
            ("MITRE Matrix Coverage", f"{es.get('coverage_pct', 'N/A')}%"),
            ("Noise Level", str(es.get("noise_level", "N/A"))),
            ("Detection Success", f"{es.get('detection_success_pct', 'N/A')}%"),
            ("Overall Grade", str(es.get("overall_grade", "N/A"))),
        ], styles))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(
            "This project's own MITRE Matrix Coverage is deliberately low: it covers 2 CVEs / 3 "
            "techniques against the full 216-technique matrix. This engine reports that ratio "
            "honestly rather than inflating its own scope.",
            styles["Disclaimer"],
        ))
    else:
        story.append(Paragraph("No data - emulation-score/emulation_score.py has not been run.", styles["BodySmall"]))

    story.append(PageBreak())

    # --- IOC Confidence & Decay ---
    story += section_title("IOC Confidence &amp; Decay", "Section 11", styles)
    story.append(Paragraph(
        "IOCs age. A composite confidence score is computed from exponential time decay "
        "(90-day half-life), a log-scaled frequency boost, and a source-diversity boost, banding "
        "each IOC into ACTIVE / AGING / STALE / EXPIRED.",
        styles["Body"],
    ))
    if ctx["ioc_confidence"]:
        story.append(build_ioc_table(ctx, styles))
    else:
        story.append(Paragraph("No data - ioc-decay/ioc_decay.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Attack Replay Timeline ---
    story += section_title("Attack Replay Timeline", "Section 12", styles)
    story.append(Paragraph(
        "A minute-by-minute, evidence-timestamped replay of the operation, merging telemetry and "
        "Purple Team validation data into a single chronological sequence.",
        styles["Body"],
    ))
    if ctx["attack_replay"]:
        story.append(build_replay_table(ctx, styles))
    else:
        story.append(Paragraph("No data - attack-replay/replay.py has not been run.", styles["BodySmall"]))

    story.append(PageBreak())

    # --- Blackwell Core ---
    story += section_title("Blackwell Core \u2014 Evidence-Driven Reasoning Layer", "Section 13", styles)
    story.append(Paragraph(
        "Blackwell Core sits on top of the 17-module pipeline above, turning every module's output "
        "into a single typed Evidence Graph of claims and the relationships between them "
        "(SUPPORTS, CONTRADICTS, CAUSES). Rather than presenting raw dashboards, the Decision "
        "Engine synthesizes the graph into a prioritized, explainable action list.",
        styles["Body"],
    ))

    bw = ctx["blackwell"]
    if bw.get("decisions"):
        story.append(Paragraph("Decision Engine \u2014 Prioritized Findings", styles["SubHeader"]))
        story.append(build_decision_table(ctx, styles))
        story.append(Spacer(1, 0.18 * inch))
    if bw.get("confidence"):
        story.append(Paragraph("Confidence Engine \u2014 Multi-Signal Confidence Breakdown", styles["SubHeader"]))
        story.append(build_confidence_table(ctx, styles))
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph(
            "Confidence combines corroboration (independent supporting evidence), source "
            "diversity, pattern strength against known kill-chains, and a contradiction penalty "
            "&mdash; distinct from the Evidence Ranking score, where the confidence term is "
            "deliberately inverted (an analyst should look at low-confidence-but-high-severity "
            "findings first, not last).",
            styles["Disclaimer"],
        ))
    if not bw.get("decisions") and not bw.get("confidence"):
        story.append(Paragraph(
            "No data - run the blackwell-core/ pipeline (evidence-graph -> correlation-bca -> "
            "risk-score-brs -> confidence-engine -> decision-engine) to populate this section.",
            styles["BodySmall"],
        ))

    story.append(PageBreak())

    # --- Related Output Files ---
    story += section_title("Related Output Files &amp; Classification", "Section 14", styles)
    outputs = [
        "reporting/navigator/obsidian_protocol_layer.json \u2014 ATT&amp;CK Navigator layer file",
        "docs/detection-coverage-matrix.md \u2014 Markdown coverage matrix",
        "intel-export/output/obsidian_protocol_bundle.stix2.json \u2014 STIX 2.1 IOC bundle",
        "telemetry/output/unified_timeline.ndjson \u2014 Raw unified telemetry timeline",
        "blackwell-core/evidence-graph/output/evidence_graph.json \u2014 Full Evidence Graph (BEG)",
        "blackwell-core/decision-engine/output/executive_briefing.md \u2014 Executive briefing",
        "blackwell-core/decision-engine/output/technical_briefing.md \u2014 Technical briefing",
    ]
    for o in outputs:
        story.append(Paragraph(f"\u2022 {o}", styles["BodySmall"]))

    story.append(Spacer(1, 0.4 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=10))
    story.append(Paragraph(
        "<b>Classification:</b> This report was generated automatically from an "
        "educational/portfolio adversarial simulation conducted by OBSIDIAN PROTOCOL "
        "in an isolated, internet-disconnected Docker range. No real/third-party "
        "system was accessed in any way. All intelligence sources referenced "
        "(NVD, CISA KEV, CISA/FBI advisories, MITRE ATT&amp;CK, OASIS STIX/TAXII) are "
        "public standards.",
        styles["Disclaimer"],
    ))

    def is_cover(d):
        return d.page == 1

    doc.build(story, onFirstPage=make_page_callback(ctx, is_cover), onLaterPages=make_page_callback(ctx, is_cover))


def main():
    ctx = collect_report_context()
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    build_pdf(ctx, OUTPUT_PATH)
    print(f"[+] PDF report generated: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

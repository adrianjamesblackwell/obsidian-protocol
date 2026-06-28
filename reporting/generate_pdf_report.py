#!/usr/bin/env python3
"""
reporting/generate_pdf_report.py

OBSIDIAN PROTOCOL — PDF Operation Report Generator

Produces a multi-page, professional PDF report using reportlab
Platypus. Uses the same data source as the HTML report
(collect_report_data.py), so there is never a data inconsistency
between the two formats.
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
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

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


def _register_unicode_fonts():
    regular_path = next((p for p in DEJAVU_PATHS if os.path.exists(p)), None)
    bold_path = next((p for p in DEJAVU_BOLD_PATHS if os.path.exists(p)), None)

    if regular_path and bold_path:
        pdfmetrics.registerFont(TTFont("DejaVuSans", regular_path))
        pdfmetrics.registerFont(TTFont("DejaVuSans-Bold", bold_path))
        return "DejaVuSans", "DejaVuSans-Bold"
    # Fall back to Helvetica if the font isn't found (some glyphs may
    # render incorrectly, but PDF generation won't fail)
    return "Helvetica", "Helvetica-Bold"


FONT_REGULAR, FONT_BOLD = _register_unicode_fonts()

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "reports", "obsidian_protocol_report.pdf")

DARK_BG = colors.HexColor("#1a1a2e")
ACCENT = colors.HexColor("#e94560")
GREEN = colors.HexColor("#2ecc71")
RED = colors.HexColor("#e74c3c")
ORANGE = colors.HexColor("#e67e22")
YELLOW = colors.HexColor("#f1c40f")
GREY = colors.HexColor("#888888")


def risk_band_color(band: str):
    return {
        "CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREEN,
    }.get(band, GREY)


def build_styles():
    styles = getSampleStyleSheet()
    for style_name in ["Normal", "Title", "Heading1", "Heading2", "BodyText"]:
        styles[style_name].fontName = FONT_REGULAR

    styles.add(ParagraphStyle(
        "ObsidianTitle", parent=styles["Title"],
        fontName=FONT_BOLD, fontSize=26, textColor=DARK_BG, spaceAfter=4, alignment=TA_CENTER, leading=30,
    ))
    styles.add(ParagraphStyle(
        "ObsidianSubtitle", parent=styles["Normal"],
        fontName=FONT_REGULAR, fontSize=11, textColor=colors.grey, alignment=TA_CENTER, spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        "SectionHeader", parent=styles["Heading2"],
        fontName=FONT_BOLD, textColor=ACCENT, spaceBefore=18, spaceAfter=10, borderColor=ACCENT,
    ))
    styles.add(ParagraphStyle(
        "BodySmall", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=9, leading=12,
    ))
    styles.add(ParagraphStyle(
        "Disclaimer", parent=styles["Normal"], fontName=FONT_REGULAR, fontSize=8, textColor=colors.grey,
        leading=11, alignment=TA_LEFT,
    ))
    return styles


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
    table = Table(data, colWidths=[3 * inch, 3 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, -1), FONT_REGULAR),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


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

    table = Table(data, colWidths=[0.7 * inch, 1.1 * inch, 2.6 * inch, 0.7 * inch, 1.1 * inch])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, -1), FONT_REGULAR),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, c in enumerate(row_colors):
        if c:
            style_cmds.append(("TEXTCOLOR", (4, i), (4, i), c))
            style_cmds.append(("FONTNAME", (4, i), (4, i), FONT_BOLD))
    table.setStyle(TableStyle(style_cmds))
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
            Paragraph(s["rationale"], styles["BodySmall"]),
        ])
        band_colors.append(risk_band_color(s["risk_band"]))

    table = Table(data, colWidths=[1.3 * inch, 1.0 * inch, 0.8 * inch, 3.1 * inch])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, -1), FONT_REGULAR),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, c in enumerate(band_colors):
        if c:
            style_cmds.append(("BACKGROUND", (1, i), (1, i), c))
            style_cmds.append(("TEXTCOLOR", (1, i), (1, i), colors.white))
            style_cmds.append(("FONTNAME", (1, i), (1, i), FONT_BOLD))
    table.setStyle(TableStyle(style_cmds))
    return table


def build_correlation_table(ctx: dict, styles) -> Table:
    sev_colors = {"CRITICAL": RED, "HIGH": ORANGE, "MEDIUM": YELLOW, "LOW": GREY}
    header = ["Severity", "Actor", "MITRE Chain", "Confidence", "Narrative"]
    data = [header]
    row_colors = [None]

    for inc in sorted(ctx["correlated_incidents"], key=lambda i: -i["confidence"]):
        data.append([
            inc["severity"],
            inc["actor_key"],
            " -> ".join(inc["mitre_chain"]) or "-",
            f"{inc['confidence']:.0f}%",
            Paragraph(inc["narrative"], styles["BodySmall"]),
        ])
        row_colors.append(sev_colors.get(inc["severity"], GREY))

    table = Table(data, colWidths=[0.7 * inch, 1.0 * inch, 1.2 * inch, 0.8 * inch, 2.8 * inch])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("FONTNAME", (0, 0), (-1, -1), FONT_REGULAR),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]
    for i, c in enumerate(row_colors):
        if c:
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), c))
            style_cmds.append(("FONTNAME", (0, i), (0, i), FONT_BOLD))
    table.setStyle(TableStyle(style_cmds))
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
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.whitesmoke, colors.white]),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def build_rule_quality_table(ctx: dict, styles) -> Table:
    header = ["Rule", "FP Risk", "Perf. Cost", "Coverage"]
    data = [header]
    for r in ctx["rule_quality"]:
        data.append([
            Paragraph(r["rule_file"], styles["BodySmall"]),
            "★" * r["fp_risk_score"] + "☆" * (5 - r["fp_risk_score"]),
            "★" * r["performance_cost_score"] + "☆" * (5 - r["performance_cost_score"]),
            "★" * r["coverage_score"] + "☆" * (5 - r["coverage_score"]),
        ])
    table = Table(data, colWidths=[2.8 * inch, 1.1 * inch, 1.1 * inch, 1.1 * inch])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("FONTNAME", (0, 0), (-1, 0), FONT_BOLD),
        ("FONTNAME", (0, 1), (-1, -1), FONT_REGULAR),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.lightgrey),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    return table


def build_pdf(ctx: dict, output_path: str):
    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    styles = build_styles()
    story = []

    # --- Cover page ---
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("OBSIDIAN PROTOCOL", styles["ObsidianTitle"]))
    story.append(Paragraph("Adversarial Simulation &amp; Detection Engineering — Operation Report", styles["ObsidianSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=20))
    story.append(Paragraph(f"Generated at: {ctx['generated_at']}", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    if ctx["missing_modules"]:
        warn_text = "⚠ Missing Module Data: " + "; ".join(ctx["missing_modules"])
        story.append(Paragraph(warn_text, ParagraphStyle("Warn", parent=styles["BodySmall"], textColor=RED)))

    story.append(PageBreak())

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
    story.append(build_summary_table(ctx, styles))
    story.append(Spacer(1, 0.3 * inch))

    # --- Correlation Engine ---
    story.append(Paragraph("Correlation Engine — Solving Alert Fatigue", styles["SectionHeader"]))
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
    story.append(Paragraph("Purple Team Detection Coverage", styles["SectionHeader"]))
    if ctx["coverage_results"]:
        story.append(build_coverage_table(ctx, styles))
    else:
        story.append(Paragraph("No data - purple-team/validate.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Risk Scoring ---
    story.append(Paragraph("Risk Scoring Engine Results", styles["SectionHeader"]))
    if ctx["risk_scores"]:
        story.append(build_risk_table(ctx, styles))
    else:
        story.append(Paragraph("No data - risk-engine/risk_engine.py has not been run.", styles["BodySmall"]))

    story.append(PageBreak())

    # --- Coverage Heatmap (summary) ---
    story.append(Paragraph("Detection Coverage Heatmap (MITRE ATT&CK)", styles["SectionHeader"]))
    if ctx["coverage_heatmap"]:
        hm = ctx["coverage_heatmap"]
        items = [(tactic, f"{data.get('validated_coverage_pct', 0)}% validated / {data.get('rule_coverage_pct', 0)}% rule")
                 for tactic, data in hm.items() if data.get("known_techniques_in_scope", 0) > 0]
        story.append(build_metric_cards_table(items, styles))
        story.append(Paragraph(
            "Note: percentages are computed over the set of techniques this project "
            "knows about/has labeled, not over all 216 MITRE techniques.",
            styles["Disclaimer"],
        ))
    else:
        story.append(Paragraph("No data - coverage-heatmap/heatmap.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Telemetry Gap ---
    story.append(Paragraph("Telemetry Gap Analysis", styles["SectionHeader"]))
    if ctx["telemetry_gap"]:
        tg = ctx["telemetry_gap"]
        story.append(Paragraph(f"<b>Blind Tactics:</b> {', '.join(tg.get('blind_tactics', [])) or '-'}", styles["BodySmall"]))
        for i, rec in enumerate(tg.get("recommendations", []), 1):
            story.append(Paragraph(f"{i}. {rec}", styles["BodySmall"]))
    else:
        story.append(Paragraph("No data - telemetry-gap/gap_analysis.py has not been run.", styles["BodySmall"]))

    story.append(PageBreak())

    # --- Rule Quality ---
    story.append(Paragraph("Rule Quality Analysis (WARDEN)", styles["SectionHeader"]))
    if ctx["rule_quality"]:
        story.append(build_rule_quality_table(ctx, styles))
    else:
        story.append(Paragraph("No data - rule-quality/analyze_rules.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.3 * inch))

    # --- Root Cause ---
    story.append(Paragraph("Root Cause Discovery", styles["SectionHeader"]))
    if ctx["root_cause"]:
        for rc in ctx["root_cause"]:
            story.append(Paragraph(f"<b>{rc['cve']}</b> — {rc['primary_cause']}", styles["BodySmall"]))
            story.append(Paragraph(" -&gt; ".join(rc.get("causal_chain", [])), styles["Disclaimer"]))
            story.append(Spacer(1, 0.1 * inch))
    else:
        story.append(Paragraph("No data - root-cause/root_cause.py has not been run.", styles["BodySmall"]))
    story.append(Spacer(1, 0.2 * inch))

    # --- Emulation Score ---
    story.append(Paragraph("Adversary Emulation Quality Score", styles["SectionHeader"]))
    if ctx["emulation_score"]:
        es = ctx["emulation_score"]
        story.append(build_metric_cards_table([
            ("Attack Diversity", f"{es.get('attack_diversity_pct', 'N/A')}%"),
            ("MITRE Matrix Coverage", f"{es.get('coverage_pct', 'N/A')}%"),
            ("Noise Level", str(es.get("noise_level", "N/A"))),
            ("Detection Success", f"{es.get('detection_success_pct', 'N/A')}%"),
            ("Overall Grade", str(es.get("overall_grade", "N/A"))),
        ], styles))
    else:
        story.append(Paragraph("No data - emulation-score/emulation_score.py has not been run.", styles["BodySmall"]))

    story.append(PageBreak())

    # --- Related Output Files ---
    story.append(Paragraph("Related Output Files", styles["SectionHeader"]))
    outputs = [
        "reporting/navigator/obsidian_protocol_layer.json — ATT&CK Navigator layer file",
        "docs/detection-coverage-matrix.md — Markdown coverage matrix",
        "intel-export/output/obsidian_protocol_bundle.stix2.json — STIX 2.1 IOC bundle",
        "telemetry/output/unified_timeline.ndjson — Raw unified telemetry timeline",
    ]
    for o in outputs:
        story.append(Paragraph(f"• {o}", styles["BodySmall"]))

    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey, spaceAfter=10))
    story.append(Paragraph(
        "<b>Classification:</b> This report was generated automatically from an "
        "educational/portfolio adversarial simulation conducted by OBSIDIAN PROTOCOL "
        "in an isolated, internet-disconnected Docker range. No real/third-party "
        "system was accessed in any way.",
        styles["Disclaimer"],
    ))

    doc.build(story)


def main():
    ctx = collect_report_context()
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    build_pdf(ctx, OUTPUT_PATH)
    print(f"[+] PDF report generated: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

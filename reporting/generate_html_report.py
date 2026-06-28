#!/usr/bin/env python3
"""
reporting/generate_html_report.py

OBSIDIAN PROTOCOL — HTML Operation Report Generator

Renders a single self-contained HTML file (no external dependencies,
all CSS inline) from every module's output, including the Blackwell
Core reasoning layer. Visual language: an "evidence dossier" — a
vertical spine connects every section the way a SUPPORTS edge connects
evidence to a conclusion in the underlying Evidence Graph, so the
report's own structure echoes the data model it's reporting on rather
than being a generic dashboard skin.
"""

import sys
import os
import html as html_lib

sys.path.insert(0, os.path.dirname(__file__))
from collect_report_data import collect_report_context

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "reports", "obsidian_protocol_report.html")

# Minimal inline SVG icons for the tab nav — kept tiny and monochrome
# (currentColor) so they inherit the active/inactive tab color.
ICON_OVERVIEW = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="3" y="3" width="7" height="9" rx="1.5"/><rect x="14" y="3" width="7" height="5" rx="1.5"/><rect x="14" y="12" width="7" height="9" rx="1.5"/><rect x="3" y="16" width="7" height="5" rx="1.5"/></svg>'
ICON_FINDINGS = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="12" r="3.2"/><circle cx="4.5" cy="6" r="1.8"/><circle cx="19.5" cy="6" r="1.8"/><circle cx="4.5" cy="18" r="1.8"/><circle cx="19.5" cy="18" r="1.8"/><line x1="6" y1="7.3" x2="9.8" y2="10"/><line x1="18" y1="7.3" x2="14.2" y2="10"/><line x1="6" y1="16.7" x2="9.8" y2="14"/><line x1="18" y1="16.7" x2="14.2" y2="14"/></svg>'
ICON_DETECTION = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.2" y2="16.2"/></svg>'
ICON_RISK = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M12 2 L4 6 V12 C4 17 7.5 20.5 12 22 C16.5 20.5 20 17 20 12 V6 Z"/><path d="M9 12 L11 14 L15.5 9.2" stroke-linecap="round" stroke-linejoin="round"/></svg>'
ICON_ENGINEERING = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M14.7 6.3 L17.7 3.3 L20.7 6.3 L17.7 9.3 Z"/><path d="M14.7 6.3 L4 17 V20 H7 L17.7 9.3"/><line x1="13" y1="8" x2="16" y2="11"/></svg>'
ICON_ROOTCAUSE = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><circle cx="12" cy="6" r="3"/><path d="M12 9 V13 M12 13 L7 18 M12 13 L17 18"/><circle cx="7" cy="20" r="1.6"/><circle cx="17" cy="20" r="1.6"/></svg>'
ICON_ARTIFACTS = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M5 4 H15 L19 8 V20 H5 Z"/><path d="M14 4 V8 H19"/><line x1="8" y1="13" x2="16" y2="13"/><line x1="8" y1="16.5" x2="16" y2="16.5"/></svg>'

RISK_COLOR = {
    "CRITICAL": "#ff5c72",
    "HIGH": "#ff9d4d",
    "MEDIUM": "#f0c94d",
    "LOW": "#5ce0a8",
}
SEV_COLOR = {
    "CRITICAL": "#ff5c72",
    "HIGH": "#ff9d4d",
    "MEDIUM": "#f0c94d",
    "LOW": "#7c9dff",
}


def esc(s) -> str:
    return html_lib.escape(str(s)) if s is not None else ""


def risk_color(band: str) -> str:
    return RISK_COLOR.get(band, "#5a6275")


def sev_color(band: str) -> str:
    return SEV_COLOR.get(band, "#5a6275")


def node_tag(node_id: str) -> str:
    return f'<span class="node-tag">{esc(node_id)}</span>'


# ---------------------------------------------------------------------
# SVG chart primitives — native, dependency-free, self-contained
# ---------------------------------------------------------------------

def svg_donut(segments: list, size: int = 180, stroke: int = 22, center_label: str = "", center_sub: str = "") -> str:
    """
    segments: list of (value, color, label) or (value, color, label,
    tooltip, target) tuples — the last two are optional and feed the
    shared interactive-chart hover/click engine.
    Renders a real ring chart via stroke-dasharray arcs — not a CSS hack.
    """
    total = sum(s[0] for s in segments) or 1
    radius = (size - stroke) / 2
    circumference = 2 * 3.14159265 * radius
    cx = cy = size / 2

    arcs = []
    offset = 0.0
    for seg in segments:
        value, color, label = seg[0], seg[1], seg[2]
        tip = seg[3] if len(seg) > 3 else label
        target = seg[4] if len(seg) > 4 else None
        frac = value / total
        length = frac * circumference
        gap = circumference - length
        rotation = (offset / total) * 360 - 90
        target_attr = f' data-target="{esc(target)}"' if target else ""
        arcs.append(
            f'<circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="{color}" '
            f'stroke-width="{stroke}" stroke-dasharray="{length:.2f} {gap:.2f}" '
            f'stroke-linecap="butt" transform="rotate({rotation:.2f} {cx} {cy})" '
            f'class="ix-point donut-arc" data-tip="{esc(tip)}"{target_attr} '
            f'opacity="0.95"/>'
        )
        offset += value

    center_text = ""
    if center_label:
        center_text = (
            f'<text x="{cx}" y="{cy - 4}" text-anchor="middle" class="donut-center-value">{esc(center_label)}</text>'
            f'<text x="{cx}" y="{cy + 16}" text-anchor="middle" class="donut-center-sub">{esc(center_sub)}</text>'
        )

    return f"""<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" class="donut-svg ix-chart">
        <circle cx="{cx}" cy="{cy}" r="{radius}" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="{stroke}"/>
        {''.join(arcs)}
        {center_text}
    </svg>"""


def svg_scatter(points: list, width: int = 560, height: int = 320,
                 x_label: str = "X", y_label: str = "Y") -> str:
    """
    points: list of dicts with keys x, y (both 0..1 normalized), color,
    label, r (radius), and optionally tooltip (str) and target (element
    id to jump to on click, in the same document).
    Renders a quadrant scatter plot with axis labels and gridlines —
    used for the Confidence x Priority view of Blackwell incidents.
    Dots carry data-tip/data-target so the shared interactive-chart
    engine (CHART_INTERACTIVITY_JS) can drive hover tooltips and
    click-to-navigate uniformly across every chart in the report.
    """
    pad_l, pad_r, pad_t, pad_b = 56, 24, 24, 44
    plot_w = width - pad_l - pad_r
    plot_h = height - pad_t - pad_b

    def px(x):
        return pad_l + x * plot_w

    def py(y):
        return pad_t + (1 - y) * plot_h

    gridlines = []
    for frac in (0.0, 0.25, 0.5, 0.75, 1.0):
        gx, gy = px(frac), py(frac)
        gridlines.append(f'<line x1="{pad_l}" y1="{gy:.1f}" x2="{width-pad_r}" y2="{gy:.1f}" class="scatter-grid"/>')
        gridlines.append(f'<line x1="{gx:.1f}" y1="{pad_t}" x2="{gx:.1f}" y2="{height-pad_b}" class="scatter-grid"/>')

    mid_x, mid_y = px(0.5), py(0.5)
    quadrant_lines = (
        f'<line x1="{mid_x:.1f}" y1="{pad_t}" x2="{mid_x:.1f}" y2="{height-pad_b}" class="scatter-axis-mid"/>'
        f'<line x1="{pad_l}" y1="{mid_y:.1f}" x2="{width-pad_r}" y2="{mid_y:.1f}" class="scatter-axis-mid"/>'
    )

    dots = []
    labels = []
    for p in points:
        cx, cy = px(p["x"]), py(p["y"])
        r = p.get("r", 9)
        tip = esc(p.get("tooltip", p["label"]))
        target_attr = f' data-target="{esc(p["target"])}"' if p.get("target") else ""
        dots.append(
            f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r}" fill="{p["color"]}" '
            f'fill-opacity="0.85" stroke="{p["color"]}" stroke-width="1.5" '
            f'class="ix-point" data-tip="{tip}"{target_attr}/>'
        )
        labels.append(
            f'<text x="{cx:.1f}" y="{cy - r - 7:.1f}" text-anchor="middle" class="scatter-label">{esc(p["label"])}</text>'
        )

    return f"""<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" class="scatter-svg ix-chart" preserveAspectRatio="xMidYMid meet">
        {''.join(gridlines)}
        {quadrant_lines}
        <line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{height-pad_b}" class="scatter-axis"/>
        <line x1="{pad_l}" y1="{height-pad_b}" x2="{width-pad_r}" y2="{height-pad_b}" class="scatter-axis"/>
        <text x="{pad_l - 12}" y="{pad_t - 6}" text-anchor="start" class="scatter-axis-label">High</text>
        <text x="{pad_l - 12}" y="{height-pad_b + 14}" text-anchor="start" class="scatter-axis-label">Low</text>
        <text x="{(pad_l+width-pad_r)/2:.1f}" y="{height - 8}" text-anchor="middle" class="scatter-axis-title">{esc(x_label)}</text>
        <text x="14" y="{(pad_t+height-pad_b)/2:.1f}" text-anchor="middle" class="scatter-axis-title" transform="rotate(-90 14 {(pad_t+height-pad_b)/2:.1f})">{esc(y_label)}</text>
        <text x="{width - pad_r - 4}" y="{pad_t + 14}" text-anchor="end" class="scatter-quadrant-label">NEEDS REVIEW</text>
        <text x="{pad_l + 4}" y="{height - pad_b - 8}" text-anchor="start" class="scatter-quadrant-label">LOW PRIORITY</text>
        {''.join(dots)}
        {''.join(labels)}
    </svg>"""


def svg_heatmap_grid(rows: list, cols: list, get_value_fn, width: int = 720, row_h: int = 34) -> str:
    """
    rows: list of row labels
    cols: list of (col_label, color_hex) tuples
    get_value_fn(row, col_label) -> 0..100 or None
    Renders a real grid heatmap with color-intensity cells, not a table
    with embedded bars. Each cell carries data-tip so the shared
    interactive-chart engine can show a real-number tooltip on hover.
    """
    label_w = 200
    cell_w = (width - label_w) / len(cols)
    height = row_h * (len(rows) + 1) + 10

    header_cells = []
    for i, (col_label, color) in enumerate(cols):
        cx = label_w + i * cell_w + cell_w / 2
        header_cells.append(
            f'<text x="{cx:.1f}" y="16" text-anchor="middle" class="heatmap-col-label">{esc(col_label)}</text>'
        )

    rows_svg = []
    for ri, row_label in enumerate(rows):
        y = row_h * (ri + 1) + 6
        rows_svg.append(
            f'<text x="{label_w - 12}" y="{y + row_h/2 + 4:.1f}" text-anchor="end" class="heatmap-row-label">{esc(row_label)}</text>'
        )
        for ci, (col_label, color) in enumerate(cols):
            value = get_value_fn(row_label, col_label)
            x = label_w + ci * cell_w
            if value is None:
                opacity = 0.04
                text = "—"
                text_color = "var(--text-dim)"
                tip = f"{row_label} / {col_label}: no technique in scope"
            else:
                opacity = max(0.08, min(1.0, value / 100))
                text = f"{value:.0f}"
                text_color = "#0a0d12" if opacity > 0.55 else "var(--text)"
                tip = f"{row_label} — {col_label}: {value:.0f}%"
            rows_svg.append(
                f'<g class="ix-point heatmap-cell" data-tip="{esc(tip)}">'
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{cell_w - 3:.1f}" height="{row_h - 4}" rx="3" '
                f'fill="{color}" fill-opacity="{opacity:.2f}"/>'
                f'<text x="{x + (cell_w-3)/2:.1f}" y="{y + row_h/2 + 4:.1f}" text-anchor="middle" '
                f'class="heatmap-cell-text" fill="{text_color}">{text}</text>'
                f'</g>'
            )

    return f"""<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" class="heatmap-svg ix-chart" preserveAspectRatio="xMidYMid meet">
        {''.join(header_cells)}
        {''.join(rows_svg)}
    </svg>"""


def svg_timeline(steps: list, width: int = 760) -> str:
    """
    steps: list of dicts with keys: t (0..1 normalized time), label, detected (bool),
    latency (float or None), color
    Renders a horizontal timeline with event markers and connecting line.
    """
    pad_l, pad_r = 30, 30
    track_y = 70
    height = 150
    track_w = width - pad_l - pad_r

    def px(t):
        return pad_l + t * track_w

    markers = []
    for i, s in enumerate(steps):
        x = px(s["t"])
        color = s["color"]
        above = i % 2 == 0
        label_y = track_y - 26 if above else track_y + 40
        line_y2 = track_y - 8 if above else track_y + 8
        status = f"detected +{s['latency']:.1f}s" if s.get("latency") is not None else "missed"
        tip = f"{s['label']} — {status}"
        markers.append(f'<line x1="{x:.1f}" y1="{track_y}" x2="{x:.1f}" y2="{line_y2}" class="timeline-tick"/>')
        markers.append(
            f'<circle cx="{x:.1f}" cy="{track_y}" r="9" fill="{color}" stroke="#0a0d12" stroke-width="2" '
            f'class="ix-point" data-tip="{esc(tip)}"/>'
        )
        label_anchor = "middle"
        markers.append(
            f'<text x="{x:.1f}" y="{label_y}" text-anchor="{label_anchor}" class="timeline-label">{esc(s["label"])}</text>'
        )
        if s.get("latency") is not None:
            sub_y = label_y + (12 if above else 14)
            markers.append(
                f'<text x="{x:.1f}" y="{sub_y}" text-anchor="{label_anchor}" class="timeline-sub">+{s["latency"]:.1f}s</text>'
            )

    return f"""<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" class="timeline-svg ix-chart" preserveAspectRatio="xMidYMid meet">
        <line x1="{pad_l}" y1="{track_y}" x2="{width-pad_r}" y2="{track_y}" class="timeline-track"/>
        {''.join(markers)}
    </svg>"""


def svg_sparkline(values: list, width: int = 140, height: int = 36, color: str = "#7c9dff") -> str:
    """values: list of 0..100 floats, left = oldest. Renders a decay/trend curve."""
    if len(values) < 2:
        values = values * 2 if values else [0, 0]
    n = len(values)
    pts = []
    for i, v in enumerate(values):
        x = (i / (n - 1)) * (width - 8) + 4
        y = height - 4 - (max(0, min(100, v)) / 100) * (height - 8)
        pts.append((x, y))
    path = "M " + " L ".join(f"{x:.1f} {y:.1f}" for x, y in pts)
    area = path + f" L {pts[-1][0]:.1f} {height} L {pts[0][0]:.1f} {height} Z"
    return f"""<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" class="spark-svg">
        <path d="{area}" fill="{color}" fill-opacity="0.12"/>
        <path d="{path}" fill="none" stroke="{color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
        <circle cx="{pts[-1][0]:.1f}" cy="{pts[-1][1]:.1f}" r="3" fill="{color}"/>
    </svg>"""


def svg_bullet(value: float, max_value: float, color: str, width: int = 200, height: int = 10) -> str:
    """A precise horizontal bullet/progress bar with tick marks, used in tables."""
    pct = max(0, min(1, value / max_value if max_value else 0))
    fill_w = pct * width
    ticks = "".join(
        f'<line x1="{width*f:.1f}" y1="0" x2="{width*f:.1f}" y2="{height}" class="bullet-tick"/>'
        for f in (0.25, 0.5, 0.75)
    )
    return f"""<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" class="bullet-svg">
        <rect x="0" y="0" width="{width}" height="{height}" rx="2" class="bullet-track"/>
        {ticks}
        <rect x="0" y="0" width="{fill_w:.1f}" height="{height}" rx="2" fill="{color}"/>
    </svg>"""


# ---------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------

def render_evidence_section(ctx: dict) -> str:
    """The Blackwell Decision Engine output — the report's lead section,
    since it is the platform's actual synthesized output, not a raw
    module dump."""
    decisions = ctx["blackwell"]["decisions"]
    if not decisions:
        return ""

    # --- Confidence x Priority scatter: where BER's deliberate
    # confidence-inversion becomes visible as actual point placement ---
    scatter_points = []
    for d in decisions:
        risk_band = d.get("risk_band") or "UNSCORED"
        scatter_points.append({
            "x": max(0.03, min(0.97, d.get("confidence", 0))),
            "y": max(0.03, min(0.97, min(1.0, d.get("priority", 0) * 1.6))),
            "color": risk_color(risk_band),
            "label": d["node_id"].replace("assert-", ""),
            "r": 8 + min(8, (d.get("risk_score") or 0) / 12),
            "tooltip": f"{d['label']} — {risk_band} · confidence {d.get('confidence',0)*100:.0f}% · priority {d.get('priority',0):.2f}",
            "target": f"findings:finding-{d['node_id']}",
        })
    scatter_html = ""
    if len(scatter_points) >= 1:
        scatter_svg = svg_scatter(scatter_points, x_label="CONFIDENCE →", y_label="PRIORITY →")
        scatter_html = f"""
        <div class="scatter-panel">
            <div class="scatter-panel-title">CONFIDENCE vs. PRIORITY
                <span class="scatter-panel-note">— low confidence intentionally pushes priority up (Section 4.6)</span>
            </div>
            {scatter_svg}
        </div>"""

    items_html = ""
    for d in decisions:
        risk_band = d.get("risk_band") or "UNSCORED"
        rcolor = risk_color(risk_band)
        confidence = d.get("confidence", 0) * 100
        priority_pct = min(100, d.get("priority", 0) * 100)

        hyp_html = ""
        if d.get("hypothetical_next"):
            hyp_items = "".join(
                f'<li>{esc(h)}</li>' for h in d["hypothetical_next"]
            )
            hyp_html = f"""
            <div class="hypo-block">
                <div class="hypo-label">IF THIS CONTINUES <span class="hypo-caveat">— structural hypothesis, not a forecast</span></div>
                <ul class="hypo-list">{hyp_items}</ul>
            </div>"""

        actions_html = ""
        if d.get("preventive_actions"):
            action_items = "".join(f'<li>{esc(a)}</li>' for a in d["preventive_actions"])
            actions_html = f"""
            <div class="action-block">
                <div class="action-label">PREVENTIVE ACTIONS</div>
                <ul class="action-list">{action_items}</ul>
            </div>"""

        items_html += f"""
        <div class="decision-card" id="finding-{esc(d['node_id'])}" style="--accent:{rcolor}">
            <div class="decision-rail"></div>
            <div class="decision-body">
                <div class="decision-top">
                    <div>
                        {node_tag(d['node_id'])}
                        <div class="decision-title">{esc(d['label'])}</div>
                    </div>
                    <div class="decision-risk" style="color:{rcolor}; border-color:{rcolor}">{esc(risk_band)}</div>
                </div>

                <div class="decision-metrics">
                    <div class="dm">
                        <div class="dm-label">Priority</div>
                        <div class="dm-value">{d.get('priority', 0):.3f}</div>
                        {svg_bullet(priority_pct, 100, "#7c9dff")}
                    </div>
                    <div class="dm">
                        <div class="dm-label">Confidence</div>
                        <div class="dm-value">{confidence:.0f}%</div>
                        {svg_bullet(confidence, 100, "#5ce0a8")}
                    </div>
                    <div class="dm">
                        <div class="dm-label">Risk Score</div>
                        <div class="dm-value">{d.get('risk_score', 'N/A')}</div>
                        {svg_bullet(d.get('risk_score') or 0, 100, rcolor)}
                    </div>
                </div>

                <div class="evidence-line">
                    <span class="evidence-icon">⟁</span> {esc(d.get('evidence_summary', ''))}
                </div>

                {f'<div class="root-cause-line"><span class="rc-label">ROOT CAUSE</span> {esc(d["root_cause_primary"])}</div>' if d.get('root_cause_primary') else ''}
                {f'<div class="temporal-line"><span class="rc-label">TEMPO</span> {esc(d["temporal_note"])}</div>' if d.get('temporal_note') else ''}

                <div class="decision-grid">
                    {actions_html}
                    {hyp_html}
                </div>

                <details class="why-details">
                    <summary>Why this score — full component breakdown</summary>
                    <code>{esc(d.get('why_summary', ''))}</code>
                </details>
            </div>
        </div>"""

    return f"""
    <section class="tab-block" id="decisions">
        <div class="section-eyebrow">BLACKWELL DECISION ENGINE</div>
        <h2>Prioritized Findings</h2>
        <p class="section-intro">
            Every item below is a join across correlation, risk scoring, confidence,
            root cause, and structural attack-path hypotheses — traceable back to its
            supporting evidence nodes, not a standalone score.
        </p>
        {scatter_html}
        {items_html}
    </section>"""


def render_neural_network(ctx: dict) -> str:
    """
    Renders the Blackwell Evidence Graph as a live, animated, fully
    interactive force-directed network — real node_id/kind/weight and
    real edge relations from
    blackwell-core/evidence-graph/output/evidence_graph.json, not a
    decorative random graph. Node color encodes evidence kind
    (RAW_EVENT / INDICATOR / ASSERTION / CONCLUSION), node size encodes
    weight, and edge particles flow in the direction evidence actually
    supports a conclusion.

    Each node is wired to the real report element it corresponds to:
    ASSERTION nodes link to their Decision Engine card in the Findings
    tab (real id="finding-{node_id}" match), INDICATOR nodes link to
    their CVE row in the Risk & Intel tab (real id="riskrow-{cve}"
    match). Clicking a node switches tabs and highlights the matching
    element — clicking is real navigation, not a cosmetic gesture.
    """
    graph = ctx["blackwell"].get("evidence_graph")
    if not graph or not graph.get("nodes"):
        return ""

    kind_color = {
        "RAW_EVENT": "#7c9dff",
        "INDICATOR": "#ffb454",
        "ASSERTION": "#5ce0a8",
        "CONCLUSION": "#ff5c72",
    }
    kind_tab = {
        "RAW_EVENT": "detection",
        "INDICATOR": "risk",
        "ASSERTION": "findings",
        "CONCLUSION": "findings",
    }

    decision_ids = {d["node_id"] for d in ctx["blackwell"].get("decisions") or []}

    def target_for(node) -> str:
        nid = node["node_id"]
        if node["kind"] == "ASSERTION" and nid in decision_ids:
            return f"finding-{nid}"
        if node["kind"] == "INDICATOR":
            cve = nid.replace("ind-", "")
            return f"riskrow-{cve}"
        return ""

    nodes_payload = [
        {
            "id": n["node_id"],
            "kind": n["kind"],
            "label": n["label"],
            "weight": n.get("weight", 0.5),
            "color": kind_color.get(n["kind"], "#5a6275"),
            "provenance": n.get("provenance", ""),
            "tab": kind_tab.get(n["kind"], "overview"),
            "target": target_for(n),
        }
        for n in graph["nodes"]
    ]
    edges_payload = [
        {"source": e["source"], "target": e["target"], "relation": e["relation"], "strength": e.get("strength", 0.5)}
        for e in graph["edges"]
        if e["source"] in {n["node_id"] for n in graph["nodes"]} and e["target"] in {n["node_id"] for n in graph["nodes"]}
    ]

    import json as _json
    payload = _json.dumps({"nodes": nodes_payload, "edges": edges_payload})

    legend_items = "".join(
        f'<div class="nn-legend-row"><span class="nn-legend-dot" style="background:{color}"></span>{kind}</div>'
        for kind, color in kind_color.items()
        if any(n["kind"] == kind for n in graph["nodes"])
    )

    return f"""
    <div class="nn-panel">
        <div class="nn-panel-head">
            <div>
                <div class="nn-panel-title">EVIDENCE REASONING NETWORK</div>
                <div class="nn-panel-sub">Live, draggable render of the Blackwell Evidence Graph — {len(nodes_payload)} nodes, {len(edges_payload)} evidence edges. Drag to rearrange, click a node to jump to its source.</div>
            </div>
            <div class="nn-legend">{legend_items}</div>
        </div>
        <div class="nn-canvas-wrap">
            <canvas id="nn-canvas" class="nn-canvas"></canvas>
            <div id="nn-tooltip" class="nn-tooltip"></div>
            <div class="nn-hint">⊹ drag nodes · scroll to zoom · click to inspect</div>
        </div>
    </div>
    <script id="nn-data" type="application/json">{payload}</script>
    <script>{NEURAL_NETWORK_JS}</script>"""


def render_summary_section(ctx: dict) -> str:
    s = ctx["summary"]
    coverage_display = f"{s['coverage_pct']}%" if s["coverage_pct"] is not None else "—"
    risk_band = s.get("highest_risk_band")
    rcolor = risk_color(risk_band) if risk_band else "#5a6275"

    cards = [
        ("Attack Steps", str(s["total_attack_steps"]), "#7c9dff"),
        ("Detection Coverage", coverage_display, "#5ce0a8"),
        ("Avg. Detect Latency", f"{s['avg_detection_latency'] or '—'}s", "#7c9dff"),
        ("Telemetry Events", str(ctx["telemetry_event_count"]), "#7c9dff"),
        ("STIX Objects", str(ctx["stix_object_count"]), "#7c9dff"),
        (f"Peak Risk ({s['highest_risk_cve'] or 'N/A'})", str(s['highest_risk_score'] or '—'), rcolor),
    ]
    cards_html = "".join(
        f"""<div class="metric-card" style="--card-accent:{c}">
                <div class="metric-value">{v}</div>
                <div class="metric-label">{esc(k)}</div>
            </div>"""
        for k, v, c in cards
    )

    # --- Risk distribution donut: composite share of each CVE's risk ---
    donut_html = ""
    risk_scores = ctx.get("risk_scores") or []
    if risk_scores:
        total_score = sum(r["composite_score"] for r in risk_scores) or 1
        segments = [
            (r["composite_score"], risk_color(r["risk_band"]), r["cve"],
             f"{r['cve']} — {r['risk_band']} · score {r['composite_score']}",
             f"risk:riskrow-{r['cve']}")
            for r in risk_scores
        ]
        peak = max(risk_scores, key=lambda r: r["composite_score"])
        donut_svg = svg_donut(segments, size=176, stroke=20,
                               center_label=f"{peak['composite_score']:.0f}", center_sub=peak["risk_band"])
        legend = "".join(
            f'<div class="donut-legend-row"><span class="donut-swatch" style="background:{risk_color(r["risk_band"])}"></span>'
            f'<span class="mono">{esc(r["cve"])}</span><span class="donut-legend-score">{r["composite_score"]}</span></div>'
            for r in sorted(risk_scores, key=lambda r: -r["composite_score"])
        )
        donut_html = f"""
        <div class="donut-panel">
            <div class="donut-panel-title">RISK DISTRIBUTION</div>
            <div class="donut-panel-body">
                {donut_svg}
                <div class="donut-legend">{legend}</div>
            </div>
        </div>"""

    return f"""
    <section class="hero">
        <div class="metric-grid">{cards_html}</div>
        {render_neural_network(ctx)}
        {f'<div class="hero-secondary">{donut_html}</div>' if donut_html else ''}
    </section>"""


def render_correlation_section(ctx: dict) -> str:
    cs = ctx["correlation_summary"]
    if not cs:
        return ""
    rows = ""
    for inc in sorted(ctx["correlated_incidents"], key=lambda i: -i["confidence"]):
        scolor = sev_color(inc["severity"])
        rows += f"""
        <tr>
            <td><span class="pill" style="--pill-color:{scolor}">{esc(inc['severity'])}</span></td>
            <td class="mono">{esc(inc['actor_key'])}</td>
            <td class="mono">{' → '.join(inc['mitre_chain']) or '—'}</td>
            <td>{svg_bullet(inc['confidence'], 100, '#7c9dff', 90, 8)}<span class="inline-pct">{inc['confidence']:.0f}%</span></td>
            <td class="narrative">{esc(inc['narrative'])}</td>
        </tr>"""
    return f"""
    <section class="tab-block" id="correlation">
        <div class="section-eyebrow">CORRELATION ENGINE — ALERT FATIGUE</div>
        <h2>{cs['raw_event_count']} raw events &rarr; {cs['incident_count']} incidents
            <span class="reduction-tag">{cs['reduction_pct']}% reduction</span></h2>
        <table class="data-table">
            <thead><tr><th>Severity</th><th>Actor</th><th>MITRE Chain</th><th>Confidence</th><th>Narrative</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </section>"""


def render_coverage_section(ctx: dict) -> str:
    results = ctx["coverage_results"]
    if not results:
        return """
    <section class="tab-block" id="coverage-empty">
        <div class="section-eyebrow">PURPLE TEAM VALIDATION</div>
        <h2>Detection Coverage</h2>
        <table class="data-table"><tbody><tr><td class="empty">No data</td></tr></tbody></table>
    </section>"""

    # --- Real timeline from actual attack_timestamp values ---
    timeline_html = ""
    try:
        from datetime import datetime as _dt
        times = [_dt.fromisoformat(r["attack_timestamp"].replace("Z", "+00:00")) for r in results]
        t_min, t_max = min(times), max(times)
        span = (t_max - t_min).total_seconds() or 1
        steps = []
        for r, t in zip(results, times):
            frac = (t - t_min).total_seconds() / span
            color = "#5ce0a8" if r["detected"] else "#ff5c72"
            label = r["mitre_technique"] or r["vector"]
            steps.append({
                "t": frac, "label": label, "color": color,
                "latency": r["detection_latency_seconds"] if r["detected"] else None,
            })
        timeline_svg = svg_timeline(steps, width=720)
        timeline_html = f'<div class="timeline-panel">{timeline_svg}</div>'
    except (ValueError, KeyError):
        timeline_html = ""

    rows = ""
    for r in results:
        if r["detected"]:
            status = f'<span class="status-ok">DETECTED</span> <span class="status-meta">+{r["detection_latency_seconds"]}s · {esc(r["detection_source"])}</span>'
        else:
            status = '<span class="status-miss">MISSED</span>'
        rows += f"""
        <tr>
            <td class="mono">{esc(r['vector'])}</td>
            <td class="mono">{esc(r['cve']) or '—'}</td>
            <td>{esc(r['attack_step'])}</td>
            <td class="mono">{esc(r['mitre_technique']) or '—'}</td>
            <td>{status}</td>
        </tr>"""
    return f"""
    <section class="tab-block" id="coverage">
        <div class="section-eyebrow">PURPLE TEAM VALIDATION</div>
        <h2>Detection Coverage</h2>
        {timeline_html}
        <table class="data-table">
            <thead><tr><th>Vector</th><th>CVE</th><th>Attack Step</th><th>MITRE</th><th>Status</th></tr></thead>
            <tbody>{rows or '<tr><td colspan="5" class="empty">No data</td></tr>'}</tbody>
        </table>
    </section>"""


def render_risk_section(ctx: dict) -> str:
    rows = ""
    for s in ctx["risk_scores"]:
        rcolor = risk_color(s["risk_band"])
        rows += f"""
        <tr id="riskrow-{esc(s['cve'])}">
            <td class="mono">{esc(s['cve'])}</td>
            <td><span class="pill" style="--pill-color:{rcolor}">{esc(s['risk_band'])}</span></td>
            <td>{svg_bullet(s['composite_score'], 100, rcolor, 90, 8)}<span class="inline-pct">{s['composite_score']}</span></td>
            <td class="narrative mono-small">{esc(s['rationale'])}</td>
        </tr>"""
    return f"""
    <section class="tab-block" id="risk">
        <div class="section-eyebrow">RISK SCORING ENGINE</div>
        <h2>Composite Risk</h2>
        <table class="data-table">
            <thead><tr><th>CVE</th><th>Band</th><th>Score</th><th>Rationale</th></tr></thead>
            <tbody>{rows or '<tr><td colspan="4" class="empty">No data</td></tr>'}</tbody>
        </table>
    </section>"""


def render_heatmap_section(ctx: dict) -> str:
    hm = ctx["coverage_heatmap"]
    if not hm:
        return ""
    tactics_in_scope = [t for t, data in hm.items() if data.get("known_techniques_in_scope", 0) > 0]
    if not tactics_in_scope:
        return ""

    cols = [("Validated", "#5ce0a8"), ("Rule Exists", "#7c9dff")]

    def get_value(tactic, col_label):
        data = hm[tactic]
        if col_label == "Validated":
            return data.get("validated_coverage_pct", 0)
        return data.get("rule_coverage_pct", 0)

    heatmap_svg = svg_heatmap_grid(tactics_in_scope, cols, get_value, width=680, row_h=36)

    return f"""
    <section class="tab-block" id="heatmap">
        <div class="section-eyebrow">MITRE ATT&amp;CK COVERAGE</div>
        <h2>Detection Heatmap</h2>
        <p class="section-intro">Computed over the technique set this project knows about — not all 216 ATT&amp;CK techniques.</p>
        <div class="heatmap-panel">{heatmap_svg}</div>
    </section>"""


def render_gap_section(ctx: dict) -> str:
    tg = ctx["telemetry_gap"]
    if not tg:
        return ""
    src_rows = ""
    for source, status in tg.get("source_status", {}).items():
        mark = '<span class="status-ok">●</span>' if status["collected"] else '<span class="status-miss">●</span>'
        src_rows += f"<tr><td>{mark}</td><td>{esc(source)}</td><td class='mono-small'>{esc(', '.join(status['tactics']))}</td></tr>"
    rec_items = "".join(f"<li>{esc(r)}</li>" for r in tg.get("recommendations", []))
    return f"""
    <section class="tab-block" id="gaps">
        <div class="section-eyebrow">TELEMETRY GAP ANALYSIS</div>
        <h2>Visibility</h2>
        <table class="data-table">
            <thead><tr><th>Status</th><th>Source</th><th>Tactics Covered</th></tr></thead>
            <tbody>{src_rows}</tbody>
        </table>
        <p class="blind-line"><span class="rc-label">BLIND TACTICS</span> {esc(', '.join(tg.get('blind_tactics', [])) or '—')}</p>
        <div class="action-block">
            <div class="action-label">COLLECTION PRIORITIES</div>
            <ul class="action-list">{rec_items}</ul>
        </div>
    </section>"""


def render_rule_quality_section(ctx: dict) -> str:
    if not ctx["rule_quality"]:
        return ""
    rows = ""
    for r in ctx["rule_quality"]:
        rows += f"""
        <tr>
            <td class="mono-small">{esc(r['rule_file'])}</td>
            <td>{'●' * r['fp_risk_score']}{'○' * (5 - r['fp_risk_score'])}</td>
            <td>{'●' * r['performance_cost_score']}{'○' * (5 - r['performance_cost_score'])}</td>
            <td>{'●' * r['coverage_score']}{'○' * (5 - r['coverage_score'])}</td>
            <td class="mono-small">{esc('; '.join(r.get('recommendations', [])))}</td>
        </tr>"""
    return f"""
    <section class="tab-block" id="rules">
        <div class="section-eyebrow">WARDEN — RULE QUALITY</div>
        <h2>Sigma Rule Analysis</h2>
        <table class="data-table">
            <thead><tr><th>Rule</th><th>FP Risk</th><th>Perf. Cost</th><th>Coverage</th><th>Notes</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </section>"""


def render_ioc_section(ctx: dict) -> str:
    if not ctx["ioc_confidence"]:
        return ""
    rows = ""
    band_color = {"ACTIVE": "#5ce0a8", "AGING": "#ffb454", "STALE": "#ff5c72"}
    for i in ctx["ioc_confidence"]:
        c = band_color.get(i.get("confidence_band"), "#5a6275")
        # Reconstruct the decay curve shape from the half-life model
        # (90-day half-life, same constant the engine itself uses) so
        # the sparkline shows real projected decay, not a fabricated trend.
        age = i["age_days"]
        decay_factor = i.get("decay_factor", 1.0)
        freq_boost = i.get("frequency_boost", 1.0)
        source_boost = i.get("source_boost", 1.0)
        raw = i.get("raw_confidence", 100.0)
        sample_ages = [age * f for f in (0, 0.25, 0.5, 0.75, 1.0)]
        half_life = 90.0
        curve = []
        for a in sample_ages:
            df = 0.5 ** (a / half_life) if half_life else 1.0
            curve.append(min(100.0, raw * df * freq_boost * source_boost))
        spark = svg_sparkline(curve, width=110, height=32, color=c)
        rows += f"""
        <tr>
            <td class="mono-small">{esc(i['ioc_value'])}</td>
            <td><span class="pill" style="--pill-color:{c}">{esc(i['confidence_band'])}</span></td>
            <td>{i['age_days']:.1f}d</td>
            <td>{spark}</td>
            <td>{svg_bullet(i['decayed_confidence'], 100, c, 90, 8)}<span class="inline-pct">{i['decayed_confidence']:.0f}</span></td>
        </tr>"""
    return f"""
    <section class="tab-block" id="ioc">
        <div class="section-eyebrow">IOC DECAY ENGINE</div>
        <h2>Indicator Confidence</h2>
        <table class="data-table">
            <thead><tr><th>IOC</th><th>Status</th><th>Age</th><th>Decay Trend</th><th>Confidence</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </section>"""


def render_root_cause_section(ctx: dict) -> str:
    if not ctx["root_cause"]:
        return ""
    blocks = ""
    for rc in ctx["root_cause"]:
        chain = " → ".join(rc.get("causal_chain", []))
        actions = "".join(f"<li>{esc(a)}</li>" for a in rc.get("preventive_actions", []))
        blocks += f"""
        <div class="cause-card">
            <div class="cause-head"><span class="mono">{esc(rc['cve'])}</span> — {esc(rc['primary_cause'])}</div>
            <div class="cause-chain mono-small">{esc(chain)}</div>
            <ul class="action-list">{actions}</ul>
        </div>"""
    return f"""
    <section class="tab-block" id="rootcause">
        <div class="section-eyebrow">ROOT CAUSE DISCOVERY</div>
        <h2>Why This Happened</h2>
        {blocks}
    </section>"""


def render_emulation_section(ctx: dict) -> str:
    es = ctx["emulation_score"]
    if not es:
        return ""
    cards = [
        ("Attack Diversity", f"{es.get('attack_diversity_pct', 'N/A')}%"),
        ("ATT&CK Coverage", f"{es.get('coverage_pct', 'N/A')}%"),
        ("Noise Level", str(es.get("noise_level", "N/A"))),
        ("Detection Success", f"{es.get('detection_success_pct', 'N/A')}%"),
        ("Grade", str(es.get("overall_grade", "N/A"))),
    ]
    cards_html = "".join(
        f'<div class="metric-card small"><div class="metric-value">{esc(v)}</div><div class="metric-label">{esc(k)}</div></div>'
        for k, v in cards
    )
    return f"""
    <section class="tab-block" id="emulation">
        <div class="section-eyebrow">ADVERSARY EMULATION QUALITY</div>
        <h2>Operation Self-Assessment</h2>
        <div class="metric-grid small-grid">{cards_html}</div>
    </section>"""


def render_html(ctx: dict) -> str:
    missing_html = ""
    if ctx["missing_modules"]:
        items = "".join(f"<li>{esc(m)}</li>" for m in ctx["missing_modules"])
        missing_html = f"""
        <div class="warning-box">
            <strong>Incomplete Dataset</strong> — the following modules have not been
            run; their sections are absent rather than estimated:
            <ul>{items}</ul>
        </div>"""

    # --- Tab definitions: (tab_id, nav_label, nav_icon, content_fn_or_html) ---
    findings_content = render_evidence_section(ctx)
    detection_content = render_correlation_section(ctx) + render_coverage_section(ctx) + render_heatmap_section(ctx)
    risk_content = render_risk_section(ctx) + render_ioc_section(ctx)
    engineering_content = render_rule_quality_section(ctx) + render_gap_section(ctx)
    rootcause_content = render_root_cause_section(ctx) + render_emulation_section(ctx)
    artifacts_content = f"""
    <section class="tab-block" id="outputs">
        <div class="section-eyebrow">RELATED OUTPUTS</div>
        <h2>Artifact Index</h2>
        <ul class="artifact-list">
            <li><code>reporting/navigator/obsidian_protocol_layer.json</code> — ATT&amp;CK Navigator layer</li>
            <li><code>docs/detection-coverage-matrix.md</code> — Markdown coverage matrix</li>
            <li><code>intel-export/output/obsidian_protocol_bundle.stix2.json</code> — STIX 2.1 bundle</li>
            <li><code>telemetry/output/unified_timeline.ndjson</code> — Unified telemetry timeline</li>
            <li><code>blackwell-core/evidence-graph/output/evidence_graph.json</code> — Full evidence graph</li>
            <li><code>blackwell-core/decision-engine/output/technical_briefing.md</code> — Analyst briefing</li>
            <li><code>blackwell-core/decision-engine/output/executive_briefing.md</code> — Executive briefing</li>
        </ul>
        <div class="disclaimer">
            <strong>Classification.</strong> This report was generated automatically from an
            educational/portfolio adversarial simulation conducted in an isolated,
            internet-disconnected Docker range. No real or third-party system was
            accessed at any point.
        </div>
    </section>"""

    tabs = [
        ("overview", "Overview", ICON_OVERVIEW, render_summary_section(ctx)),
        ("findings", "Findings", ICON_FINDINGS, findings_content),
        ("detection", "Detection", ICON_DETECTION, detection_content),
        ("risk", "Risk &amp; Intel", ICON_RISK, risk_content),
        ("engineering", "Engineering", ICON_ENGINEERING, engineering_content),
        ("rootcause", "Root Cause", ICON_ROOTCAUSE, rootcause_content),
        ("artifacts", "Artifacts", ICON_ARTIFACTS, artifacts_content),
    ]
    # Drop tabs that have no content at all (e.g. module never run)
    tabs = [t for t in tabs if t[3].strip()]

    nav_items = "".join(
        f'<button class="tab-btn{" active" if i == 0 else ""}" data-tab="{tid}">'
        f'<span class="tab-icon">{icon}</span><span class="tab-label">{label}</span></button>'
        for i, (tid, label, icon, _) in enumerate(tabs)
    )
    panels = "".join(
        f'<div class="tab-panel{" active" if i == 0 else ""}" id="panel-{tid}">{content}</div>'
        for i, (tid, label, icon, content) in enumerate(tabs)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OBSIDIAN PROTOCOL — Operation Report</title>
<style>
{CSS}
</style>
</head>
<body>

<header class="masthead">
    <div class="masthead-inner">
        <div class="masthead-row">
            <div>
                <div class="case-eyebrow">CASE FILE · EVIDENCE-GROUNDED OPERATION REPORT</div>
                <h1>OBSIDIAN<span class="title-accent">_</span>PROTOCOL</h1>
            </div>
            <div class="masthead-meta">
                <span>Generated {esc(ctx['generated_at'])}</span>
                <span class="dot">·</span>
                <span>Adversarial Simulation &amp; Detection Engineering</span>
            </div>
        </div>
    </div>
</header>

<nav class="tab-nav">
    <div class="tab-nav-inner">{nav_items}</div>
</nav>

<main class="dossier">
    {missing_html}
    {panels}
</main>

<footer class="dossier-footer">
    OBSIDIAN PROTOCOL — generated by <code>reporting/generate_html_report.py</code>
</footer>

<script>{CHART_INTERACTIVITY_JS}</script>

<script>
(function() {{
    const buttons = document.querySelectorAll('.tab-btn');
    const panels = document.querySelectorAll('.tab-panel');
    function activate(tabId) {{
        buttons.forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
        panels.forEach(p => p.classList.toggle('active', p.id === 'panel-' + tabId));
        window.scrollTo({{top: 0, behavior: 'instant'}});
        try {{ history.replaceState(null, '', '#' + tabId); }} catch (e) {{}}
    }}
    buttons.forEach(b => b.addEventListener('click', () => activate(b.dataset.tab)));
    const initial = (location.hash || '').replace('#', '');
    if (initial && document.getElementById('panel-' + initial)) {{
        activate(initial);
    }}
}})();
</script>

</body>
</html>
"""


CHART_INTERACTIVITY_JS = r"""
(function() {
    // Shared hover-tooltip + click-to-navigate engine for every SVG
    // chart in the report (scatter, heatmap, timeline, donut). One
    // tooltip element, one event-delegation listener — every chart
    // gets the same interaction language instead of bespoke per-chart
    // JS, and every data-target is real navigation (tab:elementId),
    // not a decorative hover state.
    let tip = document.getElementById('ix-tooltip');
    if (!tip) {
        tip = document.createElement('div');
        tip.id = 'ix-tooltip';
        tip.className = 'ix-tooltip';
        document.body.appendChild(tip);
    }

    function showTip(target, ev) {
        const text = target.getAttribute('data-tip');
        if (!text) return;
        tip.textContent = text;
        tip.style.left = (ev.clientX + 16) + 'px';
        tip.style.top = (ev.clientY - 10) + 'px';
        tip.classList.add('visible');
        target.classList.add('ix-point-hover');
    }
    function hideTip(target) {
        tip.classList.remove('visible');
        if (target) target.classList.remove('ix-point-hover');
    }

    function activateTab(tabId) {
        const btn = document.querySelector('.tab-btn[data-tab="' + tabId + '"]');
        if (btn) btn.click();
    }
    function highlightTarget(elId) {
        const el = document.getElementById(elId);
        if (!el) return;
        setTimeout(() => {
            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            el.classList.add('nn-jump-highlight');
            setTimeout(() => el.classList.remove('nn-jump-highlight'), 1800);
        }, 120);
    }
    function followTarget(raw) {
        // Format: "tabId:elementId" or bare "elementId" (same-tab link).
        const idx = raw.indexOf(':');
        if (idx === -1) { highlightTarget(raw); return; }
        const tabId = raw.slice(0, idx), elId = raw.slice(idx + 1);
        activateTab(tabId);
        highlightTarget(elId);
    }

    let current = null;
    document.addEventListener('mousemove', (ev) => {
        const pt = ev.target.closest('.ix-point');
        if (pt === current) {
            if (pt) { tip.style.left = (ev.clientX + 16) + 'px'; tip.style.top = (ev.clientY - 10) + 'px'; }
            return;
        }
        if (current) hideTip(current);
        current = pt;
        if (pt) showTip(pt, ev);
    });
    document.addEventListener('mouseleave', () => { if (current) hideTip(current); current = null; });

    document.addEventListener('click', (ev) => {
        const pt = ev.target.closest('.ix-point');
        if (!pt) return;
        const target = pt.getAttribute('data-target');
        if (target) followTarget(target);
    });

    // Pointer affordance: anything clickable shows a pointer cursor.
    document.addEventListener('mouseover', (ev) => {
        const pt = ev.target.closest('.ix-point');
        if (pt && pt.hasAttribute('data-target')) pt.style.cursor = 'pointer';
    });
})();
"""

NEURAL_NETWORK_JS = r"""
(function() {
    const dataEl = document.getElementById('nn-data');
    const canvas = document.getElementById('nn-canvas');
    const tooltip = document.getElementById('nn-tooltip');
    if (!dataEl || !canvas) return;
    const graph = JSON.parse(dataEl.textContent);
    const ctx2d = canvas.getContext('2d');
    const CANVAS_H = 340;

    let width, height, dpr;
    let view = { x: 0, y: 0, scale: 1 };   // pan/zoom transform
    let hovered = null;
    let dragging = null;
    let dragOffset = { x: 0, y: 0 };
    let panning = false;
    let panStart = null;
    let mouse = { x: -9999, y: -9999, active: false };

    const nodes = graph.nodes.map((n, i) => ({
        ...n,
        x: 0, y: 0, vx: 0, vy: 0,
        angle: (i / graph.nodes.length) * Math.PI * 2,
        pinned: false,
    }));
    const nodeById = {};
    nodes.forEach(n => nodeById[n.id] = n);
    const edges = graph.edges
        .map(e => ({ ...e, a: nodeById[e.source], b: nodeById[e.target] }))
        .filter(e => e.a && e.b);

    function resize() {
        const rect = canvas.parentElement.getBoundingClientRect();
        dpr = Math.min(window.devicePixelRatio || 1, 2);
        width = rect.width;
        height = CANVAS_H;
        canvas.width = Math.round(width * dpr);
        canvas.height = Math.round(height * dpr);
        canvas.style.height = height + 'px';
        ctx2d.setTransform(dpr, 0, 0, dpr, 0, 0);

        const cx = width / 2, cy = height / 2;
        const r = Math.min(width, height) * 0.36;
        nodes.forEach(n => {
            if (n.x === 0 && n.y === 0) {
                n.x = cx + Math.cos(n.angle) * r * (0.5 + Math.random() * 0.5);
                n.y = cy + Math.sin(n.angle) * r * (0.5 + Math.random() * 0.5);
            }
        });
    }

    // Screen <-> world coordinate conversion, accounting for pan/zoom.
    function toWorld(sx, sy) {
        return { x: (sx - view.x) / view.scale, y: (sy - view.y) / view.scale };
    }

    function nodeAt(wx, wy) {
        let best = null, bestDist = Infinity;
        for (const n of nodes) {
            const r = (3.4 + n.weight * 6) + 5; // generous hit radius
            const dx = n.x - wx, dy = n.y - wy;
            const d = Math.sqrt(dx * dx + dy * dy);
            if (d < r && d < bestDist) { best = n; bestDist = d; }
        }
        return best;
    }

    // --- Force simulation: spring edges + repulsion + center pull + cursor pressure ---
    function step() {
        const cx = width / 2, cy = height / 2;
        for (const n of nodes) {
            if (n === dragging || n === hovered) continue;
            n.vx += (cx - n.x) * 0.0016;
            n.vy += (cy - n.y) * 0.0016;
        }
        for (let i = 0; i < nodes.length; i++) {
            for (let j = i + 1; j < nodes.length; j++) {
                const a = nodes[i], b = nodes[j];
                let dx = a.x - b.x, dy = a.y - b.y;
                let distSq = dx * dx + dy * dy;
                if (distSq < 1) distSq = 1;
                const force = 460 / distSq;
                const dist = Math.sqrt(distSq);
                dx /= dist; dy /= dist;
                if (a !== dragging && a !== hovered) { a.vx += dx * force; a.vy += dy * force; }
                if (b !== dragging && b !== hovered) { b.vx -= dx * force; b.vy -= dy * force; }
            }
        }
        for (const e of edges) {
            const dx = e.b.x - e.a.x, dy = e.b.y - e.a.y;
            const dist = Math.sqrt(dx * dx + dy * dy) || 1;
            const target = 100;
            const k = 0.0026 * (0.4 + e.strength);
            const f = (dist - target) * k;
            const ux = dx / dist, uy = dy / dist;
            if (e.a !== dragging && e.a !== hovered) { e.a.vx += ux * f; e.a.vy += uy * f; }
            if (e.b !== dragging && e.b !== hovered) { e.b.vx -= ux * f; e.b.vy -= uy * f; }
        }
        // Cursor pressure: nodes near the pointer get a very gentle
        // outward push — enough to feel like a live simulation reacting
        // to a probe, but weak enough that hovering and clicking a node
        // still works (a strong push here would make nodes unhittable).
        if (mouse.active && !hovered) {
            const w = toWorld(mouse.x, mouse.y);
            for (const n of nodes) {
                if (n === dragging) continue;
                const dx = n.x - w.x, dy = n.y - w.y;
                const distSq = dx * dx + dy * dy;
                const radius = 46;
                if (distSq < radius * radius && distSq > 4) {
                    const dist = Math.sqrt(distSq);
                    const f = (1 - dist / radius) * 0.32;
                    n.vx += (dx / dist) * f;
                    n.vy += (dy / dist) * f;
                }
            }
        }
        const pad = 16;
        for (const n of nodes) {
            if (n === dragging) continue;
            n.vx *= 0.86; n.vy *= 0.86;
            if (n === hovered) { n.vx *= 0.3; n.vy *= 0.3; } // settle quickly, stay put while hovered
            n.x += n.vx; n.y += n.vy;
            n.x = Math.max(pad, Math.min(width - pad, n.x));
            n.y = Math.max(pad, Math.min(height - pad, n.y));
        }
    }

    let t = 0;
    function draw() {
        ctx2d.save();
        ctx2d.clearRect(0, 0, width, height);
        ctx2d.translate(view.x, view.y);
        ctx2d.scale(view.scale, view.scale);

        for (const e of edges) {
            const isLinkedToHover = hovered && (e.a === hovered || e.b === hovered);
            const grad = ctx2d.createLinearGradient(e.a.x, e.a.y, e.b.x, e.b.y);
            grad.addColorStop(0, e.a.color + (isLinkedToHover ? 'aa' : '4a'));
            grad.addColorStop(1, e.b.color + (isLinkedToHover ? 'aa' : '4a'));
            ctx2d.strokeStyle = grad;
            ctx2d.lineWidth = (isLinkedToHover ? 1.6 : 0.6) + e.strength * 1.4;
            ctx2d.setLineDash([3, 5]);
            ctx2d.lineDashOffset = -t * (0.4 + e.strength);
            ctx2d.beginPath();
            ctx2d.moveTo(e.a.x, e.a.y);
            ctx2d.lineTo(e.b.x, e.b.y);
            ctx2d.stroke();
        }
        ctx2d.setLineDash([]);

        for (const n of nodes) {
            const isHovered = n === hovered;
            const r = (3.4 + n.weight * 6) * (isHovered ? 1.35 : 1);
            const pulse = 1 + 0.08 * Math.sin(t * 0.05 + n.angle * 3);
            ctx2d.save();
            ctx2d.shadowColor = n.color;
            ctx2d.shadowBlur = (isHovered ? 20 : 10) * pulse;
            ctx2d.beginPath();
            ctx2d.arc(n.x, n.y, r * pulse, 0, Math.PI * 2);
            ctx2d.fillStyle = n.color;
            ctx2d.globalAlpha = isHovered ? 1 : 0.92;
            ctx2d.fill();
            if (isHovered || n.target) {
                ctx2d.lineWidth = 1.5;
                ctx2d.strokeStyle = '#ffffff';
                ctx2d.globalAlpha = isHovered ? 0.9 : 0.25;
                ctx2d.stroke();
            }
            ctx2d.restore();
        }

        ctx2d.restore();
        t += 1;
    }

    function tick() {
        step();
        draw();
        requestAnimationFrame(tick);
    }

    // --- Tooltip ---
    function showTooltip(n, sx, sy) {
        if (!tooltip) return;
        const linkHint = n.target
            ? '<span class="nn-tt-link">click to open in ' + (n.tab === 'risk' ? 'Risk & Intel' : n.tab === 'findings' ? 'Findings' : n.tab === 'detection' ? 'Detection' : n.tab) + ' &rarr;</span>'
            : '<span class="nn-tt-nolink">no linked detail view</span>';
        tooltip.innerHTML =
            '<div class="nn-tt-kind" style="color:' + n.color + '">' + n.kind + '</div>' +
            '<div class="nn-tt-label">' + n.label.replace(/</g, '&lt;') + '</div>' +
            '<div class="nn-tt-meta">weight ' + n.weight.toFixed(2) + (n.provenance ? ' &middot; ' + n.provenance.replace(/</g, '&lt;') : '') + '</div>' +
            linkHint;
        tooltip.style.left = sx + 'px';
        tooltip.style.top = sy + 'px';
        tooltip.classList.add('visible');
    }
    function hideTooltip() {
        if (tooltip) tooltip.classList.remove('visible');
    }

    // --- Cross-tab navigation: a click is real navigation, not decoration ---
    function activateTab(tabId) {
        const btn = document.querySelector('.tab-btn[data-tab="' + tabId + '"]');
        if (btn) btn.click();
    }
    function highlightTarget(elId) {
        const el = document.getElementById(elId);
        if (!el) return;
        setTimeout(() => {
            el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            el.classList.add('nn-jump-highlight');
            setTimeout(() => el.classList.remove('nn-jump-highlight'), 1800);
        }, 120);
    }

    canvas.addEventListener('mousemove', (ev) => {
        const rect = canvas.getBoundingClientRect();
        const sx = ev.clientX - rect.left, sy = ev.clientY - rect.top;
        mouse.x = sx; mouse.y = sy; mouse.active = true;
        const w = toWorld(sx, sy);

        if (dragging) {
            dragging.x = w.x - dragOffset.x;
            dragging.y = w.y - dragOffset.y;
            hideTooltip();
            return;
        }
        if (panning) {
            view.x = panStart.vx + (sx - panStart.sx);
            view.y = panStart.vy + (sy - panStart.sy);
            return;
        }
        const hit = nodeAt(w.x, w.y);
        if (hit !== hovered) {
            hovered = hit;
            canvas.style.cursor = hit ? (hit.target ? 'pointer' : 'grab') : 'grab';
        }
        if (hovered) {
            showTooltip(hovered, sx + 14, sy - 10);
        } else {
            hideTooltip();
        }
    });

    canvas.addEventListener('mousedown', (ev) => {
        const rect = canvas.getBoundingClientRect();
        const sx = ev.clientX - rect.left, sy = ev.clientY - rect.top;
        const w = toWorld(sx, sy);
        // Prefer the already-hovered node (set on the immediately
        // preceding mousemove) over a fresh hit-test — physics can
        // nudge a node a pixel or two between the hover frame and the
        // mousedown frame, and we don't want that micro-drift to make
        // an obviously-targeted node un-clickable.
        const hit = hovered || nodeAt(w.x, w.y);
        if (hit) {
            dragging = hit;
            dragging.pinned = true;
            dragOffset = { x: w.x - hit.x, y: w.y - hit.y };
            canvas.style.cursor = 'grabbing';
        } else {
            panning = true;
            panStart = { sx, sy, vx: view.x, vy: view.y };
            canvas.style.cursor = 'grabbing';
        }
    });

    function endInteraction(ev) {
        if (dragging) {
            // Was this a drag or a click? Tiny movement = treat as click.
            const rect = canvas.getBoundingClientRect();
            const sx = ev.clientX - rect.left, sy = ev.clientY - rect.top;
            const w = toWorld(sx, sy);
            const moved = Math.hypot(w.x - (dragging.x), w.y - (dragging.y));
            const clickedNode = dragging;
            dragging = null;
            if (clickedNode.target) {
                activateTab(clickedNode.tab);
                highlightTarget(clickedNode.target);
            }
        }
        panning = false;
        canvas.style.cursor = hovered ? 'pointer' : 'grab';
    }
    canvas.addEventListener('mouseup', endInteraction);
    canvas.addEventListener('mouseleave', () => {
        mouse.active = false;
        hovered = null;
        dragging = null;
        panning = false;
        hideTooltip();
    });

    // Scroll to zoom, centered on the cursor.
    canvas.addEventListener('wheel', (ev) => {
        ev.preventDefault();
        const rect = canvas.getBoundingClientRect();
        const sx = ev.clientX - rect.left, sy = ev.clientY - rect.top;
        const before = toWorld(sx, sy);
        const delta = ev.deltaY > 0 ? 0.92 : 1.08;
        view.scale = Math.max(0.5, Math.min(2.6, view.scale * delta));
        const after = toWorld(sx, sy);
        view.x += (after.x - before.x) * view.scale;
        view.y += (after.y - before.y) * view.scale;
    }, { passive: false });

    // Touch support: one-finger drag pans; touching a node drags it.
    canvas.addEventListener('touchstart', (ev) => {
        const t0 = ev.touches[0];
        const rect = canvas.getBoundingClientRect();
        const sx = t0.clientX - rect.left, sy = t0.clientY - rect.top;
        const w = toWorld(sx, sy);
        const hit = nodeAt(w.x, w.y);
        if (hit) {
            dragging = hit;
            dragOffset = { x: w.x - hit.x, y: w.y - hit.y };
        } else {
            panning = true;
            panStart = { sx, sy, vx: view.x, vy: view.y };
        }
    }, { passive: true });
    canvas.addEventListener('touchmove', (ev) => {
        const t0 = ev.touches[0];
        const rect = canvas.getBoundingClientRect();
        const sx = t0.clientX - rect.left, sy = t0.clientY - rect.top;
        const w = toWorld(sx, sy);
        if (dragging) { dragging.x = w.x - dragOffset.x; dragging.y = w.y - dragOffset.y; }
        else if (panning) {
            view.x = panStart.vx + (sx - panStart.sx);
            view.y = panStart.vy + (sy - panStart.sy);
        }
    }, { passive: true });
    canvas.addEventListener('touchend', (ev) => {
        if (dragging && dragging.target) {
            activateTab(dragging.tab);
            highlightTarget(dragging.target);
        }
        dragging = null; panning = false;
    });

    const ro = new ResizeObserver(() => resize());
    ro.observe(canvas.parentElement);
    resize();
    requestAnimationFrame(tick);
})();
"""

CSS = """
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700&family=Inter:wght@400;500;600;700&display=swap');

:root {
    --bg: #07090d;
    --panel: #11151e;
    --panel-glass: rgba(18,22,32,0.65);
    --panel-border: #1d2433;
    --panel-border-hover: #2a3344;
    --text: #c9cdd6;
    --text-dim: #6b7280;
    --text-bright: #f3f5f8;
    --accent-blue: #7c9dff;
    --accent-green: #5ce0a8;
    --accent-amber: #ffb454;
    --accent-red: #ff5c72;
    --glow-blue: rgba(124,157,255,0.35);
    --glow-green: rgba(92,224,168,0.3);
    --mono: 'JetBrains Mono', monospace;
    --sans: 'Inter', -apple-system, sans-serif;
}

* { box-sizing: border-box; }
html { scroll-behavior: smooth; }

body {
    margin: 0;
    background: var(--bg);
    background-image:
        radial-gradient(ellipse 900px 500px at 12% -5%, rgba(124,157,255,0.10), transparent 60%),
        radial-gradient(ellipse 700px 500px at 88% 10%, rgba(92,224,168,0.07), transparent 60%),
        radial-gradient(ellipse 800px 600px at 50% 100%, rgba(255,92,114,0.04), transparent 60%);
    background-attachment: fixed;
    color: var(--text);
    font-family: var(--sans);
    line-height: 1.6;
}

/* ---------- Masthead ---------- */
.masthead {
    border-bottom: 1px solid var(--panel-border);
    padding: 36px 24px 28px;
    position: relative;
    overflow: hidden;
}
.masthead::before {
    content: "";
    position: absolute;
    inset: 0;
    background:
        repeating-linear-gradient(90deg, rgba(110,143,255,0.035) 0px, rgba(110,143,255,0.035) 1px, transparent 1px, transparent 80px);
    pointer-events: none;
}
.masthead-inner { max-width: 1200px; margin: 0 auto; position: relative; }
.masthead-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    flex-wrap: wrap;
    gap: 16px;
}
.case-eyebrow {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 3px;
    color: var(--accent-blue);
    margin-bottom: 14px;
    font-weight: 600;
}
.masthead h1 {
    font-family: var(--mono);
    font-size: clamp(1.6em, 6vw, 3em);
    font-weight: 700;
    letter-spacing: 1px;
    margin: 0;
    color: var(--text-bright);
    overflow-wrap: break-word;
    line-height: 1.1;
    text-shadow: 0 0 36px rgba(124,157,255,0.18);
}
.title-accent {
    color: var(--accent-red);
    text-shadow: 0 0 14px rgba(255,92,114,0.6);
    animation: accentBlink 2.4s ease-in-out infinite;
}
@keyframes accentBlink {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.45; }
}
.masthead-meta {
    font-family: var(--mono);
    font-size: 12.5px;
    color: var(--text-dim);
    text-align: right;
    padding-bottom: 4px;
}
.masthead-meta .dot { margin: 0 10px; color: var(--panel-border); }
.masthead-meta span { display: inline; }

/* ---------- Tab navigation ---------- */
.tab-nav {
    position: sticky;
    top: 0;
    z-index: 50;
    background: rgba(7,9,13,0.85);
    backdrop-filter: blur(14px) saturate(140%);
    border-bottom: 1px solid var(--panel-border);
}
.tab-nav-inner {
    max-width: 1200px;
    margin: 0 auto;
    display: flex;
    gap: 4px;
    padding: 0 24px;
    overflow-x: auto;
    scrollbar-width: none;
}
.tab-nav-inner::-webkit-scrollbar { display: none; }
.tab-btn {
    display: flex;
    align-items: center;
    gap: 8px;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-dim);
    font-family: var(--sans);
    font-size: 13.5px;
    font-weight: 600;
    padding: 16px 14px;
    cursor: pointer;
    white-space: nowrap;
    transition: color 0.15s ease, border-color 0.15s ease;
    position: relative;
}
.tab-btn:hover { color: var(--text); }
.tab-btn.active { color: var(--accent-blue); border-bottom-color: var(--accent-blue); }
.tab-btn.active .tab-icon { filter: drop-shadow(0 0 6px var(--glow-blue)); }
.tab-icon { width: 16px; height: 16px; display: inline-flex; flex-shrink: 0; }
.tab-icon svg { width: 100%; height: 100%; }

/* ---------- Layout ---------- */
.dossier { max-width: 1200px; margin: 0 auto; padding: 32px 24px 80px; }

.warning-box {
    background: rgba(255,92,114,0.08);
    border: 1px solid rgba(255,92,114,0.3);
    border-radius: 4px;
    padding: 16px 20px;
    margin: 0 0 28px;
    color: #ffb3bc;
    font-size: 14px;
}
.warning-box ul { margin: 8px 0 0; padding-left: 20px; }

/* ---------- Hero metric grid ---------- */
.hero { margin: 0; }
.metric-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
    gap: 1px;
    background: var(--panel-border);
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    overflow: hidden;
}
.metric-grid.small-grid { grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); }
.metric-card {
    background: linear-gradient(165deg, rgba(255,255,255,0.025), transparent 60%), var(--panel);
    padding: 24px 20px;
    border-top: 2px solid var(--card-accent, var(--accent-blue));
    position: relative;
    transition: background-color 0.2s ease;
}
.metric-card:hover { background-color: #151a25; }
.metric-card.small { padding: 18px 16px; }
.metric-value {
    font-family: var(--mono);
    font-size: 1.9em;
    font-weight: 700;
    color: var(--text-bright);
    letter-spacing: -0.5px;
    overflow-wrap: break-word;
    word-break: break-word;
    text-shadow: 0 0 24px var(--card-accent, var(--glow-blue));
}
.metric-card.small .metric-value { font-size: 1.05em; line-height: 1.3; }
.metric-label {
    color: var(--text-dim);
    font-size: 12px;
    margin-top: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    overflow-wrap: break-word;
}

/* ---------- Tab panels (replaces the old vertical spine) ---------- */
.tab-panel { display: none; }
.tab-panel.active { display: block; animation: tabFadeIn 0.18s ease; }
@keyframes tabFadeIn {
    from { opacity: 0; transform: translateY(4px); }
    to { opacity: 1; transform: translateY(0); }
}
.tab-block {
    position: relative;
    margin-bottom: 48px;
}
.tab-block:last-child { margin-bottom: 0; }
.section-eyebrow {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2.5px;
    color: var(--accent-blue);
    font-weight: 600;
    margin-bottom: 8px;
}
.tab-block h2 {
    font-family: var(--sans);
    font-size: 1.5em;
    font-weight: 700;
    color: var(--text-bright);
    margin: 0 0 16px;
}
.section-intro { color: var(--text-dim); font-size: 14px; max-width: 640px; margin: -4px 0 20px; }
.reduction-tag {
    display: inline-block;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--accent-green);
    background: rgba(92,224,168,0.1);
    border: 1px solid rgba(92,224,168,0.3);
    border-radius: 3px;
    padding: 3px 8px;
    margin-left: 10px;
    vertical-align: middle;
}

/* ---------- Decision cards (Blackwell Core) ---------- */
.decision-card {
    display: flex;
    background: linear-gradient(135deg, rgba(255,255,255,0.02), transparent 50%), var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    margin-bottom: 16px;
    overflow: hidden;
    transition: border-color 0.2s ease, transform 0.2s ease;
}
.decision-card:hover {
    border-color: var(--panel-border-hover);
    transform: translateY(-1px);
}
.decision-rail { width: 4px; background: var(--accent); flex-shrink: 0; box-shadow: 0 0 12px var(--accent); }
.decision-body { padding: 20px 24px; flex: 1; }
.decision-top { display: flex; justify-content: space-between; align-items: flex-start; gap: 16px; }
.node-tag {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--text-dim);
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--panel-border);
    border-radius: 3px;
    padding: 2px 6px;
}
.decision-title { font-size: 1.05em; font-weight: 600; color: var(--text-bright); margin-top: 6px; }
.decision-risk {
    font-family: var(--mono);
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    border: 1px solid;
    border-radius: 3px;
    padding: 4px 10px;
    white-space: nowrap;
}
.decision-metrics {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 20px;
    margin: 18px 0;
}
.dm-label { font-size: 11px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }
.dm-value { font-family: var(--mono); font-size: 1.2em; color: var(--text-bright); margin: 2px 0 6px; }
.meter { width: 100%; height: 6px; background: rgba(255,255,255,0.06); border-radius: 3px; overflow: hidden; }
.meter-fill { border-radius: 3px; }
.evidence-line {
    font-size: 13px;
    color: var(--text-dim);
    border-top: 1px dashed var(--panel-border);
    padding-top: 12px;
    margin-top: 4px;
}
.evidence-icon { color: var(--accent-blue); }
.root-cause-line, .temporal-line { font-size: 13px; margin-top: 8px; color: var(--text); }
.rc-label {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--accent-amber);
    letter-spacing: 1px;
    margin-right: 6px;
}
.decision-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-top: 16px;
}
.action-label, .hypo-label {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1px;
    color: var(--text-dim);
    margin-bottom: 6px;
}
.hypo-caveat { color: var(--text-dim); font-weight: 400; text-transform: none; letter-spacing: 0; }
.action-list, .hypo-list { margin: 0; padding-left: 18px; font-size: 13px; }
.action-list li, .hypo-list li { margin-bottom: 4px; }
.why-details { margin-top: 16px; }
.why-details summary {
    cursor: pointer;
    font-size: 12px;
    color: var(--accent-blue);
    font-family: var(--mono);
}
.why-details code {
    display: block;
    margin-top: 8px;
    font-size: 11px;
    color: var(--text-dim);
    white-space: pre-wrap;
    word-break: break-word;
    background: rgba(255,255,255,0.02);
    padding: 10px;
    border-radius: 4px;
}

/* ---------- Tables ---------- */
.data-table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
.data-table th {
    text-align: left;
    font-family: var(--mono);
    font-size: 10.5px;
    letter-spacing: 1px;
    text-transform: uppercase;
    color: var(--text-dim);
    border-bottom: 1px solid var(--panel-border);
    padding: 0 12px 10px;
}
.data-table td {
    padding: 12px;
    border-bottom: 1px solid var(--panel-border);
    vertical-align: middle;
}
.data-table tbody tr:hover { background: rgba(255,255,255,0.015); }
.mono { font-family: var(--mono); font-size: 12.5px; }
.mono-small { font-family: var(--mono); font-size: 11.5px; color: var(--text-dim); }
.narrative { color: var(--text-dim); font-size: 12.5px; max-width: 320px; }
.empty { color: var(--text-dim); text-align: center; padding: 24px; }

.pill {
    display: inline-block;
    font-family: var(--mono);
    font-size: 10.5px;
    font-weight: 700;
    letter-spacing: 0.5px;
    color: var(--pill-color);
    border: 1px solid var(--pill-color);
    border-radius: 3px;
    padding: 2px 8px;
    background: color-mix(in srgb, var(--pill-color) 12%, transparent);
}
.inline-pct { font-family: var(--mono); font-size: 11px; color: var(--text-dim); margin-left: 8px; }

.status-ok { color: var(--accent-green); font-family: var(--mono); font-size: 11px; font-weight: 700; }
.status-miss { color: var(--accent-red); font-family: var(--mono); font-size: 11px; font-weight: 700; }
.status-meta { color: var(--text-dim); font-size: 11px; }

/* ---------- Root cause cards ---------- */
.cause-card {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 18px 22px;
    margin-bottom: 14px;
}
.cause-head { font-size: 14px; color: var(--text-bright); margin-bottom: 8px; }
.cause-chain { color: var(--text-dim); margin-bottom: 10px; }

.blind-line { font-size: 13px; margin: 14px 0; }
.action-block { margin-top: 14px; }

/* ---------- Artifact list ---------- */
.artifact-list { list-style: none; padding: 0; margin: 0; }
.artifact-list li {
    padding: 10px 0;
    border-bottom: 1px solid var(--panel-border);
    font-size: 13px;
    color: var(--text-dim);
}
.artifact-list code { color: var(--accent-blue); font-family: var(--mono); font-size: 12px; }

/* ---------- Footer ---------- */
.disclaimer {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 18px 22px;
    font-size: 12.5px;
    color: var(--text-dim);
    margin-top: 56px;
}
.dossier-footer {
    text-align: center;
    color: var(--text-dim);
    font-family: var(--mono);
    font-size: 11px;
    padding: 32px;
    border-top: 1px solid var(--panel-border);
}
.dossier-footer code { color: var(--accent-blue); }

/* ---------- Hero secondary: risk donut ---------- */
.hero-secondary { margin-top: 20px; }

/* ---------- Neural network panel (live Evidence Graph render) ---------- */
.nn-panel {
    background: linear-gradient(165deg, rgba(110,143,255,0.05), var(--panel) 45%);
    border: 1px solid var(--panel-border);
    border-radius: 8px;
    padding: 20px 24px 8px;
    margin-top: 20px;
    position: relative;
    overflow: hidden;
}
.nn-panel::after {
    content: "";
    position: absolute;
    inset: 0;
    background: radial-gradient(circle at 80% 20%, rgba(110,143,255,0.08), transparent 55%);
    pointer-events: none;
}
.nn-panel-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    flex-wrap: wrap;
    gap: 12px;
    position: relative;
    z-index: 1;
}
.nn-panel-title {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--accent-blue);
    font-weight: 600;
}
.nn-panel-sub { font-size: 12.5px; color: var(--text-dim); margin-top: 4px; }
.nn-legend { display: flex; gap: 16px; flex-wrap: wrap; }
.nn-legend-row {
    display: flex;
    align-items: center;
    gap: 6px;
    font-family: var(--mono);
    font-size: 10.5px;
    letter-spacing: 0.5px;
    color: var(--text-dim);
    text-transform: uppercase;
}
.nn-legend-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
.nn-canvas-wrap {
    position: relative;
    margin-top: 8px;
    border-radius: 6px;
    overflow: hidden;
    background: radial-gradient(circle at 50% 50%, rgba(124,157,255,0.04), transparent 70%);
}
.nn-canvas {
    display: block;
    width: 100%;
    height: 340px;
    position: relative;
    z-index: 1;
    cursor: grab;
    touch-action: none;
}
.nn-hint {
    position: absolute;
    bottom: 10px;
    left: 14px;
    font-family: var(--mono);
    font-size: 10.5px;
    letter-spacing: 0.5px;
    color: var(--text-dim);
    opacity: 0.7;
    pointer-events: none;
    z-index: 2;
}
.nn-tooltip {
    position: absolute;
    top: 0; left: 0;
    transform: translate(0, 0);
    background: rgba(11,14,20,0.96);
    border: 1px solid var(--panel-border-hover);
    border-radius: 8px;
    padding: 10px 13px;
    font-size: 12px;
    max-width: 240px;
    pointer-events: none;
    opacity: 0;
    z-index: 5;
    box-shadow: 0 12px 30px rgba(0,0,0,0.5);
    transition: opacity 0.1s ease;
}
.nn-tooltip.visible { opacity: 1; }
.nn-tt-kind {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 1.2px;
    font-weight: 700;
    margin-bottom: 4px;
}
.nn-tt-label { color: var(--text-bright); font-weight: 600; margin-bottom: 4px; line-height: 1.35; }
.nn-tt-meta { color: var(--text-dim); font-size: 11px; margin-bottom: 6px; }
.nn-tt-link {
    display: inline-block;
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--accent-blue);
}
.nn-tt-nolink {
    display: inline-block;
    font-family: var(--mono);
    font-size: 10.5px;
    color: var(--text-dim);
    opacity: 0.7;
}
@keyframes jumpHighlight {
    0%, 100% { box-shadow: 0 0 0 0 rgba(124,157,255,0); }
    15% { box-shadow: 0 0 0 3px rgba(124,157,255,0.55); }
    50% { box-shadow: 0 0 0 6px rgba(124,157,255,0.15); }
}
.nn-jump-highlight {
    animation: jumpHighlight 1.6s ease-out;
    border-color: var(--accent-blue) !important;
}
.donut-panel {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 20px 24px;
}
.donut-panel-title {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--text-dim);
    margin-bottom: 16px;
}
.donut-panel-body { display: flex; align-items: center; gap: 32px; flex-wrap: wrap; }
.donut-svg { flex-shrink: 0; }
.donut-center-value { font-family: var(--mono); font-size: 28px; font-weight: 700; fill: var(--text-bright); }
.donut-center-sub { font-family: var(--mono); font-size: 10px; letter-spacing: 1px; fill: var(--text-dim); }
.donut-legend { display: flex; flex-direction: column; gap: 10px; min-width: 180px; }
.donut-legend-row { display: flex; align-items: center; gap: 10px; font-size: 13px; }
.donut-swatch { width: 10px; height: 10px; border-radius: 2px; flex-shrink: 0; }
.donut-legend-score { margin-left: auto; font-family: var(--mono); color: var(--text-dim); font-size: 12px; }

/* ---------- Scatter panel (Blackwell confidence x priority) ---------- */
.scatter-panel {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 20px 24px;
    margin-bottom: 24px;
}
.scatter-panel-title {
    font-family: var(--mono);
    font-size: 11px;
    letter-spacing: 2px;
    color: var(--text-dim);
    margin-bottom: 12px;
}
.scatter-panel-note { font-weight: 400; letter-spacing: 0; text-transform: none; color: var(--text-dim); }
.scatter-svg { display: block; }
.scatter-grid { stroke: rgba(255,255,255,0.04); stroke-width: 1; }
.scatter-axis { stroke: var(--panel-border); stroke-width: 1.5; }
.scatter-axis-mid { stroke: rgba(255,255,255,0.08); stroke-width: 1; stroke-dasharray: 3 4; }
.scatter-axis-label { font-family: var(--mono); font-size: 9px; fill: var(--text-dim); }
.scatter-axis-title { font-family: var(--mono); font-size: 10px; letter-spacing: 1px; fill: var(--text-dim); }
.scatter-quadrant-label { font-family: var(--mono); font-size: 9px; letter-spacing: 1px; fill: rgba(255,255,255,0.18); }
.scatter-label { font-family: var(--mono); font-size: 10px; fill: var(--text-dim); }

/* ---------- Shared interactive-chart engine ---------- */
.ix-chart { overflow: visible; }
.ix-point { transition: filter 0.12s ease, opacity 0.12s ease, stroke-width 0.12s ease; }
.ix-point-hover {
    filter: drop-shadow(0 0 8px currentColor) brightness(1.25);
}
circle.ix-point.ix-point-hover { stroke-width: 2.5; }
.heatmap-cell.ix-point-hover rect { stroke: rgba(255,255,255,0.55); stroke-width: 1.5; }
.donut-arc.ix-point-hover { opacity: 1; filter: drop-shadow(0 0 10px rgba(255,255,255,0.35)); }
.ix-tooltip {
    position: fixed;
    top: 0; left: 0;
    background: rgba(11,14,20,0.97);
    border: 1px solid var(--panel-border-hover);
    color: var(--text-bright);
    font-family: var(--mono);
    font-size: 12px;
    padding: 7px 11px;
    border-radius: 6px;
    pointer-events: none;
    opacity: 0;
    z-index: 999;
    box-shadow: 0 10px 28px rgba(0,0,0,0.5);
    transition: opacity 0.08s ease;
    max-width: 280px;
    white-space: pre-line;
}
.ix-tooltip.visible { opacity: 1; }

/* ---------- Heatmap grid ---------- */
.heatmap-panel {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 16px 20px;
}
.heatmap-svg { display: block; }
.heatmap-col-label { font-family: var(--mono); font-size: 10px; letter-spacing: 1px; fill: var(--text-dim); }
.heatmap-row-label { font-family: var(--sans); font-size: 12.5px; fill: var(--text); }
.heatmap-cell-text { font-family: var(--mono); font-size: 11px; font-weight: 700; }
.heatmap-cell rect { transition: fill-opacity 0.15s ease; }
.heatmap-cell:hover rect { fill-opacity: 1 !important; }

/* ---------- Timeline ---------- */
.timeline-panel {
    background: var(--panel);
    border: 1px solid var(--panel-border);
    border-radius: 6px;
    padding: 12px 20px 4px;
    margin-bottom: 20px;
}
.timeline-svg { display: block; }
.timeline-track { stroke: var(--panel-border); stroke-width: 2; }
.timeline-tick { stroke: rgba(255,255,255,0.15); stroke-width: 1.5; }
.timeline-label { font-family: var(--mono); font-size: 10.5px; fill: var(--text); font-weight: 600; }
.timeline-sub { font-family: var(--mono); font-size: 9.5px; fill: var(--text-dim); }

/* ---------- Sparkline + bullet (SVG, replacing div-based meters) ---------- */
.spark-svg { display: block; }
.bullet-svg { display: block; vertical-align: middle; }
.bullet-track { fill: rgba(255,255,255,0.06); }
.bullet-tick { stroke: rgba(10,13,18,0.5); stroke-width: 1; }

@media (max-width: 640px) {
    .decision-metrics, .decision-grid { grid-template-columns: 1fr; }
    .masthead { padding: 24px 16px 20px; }
    .masthead-row { flex-direction: column; align-items: flex-start; }
    .masthead-meta { text-align: left; padding-bottom: 0; }
    .tab-nav-inner { padding: 0 10px; }
    .tab-btn { padding: 13px 10px; font-size: 12.5px; }
    .tab-label { display: none; }
    .tab-icon { width: 19px; height: 19px; }
    .dossier { padding: 20px 14px 60px; }
    .donut-panel-body { flex-direction: column; align-items: flex-start; gap: 20px; }
    .scatter-panel, .heatmap-panel, .timeline-panel { padding: 14px; }
}
"""


def main():
    ctx = collect_report_context()
    html = render_html(ctx)
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        f.write(html)
    print(f"[+] HTML report generated: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

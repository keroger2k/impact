"""utils/cdrl49_report.py — CDRL49 daily WAN response-time report.

Builds the combined landscape PDF (AT&T EIS routers + SOHO routers WAN
response time, per Deliverable 65) from live SolarWinds Orion SWQL queries.
Pure data/formatting logic lives here; `routers/reports.py` owns the HTTP
surface. Every call re-queries SolarWinds — nothing here is cached, since a
CDRL is a point-in-time deliverable rather than a dataset worth staleness.
"""
from __future__ import annotations

import csv
import html
import io
import re
import unicodedata
from datetime import date, timedelta

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import landscape, letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

import clients.solarwinds as solarwinds

REPORT_DEFS = {
    "eis": {
        "title": "Wan Response Time AT&T EIS Routers - Del 65",
        "csv_name": "daily_eis",
        "node_filter": (
            "N.Caption LIKE 'R%'\n"
            "    AND N.Caption NOT LIKE '%AS001%'\n"
            "    AND N.Caption NOT LIKE '%AD001%'\n"
            "    AND N.Caption NOT LIKE '%DS001%'"
        ),
    },
    "soho": {
        "title": "Wan Response Time SOHO Routers - Del 65",
        "csv_name": "daily_soho",
        "node_filter": "(N.Caption LIKE 'I%' OR N.Caption LIKE '%AS001')",
    },
}

CSV_COLUMNS = [
    "Node Name", "Site", "Building", "State", "Machine Type",
    "Average Response Time", "Maximum Response Time", "Availability",
]


# ── Text cleanup ─────────────────────────────────────────────────────────────

def clean_text(value) -> str:
    if value is None:
        return ""

    text = str(value)
    text = unicodedata.normalize("NFKC", text)

    replacements = {
        " ": " ", "­": "", "​": "", "‌": "", "‍": "",
        "﻿": "", "�": "", "‘": "'", "’": "'", "“": '"',
        "”": '"', "–": "-", "—": "-", "−": "-", "…": "...",
    }
    for bad, good in replacements.items():
        text = text.replace(bad, good)

    text = "".join(
        ch for ch in text
        if unicodedata.category(ch) not in {"Cc", "Cf"} or ch in {"\n", "\r", "\t"}
    )
    text = re.sub(r"[ \t]+", " ", text)
    return text.strip()


def _format_number(value, decimals=2) -> str:
    text = clean_text(value)
    if text == "":
        return ""
    try:
        return f"{float(text):.{decimals}f}"
    except ValueError:
        return text


def _format_integer(value) -> str:
    text = clean_text(value)
    if text == "":
        return ""
    try:
        return str(int(round(float(text))))
    except ValueError:
        return text


def _format_availability(value) -> str:
    text = clean_text(value).replace("%", "").strip()
    if text == "":
        return ""
    try:
        return f"{float(text):.2f} %"
    except ValueError:
        return clean_text(value)


def normalize_result_row(row: dict) -> dict:
    return {
        "Node Name": clean_text(row.get("NodeName", row.get("Node Name", ""))),
        "Site": clean_text(row.get("Site", "")),
        "Building": clean_text(row.get("Building", "")),
        "State": clean_text(row.get("State", "")),
        "Machine Type": clean_text(row.get("MachineType", row.get("Machine Type", ""))),
        "Average Response Time": _format_number(
            row.get("AverageResponseTime", row.get("Average Response Time", "")), 2),
        "Maximum Response Time": _format_integer(
            row.get("MaximumResponseTime", row.get("Maximum Response Time", ""))),
        "Availability": _format_availability(row.get("Availability", "")),
    }


# ── SWQL ─────────────────────────────────────────────────────────────────────

def build_swql(key: str, day: date) -> str:
    """Build the SWQL for one report, scoped to the given calendar day.

    Date bounds are interpolated from a validated `date` object (never raw
    user text), so this can't be used as a SWQL-injection vector.
    """
    report = REPORT_DEFS[key]
    start = day.isoformat()
    end = (day + timedelta(days=1)).isoformat()
    return f"""
SELECT
    N.Caption AS NodeName,
    CP.Site,
    CP.Building,
    CP.State,
    N.MachineType,
    AVG(RT.AvgResponseTime) AS AverageResponseTime,
    MAX(RT.MaxResponseTime) AS MaximumResponseTime,
    AVG(RT.Availability) AS Availability
FROM Orion.Nodes N
JOIN Orion.NodesCustomProperties CP ON CP.NodeID = N.NodeID
JOIN Orion.ResponseTime RT ON RT.NodeID = N.NodeID
WHERE
    N.Vendor = 'Cisco'
    AND {report['node_filter']}
    AND RT.ObservationTimestamp >= '{start}'
    AND RT.ObservationTimestamp < '{end}'
GROUP BY
    N.Caption,
    CP.Site,
    CP.Building,
    CP.State,
    N.MachineType
ORDER BY
    N.Caption
"""


# ── CSV ──────────────────────────────────────────────────────────────────────

def rows_to_csv(rows: list[dict]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_COLUMNS)
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


# ── PDF ──────────────────────────────────────────────────────────────────────

def _safe_style_name(title: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", title)[:80]


def _make_paragraph(text: str, style: ParagraphStyle, escape: bool = True) -> Paragraph:
    text = clean_text(text)
    return Paragraph(html.escape(text) if escape else text, style)


def _build_table_data(rows: list[dict], body_style: ParagraphStyle, header_style: ParagraphStyle) -> list:
    # Headers are trusted static strings using <br/> intentionally to force
    # 3-line wrapping in narrow columns — don't html-escape them or the <br/>
    # tags render as literal text instead of line breaks. Body cells come from
    # SolarWinds and are escaped so a stray '<' or '&' in a hostname/site name
    # can't break reportlab's mini-markup parser.
    headers = [
        "Node Name", "Site", "Building", "State", "Machine Type",
        "Average<br/>Response<br/>Time", "Maximum<br/>Response<br/>Time", "Availability",
    ]
    table_data = [[_make_paragraph(h, header_style, escape=False) for h in headers]]
    for row in rows:
        table_data.append([_make_paragraph(row[c], body_style) for c in CSV_COLUMNS])
    return table_data


def _add_page_footer(canvas, doc):
    canvas.saveState()
    page_width, _ = landscape(letter)
    footer_text = f"Generated: {doc.generated_at}"
    page_text = f"Page {doc.page}"
    canvas.setFont("Helvetica", 7)
    canvas.drawString(0.35 * inch, 0.25 * inch, footer_text)
    canvas.drawRightString(page_width - 0.35 * inch, 0.25 * inch, page_text)
    canvas.restoreState()


def _add_report_section(story: list, title: str, rows: list[dict], is_first: bool):
    if not is_first:
        story.append(PageBreak())

    name = _safe_style_name(title)
    title_style = ParagraphStyle(
        name=f"Title_{name}", fontName="Helvetica-Bold", fontSize=10,
        leading=12, alignment=TA_CENTER, spaceAfter=6,
    )
    header_style = ParagraphStyle(
        name=f"Header_{name}", fontName="Helvetica-Bold", fontSize=6.5,
        leading=7, alignment=TA_CENTER,
    )
    body_style = ParagraphStyle(name=f"Body_{name}", fontName="Helvetica", fontSize=6.0, leading=7)
    count_style = ParagraphStyle(
        name=f"Count_{name}", fontName="Helvetica", fontSize=7,
        leading=8, alignment=TA_CENTER, spaceAfter=5,
    )

    story.append(Paragraph(html.escape(clean_text(title)), title_style))
    story.append(Paragraph(f"Rows: {len(rows)}", count_style))
    story.append(Spacer(1, 0.05 * inch))

    table = Table(
        _build_table_data(rows, body_style, header_style),
        colWidths=[1.15 * inch, 0.55 * inch, 2.25 * inch, 0.40 * inch,
                   2.25 * inch, 0.75 * inch, 0.75 * inch, 0.70 * inch],
        repeatRows=1,
        hAlign="LEFT",
    )
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9EAF7")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 6.5),
        ("ALIGN", (0, 0), (-1, 0), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 1), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 1), (-1, -1), 6.0),
        ("ALIGN", (5, 1), (7, -1), "RIGHT"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#A6A6A6")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F7F7")]),
        ("LEFTPADDING", (0, 0), (-1, -1), 2),
        ("RIGHTPADDING", (0, 0), (-1, -1), 2),
        ("TOPPADDING", (0, 0), (-1, -1), 2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
    ]))
    story.append(table)


def build_pdf(rows_by_key: dict[str, list[dict]], keys: list[str], generated_at: str) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=landscape(letter),
        rightMargin=0.25 * inch, leftMargin=0.25 * inch,
        topMargin=0.30 * inch, bottomMargin=0.45 * inch,
    )
    doc.generated_at = generated_at

    story = []
    for i, key in enumerate(keys):
        _add_report_section(story, REPORT_DEFS[key]["title"], rows_by_key[key], is_first=(i == 0))

    doc.build(story, onFirstPage=_add_page_footer, onLaterPages=_add_page_footer)
    return buf.getvalue()


# ── Orchestration ────────────────────────────────────────────────────────────

def generate_report(
    day: date, keys: list[str], generated_at: str, username: str, password: str
) -> tuple[bytes, dict[str, list[dict]]]:
    """Query SolarWinds for each selected report and build the combined PDF.

    Uses the logged-in user's own AD credentials (same pattern as F5) rather
    than a dedicated service account. Returns (pdf_bytes, rows_by_key) so the
    caller can also offer the underlying CSVs without re-querying.
    """
    rows_by_key: dict[str, list[dict]] = {}
    for key in keys:
        raw = solarwinds.query(build_swql(key, day), username, password)
        rows_by_key[key] = [normalize_result_row(r) for r in raw]

    pdf_bytes = build_pdf(rows_by_key, keys, generated_at)
    return pdf_bytes, rows_by_key

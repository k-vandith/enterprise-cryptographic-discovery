"""Human-readable PDF report generation. Uses ReportLab, a local optional dependency."""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from io import BytesIO
from typing import Any, Iterable

from src.scanner import Finding


def build_pdf_report(
    findings: Iterable[Finding],
    certificates: Iterable[dict[str, Any]] = (),
    source_label: str = "Uploaded project",
) -> bytes:
    """Build a compact, locally generated PDF summary."""
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import landscape, letter
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import inch
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except ImportError as exc:
        raise RuntimeError("PDF export needs ReportLab. Install it with: python -m pip install reportlab") from exc

    items = list(findings)
    certs = list(certificates)
    output = BytesIO()
    doc = SimpleDocTemplate(
        output, pagesize=landscape(letter),
        rightMargin=0.42 * inch, leftMargin=0.42 * inch,
        topMargin=0.45 * inch, bottomMargin=0.45 * inch,
        title="CipherScope Cryptographic Review",
        author="CipherScope / ECDAT",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CSSubtitle", parent=styles["Normal"], textColor=colors.HexColor("#64748b"),
        fontSize=8.5, leading=11, spaceAfter=8,
    ))
    styles.add(ParagraphStyle(
        name="CSCell", parent=styles["Normal"], fontName="Helvetica",
        fontSize=6.7, leading=8.4, alignment=TA_LEFT, wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="CSHeading", parent=styles["Heading2"], textColor=colors.HexColor("#0e7490"),
        fontSize=12, leading=14, spaceBefore=12, spaceAfter=6,
    ))
    story = [
        Paragraph("CipherScope", styles["Title"]),
        Paragraph("Enterprise Cryptographic Discovery &amp; Analysis · Local heuristic review", styles["CSSubtitle"]),
        Paragraph(f"<b>Scanned source:</b> {escape(source_label)}", styles["Normal"]),
        Paragraph(f"<b>Generated (UTC):</b> {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
        Spacer(1, 8),
        Paragraph("Executive summary", styles["CSHeading"]),
    ]

    counts = {
        level: sum(1 for finding in items if finding.severity.value == level)
        for level in ("critical", "high", "medium", "low", "info")
    }
    metric_data = [[
        Paragraph(f"<b>{level.title()}</b><br/>{counts[level]}", styles["Normal"])
        for level in ("critical", "high", "medium", "low", "info")
    ]]
    metric_table = Table(metric_data, colWidths=[1.3 * inch] * 5, hAlign="LEFT")
    metric_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ("INNERGRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#dbe3ed")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 9),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 9),
    ]))
    story.extend([
        metric_table, Spacer(1, 7),
        Paragraph(
            "Interpretation: detections are pattern-based review signals, not proof of exploitability. "
            "Validate each result in context; this report is not a formal compliance or post-quantum certification.",
            styles["CSSubtitle"],
        ),
        Paragraph("Findings and recommended actions", styles["CSHeading"]),
    ])

    head = ["Severity", "Finding", "Rule", "Location", "Evidence (secrets redacted)", "Suggested action"]
    table_rows = [[Paragraph(f"<b>{escape(value)}</b>", styles["CSCell"]) for value in head]]
    severity_rank = {level: rank for rank, level in enumerate(("critical", "high", "medium", "low", "info"))}
    ordered = sorted(items, key=lambda f: (severity_rank.get(f.severity.value, 9), f.file, f.line))
    report_limit = 500
    for finding in ordered[:report_limit]:
        values = [
            finding.severity.value.upper(), finding.title, finding.rule_id,
            f"{finding.file}:{finding.line}", finding.evidence, finding.remediation,
        ]
        table_rows.append([Paragraph(escape(str(value)), styles["CSCell"]) for value in values])
    widths = [0.65 * inch, 1.25 * inch, 0.85 * inch, 1.25 * inch, 2.0 * inch, 2.4 * inch]
    finding_table = Table(table_rows, colWidths=widths, repeatRows=1, hAlign="LEFT")
    finding_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b0d14")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#dbe3ed")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
    ]))
    story.append(finding_table)
    if len(ordered) > report_limit:
        story.append(Paragraph(f"Showing the first {report_limit} findings of {len(ordered)} total.", styles["CSSubtitle"]))
    if not ordered:
        story.append(Paragraph("No matching patterns were found in the scanned files.", styles["Normal"]))

    if certs:
        story.append(Paragraph("Local certificate validity", styles["CSHeading"]))
        cert_head = ["File", "Subject", "Issuer", "Expires (UTC)", "Days left", "Status"]
        cert_rows = [[Paragraph(f"<b>{escape(value)}</b>", styles["CSCell"]) for value in cert_head]]
        for cert in certs:
            values = [
                cert.get("file", ""), cert.get("subject", ""), cert.get("issuer", ""),
                cert.get("expires_at", ""), cert.get("days_to_expiry", ""), cert.get("status", ""),
            ]
            cert_rows.append([Paragraph(escape(str(value)), styles["CSCell"]) for value in values])
        certificate_table = Table(
            cert_rows,
            colWidths=[1.0 * inch, 2.1 * inch, 2.1 * inch, 1.5 * inch, 0.7 * inch, 1.0 * inch],
            repeatRows=1, hAlign="LEFT",
        )
        certificate_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b0d14")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#dbe3ed")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ]))
        story.append(certificate_table)

    story.extend([
        Spacer(1, 10),
        Paragraph(
            "Privacy: this report is generated locally. It contains file locations and matched evidence; "
            "review it before sharing. Suspected secret values are redacted in scanner evidence.",
            styles["CSSubtitle"],
        ),
    ])
    doc.build(story)
    return output.getvalue()

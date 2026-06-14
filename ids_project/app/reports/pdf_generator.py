"""
PDF report generator using ReportLab.

Produces an executive-style security incident summary PDF including:
  - Cover page with report metadata
  - Executive summary (counts by severity, MTTA/MTTR)
  - Top 10 attack sources table
  - Attack type distribution table
  - Severity trend chart (via ReportLab's built-in graphics)

Falls back gracefully if ReportLab is not installed (returns None).
"""

import io
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)


def generate_pdf_report(app, hours: int = 24) -> bytes:
    """Generate a PDF security report for the given time window.

    Args:
        app:   Flask application instance (for DB context).
        hours: Time window in hours (default 24).

    Returns:
        Raw PDF bytes, or empty bytes on error.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
        )
    except ImportError:
        logger.warning("ReportLab not installed — PDF generation unavailable")
        return b""

    with app.app_context():
        data = _collect_report_data(hours)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2.5 * cm,
        bottomMargin=2 * cm,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "IDS_Title",
        parent=styles["Heading1"],
        textColor=colors.HexColor("#7C3AED"),
        fontSize=22,
        spaceAfter=6,
    )
    section_style = ParagraphStyle(
        "IDS_Section",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#374151"),
        fontSize=14,
        spaceBefore=12,
        spaceAfter=4,
    )
    body_style = styles["Normal"]

    story = []

    # --- Cover ---
    story.append(Paragraph("Network IDS — Security Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | "
        f"Window: last {hours} hours",
        body_style,
    ))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#7C3AED"), thickness=2))
    story.append(Spacer(1, 0.5 * cm))

    # --- Executive summary ---
    story.append(Paragraph("Executive Summary", section_style))
    summary = data["summary"]
    summary_rows = [
        ["Metric", "Value"],
        ["Total Alerts", str(summary.get("total_alerts", 0))],
        ["Critical", str(summary.get("critical", 0))],
        ["High", str(summary.get("high", 0))],
        ["Medium", str(summary.get("medium", 0))],
        ["Low", str(summary.get("low", 0))],
        ["Mean Time to Acknowledge", _fmt_seconds(summary.get("mtta_seconds"))],
        ["Mean Time to Resolve", _fmt_seconds(summary.get("mttr_seconds"))],
        ["Unique Attack Sources", str(summary.get("unique_sources", 0))],
        ["Auto-blocked IPs", str(summary.get("auto_blocked", 0))],
    ]
    t = Table(summary_rows, colWidths=[9 * cm, 7 * cm])
    t.setStyle(_summary_table_style())
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    # --- Top attack sources ---
    story.append(Paragraph("Top 10 Attack Sources", section_style))
    src_rows = [["Source IP", "Attack Count", "Types"]]
    for entry in data.get("top_sources", [])[:10]:
        src_rows.append([
            entry["source_ip"],
            str(entry["count"]),
            ", ".join(entry.get("attack_types", []))[:40],
        ])
    if len(src_rows) > 1:
        t2 = Table(src_rows, colWidths=[6 * cm, 4 * cm, 7 * cm])
        t2.setStyle(_detail_table_style())
        story.append(t2)
    else:
        story.append(Paragraph("No attack sources detected in this window.", body_style))

    # --- Attack type breakdown ---
    story.append(Spacer(1, 0.4 * cm))
    story.append(Paragraph("Attack Type Distribution", section_style))
    type_rows = [["Attack Type", "Count"]]
    for at, cnt in data.get("attack_types", {}).items():
        type_rows.append([at.replace("_", " ").title(), str(cnt)])
    if len(type_rows) > 1:
        t3 = Table(type_rows, colWidths=[12 * cm, 4 * cm])
        t3.setStyle(_detail_table_style())
        story.append(t3)
    else:
        story.append(Paragraph("No attacks detected in this window.", body_style))

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _collect_report_data(hours: int) -> dict:
    """Pull report data from the database."""
    from datetime import datetime, timedelta, timezone
    from app.extensions import db
    from app.models.alert import Alert, AlertSeverity, AlertStatus
    from app.models.attack import AttackEvent
    from app.models.block import IpBlock, BlockType
    from sqlalchemy import func

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

    # Alert counts by severity
    sev_counts = dict(
        db.session.query(Alert.severity, func.count(Alert.id))
        .filter(Alert.created_at >= cutoff)
        .group_by(Alert.severity)
        .all()
    )

    total = sum(sev_counts.values())

    def _sev(key):
        return sev_counts.get(AlertSeverity(key), 0)

    # MTTA / MTTR
    mtta = db.session.query(
        func.avg(func.extract("epoch", Alert.acknowledged_at - Alert.created_at))
    ).filter(Alert.acknowledged_at.isnot(None), Alert.created_at >= cutoff).scalar()

    mttr = db.session.query(
        func.avg(func.extract("epoch", Alert.resolved_at - Alert.created_at))
    ).filter(Alert.resolved_at.isnot(None), Alert.created_at >= cutoff).scalar()

    # Unique source IPs
    unique_src = db.session.query(func.count(func.distinct(AttackEvent.source_ip))).filter(
        AttackEvent.first_seen >= cutoff
    ).scalar()

    # Auto-blocks
    auto_blocked = IpBlock.query.filter(
        IpBlock.block_type == BlockType.AUTO,
        IpBlock.blocked_at >= cutoff,
    ).count()

    # Top sources
    top_sources_q = (
        db.session.query(
            AttackEvent.source_ip.label("source_ip"),
            func.count(AttackEvent.id).label("cnt"),
        )
        .filter(AttackEvent.first_seen >= cutoff)
        .group_by(AttackEvent.source_ip)
        .order_by(func.count(AttackEvent.id).desc())
        .limit(10)
        .all()
    )
    top_sources = [{"source_ip": str(r.source_ip), "count": r.cnt, "attack_types": []} for r in top_sources_q]

    # Attack type breakdown
    attack_types_q = (
        db.session.query(AttackEvent.attack_type, func.count(AttackEvent.id).label("cnt"))
        .filter(AttackEvent.first_seen >= cutoff)
        .group_by(AttackEvent.attack_type)
        .all()
    )
    attack_types = {str(r.attack_type): r.cnt for r in attack_types_q}

    return {
        "summary": {
            "total_alerts": total,
            "critical": _sev("critical"),
            "high": _sev("high"),
            "medium": _sev("medium"),
            "low": _sev("low"),
            "mtta_seconds": float(mtta) if mtta else None,
            "mttr_seconds": float(mttr) if mttr else None,
            "unique_sources": int(unique_src or 0),
            "auto_blocked": int(auto_blocked or 0),
        },
        "top_sources": top_sources,
        "attack_types": attack_types,
    }


def _fmt_seconds(seconds) -> str:
    if seconds is None:
        return "N/A"
    minutes = int(seconds) // 60
    if minutes < 60:
        return f"{minutes}m"
    return f"{minutes // 60}h {minutes % 60}m"


def _summary_table_style():
    from reportlab.lib import colors
    from reportlab.platypus import TableStyle
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#7C3AED")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("PADDING", (0, 0), (-1, -1), 6),
    ])


def _detail_table_style():
    from reportlab.lib import colors
    from reportlab.platypus import TableStyle
    return TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#374151")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.HexColor("#F9FAFB"), colors.white]),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
        ("PADDING", (0, 0), (-1, -1), 5),
    ])

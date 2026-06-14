"""
Reports REST API.

GET  /api/v1/reports/pdf  — generate and download a PDF report
GET  /api/v1/reports/csv  — stream a CSV export of packet logs
"""

import logging

from flask import Blueprint, Response, jsonify, request, stream_with_context

logger = logging.getLogger(__name__)

reports_bp = Blueprint("reports", __name__, url_prefix="/api/v1/reports")


@reports_bp.route("/pdf", methods=["GET"])
def download_pdf():
    """GET /api/v1/reports/pdf — download security report PDF."""
    from flask import current_app
    hours = int(request.args.get("hours", 24))
    try:
        from app.reports.pdf_generator import generate_pdf_report
        pdf_bytes = generate_pdf_report(current_app._get_current_object(), hours=hours)
        if not pdf_bytes:
            return jsonify({"error": "PDF generation failed or ReportLab not installed"}), 500
    except Exception as exc:
        logger.error("PDF generation error: %s", exc)
        return jsonify({"error": str(exc)}), 500

    filename = f"ids_report_{hours}h.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@reports_bp.route("/csv", methods=["GET"])
def download_csv():
    """GET /api/v1/reports/csv — stream CSV packet export."""
    from datetime import datetime

    args = request.args
    start_time = None
    end_time = None
    if args.get("start"):
        try:
            start_time = datetime.fromisoformat(args["start"])
        except ValueError:
            return jsonify({"error": "Invalid start datetime"}), 400
    if args.get("end"):
        try:
            end_time = datetime.fromisoformat(args["end"])
        except ValueError:
            return jsonify({"error": "Invalid end datetime"}), 400

    from app.reports.csv_exporter import stream_packets_csv

    gen = stream_with_context(stream_packets_csv(
        src_ip=args.get("src_ip"),
        dst_ip=args.get("dst_ip"),
        protocol=args.get("protocol"),
        start_time=start_time,
        end_time=end_time,
        max_rows=int(args.get("max_rows", 1_000_000)),
    ))

    return Response(
        gen,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=packets.csv"},
    )

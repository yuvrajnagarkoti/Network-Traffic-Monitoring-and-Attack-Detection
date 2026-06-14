"""
Dashboard web page routes.

Renders HTML views for the security operations console.
All routes require Flask-Login authentication.
"""

import logging

from flask import Blueprint, redirect, render_template, url_for
from flask_login import current_user, login_required

logger = logging.getLogger(__name__)

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/")


@dashboard_bp.route("/")
@login_required
def index():
    """Root redirect to dashboard."""
    return redirect(url_for("dashboard.overview"))


@dashboard_bp.route("/dashboard")
@login_required
def overview():
    """Main live traffic dashboard."""
    return render_template("dashboard.html", user=current_user)


@dashboard_bp.route("/alerts")
@login_required
def alerts():
    """Alert center page."""
    return render_template("alerts.html", user=current_user)


@dashboard_bp.route("/search")
@login_required
def search():
    """Packet search page."""
    return render_template("search.html", user=current_user)


@dashboard_bp.route("/investigation")
@login_required
def investigation():
    """Investigation tools page."""
    return render_template("investigation.html", user=current_user)


@dashboard_bp.route("/reports")
@login_required
def reports():
    """Reports download page."""
    return render_template("reports.html", user=current_user)


@dashboard_bp.route("/settings")
@login_required
def settings():
    """System settings and administration page."""
    return render_template("settings.html", user=current_user)

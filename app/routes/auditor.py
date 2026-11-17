"""Auditor panel: read-only, filterable view of security audit events.

Only GET is routed here, so the Auditor has no state-changing capability, and
no route in this blueprint touches document contents.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from flask import Blueprint, current_app, render_template, request

from ..extensions import db
from ..forms import AuditFilterForm
from ..models import AuditEvent
from ..security.audit import Action, Result
from ..security.rbac import Permission, permission_required

bp = Blueprint("auditor", __name__, url_prefix="/audit")


def _parse_date(value: str | None):
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return None


@bp.route("/", methods=["GET"])
@permission_required(Permission.VIEW_AUDIT_LOG)
def logs():
    form = AuditFilterForm(request.args)
    form.action.choices = [("", "Any action")] + [(a, a) for a in Action.all()]
    form.result.choices = [("", "Any result")] + [(r, r) for r in Result.all()]

    query = db.select(AuditEvent)
    # Allow-list filters: action/result must be known values.
    if form.action.data in Action.all():
        query = query.filter(AuditEvent.action == form.action.data)
    if form.result.data in Result.all():
        query = query.filter(AuditEvent.result == form.result.data)
    username = (form.username.data or "").strip().lower()[:64]
    if username:
        # Bound parameter; LIKE wildcards in user input are escaped.
        escaped = username.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        query = query.filter(AuditEvent.username.like(f"%{escaped}%", escape="\\"))
    start = _parse_date(form.date_from.data)
    end = _parse_date(form.date_to.data)
    if start:
        query = query.filter(AuditEvent.timestamp >= start)
    if end:
        query = query.filter(AuditEvent.timestamp < end + timedelta(days=1))

    page = request.args.get("page", 1, type=int)
    page = max(1, min(page or 1, 10_000))
    pagination = db.paginate(query.order_by(AuditEvent.timestamp.desc(), AuditEvent.id.desc()),
                             page=page, per_page=current_app.config["AUDIT_PAGE_SIZE"],
                             error_out=False)

    filter_args = {k: v for k, v in request.args.items() if k != "page" and v}
    return render_template("auditor/logs.html", form=form, pagination=pagination,
                           events=pagination.items, filter_args=filter_args)

"""Staff document management: upload, list, download, verify, delete.

Every query is scoped by ``owner_id == current_user.id``. Requests for a file
that does not exist *or* belongs to another user both return 404 (so IDs
cannot be enumerated) and the latter is recorded as an access denial.
"""
from __future__ import annotations

import io

from flask import (Blueprint, abort, current_app, flash, redirect, render_template, request,
                   send_file, url_for)
from flask_login import current_user

from ..extensions import db
from ..forms import ActionForm, UploadForm
from ..models import StoredFile
from ..security.audit import Action, Result, log_event
from ..security.crypto import IntegrityError
from ..security.rbac import Permission, permission_required
from ..security.validation import ALLOWED_TYPES, ValidationError, validate_upload
from ..services import storage

bp = Blueprint("files", __name__, url_prefix="/files")


def _get_owned_file_or_404(file_id: int) -> StoredFile:
    record = db.session.get(StoredFile, file_id)
    if record is None:
        abort(404)
    if record.owner_id != current_user.id:
        log_event(Action.ACCESS_DENIED, Result.DENIED, file_id=file_id,
                  details=f"IDOR attempt: {request.method} {request.path} on file owned by another user")
        abort(404)
    return record


@bp.route("/", methods=["GET"])
@permission_required(Permission.MANAGE_OWN_FILES)
def index():
    records = db.session.execute(
        db.select(StoredFile).filter_by(owner_id=current_user.id).order_by(StoredFile.created_at.desc())
    ).scalars().all()

    # Live integrity check so tampering is visible immediately in the GUI.
    for record in records:
        previous = record.integrity_status
        ok, reason = storage.verify(record)
        if not ok and previous != record.integrity_status:
            log_event(Action.INTEGRITY_FAILURE, Result.FAILURE, file_id=record.id,
                      details=f"detected during listing: {reason}")

    allowed = ", ".join(sorted({e.upper() for e in ALLOWED_TYPES} - {"JPEG"}))
    return render_template("files/index.html", files=records, upload_form=UploadForm(),
                           action_form=ActionForm(), allowed=allowed,
                           max_mb=current_app.config["MAX_UPLOAD_BYTES"] // (1024 * 1024))


@bp.route("/upload", methods=["POST"])
@permission_required(Permission.MANAGE_OWN_FILES)
def upload():
    form = UploadForm()
    if not form.validate_on_submit():
        log_event(Action.UPLOAD_REJECTED, Result.FAILURE, details="no file supplied")
        flash("Please choose a file to upload.", "danger")
        return redirect(url_for("files.index"))

    file_storage = form.file.data
    max_bytes = current_app.config["MAX_UPLOAD_BYTES"]
    # Read at most max_bytes + 1 so oversize files are detected without
    # buffering arbitrarily large bodies.
    data = file_storage.stream.read(max_bytes + 1)
    try:
        validated = validate_upload(file_storage.filename, data, max_bytes)
    except ValidationError as exc:
        log_event(Action.UPLOAD_REJECTED, Result.FAILURE, details=str(exc))
        flash(str(exc), "danger")
        return redirect(url_for("files.index"))

    record = storage.save_encrypted(current_user.id, validated)
    log_event(Action.UPLOAD, Result.SUCCESS, file_id=record.id,
              details=f"{record.extension} {record.size_bytes} bytes")
    flash(f"'{record.original_name}' was encrypted and stored.", "success")
    return redirect(url_for("files.index"))


@bp.route("/<int:file_id>/download", methods=["GET"])
@permission_required(Permission.MANAGE_OWN_FILES)
def download(file_id: int):
    record = _get_owned_file_or_404(file_id)
    try:
        plaintext = storage.read_and_verify(record)
    except IntegrityError as exc:
        storage.verify(record)  # persist FAILED status
        log_event(Action.INTEGRITY_FAILURE, Result.FAILURE, file_id=record.id,
                  details=f"download blocked: {exc.reason}")
        flash(f"Integrity check failed for '{record.original_name}'. "
              "The download was blocked and the event has been logged.", "danger")
        return redirect(url_for("files.index")), 303

    log_event(Action.DOWNLOAD, Result.SUCCESS, file_id=record.id)
    response = send_file(
        io.BytesIO(plaintext),
        mimetype=record.mime_type,
        as_attachment=True,  # never render user content inline
        download_name=record.original_name,
        max_age=0,
    )
    response.headers["Cache-Control"] = "no-store"
    return response


@bp.route("/<int:file_id>/verify", methods=["POST"])
@permission_required(Permission.MANAGE_OWN_FILES)
def verify(file_id: int):
    ActionForm().validate_on_submit()  # CSRF enforced globally by CSRFProtect
    record = _get_owned_file_or_404(file_id)
    ok, reason = storage.verify(record)
    if ok:
        flash(f"'{record.original_name}' verified: AES-GCM tag and SHA-256 digest match.", "success")
    else:
        log_event(Action.INTEGRITY_FAILURE, Result.FAILURE, file_id=record.id,
                  details=f"manual verification: {reason}")
        flash(f"Integrity check FAILED for '{record.original_name}'.", "danger")
    return redirect(url_for("files.index"))


@bp.route("/<int:file_id>/delete", methods=["POST"])
@permission_required(Permission.MANAGE_OWN_FILES)
def delete(file_id: int):
    record = _get_owned_file_or_404(file_id)
    name, fid = record.original_name, record.id
    storage.delete(record)
    log_event(Action.DELETE, Result.SUCCESS, file_id=fid)
    flash(f"'{name}' was deleted.", "success")
    return redirect(url_for("files.index"))

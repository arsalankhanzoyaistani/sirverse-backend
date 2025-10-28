# backend/routes/note_routes.py
import os
from flask import Blueprint, request, jsonify, current_app
from config.database import db
from backend.utils.cloudinary_helper import upload_file_to_cloudinary  # adjust path if needed
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.utils import secure_filename

note_bp = Blueprint("note_bp", __name__, url_prefix="/api/tools/notes")

ALLOWED_EXTENSIONS = {"pdf", "docx", "doc", "txt", "png", "jpg", "jpeg"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@note_bp.route("/", methods=["POST"])
@jwt_required()
def create_note():
    # Lazy imports to avoid circular import with app.py
    from app import User, Note

    user_id = get_jwt_identity()
    if "file" not in request.files:
        return jsonify({"error": "file is required"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "no selected file"}), 400
    if not allowed_file(file.filename):
        return jsonify({"error": "file type not allowed"}), 400

    title = request.form.get("title", "").strip()
    if not title:
        return jsonify({"error": "title is required"}), 400

    description = request.form.get("description", "")
    public = request.form.get("public", "false").lower() in ("true", "1", "yes")

    filename = secure_filename(file.filename)
    try:
        upload_result = upload_file_to_cloudinary(file, folder="sirverse/notes")
        file_url = upload_result.get("secure_url") or upload_result.get("url")
    except Exception as e:
        current_app.logger.exception("Cloudinary upload failed")
        return jsonify({"error": "failed to upload file", "details": str(e)}), 500

    file_type = filename.rsplit(".", 1)[1].lower()

    note = Note(
        title=title,
        description=description,
        file_url=file_url,
        file_type=file_type,
        public=public,
        user_id=user_id
    )

    db.session.add(note)
    db.session.commit()

    return jsonify({"message": "note uploaded", "note": {
        "id": str(note.id),
        "title": note.title,
        "description": note.description,
        "file_url": note.file_url,
        "file_type": note.file_type,
        "public": note.public,
        "user_id": note.user_id,
        "created_at": note.created_at.isoformat()
    }}), 201

@note_bp.route("/", methods=["GET"])
@jwt_required(optional=True)
def list_notes():
    from app import Note
    q = request.args.get("q", None)
    public_only = request.args.get("public", None)
    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 20))

    query = Note.query
    if public_only and public_only.lower() in ("true", "1", "yes"):
        query = query.filter_by(public=True)

    if q:
        q_like = f"%{q}%"
        query = query.filter((Note.title.ilike(q_like)) | (Note.description.ilike(q_like)))

    query = query.order_by(Note.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)

    items = [{
        "id": getattr(n, "id", None),
        "title": getattr(n, "title", None),
        "description": getattr(n, "description", None),
        "file_url": getattr(n, "file_url", None),
        "file_type": getattr(n, "file_type", None),
        "public": getattr(n, "public", None),
        "user_id": getattr(n, "user_id", None),
        "created_at": n.created_at.isoformat() if n.created_at else None
    } for n in pagination.items]

    return jsonify({
        "items": items,
        "page": pagination.page,
        "per_page": pagination.per_page,
        "total": pagination.total,
        "pages": pagination.pages
    }), 200

@note_bp.route("/<note_id>", methods=["GET"])
@jwt_required(optional=True)
def get_note(note_id):
    from app import Note
    note = Note.query.get(note_id)
    if not note:
        return jsonify({"error": "note not found"}), 404

    if not note.public:
        current = get_jwt_identity()
        if not current or str(current) != str(note.user_id):
            return jsonify({"error": "forbidden"}), 403

    return jsonify({
        "id": str(note.id),
        "title": note.title,
        "description": note.description,
        "file_url": note.file_url,
        "file_type": note.file_type,
        "public": note.public,
        "user_id": note.user_id,
        "created_at": note.created_at.isoformat()
    }), 200

@note_bp.route("/<note_id>", methods=["DELETE"])
@jwt_required()
def delete_note(note_id):
    from app import Note
    current = get_jwt_identity()
    note = Note.query.get(note_id)
    if not note:
        return jsonify({"error": "note not found"}), 404

    if str(note.user_id) != str(current):
        return jsonify({"error": "forbidden"}), 403

    try:
        from backend.utils.cloudinary_helper import delete_file_by_url
        delete_file_by_url(note.file_url)
    except Exception:
        current_app.logger.warning("Could not delete remote asset (continuing)")

    db.session.delete(note)
    db.session.commit()

    return jsonify({"message": "note deleted"}), 200

# backend/models/note.py
from datetime import datetime
from backend.extensions import db  # adjust import to match your project (or from app import db)
from sqlalchemy.dialects.postgresql import UUID
import uuid

class Note(db.Model):
    __tablename__ = "notes"

    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    file_url = db.Column(db.String(1024), nullable=False)
    file_type = db.Column(db.String(50), nullable=False)
    public = db.Column(db.Boolean, default=False, nullable=False)
    user_id = db.Column(db.ForeignKey("users.id"), nullable=False)  # adjust if users table name is different
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # relationship (optional)
    user = db.relationship("User", back_populates="notes")  # ensure User model defines notes relationship

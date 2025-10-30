from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from models import User, Post, Reel, Comment, Report

report_bp = Blueprint('reports', __name__)

@report_bp.route('/api/reports', methods=['POST'])
@jwt_required()
def create_report():
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    
    report = Report(
        reporter_id=uid,
        content_type=data.get('content_type'),  # 'post', 'reel', 'comment', 'user'
        content_id=data.get('content_id'),
        reason=data.get('reason'),
        description=data.get('description', '')
    )
    
    db.session.add(report)
    db.session.commit()
    
    return jsonify({"message": "Report submitted successfully"}), 201

@report_bp.route('/api/reports', methods=['GET'])
@jwt_required()
def get_reports():
    # Admin only - implement admin check
    reports = Report.query.order_by(Report.created_at.desc()).all()
    return jsonify({
        "reports": [{
            "id": r.id,
            "reporter": r.reporter.username,
            "content_type": r.content_type,
            "content_id": r.content_id,
            "reason": r.reason,
            "status": r.status,
            "created_at": r.created_at.isoformat()
        } for r in reports]
    }), 200

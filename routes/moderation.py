from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

moderation_bp = Blueprint('moderation', __name__)

# -------------------- BLOCK ENDPOINTS --------------------

@moderation_bp.route('/api/blocks/<int:user_id>', methods=['POST'])
@jwt_required()
def block_user(user_id):
    from app import db  # ✅ Import INSIDE function to avoid circular imports
    from models import User, Block
    
    uid = int(get_jwt_identity())
    
    if uid == user_id:
        return jsonify({"error": "Cannot block yourself"}), 400
    
    # Check if already blocked
    existing = Block.query.filter_by(blocker_id=uid, blocked_id=user_id).first()
    if existing:
        return jsonify({"error": "User already blocked"}), 400
    
    # Check if user exists
    user_to_block = User.query.get(user_id)
    if not user_to_block:
        return jsonify({"error": "User not found"}), 404
    
    block = Block(blocker_id=uid, blocked_id=user_id)
    db.session.add(block)
    db.session.commit()
    
    return jsonify({"message": "User blocked successfully"}), 201

@moderation_bp.route('/api/blocks/<int:user_id>', methods=['DELETE'])
@jwt_required()
def unblock_user(user_id):
    from app import db  # ✅ Import INSIDE function
    from models import Block
    
    uid = int(get_jwt_identity())
    
    block = Block.query.filter_by(blocker_id=uid, blocked_id=user_id).first()
    if not block:
        return jsonify({"error": "User not blocked"}), 404
    
    db.session.delete(block)
    db.session.commit()
    
    return jsonify({"message": "User unblocked successfully"}), 200

@moderation_bp.route('/api/blocks', methods=['GET'])
@jwt_required()
def get_blocked_users():
    from app import db  # ✅ Import INSIDE function
    from models import User, Block
    
    uid = int(get_jwt_identity())
    blocks = Block.query.filter_by(blocker_id=uid).all()
    
    blocked_users = []
    for block in blocks:
        user = User.query.get(block.blocked_id)
        if user:
            blocked_users.append({
                "id": user.id,
                "username": user.username,
                "avatar": user.avatar,
                "blocked_at": block.created_at.isoformat()
            })
    
    return jsonify({"blocked_users": blocked_users}), 200

# -------------------- FOLLOW ENDPOINTS --------------------

@moderation_bp.route('/api/follow/<int:user_id>', methods=['POST'])
@jwt_required()
def follow_user(user_id):
    from app import db  # ✅ Import INSIDE function
    from models import User, Follow
    
    uid = int(get_jwt_identity())
    
    if uid == user_id:
        return jsonify({"error": "Cannot follow yourself"}), 400
    
    # Check if already following
    existing = Follow.query.filter_by(follower_id=uid, following_id=user_id).first()
    if existing:
        return jsonify({"error": "Already following this user"}), 400
    
    # Check if user exists
    user_to_follow = User.query.get(user_id)
    if not user_to_follow:
        return jsonify({"error": "User not found"}), 404
    
    follow = Follow(follower_id=uid, following_id=user_id)
    db.session.add(follow)
    db.session.commit()
    
    return jsonify({"message": "User followed successfully"}), 201

@moderation_bp.route('/api/follow/<int:user_id>', methods=['DELETE'])
@jwt_required()
def unfollow_user(user_id):
    from app import db  # ✅ Import INSIDE function
    from models import Follow
    
    uid = int(get_jwt_identity())
    
    follow = Follow.query.filter_by(follower_id=uid, following_id=user_id).first()
    if not follow:
        return jsonify({"error": "Not following this user"}), 404
    
    db.session.delete(follow)
    db.session.commit()
    
    return jsonify({"message": "User unfollowed successfully"}), 200

@moderation_bp.route('/api/follow/status/<int:user_id>', methods=['GET'])
@jwt_required()
def get_follow_status(user_id):
    from app import db  # ✅ Import INSIDE function
    from models import Follow
    
    uid = int(get_jwt_identity())
    
    is_following = Follow.query.filter_by(follower_id=uid, following_id=user_id).first() is not None
    
    return jsonify({"is_following": is_following}), 200

@moderation_bp.route('/api/follow/stats/<string:username>', methods=['GET'])
def get_follow_stats(username):
    from app import db  # ✅ Import INSIDE function
    from models import User, Follow
    
    user = User.query.filter_by(username=username).first_or_404()
    
    followers_count = Follow.query.filter_by(following_id=user.id).count()
    following_count = Follow.query.filter_by(follower_id=user.id).count()
    
    return jsonify({
        "followers_count": followers_count,
        "following_count": following_count
    }), 200

# -------------------- REPORT ENDPOINTS --------------------

@moderation_bp.route('/api/reports', methods=['POST'])
@jwt_required()
def create_report():
    from app import db  # ✅ Import INSIDE function
    from models import Report
    
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    
    # Validate required fields
    if not data.get('content_type') or not data.get('content_id') or not data.get('reason'):
        return jsonify({"error": "content_type, content_id, and reason are required"}), 400
    
    # Validate content_type
    valid_content_types = ['post', 'reel', 'comment', 'user']
    if data.get('content_type') not in valid_content_types:
        return jsonify({"error": f"content_type must be one of: {', '.join(valid_content_types)}"}), 400
    
    report = Report(
        reporter_id=uid,
        content_type=data.get('content_type'),
        content_id=data.get('content_id'),
        reason=data.get('reason'),
        description=data.get('description', ''),
        status='pending'
    )
    
    db.session.add(report)
    db.session.commit()
    
    return jsonify({"message": "Report submitted successfully"}), 201

@moderation_bp.route('/api/reports', methods=['GET'])
@jwt_required()
def get_reports():
    from app import db  # ✅ Import INSIDE function
    from models import User, Report, Post, Reel, Comment
    
    uid = int(get_jwt_identity())
    current_user = User.query.get(uid)
    
    # Simple admin check - you might want to add an 'is_admin' field to User model
    if current_user.username not in ['admin', 'moderator']:  # Adjust as needed
        return jsonify({"error": "Admin access required"}), 403
    
    reports = Report.query.order_by(Report.created_at.desc()).all()
    
    reports_data = []
    for report in reports:
        reporter = User.query.get(report.reporter_id)
        
        # Get content author based on content_type
        content_author = None
        if report.content_type == 'user':
            content_author = User.query.get(report.content_id)
        elif report.content_type == 'post':
            post = Post.query.get(report.content_id)
            content_author = post.user if post else None
        elif report.content_type == 'reel':
            reel = Reel.query.get(report.content_id)
            content_author = reel.user if reel else None
        elif report.content_type == 'comment':
            comment = Comment.query.get(report.content_id)
            content_author = comment.user if comment else None
        
        reports_data.append({
            "id": report.id,
            "reporter": {
                "id": reporter.id,
                "username": reporter.username
            },
            "content_type": report.content_type,
            "content_id": report.content_id,
            "content_author": {
                "id": content_author.id,
                "username": content_author.username
            } if content_author else None,
            "reason": report.reason,
            "description": report.description,
            "status": report.status,
            "created_at": report.created_at.isoformat()
        })
    
    return jsonify({"reports": reports_data}), 200

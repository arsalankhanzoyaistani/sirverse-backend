from flask import Blueprint, request, jsonify

legal_bp = Blueprint('legal', __name__)

# -------------------- TERMS OF SERVICE --------------------

@legal_bp.route('/api/legal/terms', methods=['GET'])
def get_terms():
    from app import db  # ✅ Import INSIDE function
    from models import TermsOfService
    
    terms = TermsOfService.query.filter_by(active=True).first()
    if not terms:
        return jsonify({"error": "No active terms of service found"}), 404
    
    return jsonify({
        "terms": {
            "id": terms.id,
            "version": terms.version,
            "content": terms.content,
            "created_at": terms.created_at.isoformat()
        }
    }), 200

@legal_bp.route('/api/legal/terms', methods=['POST'])
def create_terms():
    from app import db  # ✅ Import INSIDE function
    from models import TermsOfService
    
    data = request.get_json() or {}
    
    if not data.get('content') or not data.get('version'):
        return jsonify({"error": "content and version are required"}), 400
    
    # Deactivate all previous terms
    TermsOfService.query.update({'active': False})
    
    terms = TermsOfService(
        version=data.get('version'),
        content=data.get('content'),
        active=True
    )
    
    db.session.add(terms)
    db.session.commit()
    
    return jsonify({"message": "Terms of service created successfully"}), 201

# -------------------- PRIVACY POLICY --------------------

@legal_bp.route('/api/legal/privacy', methods=['GET'])
def get_privacy_policy():
    from app import db  # ✅ Import INSIDE function
    from models import PrivacyPolicy
    
    policy = PrivacyPolicy.query.filter_by(active=True).first()
    if not policy:
        return jsonify({"error": "No active privacy policy found"}), 404
    
    return jsonify({
        "privacy_policy": {
            "id": policy.id,
            "version": policy.version,
            "content": policy.content,
            "created_at": policy.created_at.isoformat()
        }
    }), 200

@legal_bp.route('/api/legal/privacy', methods=['POST'])
def create_privacy_policy():
    from app import db  # ✅ Import INSIDE function
    from models import PrivacyPolicy
    
    data = request.get_json() or {}
    
    if not data.get('content') or not data.get('version'):
        return jsonify({"error": "content and version are required"}), 400
    
    # Deactivate all previous policies
    PrivacyPolicy.query.update({'active': False})
    
    policy = PrivacyPolicy(
        version=data.get('version'),
        content=data.get('content'),
        active=True
    )
    
    db.session.add(policy)
    db.session.commit()
    
    return jsonify({"message": "Privacy policy created successfully"}), 201

# -------------------- LEGAL ACCEPTANCE --------------------

@legal_bp.route('/api/legal/accept', methods=['POST'])
def accept_legal():
    # This endpoint can be used to track user acceptance
    # You might want to add a field to User model for this
    data = request.get_json() or {}
    
    # For now, just return success
    return jsonify({"message": "Legal terms accepted"}), 200

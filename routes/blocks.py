from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app import db
from models import User, Block

block_bp = Blueprint('blocks', __name__)

@block_bp.route('/api/blocks/<int:user_id>', methods=['POST'])
@jwt_required()
def block_user(user_id):
    uid = int(get_jwt_identity())
    
    if uid == user_id:
        return jsonify({"error": "Cannot block yourself"}), 400
    
    existing = Block.query.filter_by(blocker_id=uid, blocked_id=user_id).first()
    if existing:
        return jsonify({"error": "User already blocked"}), 400
    
    block = Block(blocker_id=uid, blocked_id=user_id)
    db.session.add(block)
    db.session.commit()
    
    return jsonify({"message": "User blocked successfully"}), 201

@block_bp.route('/api/blocks/<int:user_id>', methods=['DELETE'])
@jwt_required()
def unblock_user(user_id):
    uid = int(get_jwt_identity())
    
    block = Block.query.filter_by(blocker_id=uid, blocked_id=user_id).first()
    if not block:
        return jsonify({"error": "User not blocked"}), 404
    
    db.session.delete(block)
    db.session.commit()
    
    return jsonify({"message": "User unblocked successfully"}), 200

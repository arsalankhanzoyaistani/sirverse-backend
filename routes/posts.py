# 🧩 START: Edit & Delete Post Feature

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, Post

# ✏️ Edit a post
@app.route("/posts/<int:post_id>/edit", methods=["PUT"])
@jwt_required()
def edit_post(post_id):
    try:
        current_user = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # 🛡️ Ensure only owner can edit
        if post.user_id != current_user:
            return jsonify({"error": "Unauthorized"}), 403

        data = request.get_json()
        post.caption = data.get("caption", post.caption)
        post.image_url = data.get("image_url", post.image_url)

        db.session.commit()
        return jsonify({"message": "Post updated successfully!"}), 200

    except Exception as e:
        print("Edit error:", e)
        return jsonify({"error": str(e)}), 500


# 🗑️ Delete a post
@app.route("/posts/<int:post_id>/delete", methods=["DELETE"])
@jwt_required()
def delete_post(post_id):
    try:
        current_user = get_jwt_identity()
        post = Post.query.get_or_404(post_id)

        # 🛡️ Ensure only owner can delete
        if post.user_id != current_user:
            return jsonify({"error": "Unauthorized"}), 403

        db.session.delete(post)
        db.session.commit()
        return jsonify({"message": "Post deleted successfully!"}), 200

    except Exception as e:
        print("Delete error:", e)
        return jsonify({"error": str(e)}), 500

# 🧩 END: Edit & Delete Post Feature

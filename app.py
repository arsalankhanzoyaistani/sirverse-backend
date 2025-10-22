import os
import bcrypt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity
)
from flask_migrate import Migrate
from dotenv import load_dotenv
from sqlalchemy import desc
from config.database import init_db, db
from pytz import timezone
import cloudinary.uploader

# ------------------------------------------------
# Load env & configure app
# ------------------------------------------------
load_dotenv()
app = Flask(__name__)

cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "change-this"),
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "jwt-change-this"),
    SQLALCHEMY_DATABASE_URI=os.getenv(
        "DATABASE_URL",
        "postgresql+psycopg2://sirverse_user:sirverse123@localhost:5432/sirverse_gpt_db"
    ),
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

init_db(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

print("🚀 SirVerse GPT backend starting...")

# ------------------------------------------------
# Models
# ------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(100))
    avatar = db.Column(db.String(200), default="👤")
    bio = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    posts = db.relationship("Post", backref="user", lazy=True)

    def set_password(self, pw):
        self.password_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    def check_password(self, pw):
        return bcrypt.checkpw(pw.encode(), self.password_hash.encode())


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship("Comment", backref="post", cascade="all,delete-orphan", lazy=True)
    likes = db.relationship("Like", backref="post", cascade="all,delete-orphan", lazy=True)


class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", lazy=True)


class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "post_id", name="_user_post_unique"),)


# ------------------------------------------------
# Helpers
# ------------------------------------------------
PK_TZ = timezone("Asia/Karachi")
def to_pk_time(dt):
    return dt.astimezone(PK_TZ).strftime("%Y-%m-%d %I:%M:%S %p") if dt else None

def post_dict(p):
    return {
        "id": p.id,
        "content": p.content,
        "image_url": p.image_url,
        "author": {"id": p.user.id, "username": p.user.username, "avatar": p.user.avatar},
        "likes_count": len(p.likes),
        "comments_count": len(p.comments),
        "created_at": p.created_at.isoformat(),
        "created_at_pk": to_pk_time(p.created_at)
    }

def comment_dict(c):
    return {
        "id": c.id,
        "post_id": c.post_id,
        "user": {"id": c.user_id, "username": c.user.username},
        "content": c.content,
        "created_at": c.created_at.isoformat(),
        "created_at_pk": to_pk_time(c.created_at)
    }

# ------------------------------------------------
# Auth
# ------------------------------------------------
@app.route("/api/auth/register", methods=["POST"])
def register():
    data = request.get_json() or {}
    if not data.get("username") or not data.get("email") or not data.get("password"):
        return jsonify({"error": "Missing required fields"}), 400
    if User.query.filter((User.username == data["username"]) | (User.email == data["email"])).first():
        return jsonify({"error": "User already exists"}), 409

    user = User(username=data["username"], email=data["email"])
    user.set_password(data["password"])
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
    return jsonify({"access_token": token, "user": {"id": user.id, "username": user.username}}), 201


@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.get_json() or {}
    email, username, pw = data.get("email"), data.get("username"), data.get("password")
    if not pw or (not email and not username):
        return jsonify({"error": "Missing credentials"}), 400
    user = User.query.filter((User.email == email) | (User.username == username)).first()
    if not user or not user.check_password(pw):
        return jsonify({"error": "Invalid credentials"}), 401
    token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
    return jsonify({"access_token": token, "user": {"id": user.id, "username": user.username}}), 200


# ------------------------------------------------
# Posts + Upload
# ------------------------------------------------
@app.route("/api/posts", methods=["GET"])
@jwt_required(optional=True)
def get_posts():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    posts = Post.query.order_by(desc(Post.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({
        "items": [post_dict(p) for p in posts.items],
        "page": page, "pages": posts.pages, "total": posts.total
    }), 200


@app.route("/api/posts", methods=["POST"])
@jwt_required()
def create_post():
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    if not data.get("content") and not data.get("image_url"):
        return jsonify({"error": "Content required"}), 400
    p = Post(content=data["content"], image_url=data.get("image_url"), user_id=uid)
    db.session.add(p)
    db.session.commit()
    return jsonify({"message": "Post created", "post": post_dict(p)}), 201


@app.route("/api/posts/<int:pid>", methods=["DELETE"])
@jwt_required()
def delete_post(pid):
    uid = int(get_jwt_identity())
    post = Post.query.get_or_404(pid)
    if post.user_id != uid:
        return jsonify({"error": "Unauthorized"}), 403
    if post.image_url:
        try:
            pub = post.image_url.split("upload/")[1].split(".")[0]
            cloudinary.uploader.destroy(pub)
        except Exception as e:
            print("Cloudinary delete failed:", e)
    db.session.delete(post)
    db.session.commit()
    return jsonify({"message": "Post deleted"}), 200

# backward-compatibility
@app.route("/api/posts/<int:pid>/delete", methods=["DELETE"])
@jwt_required()
def delete_post_old(pid):
    return delete_post(pid)


@app.route("/api/upload", methods=["POST"])
@jwt_required()
def upload_file():
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["file"]
    up = cloudinary.uploader.upload(f, folder="sirverse_uploads")
    return jsonify({"url": up["secure_url"], "public_id": up["public_id"]}), 201


# ------------------------------------------------
# Comments + Likes + Profiles
# ------------------------------------------------
@app.route("/api/posts/<int:pid>/comments", methods=["GET"])
def get_comments(pid):
    post = Post.query.get_or_404(pid)
    cmts = Comment.query.filter_by(post_id=post.id).order_by(Comment.created_at.asc()).all()
    return jsonify({"comments": [comment_dict(c) for c in cmts]}), 200


@app.route("/api/posts/<int:pid>/comments", methods=["POST"])
@jwt_required()
def add_comment(pid):
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    if not data.get("content"):
        return jsonify({"error": "Content required"}), 400
    c = Comment(post_id=pid, user_id=uid, content=data["content"])
    db.session.add(c)
    db.session.commit()
    return jsonify({"message": "Comment added", "comment": comment_dict(c)}), 201


@app.route("/api/posts/<int:pid>/like", methods=["POST"])
@jwt_required()
def toggle_like(pid):
    uid = int(get_jwt_identity())
    post = Post.query.get_or_404(pid)
    existing = Like.query.filter_by(post_id=pid, user_id=uid).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        liked = False
    else:
        db.session.add(Like(post_id=pid, user_id=uid))
        db.session.commit()
        liked = True
    count = Like.query.filter_by(post_id=pid).count()
    return jsonify({"liked": liked, "likes_count": count}), 200


@app.route("/api/users/<string:username>", methods=["GET"])
def get_profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(desc(Post.created_at)).all()
    return jsonify({
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "avatar": user.avatar,
            "bio": user.bio,
            "created_at": user.created_at.isoformat(),
            "created_at_pk": to_pk_time(user.created_at),
            "total_posts": len(posts)
        },
        "posts": [post_dict(p) for p in posts]
    }), 200


@app.route("/ping")
def ping():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()}), 200


if __name__ == "__main__":
    print("✅ Ready: Auth, Posts, Upload, Comments, Likes, Profile")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)

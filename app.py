# backend/app.py
import os, sys, random, hashlib
from datetime import datetime, timedelta
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import (
    JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
)
from flask_migrate import Migrate
from sqlalchemy import desc
from pytz import timezone, UTC
from flask_socketio import SocketIO, emit, join_room, leave_room
import cloudinary
import cloudinary.uploader

load_dotenv()

app = Flask(__name__)
CORS(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# (then rest of your backend code)



# (rest of your app.py continues below...)

# ------------------------------------------------
# load .env from project root reliably
load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

# ------------------------------------------------
# App + config
# ------------------------------------------------
app = Flask(__name__)

# fix DATABASE_URL prefix if needed (Railway etc.)
db_url = os.getenv("DATABASE_URL")
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql+psycopg2://", 1)
elif db_url and db_url.startswith("postgresql://"):
    db_url = db_url.replace("postgresql://", "postgresql+psycopg2://", 1)

app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "change-this"),
    JWT_SECRET_KEY=os.getenv("JWT_SECRET_KEY", "jwt-change-this"),
    SQLALCHEMY_DATABASE_URI=db_url or "postgresql+psycopg2://sirverse_user:sirverse123@localhost:5432/sirverse_gpt_db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False
)

# Cloudinary config
cloudinary.config(
    cloud_name=os.getenv("CLOUDINARY_CLOUD_NAME"),
    api_key=os.getenv("CLOUDINARY_API_KEY"),
    api_secret=os.getenv("CLOUDINARY_API_SECRET"),
    secure=True,
)

# Import DB init after app config (your config.database file)
from config.database import init_db, db
init_db(app)                  # sets up db = SQLAlchemy(app) inside your config
migrate = Migrate(app, db)
jwt = JWTManager(app)
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)
# --- SocketIO setup ---
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")
connected_users = {}  # sid -> user_id mapping for online tracking
# -----------------------


print("🚀 SirVerse GPT backend starting...")

# ------------------------------------------------
# OTP config helpers
# ------------------------------------------------
OTP_LENGTH = 6
OTP_EXP_MINUTES = 3
OTP_MAX_ATTEMPTS = 5
DEV_MODE = True  # set False in production

def hash_otp(otp: str) -> str:
    return hashlib.sha256(otp.encode()).hexdigest()

def generate_otp() -> str:
    return f"{random.randint(0, 10**OTP_LENGTH - 1):0{OTP_LENGTH}d}"

def send_sms_via_provider(phone: str, message: str) -> bool:
    # placeholder: implement Twilio/JazzCash later
    try:
        print(f"📲 SMS SEND (placeholder) -> {phone}: {message}")
        return True
    except Exception as e:
        print("SMS send error:", e)
        return False

# ------------------------------------------------
# Models
# (kept simple and matching your previous structure)
# ------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    phone = db.Column(db.String(20), unique=True, nullable=False)
    full_name = db.Column(db.String(100))
    avatar = db.Column(db.String(200), default="👤")
    bio = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    otp_hash = db.Column(db.String(128), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    otp_attempts = db.Column(db.Integer, default=0)


class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    image_url = db.Column(db.String(500))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship("User", backref="posts", lazy=True)
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
# Chat System (Phase 1)
# ------------------------------------------------
class ChatRoom(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    is_group = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    participants = db.relationship("ChatParticipant", backref="room", cascade="all,delete-orphan", lazy=True)
    messages = db.relationship("Message", backref="room_obj", cascade="all,delete-orphan", lazy=True)

class ChatParticipant(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey("chat_room.id"), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- serializers ---
def message_dict(m):
    iso, human = to_pk_time(m.created_at)
    sender = User.query.get(m.sender_id)
    return {
        "id": m.id,
        "room_id": m.room_id,
        "sender": {"id": sender.id, "username": sender.username, "avatar": sender.avatar},
        "content": m.content,
        "created_at": m.created_at.isoformat(),
        "created_at_pk": iso,
        "created_at_pk_human": human,
    }

def room_dict(r, current_user_id=None):
    last = Message.query.filter_by(room_id=r.id).order_by(Message.created_at.desc()).first()
    participants = [p.user_id for p in r.participants]
    last_msg = message_dict(last) if last else None
    name = r.name
    if not r.is_group and current_user_id:
        other = [uid for uid in participants if uid != current_user_id]
        if other:
            u = User.query.get(other[0])
            name = u.username if u else name
    return {
        "id": r.id,
        "name": name,
        "is_group": r.is_group,
        "participants": participants,
        "last_message": last_msg,
        "created_at": r.created_at.isoformat(),
    }

# --- API endpoints ---
@app.route("/api/chats", methods=["GET"])
@jwt_required()
def get_user_chats():
    uid = int(get_jwt_identity())
    parts = ChatParticipant.query.filter_by(user_id=uid).all()
    rooms = [ChatRoom.query.get(p.room_id) for p in parts if p.room_id]
    return jsonify({"rooms": [room_dict(r, current_user_id=uid) for r in rooms if r]}), 200

@app.route("/api/chats/<int:room_id>/messages", methods=["GET"])
@jwt_required()
def get_room_messages(room_id):
    uid = int(get_jwt_identity())
    if not ChatParticipant.query.filter_by(room_id=room_id, user_id=uid).first():
        return jsonify({"error": "Unauthorized"}), 403
    msgs = Message.query.filter_by(room_id=room_id).order_by(Message.created_at.asc()).all()
    return jsonify({"messages": [message_dict(m) for m in msgs]}), 200

@app.route("/api/chats/create_room", methods=["POST"])
@jwt_required()
def create_room():
    uid = int(get_jwt_identity())
    data = request.get_json() or {}

    # --- Get identifiers ---
    other = data.get("other_user_id")
    username = data.get("username")
    phone = data.get("phone")

    # --- Find the other user (ID, username, or phone) ---
    other_user = None
    if other:
        other_user = User.query.get(int(other))
    elif username:
        other_user = User.query.filter_by(username=username).first()
    elif phone:
        other_user = User.query.filter_by(phone=phone).first()

    if not other_user:
        return jsonify({"error": "User not found"}), 404

    # --- Prevent duplicate rooms ---
    existing = ChatRoom.query.filter_by(is_group=False).all()
    for r in existing:
        ids = [p.user_id for p in r.participants]
        if set(ids) == set([uid, other_user.id]):
            return jsonify({"room": room_dict(r, uid)}), 200

    # --- Create new private room ---
    r = ChatRoom(is_group=False)
    db.session.add(r)
    db.session.commit()

    db.session.add(ChatParticipant(room_id=r.id, user_id=uid))
    db.session.add(ChatParticipant(room_id=r.id, user_id=other_user.id))
    db.session.commit()

    return jsonify({"room": room_dict(r, uid)}), 201


# --- SocketIO handlers ---
def _get_user_id_from_token(token):
    try:
        d = decode_token(token)
        return int(d.get("sub") or d.get("identity"))
    except Exception:
        return None

@socketio.on("connect")
def on_connect(auth):
    sid = request.sid
    token = (auth or {}).get("token")
    print("🟢 CONNECT EVENT - SID:", sid, "| token:", token)
    uid = _get_user_id_from_token(token)
    if not uid:
        print("❌ Invalid or missing token during connect.")
        return False  # reject connection
    connected_users[sid] = uid
    emit("user_online", {"user_id": uid}, broadcast=True)
    print(f"✅ user {uid} connected via socket.")

    sid = request.sid
    token = (auth or {}).get("token")
    uid = _get_user_id_from_token(token)
    if not uid:
        return False  # reject
    connected_users[sid] = uid
    emit("user_online", {"user_id": uid}, broadcast=True)
    print(f"✅ user {uid} connected")

@socketio.on("disconnect")
def on_disconnect():
    sid = request.sid
    uid = connected_users.pop(sid, None)
    if uid:
        emit("user_offline", {"user_id": uid}, broadcast=True)
        print(f"❌ user {uid} disconnected")

@socketio.on("join_room")
def on_join(data):
    room = str(data.get("room"))
    join_room(room)
    emit("joined_room", {"room": room}, room=room)

@socketio.on("send_message")
def on_send(data):
    sid = request.sid
    uid = connected_users.get(sid)
    room = int(data.get("room"))
    text = (data.get("content") or "").strip()
    if not text:
        return
    msg = Message(room_id=room, sender_id=uid, content=text)
    db.session.add(msg); db.session.commit()
    emit("receive_message", message_dict(msg), room=str(room))
# ------------------------------------------------


# ------------------------------------------------
# Time helpers & serializers
# ------------------------------------------------
PK_TZ = timezone("Asia/Karachi")

def to_pk_time(dt):
    if not dt:
        return None, None
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        dt_aware = UTC.localize(dt)
    else:
        dt_aware = dt
    pk_dt = dt_aware.astimezone(PK_TZ)
    iso = pk_dt.isoformat()
    human = pk_dt.strftime("%Y-%m-%d %I:%M %p")
    return iso, human

def post_dict(p):
    iso, human = to_pk_time(p.created_at)
    if not hasattr(p, "user") or p.user is None:
        author = {"id": None, "username": "Unknown User", "avatar": "https://cdn-icons-png.flaticon.com/512/1077/1077012.png"}
    else:
        author = {"id": p.user.id, "username": p.user.username, "avatar": p.user.avatar or "👤"}
    return {
        "id": p.id,
        "content": p.content,
        "image_url": p.image_url,
        "author": author,
        "likes_count": len(p.likes),
        "comments_count": len(p.comments),
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "created_at_pk": iso,
        "created_at_pk_human": human,
    }

def comment_dict(c):
    iso, human = to_pk_time(c.created_at)
    if not hasattr(c, "user") or c.user is None:
        commenter = {"id": None, "username": "Unknown User", "avatar": "https://cdn-icons-png.flaticon.com/512/1077/1077012.png"}
    else:
        commenter = {"id": c.user.id, "username": c.user.username, "avatar": getattr(c.user, "avatar", "👤")}
    return {
        "id": c.id,
        "post_id": c.post_id,
        "user": commenter,
        "content": c.content,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "created_at_pk": iso,
        "created_at_pk_human": human,
    }

# ------------------------------------------------
# AUTH: OTP send & verify
# ------------------------------------------------
@app.route("/api/auth/send_otp", methods=["POST"])
def send_otp():
    data = request.get_json() or {}
    phone = (data.get("phone") or "").strip()
    username = data.get("username")
    if not phone:
        return jsonify({"error": "phone required"}), 400

    phone = phone.replace(" ", "").replace("-", "")
    user = User.query.filter_by(phone=phone).first()
    if not user:
        uname = username or f"user_{phone[-4:]}"
        if User.query.filter_by(username=uname).first():
            uname = f"{uname}_{int(datetime.utcnow().timestamp())%10000}"
        user = User(username=uname, phone=phone)
        db.session.add(user)
        db.session.commit()

    now = datetime.utcnow()
    if user.otp_expiry and user.otp_expiry > now - timedelta(minutes=10) and (user.otp_attempts or 0) >= 10:
        return jsonify({"error": "Too many OTP requests. Try later."}), 429

    otp = generate_otp()
    user.otp_hash = hash_otp(otp)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)
    user.otp_attempts = (user.otp_attempts or 0) + 1
    db.session.commit()

    if DEV_MODE:
        print(f"DEV OTP for {phone} -> {otp}")
        return jsonify({"message": "OTP generated (DEV_MODE)", "dev_otp": otp, "username": user.username}), 200
    else:
        sent = send_sms_via_provider(phone, f"Your SirVerse OTP is {otp}")
        if not sent:
            return jsonify({"error": "Failed to send SMS"}), 500
        return jsonify({"message": "OTP sent"}), 200

@app.route("/api/auth/verify_otp", methods=["POST"])
def verify_otp():
    data = request.get_json() or {}
    phone = (data.get("phone") or "").strip()
    otp = (data.get("otp") or "").strip()
    if not phone or not otp:
        return jsonify({"error": "phone and otp required"}), 400

    user = User.query.filter_by(phone=phone).first()
    if not user or not user.otp_hash:
        return jsonify({"error": "No OTP request found for this number"}), 404

    now = datetime.utcnow()
    if not user.otp_expiry or user.otp_expiry < now:
        return jsonify({"error": "OTP expired"}), 400

    if (user.otp_attempts or 0) >= OTP_MAX_ATTEMPTS and user.otp_expiry > now - timedelta(minutes=15):
        return jsonify({"error": "Too many wrong attempts. Try later."}), 429

    if hash_otp(otp) == user.otp_hash:
        user.otp_hash = None
        user.otp_expiry = None
        user.otp_attempts = 0
        db.session.commit()
        token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
        return jsonify({"access_token": token, "user": {"id": user.id, "username": user.username}}), 200
    else:
        user.otp_attempts = (user.otp_attempts or 0) + 1
        db.session.commit()
        return jsonify({"error": "Invalid OTP"}), 401

# ------------------------------------------------
# Posts CRUD + upload
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
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400

    data = request.get_json() or {}
    if not data.get("content") and not data.get("image_url"):
        return jsonify({"error": "Content required"}), 400
    p = Post(content=data.get("content", ""), image_url=data.get("image_url"), user_id=uid_int)
    db.session.add(p)
    db.session.commit()
    return jsonify({"message": "Post created", "post": post_dict(p)}), 201

@app.route("/api/posts/<int:pid>", methods=["DELETE"])
@jwt_required()
def delete_post(pid):
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400

    post = Post.query.get_or_404(pid)
    if post.user_id != uid_int:
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

@app.route("/api/upload", methods=["POST"])
@jwt_required()
def upload_file():
    """
    Upload any file (image, PDF, etc.) to Cloudinary.
    Used for posts, profile pictures, notes, etc.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    if not f.filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp")):
        return jsonify({"error": "Only image files allowed"}), 400

    try:
        up = cloudinary.uploader.upload(
            f,
            folder="sirverse_profile_pics",   # 🎯 store separately for profile pics
            resource_type="image",
            transformation=[{"width": 512, "height": 512, "crop": "limit"}],
        )
        return jsonify({
            "url": up.get("secure_url"),
            "public_id": up.get("public_id"),
        }), 201
    except Exception as e:
        print("❌ Upload failed:", e)
        return jsonify({"error": "Upload failed"}), 500
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
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400
    data = request.get_json() or {}
    if not data.get("content"):
        return jsonify({"error": "Content required"}), 400
    c = Comment(post_id=pid, user_id=uid_int, content=data["content"])
    db.session.add(c)
    db.session.commit()
    return jsonify({"message": "Comment added", "comment": comment_dict(c)}), 201

@app.route("/api/posts/<int:pid>/like", methods=["POST"])
@jwt_required()
def toggle_like(pid):
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400
    post = Post.query.get_or_404(pid)
    existing = Like.query.filter_by(post_id=pid, user_id=uid_int).first()
    if existing:
        db.session.delete(existing)
        db.session.commit()
        liked = False
    else:
        db.session.add(Like(post_id=pid, user_id=uid_int))
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
            "created_at": user.created_at.isoformat() if user.created_at else None,
            "created_at_pk": to_pk_time(user.created_at)[0] if user.created_at else None,
            "created_at_pk_human": to_pk_time(user.created_at)[1] if user.created_at else None,
            "total_posts": len(posts)
        },
        "posts": [post_dict(p) for p in posts]
    }), 200
# ------------------------------------------------
# Update user profile (Phase 3)
# ------------------------------------------------
@app.route("/api/users/<int:uid>", methods=["PUT"])
@jwt_required()
def update_user(uid):
    """
    Update the logged-in user's profile: full_name, bio, avatar.
    Only allowed if JWT identity matches uid.
    """
    try:
        current_user_id = int(get_jwt_identity())
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    # make sure user edits only their own profile
    if current_user_id != uid:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json() or {}
    user = User.query.get_or_404(uid)

    # Update only if provided
    if "full_name" in data:
        user.full_name = data.get("full_name") or None
    if "bio" in data:
        user.bio = data.get("bio") or None
    if "avatar" in data:
        user.avatar = data.get("avatar") or user.avatar

    db.session.commit()

    return jsonify({
        "message": "Profile updated",
        "user": {
            "id": user.id,
            "username": user.username,
            "full_name": user.full_name,
            "bio": user.bio,
            "avatar": user.avatar,
            "created_at": user.created_at.isoformat() if user.created_at else None
        }
    }), 200

# ------------------------------------------------
# Dashboard stats (Phase 4)
# ------------------------------------------------
@app.route("/api/stats", methods=["GET"])
@jwt_required()
def get_user_stats():
    """Return counts of posts, likes, and comments for current user."""
    try:
        uid = int(get_jwt_identity())
    except Exception:
        return jsonify({"error": "Invalid token"}), 401

    # Count posts
    posts_count = Post.query.filter_by(user_id=uid).count()

    # Count comments made by user
    comments_count = Comment.query.filter_by(user_id=uid).count()

    # Count total likes user received on their posts
    user_posts = Post.query.filter_by(user_id=uid).all()
    post_ids = [p.id for p in user_posts]
    likes_received = Like.query.filter(Like.post_id.in_(post_ids)).count() if post_ids else 0

    return jsonify({
        "posts": posts_count,
        "comments": comments_count,
        "likes_received": likes_received
    }), 200


# -------------------------
# Sir G: Hugging Face AI Chat
# -------------------------
import hashlib
import time
import requests

# You can override model with env var
HF_MODEL = os.getenv("HF_MODEL", "google/gemma-2b")
HF_API_KEY = os.getenv("HF_API_KEY")  # must be set in your .env

# Simple in-memory cache to reduce calls for repeated identical questions.
# Key: sha256(prompt + mode) -> value: {"reply": "...", "ts": unix_ts}
SIRG_CACHE = {}
SIRG_CACHE_TTL = 60 * 60  # cache identical answers for 1 hour

def _cache_get(key):
    v = SIRG_CACHE.get(key)
    if not v: 
        return None
    if time.time() - v["ts"] > SIRG_CACHE_TTL:
        SIRG_CACHE.pop(key, None)
        return None
    return v["reply"]

def _cache_set(key, reply):
    SIRG_CACHE[key] = {"reply": reply, "ts": time.time()}

@app.route("/api/sirg", methods=["POST"])
@jwt_required(optional=True)  # optional: allow logged and anonymous users
def sirg_chat():
    """
    POST JSON: { prompt: "...", mode: "explain" | "summarize" | "quiz" (optional) }
    Calls Hugging Face Inference API and returns {"reply": "..."}.
    Uses simple caching and retry on network errors.
    """
    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    mode = (data.get("mode") or "explain").strip().lower()

    if not prompt:
        return jsonify({"error": "prompt required"}), 400

    if not HF_API_KEY:
        return jsonify({"error": "HF_API_KEY not configured on server"}), 500

    # sanitize mode -> add instruction prefix to make replies educational
    mode_prompts = {
        "explain": "Explain this to a student step-by-step and simply:",
        "summarize": "Summarize this clearly as short study notes:",
        "quiz": "Create 5 multiple-choice questions with answers about:",
        "translate_urdu": "Translate the following into Urdu, simple words:",
    }
    prefix = mode_prompts.get(mode, mode_prompts["explain"])

    full_prompt = f"{prefix}\n\n{prompt}"

    # cache key
    cache_key = hashlib.sha256(f"{HF_MODEL}|{mode}|{full_prompt}".encode()).hexdigest()
    cached = _cache_get(cache_key)
    if cached:
        return jsonify({"reply": cached, "cached": True}), 200

    # HF inference endpoint
    hf_url = f"https://api-inference.huggingface.co/models/{HF_MODEL}"

    headers = {
        "Authorization": f"Bearer {HF_API_KEY}",
        "Content-Type": "application/json",
    }

    payload = {
        "inputs": full_prompt,
        # optional parameters to control length and deterministic answers
        "parameters": {"max_new_tokens": 300, "temperature": 0.2, "return_full_text": False},
    }

    # try request with retries
    last_err = None
    for attempt in range(2):
        try:
            resp = requests.post(hf_url, headers=headers, json=payload, timeout=30)
            # handle non-JSON error body
            try:
                j = resp.json()
            except Exception:
                j = None

            if resp.status_code == 200 and isinstance(j, list) and j and "generated_text" in j[0]:
                reply = j[0]["generated_text"].strip()
                _cache_set(cache_key, reply)
                return jsonify({"reply": reply, "cached": False}), 200

            # Some models return {"error": "..."} or different shape - try to extract text
            if isinstance(j, dict) and "error" in j:
                last_err = j.get("error")
                # if rate limit or model overloaded, break to return error below
                break
            # fallback if response is plain text
            if isinstance(j, str):
                reply = j.strip()
                _cache_set(cache_key, reply)
                return jsonify({"reply": reply}), 200

            # unknown format - capture text body as fallback
            text_body = resp.text or ""
            if text_body:
                # tiny fallback
                reply = text_body.strip()[:1500]
                _cache_set(cache_key, reply)
                return jsonify({"reply": reply}), 200

            last_err = f"HF status {resp.status_code}"
        except requests.exceptions.RequestException as e:
            last_err = str(e)
            # short backoff
            time.sleep(0.5)

    # final error
    print("SirG HF error:", last_err)
    return jsonify({"error": "AI service error", "detail": last_err}), 502

# ------------------------------------------------
# Ping
# ------------------------------------------------
@app.route("/ping")
def ping():
    return jsonify({"ok": True, "time": datetime.utcnow().isoformat()}), 200

# ------------------------------------------------
# Register tools blueprint (notes)
# ------------------------------------------------
# Ensure backend/routes/__init__.py exists
#from routes.note_routes import note_bp
#app.register_blueprint(note_bp)
if __name__ == "__main__":
    print("✅ Ready: Auth, Posts, Upload, Comments, Likes, Profile, Chat (SocketIO)")
    socketio.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)

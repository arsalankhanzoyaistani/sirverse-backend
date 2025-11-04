# backend/app.py
# Add this at the VERY TOP of app.py - before any other imports
import eventlet
eventlet.monkey_patch()

# Then your existing imports...
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

# (rest of your backend code continues...)


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
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(120), nullable=True)
    avatar = db.Column(db.String(255), nullable=True)
    bio = db.Column(db.Text, nullable=True) 
    created_at = db.Column(db.DateTime, server_default=db.func.now())

    otp_hash = db.Column(db.String(255), nullable=True)
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
# Reels Models
# ------------------------------------------------
class Reel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_url = db.Column(db.String(500), nullable=False)
    caption = db.Column(db.Text, nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    likes_count = db.Column(db.Integer, default=0)
    user = db.relationship("User", backref="reels", lazy=True)
    likes = db.relationship("ReelLike", backref="reel", cascade="all,delete-orphan", lazy=True)
    comments = db.relationship("ReelComment", backref="reel", cascade="all,delete-orphan", lazy=True)  

class ReelLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reel_id = db.Column(db.Integer, db.ForeignKey("reel.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "reel_id", name="_user_reel_unique"),)

class ReelComment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reel_id = db.Column(db.Integer, db.ForeignKey("reel.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user = db.relationship("User", lazy=True)


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


# Add to your existing models in app.py

# ------------------------------------------------
# Follow System
# ------------------------------------------------
class Follow(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    follower_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    following_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint("follower_id", "following_id", name="_follower_following_unique"),)
    
    follower = db.relationship("User", foreign_keys=[follower_id], backref="following")
    following = db.relationship("User", foreign_keys=[following_id], backref="followers")

# ------------------------------------------------
# Block System
# ------------------------------------------------
class Block(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    blocker_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    blocked_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    __table_args__ = (db.UniqueConstraint("blocker_id", "blocked_id", name="_blocker_blocked_unique"),)
    
    blocker = db.relationship("User", foreign_keys=[blocker_id])
    blocked = db.relationship("User", foreign_keys=[blocked_id])
# ------------------------------------------------
# Report System Models
# ------------------------------------------------
class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    reported_post_id = db.Column(db.Integer, db.ForeignKey("post.id"), nullable=True)
    reported_reel_id = db.Column(db.Integer, db.ForeignKey("reel.id"), nullable=True)
    report_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default="pending")  # pending, reviewed, resolved, rejected
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    reporter = db.relationship("User", foreign_keys=[reporter_id], backref="reports_made")
    reported_user = db.relationship("User", foreign_keys=[reported_user_id], backref="reports_received")
    reported_post = db.relationship("Post", foreign_keys=[reported_post_id])
    reported_reel = db.relationship("Reel", foreign_keys=[reported_reel_id])


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
# Reels serializers and helpers
# ------------------------------------------------
def reel_dict(r):
    iso, human = to_pk_time(r.created_at)
    if not hasattr(r, "user") or r.user is None:
        author = {"id": None, "username": "Unknown User", "avatar": "https://cdn-icons-png.flaticon.com/512/1077/1077012.png"}
    else:
        author = {"id": r.user.id, "username": r.user.username, "avatar": r.user.avatar or "👤"}
    
    return {
        "id": r.id,
        "video_url": r.video_url,
        "caption": r.caption,
        "author": author,
        "likes_count": r.likes_count,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "created_at_pk": iso,
        "created_at_pk_human": human,
    }

def reel_comment_dict(c):
    iso, human = to_pk_time(c.created_at)
    if not hasattr(c, "user") or c.user is None:
        commenter = {"id": None, "username": "Unknown User", "avatar": "👤"}
    else:
        commenter = {"id": c.user.id, "username": c.user.username, "avatar": c.user.avatar or "👤"}

    return {
        "id": c.id,
        "reel_id": c.reel_id,
        "user": commenter,
        "content": c.content,
        "created_at": c.created_at.isoformat(),
        "created_at_pk": iso,
        "created_at_pk_human": human,
    }


# ------------------------------------------------
# AUTH: EMAIL OTP send & verify (FINAL FIXED)
# ------------------------------------------------
from email.mime.text import MIMEText
import smtplib

@app.route("/api/auth/send_otp", methods=["POST"])
def send_otp():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    username = (data.get("username") or "").strip()

    if not email:
        return jsonify({"error": "Email required"}), 400
    if not username:
        return jsonify({"error": "Username required"}), 400

    # ✅ FIX: Check by both username and email (to avoid duplicate error)
    user = User.query.filter(
        (User.username == username) | (User.email == email)
    ).first()

    if user:
        # update email if changed
        user.email = email
    else:
        # create new user
        user = User(username=username, email=email)
        db.session.add(user)

    # Generate & store OTP
    otp = generate_otp()
    user.otp_hash = hash_otp(otp)
    user.otp_expiry = datetime.utcnow() + timedelta(minutes=OTP_EXP_MINUTES)
    user.otp_attempts = (user.otp_attempts or 0) + 1
    db.session.commit()

    # Send OTP via Gmail
    sender = os.getenv("GMAIL_USER")
    password = os.getenv("GMAIL_PASS")

    msg = MIMEText(f"""
Hi {username},

Your SirVerse GPT verification code is: {otp}
It expires in 5 minutes.

Regards,
SirVerse GPT Team
""")
    msg["Subject"] = "SirVerse GPT - Email OTP Verification"
    msg["From"] = f"SirVerse GPT <{sender}>"
    msg["To"] = email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender, password)
        server.sendmail(sender, [email], msg.as_string())
        server.quit()
        print(f"📧 OTP sent to {email} (code: {otp})")
        return jsonify({"message": "OTP sent to email"}), 200
    except Exception as e:
        print("Email send error:", e)
        return jsonify({"error": "Failed to send OTP"}), 500


@app.route("/api/auth/verify_otp", methods=["POST"])
def verify_otp():
    data = request.get_json() or {}
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()

    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not user.otp_hash:
        return jsonify({"error": "No OTP request found"}), 404

    now = datetime.utcnow()
    if not user.otp_expiry or user.otp_expiry < now:
        return jsonify({"error": "OTP expired"}), 400

    if hash_otp(otp) == user.otp_hash:
        user.otp_hash = None
        user.otp_expiry = None
        user.otp_attempts = 0
        db.session.commit()
        token = create_access_token(identity=str(user.id), expires_delta=timedelta(days=30))
        return jsonify({
            "access_token": token,
            "user": {"id": user.id, "username": user.username, "email": user.email}
        }), 200
    else:
        user.otp_attempts = (user.otp_attempts or 0) + 1
        db.session.commit()
        return jsonify({"error": "Invalid OTP"}), 401
    

    # ------------------------------------------------

# ------------------------------------------------
# Follow/Unfollow System
# ------------------------------------------------
@app.route("/api/users/<int:user_id>/follow", methods=["POST"])
@jwt_required()
def follow_user(user_id):
    current_user_id = int(get_jwt_identity())
    
    if current_user_id == user_id:
        return jsonify({"error": "Cannot follow yourself"}), 400
    
    user_to_follow = User.query.get_or_404(user_id)
    
    # Check if already following
    existing_follow = Follow.query.filter_by(
        follower_id=current_user_id, 
        following_id=user_id
    ).first()
    
    if existing_follow:
        return jsonify({"error": "Already following this user"}), 400
    
    # Create follow relationship
    follow = Follow(follower_id=current_user_id, following_id=user_id)
    db.session.add(follow)
    db.session.commit()
    
    return jsonify({
        "message": f"Started following {user_to_follow.username}",
        "following": True,
        "followers_count": Follow.query.filter_by(following_id=user_id).count(),
        "following_count": Follow.query.filter_by(follower_id=current_user_id).count()
    }), 201

@app.route("/api/users/<int:user_id>/unfollow", methods=["POST"])
@jwt_required()
def unfollow_user(user_id):
    current_user_id = int(get_jwt_identity())
    
    if current_user_id == user_id:
        return jsonify({"error": "Cannot unfollow yourself"}), 400
    
    # Find and delete follow relationship
    follow = Follow.query.filter_by(
        follower_id=current_user_id, 
        following_id=user_id
    ).first_or_404()
    
    db.session.delete(follow)
    db.session.commit()
    
    user_to_unfollow = User.query.get(user_id)
    
    return jsonify({
        "message": f"Unfollowed {user_to_unfollow.username}",
        "following": False,
        "followers_count": Follow.query.filter_by(following_id=user_id).count(),
        "following_count": Follow.query.filter_by(follower_id=current_user_id).count()
    }), 200

@app.route("/api/users/<int:user_id>/follow_status", methods=["GET"])
@jwt_required()
def get_follow_status(user_id):
    current_user_id = int(get_jwt_identity())
    
    is_following = Follow.query.filter_by(
        follower_id=current_user_id, 
        following_id=user_id
    ).first() is not None
    
    is_blocked = Block.query.filter_by(
        blocker_id=current_user_id,
        blocked_id=user_id
    ).first() is not None
    
    followers_count = Follow.query.filter_by(following_id=user_id).count()
    following_count = Follow.query.filter_by(follower_id=user_id).count()
    
    return jsonify({
        "is_following": is_following,
        "is_blocked": is_blocked,
        "followers_count": followers_count,
        "following_count": following_count
    }), 200



# ------------------------------------------------
# Block/Unblock System
# ------------------------------------------------
@app.route("/api/users/<int:user_id>/block", methods=["POST"])
@jwt_required()
def block_user(user_id):
    current_user_id = int(get_jwt_identity())
    
    if current_user_id == user_id:
        return jsonify({"error": "Cannot block yourself"}), 400
    
    user_to_block = User.query.get_or_404(user_id)
    
    # Check if already blocked
    existing_block = Block.query.filter_by(
        blocker_id=current_user_id, 
        blocked_id=user_id
    ).first()
    
    if existing_block:
        return jsonify({"error": "User already blocked"}), 400
    
    # Remove follow relationships if they exist
    Follow.query.filter_by(follower_id=current_user_id, following_id=user_id).delete()
    Follow.query.filter_by(follower_id=user_id, following_id=current_user_id).delete()
    
    # Create block relationship
    block = Block(blocker_id=current_user_id, blocked_id=user_id)
    db.session.add(block)
    db.session.commit()
    
    return jsonify({
        "message": f"Blocked {user_to_block.username}",
        "blocked": True
    }), 201

@app.route("/api/users/<int:user_id>/unblock", methods=["POST"])
@jwt_required()
def unblock_user(user_id):
    current_user_id = int(get_jwt_identity())
    
    block = Block.query.filter_by(
        blocker_id=current_user_id, 
        blocked_id=user_id
    ).first_or_404()
    
    db.session.delete(block)
    db.session.commit()
    
    user_to_unblock = User.query.get(user_id)
    
    return jsonify({
        "message": f"Unblocked {user_to_unblock.username}",
        "blocked": False
    }), 200

@app.route("/api/users/blocked", methods=["GET"])
@jwt_required()
def get_blocked_users():
    current_user_id = int(get_jwt_identity())
    
    blocked_users = Block.query.filter_by(blocker_id=current_user_id).all()
    
    blocked_list = []
    for block in blocked_users:
        user = User.query.get(block.blocked_id)
        blocked_list.append({
            "id": user.id,
            "username": user.username,
            "avatar": user.avatar,
            "blocked_at": block.created_at.isoformat()
        })
    
    return jsonify({"blocked_users": blocked_list}), 200


# ------------------------------------------------
# Report System API Routes
# ------------------------------------------------

@app.route("/api/report", methods=["POST"])
@jwt_required()
def create_report():
    """
    Create a new report for a user, post, or reel
    """
    current_user_id = int(get_jwt_identity())
    data = request.get_json() or {}
    
    print(f"🔍 [DEBUG] Report endpoint called by user {current_user_id}")
    print(f"📋 [DEBUG] Report data: {data}")
    
    report_type = data.get("report_type")
    description = data.get("description", "").strip()
    reported_user_id = data.get("reported_user_id")
    reported_post_id = data.get("reported_post_id")
    reported_reel_id = data.get("reported_reel_id")
    
    if not report_type:
        print("❌ [DEBUG] No report type provided")
        return jsonify({"error": "Report type is required"}), 400
    
    # Validate that at least one entity is reported
    if not any([reported_user_id, reported_post_id, reported_reel_id]):
        print("❌ [DEBUG] No entity to report")
        return jsonify({"error": "Must report a user, post, or reel"}), 400
    
    # Convert to integers and handle None values properly
    try:
        reported_user_id = int(reported_user_id) if reported_user_id else None
        reported_post_id = int(reported_post_id) if reported_post_id else None
        reported_reel_id = int(reported_reel_id) if reported_reel_id else None
    except (TypeError, ValueError) as e:
        print(f"❌ [DEBUG] Error converting IDs: {e}")
        return jsonify({"error": "Invalid ID format"}), 400
    
    print(f"🔍 [DEBUG] Processed IDs - User: {reported_user_id}, Post: {reported_post_id}, Reel: {reported_reel_id}")
    
    # Validate the reported entities exist
    if reported_user_id:
        user = User.query.get(reported_user_id)
        if not user:
            print(f"❌ [DEBUG] Reported user {reported_user_id} not found")
            return jsonify({"error": "Reported user not found"}), 404
        print(f"✅ [DEBUG] User {reported_user_id} exists: {user.username}")
    
    if reported_post_id:
        post = Post.query.get(reported_post_id)
        if not post:
            print(f"❌ [DEBUG] Reported post {reported_post_id} not found")
            return jsonify({"error": "Reported post not found"}), 404
        print(f"✅ [DEBUG] Post {reported_post_id} exists")
    
    if reported_reel_id:
        reel = Reel.query.get(reported_reel_id)
        if not reel:
            print(f"❌ [DEBUG] Reported reel {reported_reel_id} not found")
            return jsonify({"error": "Reported reel not found"}), 404
        print(f"✅ [DEBUG] Reel {reported_reel_id} exists")
    
    # Check if similar report already exists from this user (within last 24 hours)
    twenty_four_hours_ago = datetime.utcnow() - timedelta(hours=24)
    
    # Build the query properly - handle NULL values correctly
    query = Report.query.filter(
        Report.reporter_id == current_user_id,
        Report.report_type == report_type,
        Report.created_at >= twenty_four_hours_ago
    )
    
    # Handle the NULL/None comparison properly for database
    if reported_user_id is not None:
        query = query.filter(Report.reported_user_id == reported_user_id)
    else:
        query = query.filter(Report.reported_user_id.is_(None))
    
    if reported_post_id is not None:
        query = query.filter(Report.reported_post_id == reported_post_id)
    else:
        query = query.filter(Report.reported_post_id.is_(None))
    
    if reported_reel_id is not None:
        query = query.filter(Report.reported_reel_id == reported_reel_id)
    else:
        query = query.filter(Report.reported_reel_id.is_(None))
    
    existing_report = query.first()
    
    if existing_report:
        print(f"⚠️ [DEBUG] Duplicate report found: {existing_report.id}")
        return jsonify({"error": "You have already reported this content recently. Please wait 24 hours before reporting again."}), 400
    
    print("✅ [DEBUG] No duplicate found, creating new report...")
    
    try:
        report = Report(
            reporter_id=current_user_id,
            reported_user_id=reported_user_id,
            reported_post_id=reported_post_id,
            reported_reel_id=reported_reel_id,
            report_type=report_type,
            description=description,
            status="pending"
        )
        
        db.session.add(report)
        db.session.commit()
        
        print(f"🎉 [DEBUG] Report created successfully! ID: {report.id}")
        
        # Log the report for admin review
        print(f"🚨 NEW REPORT: User {current_user_id} reported {report_type}")
        if reported_user_id:
            reported_user = User.query.get(reported_user_id)
            print(f"   - Reported User: {reported_user.username} (ID: {reported_user_id})")
        if reported_post_id:
            print(f"   - Reported Post: {reported_post_id}")
        if reported_reel_id:
            print(f"   - Reported Reel: {reported_reel_id}")
        if description:
            print(f"   - Description: {description}")
        
        return jsonify({
            "message": "Report submitted successfully. Our team will review it shortly.",
            "report_id": report.id
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"💥 [DEBUG] Database error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Failed to create report"}), 500

@app.route("/api/report/types", methods=["GET"])
@jwt_required(optional=True)
def get_report_types():
    """
    Get all available report types
    """
    print("🔍 [DEBUG] Report types endpoint called")
    
    report_types = [
        {"value": "spam", "label": "Spam"},
        {"value": "harassment", "label": "Harassment or Bullying"},
        {"value": "hate_speech", "label": "Hate Speech"},
        {"value": "nudity", "label": "Nudity or Sexual Content"},
        {"value": "violence", "label": "Violence or Harm"},
        {"value": "false_info", "label": "False Information"},
        {"value": "scam", "label": "Scam or Fraud"},
        {"value": "intellectual_property", "label": "Intellectual Property Violation"},
        {"value": "suicide_self_injury", "label": "Suicide or Self-Injury"},
        {"value": "other", "label": "Other"}
    ]
    
    print(f"✅ [DEBUG] Sending {len(report_types)} report types")
    return jsonify({"report_types": report_types}), 200
@app.route("/api/reports/my", methods=["GET"])
@jwt_required()
def get_my_reports():
    """
    Get all reports made by the current user
    """
    current_user_id = int(get_jwt_identity())
    
    reports = Report.query.filter_by(reporter_id=current_user_id)\
        .order_by(desc(Report.created_at))\
        .all()
    
    report_list = []
    for report in reports:
        report_data = {
            "id": report.id,
            "report_type": report.report_type,
            "description": report.description,
            "status": report.status,
            "created_at": report.created_at.isoformat(),
            "reported_content": {}
        }
        
        # Add reported user info if exists
        if report.reported_user_id:
            user = User.query.get(report.reported_user_id)
            if user:
                report_data["reported_content"]["user"] = {
                    "id": user.id,
                    "username": user.username,
                    "avatar": user.avatar
                }
        
        # Add reported post info if exists
        if report.reported_post_id:
            post = Post.query.get(report.reported_post_id)
            if post:
                report_data["reported_content"]["post"] = {
                    "id": post.id,
                    "content_preview": post.content[:100] + "..." if post.content else None,
                    "author_username": post.user.username if post.user else None
                }
        
        # Add reported reel info if exists
        if report.reported_reel_id:
            reel = Reel.query.get(report.reported_reel_id)
            if reel:
                report_data["reported_content"]["reel"] = {
                    "id": reel.id,
                    "caption": reel.caption,
                    "author_username": reel.user.username if reel.user else None
                }
        
        report_list.append(report_data)
    
    return jsonify({"reports": report_list}), 200

# ------------------------------------------------
# Admin Report Management Routes
# ------------------------------------------------

@app.route("/api/admin/reports", methods=["GET"])
@jwt_required()
def get_all_reports():
    """
    Get all reports (admin only)
    """
    # In production, add proper admin authentication here
    current_user_id = int(get_jwt_identity())
    print(f"👮 Admin reports accessed by user {current_user_id}")
    
    # Get query parameters for filtering
    status_filter = request.args.get("status", "all")
    report_type_filter = request.args.get("type", "all")
    
    # Base query
    query = Report.query
    
    # Apply filters
    if status_filter != "all":
        query = query.filter(Report.status == status_filter)
    
    if report_type_filter != "all":
        query = query.filter(Report.report_type == report_type_filter)
    
    reports = query.order_by(desc(Report.created_at)).all()
    
    report_list = []
    for report in reports:
        reporter = User.query.get(report.reporter_id)
        reported_user = User.query.get(report.reported_user_id) if report.reported_user_id else None
        reported_post = Post.query.get(report.reported_post_id) if report.reported_post_id else None
        reported_reel = Reel.query.get(report.reported_reel_id) if report.reported_reel_id else None
        
        report_data = {
            "id": report.id,
            "reporter": {
                "id": reporter.id,
                "username": reporter.username,
                "avatar": reporter.avatar
            } if reporter else None,
            "reported_user": {
                "id": reported_user.id,
                "username": reported_user.username,
                "avatar": reported_user.avatar
            } if reported_user else None,
            "reported_post": {
                "id": reported_post.id,
                "content_preview": reported_post.content[:100] + "..." if reported_post and reported_post.content else None,
                "author_username": reported_post.user.username if reported_post and reported_post.user else None
            } if reported_post else None,
            "reported_reel": {
                "id": reported_reel.id,
                "caption": reported_reel.caption,
                "author_username": reported_reel.user.username if reported_reel and reported_reel.user else None
            } if reported_reel else None,
            "report_type": report.report_type,
            "description": report.description,
            "status": report.status,
            "created_at": report.created_at.isoformat(),
            "created_at_pk": to_pk_time(report.created_at)[0],
            "created_at_pk_human": to_pk_time(report.created_at)[1]
        }
        
        report_list.append(report_data)
    
    return jsonify({
        "reports": report_list,
        "total": len(report_list),
        "filters": {
            "status": status_filter,
            "type": report_type_filter
        }
    }), 200

@app.route("/api/admin/reports/<int:report_id>", methods=["GET"])
@jwt_required()
def get_report_details(report_id):
    """
    Get detailed information about a specific report
    """
    report = Report.query.get_or_404(report_id)
    
    reporter = User.query.get(report.reporter_id)
    reported_user = User.query.get(report.reported_user_id) if report.reported_user_id else None
    reported_post = Post.query.get(report.reported_post_id) if report.reported_post_id else None
    reported_reel = Reel.query.get(report.reported_reel_id) if report.reported_reel_id else None
    
    report_data = {
        "id": report.id,
        "reporter": {
            "id": reporter.id,
            "username": reporter.username,
            "avatar": reporter.avatar,
            "email": reporter.email
        } if reporter else None,
        "reported_user": {
            "id": reported_user.id,
            "username": reported_user.username,
            "avatar": reported_user.avatar,
            "email": reported_user.email
        } if reported_user else None,
        "reported_post": post_dict(reported_post) if reported_post else None,
        "reported_reel": reel_dict(reported_reel) if reported_reel else None,
        "report_type": report.report_type,
        "description": report.description,
        "status": report.status,
        "created_at": report.created_at.isoformat(),
        "created_at_pk": to_pk_time(report.created_at)[0],
        "created_at_pk_human": to_pk_time(report.created_at)[1]
    }
    
    return jsonify({"report": report_data}), 200

@app.route("/api/admin/reports/<int:report_id>/status", methods=["PUT"])
@jwt_required()
def update_report_status(report_id):
    """
    Update report status (admin only)
    """
    report = Report.query.get_or_404(report_id)
    data = request.get_json() or {}
    
    new_status = data.get("status")
    if new_status not in ["pending", "reviewed", "resolved", "rejected"]:
        return jsonify({"error": "Invalid status"}), 400
    
    report.status = new_status
    db.session.commit()
    
    print(f"📝 Report {report_id} status updated to: {new_status}")
    
    return jsonify({
        "message": f"Report status updated to {new_status}",
        "report_id": report.id,
        "status": report.status
    }), 200

@app.route("/api/admin/reports/<int:report_id>/resolve", methods=["POST"])
@jwt_required()
def resolve_report(report_id):
    """
    Mark report as resolved (admin only)
    """
    report = Report.query.get_or_404(report_id)
    report.status = "resolved"
    db.session.commit()
    
    print(f"✅ Report {report_id} marked as resolved")
    
    return jsonify({
        "message": "Report marked as resolved",
        "report_id": report.id,
        "status": report.status
    }), 200

@app.route("/api/admin/reports/<int:report_id>/reject", methods=["POST"])
@jwt_required()
def reject_report(report_id):
    """
    Mark report as rejected (admin only)
    """
    report = Report.query.get_or_404(report_id)
    report.status = "rejected"
    db.session.commit()
    
    print(f"❌ Report {report_id} marked as rejected")
    
    return jsonify({
        "message": "Report marked as rejected",
        "report_id": report.id,
        "status": report.status
    }), 200

@app.route("/api/admin/reports/stats", methods=["GET"])
@jwt_required()
def get_report_stats():
    """
    Get reporting statistics (admin only)
    """
    total_reports = Report.query.count()
    pending_reports = Report.query.filter_by(status="pending").count()
    resolved_reports = Report.query.filter_by(status="resolved").count()
    rejected_reports = Report.query.filter_by(status="rejected").count()
    
    # Reports by type
    reports_by_type = db.session.query(
        Report.report_type,
        db.func.count(Report.id)
    ).group_by(Report.report_type).all()
    
    # Recent reports (last 7 days)
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    recent_reports = Report.query.filter(Report.created_at >= seven_days_ago).count()
    
    stats = {
        "total_reports": total_reports,
        "pending_reports": pending_reports,
        "resolved_reports": resolved_reports,
        "rejected_reports": rejected_reports,
        "recent_reports_7d": recent_reports,
        "reports_by_type": {report_type: count for report_type, count in reports_by_type},
        "resolution_rate": round((resolved_reports / total_reports * 100), 2) if total_reports > 0 else 0
    }
    
    return jsonify({"stats": stats}), 200

# ------------------------------------------------
# Privacy Policy & Terms
# ------------------------------------------------
@app.route("/api/privacy-policy", methods=["GET"])
def get_privacy_policy():
    policy = {
        "title": "Privacy Policy",
        "last_updated": "2024-01-01",
        "sections": [
            {
                "title": "Information We Collect",
                "content": "We collect information you provide directly to us, including your username, email address, profile information, and content you post."
            },
            {
                "title": "How We Use Your Information",
                "content": "We use your information to provide and improve our services, communicate with you, and ensure platform safety."
            },
            {
                "title": "Data Sharing",
                "content": "We do not sell your personal data. We may share information with service providers or when required by law."
            },
            {
                "title": "Your Rights",
                "content": "You can access, update, or delete your personal information through your account settings."
            }
        ]
    }
    return jsonify(policy), 200

@app.route("/api/terms-of-service", methods=["GET"])
def get_terms_of_service():
    terms = {
        "title": "Terms of Service",
        "last_updated": "2024-01-01",
        "sections": [
            {
                "title": "User Conduct",
                "content": "You agree not to post illegal, harmful, or offensive content. Respect other users and their privacy."
            },
            {
                "title": "Content Ownership",
                "content": "You retain ownership of your content but grant us license to display and distribute it on our platform."
            },
            {
                "title": "Account Termination",
                "content": "We reserve the right to suspend or terminate accounts that violate our terms."
            },
            {
                "title": "Limitation of Liability",
                "content": "We are not liable for any indirect damages resulting from your use of our service."
            }
        ]
    }
    return jsonify(terms), 200
# ------------------------------------------------



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
# Reels CRUD + upload
# ------------------------------------------------
@app.route("/api/upload/reel", methods=["POST"])
@jwt_required()
def upload_reel():
    """
    Upload video reels (max 30 seconds) to Cloudinary.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    f = request.files["file"]
    
    # Check if it's a video file
    if not f.filename.lower().endswith((".mp4", ".mov", ".avi", ".webm", ".mkv")):
        return jsonify({"error": "Only video files allowed (MP4, MOV, AVI, WEBM, MKV)"}), 400

    try:
        # Upload to Cloudinary with video-specific settings
        up = cloudinary.uploader.upload(
            f,
            folder="sirverse_reels",  # Separate folder for reels
            resource_type="video",
            transformation=[
                {"width": 720, "height": 1280, "crop": "limit"},  # Mobile-friendly aspect ratio
                {"duration": 30}  # Limit to 30 seconds
            ],
        )
        
        return jsonify({
            "url": up.get("secure_url"),
            "public_id": up.get("public_id"),
            "duration": up.get("duration"),  # Actual duration of uploaded video
            "format": up.get("format")
        }), 201
        
    except Exception as e:
        print("❌ Reel upload failed:", e)
        return jsonify({"error": "Reel upload failed"}), 500

@app.route("/api/reels", methods=["GET"])
@jwt_required(optional=True)
def get_reels():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    reels = Reel.query.order_by(desc(Reel.created_at)).paginate(page=page, per_page=per_page, error_out=False)
    
    return jsonify({
        "items": [reel_dict(r) for r in reels.items],
        "page": page, 
        "pages": reels.pages, 
        "total": reels.total
    }), 200

@app.route("/api/reels", methods=["POST"])
@jwt_required()
def create_reel():
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400

    data = request.get_json() or {}
    if not data.get("video_url"):
        return jsonify({"error": "Video URL required"}), 400
        
    reel = Reel(
        video_url=data.get("video_url"),
        caption=data.get("caption", ""),
        user_id=uid_int
    )
    db.session.add(reel)
    db.session.commit()
    return jsonify({"message": "Reel created", "reel": reel_dict(reel)}), 201

@app.route("/api/reels/<int:reel_id>/like", methods=["POST"])
@jwt_required()
def toggle_reel_like(reel_id):
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400
        
    reel = Reel.query.get_or_404(reel_id)
    existing = ReelLike.query.filter_by(reel_id=reel_id, user_id=uid_int).first()
    
    if existing:
        db.session.delete(existing)
        reel.likes_count = max(0, reel.likes_count - 1)
        liked = False
    else:
        db.session.add(ReelLike(reel_id=reel_id, user_id=uid_int))
        reel.likes_count += 1
        liked = True
        
    db.session.commit()
    return jsonify({"liked": liked, "likes_count": reel.likes_count}), 200

@app.route("/api/reels/<int:reel_id>", methods=["DELETE"])
@jwt_required()
def delete_reel(reel_id):
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400

    reel = Reel.query.get_or_404(reel_id)
    if reel.user_id != uid_int:
        return jsonify({"error": "Unauthorized"}), 403
        
    if reel.video_url:
        try:
            pub = reel.video_url.split("upload/")[1].split(".")[0]
            cloudinary.uploader.destroy(pub, resource_type="video")
        except Exception as e:
            print("Cloudinary video delete failed:", e)
            
    db.session.delete(reel)
    db.session.commit()
    return jsonify({"message": "Reel deleted"}), 200

# ------------------------------------------------
# 🎬 Reel Comments
# ------------------------------------------------
@app.route("/api/reels/<int:reel_id>/comments", methods=["GET"])
def get_reel_comments(reel_id):
    Reel.query.get_or_404(reel_id)
    cmts = ReelComment.query.filter_by(reel_id=reel_id).order_by(ReelComment.created_at.asc()).all()
    return jsonify({"comments": [reel_comment_dict(c) for c in cmts]}), 200


@app.route("/api/reels/<int:reel_id>/comments", methods=["POST"])
@jwt_required()
def add_reel_comment(reel_id):
    uid = get_jwt_identity()
    try:
        uid_int = int(uid)
    except Exception:
        return jsonify({"error": "invalid user id"}), 400

    data = request.get_json() or {}
    text = (data.get("content") or "").strip()
    if not text:
        return jsonify({"error": "Content required"}), 400

    Reel.query.get_or_404(reel_id)
    c = ReelComment(reel_id=reel_id, user_id=uid_int, content=text)
    db.session.add(c)
    db.session.commit()

    return jsonify({"message": "Comment added", "comment": reel_comment_dict(c)}), 201

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
    reels = Reel.query.filter_by(user_id=user.id).order_by(desc(Reel.created_at)).all()
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
            "total_posts": len(posts),
            "total_reels": len(reels)
        },
        "posts": [post_dict(p) for p in posts],
        "reels": [reel_dict(r) for r in reels]
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

    # Count reels
    reels_count = Reel.query.filter_by(user_id=uid).count()

    # Count comments made by user
    comments_count = Comment.query.filter_by(user_id=uid).count()

    # Count total likes user received on their posts
    user_posts = Post.query.filter_by(user_id=uid).all()
    post_ids = [p.id for p in user_posts]
    likes_received = Like.query.filter(Like.post_id.in_(post_ids)).count() if post_ids else 0

    # Count total likes user received on their reels
    user_reels = Reel.query.filter_by(user_id=uid).all()
    reel_ids = [r.id for r in user_reels]
    reel_likes_received = ReelLike.query.filter(ReelLike.reel_id.in_(reel_ids)).count() if reel_ids else 0

    return jsonify({
        "posts": posts_count,
        "reels": reels_count,
        "comments": comments_count,
        "likes_received": likes_received + reel_likes_received,
        "total_engagement": posts_count + reels_count + comments_count + likes_received + reel_likes_received
    }), 200


# ------------------------------------------------
# 🤖 Sir G — Dual Cloud (Groq + Hugging Face)
# ------------------------------------------------
import requests, time, hashlib

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = os.getenv("GROQ_MODEL", "llama3-8b-instant")
HF_API_KEY = os.getenv("HF_API_KEY")
HF_MODEL = os.getenv("HF_MODEL", "meta-llama/Meta-Llama-3-8B-Instruct")

SIRG_CACHE = {}
CACHE_TTL = 3600  # 1 hour


def get_cache(key):
    v = SIRG_CACHE.get(key)
    if v and time.time() - v["t"] < CACHE_TTL:
        return v["r"]
    return None


def set_cache(key, reply):
    SIRG_CACHE[key] = {"r": reply, "t": time.time()}


def query_groq(prompt):
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    data = {
        "model": GROQ_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.3,
        "max_tokens": 400,
    }
    r = requests.post(url, headers=headers, json=data, timeout=30)
    j = r.json()
    if r.status_code == 200 and "choices" in j:
        return j["choices"][0]["message"]["content"].strip()
    raise Exception(j.get("error", j))


def query_hf(prompt):
    url = f"https://api-inference.huggingface.co/models/{HF_MODEL}"
    headers = {"Authorization": f"Bearer {HF_API_KEY}", "Content-Type": "application/json"}
    data = {"inputs": prompt, "parameters": {"max_new_tokens": 300, "temperature": 0.3}}
    r = requests.post(url, headers=headers, json=data, timeout=40)
    j = r.json()
    if isinstance(j, list) and j and "generated_text" in j[0]:
        return j[0]["generated_text"].strip()
    if isinstance(j, dict) and "error" in j:
        raise Exception(j["error"])
    return str(j)


@app.route("/api/sirg", methods=["POST"])
@jwt_required(optional=True)
def sirg_chat():
    data = request.get_json() or {}
    prompt = (data.get("prompt") or "").strip()
    if not prompt:
        return jsonify({"error": "prompt required"}), 400

    mode = (data.get("mode") or "explain").lower()
    prefix = {
        "explain": "Explain step by step and clearly:",
        "summarize": "Summarize this text as short study notes:",
        "quiz": "Create 5 multiple-choice questions with answers about:",
        "translate_urdu": "Translate the following into Urdu (simple words):",
    }.get(mode, "Explain:")

    full_prompt = f"{prefix}\n\n{prompt}"
    cache_key = hashlib.sha256(full_prompt.encode()).hexdigest()
    cached = get_cache(cache_key)
    if cached:
        return jsonify({"reply": cached, "cached": True})

    # 1️⃣ Try Groq
    if GROQ_API_KEY:
        try:
            reply = query_groq(full_prompt)
            set_cache(cache_key, reply)
            return jsonify({"reply": reply, "source": "groq"})
        except Exception as e:
            print("Groq error:", e)

    # 2️⃣ Fallback Hugging Face
    if HF_API_KEY:
        try:
            reply = query_hf(full_prompt)
            set_cache(cache_key, reply)
            return jsonify({"reply": reply, "source": "huggingface"})
        except Exception as e:
            print("HF error:", e)

    return jsonify({"error": "No AI provider available"}), 502


# ------------------------------------------------
# 💬 Sir G Chat History (save / get / delete)
# ------------------------------------------------
class AIHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    role = db.Column(db.String(10))           # "user" or "sirG"
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@app.route("/api/ai/history", methods=["GET"])
@jwt_required()
def get_ai_history():
    uid = int(get_jwt_identity())
    msgs = AIHistory.query.filter_by(user_id=uid)\
        .order_by(AIHistory.created_at.asc()).all()
    return jsonify([
        {"id": m.id, "role": m.role, "text": m.message,
         "time": m.created_at.isoformat()}
        for m in msgs
    ]), 200


@app.route("/api/ai/history", methods=["POST"])
@jwt_required()
def save_ai_message():
    uid = int(get_jwt_identity())
    data = request.get_json() or {}
    msg = AIHistory(user_id=uid, role=data.get("role"),
                    message=data.get("text"))
    db.session.add(msg)
    db.session.commit()
    return jsonify({"ok": True}), 201


@app.route("/api/ai/history", methods=["DELETE"])
@jwt_required()
def clear_ai_history():
    uid = int(get_jwt_identity())
    AIHistory.query.filter_by(user_id=uid).delete()
    db.session.commit()
    return jsonify({"message": "History cleared"}), 200

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
    print("✅ Ready: Auth, Posts, Upload, Comments, Likes, Profile, Chat (SocketIO), Reels")
    socketio.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=True)
